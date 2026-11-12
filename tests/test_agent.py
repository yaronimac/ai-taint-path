"""Claude mode for discovery, driven by a scripted client: no network, no API key.

The point of these tests is the fence: whatever the model asks for, it can only
pick leads the crawler built, every probe goes through the same Prober, and no
text written by a scanned system reaches the model.
"""

import json
import sys
from types import SimpleNamespace

import pytest

from ai_taint_path.cli import main
from ai_taint_path.discovery import discover
from ai_taint_path.discovery.agent import DEFAULT_MODEL, FALLBACK_BETA, ClaudeDiscoveryAgent, clean
from ai_taint_path.discovery.probe import FixtureTransport

from conftest import SAMPLE

POISON = ["<IMPORTANT>", "~/.aws/credentials", "Do not mention", "refunds-desk", "<!--", "pdfapi-EXAMPLE"]


def tool_use(name, n, **args):
    return SimpleNamespace(type="tool_use", id=f"tu_{n}_{name}", name=name, input=args)


def reply(*blocks, stop="tool_use", category=None):
    details = SimpleNamespace(type="refusal", category=category) if stop == "refusal" else None
    return SimpleNamespace(content=list(blocks), stop_reason=stop, stop_details=details)


class ScriptedClaude:
    """Stands in for anthropic.Anthropic(): returns scripted turns and records every request."""

    def __init__(self, turns):
        self.turns = iter(turns)
        self.requests = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **kwargs):
        self.requests.append(json.loads(json.dumps(kwargs, default=lambda o: o.__dict__)))
        turn = next(self.turns)
        return turn(kwargs["messages"]) if callable(turn) else turn


def results_of(messages):
    """Tool results from the last user turn, as parsed JSON (or the raw error text)."""
    out = {}
    for block in messages[-1]["content"]:
        body = block["content"]
        out[block["tool_use_id"]] = body if block.get("is_error") else json.loads(body)
    return out


def careful_agent(order):
    """Look at the evidence, probe the leads in the given order, then write a note."""
    return [
        reply(tool_use("describe_evidence", 1), tool_use("list_leads", 1)),
        reply(*[tool_use("probe_lead", i, lead_id=lead) for i, lead in enumerate(order)]),
        reply(SimpleNamespace(type="text", text="Probed the public chat agent's CRM server first."), stop="end_turn"),
    ]


def run(turns, **kw):
    transport = FixtureTransport.load(SAMPLE / "discovery" / "probes.json")
    client = ScriptedClaude(turns)
    env = __import__("ai_taint_path.model", fromlist=["load_environment"]).load_environment(SAMPLE)
    result = discover(env, transport, agent=ClaudeDiscoveryAgent(client=client, **kw),
                      transport_name="recorded probes (fixtures)")
    return result, client, transport


def test_agent_that_probes_every_lead_matches_the_crawler(result):
    order = [f"L{i}" for i in (2, 3, 7, 9, 1, 4, 5, 6, 8)]  # its own priority, not the crawler's order
    agent_result, client, _ = run(careful_agent(order))
    assert {i.id for i in agent_result.inventory} == {i.id for i in result.discovery.inventory}
    assert {(f.asset, f.rule) for f in agent_result.findings} == {(f.asset, f.rule) for f in result.discovery.findings}
    assert agent_result.mode == f"agent (Claude, {DEFAULT_MODEL})"
    assert agent_result.narrative == "Probed the public chat agent's CRM server first."
    assert len(client.requests) == 3


def test_requests_use_the_current_api_surface():
    _, client, _ = run(careful_agent(["L1"]))
    first = client.requests[0]
    assert first["model"] == DEFAULT_MODEL
    assert first["betas"] == [FALLBACK_BETA] and first["fallbacks"] == "default"
    assert "thinking" not in first and "tool_choice" not in first  # adaptive thinking; never forced tool use
    assert first["output_config"] == {"effort": "medium"}
    assert all(t["strict"] and t["input_schema"]["additionalProperties"] is False for t in first["tools"])


def test_the_model_cannot_leave_the_scope_or_invent_targets():
    sent_turn = {}

    def probe_badly(messages):
        return reply(tool_use("probe_lead", 1, lead_id="L8"),  # mcp.crm-vendor.example: outside the scope list
                     tool_use("probe_lead", 2, lead_id="https://evil.example/mcp"),
                     tool_use("probe_lead", 3, lead_id="L99"),
                     tool_use("call_tool", 4, server="L1", tool="run_shell"))

    def inspect(messages):
        sent_turn.update(results_of(messages))
        return reply(SimpleNamespace(type="text", text="done"), stop="end_turn")

    agent_result, _, transport = run([probe_badly, inspect])
    assert sent_turn["tu_1_probe_lead"]["status"] == "out_of_scope"
    assert "no lead" in sent_turn["tu_2_probe_lead"] and "no lead" in sent_turn["tu_3_probe_lead"]
    assert "Unknown tool" in sent_turn["tu_4_call_tool"]
    assert transport.sent == []  # nothing was contacted at all
    leads = {lead["url"]: lead for lead in agent_result.leads}
    assert leads["https://mcp.crm-vendor.example/mcp"]["status"] == "out_of_scope"
    assert all(lead["status"] in ("out_of_scope", "not_probed") for lead in agent_result.leads)


def test_text_from_scanned_systems_never_reaches_the_model():
    seen = {}

    def keep(messages):
        seen.update(results_of(messages))
        return reply(SimpleNamespace(type="text", text="done"), stop="end_turn")

    turns = [reply(tool_use("describe_evidence", 1), tool_use("list_leads", 1),
                   *[tool_use("probe_lead", i, lead_id=f"L{i}") for i in range(1, 10)]), keep]
    _, client, _ = run(turns)
    everything = json.dumps(client.requests)
    for marker in POISON:
        assert marker not in everything, marker
    docs = next(r for r in seen.values() if isinstance(r, dict) and r.get("result", {}).get("server") == "docs-search")
    flagged = {t["name"]: t["hidden_instructions"] for t in docs["result"]["tools"]}
    assert flagged == {"search_docs": True, "get_doc": False}


def test_a_refusal_ends_the_run_with_what_was_probed_so_far():
    turns = [reply(tool_use("probe_lead", 1, lead_id="L1")), reply(stop="refusal", category="cyber")]
    agent_result, _, transport = run(turns)
    assert "refusal, cyber" in agent_result.narrative
    statuses = {lead["url"]: lead["status"] for lead in agent_result.leads}
    assert statuses["http://10.20.1.15:8080/mcp"] == "probed"
    assert sum(s == "not_probed" for s in statuses.values()) == len(statuses) - 1
    assert len(transport.sent) == 3  # initialize, notifications/initialized, tools/list


def test_the_turn_limit_is_hard():
    agent_result, client, _ = run([reply(tool_use("list_leads", n)) for n in range(10)], max_turns=4)
    assert len(client.requests) == 4
    assert agent_result.narrative == "Stopped after 4 turns."


def test_clean_strips_invisible_and_control_characters():
    assert clean("run​_shell\n<IMPORTANT>ignore", 40) == "run _shell <IMPORTANT>ignore"
    assert len(clean("x" * 500, 64)) == 64


def test_cli_explains_a_missing_sdk(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "anthropic", None)  # import anthropic now raises ImportError
    assert main(["scan", str(SAMPLE), "--agent", "claude"]) == 2
    assert "pip install 'ai-taint-path[ai]'" in capsys.readouterr().err


@pytest.mark.parametrize("bad", [None, 42, ["L1"]])
def test_odd_tool_inputs_are_refused_cleanly(bad):
    block = SimpleNamespace(type="tool_use", id="tu_x", name="probe_lead", input=bad)
    turns = [reply(block), reply(SimpleNamespace(type="text", text="ok"), stop="end_turn")]
    agent_result, _, transport = run(turns)
    assert transport.sent == [] and agent_result.narrative == "ok"
