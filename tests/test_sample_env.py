"""Checks that the sample company and its discovery evidence are internally
consistent. These guard the demo data itself; test_discovery.py and
test_engine.py grade the tool against the planted ground truth."""

import ipaddress
import json
from collections import deque
from pathlib import Path
from urllib.parse import urlparse

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "sample" / "halden"
DISCOVERY = SAMPLE / "discovery"
FEEDS = ROOT / "data" / "feeds"


def load(name):
    return json.loads((SAMPLE / name).read_text())


@pytest.fixture(scope="module")
def env():
    nodes = {}
    for name in ("assets.json", "identities.json"):
        for item in load(name):
            assert item["id"] not in nodes, f"duplicate id {item['id']}"
            nodes[item["id"]] = item
    graph = {}
    for e in load("edges.json"):
        graph.setdefault(e["from"], []).append(e["to"])
    return {"nodes": nodes, "graph": graph, "edges": load("edges.json"), "findings": load("findings.json"),
            "assets": {a["id"]: a for a in load("assets.json")}, "registry": load("ai_registry.json")}


def reachable(graph, start):
    seen, queue = {start}, deque([start])
    while queue:
        for nxt in graph.get(queue.popleft(), []):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def scope_networks():
    return [ipaddress.ip_network(n["cidr"]) for n in json.loads((DISCOVERY / "scope.json").read_text())["networks"]]


def test_company_is_marked_fictional():
    assert load("company.json")["fictional"] is True


def test_edges_point_at_known_nodes(env):
    for e in env["edges"]:
        assert e["from"] in env["nodes"], e
        assert e["to"] in env["nodes"], e


def test_static_graph_has_no_ai_wiring(env):
    """AI agents, MCP servers and knowledge bases are discovery's job: the
    scanner-style data must not already contain them."""
    kinds = {e["kind"] for e in env["edges"]}
    assert not kinds & {"agent_input", "agent_tool", "retrieved_by", "feeds", "backs", "executes_on"}


def test_findings_point_at_known_nodes(env):
    for f in env["findings"]:
        assert f["asset"] in env["nodes"], f


def test_finding_ids_are_unique(env):
    ids = [f["id"] for f in env["findings"]]
    assert len(ids) == len(set(ids))


def test_crown_jewels_have_an_impact_weight(env):
    for a in env["assets"].values():
        if a.get("crown_jewel"):
            assert 0 < a["impact"] <= 1, a["id"]


def test_every_cve_has_a_record():
    records = json.loads((FEEDS / "cve_records.json").read_text())["records"]
    cves = {f["cve"] for f in load("findings.json") if f.get("cve")}
    cves |= {p["cve"] for p in json.loads((FEEDS / "mcp_packages.json").read_text())["packages"]}
    assert cves <= set(records), cves - set(records)


def test_registry_ids_are_unique_and_new(env):
    ids = [a["id"] for a in env["registry"]["agents"]] + [s["id"] for s in env["registry"]["mcp_servers"]]
    assert len(ids) == len(set(ids))
    assert not set(ids) & set(env["nodes"])


def test_registered_endpoints_are_inside_the_scope(env):
    nets = scope_networks()
    for s in env["registry"]["mcp_servers"]:
        if s.get("endpoint"):
            ip = ipaddress.ip_address(urlparse(s["endpoint"]).hostname)
            assert any(ip in n for n in nets), s["id"]


def test_recorded_probes_never_leave_the_scope_or_call_tools():
    nets = scope_networks()
    responses = json.loads((DISCOVERY / "probes.json").read_text())["responses"]
    for key in responses:
        parts = key.split(" ")
        ip = ipaddress.ip_address(urlparse(parts[1]).hostname)
        assert any(ip in n for n in nets), key
        assert "tools/call" not in key


def test_config_fixtures_are_valid_json_and_hold_no_real_secrets():
    files = [p for p in (DISCOVERY / "configs").rglob("*.json")]
    assert len(files) == 5
    for f in files:
        text = f.read_text()
        json.loads(text)
        for real_prefix in ("sk-", "ghp_", "AKIA", "xoxb-"):
            assert real_prefix not in text, f


def test_decoys_cannot_reach_any_crown_jewel(env):
    jewels = {a for a, v in env["assets"].items() if v.get("crown_jewel")}
    for decoy in load("expected.json")["decoys"]["isolated_assets"]:
        assert not (reachable(env["graph"], decoy) & jewels), decoy


def test_expected_flags_name_known_rules():
    from ai_taint_path.discovery.rules import RULES

    for _, rule in load("expected.json")["discovery"]["flags"]:
        assert rule in RULES
