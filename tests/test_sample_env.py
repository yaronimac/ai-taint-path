"""Checks that the sample company is internally consistent and that the planted
ground truth really exists in its graph. These guard the demo data itself; the
engine's ranking tests come in step 2."""

import json
from collections import deque
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "sample" / "halden"
FEEDS = ROOT / "data" / "feeds"


def load(name):
    return json.loads((SAMPLE / name).read_text())


@pytest.fixture(scope="module")
def env():
    nodes = {}
    for name in ("assets.json", "identities.json", "agents.json", "mcp_servers.json"):
        for item in load(name):
            assert item["id"] not in nodes, f"duplicate id {item['id']}"
            nodes[item["id"]] = item
    graph = {}
    for e in load("edges.json"):
        graph.setdefault(e["from"], []).append(e["to"])
    return {"nodes": nodes, "graph": graph, "edges": load("edges.json"),
            "findings": load("findings.json"), "expected": load("expected.json"),
            "assets": {a["id"]: a for a in load("assets.json")}}


def reachable(graph, start):
    seen, queue = {start}, deque([start])
    while queue:
        for nxt in graph.get(queue.popleft(), []):
            if nxt not in seen:
                seen.add(nxt)
                queue.append(nxt)
    return seen


def test_company_is_marked_fictional():
    assert load("company.json")["fictional"] is True


def test_edges_point_at_known_nodes(env):
    for e in env["edges"]:
        assert e["from"] in env["nodes"], e
        assert e["to"] in env["nodes"], e


def test_findings_point_at_known_nodes(env):
    for f in env["findings"]:
        assert f["asset"] in env["nodes"], f


def test_finding_ids_are_unique(env):
    ids = [f["id"] for f in env["findings"]]
    assert len(ids) == len(set(ids))


def test_agents_reference_known_identities_and_mcp_servers(env):
    for agent in load("agents.json"):
        if agent["acts_as"]:
            assert agent["acts_as"] in env["nodes"]
        for mcp in agent["mcp_servers"]:
            assert mcp in env["nodes"]


def test_every_cve_has_a_record():
    records = json.loads((FEEDS / "cve_records.json").read_text())["records"]
    cves = {f["cve"] for f in load("findings.json") if f.get("cve")}
    assert cves <= set(records), cves - set(records)


@pytest.mark.parametrize("path_id", [p["id"] for p in load("expected.json")["critical_paths"]])
def test_planted_paths_exist_edge_by_edge(env, path_id):
    path = next(p for p in env["expected"]["critical_paths"] if p["id"] == path_id)
    hops = list(zip(path["nodes"], path["nodes"][1:]))
    for a, b in hops:
        assert b in env["graph"].get(a, []), f"{path_id}: missing edge {a} -> {b}"
    assert env["assets"][path["nodes"][-1]]["crown_jewel"] is True


def test_decoys_cannot_reach_any_crown_jewel(env):
    jewels = {a for a, v in env["assets"].items() if v.get("crown_jewel")}
    for decoy in env["expected"]["decoys"]["isolated_assets"]:
        assert not (reachable(env["graph"], decoy) & jewels), decoy


def test_agent_paths_hinge_on_non_cve_findings(env):
    """The pitch: CVSS-only tools miss agent paths. Every planted path through an
    AI agent or MCP server must include a misconfiguration or agent-risk finding,
    and at least two must contain no CVE at all."""
    open_findings = [f for f in env["findings"] if f["status"] == "open"]
    non_cve_assets = {f["asset"] for f in open_findings if not f.get("cve")}
    cve_assets = {f["asset"] for f in open_findings if f.get("cve")}
    agentic = [p for p in env["expected"]["critical_paths"]
               if any(n.startswith(("agent-", "mcp-")) for n in p["nodes"])]
    assert len(agentic) >= 3
    for p in agentic:
        assert set(p["nodes"]) & non_cve_assets, p["id"]
    assert sum(1 for p in agentic if not set(p["nodes"]) & cve_assets) >= 2
