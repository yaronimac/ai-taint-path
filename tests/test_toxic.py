"""Toxic combinations: discovery flags that are joined by a real link in the graph."""

from ai_taint_path.engine.toxic import PATTERNS
from ai_taint_path.output.report import build_report

from conftest import GENERATED_AT


def by_pattern(report, pattern):
    return [c for c in report["toxic_combinations"] if c["pattern"] == pattern]


def test_ids_are_sequential_and_worst_first(report):
    combos = report["toxic_combinations"]
    assert [c["id"] for c in combos] == [f"TC-{i:02d}" for i in range(1, len(combos) + 1)]
    order = ["critical", "high", "medium", "low"]
    assert [order.index(c["severity"]) for c in combos] == sorted(order.index(c["severity"]) for c in combos)
    assert report["summary"]["toxic_combinations"] == len(combos)
    assert {c["pattern"] for c in combos} == set(PATTERNS)


def test_every_ingredient_is_a_recorded_flag_or_fact(report):
    findings = {f["id"]: f for f in report["findings"]}
    for c in report["toxic_combinations"]:
        assert len(c["ingredients"]) >= 2
        assert c["break_with"] in c["findings"]
        for i in c["ingredients"]:
            if i["finding"]:
                assert findings[i["finding"]]["asset"] == i["component"]
                assert findings[i["finding"]]["source"] == "discovery"


def test_planted_agent_risks_are_combinations(report):
    """The three planted agent paths in expected.json each show up as one named combination."""
    agents = {c["components"][1]: c for c in by_pattern(report, "untrusted-input-unapproved-tools")}
    assert agents["agent-finance"]["components"][0] == "finance-inbox"
    assert "finance-inbox->finance-erp" in agents["agent-finance"]["paths"]
    assert agents["agent-support"]["components"][0] == "support-chat"
    assert "support-chat->crm" in agents["agent-support"]["paths"]
    ops = [c for c in by_pattern(report, "open-mcp-high-impact-tools") if c["components"] == ["mcp-ops"]]
    assert ops and "vpn-gw-01->aws-prod" in ops[0]["paths"]


def test_poisoned_and_open_data_reach_an_acting_agent(report):
    docs = {(c["components"][0], c["components"][-1]) for c in by_pattern(report, "untrusted-documents-to-agent")}
    assert ("support-kb", "agent-support") in docs and ("vendor-kb", "agent-finance") in docs
    store = by_pattern(report, "open-vector-store-behind-agent")
    assert [c["components"][0] for c in store] == ["qdrant-10-20-4-30"]
    tool = by_pattern(report, "poisoned-tool-to-agent")
    assert [(c["components"][0], c["components"][-1]) for c in tool] == [("docs-search-mcp", "agent-ops")]


def test_paths_point_back_at_their_combinations(report):
    combos = {c["id"]: c for c in report["toxic_combinations"]}
    for p in report["paths"]:
        assert p["toxic_combinations"] == [c for c in combos if p["id"] in combos[c]["paths"]]
        for c in p["toxic_combinations"]:
            assert set(combos[c]["components"]) & set(p["nodes"])


def test_no_combinations_without_discovery(baseline):
    doc = build_report(baseline, top=10, generated_at=GENERATED_AT)
    assert doc["toxic_combinations"] == [] and all(p["toxic_combinations"] == [] for p in doc["paths"])
