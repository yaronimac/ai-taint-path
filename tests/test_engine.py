"""The prioritization engine, graded against the planted ground truth."""

import json

import pytest

from ai_taint_path.engine import exposure_index
from ai_taint_path.engine.enrich import cve_ease, foothold_capable
from ai_taint_path.frameworks import REFERENCED, catalog, framework_of
from ai_taint_path.output.report import build_report, frameworks_used

from conftest import GENERATED_AT, SAMPLE  # noqa: F401

PLANTED = json.loads((SAMPLE / "expected.json").read_text())["critical_paths"]


def matches(path, planted):
    return path.target == planted["target"] and set(planted["decisive"]) <= set(path.nodes)


@pytest.mark.parametrize("planted", PLANTED, ids=[p["id"] for p in PLANTED])
def test_every_planted_path_is_in_the_top_10(result, planted):
    assert any(matches(p, planted) for p in result.paths[:10]), planted["id"]


@pytest.mark.parametrize("planted", PLANTED, ids=[p["id"] for p in PLANTED])
def test_planted_example_paths_exist_edge_by_edge(result, planted):
    out = {(e.src, e.dst) for e in result.edges}
    for a, b in zip(planted["example"], planted["example"][1:]):
        assert (a, b) in out, f"{planted['id']}: missing edge {a} -> {b}"


@pytest.mark.parametrize("planted", [p for p in PLANTED if p["needs_discovery"]], ids=lambda p: p["id"])
def test_ai_paths_are_invisible_without_discovery(baseline, planted):
    assert not any(matches(p, planted) for p in baseline.paths), planted["id"]


@pytest.mark.parametrize("planted", [p for p in PLANTED if not p["needs_discovery"]], ids=lambda p: p["id"])
def test_classic_paths_are_found_without_discovery(baseline, planted):
    assert any(matches(p, planted) for p in baseline.paths[:10]), planted["id"]


def test_discovery_raises_the_exposure_index(result, baseline):
    assert exposure_index(result.paths) > exposure_index(baseline.paths) + 100


def test_decoys_never_appear_on_a_path(result, expected):
    decoys = set(expected["decoys"]["isolated_assets"])
    for p in result.paths:
        assert not decoys & set(p.nodes), p.id


def test_fixed_cves_never_gate_a_path(result, expected):
    fixed_ids = {f.id for f in result.findings if f.cve in expected["fixed_cves_excluded"]}
    assert len(fixed_ids) == len(expected["fixed_cves_excluded"])
    for p in result.paths:
        assert not fixed_ids & set(p.findings), p.id
    assert not {"fw-edge-01", "pan-gp-01", "citrix-adc-01"} & {p.entry for p in result.paths}


def test_denial_of_service_cves_are_not_footholds(result):
    rapid_reset = [f for f in result.findings if f.cve == "CVE-2023-44487"]
    assert rapid_reset and all("foothold" not in f.tags for f in rapid_reset)


def test_kev_beats_epss_beats_cvss():
    assert cve_ease({"kev": True, "epss": 0.01, "cvss": 5.0})[0] == 0.9
    assert cve_ease({"kev": False, "epss": 0.5, "cvss": 5.0})[0] == 0.6
    assert cve_ease({"kev": False, "epss": 0.01, "cvss": 10.0})[0] == 0.3
    assert cve_ease({"kev": False, "epss": None, "cvss": 9.8})[0] == 0.4
    assert cve_ease({"kev": False, "epss": None, "cvss": None})[0] == 0.15


def test_foothold_rules():
    assert not foothold_capable({"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"})[0]
    assert not foothold_capable({"cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "kev": False})[0]
    assert foothold_capable({"cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", "kev": True})[0]
    assert foothold_capable({"cvss_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"})[0]


def test_scores_are_bounded_and_ranked(result):
    scores = [p.score for p in result.paths]
    assert all(0 < s <= 100 for s in scores)
    assert scores == sorted(scores, reverse=True)
    assert len({p.id for p in result.paths}) == len(result.paths)


def test_every_step_explains_itself(result):
    for p in result.paths:
        assert p.steps[0].kind == "entry"
        for s in p.steps:
            assert s.why and 0 < s.ease <= 1, (p.id, s)


def test_ranking_is_deterministic(env, feeds, transport, report):
    from ai_taint_path.engine import scan

    again = build_report(scan(env, feeds, transport=transport, transport_name="recorded probes (fixtures)"),
                         top=10, generated_at=GENERATED_AT)
    assert json.dumps(again, sort_keys=True) == json.dumps(report, sort_keys=True)


def test_choke_points_put_the_biggest_fixes_first(result):
    top = [result.finding(c.finding) for c in result.choke_points[:5]]
    assert top[0].cve == "CVE-2024-21887"  # the VPN flaw opens five paths at once
    assert {"agent-support", "agent-finance"} <= {f.asset for f in top}  # approval steps on two agents
    assert any(f.asset == "svc-ops-agent" for f in top)  # an over-privileged machine identity


def test_remediation_plan_cuts_most_of_the_risk(result):
    before = exposure_index(result.paths)
    assert len(result.plan) == 5
    assert result.plan[-1].index_after < 0.3 * before


def test_cited_framework_ids_are_verified(report):
    cat = catalog()
    for framework, ids in frameworks_used(report).items():
        for ident in ids:
            assert ident in REFERENCED[framework], ident
            assert ident in cat[framework], ident
            assert framework_of(ident) == framework
