"""The scan result as one JSON document (schema/scan-result.schema.json).

This is the integration surface: SOAR playbooks, ticketing and the analyst
agent all read this. Path IDs ("<entry>-><target>") and finding IDs are stable
across runs on the same data, so a playbook can track them over time.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

from .. import __version__
from ..engine import ScanResult, exposure_index
from ..frameworks import framework_of
from ..model import AI_KINDS, ROOT

SCHEMA_VERSION = "1.0"


def _display_path(path) -> str:
    """Repo-relative when possible, so reports do not leak local directory names."""
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.name


def _path_dict(r: ScanResult, p, rank: int, top: int, ai_ids: set, baseline: dict) -> dict:
    ai_nodes = [n for n in p.nodes if n in ai_ids]
    base = baseline.get(p.id)
    return {
        "id": p.id,
        "rank": rank,
        "top": rank <= top,
        "score": round(p.score, 1),
        "tier": p.tier,
        "entry": p.entry,
        "target": p.target,
        "target_name": r.graph.name(p.target),
        "impact": p.impact,
        "exposure": p.exposure,
        "likelihood": round(p.likelihood, 4),
        "hops": p.hops,
        "nodes": p.nodes,
        "summary": " → ".join(r.graph.name(n) for n in p.nodes),
        "through_ai": bool(ai_nodes),
        "ai_nodes": ai_nodes,
        "blind_spot": base is None or base < p.score - 0.05,
        "score_without_discovery": None if base is None else round(base, 1),
        "findings": p.findings,
        "techniques": list(dict.fromkeys(t for s in p.steps for t in s.techniques)),
        "steps": [{
            "from": s.src, "to": s.dst, "kind": s.kind, "ease": s.ease, "why": s.why,
            "findings": s.findings, "techniques": s.techniques, "origin": s.origin,
        } for s in p.steps],
    }


def _cvss_view(r: ScanResult, on_paths: dict) -> list[dict]:
    """What a CVSS-sorted scanner list looks like for the same company."""
    static_ids = {f.id for f in r.env.findings}
    cves = [f for f in r.findings if f.cve and f.is_open and f.id in static_ids]
    cves.sort(key=lambda f: (-(f.intel.get("cvss") or 0), f.id))
    return [{"cvss_rank": i, "finding": f.id, "asset": f.asset, "cve": f.cve, "cvss": f.intel.get("cvss"),
             "kev": bool(f.intel.get("kev")), "on_a_path": f.id in on_paths}
            for i, f in enumerate(cves, start=1)]


def build_report(r: ScanResult, *, top: int = 10, generated_at: str | None = None) -> dict:
    ai_ids = {n.id for n in r.nodes.values() if n.kind in AI_KINDS}
    jewels = [n for n in r.nodes.values() if n.crown_jewel]
    index = exposure_index(r.paths)
    base_index = exposure_index(r.baseline_paths)
    baseline = {p.id: p.score for p in r.baseline_paths}

    on_paths: dict[str, list[str]] = defaultdict(list)
    for p in r.paths:
        for fid in p.findings:
            on_paths[fid].append(p.id)
    paths = [_path_dict(r, p, i, top, ai_ids, baseline) for i, p in enumerate(r.paths, start=1)]
    cvss_view = _cvss_view(r, on_paths)
    cvss_rank = {row["finding"]: row["cvss_rank"] for row in cvss_view}

    def fix(c, extra=None) -> dict:
        f = r.finding(c.finding)
        out = {"finding": f.id, "asset": f.asset, "asset_name": r.graph.name(f.asset), "title": f.title,
               "severity": f.severity, "source": f.source, "fix": f.remediation,
               "reduction": c.reduction, "reduction_pct": round(100 * c.reduction / index, 1) if index else 0.0,
               "exposure_index_after": c.index_after}
        if f.id in cvss_rank:
            out["cvss_rank"] = cvss_rank[f.id]
        return {**out, **(extra or {})}

    findings = []
    for f in r.findings:
        d = f.to_dict()
        d["asset_name"] = r.graph.name(f.asset)
        d["on_paths"] = on_paths.get(f.id, [])
        findings.append(d)

    tiers = Counter(p["tier"] for p in paths)
    top_paths = [p for p in paths if p["top"]]
    plan_after = r.plan[-1].index_after if r.plan else round(index, 1)
    d = r.discovery
    report = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "ai-taint-path", "version": __version__},
        "generated_at": generated_at or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "environment": {"name": r.env.company.get("name", r.env.path.name), "fictional": bool(r.env.company.get("fictional")),
                        "path": _display_path(r.env.path)},
        "settings": {"discovery": d is not None, "discovery_mode": d.mode if d else None,
                     "transport": d.sources.get("transport") if d else None, "top": top},
        "feeds": r.feeds.describe(),
        "summary": {
            "exposure_index": round(index, 1),
            "exposure_index_max": 100 * len(jewels),
            "crown_jewels": len(jewels),
            "crown_jewels_reachable": len({p.target for p in r.paths}),
            "paths": len(paths),
            "paths_by_tier": {t: tiers.get(t, 0) for t in ("critical", "high", "medium", "low")},
            "top_paths": len(top_paths),
            "top_paths_through_ai": sum(1 for p in top_paths if p["through_ai"]),
            "top_paths_blind_spot": sum(1 for p in top_paths if p["blind_spot"]),
            "findings_open": sum(1 for f in r.findings if f.is_open),
            "findings_on_paths": len(on_paths),
            "ai_components": len(d.inventory) if d else 0,
            "ai_not_registered": sum(1 for i in d.inventory if not i.registered) if d else 0,
            "discovery_flags": len(d.findings) if d else 0,
            "without_discovery": {"exposure_index": round(base_index, 1), "paths": len(r.baseline_paths)},
            "plan": {"fixes": len(r.plan), "exposure_index_after": plan_after,
                     "reduction_pct": round(100 * (index - plan_after) / index, 1) if index else 0.0},
        },
        "paths": paths,
        "choke_points": [fix(c, {"paths_closed": c.paths_closed, "paths_weakened": c.paths_weakened}) for c in r.choke_points],
        "remediation_plan": [fix(c, {"step": i}) for i, c in enumerate(r.plan, start=1)],
        "findings": findings,
        "inventory": [i.to_dict() for i in d.inventory] if d else [],
        "nodes": [{"id": n.id, "kind": n.kind, "name": n.name, "type": n.type, "crown_jewel": n.crown_jewel,
                   "impact": n.impact, "entry_point": n.entry_point, "open_channel": n.open_channel,
                   "discovered": n.discovered} for n in r.nodes.values()],
        "edges": [{"from": e.src, "to": e.dst, "kind": e.kind, "origin": e.origin, "note": e.note} for e in r.edges],
        "discovery": None if d is None else {
            "mode": d.mode, "summary": d.summary(), "sources": d.sources, "leads": d.leads,
            "requests": d.requests, "narrative": d.narrative,
        },
        "baseline": {
            "description": "The same engine on scanner, CMDB and posture data only, without discovery.",
            "exposure_index": round(base_index, 1),
            "paths": [{"id": p.id, "score": round(p.score, 1), "tier": p.tier} for p in r.baseline_paths],
            "cvss_top10": cvss_view[:10],
        },
    }
    return report


def frameworks_used(report: dict) -> dict[str, list[str]]:
    """Every framework ID a report cites, grouped by framework (used by tests)."""
    ids = set()
    for p in report["paths"]:
        ids.update(p["techniques"])
    for f in report["findings"]:
        for values in f.get("frameworks", {}).values():
            ids.update(values)
    out: dict[str, list[str]] = defaultdict(list)
    for i in sorted(ids):
        out[framework_of(i)].append(i)
    return dict(out)
