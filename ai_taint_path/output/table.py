"""Plain-text report for the terminal."""

from __future__ import annotations

import textwrap


def _wrap(text: str, width: int, indent: str) -> str:
    return textwrap.fill(text, width=width, initial_indent=indent, subsequent_indent=indent)


def render_scan(report: dict, width: int = 100) -> str:
    s = report["summary"]
    lines = [
        f"ai-taint-path {report['tool']['version']}: {report['environment']['name']}"
        + (" (fictional sample)" if report["environment"]["fictional"] else ""),
        "",
        f"Exposure index {s['exposure_index']} of {s['exposure_index_max']} "
        f"(without discovery: {s['without_discovery']['exposure_index']})",
        f"{s['paths']} attack paths reach {s['crown_jewels_reachable']} of {s['crown_jewels']} crown jewels; "
        f"{s['top_paths_through_ai']} of the top {s['top_paths']} go through AI agents, MCP servers or knowledge bases.",
    ]
    if report["settings"]["discovery"]:
        lines.append(f"Discovery: {s['ai_components']} AI components, {s['ai_not_registered']} not in any inventory, "
                     f"{s['discovery_flags']} flags.")
    lines += ["", f"TOP {s['top_paths']} ATTACK PATHS", ""]
    for p in report["paths"]:
        if not p["top"]:
            break
        tag = "  [AI]" if p["through_ai"] else ""
        blind = "  [blind spot without discovery]" if p["blind_spot"] else ""
        lines.append(f"{p['rank']:>2}. {p['score']:5.1f} {p['tier']:<8} {p['id']}{tag}{blind}")
        lines.append(_wrap(" > ".join(p["nodes"]), width, "              "))
    lines += ["", "CHOKE POINTS (single fix, exposure index reduction)", ""]
    for c in report["choke_points"][:8]:
        lines.append(f"  -{c['reduction']:6.1f}  {c['finding']:<7} {c['asset']:<20} {c['title'][:width - 40]}")
    if report["remediation_plan"]:
        lines += ["", f"REMEDIATION PLAN: {s['plan']['fixes']} fixes take the index from {s['exposure_index']} "
                      f"to {s['plan']['exposure_index_after']} (-{s['plan']['reduction_pct']}%)", ""]
        for c in report["remediation_plan"]:
            lines.append(f"  {c['step']}. {c['asset']}: {c['title'][:width - 30]}")
            lines.append(_wrap(f"Fix: {c['fix']}", width, "     "))
    return "\n".join(lines) + "\n"


def render_discovery(report: dict, width: int = 100) -> str:
    d = report["discovery"]
    if not d:
        return "Discovery was not run.\n"
    lines = [f"Discovery ({d['mode']}): {d['summary']['found']} AI components found, "
             f"{d['summary']['not_registered']} not in any inventory, {d['summary']['flags']} flags, "
             f"{d['summary']['requests_sent']} read-only requests sent.", ""]
    flags = {}
    for f in report["findings"]:
        if f.get("source") == "discovery":
            flags.setdefault(f["asset"], []).append(f)
    for item in report["inventory"]:
        mark = "" if item["registered"] else "  [NOT IN INVENTORY]"
        lines.append(f"{item['kind']:<15} {item['id']:<22} {item['name'][:width - 60]}{mark}")
        for f in flags.get(item["id"], []):
            lines.append(f"    {f['severity']:<8} {f['rule']}  {f['title'][:width - 30]}")
    host_flags = [f for a, fs in flags.items() if a not in {i["id"] for i in report["inventory"]} for f in fs]
    for f in host_flags:
        lines.append(f"{'host':<15} {f['asset']:<22}")
        lines.append(f"    {f['severity']:<8} {f['rule']}  {f['title'][:width - 30]}")
    out_of_scope = [lead for lead in d["leads"] if lead["status"] == "out_of_scope"]
    if out_of_scope:
        lines += ["", "Leads not probed (outside the scope):"]
        lines += [f"  {lead['url']}  ({lead['reasons'][0]})" for lead in out_of_scope]
    return "\n".join(lines) + "\n"
