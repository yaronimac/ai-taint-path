"""A one-file HTML dashboard for a scan report (`scan --format html`).

The page is self-contained and makes no network requests: the styles and the
small tooltip script are inline, and text uses the reader's system fonts.
Everything that came from the scanned environment is HTML-escaped, including
tool descriptions and document excerpts, which discovery treats as untrusted.
The tooltip script only ever writes with textContent.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime
from html import escape
from urllib.parse import urlsplit

from ..discovery.inventory import KIND_LABELS
from ..discovery.probe import ALLOWED_RPC, VECTOR_PROBES
from ..engine.graph import EXPOSURE
from ..engine.paths import TIERS
from ..frameworks import FRAMEWORK_TITLES, framework_of
from ..frameworks import name as technique_name
from ..model import AI_KINDS
from .report import frameworks_used

MINUS = "−"
# One line per block element keeps the file readable and diffable (whitespace between blocks does not render).
BREAK_AFTER = re.compile(r"(</(?:div|section|header|footer|nav|main|table|thead|tbody|tr|ul|ol|li|details)>)")
LEVELS = ("critical", "high", "medium", "low")
UNTRUSTED = "excerpt (untrusted, not followed): "
PLATFORMS = {"azure_ai_foundry": "Azure AI Foundry", "aws_bedrock": "Amazon Bedrock",
             "claude_code": "Claude Code", "desktop": "Desktop AI clients"}
AUTH = {"none": "no authentication", "required": "asks for credentials", "local": "local process",
        "unknown": "not probed (out of scope)"}
ENTRY_WORDS = {"internet": "the entry point faces the internet", "user_action": "someone has to open or click something"}


# --- small helpers ------------------------------------------------------------------

def e(value) -> str:
    return "" if value is None else escape(str(value), quote=True)


def num(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.1f}"


def pct(value: float, top: float) -> str:
    """A CSS percentage for a bar length or a dot position, kept inside 0..100."""
    share = 100 * value / top if top else 0.0
    return f"{max(0.0, min(100.0, share)):.2f}%"


def short(name: str | None) -> str:
    """'Corporate network (10.20.0.0/16, ...)' -> 'Corporate network'."""
    name = name or ""
    return name.split(" (")[0].strip() or name


def words(token: str | None) -> str:
    return (token or "").replace("_", " ")


def join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def tip(text: str, focus: bool = False) -> str:
    return f' data-tip="{e(text)}"' + (' tabindex="0"' if focus else "")


def level(name: str) -> str:
    return f'<span class="lvl l-{e(name)}"><i aria-hidden="true"></i>{e(name.capitalize())}</span>'


def when(stamp: str) -> str:
    try:
        d = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return stamp
    return f"{d.day} {d:%b %Y, %H:%M} UTC"


def tier_bands() -> list[tuple[str, int, int]]:
    floors = sorted(TIERS)
    return [(name, lo, floors[i + 1][0] if i + 1 < len(floors) else 100) for i, (lo, name) in enumerate(floors)]


def section(sid: str, title: str, lede: str, body: str) -> str:
    return (f'<section id="{sid}" aria-labelledby="{sid}-h"><div class="sec-head"><h2 id="{sid}-h">{e(title)}</h2>'
            f'<p class="lede">{lede}</p></div>{body}</section>')


class _View:
    """The report plus the lookups every section needs."""

    def __init__(self, report: dict):
        self.r = report
        self.s = report["summary"]
        self.discovery = bool(report["settings"]["discovery"])
        self.nodes = {n["id"]: n for n in report["nodes"]}
        self.ai = {n["id"] for n in report["nodes"] if n["kind"] in AI_KINDS}
        self.findings = {f["id"]: f for f in report["findings"]}
        self.flags = [f for f in report["findings"] if f.get("source") == "discovery"]
        self.top = [p for p in report["paths"] if p["top"]]

    def name(self, node_id: str | None) -> str:
        node = self.nodes.get(node_id or "")
        return node["name"] if node else (node_id or "")

    def route(self, nodes: list[str]) -> str:
        return " → ".join(short(self.name(n)) for n in nodes)

    def title(self, finding_id: str, title: str) -> str:
        """A finding title without the 'CVE-2024-21887: ' prefix that label() already shows."""
        prefix = f"{self.label(finding_id)}: "
        return title[len(prefix):] if title.startswith(prefix) else title

    def label(self, finding_id: str) -> str:
        """CVE for a scanner finding, rule for a discovery flag, else the finding ID."""
        f = self.findings.get(finding_id, {})
        return f.get("cve") or f.get("rule") or finding_id


# --- sections -----------------------------------------------------------------------

def _header(v: _View) -> str:
    r, s = v.r, v.s
    env, settings, feeds = r["environment"], r["settings"], r["feeds"]
    pill = '<span class="pill">Fictional company</span>' if env.get("fictional") else ""
    headline = (f"{plural(s['paths'], 'attack path')} reach {s['crown_jewels_reachable']} of "
                f"{plural(s['crown_jewels'], 'crown jewel')}.")
    if v.discovery and v.top:
        invisible = sum(1 for p in v.top if p["score_without_discovery"] is None)
        headline += (f" {s['top_paths_through_ai']} of the top {len(v.top)} run through AI agents, MCP servers or "
                     f"knowledge bases")
        headline += f", and {invisible} of those are invisible to scanner data alone." if invisible else "."
    meta = [f"Generated {when(r['generated_at'])}", f"ai-taint-path {r['tool']['version']}"]
    if v.discovery:
        meta.append(f"AI discovery: {settings['discovery_mode']}, {settings['transport']}")
    else:
        meta.append("AI discovery off: scanner, CMDB and posture data only")
    meta.append(f"CISA KEV catalog {feeds['kev_catalog_version']}, {feeds['cve_records']} CVE records")
    meta.append(f"EPSS {feeds['epss']}")
    return (f'<header class="top"><p class="eyebrow">Attack-path report</p>'
            f'<div class="title-row"><h1>{e(env["name"])}</h1>{pill}</div>'
            f'<p class="headline">{e(headline)}</p>'
            f'<p class="meta">{"".join(f"<span>{e(m)}</span>" for m in meta)}</p></header>')


def _kpis(v: _View) -> str:
    s = v.s
    index, top = s["exposure_index"], s["exposure_index_max"]
    base = s["without_discovery"]["exposure_index"]
    added = round(max(0.0, index - base), 1)
    if v.discovery:
        segs = (f'<span class="seg base" style="width:{pct(base, top)}"'
                f'{tip(f"Found from scanner, CMDB and posture data: {num(base)}")}></span>'
                f'<span class="seg with end" style="width:{pct(added, top)}"'
                f'{tip(f"Added by AI discovery: +{num(added)}")}></span><span class="seg rest"></span>')
        legend = (f'<span><i class="sw sw-base"></i>Scanner, CMDB and posture data: {num(base)}</span>'
                  f'<span><i class="sw sw-with"></i>Added by AI discovery: +{num(added)}</span>')
        aria = f"Exposure index {num(index)} of {top}: {num(base)} from scanner data, {num(added)} added by AI discovery"
    else:
        segs = f'<span class="seg base end" style="width:{pct(index, top)}"></span><span class="seg rest"></span>'
        legend = '<span><i class="sw sw-base"></i>Scanner, CMDB and posture data only</span>'
        aria = f"Exposure index {num(index)} of {top}"
    hero = (f'<div class="kpi hero"><div class="kpi-num"><span class="big">{num(index)}</span>'
            f'<span class="of">of {top}</span></div><div class="kpi-body"><p class="kpi-label">Exposure index</p>'
            f'<p class="kpi-note">The worst attack-path score to each of the {s["crown_jewels"]} crown jewels, added '
            f'up. Each path scores 0 to 100. Lower is better.</p>'
            f'<div class="meter" role="img" aria-label="{e(aria)}">{segs}</div>'
            f'<div class="legend">{legend}</div></div></div>')

    def tile(big: str, label: str, note: str) -> str:
        return (f'<div class="kpi"><span class="num">{e(big)}</span><p class="kpi-label">{e(label)}</p>'
                f'<p class="kpi-note">{e(note)}</p></div>')

    tiles = []
    if v.discovery and v.top:
        invisible = sum(1 for p in v.top if p["score_without_discovery"] is None)
        under = sum(1 for p in v.top if p["blind_spot"] and p["score_without_discovery"] is not None)
        tiles.append(tile(f"{s['top_paths_through_ai']} of {len(v.top)}", "top paths run through AI",
                          f"{invisible} invisible and {under} under-rated without AI discovery"))
        sev = Counter(f["severity"] for f in v.flags)
        tiles.append(tile(str(s["ai_components"]), "AI components found",
                          f"{s['ai_not_registered']} in no inventory, {plural(s['discovery_flags'], 'risk flag')} "
                          f"({sev['critical']} critical)"))
    else:
        tiles.append(tile(str(s["paths"]), "attack paths", f"{s['paths_by_tier']['critical']} critical"))
        tiles.append(tile(f"{s['findings_on_paths']} of {s['findings_open']}", "open findings on a path",
                          "the rest lead to no crown jewel"))
    plan = s["plan"]
    if plan["fixes"]:
        tiles.append(tile(f"{MINUS}{plan['reduction_pct']}%", f"exposure after {plural(plan['fixes'], 'fix', 'fixes')}",
                          f"index {num(index)} → {num(plan['exposure_index_after'])}"))
    return f'<div class="kpis">{hero}{"".join(tiles)}</div>'


def _nav(v: _View) -> str:
    links = [("jewels", "Crown jewels"), ("paths", "Attack paths"), ("fixes", "Fix first"), ("cvss", "CVSS view")]
    if v.discovery:
        links += [("ai", "AI inventory"), ("method", "How discovery worked")]
    return ('<nav class="toc" aria-label="Sections">'
            + "".join(f'<a href="#{i}">{e(t)}</a>' for i, t in links) + "</nav>")


def _jewel_rows(v: _View) -> list[dict]:
    worst, base = {}, {}
    for p in v.r["paths"]:  # ranked, so the first path to a target is its worst
        worst.setdefault(p["target"], p)
    for p in v.r["baseline"]["paths"]:
        target = p["id"].split("->", 1)[1]
        if target not in base or p["score"] > base[target]["score"]:
            base[target] = p
    rows = []
    for n in v.r["nodes"]:
        if n["crown_jewel"]:
            w, b = worst.get(n["id"]), base.get(n["id"])
            rows.append({"id": n["id"], "name": n["name"], "path": w,
                         "with": w["score"] if w else None, "base": b["score"] if b else None})
    rows.sort(key=lambda x: (-(x["with"] or 0), -(x["base"] or 0), x["id"]))
    return rows


def _jewels(v: _View) -> str:
    rows = _jewel_rows(v)
    if v.discovery:
        changed = [x for x in rows if x["with"] is not None and (x["base"] is None or x["with"] > x["base"] + 0.05)]
        unseen = [short(x["name"]) for x in rows if x["base"] is None and x["with"] is not None]
        lede = f"AI discovery changes the worst path to {len(changed)} of {len(rows)} crown jewels."
        if unseen:
            lede += f" On scanner, CMDB and posture data alone, {join(unseen)} {'looks' if len(unseen) == 1 else 'look'} unreachable."
        legend = ('<span><i class="sw sw-base"></i>Scanner, CMDB and posture data only</span>'
                  '<span><i class="sw sw-with"></i>With AI discovery</span>')
        if any(x["base"] is None for x in rows):
            legend += '<span><i class="sw sw-none"></i>No path without discovery</span>'
    else:
        lede = "AI discovery was off, so these are the paths a scanner, CMDB and posture view can see."
        legend = '<span><i class="sw sw-base"></i>Scanner, CMDB and posture data only</span>'

    out = []
    for x in rows:
        w, b = x["with"], x["base"]
        marks = []
        if w is None:
            marks.append('<span class="db-empty">No path found</span>')
        elif not v.discovery:
            marks += [f'<span class="db-dot base" style="left:{pct(w, 100)}"></span>',
                      f'<span class="db-val" style="left:{pct(w, 100)}">{num(w)}</span>']
        else:
            start = b if b is not None else 0.0
            if w - start > 0.05:
                marks.append(f'<span class="db-link" style="left:{pct(start, 100)};width:{pct(w - start, 100)}"></span>')
            if b is None:
                marks.append('<span class="db-dot none" style="left:0%"></span>')
            elif w - b > 0.05:
                marks += [f'<span class="db-dot base" style="left:{pct(b, 100)}"></span>',
                          f'<span class="db-val lo" style="left:{pct(b, 100)}">{num(b)}</span>']
            marks += [f'<span class="db-dot with" style="left:{pct(w, 100)}"></span>',
                      f'<span class="db-val" style="left:{pct(w, 100)}">{num(w)}</span>']
        lines = [x["name"]]
        if w is not None:
            lines.append(f"{'With AI discovery' if v.discovery else 'Worst path'}: {num(w)} "
                         f"({x['path']['tier']}), {v.route(x['path']['nodes'])}")
        if v.discovery:
            lines.append(f"Scanner, CMDB and posture data only: {num(b) if b is not None else 'no path'}")
        out.append(f'<div class="db-row"{tip(chr(10).join(lines), True)}><div class="db-label">{e(short(x["name"]))}'
                   f'<span class="sub mono">{e(x["id"])}</span></div><div class="db-track">{"".join(marks)}</div></div>')

    ticks = "".join(f'<span style="left:{t}%">{t}</span>' for t in range(0, 101, 20))
    bands = "".join(f'<span style="left:{(lo + hi) / 2:g}%">{e(name)}</span>' for name, lo, hi in tier_bands())
    axis = (f'<div class="db-axis"><div></div><div class="ticks">{ticks}</div></div>'
            f'<div class="db-axis"><div></div><div class="ticks bands">{bands}</div></div>')

    trs = []
    for x in rows:
        w, b = x["with"], x["base"]
        change = ("new path" if b is None and w is not None else
                  f"+{w - b:.1f}" if w is not None and b is not None and w - b > 0.05 else "no change")
        route = v.route(x["path"]["nodes"]) if x["path"] else "no path"
        trs.append(f'<tr><td>{e(x["name"])}</td><td class="n">{num(b) if b is not None else "no path"}</td>'
                   f'<td class="n">{num(w) if w is not None else "no path"}</td><td class="n">{e(change)}</td>'
                   f'<td>{e(route)}</td></tr>')
    table = ('<details class="tableview"><summary>Show as a table</summary><div class="scroll"><table class="wide">'
             '<thead><tr><th>Crown jewel</th><th class="n">Scanner data only</th><th class="n">With AI discovery</th>'
             f'<th class="n">Change</th><th>Worst path</th></tr></thead><tbody>{"".join(trs)}</tbody></table></div></details>')
    chart = (f'<div class="card chart"><div class="legend">{legend}</div>'
             f'<div class="db" role="img" aria-label="Worst path score to each crown jewel, with and without AI '
             f'discovery. The table below has the same numbers.">{"".join(out)}{axis}</div>'
             f'<p class="axis-title">Worst attack-path score, 0 to 100</p>{table}</div>')
    return section("jewels", "Worst path to each crown jewel", e(lede), chart)


def _chip(v: _View, node_id: str, last: bool) -> str:
    node = v.nodes.get(node_id, {})
    kind = KIND_LABELS.get(node.get("kind"), words(node.get("type")))
    classes = "chip" + (" ai" if node_id in v.ai else "") + (" jewel" if last else "")
    return (f'<li><span class="{classes}"{tip(f"{v.name(node_id)}{chr(10)}{node_id} · {kind}")}>'
            f'{e(short(v.name(node_id)))}</span></li>')


def _technique(ident: str) -> str:
    return f'<span class="fw"{tip(technique_name(framework_of(ident), ident))}>{e(ident)}</span>'


def _steps(v: _View, p: dict) -> str:
    rows = []
    for i, s in enumerate(p["steps"], start=1):
        hop = (f"Entry at {short(v.name(s['to']))}" if s["kind"] == "entry"
               else f"{short(v.name(s['from']))} → {short(v.name(s['to']))}")
        found = ' <span class="tag">found by discovery</span>' if s["origin"] == "discovery" else ""
        fids = " ".join(f'<span class="mono"{tip(v.findings.get(f, {}).get("title", f))}>{e(f)}</span>'
                        for f in s["findings"]) or '<span class="none">none</span>'
        techs = " ".join(_technique(t) for t in s["techniques"]) or '<span class="none">none</span>'
        rows.append(f'<tr><td class="n">{i}</td><td>{e(hop)}{found}<span class="sub">{e(words(s["kind"]))}</span></td>'
                    f'<td>{e(s["why"])}</td><td class="n">{s["ease"]:.2f}</td><td>{fids}</td><td>{techs}</td></tr>')
    return ('<div class="scroll"><table class="wide steps"><thead><tr><th class="n">#</th><th>Step</th><th>Why it works</th>'
            f'<th class="n">Ease</th><th>Findings</th><th>Techniques</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>')


def _path_item(v: _View, p: dict) -> str:
    title = (f'{e(short(v.name(p["entry"])))}<span class="arrow" aria-hidden="true"> → </span>'
             f'<span class="vh"> to </span>{e(short(p["target_name"]))}')
    why = (f"Score {num(p['score'])} = 100 × exposure {p['exposure']:g} × likelihood {p['likelihood']:.3f} "
           f"× impact {p['impact']:g}{chr(10)}{plural(p['hops'], 'step')} from the entry point to the crown jewel")
    score = (f'<div class="score"{tip(why, True)}><span class="track"><span class="fill" style="width:{pct(p["score"], 100)}">'
             f'</span></span><span class="val">{num(p["score"])}</span>{level(p["tier"])}</div>')
    chips = "".join(_chip(v, n, i == len(p["nodes"]) - 1) for i, n in enumerate(p["nodes"]))
    tags = []
    if p["ai_nodes"]:
        tags.append(f'<span class="tag strong">Runs through {plural(len(p["ai_nodes"]), "AI component")}</span>')
    if v.discovery and p["score_without_discovery"] is None:
        tags.append('<span class="tag strong">Invisible without AI discovery</span>')
    elif v.discovery and p["blind_spot"]:
        tags.append(f'<span class="tag">Scores {num(p["score_without_discovery"])} without AI discovery</span>')
    tags_html = f'<div class="tags">{"".join(tags)}</div>' if tags else ""
    return (f'<li class="path"><span class="rank">{p["rank"]}</span><div class="path-main">'
            f'<p class="path-title">{title}<span class="sub mono">{e(p["id"])}</span></p>{score}'
            f'<ol class="chain" aria-label="Route">{chips}</ol>{tags_html}'
            f'<details><summary>How this path works, step by step</summary>{_steps(v, p)}</details></div></li>')


def _paths(v: _View) -> str:
    paths = v.r["paths"]
    if not paths:
        return section("paths", "Attack paths", "No path reaches a crown jewel.", "")
    floors = {name: lo for lo, name in TIERS}
    exposure = "; ".join(f"{val:.1f} when {ENTRY_WORDS.get(k, words(k))}" for k, val in EXPOSURE.items())
    lede = (f"Score = 100 × exposure × likelihood × impact. Exposure is {e(exposure)}. Likelihood "
            f"multiplies the ease of every step, for example 0.9 for a CVE on the CISA KEV list. Impact is how much "
            f"the crown jewel matters, from 0 to 1. Tiers: critical from {floors['critical']}, high from "
            f"{floors['high']}, medium from {floors['medium']}.")
    legend = ('<div class="legend"><span><i class="sw sw-bar"></i>Path score, 0 to 100</span>'
              '<span><i class="sw sw-ai"></i>AI agent, MCP server, knowledge base or vector database</span></div>')
    items = "".join(_path_item(v, p) for p in v.top)
    body = f'<div class="card">{legend}<ol class="paths">{items}</ol></div>'
    rest = [p for p in paths if not p["top"]]
    if rest:
        trs = "".join(
            f'<tr><td class="n">{p["rank"]}</td><td class="n">{num(p["score"])}</td><td>{level(p["tier"])}</td>'
            f'<td>{e(v.route(p["nodes"]))}</td><td>{"Yes" if p["ai_nodes"] else "No"}</td>'
            f'<td class="n">{num(p["score_without_discovery"]) if p["score_without_discovery"] is not None else "no path"}</td></tr>'
            for p in rest)
        body += (f'<div class="card"><h3>The other {plural(len(rest), "path")}</h3><div class="scroll"><table class="wide">'
                 '<thead><tr><th class="n">Rank</th><th class="n">Score</th><th>Tier</th><th>Route</th>'
                 f'<th>Through AI</th><th class="n">Without discovery</th></tr></thead><tbody>{trs}</tbody></table></div></div>')
    return section("paths", f"Top {len(v.top)} attack paths", lede, body)


def _fixes(v: _View) -> str:
    plan, s = v.r["remediation_plan"], v.s
    if not plan:
        return section("fixes", "Fix these first", "Nothing to fix: no path reaches a crown jewel.", "")
    index, after = s["exposure_index"], s["plan"]["exposure_index_after"]
    lede = (f"{plural(len(plan), 'fix', 'fixes')} take the exposure index from {num(index)} to {num(after)}, "
            f"{MINUS}{s['plan']['reduction_pct']}%. Every path is re-scored after each fix, so each step is the "
            f"best next move.")
    from_ai = sum(1 for x in plan if x["source"] == "discovery")
    if from_ai:
        lede += f" {from_ai} of the {len(plan)} come from AI discovery, which no vulnerability scanner reports."
    if plan[0].get("cvss_rank", 0) > 10:
        lede += f" The first is #{plan[0]['cvss_rank']} on a CVSS-sorted list."

    rows = [f'<div class="hb-row"{tip(f"Today: exposure index {num(index)}", True)}><div class="hb-label">Today</div>'
            f'<div class="hb-track"><span class="hb-fill ref" style="width:100%"></span></div>'
            f'<div class="hb-val">{num(index)}</div></div>']
    for x in plan:
        text = (f"Step {x['step']}: {x['title']}{chr(10)}On {x['asset_name']}{chr(10)}Cuts {num(x['reduction'])} points "
                f"({x['reduction_pct']}%), index after: {num(x['exposure_index_after'])}{chr(10)}Fix: {x['fix']}")
        rows.append(f'<div class="hb-row"{tip(text, True)}><div class="hb-label"><span class="step">{x["step"]}</span>'
                    f'{e(short(x["asset_name"]))}<span class="sub mono">{e(v.label(x["finding"]))}</span></div>'
                    f'<div class="hb-track"><span class="hb-fill" style="width:{pct(x["exposure_index_after"], index)}">'
                    f'</span></div><div class="hb-val">{num(x["exposure_index_after"])}'
                    f'<span class="delta">{MINUS}{num(x["reduction"])}</span></div></div>')
    chart = (f'<div class="card chart"><h3>Exposure index after each fix</h3><div class="hb" role="img" '
             f'aria-label="Exposure index after each fix; the table below has the same numbers.">{"".join(rows)}</div>')
    trs = "".join(
        f'<tr><td class="n">{x["step"]}</td><td><span class="mono">{e(v.label(x["finding"]))}</span>'
        f'<span class="sub">{e(v.title(x["finding"], x["title"]))}</span></td><td>{e(x["asset_name"])}</td>'
        f'<td>{e(x["fix"])}</td>'
        f'<td class="n">{MINUS}{num(x["reduction"])}</td><td class="n">{num(x["exposure_index_after"])}</td>'
        f'<td class="n">{"#" + str(x["cvss_rank"]) if x.get("cvss_rank") else "not a CVE"}</td></tr>' for x in plan)
    chart += ('<div class="scroll"><table class="wide"><thead><tr><th class="n">Step</th><th>Finding</th><th>Asset</th>'
              '<th>What to do</th><th class="n">Cuts</th><th class="n">Index after</th><th class="n">CVSS rank</th></tr>'
              f'</thead><tbody>{trs}</tbody></table></div></div>')

    chokes = v.r["choke_points"][:8]
    trs = "".join(
        f'<tr><td><span class="mono">{e(v.label(c["finding"]))}</span><span class="sub">{e(v.title(c["finding"], c["title"]))}</span></td>'
        f'<td>{e(c["asset_name"])}</td><td class="n">{MINUS}{num(c["reduction"])}</td>'
        f'<td class="n">{len(c["paths_closed"])}</td><td class="n">{len(c["paths_weakened"])}</td>'
        f'<td class="n">{"#" + str(c["cvss_rank"]) if c.get("cvss_rank") else "not a CVE"}</td></tr>' for c in chokes)
    chokes_html = ('<div class="card"><h3>Biggest single fixes</h3><p class="note">What each fix would remove on its own, '
                   'before any other fix. Fixes overlap, which is why the plan above re-scores after each one.</p>'
                   '<div class="scroll"><table class="wide"><thead><tr><th>Finding</th><th>Asset</th>'
                   '<th class="n">Cuts alone</th><th class="n">Paths closed</th><th class="n">Paths weakened</th>'
                   f'<th class="n">CVSS rank</th></tr></thead><tbody>{trs}</tbody></table></div></div>') if chokes else ""
    return section("fixes", "Fix these first", e(lede), chart + chokes_html)


def _cvss(v: _View) -> str:
    view = v.r["baseline"]["cvss_top10"]
    if not view:
        return ""
    off = sum(1 for x in view if not x["on_a_path"])
    lede = f"Sorted by CVSS alone, {off} of the top {len(view)} findings lead to no crown jewel."
    best = v.r["choke_points"][0] if v.r["choke_points"] else None
    extra = ""
    if best and best.get("cvss_rank", 0) > len(view):
        f = v.findings.get(best["finding"], {})
        lede += (f" The single fix that removes the most exposure, {v.label(best['finding'])}, is "
                 f"#{best['cvss_rank']} on that list.")
        extra = (f'<tr class="hl"><td class="n">#{best["cvss_rank"]}</td><td class="mono">{e(f.get("cve"))}</td>'
                 f'<td>{e(best["asset_name"])}</td><td class="n">{e(f.get("intel", {}).get("cvss"))}</td>'
                 f'<td>{"Yes" if f.get("intel", {}).get("kev") else "No"}</td>'
                 f'<td>Yes: the biggest single fix</td></tr>')
    elif best and not best.get("cvss_rank"):
        lede += f" The single fix that removes the most exposure, {v.label(best['finding'])}, is not a CVE at all."
    trs = "".join(
        f'<tr><td class="n">#{x["cvss_rank"]}</td><td class="mono">{e(x["cve"])}</td>'
        f'<td>{e(short(v.name(x["asset"])))}<span class="sub mono">{e(x["asset"])}</span></td>'
        f'<td class="n">{e(x["cvss"])}</td><td>{"Yes" if x["kev"] else "No"}</td>'
        f'<td>{"<span class=yes>✓ Yes</span>" if x["on_a_path"] else "<span class=no>No</span>"}</td></tr>'
        for x in view)
    body = ('<div class="card"><div class="scroll"><table class="mid"><thead><tr><th class="n">CVSS rank</th><th>CVE</th>'
            '<th>Asset</th><th class="n">CVSS</th><th>CISA KEV</th><th>On an attack path</th></tr></thead>'
            f'<tbody>{trs}{extra}</tbody></table></div></div>')
    return section("cvss", "What a CVSS-sorted list would fix first", e(lede), body)


def _where(v: _View, item: dict) -> list[str]:
    kind, out = item["kind"], []
    if kind == "agent":
        out.append(e(PLATFORMS.get(item.get("platform"), words(item.get("platform")))))
        for ch in item.get("channels") or []:
            via = words(ch.get("channel")) or short(v.name(ch.get("asset")))
            out.append(e(f"{ch.get('audience', 'unknown')} input via {via}"))
        tools = item.get("tools") or []
        if tools:
            free = sum(1 for t in tools if not t.get("needs_approval"))
            out.append(e(f"{plural(len(tools), 'tool')}, {free} without approval"))
    elif kind == "knowledge_base":
        store = (item.get("store") or {}).get("type")
        out.append(e(" · ".join(x for x in (PLATFORMS.get(item.get("platform"), ""), words(store)) if x)))
        sources = item.get("sources") or []
        if sources:
            out.append(e("sources: " + ", ".join(f"{s['name']} ({s.get('trust', 'unknown')})" for s in sources)))
    else:
        if item.get("endpoint"):
            out.append(f'<span class="mono">{e(item["endpoint"])}</span>')
        elif item.get("package"):
            out.append(f'<span class="mono">{e(item["package"])}@{e(item.get("version") or "unpinned")}</span>'
                       f' on {e(item.get("host"))}')
        out.append(e(AUTH.get(item.get("auth"), words(item.get("auth")))))
    if item.get("third_party"):
        out.append("third party")
    return out


def _flag(f: dict) -> str:
    lines = []
    for line in f.get("evidence", []):
        if line.startswith(UNTRUSTED):
            quoted = line[len(UNTRUSTED):].strip()
            if len(quoted) > 1 and quoted[0] == quoted[-1] == '"':
                quoted = quoted[1:-1]
            lines.append(f'<li>Excerpt, untrusted and not followed:<span class="untrusted">{e(quoted)}</span></li>')
        else:
            lines.append(f"<li>{e(line)}</li>")
    fws = " ".join(_technique(i) for ids in f.get("frameworks", {}).values() for i in ids)
    return (f'<li><details><summary>{level(f["severity"])} <span class="mono">{e(f.get("rule"))}</span> '
            f'{e(f["title"])}</summary><div class="flag-body"><ul>{"".join(lines)}</ul>'
            f'<p><strong>Fix:</strong> {e(f.get("remediation"))}</p>'
            f'{f"<p class=fws>{fws}</p>" if fws else ""}</div></details></li>')


def _inventory(v: _View) -> str:
    s = v.s
    by_asset = defaultdict(list)
    for f in v.flags:
        by_asset[f["asset"]].append(f)
    sev = Counter(f["severity"] for f in v.flags)
    lede = (f"{plural(s['ai_components'], 'AI component')} found, {s['ai_not_registered']} of them in no inventory. "
            f"{plural(len(v.flags), 'risk flag')}: " + ", ".join(f"{sev[k]} {k}" for k in LEVELS if sev[k]) + ".")
    rows = []
    for item in v.r["inventory"]:
        flags = sorted(by_asset.get(item["id"], []), key=lambda f: (_rank(f["severity"]), f["id"]))
        status = ('Listed' if item["registered"] else '<span class="shadow">Not in any inventory</span>')
        flag_html = (f'<ul class="flags">{"".join(_flag(f) for f in flags)}</ul>' if flags
                     else '<span class="none">none</span>')
        rows.append(f'<tr><td><strong>{e(item["name"])}</strong><span class="sub mono">{e(item["id"])}</span></td>'
                    f'<td class="kind">{e(KIND_LABELS.get(item["kind"], item["kind"]))}</td><td>{status}</td>'
                    f'<td class="where">{"<br>".join(_where(v, item))}</td><td>{flag_html}</td></tr>')
    # flags raised on assets that are not AI components (a vulnerable MCP client on laptops, for example)
    listed = {i["id"] for i in v.r["inventory"]}
    others = [f for f in v.flags if f["asset"] not in listed]
    for asset in sorted({f["asset"] for f in others}):
        flags = [f for f in others if f["asset"] == asset]
        rows.append(f'<tr><td><strong>{e(v.name(asset))}</strong><span class="sub mono">{e(asset)}</span></td>'
                    f'<td>Host</td><td>Listed</td><td class="where">MCP client configuration</td>'
                    f'<td><ul class="flags">{"".join(_flag(f) for f in flags)}</ul></td></tr>')
    body = ('<div class="card"><p class="note">Open a flag for its evidence, the fix and the framework IDs it maps to.</p>'
            '<div class="scroll"><table class="inv"><thead><tr><th>Component</th><th>Kind</th><th>Inventory</th>'
            f'<th>Where and access</th><th>Flags</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div></div>')
    return section("ai", "AI components found by discovery", e(lede), body)


def _rank(severity: str) -> int:
    return LEVELS.index(severity) if severity in LEVELS else len(LEVELS)


def _describe_only(request: str) -> bool:
    method, _, rest = request.partition(" ")
    if method == "POST":
        m = re.search(r"\(([^)]+)\)\s*$", rest)
        return bool(m) and m.group(1) in ALLOWED_RPC
    if method == "GET":
        path = urlsplit(rest.split(" ")[0]).path
        return any(path.endswith(p) for p in VECTOR_PROBES.values())
    return False


def _detail(text: str | None) -> str:
    """'auth_required' -> 'auth required'; free text is left alone."""
    return words(text) if text and re.fullmatch(r"[a-z_]+", text) else (text or "")


def _method(v: _View) -> str:
    d = v.r["discovery"]
    src, requests, leads = d["sources"], d["requests"], d["leads"]
    ok = sum(1 for q in requests if _describe_only(q["request"]))
    outside = [lead for lead in leads if lead["status"] == "out_of_scope"]
    scope = src.get("scope", {})
    lede = (f"Discovery read {plural(len(src.get('config_files', [])), 'MCP client config file')} and "
            f"{plural(len(src.get('cloud_exports', [])), 'cloud AI export')}, then sent "
            f"{plural(len(requests), 'read-only request')} to endpoints inside the scope list. "
            f"{ok} of {len(requests)} in the request log are describe-only calls.")

    def files(items):
        return "".join(f"<li>{e(x)}</li>" for x in items) or "<li>none</li>"

    read = (f'<div class="card"><h3>What it read</h3><p class="note">MCP client configs</p>'
            f'<ul class="files">{files(src.get("config_files", []))}</ul>'
            f'<p class="note">Cloud AI exports</p><ul class="files">{files(src.get("cloud_exports", []))}</ul>'
            + (f'<p class="note">Could not read</p><ul class="files">{files(src["errors"])}</ul>' if src.get("errors") else "")
            + "</div>")
    nets = ", ".join(scope.get("networks", []) + scope.get("hosts", [])) or "none"
    reqs = "".join(f'<tr><td class="mono">{e(q["request"])}</td><td class="n">{e(q["result"])}</td></tr>' for q in requests)
    asked = (f'<div class="card"><h3>What it asked</h3><p>Scope: <span class="mono">{e(nets)}</span>, at most '
             f'{e(scope.get("max_requests"))} requests. Transport: {e(src.get("transport"))}.</p>'
             f'<details><summary>Request log ({len(requests)})</summary><div class="scroll"><table class="mid">'
             f'<thead><tr><th>Request</th><th class="n">Result</th></tr></thead><tbody>{reqs}</tbody></table></div>'
             '</details></div>')
    outcome = {"probed": "probed", "out_of_scope": "outside scope, not contacted"}
    lrows = "".join(
        f'<tr><td class="mono">{e(lead["url"])}</td><td>{e("; ".join(lead["reasons"]))}</td>'
        f'<td>{e(outcome.get(lead["status"], words(lead["status"])))}: {e(_detail(lead.get("detail")))}</td></tr>'
        for lead in leads)
    leads_html = ('<div class="card"><h3>Leads it followed</h3><div class="scroll"><table class="wide"><thead><tr>'
                  f'<th>Endpoint</th><th>Why it was a lead</th><th>Outcome</th></tr></thead><tbody>{lrows}</tbody>'
                  '</table></div></div>')
    vectors = ", ".join(f"{k.capitalize()} GET {p}" for k, p in VECTOR_PROBES.items())
    promises = [
        f"MCP servers were only asked to describe themselves ({', '.join(ALLOWED_RPC)}). No tool was called.",
        f"Vector databases were only asked to list their collections ({vectors}).",
        "Redirects are not followed. An endpoint outside the scope list is recorded as a lead but never contacted "
        f"({len(outside)} this run).",
        "Secret values in config files are never stored. Only the variable name is kept as evidence.",
        "Tool descriptions and documents are untrusted input. Excerpts on this page are inert text.",
    ]
    safety = ('<div class="card"><h3>Safety rules the code enforces</h3><ul class="promises">'
              + "".join(f"<li>{e(p)}</li>" for p in promises) + "</ul></div>")
    notes = (f'<div class="card"><h3>Agent notes</h3><p class="narrative">{e(d["narrative"])}</p></div>'
             if d.get("narrative") else "")
    body = f'<div class="cols">{read}{asked}</div>{leads_html}{safety}{notes}'
    return section("method", "How discovery worked", e(lede), body)


def _footer(v: _View) -> str:
    used = frameworks_used(v.r)
    rows = "".join(
        f'<div class="fw-row"><strong>{e(FRAMEWORK_TITLES.get(fw, fw))}</strong>{" ".join(_technique(i) for i in ids)}</div>'
        for fw, ids in sorted(used.items(), key=lambda kv: list(FRAMEWORK_TITLES).index(kv[0])
                              if kv[0] in FRAMEWORK_TITLES else 99))
    feeds = v.r["feeds"]
    return (f'<footer><div class="fw-list"><h3>Frameworks cited</h3>{rows}</div>'
            f'<p>Threat intelligence: CISA KEV catalog {e(feeds["kev_catalog_version"])} '
            f'({e(feeds["kev_entries_used"])} entries used), {e(feeds["cve_records"])} CVE records, EPSS '
            f'{e(feeds["epss"])}.</p><p>The same data is available as JSON (<span class="mono">--format json</span>), '
            f'checked against <span class="mono">schema/scan-result.schema.json</span> version '
            f'{e(v.r["schema_version"])}.</p></footer>')


# --- page ---------------------------------------------------------------------------

def render_html(report: dict, *, standalone: bool = True) -> str:
    """The dashboard as a full HTML document, or as a page fragment (no doctype,
    head or body) for hosts that wrap pages in their own skeleton."""
    v = _View(report)
    parts = [_header(v), _kpis(v), _nav(v), "<main>", _jewels(v), _paths(v), _fixes(v), _cvss(v)]
    if v.discovery:
        parts += [_inventory(v), _method(v)]
    parts += ["</main>", _footer(v)]
    title = f"{report['environment']['name']} attack paths"
    body = BREAK_AFTER.sub(r"\1\n", "".join(parts))
    page = (f'<div class="page">\n{body}</div>\n<div id="tip" role="tooltip" hidden></div>\n'
            f"<script>{JS}</script>")
    if not standalone:
        return (f'<title>{e(title)}</title>\n<meta name="claude:viewport-fit-sides" content="cover">\n'
                f"<style>{CSS}</style>\n{page}\n")
    return ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
            f"<title>{e(title)}</title>\n<style>{CSS}</style>\n</head>\n<body>\n{page}\n</body>\n</html>\n")


CSS = """
:root{--page:#f9f9f7;--surface:#fcfcfb;--sunken:#f0efea;--ink:#0b0b0b;--ink-2:#52514e;--muted:#898781;
--grid:#e1e0d9;--axis:#c3c2b7;--border:#e1e0d9;--blue:#2a78d6;--violet:#6250d6;--gray-mark:#898781;
--critical:#d03b3b;--serious:#ec835a;--warning:#fab219;--good:#0ca30c;--tip-bg:#1f1f1e;--tip-ink:#f0efec;
--sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,"SF Mono","Cascadia Mono","Segoe UI Mono",Menlo,Consolas,"Liberation Mono",monospace}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--page:#0d0d0d;--surface:#1a1a19;--sunken:#242422;
--ink:#f0efec;--ink-2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;--border:#2c2c2a;--blue:#3987e5;
--violet:#9085e9;--gray-mark:#898781;--tip-bg:#f0efec;--tip-ink:#0b0b0b;color-scheme:dark}}
:root[data-theme="dark"]{--page:#0d0d0d;--surface:#1a1a19;--sunken:#242422;--ink:#f0efec;--ink-2:#c3c2b7;
--muted:#898781;--grid:#2c2c2a;--axis:#383835;--border:#2c2c2a;--blue:#3987e5;--violet:#9085e9;--gray-mark:#898781;
--tip-bg:#f0efec;--tip-ink:#0b0b0b;color-scheme:dark}
*,*::before,*::after{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.55 var(--sans);-webkit-text-size-adjust:100%}
.page{max-width:72rem;margin:0 auto;padding-block:2.5rem 4rem;padding-left:max(16px,env(safe-area-inset-left,0px));
padding-right:max(16px,env(safe-area-inset-right,0px));display:grid;gap:2rem}
main{display:grid;gap:3.25rem;min-width:0}
h1,h2,h3{margin:0;text-wrap:balance}
h1{font-size:2.25rem;line-height:1.1;font-weight:700;letter-spacing:-.02em}
h2{font-size:1.375rem;line-height:1.3;font-weight:650;letter-spacing:-.01em}
h3{font-size:.75rem;line-height:1.4;font-weight:650;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-2)}
p{margin:0}
a{color:inherit}
.mono,code{font-family:var(--mono);font-size:.8125rem}
.sub{display:block;font-size:.75rem;color:var(--muted);font-weight:400}
.none{color:var(--muted)}
.note{font-size:.8125rem;color:var(--ink-2)}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.eyebrow{font-family:var(--mono);font-size:.75rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
header.top{display:grid;gap:.75rem}
.title-row{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem 1rem}
.pill{font-size:.75rem;font-weight:600;padding:2px 10px;border:1px solid var(--axis);border-radius:999px;color:var(--ink-2)}
.headline{font-size:1.125rem;line-height:1.5;max-width:62ch}
.meta{display:flex;flex-wrap:wrap;gap:.25rem 1.25rem;font-size:.8125rem;color:var(--muted)}
.toc{display:flex;flex-wrap:wrap;gap:.25rem 1.5rem;font-size:.875rem;padding-block:.65rem;border-block:1px solid var(--border)}
.toc a{color:var(--ink-2);text-decoration:none}
.toc a:hover{color:var(--ink);text-decoration:underline}
section{display:grid;gap:1rem;min-width:0;scroll-margin-top:1rem}
.sec-head{display:grid;gap:.4rem}
.lede{max-width:68ch;color:var(--ink-2)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.25rem;min-width:0;display:grid;gap:.9rem;align-content:start}
.kpis{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1rem 1.25rem;display:grid;gap:.3rem;align-content:start;min-width:0}
.kpi.hero{grid-column:1/-1;grid-template-columns:auto minmax(0,1fr);gap:.75rem 2.5rem;align-items:center;padding:1.25rem 1.5rem}
.kpi-body{display:grid;gap:.35rem;min-width:0;max-width:40rem}
.big{font-size:3.5rem;line-height:1;font-weight:700;letter-spacing:-.03em;font-variant-numeric:tabular-nums}
.of{display:block;font-size:.875rem;color:var(--muted);margin-top:.35rem}
.kpi .num{font-size:1.875rem;line-height:1.15;font-weight:700;letter-spacing:-.01em;font-variant-numeric:tabular-nums}
.kpi-label{font-weight:650}
.kpi-note{font-size:.8125rem;color:var(--ink-2)}
.meter{display:flex;gap:2px;height:14px;margin-top:.4rem}
.meter .seg{display:block;height:100%;flex:none}
.seg.base{background:var(--gray-mark)}
.seg.with{background:var(--blue)}
.seg.end,.seg.rest{border-radius:0 4px 4px 0}
.seg.rest{flex:1 1 auto;background:var(--sunken)}
.legend{display:flex;flex-wrap:wrap;gap:.35rem 1.25rem;font-size:.8125rem;color:var(--ink-2)}
.legend span{display:inline-flex;align-items:center;gap:.45rem}
.sw{display:inline-block;flex:none;width:10px;height:10px;border-radius:50%}
.sw-base{background:var(--gray-mark)}
.sw-with{background:var(--blue)}
.sw-none{border:2px solid var(--gray-mark)}
.sw-bar{width:16px;height:8px;border-radius:0 3px 3px 0;background:var(--blue)}
.sw-ai{width:8px;height:8px;border-radius:1px;transform:rotate(45deg);background:var(--violet)}
.db{display:grid;gap:2px}
.db-row,.db-axis{display:grid;grid-template-columns:12.5rem minmax(0,1fr);gap:1rem;align-items:center}
.db-row{padding-block:5px;border-radius:6px}
.db-label{font-size:.875rem;line-height:1.3;min-width:0;font-weight:600}
.db-track{position:relative;height:30px;margin-right:3rem;border-right:1px solid var(--grid);
background:linear-gradient(to right,var(--grid) 1px,transparent 1px) 0 0/20% 100% repeat-x}
.db-link{position:absolute;top:50%;height:2px;margin-top:-1px;background:var(--axis)}
.db-dot{position:absolute;top:50%;width:12px;height:12px;margin:-6px 0 0 -6px;border-radius:50%}
.db-dot.base{background:var(--gray-mark)}
.db-dot.none{background:var(--surface);border:2px solid var(--gray-mark)}
.db-dot.with{background:var(--blue);box-shadow:0 0 0 2px var(--surface)}
.db-val{position:absolute;top:50%;transform:translate(12px,-50%);font-size:.8125rem;font-weight:650;white-space:nowrap;font-variant-numeric:tabular-nums}
.db-val.lo{transform:translate(calc(-100% - 12px),-50%);font-weight:400;color:var(--ink-2)}
.db-empty{position:absolute;top:50%;left:10px;transform:translateY(-50%);font-size:.8125rem;color:var(--muted)}
.ticks{position:relative;height:1.15rem;margin-right:3rem;font-size:.75rem;color:var(--muted);font-variant-numeric:tabular-nums}
.ticks span{position:absolute;top:0;transform:translateX(-50%);white-space:nowrap}
.ticks.bands span{font-size:.6875rem;letter-spacing:.07em;text-transform:uppercase}
.axis-title{font-size:.75rem;color:var(--muted)}
.paths{list-style:none;margin:0;padding:0;display:grid}
.path{display:grid;grid-template-columns:2rem minmax(0,1fr);gap:.25rem 1rem;padding-block:1.1rem;border-top:1px solid var(--border)}
.path:first-child{border-top:0;padding-top:.25rem}
.path:last-child{padding-bottom:0}
.rank{font-size:1.125rem;line-height:1.45;font-weight:700;color:var(--muted);font-variant-numeric:tabular-nums}
.path-main{display:grid;gap:.6rem;min-width:0}
.path-title{font-weight:650;font-size:1rem;line-height:1.4}
.path-title .arrow{color:var(--muted);font-weight:400}
.score{display:grid;grid-template-columns:18rem 3rem auto;align-items:center;gap:.75rem;justify-content:start;width:fit-content;max-width:100%;border-radius:4px}
.track{display:block;height:10px;background:var(--sunken);border-radius:0 4px 4px 0}
.fill{display:block;height:100%;background:var(--blue);border-radius:0 4px 4px 0}
.score .val{font-weight:700;text-align:right;font-variant-numeric:tabular-nums}
.lvl{display:inline-flex;align-items:center;gap:6px;font-size:.8125rem;font-weight:600;white-space:nowrap}
.lvl i{flex:none;width:9px;height:9px;border-radius:50%;background:var(--c,var(--muted))}
.l-critical{--c:var(--critical)}.l-high{--c:var(--serious)}.l-medium{--c:var(--warning)}.l-low{--c:var(--muted)}
.chain{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;align-items:center;gap:6px}
.chain li{display:inline-flex;align-items:center;gap:6px;min-width:0;max-width:100%}
.chain li+li::before{content:"\\2192";color:var(--muted)}
.chip{display:inline-flex;align-items:center;gap:6px;padding:1px 9px;border:1px solid var(--axis);border-radius:999px;font-size:.8125rem;line-height:1.55;background:var(--surface);min-width:0;overflow-wrap:anywhere}
.chip.ai{border:1.5px solid var(--violet)}
.chip.ai::before{content:"";flex:none;width:7px;height:7px;border-radius:1px;transform:rotate(45deg);background:var(--violet)}
.chip.jewel{font-weight:650}
.tags{display:flex;flex-wrap:wrap;gap:6px}
.tag{font-size:.75rem;padding:1px 8px;border-radius:4px;background:var(--sunken);color:var(--ink-2);white-space:nowrap}
.tag.strong{color:var(--ink);font-weight:600}
details>summary{cursor:pointer;font-size:.875rem;color:var(--ink-2);width:fit-content;max-width:100%}
details>summary:hover{color:var(--ink)}
details[open]>summary{margin-bottom:.6rem}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;min-width:0}
table{width:100%;border-collapse:collapse;font-size:.875rem}
table.wide{min-width:48rem}
table.mid{min-width:34rem}
table.inv{min-width:60rem}
th{font-size:.6875rem;font-weight:650;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);text-align:left;padding:.45rem .7rem;border-bottom:1px solid var(--axis);vertical-align:bottom;white-space:nowrap}
td.kind{white-space:nowrap}
td{padding:.55rem .7rem;border-bottom:1px solid var(--grid);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
th:first-child,td:first-child{padding-left:0}
th:last-child,td:last-child{padding-right:0}
.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
tr.hl td{background:var(--sunken);font-weight:600}
tr.hl td:first-child{padding-left:.7rem}
.yes{font-weight:650}
.no{color:var(--muted)}
.steps td:nth-child(3){min-width:18rem}
.hb{display:grid;gap:4px}
.hb-row{display:grid;grid-template-columns:minmax(0,15rem) minmax(0,1fr) 5.5rem;gap:1rem;align-items:center;padding-block:4px;border-radius:4px}
.hb-label{font-size:.875rem;line-height:1.3;min-width:0;font-weight:600}
.hb-label .step{display:inline-block;min-width:1.4rem;color:var(--muted);font-variant-numeric:tabular-nums}
.hb-track{height:18px}
.hb-fill{display:block;height:100%;background:var(--blue);border-radius:0 4px 4px 0}
.hb-fill.ref{background:var(--gray-mark)}
.hb-val{text-align:right;font-weight:650;font-size:.875rem;font-variant-numeric:tabular-nums;white-space:nowrap}
.hb-val .delta{display:block;font-size:.75rem;font-weight:400;color:var(--ink-2)}
.shadow{display:inline-block;font-size:.75rem;font-weight:650;padding:1px 8px;border:1.5px dashed var(--ink-2);border-radius:4px;white-space:nowrap}
.where{font-size:.8125rem;color:var(--ink-2);min-width:14rem}
.flags{list-style:none;margin:0;padding:0;display:grid;gap:.45rem;min-width:20rem}
.flags summary{color:var(--ink);font-size:.8125rem;line-height:1.45}
.flags summary .lvl{margin-right:.25rem}
.flag-body{display:grid;gap:.45rem;margin:.1rem 0 .4rem 1.1rem;font-size:.8125rem;color:var(--ink-2)}
.flag-body ul{margin:0;padding-left:1.1rem;display:grid;gap:.25rem}
.untrusted{display:block;margin-top:.3rem;padding:.45rem .65rem;font-family:var(--mono);font-size:.75rem;line-height:1.5;color:var(--ink);background:var(--sunken);border-left:3px solid var(--axis);white-space:pre-wrap;overflow-wrap:anywhere}
.fws{display:flex;flex-wrap:wrap;gap:4px}
.fw{display:inline-block;font-family:var(--mono);font-size:.71875rem;padding:0 6px;border:1px solid var(--border);border-radius:4px;white-space:nowrap;color:var(--ink-2)}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,20rem),1fr));gap:1rem}
.files{margin:0;padding-left:1.1rem;font-family:var(--mono);font-size:.8125rem;overflow-wrap:anywhere}
.promises{list-style:none;margin:0;padding:0;display:grid;gap:.5rem;max-width:72ch}
.promises li{display:grid;grid-template-columns:1.25rem minmax(0,1fr);gap:.4rem}
.promises li::before{content:"\\2713";font-weight:700;color:var(--good)}
.narrative{white-space:pre-line;max-width:72ch}
footer{display:grid;gap:.75rem;font-size:.8125rem;color:var(--ink-2);border-top:1px solid var(--border);padding-top:1.5rem}
.fw-list{display:grid;gap:.5rem}
.fw-row{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px}
.fw-row strong{color:var(--ink);font-weight:600;margin-right:.25rem}
#tip{position:fixed;left:0;top:0;z-index:30;max-width:min(24rem,calc(100vw - 16px));padding:.5rem .7rem;border-radius:6px;background:var(--tip-bg);color:var(--tip-ink);font-size:.8125rem;line-height:1.45;white-space:pre-line;pointer-events:none;box-shadow:0 6px 20px rgb(0 0 0/.22)}
[data-tip]:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
@media (max-width:760px){.kpis{grid-template-columns:minmax(0,1fr)}.kpi.hero{grid-template-columns:minmax(0,1fr)}.big{font-size:3rem}}
@media (max-width:640px){h1{font-size:1.875rem}.db-row,.db-axis{grid-template-columns:minmax(0,1fr);gap:.2rem}
.db-axis>:first-child{display:none}.hb-row{grid-template-columns:minmax(0,1fr) 4.75rem;gap:.3rem .75rem}
.hb-label{grid-column:1/-1}.path{grid-template-columns:1.5rem minmax(0,1fr);gap:.25rem .6rem}.card{padding:1rem}
.score{grid-template-columns:minmax(0,1fr) 2.75rem auto;width:100%}}
"""

JS = """
(function () {
  var tip = document.getElementById("tip");
  if (!tip) return;
  function target(ev) { return ev.target && ev.target.closest ? ev.target.closest("[data-tip]") : null; }
  function show(el, x, y) {
    tip.textContent = el.getAttribute("data-tip");
    tip.hidden = false;
    var w = tip.offsetWidth, h = tip.offsetHeight, left = x + 14, top = y + 16;
    if (left + w > window.innerWidth - 8) left = Math.max(8, x - w - 14);
    if (top + h > window.innerHeight - 8) top = Math.max(8, y - h - 16);
    tip.style.left = left + "px";
    tip.style.top = top + "px";
  }
  function hide() { tip.hidden = true; }
  function pointer(ev) { var el = target(ev); if (el) show(el, ev.clientX, ev.clientY); else hide(); }
  document.addEventListener("pointermove", pointer);
  document.addEventListener("pointerdown", pointer);
  document.addEventListener("focusin", function (ev) {
    var el = target(ev);
    if (!el) { hide(); return; }
    var r = el.getBoundingClientRect();
    show(el, r.left, r.bottom);
  });
  document.addEventListener("focusout", hide);
  document.addEventListener("keydown", function (ev) { if (ev.key === "Escape") hide(); });
  window.addEventListener("scroll", hide, { passive: true });
})();
"""
