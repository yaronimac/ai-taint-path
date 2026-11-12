"""A one-file HTML dashboard for a scan report (`scan --format html`).

The page has four views, the way AI security and exposure-management consoles
present the same data: an Overview (three answers, the attack-path graph and the
first fixes), the ranked Attack paths, the Fix plan, and the AI inventory with
its toxic combinations. How the report was made sits in a collapsed panel below.

The page is self-contained and makes no network requests: the styles, the graph
(inline SVG drawn here) and the small script are inline, and text uses the
reader's system fonts. Everything that came from the scanned environment is
HTML-escaped, including tool descriptions and document excerpts, which discovery
treats as untrusted. The script only toggles attributes and classes and writes
text with textContent. Without the script every view shows, one after another.
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
BREAK_AFTER = re.compile(r"(</(?:div|section|header|footer|nav|main|table|thead|tbody|tr|ul|ol|li|details|g|svg|button)>"
                         r"|<path [^>]*/>)")
LEVELS = ("critical", "high", "medium", "low")
UNTRUSTED = "excerpt (untrusted, not followed): "
PLATFORMS = {"azure_ai_foundry": "Azure AI Foundry", "aws_bedrock": "Amazon Bedrock",
             "claude_code": "Claude Code", "desktop": "Desktop AI clients"}
AUTH = {"none": "no authentication", "required": "asks for credentials", "local": "local process",
        "unknown": "not probed (out of scope)"}
ENTRY_WORDS = {"internet": "the entry point faces the internet", "user_action": "someone has to open or click something"}
KIND_PLURAL = {"agent": "AI agents", "mcp_server": "MCP servers", "knowledge_base": "Knowledge bases",
               "vector_store": "Vector databases"}


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


def dot(name: str) -> str:
    return f'<span class="lvl l-{e(name)}" title="{e(name.capitalize())}"><i aria-hidden="true"></i></span>'


def when(stamp: str) -> str:
    try:
        d = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return stamp
    return f"{d.day} {d:%b %Y, %H:%M} UTC"


def wrap(text: str, width: int = 17, lines: int = 2) -> list[str]:
    """Break a label into at most `lines` lines of about `width` characters."""
    out: list[str] = []
    for word in text.split():
        if out and len(out[-1]) + 1 + len(word) <= width:
            out[-1] += " " + word
        else:
            out.append(word)
    if len(out) > lines:
        out = out[:lines]
        out[-1] = out[-1][: width - 1].rstrip() + "…"
    return [x if len(x) <= width else x[: width - 1] + "…" for x in out] or [""]


def panel(pid: str, title: str, lede: str, body: str, *, heading: bool = True) -> str:
    head = (f'<div class="sec-head"><h2>{e(title)}</h2>{f"<p class=lede>{lede}</p>" if lede else ""}</div>'
            if heading else f'<h2 class="vh">{e(title)}</h2>')
    return (f'<section id="{pid}" class="panel" role="tabpanel" aria-labelledby="tab-{pid}" tabindex="-1">'
            f'{head}{body}</section>')


def seg(group: str, options: list[tuple[str, str]], label: str) -> str:
    """A segmented control that shows one [data-view] of its group at a time."""
    buttons = "".join(f'<button type="button" data-show="{e(k)}" aria-pressed="{"true" if i == 0 else "false"}">'
                      f'{t}</button>' for i, (k, t) in enumerate(options))
    return f'<div class="seg" role="group" aria-label="{e(label)}" data-group="{e(group)}">{buttons}</div>'


def filters(target: str, options: list[tuple[str, str, int]], label: str) -> str:
    """Filter chips for the list with id `target`; items carry data-tags."""
    buttons = "".join(f'<button type="button" data-f="{e(k)}" aria-pressed="{"true" if i == 0 else "false"}">'
                      f'{e(t)} <span class="count">{n}</span></button>' for i, (k, t, n) in enumerate(options) if n or i == 0)
    return f'<div class="chips" role="group" aria-label="{e(label)}" data-list="{e(target)}">{buttons}</div>'


class _View:
    """The report plus the lookups every view needs."""

    def __init__(self, report: dict):
        self.r = report
        self.s = report["summary"]
        self.discovery = bool(report["settings"]["discovery"])
        self.nodes = {n["id"]: n for n in report["nodes"]}
        self.ai = {n["id"] for n in report["nodes"] if n["kind"] in AI_KINDS}
        self.findings = {f["id"]: f for f in report["findings"]}
        self.flags = [f for f in report["findings"] if f.get("source") == "discovery"]
        self.top = [p for p in report["paths"] if p["top"]]
        self.toxic = report.get("toxic_combinations", [])
        self.tc = {c["id"]: c for c in self.toxic}
        self.inventory = {i["id"]: i for i in report["inventory"]}

    def name(self, node_id: str | None) -> str:
        node = self.nodes.get(node_id or "")
        return node["name"] if node else (node_id or "")

    def owner(self, node_id: str | None) -> str | None:
        return self.nodes.get(node_id or "", {}).get("owner")

    def route(self, nodes: list[str]) -> str:
        return " → ".join(short(self.name(n)) for n in nodes)

    def title(self, finding_id: str, title: str) -> str:
        """A finding title without the 'CVE-2024-21887: ' prefix that fid() already shows."""
        cve = self.findings.get(finding_id, {}).get("cve")
        prefix = f"{cve}: " if cve else ""
        return title[len(prefix):] if prefix and title.startswith(prefix) else title

    def fid(self, finding_id: str, brief: bool = False) -> str:
        """A finding's own ID first (unique), then what kind it is: the CVE or the discovery rule."""
        f = self.findings.get(finding_id, {})
        if brief:
            return f'<span class="fid mono"{tip(f.get("title", finding_id))}>{e(finding_id)}</span>'
        if f.get("cve"):
            return (f'<span class="fid"{tip(f.get("title", finding_id))}><span class="mono">{e(f["cve"])}</span>'
                    f'<span class="rule">{e(finding_id)}</span></span>')
        rule = f'<span class="rule">rule {e(f["rule"])}</span>' if f.get("rule") else ""
        return f'<span class="fid"{tip(f.get("title", finding_id))}><span class="mono">{e(finding_id)}</span>{rule}</span>'

    def breaks(self, finding_id: str) -> list[str]:
        """Toxic combinations that a fix for this finding breaks."""
        return [c["id"] for c in self.toxic if finding_id in c["findings"]]

    def jewel_rows(self) -> list[dict]:
        worst, base = {}, {}
        for p in self.r["paths"]:  # ranked, so the first path to a target is its worst
            worst.setdefault(p["target"], p)
        for p in self.r["baseline"]["paths"]:
            target = p["id"].split("->", 1)[1]
            if target not in base or p["score"] > base[target]["score"]:
                base[target] = p
        rows = []
        for n in self.r["nodes"]:
            if n["crown_jewel"]:
                w, b = worst.get(n["id"]), base.get(n["id"])
                rows.append({"id": n["id"], "name": n["name"], "path": w,
                             "with": w["score"] if w else None, "base": b["score"] if b else None})
        rows.sort(key=lambda x: (-(x["with"] or 0), -(x["base"] or 0), x["id"]))
        return rows


# --- header and tabs ----------------------------------------------------------------

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
    meta.append(f"CISA KEV catalog {feeds['kev_catalog_version']}")
    return (f'<header class="top"><p class="eyebrow">AI attack-path report</p>'
            f'<div class="title-row"><h1>{e(env["name"])}</h1>{pill}</div>'
            f'<p class="headline">{e(headline)}</p>'
            f'<p class="meta">{"".join(f"<span>{e(m)}</span>" for m in meta)}</p></header>')


def _tabs(v: _View) -> str:
    tabs = [("overview", "Overview", None), ("paths", "Attack paths", len(v.r["paths"])),
            ("fixes", "Fix plan", len(v.r["remediation_plan"]))]
    if v.discovery:
        tabs.append(("ai", "AI inventory", v.s["ai_components"]))
    links = "".join(
        f'<a role="tab" id="tab-{k}" href="#{k}" aria-controls="{k}" aria-selected="{"true" if i == 0 else "false"}">'
        f'{e(t)}{f" <span class=count>{n}</span>" if n is not None else ""}</a>' for i, (k, t, n) in enumerate(tabs))
    return f'<nav class="tabs" role="tablist" aria-label="Report views">{links}</nav>'


# --- overview -----------------------------------------------------------------------

def _cards(v: _View) -> str:
    s = v.s
    rows = v.jewel_rows()

    def card(big: str, line: str, note: str, cls: str = "") -> str:
        return (f'<div class="kpi{cls}"><span class="num">{e(big)}</span><p class="kpi-label">{e(line)}</p>'
                f'<p class="kpi-note">{e(note)}</p></div>')

    reach = s["crown_jewels_reachable"]
    if v.discovery:
        only_ai = sum(1 for x in rows if x["base"] is None and x["with"] is not None)
        worse = sum(1 for x in rows if x["base"] is not None and x["with"] is not None and x["with"] > x["base"] + 0.05)
        note = (f"{only_ai} of them only through AI" + (f", {worse} more made worse by it" if worse else "")
                if only_ai else f"AI makes {worse} of them easier to reach" if worse else "AI adds no new route")
    else:
        note = f"{plural(s['paths_by_tier']['critical'], 'critical path')}"
    cards = [card(f"{reach} of {s['crown_jewels']} crown jewels", "reachable from an entry point", note)]

    chokes = v.r["choke_points"]
    if chokes:
        c = chokes[0]
        closed = len(c["paths_closed"])
        big = f"1 fix closes {closed} paths" if closed > 1 else f"1 fix cuts {num(c['reduction'])} points"
        cards.append(card(big, f"Top choke point: {short(c['asset_name'])}",
                          f"cuts {c['reduction_pct']:g}% of the exposure index on its own"))
    else:
        cards.append(card("No choke point", "nothing gates a path", "no path reaches a crown jewel"))

    if v.discovery:
        sev = Counter(f["severity"] for f in v.flags)
        cards.append(card(f"{s['ai_not_registered']} shadow AI components",
                          f"in no inventory, of {s['ai_components']} found",
                          f"{plural(len(v.toxic), 'toxic combination')}, {sev['critical']} critical flags"))
    else:
        cards.append(card(f"{s['findings_on_paths']} of {s['findings_open']} findings", "sit on an attack path",
                          "the rest lead to no crown jewel"))
    return f'<div class="kpis">{"".join(cards)}</div>'


def _strip(v: _View) -> str:
    s = v.s
    index, top = s["exposure_index"], s["exposure_index_max"]
    base = s["without_discovery"]["exposure_index"]
    added = round(max(0.0, index - base), 1)
    plan = s["plan"]
    explain = (f"Exposure index: the worst attack-path score to each of the {s['crown_jewels']} crown jewels, added "
               f"up. Each path scores 0 to 100, so the maximum is {top}. Lower is better.")
    if v.discovery:
        segs = (f'<span class="seg-bar base" style="width:{pct(base, top)}"></span>'
                f'<span class="seg-bar with end" style="width:{pct(added, top)}"></span><span class="seg-bar rest"></span>')
        parts = [f"{num(base)} on scanner data alone", f"+{num(added)} added by AI discovery"]
    else:
        segs = f'<span class="seg-bar base end" style="width:{pct(index, top)}"></span><span class="seg-bar rest"></span>'
        parts = ["scanner, CMDB and posture data only"]
    if plan["fixes"]:
        parts.append(f"{num(plan['exposure_index_after'])} after the {plural(plan['fixes'], 'fix', 'fixes')} "
                     f"below ({MINUS}{plan['reduction_pct']}%)")
    aria = f"Exposure index {num(index)} of {top}" + (f": {num(base)} from scanner data, {num(added)} added by AI discovery"
                                                      if v.discovery else "")
    return (f'<div class="strip"{tip(explain, True)}><p><span class="strip-label">Exposure index</span> '
            f'<strong class="strip-num">{num(index)}</strong> <span class="of">of {top}</span></p>'
            f'<div class="meter" role="img" aria-label="{e(aria)}">{segs}</div>'
            f'<p class="strip-note">{e(" · ".join(parts))}</p></div>')


# The attack-path graph: a layered drawing (entry points left, crown jewels where their routes end),
# with long links routed through empty slots so a line never runs behind a box it does not touch.
NODE_W, COL, PAD = 128, 146, 12
ROW_SEP, DUMMY_SEP = 14, 8


def _layout(routes: dict[str, list[str]], order: list[str]):
    links = list(dict.fromkeys((a, b) for ns in routes.values() for a, b in zip(ns, ns[1:])))
    layer = {n: 0 for n in order}
    for _ in range(len(order)):
        moved = False
        for a, b in links:
            if layer[b] < layer[a] + 1 <= len(order):
                layer[b], moved = layer[a] + 1, True
        if not moved:
            break
    # long links get a pass-through slot in every layer they cross
    chains, slots = {}, defaultdict(list)
    for n in order:
        slots[layer[n]].append(n)
    for a, b in links:
        chain = [a]
        for lay in range(layer[a] + 1, layer[b]):
            d = f"~{a}~{b}~{lay}"
            layer[d] = lay
            slots[lay].append(d)
            chain.append(d)
        chains[(a, b)] = chain + [b]
    up, down = defaultdict(list), defaultdict(list)
    for chain in chains.values():
        for u, w in zip(chain, chain[1:]):
            down[u].append(w)
            up[w].append(u)
    return layer, slots, chains, up, down


def _graph(v: _View) -> str:
    if not v.top:
        return ""
    rank_of = {p["id"]: p["rank"] for p in v.top}
    routes = {f"p{p['rank']}": p["nodes"] for p in v.top}
    if v.discovery:
        for b in v.r["baseline"]["paths"]:
            if b["id"] in rank_of and b.get("nodes"):
                routes[f"q{rank_of[b['id']]}"] = b["nodes"]
    order = list(dict.fromkeys(n for ns in routes.values() for n in ns))
    layer, slots, chains, up, down = _layout(routes, order)
    labels = {n: wrap(short(v.name(n))) for n in order}
    height = {n: 22 + 15 * len(labels[n]) for n in order}

    def h(n):
        return height.get(n, 0)

    def sep(a, b):
        return h(a) / 2 + h(b) / 2 + (ROW_SEP if a in height and b in height else DUMMY_SEP)

    layers = sorted(slots)
    # order inside each layer: barycentre sweeps, starting from the order of first appearance
    first = {n: i for i, n in enumerate(order)}
    for lay in layers:
        slots[lay].sort(key=lambda n: first[n] if n in first else first.get(n.split("~")[1], 0) + 0.5)
    pos = {n: i for lay in layers for i, n in enumerate(slots[lay])}
    for sweep in range(8):
        seq = layers if sweep % 2 == 0 else list(reversed(layers))
        for lay in seq:
            nbrs = up if sweep % 2 == 0 else down
            def bary(n):
                ns = nbrs.get(n, [])
                return sum(pos[x] for x in ns) / len(ns) if ns else pos[n]
            slots[lay].sort(key=lambda n: (bary(n), pos[n]))
            for i, n in enumerate(slots[lay]):
                pos[n] = i
    # vertical positions: pull each slot toward its neighbours, keep the order and the spacing
    y = {}
    for lay in layers:
        acc = 0.0
        for i, n in enumerate(slots[lay]):
            acc = acc if i == 0 else acc + sep(slots[lay][i - 1], n)
            y[n] = acc
    for sweep in range(12):
        seq = layers if sweep % 2 == 0 else list(reversed(layers))
        for lay in seq:
            col = slots[lay]
            want = []
            for n in col:
                ns = up.get(n, []) + down.get(n, [])
                want.append(sum(y[x] for x in ns) / len(ns) if ns else y[n])
            placed = []
            for i, n in enumerate(col):
                placed.append(want[i] if i == 0 else max(want[i], placed[-1] + sep(col[i - 1], n)))
            shift = sum(w - p for w, p in zip(want, placed)) / len(col)
            for n, p in zip(col, placed):
                y[n] = p + shift
    lo = min(y[n] - h(n) / 2 for n in y)
    for n in y:
        y[n] += PAD + 6 - lo
    hi = max(y[n] + h(n) / 2 for n in y)
    width = PAD * 2 + (max(layers) * COL) + NODE_W
    x = {n: PAD + layer[n] * COL + NODE_W / 2 for n in y}

    def keys_on(node=None, link=None):
        ks = [k for k, ns in routes.items() if (node in ns if node else any(
            (a, b) == link for a, b in zip(ns, ns[1:])))]
        modes = sorted({"ai" if k[0] == "p" else "base" for k in ks})
        return " ".join(ks), " ".join(modes)

    paths_svg = []
    for (a, b), chain in chains.items():
        pts = [(x[a] + NODE_W / 2, y[a])]
        for d in chain[1:-1]:
            pts += [(x[d] - NODE_W / 2, y[d]), (x[d] + NODE_W / 2, y[d])]
        pts.append((x[b] - NODE_W / 2 - 2, y[b]))
        d = f"M{pts[0][0]:.1f} {pts[0][1]:.1f}"
        for i, (px, py) in enumerate(pts[1:], start=1):
            qx, qy = pts[i - 1]
            if abs(py - qy) < 0.05:
                d += f"H{px:.1f}"
            else:
                mx = (qx + px) / 2
                d += f"C{mx:.1f} {qy:.1f} {mx:.1f} {py:.1f} {px:.1f} {py:.1f}"
        ks, ms = keys_on(link=(a, b))
        paths_svg.append(f'<path class="e" d="{d}" data-p="{ks}" data-m="{ms}"/>')

    nodes_svg = []
    for n in order:
        node = v.nodes.get(n, {})
        kind = "ai" if n in v.ai else "jewel" if node.get("crown_jewel") else "id" if node.get("kind") == "identity" else "asset"
        entry = bool(node.get("entry_point"))
        ks, ms = keys_on(node=n)
        hh, top_y = h(n), y[n] - h(n) / 2
        info = [v.name(n), KIND_LABELS.get(node.get("kind"), words(node.get("type") or node.get("kind")))]
        if node.get("crown_jewel"):
            info.append("Crown jewel")
        if entry:
            info.append(f"Entry point: {ENTRY_WORDS.get(node['entry_point'], words(node['entry_point']))}")
        if v.owner(n):
            info.append(f"Owner: {v.owner(n)}")
        if node.get("discovered") and v.discovery:
            info.append("Found by AI discovery")
        flags = [f for f in v.flags if f["asset"] == n]
        if flags:
            info.append(f"{plural(len(flags), 'risk flag')}: " + ", ".join(f["id"] for f in flags))
        text = "".join(f'<text x="{x[n]:.1f}" y="{top_y + 19 + 15 * i:.1f}">{e(line)}</text>'
                       for i, line in enumerate(labels[n]))
        bar = (f'<rect class="entry-bar" x="{x[n] - NODE_W / 2:.1f}" y="{top_y:.1f}" width="4" height="{hh}" rx="2"/>'
               if entry else "")
        nodes_svg.append(f'<g class="nd k-{kind}" data-p="{ks}" data-m="{ms}"{tip(chr(10).join(info), True)}>'
                         f'<rect x="{x[n] - NODE_W / 2:.1f}" y="{top_y:.1f}" width="{NODE_W}" height="{hh}" rx="7"/>'
                         f'{bar}{text}</g>')
    heads = ('<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" '
             'orient="auto-start-reverse"><path class="ah" d="M0 0L10 5L0 10z"/></marker>'
             '<marker id="ah-on" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" '
             'orient="auto-start-reverse"><path class="ah-on" d="M0 0L10 5L0 10z"/></marker></defs>')
    svg = (f'<svg class="graph m-ai" viewBox="0 0 {width:.0f} {hi + PAD:.0f}" role="img" '
           f'aria-label="Attack-path graph of the top {len(v.top)} paths, from entry points to crown jewels. '
           f'The Attack paths view lists the same routes as text.">{heads}<g class="edges">{"".join(paths_svg)}</g>'
           f'<g class="nodes">{"".join(nodes_svg)}</g></svg>')
    return svg


def _story(v: _View, p: dict) -> str:
    steps = []
    for s in p["steps"]:
        if s["kind"] == "entry":
            hop = f"Entry at {short(v.name(s['to']))}"
        else:
            hop = f"{short(v.name(s['from']))} → {short(v.name(s['to']))}"
        new = ' <span class="tag">found by AI discovery</span>' if s["origin"] == "discovery" else ""
        steps.append(f'<li><strong>{e(hop)}</strong>{new}<span class="sub">{e(s["why"])}</span></li>')
    tags = []
    if v.discovery and p["score_without_discovery"] is None:
        tags.append('<span class="tag strong">Invisible without AI discovery</span>')
    elif v.discovery and p["blind_spot"]:
        tags.append(f'<span class="tag">Scores {num(p["score_without_discovery"])} without AI discovery</span>')
    for c in p.get("toxic_combinations", []):
        tags.append(f'<span class="tag tc"{tip(v.tc[c]["summary"])}>{e(c)} {e(v.tc[c]["title"])}</span>')
    fixes = []
    for c in v.r["choke_points"]:
        if c["finding"] in p["findings"]:
            effect = "closes it" if p["id"] in c["paths_closed"] else "weakens it"
            fixes.append(f'<li>{v.fid(c["finding"])} {e(short(c["asset_name"]))}: {effect}'
                         f' <span class="muted">({MINUS}{num(c["reduction"])} on the index)</span></li>')
    fixes_html = (f'<p class="mini-h">Fixes that cut this path</p><ul class="plain">{"".join(fixes[:4])}</ul>'
                  if fixes else "")
    return (f'<div class="story" data-key="{p["rank"]}" hidden><p class="story-title"><span class="rank">#{p["rank"]}</span> '
            f'{e(short(v.name(p["entry"])))} → {e(short(p["target_name"]))} '
            f'<span class="story-score">{num(p["score"])}</span> {level(p["tier"])}</p>'
            f'{f"<div class=tags>{chr(10).join(tags)}</div>" if tags else ""}'
            f'<ol class="story-steps">{"".join(steps)}</ol>{fixes_html}'
            f'<p><a href="#path-{p["rank"]}" data-goto>Full step-by-step detail</a></p></div>')


def _graph_card(v: _View) -> str:
    if not v.top:
        return ""
    toggle = (seg("mode", [("ai", "With AI discovery"), ("base", "Scanner data only")], "Data shown on the graph")
              .replace('data-group="mode"', 'data-group="mode" data-graph') if v.discovery else "")
    legend = ('<div class="legend"><span><i class="sw sw-entry"></i>Entry point</span>'
              '<span><i class="sw sw-ai"></i>AI agent, MCP server, knowledge base or vector database</span>'
              '<span><i class="sw sw-jewel"></i>Crown jewel</span>'
              + ('<span class="base-only"><i class="sw sw-ghost"></i>Not visible to a scanner</span>' if v.discovery else "")
              + "</div>")
    picks = []
    base_ids = {b["id"] for b in v.r["baseline"]["paths"]}
    for p in v.top:
        ai = ' <span class="ai-mark" title="Runs through AI"></span>' if p["ai_nodes"] else ""
        missing = ' data-absent' if v.discovery and p["id"] not in base_ids else ""
        picks.append(f'<li><button type="button" class="pick" data-key="{p["rank"]}" aria-pressed="false"{missing}>'
                     f'<span class="rank">{p["rank"]}</span><span class="pick-name">{e(short(v.name(p["entry"])))} → '
                     f'{e(short(p["target_name"]))}{ai}</span><span class="pick-score">{num(p["score"])}</span></button></li>')
    stories = "".join(_story(v, p) for p in v.top)
    placeholder = ('<div class="story-empty"><p>Pick a path to trace it on the graph and read how it works, '
                   'step by step.</p>'
                   + ('<p class="muted">Switch to <em>Scanner data only</em> to see what the same company looks like '
                      'without AI discovery: the AI components fade and their paths disappear.</p>' if v.discovery else "")
                   + "</div>")
    note = (f"The top {len(v.top)} of {plural(len(v.r['paths']), 'path')}. Hover a box for details."
            if len(v.r["paths"]) > len(v.top) else "Hover a box for details.")
    return (f'<div class="card graph-card" data-graph-card><div class="gc-head"><div><h3>How an attacker reaches your crown '
            f'jewels</h3><p class="note">{e(note)}</p></div>{toggle}</div>{legend}'
            f'<div class="graph-wrap">{_graph(v)}</div>'
            f'<div class="explore"><ol class="picker" aria-label="Top attack paths">{"".join(picks)}</ol>'
            f'<div class="stories" aria-live="polite">{placeholder}{stories}</div></div></div>')


def _overview_lists(v: _View) -> str:
    plan = v.r["remediation_plan"]
    items = "".join(
        f'<li><span class="step">{x["step"]}</span><span class="mini-main"><strong>{e(short(x["asset_name"]))}</strong>'
        f'{v.fid(x["finding"])}</span><span class="mini-val">{MINUS}{num(x["reduction"])}</span></li>' for x in plan)
    fixes = (f'<div class="card"><h3>Fix these first</h3><p class="note">Each fix is the best next move after the one '
             f'before it.</p><ol class="mini">{items}</ol><p><a href="#fixes" data-goto>Open the fix plan</a></p></div>'
             if plan else "")
    if not v.discovery:
        return f'<div class="two">{fixes}</div>' if fixes else ""
    tcs = "".join(
        f'<li>{dot(c["severity"])}<span class="mini-main"><strong>{e(c["title"])}</strong>'
        f'<span class="sub">{e(c["id"])} · {e(join([short(v.name(x)) for x in c["components"][-2:]]))}</span></span>'
        f'<span class="mini-val">{plural(len(c["paths"]), "path")}</span></li>' for c in v.toxic[:5])
    toxic = (f'<div class="card"><h3>Toxic combinations</h3><p class="note">Flags that are serious only together, '
             f'joined by a real link.</p><ul class="mini">{tcs}</ul>'
             f'<p><a href="#toxic" data-goto>All {len(v.toxic)} in the AI inventory</a></p></div>') if v.toxic else ""
    return f'<div class="two">{fixes}{toxic}</div>'


def _overview(v: _View) -> str:
    return panel("overview", "Overview", "", _cards(v) + _strip(v) + _graph_card(v) + _overview_lists(v), heading=False)


# --- attack paths -------------------------------------------------------------------

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
        fids = " ".join(v.fid(f) for f in s["findings"]) or '<span class="none">none</span>'
        techs = " ".join(_technique(t) for t in s["techniques"]) or '<span class="none">none</span>'
        rows.append(f'<tr><td class="n">{i}</td><td>{e(hop)}{found}<span class="sub">{e(words(s["kind"]))}</span></td>'
                    f'<td>{e(s["why"])}</td><td class="n">{s["ease"]:.2f}</td><td>{fids}</td><td>{techs}</td></tr>')
    return ('<div class="scroll"><table class="wide steps"><thead><tr><th class="n">#</th><th>Step</th><th>Why it works</th>'
            f'<th class="n">Ease</th><th>Findings</th><th>Techniques</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>')


def _why_rank(p: dict) -> str:
    bars = [("Exposure", p["exposure"], "how open the entry point is"),
            ("Likelihood", p["likelihood"], f"every step's ease, multiplied ({plural(p['hops'], 'step')})"),
            ("Impact", p["impact"], "how much the crown jewel matters")]
    rows = "".join(f'<div class="why-row"><span class="why-label">{e(name)}</span><span class="track">'
                   f'<span class="fill" style="width:{pct(val, 1)}"></span></span><span class="why-val">{val:.2f}</span>'
                   f'<span class="sub">{e(note)}</span></div>' for name, val, note in bars)
    return (f'<div class="why">{rows}<p class="note">100 × {p["exposure"]:g} × {p["likelihood"]:.3f} × {p["impact"]:g} '
            f'= {num(p["score"])}</p></div>')


def _path_item(v: _View, p: dict) -> str:
    title = (f'{e(short(v.name(p["entry"])))}<span class="arrow" aria-hidden="true"> → </span>'
             f'<span class="vh"> to </span>{e(short(p["target_name"]))}')
    score = (f'<div class="score"><span class="track"><span class="fill" style="width:{pct(p["score"], 100)}">'
             f'</span></span><span class="val">{num(p["score"])}</span>{level(p["tier"])}</div>')
    chips = "".join(_chip(v, n, i == len(p["nodes"]) - 1) for i, n in enumerate(p["nodes"]))
    tags, flags = [], [p["tier"]]
    if p["ai_nodes"]:
        tags.append(f'<span class="tag strong">Runs through {plural(len(p["ai_nodes"]), "AI component")}</span>')
        flags.append("ai")
    if v.discovery and p["score_without_discovery"] is None:
        tags.append('<span class="tag strong">Invisible without AI discovery</span>')
        flags.append("blind")
    elif v.discovery and p["blind_spot"]:
        tags.append(f'<span class="tag">Scores {num(p["score_without_discovery"])} without AI discovery</span>')
        flags.append("blind")
    for c in p.get("toxic_combinations", []):
        tags.append(f'<span class="tag tc"{tip(v.tc[c]["summary"])}>{e(c)} {e(v.tc[c]["title"])}</span>')
    if p.get("toxic_combinations"):
        flags.append("tc")
    tags_html = f'<div class="tags">{"".join(tags)}</div>' if tags else ""
    return (f'<li class="path" id="path-{p["rank"]}" data-tags="{" ".join(flags)}"><span class="rank">{p["rank"]}</span>'
            f'<div class="path-main"><p class="path-title">{title}<span class="sub mono">{e(p["id"])}</span></p>{score}'
            f'<ol class="chain" aria-label="Route">{chips}</ol>{tags_html}'
            f'<details><summary>Why this rank, and how the path works step by step</summary>{_why_rank(p)}{_steps(v, p)}'
            f'</details></div></li>')


def _paths(v: _View) -> str:
    paths = v.r["paths"]
    if not paths:
        return panel("paths", "Attack paths", "No path reaches a crown jewel.", "")
    lede = (f"{plural(len(paths), 'path')} reach {plural(v.s['crown_jewels_reachable'], 'crown jewel')}, ranked by "
            f"score: how open the entry point is, how easy every step is, and how much the target matters. Open a "
            f"path for the breakdown.")
    opts = [("all", "All", len(paths)),
            ("ai", "Through AI", sum(1 for p in paths if p["ai_nodes"])),
            ("blind", "Missed or under-rated without AI discovery", sum(1 for p in paths if v.discovery and p["blind_spot"])),
            ("critical", "Critical", sum(1 for p in paths if p["tier"] == "critical")),
            ("tc", "In a toxic combination", sum(1 for p in paths if p.get("toxic_combinations")))]
    legend = ('<div class="legend"><span><i class="sw sw-bar"></i>Path score, 0 to 100</span>'
              '<span><i class="sw sw-ai"></i>AI agent, MCP server, knowledge base or vector database</span></div>')
    items = "".join(_path_item(v, p) for p in paths)
    body = (f'{filters("pathlist", opts, "Filter attack paths")}<div class="card">{legend}'
            f'<ol class="paths" id="pathlist">{items}</ol></div>')
    return panel("paths", "Attack paths", e(lede), body)


# --- fix plan -----------------------------------------------------------------------

def _fix_item(v: _View, x: dict) -> str:
    owner = v.owner(x["asset"])
    facts = [f'<span><strong>{MINUS}{num(x["reduction"])}</strong> on the index ({x["reduction_pct"]:g}%)</span>',
             f'<span>index after: <strong>{num(x["exposure_index_after"])}</strong></span>']
    closes = [c for c in v.r["choke_points"] if c["finding"] == x["finding"]]
    if closes and closes[0]["paths_closed"]:
        facts.append(f'<span>closes {plural(len(closes[0]["paths_closed"]), "path")} on its own</span>')
    facts.append(f'<span>CVSS rank: {"#" + str(x["cvss_rank"]) if x.get("cvss_rank") else "not a CVE"}</span>')
    if owner:
        facts.append(f"<span>Owner: {e(owner)}</span>")
    broken = v.breaks(x["finding"])
    tc = ("".join(f'<span class="tag tc"{tip(v.tc[c]["summary"])}>Breaks {e(c)} {e(v.tc[c]["title"])}</span>'
                  for c in broken))
    src = '<span class="tag strong">From AI discovery</span>' if x["source"] == "discovery" else ""
    return (f'<li class="fix"><span class="rank">{x["step"]}</span><div class="fix-main">'
            f'<p class="fix-title">{e(x["asset_name"])}</p><p class="fix-what">{v.fid(x["finding"])} '
            f'{e(v.title(x["finding"], x["title"]))}</p><p class="fix-do"><strong>Do:</strong> {e(x["fix"])}</p>'
            f'<p class="facts">{"".join(facts)}</p>{f"<div class=tags>{src}{tc}</div>" if src or tc else ""}</div></li>')


def _fixes(v: _View) -> str:
    plan, s = v.r["remediation_plan"], v.s
    if not plan:
        return panel("fixes", "Fix plan", "Nothing to fix: no path reaches a crown jewel.", "")
    index, after = s["exposure_index"], s["plan"]["exposure_index_after"]
    lede = (f"{plural(len(plan), 'fix', 'fixes')} take the exposure index from {num(index)} to {num(after)}, "
            f"{MINUS}{s['plan']['reduction_pct']}%. Every path is re-scored after each fix, so each step is the "
            f"best next move.")
    from_ai = sum(1 for x in plan if x["source"] == "discovery")
    if from_ai:
        lede += f" {from_ai} of the {len(plan)} come from AI discovery, which no vulnerability scanner reports."

    rows = [f'<div class="hb-row"{tip(f"Today: exposure index {num(index)}", True)}><div class="hb-label">Today</div>'
            f'<div class="hb-track"><span class="hb-fill ref" style="width:100%"></span></div>'
            f'<div class="hb-val">{num(index)}</div></div>']
    for x in plan:
        text = (f"Step {x['step']}: {x['title']}{chr(10)}On {x['asset_name']}{chr(10)}Cuts {num(x['reduction'])} points "
                f"({x['reduction_pct']}%), index after: {num(x['exposure_index_after'])}")
        rows.append(f'<div class="hb-row"{tip(text, True)}><div class="hb-label"><span class="step">{x["step"]}</span>'
                    f'{e(short(x["asset_name"]))}</div>'
                    f'<div class="hb-track"><span class="hb-fill" style="width:{pct(x["exposure_index_after"], index)}">'
                    f'</span></div><div class="hb-val">{num(x["exposure_index_after"])}'
                    f'<span class="delta">{MINUS}{num(x["reduction"])}</span></div></div>')
    chart = (f'<div class="card chart"><h3>Exposure index after each fix</h3><div class="hb" role="img" '
             f'aria-label="Exposure index after each fix; the list below has the same numbers.">{"".join(rows)}</div></div>')
    queue = f'<ol class="fixes">{"".join(_fix_item(v, x) for x in plan)}</ol>'
    plan_view = f'<div class="view" data-view="plan">{chart}<div class="card">{queue}</div></div>'

    chokes = v.r["choke_points"][:8]
    trs = "".join(
        f'<tr><td>{v.fid(c["finding"])}<span class="sub">{e(v.title(c["finding"], c["title"]))}</span></td>'
        f'<td>{e(c["asset_name"])}</td><td class="n">{MINUS}{num(c["reduction"])}</td>'
        f'<td class="n">{len(c["paths_closed"])}</td><td class="n">{len(c["paths_weakened"])}</td>'
        f'<td>{" ".join(e(t) for t in v.breaks(c["finding"])) or "<span class=none>none</span>"}</td>'
        f'<td class="n">{"#" + str(c["cvss_rank"]) if c.get("cvss_rank") else "not a CVE"}</td></tr>' for c in chokes)
    choke_view = ('<div class="view" data-view="chokes"><div class="card"><p class="note">What each fix would remove on its '
                  'own, before any other fix. Fixes overlap, which is why the plan re-scores after each one.</p>'
                  '<div class="scroll"><table class="wide"><thead><tr><th>Finding</th><th>Asset</th>'
                  '<th class="n">Cuts alone</th><th class="n">Paths closed</th><th class="n">Paths weakened</th>'
                  f'<th>Breaks</th><th class="n">CVSS rank</th></tr></thead><tbody>{trs}</tbody></table></div></div></div>')
    control = seg("fixviews", [("plan", "Plan order"), ("chokes", "Biggest single fixes"), ("cvss", "CVSS order")],
                  "Order the fixes")
    body = f'{control}<div class="views" data-views="fixviews">{plan_view}{choke_view}{_cvss(v)}</div>'
    return panel("fixes", "Fix plan", e(lede), body)


def _cvss(v: _View) -> str:
    view = v.r["baseline"]["cvss_top10"]
    if not view:
        return '<div class="view" data-view="cvss"><div class="card"><p class="note">No CVEs in this scan.</p></div></div>'
    off = sum(1 for x in view if not x["on_a_path"])
    lede = f"What a scanner sorted by CVSS would fix first: {off} of its top {len(view)} findings lead to no crown jewel."
    best = v.r["choke_points"][0] if v.r["choke_points"] else None
    extra = ""
    if best and best.get("cvss_rank", 0) > len(view):
        f = v.findings.get(best["finding"], {})
        lede += (f" The single fix that removes the most exposure, {f.get('cve') or best['finding']}, is "
                 f"#{best['cvss_rank']} on that list.")
        extra = (f'<tr class="hl"><td class="n">#{best["cvss_rank"]}</td><td class="mono">{e(f.get("cve"))}</td>'
                 f'<td>{e(best["asset_name"])}</td><td class="n">{e(f.get("intel", {}).get("cvss"))}</td>'
                 f'<td>{"Yes" if f.get("intel", {}).get("kev") else "No"}</td>'
                 f'<td>Yes: the biggest single fix</td></tr>')
    elif best and not best.get("cvss_rank"):
        lede += f" The single fix that removes the most exposure, {best['finding']}, is not a CVE at all."
    trs = "".join(
        f'<tr><td class="n">#{x["cvss_rank"]}</td><td class="mono">{e(x["cve"])}</td>'
        f'<td>{e(short(v.name(x["asset"])))}<span class="sub mono">{e(x["asset"])}</span></td>'
        f'<td class="n">{e(x["cvss"])}</td><td>{"Yes" if x["kev"] else "No"}</td>'
        f'<td>{"<span class=yes>✓ Yes</span>" if x["on_a_path"] else "<span class=no>No</span>"}</td></tr>'
        for x in view)
    return ('<div class="view" data-view="cvss"><div class="card">'
            f'<p class="note">{e(lede)}</p><div class="scroll"><table class="mid"><thead><tr><th class="n">CVSS rank</th>'
            '<th>CVE</th><th>Asset</th><th class="n">CVSS</th><th>CISA KEV</th><th>On an attack path</th></tr></thead>'
            f'<tbody>{trs}{extra}</tbody></table></div></div></div>')


# --- AI inventory -------------------------------------------------------------------

def _reach(v: _View, item: dict) -> list[str]:
    kind, out = item["kind"], []
    if kind == "agent":
        out.append(e(PLATFORMS.get(item.get("platform"), words(item.get("platform")))))
        for ch in item.get("channels") or []:
            via = words(ch.get("channel")) or short(v.name(ch.get("asset")))
            out.append(f'<span class="k">Input</span> {e(ch.get("audience", "unknown"))} via {e(via)}')
        tools = item.get("tools") or []
        if tools:
            free = [t["name"] for t in tools if not t.get("needs_approval")]
            out.append(f'<span class="k">Tools</span> {plural(len(tools), "tool")}, '
                       f'{len(free)} without approval' + (f': {e(", ".join(free))}' if free else ""))
        if item.get("identity"):
            out.append(f'<span class="k">Acts as</span> {e(short(v.name(item["identity"])))}')
        if item.get("knowledge_bases"):
            out.append(f'<span class="k">Reads</span> {e(", ".join(item["knowledge_bases"]))}')
    elif kind == "knowledge_base":
        store = (item.get("store") or {}).get("type")
        out.append(e(" · ".join(x for x in (PLATFORMS.get(item.get("platform"), ""), words(store)) if x)))
        for src in item.get("sources") or []:
            out.append(f'<span class="k">Source</span> {e(src["name"])} ({e(src.get("trust", "unknown"))})')
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


def _flag(v: _View, f: dict) -> str:
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
    return (f'<li><details><summary>{dot(f["severity"])} <span class="mono">{e(f["id"])}</span> '
            f'{e(f["title"])}</summary><div class="flag-body"><ul>{"".join(lines)}</ul>'
            f'<p><strong>Rule:</strong> <span class="mono">{e(f.get("rule"))}</span> · <strong>Severity:</strong> '
            f'{e(f["severity"])}</p><p><strong>Fix:</strong> {e(f.get("remediation"))}</p>'
            f'{f"<p class=fws>{fws}</p>" if fws else ""}</div></details></li>')


def _toxic(v: _View) -> str:
    if not v.toxic:
        return ""
    cards = []
    for c in v.toxic:
        parts = "".join(f'<li>{e(i["text"])}{(" " + v.fid(i["finding"], brief=True)) if i["finding"] else ""}</li>'
                        for i in c["ingredients"])
        on = (f'On {plural(len(c["paths"]), "attack path")}' if c["paths"]
              else "On no ranked path today: a posture risk")
        cards.append(f'<li class="tc-card" id="{e(c["id"]).lower()}"><p class="tc-title">{level(c["severity"])} '
                     f'<span class="mono">{e(c["id"])}</span><span class="tc-name">{e(c["title"])}</span></p><p class="tc-sum">{e(c["summary"])}</p>'
                     f'<ul class="ingredients">{parts}</ul><p class="facts"><span>{e(on)}</span>'
                     f'<span>Break it: fix {v.fid(c["break_with"])}</span></p></li>')
    return (f'<div class="card" id="toxic"><h3>Toxic combinations</h3><p class="note">Each one is several flags joined by a '
            f'real link: this input reaches that agent, that agent calls this server. Fixing any one ingredient breaks '
            f'it.</p><ol class="tc-list">{"".join(cards)}</ol></div>')


def _inventory(v: _View) -> str:
    s = v.s
    by_asset = defaultdict(list)
    for f in v.flags:
        by_asset[f["asset"]].append(f)
    sev = Counter(f["severity"] for f in v.flags)
    lede = (f"{plural(s['ai_components'], 'AI component')} found, {s['ai_not_registered']} of them in no inventory. "
            f"{plural(len(v.flags), 'risk flag')}: " + ", ".join(f"{sev[k]} {k}" for k in LEVELS if sev[k]) + ".")
    kinds = Counter(i["kind"] for i in v.r["inventory"])
    shadow = Counter(i["kind"] for i in v.r["inventory"] if not i["registered"])
    stats = "".join(f'<div class="stat"><span class="num">{kinds[k]}</span><span>{e(KIND_PLURAL[k])}</span>'
                    f'<span class="sub">{shadow[k]} in no inventory</span></div>' for k in KIND_PLURAL if kinds[k])
    stats = f'<div class="stats">{stats}</div>'

    rows = []
    for item in v.r["inventory"]:
        flags = sorted(by_asset.get(item["id"], []), key=lambda f: (_rank(f["severity"]), f["id"]))
        status = ('Listed' if item["registered"] else '<span class="shadow">Shadow: in no inventory</span>')
        flag_html = (f'<ul class="flags">{"".join(_flag(v, f) for f in flags)}</ul>' if flags
                     else '<span class="none">none</span>')
        tags = [item["kind"]] + ([] if item["registered"] else ["shadow"])
        if any(f["severity"] == "critical" for f in flags):
            tags.append("critical")
        owner = f'<span class="sub">Owner: {e(item["owner"])}</span>' if item.get("owner") else \
            '<span class="sub">Owner: unknown</span>'
        rows.append(f'<tr data-tags="{" ".join(tags)}"><td><strong>{e(item["name"])}</strong>'
                    f'<span class="sub mono">{e(item["id"])}</span>{owner}</td>'
                    f'<td class="kind">{e(KIND_LABELS.get(item["kind"], item["kind"]))}<span class="sub">{status}</span></td>'
                    f'<td class="where">{"<br>".join(_reach(v, item))}</td><td>{flag_html}</td></tr>')
    listed = {i["id"] for i in v.r["inventory"]}
    others = [f for f in v.flags if f["asset"] not in listed]
    for asset in sorted({f["asset"] for f in others}):
        flags = [f for f in others if f["asset"] == asset]
        crit = " critical" if any(f["severity"] == "critical" for f in flags) else ""
        rows.append(f'<tr data-tags="host{crit}"><td><strong>{e(v.name(asset))}</strong><span class="sub mono">{e(asset)}</span>'
                    f'</td><td class="kind">Host<span class="sub">Listed</span></td><td class="where">MCP client configuration</td>'
                    f'<td><ul class="flags">{"".join(_flag(v, f) for f in flags)}</ul></td></tr>')
    inv = v.r["inventory"]
    opts = [("all", "All", len(rows)), ("shadow", "Shadow AI", sum(1 for i in inv if not i["registered"]))]
    opts += [(k, KIND_PLURAL[k], kinds[k]) for k in KIND_PLURAL]
    opts.append(("critical", "Has a critical flag", sum(1 for r in rows if "critical" in r.split('"', 2)[1])))
    table = (f'<div class="card"><h3>AI bill of materials</h3>{filters("invlist", opts, "Filter AI components")}'
             '<p class="note">Open a flag for its evidence, the fix and the framework IDs it maps to.</p>'
             '<div class="scroll"><table class="inv"><thead><tr><th>Component</th><th>Kind</th>'
             f'<th>Reach: inputs, tools, identity, data</th><th>Flags</th></tr></thead><tbody id="invlist">{"".join(rows)}'
             '</tbody></table></div></div>')
    return panel("ai", "AI inventory", e(lede), stats + _toxic(v) + table)


def _rank(severity: str) -> int:
    return LEVELS.index(severity) if severity in LEVELS else len(LEVELS)


# --- how the report was made --------------------------------------------------------

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
    return (f'<div id="method" class="proof-part"><h3 class="proof-h">How discovery worked</h3><p class="lede">{e(lede)}</p>'
            f'<div class="cols">{read}{asked}</div>{leads_html}{safety}{notes}</div>')


def _scoring() -> str:
    floors = {name: lo for lo, name in TIERS}
    exposure = "; ".join(f"{val:.1f} when {ENTRY_WORDS.get(k, words(k))}" for k, val in EXPOSURE.items())
    return ('<div class="proof-part"><h3 class="proof-h">How a path is scored</h3><p class="lede">'
            f"Score = 100 × exposure × likelihood × impact. Exposure is {e(exposure)}. Likelihood multiplies the ease "
            f"of every step, for example 0.9 for a CVE on the CISA KEV list. Impact is how much the crown jewel "
            f"matters, from 0 to 1. Tiers: critical from {floors['critical']}, high from {floors['high']}, medium from "
            f"{floors['medium']}. The exposure index adds up the worst path score to each crown jewel, so it goes down "
            f"only when a fix actually cuts a path. The fix plan picks the best next fix and re-scores every path after "
            f"each one, because fixes overlap.</p></div>")


def _proof(v: _View) -> str:
    used = frameworks_used(v.r)
    rows = "".join(
        f'<div class="fw-row"><strong>{e(FRAMEWORK_TITLES.get(fw, fw))}</strong>{" ".join(_technique(i) for i in ids)}</div>'
        for fw, ids in sorted(used.items(), key=lambda kv: list(FRAMEWORK_TITLES).index(kv[0])
                              if kv[0] in FRAMEWORK_TITLES else 99))
    feeds = v.r["feeds"]
    meta = (f'<div class="proof-part"><h3 class="proof-h">Frameworks and data</h3><div class="fw-list">{rows}</div>'
            f'<p class="note">Threat intelligence: CISA KEV catalog {e(feeds["kev_catalog_version"])} '
            f'({e(feeds["kev_entries_used"])} entries used), {e(feeds["cve_records"])} CVE records, EPSS '
            f'{e(feeds["epss"])}.</p><p class="note">The same data is available as JSON (<span class="mono">--format json'
            f'</span>), checked against <span class="mono">schema/scan-result.schema.json</span> version '
            f'{e(v.r["schema_version"])}, for SOAR and ticketing tools.</p></div>')
    parts = _scoring() + (_method(v) if v.discovery else "") + meta
    summary = "How this report was made: scoring" + (", discovery, safety rules" if v.discovery else "") + \
        " and frameworks"
    return (f'<footer id="proof"><details class="proof"><summary>{e(summary)}</summary><div class="proof-body">{parts}'
            f'</div></details></footer>')


# --- page ---------------------------------------------------------------------------

def render_html(report: dict, *, standalone: bool = True) -> str:
    """The dashboard as a full HTML document, or as a page fragment (no doctype,
    head or body) for hosts that wrap pages in their own skeleton."""
    v = _View(report)
    parts = [_header(v), _tabs(v), "<main>", _overview(v), _paths(v), _fixes(v)]
    if v.discovery:
        parts.append(_inventory(v))
    parts += ["</main>", _proof(v)]
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
--grid:#e1e0d9;--axis:#c3c2b7;--border:#e1e0d9;--blue:#2a78d6;--violet:#6250d6;--violet-tint:#eeebfb;--gray-mark:#898781;
--critical:#d03b3b;--serious:#ec835a;--warning:#fab219;--good:#0ca30c;--tip-bg:#1f1f1e;--tip-ink:#f0efec;
--sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--mono:ui-monospace,"SF Mono","Cascadia Mono","Segoe UI Mono",Menlo,Consolas,"Liberation Mono",monospace}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--page:#0d0d0d;--surface:#1a1a19;--sunken:#242422;
--ink:#f0efec;--ink-2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;--border:#2c2c2a;--blue:#3987e5;
--violet:#9085e9;--violet-tint:#26223f;--gray-mark:#898781;--tip-bg:#f0efec;--tip-ink:#0b0b0b;color-scheme:dark}}
:root[data-theme="dark"]{--page:#0d0d0d;--surface:#1a1a19;--sunken:#242422;--ink:#f0efec;--ink-2:#c3c2b7;
--muted:#898781;--grid:#2c2c2a;--axis:#383835;--border:#2c2c2a;--blue:#3987e5;--violet:#9085e9;--violet-tint:#26223f;
--gray-mark:#898781;--tip-bg:#f0efec;--tip-ink:#0b0b0b;color-scheme:dark}
*,*::before,*::after{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.55 var(--sans);-webkit-text-size-adjust:100%}
.page{max-width:72rem;margin:0 auto;padding-block:2rem 4rem;padding-left:max(16px,env(safe-area-inset-left,0px));
padding-right:max(16px,env(safe-area-inset-right,0px));display:grid;gap:1.5rem}
main{display:grid;gap:3rem;min-width:0}
h1,h2,h3{margin:0;text-wrap:balance}
h1{font-size:2rem;line-height:1.1;font-weight:700;letter-spacing:-.02em}
h2{font-size:1.375rem;line-height:1.3;font-weight:650;letter-spacing:-.01em}
h3{font-size:.75rem;line-height:1.4;font-weight:650;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-2)}
p{margin:0}
a{color:inherit}
button{font:inherit;color:inherit}
.mono,code{font-family:var(--mono);font-size:.8125rem}
.sub{display:block;font-size:.75rem;color:var(--muted);font-weight:400}
.none,.muted{color:var(--muted)}
.note{font-size:.8125rem;color:var(--ink-2)}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.eyebrow{font-family:var(--mono);font-size:.75rem;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
header.top{display:grid;gap:.6rem}
.title-row{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem 1rem}
.pill{font-size:.75rem;font-weight:600;padding:2px 10px;border:1px solid var(--axis);border-radius:999px;color:var(--ink-2)}
.headline{font-size:1.0625rem;line-height:1.5;max-width:64ch}
.meta{display:flex;flex-wrap:wrap;gap:.25rem 1.25rem;font-size:.8125rem;color:var(--muted)}
.tabs{display:flex;gap:.25rem;border-bottom:1px solid var(--border);overflow-x:auto;position:sticky;top:0;z-index:5;
background:var(--page);padding-top:.25rem}
.tabs a{padding:.6rem .9rem;text-decoration:none;color:var(--ink-2);font-weight:600;font-size:.9375rem;white-space:nowrap;
border-bottom:2px solid transparent;margin-bottom:-1px}
.tabs a:hover{color:var(--ink)}
.tabs a[aria-selected="true"]{color:var(--ink);border-bottom-color:var(--blue)}
.count{display:inline-block;min-width:1.4rem;padding:0 6px;border-radius:999px;background:var(--sunken);color:var(--ink-2);
font-size:.75rem;font-weight:600;text-align:center;font-variant-numeric:tabular-nums}
.panel{display:grid;gap:1rem;min-width:0;scroll-margin-top:3.5rem}
.panel:focus{outline:none}
.sec-head{display:grid;gap:.4rem}
.lede{max-width:70ch;color:var(--ink-2)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.25rem;min-width:0;display:grid;gap:.9rem;align-content:start}
.kpis{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1rem 1.25rem;display:grid;gap:.25rem;align-content:start;min-width:0}
.kpi .num{font-size:1.5rem;line-height:1.2;font-weight:700;letter-spacing:-.01em;font-variant-numeric:tabular-nums}
.kpi-label{font-weight:600}
.kpi-note{font-size:.8125rem;color:var(--ink-2)}
.strip{display:grid;grid-template-columns:auto minmax(8rem,1fr) auto;align-items:center;gap:.5rem 1.25rem;padding:.75rem 1.25rem;
border:1px solid var(--border);border-radius:10px;background:var(--surface)}
.strip-label{font-weight:600}
.strip-num{font-size:1.25rem;font-variant-numeric:tabular-nums}
.of{color:var(--muted);font-size:.8125rem}
.strip-note{font-size:.8125rem;color:var(--ink-2)}
.meter{display:flex;gap:2px;height:12px}
.meter .seg-bar{display:block;height:100%;flex:none}
.seg-bar.base{background:var(--gray-mark)}
.seg-bar.with{background:var(--blue)}
.seg-bar.end,.seg-bar.rest{border-radius:0 4px 4px 0}
.seg-bar.rest{flex:1 1 auto;background:var(--sunken)}
.legend{display:flex;flex-wrap:wrap;gap:.35rem 1.25rem;font-size:.8125rem;color:var(--ink-2)}
.legend span{display:inline-flex;align-items:center;gap:.45rem}
.sw{display:inline-block;flex:none;width:10px;height:10px;border-radius:50%}
.sw-bar{width:16px;height:8px;border-radius:0 3px 3px 0;background:var(--blue)}
.sw-ai{width:14px;height:12px;border-radius:3px;background:var(--violet-tint);border:1.5px solid var(--violet)}
.sw-entry{width:14px;height:12px;border-radius:3px;border:1px solid var(--axis);box-shadow:inset 3px 0 0 var(--ink-2)}
.sw-jewel{width:14px;height:12px;border-radius:3px;border:2px solid var(--ink)}
.sw-ghost{width:14px;height:12px;border-radius:3px;border:1.5px dashed var(--muted)}
.gc-head{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-start;gap:.75rem}
.gc-head>div:first-child{display:grid;gap:.3rem}
.seg{display:inline-flex;border:1px solid var(--axis);border-radius:8px;overflow:hidden;width:fit-content;max-width:100%}
.seg button{border:0;background:transparent;padding:.4rem .85rem;font-size:.8125rem;font-weight:600;cursor:pointer;color:var(--ink-2);white-space:nowrap}
.seg button+button{border-left:1px solid var(--axis)}
.seg button[aria-pressed="true"]{background:var(--ink);color:var(--page)}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chips button{border:1px solid var(--axis);background:var(--surface);border-radius:999px;padding:.25rem .75rem;font-size:.8125rem;cursor:pointer;color:var(--ink-2)}
.chips button[aria-pressed="true"]{border-color:var(--ink);color:var(--ink);font-weight:600}
.graph-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;margin-inline:-.25rem}
.graph{display:block;width:100%;min-width:56rem;height:auto;font-family:var(--sans)}
.graph .e{fill:none;stroke:var(--axis);stroke-width:1.5;marker-end:url(#ah);transition:opacity .15s}
.graph .ah{fill:var(--axis)}
.graph .ah-on{fill:var(--blue)}
.graph .nd rect{fill:var(--surface);stroke:var(--axis);stroke-width:1}
.graph .nd text{font-size:12px;fill:var(--ink);text-anchor:middle}
.graph .nd .entry-bar{fill:var(--ink-2);stroke:none}
.graph .k-ai rect{fill:var(--violet-tint);stroke:var(--violet);stroke-width:1.5}
.graph .k-jewel rect{stroke:var(--ink);stroke-width:2}
.graph .k-jewel text{font-weight:650}
.graph .k-id text{fill:var(--ink-2)}
.graph .nd{transition:opacity .15s;cursor:default}
.graph.m-ai [data-m]:not([data-m~="ai"]).e,.graph.m-base [data-m]:not([data-m~="base"]).e{display:none}
.graph.m-ai .nd:not([data-m~="ai"]),.graph.m-base .nd:not([data-m~="base"]){opacity:.35}
.graph.m-ai .nd:not([data-m~="ai"]) rect,.graph.m-base .nd:not([data-m~="base"]) rect{stroke-dasharray:4 3;fill:none}
.graph.has-sel .e:not(.on),.graph.has-sel .nd:not(.on){opacity:.15}
.graph .e.on{stroke:var(--blue);stroke-width:2.5;marker-end:url(#ah-on)}
.graph .nd.on rect{stroke-width:2.5}
.graph .k-asset.on rect,.graph .k-id.on rect{stroke:var(--blue)}
.base-only{display:none!important}
.graph-card.m-base .base-only{display:inline-flex!important}
.explore{display:grid;gap:1rem;border-top:1px solid var(--border);padding-top:1rem}
.picker{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(16.5rem,1fr));gap:4px 8px;align-content:start}
.pick{display:grid;grid-template-columns:1.6rem minmax(0,1fr) auto;gap:.5rem;align-items:center;width:100%;text-align:left;
border:1px solid transparent;border-radius:8px;background:transparent;padding:.4rem .55rem;cursor:pointer;font-size:.875rem}
.pick:hover{background:var(--sunken)}
.pick[aria-pressed="true"]{border-color:var(--blue);background:var(--sunken)}
.pick .rank{font-size:.875rem;color:var(--muted);font-weight:700;font-variant-numeric:tabular-nums}
.pick-score{font-weight:650;font-variant-numeric:tabular-nums}
.graph-card.m-base .pick[data-absent]{opacity:.45}
.graph-card.m-base .pick[data-absent] .pick-name::after{content:" · not visible to a scanner";color:var(--muted);font-size:.75rem}
.ai-mark{display:inline-block;width:8px;height:8px;margin-left:.35rem;border-radius:2px;background:var(--violet);vertical-align:middle}
.stories{min-width:0}
.story,.story-empty{display:grid;gap:.6rem;align-content:start;padding:1rem 1.1rem;border-radius:8px;background:var(--sunken)}
.story-title{font-weight:650;font-size:1rem;display:flex;flex-wrap:wrap;align-items:center;gap:.35rem .6rem}
.story-title .rank{color:var(--muted)}
.story-score{font-variant-numeric:tabular-nums}
.story-steps{margin:0;padding-left:1.25rem;display:grid;gap:.4rem;font-size:.875rem}
.mini-h{font-size:.75rem;font-weight:650;letter-spacing:.07em;text-transform:uppercase;color:var(--ink-2)}
.plain{margin:0;padding-left:1.1rem;display:grid;gap:.25rem;font-size:.875rem}
.two{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}
.mini{list-style:none;margin:0;padding:0;display:grid}
.mini li{display:grid;grid-template-columns:1.6rem minmax(0,1fr) auto;gap:.6rem;align-items:baseline;padding-block:.45rem;border-top:1px solid var(--grid);font-size:.875rem}
.mini li:first-child{border-top:0}
.mini .step{color:var(--muted);font-weight:700;font-variant-numeric:tabular-nums}
.mini-main{display:flex;flex-wrap:wrap;gap:.1rem .5rem;align-items:baseline;min-width:0}
.mini-main .sub{flex-basis:100%}
.mini-val{font-weight:650;font-variant-numeric:tabular-nums;white-space:nowrap}
.fid{display:inline-flex;align-items:baseline;gap:.35rem;white-space:nowrap}
.fid .rule{font-size:.6875rem;color:var(--muted);font-family:var(--mono)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(10rem,1fr));gap:12px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:.8rem 1rem;display:grid;gap:.1rem}
.stat .num{font-size:1.5rem;font-weight:700;line-height:1.2;font-variant-numeric:tabular-nums}
.tc-list{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,26rem),1fr));gap:12px}
.tc-card{display:grid;gap:.5rem;align-content:start;padding:.9rem 1rem;border:1px solid var(--border);border-radius:8px;scroll-margin-top:3.5rem}
.tc-title{font-weight:650;display:flex;flex-wrap:wrap;gap:.3rem .6rem;align-items:center}
.tc-name{flex-basis:100%}
.tc-sum{font-size:.875rem;color:var(--ink-2);max-width:80ch}
.ingredients{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:6px}
.ingredients{flex-direction:column;gap:4px}
.ingredients li{font-size:.8125rem;padding:2px 9px;border-left:3px solid var(--axis);display:flex;flex-wrap:wrap;gap:.2rem .5rem;align-items:baseline}
.ingredients .fid{font-size:.75rem;color:var(--muted)}
.facts{display:flex;flex-wrap:wrap;gap:.25rem 1.25rem;font-size:.8125rem;color:var(--ink-2)}
.paths,.fixes{list-style:none;margin:0;padding:0;display:grid}
.path,.fix{display:grid;grid-template-columns:2rem minmax(0,1fr);gap:.25rem 1rem;padding-block:1.1rem;border-top:1px solid var(--border);scroll-margin-top:3.5rem}
.path:first-child,.fix:first-child{border-top:0;padding-top:.25rem}
.path:last-child,.fix:last-child{padding-bottom:0}
.rank{font-size:1.125rem;line-height:1.45;font-weight:700;color:var(--muted);font-variant-numeric:tabular-nums}
.path-main,.fix-main{display:grid;gap:.55rem;min-width:0}
.path-title,.fix-title{font-weight:650;font-size:1rem;line-height:1.4}
.path-title .arrow{color:var(--muted);font-weight:400}
.fix-what{font-size:.875rem}
.fix-do{font-size:.875rem;color:var(--ink-2)}
.score{display:grid;grid-template-columns:18rem 3rem auto;align-items:center;gap:.75rem;justify-content:start;width:fit-content;max-width:100%}
.track{display:block;height:10px;background:var(--sunken);border-radius:0 4px 4px 0}
.fill{display:block;height:100%;background:var(--blue);border-radius:0 4px 4px 0}
.score .val{font-weight:700;text-align:right;font-variant-numeric:tabular-nums}
.why{display:grid;gap:.4rem;margin-bottom:.75rem}
.why-row{display:grid;grid-template-columns:6.5rem 12rem 3rem minmax(0,1fr);gap:.75rem;align-items:center;font-size:.8125rem}
.why-row .sub{display:inline}
.why-val{font-variant-numeric:tabular-nums;text-align:right;font-weight:600}
.lvl{display:inline-flex;align-items:center;gap:6px;font-size:.8125rem;font-weight:600;white-space:nowrap}
.lvl i{flex:none;width:9px;height:9px;border-radius:50%;background:var(--c,var(--muted))}
.l-critical{--c:var(--critical)}.l-high{--c:var(--serious)}.l-medium{--c:var(--warning)}.l-low{--c:var(--muted)}
.chain{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;align-items:center;gap:6px}
.chain li{display:inline-flex;align-items:center;gap:6px;min-width:0;max-width:100%}
.chain li+li::before{content:"\\2192";color:var(--muted)}
.chip{display:inline-flex;align-items:center;gap:6px;padding:1px 9px;border:1px solid var(--axis);border-radius:999px;font-size:.8125rem;line-height:1.55;background:var(--surface);min-width:0;overflow-wrap:anywhere}
.chip.ai{border:1.5px solid var(--violet);background:var(--violet-tint)}
.chip.jewel{font-weight:650;border:2px solid var(--ink)}
.tags{display:flex;flex-wrap:wrap;gap:6px}
.tag{font-size:.75rem;padding:1px 8px;border-radius:4px;background:var(--sunken);color:var(--ink-2)}
.tag.strong{color:var(--ink);font-weight:600}
.tag.tc{background:transparent;border:1px solid var(--critical);color:var(--ink)}
details>summary{cursor:pointer;font-size:.875rem;color:var(--ink-2);width:fit-content;max-width:100%}
details>summary:hover{color:var(--ink)}
details[open]>summary{margin-bottom:.6rem}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;min-width:0}
table{width:100%;border-collapse:collapse;font-size:.875rem}
table.wide{min-width:48rem}
table.mid{min-width:34rem}
table.inv{min-width:56rem}
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
.views{display:grid;gap:1rem}
.view{display:grid;gap:1rem}
.shadow{display:inline-block;margin-top:.2rem;font-size:.75rem;font-weight:650;padding:0 6px;border:1.5px dashed var(--ink-2);border-radius:4px;white-space:nowrap;color:var(--ink)}
.where{font-size:.8125rem;color:var(--ink-2);min-width:14rem;line-height:1.6}
.where .k{display:inline-block;min-width:3.6rem;font-size:.6875rem;font-weight:650;letter-spacing:.05em;text-transform:uppercase;color:var(--muted)}
.flags{list-style:none;margin:0;padding:0;display:grid;gap:.45rem;min-width:18rem}
.flags summary{color:var(--ink);font-size:.8125rem;line-height:1.45}
.flags summary .lvl{margin-right:.15rem}
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
footer{border-top:1px solid var(--border);padding-top:1rem}
.proof>summary{font-size:.9375rem;font-weight:600;color:var(--ink)}
.proof-body{display:grid;gap:2rem;padding-top:.5rem}
.proof-part{display:grid;gap:.9rem}
.proof-h{font-size:1rem;letter-spacing:0;text-transform:none;color:var(--ink)}
.fw-list{display:grid;gap:.5rem}
.fw-row{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px;font-size:.8125rem}
.fw-row strong{color:var(--ink);font-weight:600;margin-right:.25rem}
#tip{position:fixed;left:0;top:0;z-index:30;max-width:min(24rem,calc(100vw - 16px));padding:.5rem .7rem;border-radius:6px;background:var(--tip-bg);color:var(--tip-ink);font-size:.8125rem;line-height:1.45;white-space:pre-line;pointer-events:none;box-shadow:0 6px 20px rgb(0 0 0/.22)}
[data-tip]:focus-visible,button:focus-visible,a:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
@media (max-width:900px){.two{grid-template-columns:minmax(0,1fr)}}
@media (max-width:760px){.kpis{grid-template-columns:minmax(0,1fr)}.strip{grid-template-columns:minmax(0,1fr)}}
@media (max-width:640px){h1{font-size:1.75rem}.hb-row{grid-template-columns:minmax(0,1fr) 4.75rem;gap:.3rem .75rem}
.hb-label{grid-column:1/-1}.path,.fix{grid-template-columns:1.5rem minmax(0,1fr);gap:.25rem .6rem}.card{padding:1rem}
.score{grid-template-columns:minmax(0,1fr) 2.75rem auto;width:100%}.why-row{grid-template-columns:5.5rem minmax(0,1fr) 2.5rem}
.why-row .sub{grid-column:1/-1}}
"""

JS = """
(function () {
  function all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function has(el, attr, token) { return (" " + (el.getAttribute(attr) || "") + " ").indexOf(" " + token + " ") >= 0; }

  /* tabs: every view shows without this script; with it, one view at a time */
  var tabs = all('[role="tab"]');
  function panelOf(el) { return el && el.closest ? el.closest('[role="tabpanel"]') : null; }
  function select(id, focusTab) {
    tabs.forEach(function (t) {
      var on = t.getAttribute("aria-controls") === id;
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.tabIndex = on ? 0 : -1;
      var p = document.getElementById(t.getAttribute("aria-controls"));
      if (p) p.hidden = !on;
      if (on && focusTab) t.focus();
    });
  }
  function remember(hash) { try { history.replaceState(null, "", hash); } catch (err) { /* sandboxed frame */ } }
  function go(hash) {
    var el = hash && hash.length > 1 ? document.getElementById(hash.slice(1)) : null;
    var p = el && (el.getAttribute("role") === "tabpanel" ? el : panelOf(el));
    if (!p) return false;
    select(p.id);
    if (el !== p) {
      var d = el.closest("details");
      if (el.tagName === "LI") { var inner = el.querySelector("details"); if (inner) inner.open = true; }
      if (d) d.open = true;
      el.scrollIntoView({ block: "start" });
    } else {
      window.scrollTo(0, 0);
    }
    return true;
  }
  if (tabs.length) {
    if (!go(location.hash)) select(tabs[0].getAttribute("aria-controls"));
    tabs.forEach(function (t, i) {
      t.addEventListener("click", function (ev) {
        ev.preventDefault();
        select(t.getAttribute("aria-controls"));
        remember("#" + t.getAttribute("aria-controls"));
      });
      t.addEventListener("keydown", function (ev) {
        var j = ev.key === "ArrowRight" ? i + 1 : ev.key === "ArrowLeft" ? i - 1 : -2;
        if (j === -2) return;
        ev.preventDefault();
        var next = tabs[(j + tabs.length) % tabs.length];
        select(next.getAttribute("aria-controls"), true);
      });
    });
    all("a[data-goto]").forEach(function (a) {
      a.addEventListener("click", function (ev) {
        var hash = a.getAttribute("href");
        if (go(hash)) { ev.preventDefault(); remember(hash); }
      });
    });
  }

  /* segmented controls: one [data-view] of the group at a time */
  all(".seg[data-group]").forEach(function (seg) {
    var group = seg.getAttribute("data-group");
    var buttons = all("button[data-show]", seg);
    function show(key) {
      buttons.forEach(function (b) { b.setAttribute("aria-pressed", b.getAttribute("data-show") === key ? "true" : "false"); });
      all('[data-views="' + group + '"] > [data-view]').forEach(function (v) { v.hidden = v.getAttribute("data-view") !== key; });
    }
    buttons.forEach(function (b) { b.addEventListener("click", function () { show(b.getAttribute("data-show")); }); });
    if (!seg.hasAttribute("data-graph")) show(buttons[0].getAttribute("data-show"));
  });

  /* filter chips */
  all(".chips[data-list]").forEach(function (box) {
    var list = document.getElementById(box.getAttribute("data-list"));
    var buttons = all("button[data-f]", box);
    buttons.forEach(function (b) {
      b.addEventListener("click", function () {
        var f = b.getAttribute("data-f");
        buttons.forEach(function (x) { x.setAttribute("aria-pressed", x === b ? "true" : "false"); });
        all("[data-tags]", list).forEach(function (it) { it.hidden = f !== "all" && !has(it, "data-tags", f); });
      });
    });
  });

  /* the attack-path graph: pick a path, switch between with and without AI discovery */
  all("[data-graph-card]").forEach(function (card) {
    var svg = card.querySelector("svg.graph");
    if (!svg) return;
    var mode = "ai", key = null;
    var picks = all("button.pick", card), stories = all(".story", card), empty = card.querySelector(".story-empty");
    var marks = all("[data-p]", svg);
    function paint() {
      svg.classList.toggle("m-ai", mode === "ai");
      svg.classList.toggle("m-base", mode === "base");
      card.classList.toggle("m-base", mode === "base");
      var tok = key ? (mode === "ai" ? "p" : "q") + key : null;
      svg.classList.toggle("has-sel", !!tok);
      marks.forEach(function (el) { el.classList.toggle("on", !!tok && has(el, "data-p", tok)); });
      picks.forEach(function (b) { b.setAttribute("aria-pressed", b.getAttribute("data-key") === key ? "true" : "false"); });
      stories.forEach(function (s) { s.hidden = s.getAttribute("data-key") !== key; });
      if (empty) empty.hidden = !!key;
    }
    picks.forEach(function (b) {
      b.addEventListener("click", function () { key = key === b.getAttribute("data-key") ? null : b.getAttribute("data-key"); paint(); });
    });
    all(".seg[data-graph] button", card).forEach(function (b) {
      b.addEventListener("click", function () {
        mode = b.getAttribute("data-show");
        all(".seg[data-graph] button", card).forEach(function (x) { x.setAttribute("aria-pressed", x === b ? "true" : "false"); });
        paint();
      });
    });
    paint();
  });

  /* tooltips */
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
