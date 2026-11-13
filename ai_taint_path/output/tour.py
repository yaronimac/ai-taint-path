"""A guided tour of the dashboard (`scan --format html --tour`), for demos.

The tour walks a first-time reader through the report in about two minutes. It
dims the page, puts a ring around one thing at a time (a number, a button, a
path), and explains it in a small pop-up. Some steps ask the reader to click the
ringed button; clicking it moves the tour on, and so does Next, which makes the
same click for them. Every step sets the page to the state it describes, so
Back works too.

The steps are written here, in Python, from the report's own numbers, so the
tour reads correctly for any scan. They are HTML-escaped like the rest of the
page: the script reads them with textContent, clicks the page's own controls
and positions the ring and the pop-up. It builds no markup and loads nothing.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..engine.toxic import PHRASES
from .html import _View, e, num, plural, short

ARTICLES = {"agent": "an AI agent", "mcp_server": "an MCP server", "knowledge_base": "a knowledge base",
            "vector_store": "a vector database"}


def _hero(v: _View) -> dict | None:
    """The path the tour opens: the top-ranked one through AI, best of all one a scanner under-rates."""
    through_ai = [p for p in v.top if p["ai_nodes"]]
    differs = [p for p in through_ai if p["id"] in v.base and v.base[p["id"]]["nodes"] != p["nodes"]]
    return (differs or through_ai or v.top or [None])[0]


def tour_steps(v: _View) -> list[dict]:
    """The tour as a list of steps: title, body, what to ring, the state to set, and the hint to act."""
    s, r = v.s, v.r
    steps: list[dict] = []

    def add(title: str, body: str, target: str = "", setup: str = "", do: str = "", click: bool = False) -> None:
        steps.append({"title": title, "body": body, "target": target, "setup": setup, "do": do, "click": click})

    home = "tab:overview mode:ai path:0"
    company = r["environment"]["name"]
    hero = _hero(v)
    top_n = len(v.top)
    invisible = sum(1 for p in v.top if p["id"] not in v.base)

    if r["environment"].get("fictional") and v.discovery:
        intro = (f"{company} is a fictional company with real CVEs. Its security team runs a vulnerability scanner, "
                 f"and nobody has mapped its AI agents. This tour shows what that hides, and what to fix first.")
    else:
        intro = f"This is the attack-path report for {company}. The tour shows how to read it and what to fix first."
    add("A two-minute tour", intro, setup=home, do="Press Next to start. Esc ends the tour at any time.")

    answers = (f"{s['crown_jewels_reachable']} of {plural(s['crown_jewels'], 'crown jewel')} can be reached from an "
               f"entry point.")
    chokes = r["choke_points"]
    if chokes and len(chokes[0]["paths_closed"]) > 1:
        answers += f" One fix closes {len(chokes[0]['paths_closed'])} paths."
    if v.discovery:
        answers += (f" And {plural(s['ai_not_registered'], 'AI component')} are in no inventory, so nobody is "
                    f"watching them.")
    add("Start with the answers", answers, ".kpis", home)

    index = (f"The exposure index adds up the worst path to each crown jewel: {num(s['exposure_index'])} of a "
             f"possible {s['exposure_index_max']}.")
    if v.discovery:
        base = s["without_discovery"]["exposure_index"]
        index += (f" Scanner data alone shows {num(base)}. The other {num(max(0.0, s['exposure_index'] - base))} is "
                  f"exposure this company has and cannot see.")
    add("One number for the board", index, ".strip", home)

    if not hero:
        add("That is the tour", "No path reaches a crown jewel in this scan, so there is nothing to trace.", setup=home)
        return steps

    k = hero["rank"]
    add("Every route to a crown jewel",
        "Entry points are on the left and crown jewels have a bold border."
        + (" Violet boxes are AI agents, MCP servers, knowledge bases and vector databases." if v.discovery else "")
        + " The icon shows what each box is. Hovering a path in the list traces it on the map.", "[data-map]", home)

    what = "the highest-ranked route that runs through AI" if hero["ai_nodes"] else "the highest-ranked route"
    add("Open a path",
        f"Path {k} is {what}: from {v.label(hero['entry'])[0]} to {short(hero['target_name'])}, with a score of "
        f"{num(hero['score'])}.", f'button.pick[data-key="{k}"]', home,
        "Click the highlighted path, or press Next.", click=True)

    opened = f"tab:overview mode:ai path:{k}"
    add("The path, hop by hop",
        "Each box is a real component, with its type and the facts the scan holds about it. A red badge is the "
        "weakness the attacker uses, on the box it sits on. Each arrow says how the hop works, with its ATT&CK or "
        "ATLAS technique.", f'.detail[data-keys~="p{k}"] .hops', opened)

    if hero["ai_nodes"] and v.discovery:
        node = hero["ai_nodes"][0]
        flaw = next((PHRASES[v.findings[f]["rule"]] for f in hero["findings"]
                     if v.findings.get(f, {}).get("asset") == node and v.findings[f].get("rule") in PHRASES), None)
        kind = ARTICLES.get(v.nodes.get(node, {}).get("kind"), "an AI component")
        line = f"{v.label(node)[0]} is {kind}" + (f" that {flaw}." if flaw else " on this route.")
        add("The part a scanner cannot see",
            f"{line} No vulnerability scanner reports it. Violet arrows are hops that only AI discovery found.",
            f'.detail[data-keys~="p{k}"] .nc.ai', opened)

        add("Now look through a scanner's eyes",
            "This switch redraws the same company from scanner, CMDB and posture data only, which is the view most "
            "security teams have today.", '.seg[data-graph] button[data-show="base"]', opened,
            "Click Scanner data only, or press Next.", click=True)

        base = v.base.get(hero["id"])
        gone = f" {invisible} of the top {top_n} paths have no scanner route at all." if invisible else ""
        if base and base["nodes"] != hero["nodes"]:
            add("Same target, weaker story",
                f"A scanner still finds a route to {short(hero['target_name'])}, but a weaker one. It scores "
                f"{num(base['score'])} where the real path scores {num(hero['score'])}, so it drops down the list."
                + gone, f'.detail[data-keys~="q{k}"]', f"tab:overview mode:base path:{k}")
        elif base:
            add("The same to a scanner", "This path does not depend on AI, so a scanner sees the same route." + gone,
                f'.detail[data-keys~="q{k}"]', f"tab:overview mode:base path:{k}")
        else:
            add("Nothing to see", "A scanner has no route here: the path runs through components that are in no "
                "scanner data." + gone, "[data-miss]", f"tab:overview mode:base path:{k}")

    plan = r["remediation_plan"]
    if plan:
        add("So what should be fixed first?",
            "Finding paths is half the job. The fix plan ranks fixes by how much exposure each one removes.",
            "#tab-fixes", home, "Click Fix plan, or press Next.", click=True)
        fixes = "Each bar is the exposure index after one more fix, and every path is re-scored after each one."
        from_ai = sum(1 for x in plan if x["source"] == "discovery")
        if from_ai:
            fixes += f" {from_ai} of the {len(plan)} fixes come from AI discovery."
        if plan[0].get("cvss_rank", 1) > 1:
            fixes += (f" The first fix is number {plan[0]['cvss_rank']} on a list sorted by CVSS, so sorting by "
                      f"severity would leave it for later.")
        add(f"{plural(len(plan), 'fix', 'fixes')} cut exposure by {s['plan']['reduction_pct']}%", fixes,
            "#fixes .chart", "tab:fixes seg:fixviews:plan")

    if v.discovery:
        add("Where did the AI come from?",
            "Discovery reads MCP client configs and cloud AI exports, then sends read-only probes to the hosts in "
            "scope. The AI inventory lists what it found.", "#tab-ai", "tab:fixes seg:fixviews:plan" if plan else home,
            "Click AI inventory, or press Next.", click=True)
        add("An AI bill of materials",
            f"{plural(s['ai_components'], 'AI component')}, {s['ai_not_registered']} of them in no inventory. The "
            f"table further down shows each one's inputs, tools, identity and data, with "
            f"{plural(s['discovery_flags'], 'risk flag')}.", "#ai .stats", "tab:ai")
        if v.toxic:
            add("Toxic combinations",
                f"A flag on its own is a posture finding. Joined by a real link, flags become one attack. Each of the "
                f"{plural(len(v.toxic), 'combination')} names the single fix that breaks it.", "#toxic .tc-card",
                "tab:ai")

    add("How the report was made",
        "Scoring, the frameworks and the data sources are one click away."
        + (" So are the discovery log and the safety rules: discovery only asks a server to describe itself. It "
           "never calls a tool and never stores a secret value." if v.discovery else ""), "#proof", home)

    cred = next((p for p in v.top if any(st.get("credential") for st in p["steps"])), None)
    more = (f"Try path {cred['rank']} to see a stored credential as its own box, or" if cred else "Try another path, or")
    last = "filter to the routes a scanner misses" if v.discovery else "read why each one ranks where it does"
    add("That is the tour", f"The demo is yours to explore. {more} open Attack paths and {last}.", setup=home)
    return steps


def render_tour(v: _View, home: str | None = None) -> tuple[str, str]:
    """(the bar that starts the tour, the tour itself). The bar goes above the page header."""
    if home and urlsplit(home).scheme not in ("", "http", "https"):
        raise ValueError(f"the tour's home link must be a relative or http(s) address, not {home!r}")
    link = f'<a class="tour-about" href="{e(home)}">About this project</a>' if home else ""
    bar = ('<div class="tourbar"><p><span class="tour-tag">Live demo</span> '
           + ("Fictional company, real CVEs." if v.r["environment"].get("fictional") else "Guided tour available.")
           + '</p><div class="tourbar-actions"><button type="button" class="tour-go" data-tour-start hidden>'
             f'Take the guided tour</button>{link}</div></div>')
    items = "".join(
        f'<li data-target="{e(s["target"])}" data-setup="{e(s["setup"])}"{" data-click" if s["click"] else ""}>'
        f'<span class="t">{e(s["title"])}</span><span class="b">{e(s["body"])}</span><span class="d">{e(s["do"])}</span></li>'
        for s in tour_steps(v))
    done = f'<a class="tour-about" href="{e(home)}" data-tour-home hidden>About this project</a>' if home else ""
    tour = ('<div class="tour" data-tour hidden><div class="tour-ring" data-tour-ring></div>'
            '<div class="tour-pop" data-tour-pop role="dialog" aria-labelledby="tour-title" aria-describedby="tour-body">'
            '<p class="tour-count"><span data-tour-count></span><span class="tour-track"><i data-tour-fill></i></span></p>'
            '<h2 id="tour-title" data-tour-title></h2><p id="tour-body" data-tour-body aria-live="polite"></p>'
            '<p class="tour-do" data-tour-do></p><div class="tour-nav"><button type="button" class="tour-end" data-tour-end>'
            f'End tour</button>{done}<span class="tour-gap"></span><button type="button" class="tour-back" data-tour-back>'
            'Back</button><button type="button" class="tour-next" data-tour-next>Next</button></div></div>'
            f'<ol class="tour-steps" hidden>{items}</ol></div>')
    return bar, tour


TOUR_CSS = """
.tourbar{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:.5rem 1rem;margin-bottom:1.5rem;
padding:.6rem .9rem;border:1px solid var(--border);border-radius:10px;background:var(--surface);font-size:.875rem;color:var(--ink-2)}
.tourbar-actions{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem 1rem}
.tour-tag{display:inline-block;margin-right:.35rem;padding:1px 8px;border-radius:999px;background:var(--violet-tint);
color:var(--violet);font-size:.75rem;font-weight:650;letter-spacing:.03em}
.tour-go,.tour-next{border:1px solid var(--ink);border-radius:8px;background:var(--ink);color:var(--page);padding:.4rem .9rem;
font-size:.875rem;font-weight:650;cursor:pointer}
.tour-about{font-size:.875rem;font-weight:600;color:var(--ink)}
.tour-ring{position:fixed;z-index:40;border-radius:10px;pointer-events:none;
box-shadow:0 0 0 3px var(--blue),0 0 0 200vmax rgba(0,0,0,.55);transition:left .18s,top .18s,width .18s,height .18s}
.tour-ring.none{box-shadow:0 0 0 200vmax rgba(0,0,0,.55)}
.tour-ring.pulse{animation:tour-pulse 1.3s ease-in-out infinite}
@keyframes tour-pulse{50%{box-shadow:0 0 0 7px var(--blue),0 0 0 200vmax rgba(0,0,0,.55)}}
.tour-pop{position:fixed;z-index:41;width:min(24rem,calc(100vw - 16px));display:grid;gap:.5rem;padding:1rem 1.1rem;
border:1px solid var(--axis);border-radius:12px;background:var(--surface);color:var(--ink);box-shadow:0 12px 32px rgba(0,0,0,.28)}
.tour-pop.center{left:50%;top:50%;transform:translate(-50%,-50%)}
.tour-pop.sheet{left:8px;right:8px;top:auto;bottom:8px;width:auto;transform:none}
.tour-pop h2{font-size:1.0625rem;line-height:1.3;margin:0}
.tour-pop p{margin:0;font-size:.9rem;line-height:1.5}
.tour-count{display:flex;align-items:center;gap:.6rem;font-size:.75rem!important;font-weight:650;letter-spacing:.06em;
text-transform:uppercase;color:var(--muted)}
.tour-track{flex:1 1 auto;height:3px;border-radius:2px;background:var(--sunken);overflow:hidden}
.tour-track i{display:block;height:100%;width:0;background:var(--blue);transition:width .18s}
.tour-do{font-weight:650;color:var(--blue)}
.tour-nav{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem;margin-top:.3rem}
.tour-gap{flex:1 1 auto}
.tour-end,.tour-back{border:1px solid var(--axis);border-radius:8px;background:transparent;color:var(--ink-2);padding:.4rem .8rem;
font-size:.875rem;font-weight:600;cursor:pointer}
.tour-end{border-color:transparent;padding-inline:.2rem}
.tour-back:disabled{opacity:.4;cursor:default}
@media (prefers-reduced-motion:reduce){.tour-ring,.tour-track i{transition:none}.tour-ring.pulse{animation:none}}
"""

TOUR_JS = """
(function () {
  var root = document.querySelector("[data-tour]");
  if (!root) return;
  function q(sel, base) { return (base || document).querySelector(sel); }
  function all(sel, base) { return Array.prototype.slice.call((base || document).querySelectorAll(sel)); }
  var steps = all(".tour-steps > li", root).map(function (li) {
    function text(c) { var n = q("." + c, li); return n ? n.textContent : ""; }
    return { target: li.getAttribute("data-target") || "", click: li.hasAttribute("data-click"),
             setup: (li.getAttribute("data-setup") || "").split(" ").filter(Boolean),
             title: text("t"), body: text("b"), act: text("d") };
  });
  var ring = q("[data-tour-ring]", root), pop = q("[data-tour-pop]", root);
  var count = q("[data-tour-count]", root), fill = q("[data-tour-fill]", root), title = q("[data-tour-title]", root);
  var body = q("[data-tour-body]", root), act = q("[data-tour-do]", root), home = q("[data-tour-home]", root);
  var back = q("[data-tour-back]", root), next = q("[data-tour-next]", root), end = q("[data-tour-end]", root);
  var starters = all("[data-tour-start]");
  var i = -1, el = null, off = null, opener = null, queued = false;

  /* each step sets the page to the state it describes by pressing the page's own controls */
  function press(b) {
    if (b && b.getAttribute("aria-pressed") !== "true" && b.getAttribute("aria-selected") !== "true") b.click();
  }
  var run = {
    tab: function (id) { press(document.getElementById("tab-" + id)); },
    mode: function (m) { press(q('.seg[data-graph] button[data-show="' + m + '"]')); },
    path: function (k) {
      var one = q("[data-one]"), b = q("[data-back]");
      if (k === "0") { if (one && !one.hidden && b) b.click(); }
      else press(q('button.pick[data-key="' + k + '"]'));
    },
    seg: function (g, k) { press(q('.seg[data-group="' + g + '"] button[data-show="' + k + '"]')); }
  };
  function visible(n) { return !!(n && n.getClientRects().length); }
  function find(sel) {
    var list = sel ? all(sel) : [];
    for (var j = 0; j < list.length; j++) if (visible(list[j])) return list[j];
    return null;
  }
  function narrow() { return window.innerWidth < 640; }

  /* bring the ringed thing into view, clear of the sticky tabs and with room for the pop-up */
  function bring() {
    if (!el) { window.scrollTo(0, 0); return; }
    el.scrollIntoView({ block: "nearest", inline: "nearest" });
    var r = el.getBoundingClientRect(), room = window.innerHeight * (narrow() ? 0.5 : 1);
    var want = r.height > room - 240 ? 70 : Math.max(70, (room - r.height) / 2 - (narrow() ? 0 : 70));
    window.scrollBy(0, r.top - want);
  }
  function place() {
    queued = false;
    if (i < 0) return;
    var vw = window.innerWidth, vh = window.innerHeight;
    pop.classList.toggle("sheet", narrow());
    if (!visible(el)) {
      ring.className = "tour-ring none";
      ring.style.left = vw / 2 + "px"; ring.style.top = vh / 2 + "px"; ring.style.width = ring.style.height = "0px";
      pop.classList.toggle("center", !narrow());
      pop.style.left = pop.style.top = "";
      return;
    }
    var r = el.getBoundingClientRect(), pad = 6;
    ring.className = "tour-ring" + (steps[i].click ? " pulse" : "");
    ring.style.left = (r.left - pad) + "px"; ring.style.top = (r.top - pad) + "px";
    ring.style.width = (r.width + 2 * pad) + "px"; ring.style.height = (r.height + 2 * pad) + "px";
    pop.classList.remove("center");
    if (narrow()) { pop.style.left = pop.style.top = ""; return; }
    var w = pop.offsetWidth, h = pop.offsetHeight, gap = 18, left = r.left, top;
    if (r.bottom + gap + h <= vh - 8) top = r.bottom + gap;
    else if (r.top - gap - h >= 8) top = r.top - gap - h;
    else {
      /* no room below or above: sit on the bottom corner that covers less of the target */
      top = vh - h - 8;
      var right = Math.min(vw - 8, r.right) - w;
      pop.style.pointerEvents = "none";
      if (covered(right, top, w, h) < covered(left, top, w, h)) left = right;
      pop.style.pointerEvents = "";
    }
    pop.style.top = Math.max(8, Math.min(top, vh - h - 8)) + "px";
    pop.style.left = Math.max(8, Math.min(left, vw - w - 8)) + "px";
  }
  /* how much of the target's own content a pop-up at this spot would hide: sample points, count text and marks */
  function covered(x, y, w, h) {
    var n = 0;
    for (var a = 1; a <= 5; a++) for (var b = 1; b <= 4; b++) {
      var hit = document.elementFromPoint(x + w * a / 6, y + h * b / 5);
      if (hit && hit !== el && el.contains(hit) && !hit.firstElementChild) n++;
    }
    return n;
  }
  function later() { if (!queued) { queued = true; window.requestAnimationFrame(place); } }

  function show(n) {
    if (off) { off(); off = null; }
    if (n < 0) n = 0;
    if (n >= steps.length) { stop(); return; }
    i = n;
    var s = steps[n];
    s.setup.forEach(function (tok) { var a = tok.split(":"); if (run[a[0]]) run[a[0]].apply(null, a.slice(1)); });
    el = find(s.target);
    count.textContent = "Step " + (n + 1) + " of " + steps.length;
    fill.style.width = (100 * (n + 1) / steps.length) + "%";
    title.textContent = s.title;
    body.textContent = s.body;
    act.textContent = s.act;
    act.hidden = !s.act;
    back.disabled = n === 0;
    next.textContent = n === steps.length - 1 ? "Finish" : "Next";
    end.hidden = n === steps.length - 1;
    if (home) home.hidden = n !== steps.length - 1;
    root.hidden = false;
    bring();
    place();
    if (s.click && el) {
      var target = el, on = function () { window.setTimeout(function () { if (i === n) show(n + 1); }, 0); };
      target.addEventListener("click", on);
      off = function () { target.removeEventListener("click", on); };
    }
    next.focus({ preventScroll: true });
  }
  function stop() {
    if (off) { off(); off = null; }
    i = -1;
    el = null;
    root.hidden = true;
    if (opener && opener.focus) opener.focus({ preventScroll: true });
  }
  function start(from) { opener = from || null; show(0); }

  starters.forEach(function (b) { b.hidden = false; b.addEventListener("click", function () { start(b); }); });
  next.addEventListener("click", function () { show(i + 1); });
  back.addEventListener("click", function () { show(i - 1); });
  end.addEventListener("click", stop);
  document.addEventListener("keydown", function (ev) {
    if (i < 0) return;
    if (ev.key === "Escape") { stop(); return; }
    if (!pop.contains(document.activeElement)) return;
    if (ev.key === "ArrowRight") { ev.preventDefault(); show(i + 1); }
    if (ev.key === "ArrowLeft") { ev.preventDefault(); show(i - 1); }
  });
  window.addEventListener("scroll", later, { passive: true });
  window.addEventListener("resize", later);
  if (location.hash === "#tour" && steps.length) {
    try { history.replaceState(null, "", location.pathname + location.search); } catch (err) { /* sandboxed frame */ }
    start(starters[0]);
  }
})();
"""
