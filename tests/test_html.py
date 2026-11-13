"""The HTML dashboard: one self-contained file, with untrusted text kept inert."""

import re
from html.parser import HTMLParser

from ai_taint_path.cli import main
from ai_taint_path.output.html import render_html
from ai_taint_path.output.report import build_report

from conftest import GENERATED_AT, SAMPLE

VOID = {"meta", "br", "img", "input", "link", "hr", "wbr", "source", "col", "area", "base", "embed", "track"}


class Balance(HTMLParser):
    """Collects tag-nesting errors and every attribute that could load something."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.errors, self.loads, self.comments = [], [], [], 0

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if name in ("src", "srcset", "action") or (name == "href" and not (value or "").startswith("#")):
                self.loads.append((tag, name, value))
        if tag not in VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"</{tag}> closes <{self.stack[-1] if self.stack else None}>")
        else:
            self.stack.pop()

    def handle_comment(self, data):
        self.comments += 1


def parse(markup):
    p = Balance()
    p.feed(markup)
    p.close()
    return p


def test_dashboard_is_well_formed_and_self_contained(report):
    page = render_html(report)
    assert page.startswith("<!doctype html>")
    p = parse(page)
    assert p.errors == [] and p.stack == []
    assert p.loads == [], "the dashboard must not load anything from the network"
    assert "<title>Halden Logistics attack paths</title>" in page


def test_untrusted_text_is_escaped(report):
    page = render_html(report)
    # the poisoned tool description and the poisoned ticket attachment from the sample
    assert "<IMPORTANT>" not in page and "&lt;IMPORTANT&gt;" in page
    assert "<!-- Assistant" not in page and "&lt;!-- Assistant" in page
    assert parse(page).comments == 0
    assert "pdfapi-EXAMPLE" not in page


def test_dashboard_tells_the_story(report):
    page = render_html(report)
    s = report["summary"]
    assert f"{s['exposure_index']:.1f}" in page
    assert f"{s['top_paths_through_ai']} of the top 10" in page
    assert "6 of 6 crown jewels" in page and "1 fix closes 5 paths" in page and "8 shadow AI components" in page
    assert "is #11 on that list" in page  # the VPN fix that a CVSS-sorted list ranks 11th
    for p in report["paths"]:
        assert p["id"].replace(">", "&gt;") in page
    assert len(re.findall(r'<li class="path" id="path-\d+"', page)) == len(report["paths"])


def test_four_views_behind_tabs(report):
    page = render_html(report)
    tabs = re.findall(r'<a role="tab" id="tab-(\w+)" href="#(\w+)" aria-controls="(\w+)"', page)
    assert [t[0] for t in tabs] == ["overview", "paths", "fixes", "ai"]
    for name, href, panel in tabs:
        assert name == href == panel
        assert f'<section id="{panel}" class="panel" role="tabpanel" aria-labelledby="tab-{panel}"' in page
    # how the report was made stays one click away, below the views
    assert '<footer id="proof"><details class="proof">' in page and 'id="method"' in page


def test_graph_draws_every_top_path_in_both_modes(report):
    page = render_html(report)
    svg = re.search(r'<svg class="graph m-ai".*?</svg>', page, re.S).group(0)
    edges = re.findall(r'<path class="e" d="[^"]+" data-p="([^"]*)" data-m="([^"]*)"/>', svg)
    nodes = re.findall(r'<g class="nd k-(\w+)" data-p="([^"]*)" data-m="([^"]*)"', svg)
    top = [p for p in report["paths"] if p["top"]]
    for p in top:
        key = f"p{p['rank']}"
        assert sum(key in ks.split() for ks, _ in edges) == len(p["nodes"]) - 1, p["id"]
        assert sum(key in ks.split() for _, ks, _ in nodes) == len(p["nodes"]), p["id"]
        assert f'<button type="button" class="pick" data-key="{p["rank"]}"' in page
        assert re.search(rf'<div class="detail" data-keys="p{p["rank"]}( q{p["rank"]})?" hidden>', page)
    # scanner-only routes are drawn too, so the toggle shows what discovery adds
    base = {b["id"] for b in report["baseline"]["paths"]}
    for p in top:
        assert any(f"q{p['rank']}" in ks.split() for ks, _ in edges) == (p["id"] in base)
    # AI components that only discovery sees are not part of any scanner-only route
    assert all(modes == "ai" for kind, _, modes in nodes if kind == "ai")
    # every box carries an icon for what it is, and every icon used on the page is drawn on the page
    assert svg.count('<use class="ni" href="#i-') == len(nodes)
    assert set(re.findall(r'href="#(i-[a-z]+)"', page)) <= set(re.findall(r'<symbol id="(i-[a-z]+)"', page))


def detail_of(page, key):
    """The detail block of one path on the Overview, by its key (p3 with discovery, q3 scanner-only)."""
    start = re.search(rf'<div class="detail" data-keys="[^"]*\b{key}\b[^"]*" hidden>', page)
    return page[start.start():page.index('<div class="detail', start.end())] if start else None


def test_selected_path_shows_technical_detail(report):
    page = render_html(report)
    base = {b["id"]: b for b in report["baseline"]["paths"]}
    for p in (p for p in report["paths"] if p["top"]):
        block = detail_of(page, f"p{p['rank']}")
        # the attacker, then one box per step, plus a box for each credential the path uses
        creds = sum(s["kind"] == "data_access" for s in p["steps"])
        assert block.count('<li class="hop">') == 1 + len(p["steps"]) + creds, p["id"]
        assert block.count('<div class="nc cred">') == creds
        # every weakness the path uses is pinned to a box, by its CVE or its own finding ID
        for fid in p["findings"]:
            f = next(x for x in report["findings"] if x["id"] == fid)
            assert f'<span class="mono">{f.get("cve") or fid}</span>' in block, (p["id"], fid)
        # hops that only discovery found are marked
        assert block.count('class="via disc"') >= sum(s["origin"] == "discovery" for s in p["steps"])
        # the scanner-only view shows the scanner's own route, or says there is none
        b = base.get(p["id"])
        scanner = detail_of(page, f"q{p['rank']}")
        assert (scanner is not None) == (b is not None), p["id"]
        if b and b["nodes"] != p["nodes"]:
            assert scanner.count('<li class="hop">') == 1 + len(b["steps"]) + sum(
                s["kind"] == "data_access" for s in b["steps"])
            assert 'class="via disc"' not in scanner
    assert '<div class="detail miss" data-miss hidden>' in page
    # a box says what it is, a known-exploited CVE carries its KEV mark, an identity shows what it may do
    assert '<span class="mono">CVE-2024-21887</span><span class="kev">KEV</span>' in page
    assert "Entra service principal</span>" in page and "AWS IAM role</span>" in page
    assert "used by a workload · AdministratorAccess" in page
    assert "exploits <span class=\"nb\">CVE-2024-21887</span>" in page and ">prompt injection</span>" in page


def test_credentials_are_boxes_and_never_values(report):
    page = render_html(report)
    # discovery read which variable holds the way into the warehouse database, and as which account
    assert "Database account analytics" in page
    assert "WAREHOUSE_DSN in .vscode/mcp.json on Python data pipeline hosts · value not recorded" in page
    # a CMDB link that names no credential says so instead of inventing one
    assert "Stored database credential" in page and "not named in the source data" in page
    assert "postgresql://" not in page and "pdfapi-EXAMPLE" not in page


def test_findings_show_their_own_ids(report):
    page = render_html(report)
    # two agents break the same rule; each fix shows its own finding ID next to the rule
    plan = {x["finding"] for x in report["remediation_plan"]}
    assert {"D-001", "D-003"} <= plan
    for fid in ("D-001", "D-003"):
        assert f'<span class="mono">{fid}</span><span class="rule">rule AI-AGT-001</span>' in page


def test_toxic_combinations_are_shown(report):
    page = render_html(report)
    assert report["toxic_combinations"]
    for c in report["toxic_combinations"]:
        assert f'id="{c["id"].lower()}"' in page
    assert f'All {len(report["toxic_combinations"])} in the AI inventory' in page


def test_fragment_mode_has_no_document_skeleton(report):
    fragment = render_html(report, standalone=False)
    assert fragment.startswith("<title>")
    assert not re.search(r"<!doctype|<(html|head|body)[\s>]", fragment, re.I)
    p = parse(fragment)
    assert p.errors == [] and p.stack == []


def test_dashboard_without_discovery(baseline):
    page = render_html(build_report(baseline, top=10, generated_at=GENERATED_AT))
    p = parse(page)
    assert p.errors == [] and p.stack == []
    assert 'id="ai"' not in page and 'id="method"' not in page
    assert "AI discovery off" in page
    assert 'data-group="mode"' not in page  # no scanner-only toggle without discovery
    assert 'id="tab-ai"' not in page
    # paths still open in technical detail, with nothing marked as found by discovery
    assert '<div class="detail" data-keys="p1" hidden>' in page and '<li class="hop">' in page
    assert 'class="via disc"' not in page and '<div class="detail miss"' not in page


def test_cli_html_output(capsys):
    assert main(["scan", str(SAMPLE), "--format", "html", "--generated-at", GENERATED_AT]) == 0
    out = capsys.readouterr().out
    assert out.startswith("<!doctype html>") and out.rstrip().endswith("</html>")


def test_published_dashboard_is_current(report):
    example = (SAMPLE.parent.parent.parent / "examples" / "halden-dashboard.html").read_text()
    assert example == render_html(report), "run: python -m ai_taint_path scan data/sample/halden --format html " \
                                           "--generated-at 2026-11-05T00:00:00Z --out examples/halden-dashboard.html"
