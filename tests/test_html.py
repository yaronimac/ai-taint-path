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
        assert f'<div class="story" data-key="{p["rank"]}" hidden>' in page
    # scanner-only routes are drawn too, so the toggle shows what discovery adds
    base = {b["id"] for b in report["baseline"]["paths"]}
    for p in top:
        assert any(f"q{p['rank']}" in ks.split() for ks, _ in edges) == (p["id"] in base)
    # AI components that only discovery sees are not part of any scanner-only route
    assert all(modes == "ai" for kind, _, modes in nodes if kind == "ai")


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


def test_cli_html_output(capsys):
    assert main(["scan", str(SAMPLE), "--format", "html", "--generated-at", GENERATED_AT]) == 0
    out = capsys.readouterr().out
    assert out.startswith("<!doctype html>") and out.rstrip().endswith("</html>")


def test_published_dashboard_is_current(report):
    example = (SAMPLE.parent.parent.parent / "examples" / "halden-dashboard.html").read_text()
    assert example == render_html(report), "run: python -m ai_taint_path scan data/sample/halden --format html " \
                                           "--generated-at 2026-11-05T00:00:00Z --out examples/halden-dashboard.html"
