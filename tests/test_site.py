"""The project site in docs/ (served by GitHub Pages): the landing page, the demo with its tour, and the brief."""

from ai_taint_path.output.html import render_html

from conftest import ROOT
from test_html import parse

DOCS = ROOT / "docs"
REPO = "https://github.com/yaronimac/ai-taint-path"


def test_demo_page_is_current(report):
    assert (DOCS / "demo.html").read_text() == render_html(report, tour=True, home="index.html"), \
        "run: python -m ai_taint_path scan data/sample/halden --format html --tour --tour-home index.html " \
        "--generated-at 2026-11-05T00:00:00Z --out docs/demo.html"


def test_pages_are_well_formed_and_every_local_link_resolves():
    for name in ("index.html", "brief.html"):
        page = (DOCS / name).read_text()
        p = parse(page)
        assert p.errors == [] and p.stack == [] and p.comments == 0, name
        for tag, attr, value in p.loads:
            if value.startswith("https://"):
                assert attr == "href", f"{name} loads {value}: pages may link out but not load from other sites"
                continue
            target = value.split("#")[0]
            assert target == "" or (DOCS / target).is_file(), f"{name}: {value} is not in docs/"
        assert "<script" not in page, f"{name} needs no script"


def test_landing_page_links_the_three_things_to_open():
    page = (DOCS / "index.html").read_text()
    for href in ("demo.html#tour", "demo.html", REPO, "brief.html", "ai-taint-path-prd-gtm-brief.pdf"):
        assert f'href="{href}"' in page
    assert (DOCS / "ai-taint-path-prd-gtm-brief.pdf").read_bytes().startswith(b"%PDF-")
    assert (DOCS / ".nojekyll").exists(), "without it GitHub Pages runs the folder through Jekyll"


def test_landing_page_numbers_match_the_scan(report):
    page = " ".join((DOCS / "index.html").read_text().split())
    s = report["summary"]
    hero = next(p for p in report["paths"] if p["rank"] == 2)
    base = next(b for b in report["baseline"]["paths"] if b["id"] == hero["id"])
    tour_steps = (DOCS / "demo.html").read_text().count("<li data-target=")
    for needle in (
        f"{s['exposure_index']} <span>of {s['exposure_index_max']}</span>",
        f"Scanner data alone shows {s['without_discovery']['exposure_index']}.",
        f"{s['top_paths_through_ai']} <span>of the top {s['top_paths']}</span>",
        f"{s['ai_not_registered']} <span>of {s['ai_components']}</span>",
        f"{s['discovery_flags']} risk flags",
        f"{s['plan']['fixes']} <span>fixes</span>",
        f"by {s['plan']['reduction_pct']}%",
        f"Score {hero['score']}",
        f"scores {base['score']}",
        f"in {tour_steps} steps",
    ):
        assert needle in page, needle


def test_brief_numbers_match_the_scan(report):
    page = " ".join((DOCS / "brief.html").read_text().split())
    s = report["summary"]
    for needle in (
        f"{s['exposure_index']} of {s['exposure_index_max']} with AI discovery, against {s['without_discovery']['exposure_index']}",
        f"{s['top_paths_through_ai']} of the top {s['top_paths']} attack paths",
        f"{s['ai_components']} AI components, {s['ai_not_registered']} of them in no inventory",
        f"{s['discovery_flags']} risk flags",
        f"{s['plan']['fixes']} fixes cut the exposure index by {s['plan']['reduction_pct']}%",
    ):
        assert needle in page, needle
