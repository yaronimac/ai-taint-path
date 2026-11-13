"""The guided tour: opt-in, built from the report's own numbers, and as inert as the rest of the page."""

import copy
import html
import re

import pytest

from ai_taint_path.cli import main
from ai_taint_path.output.html import _View, render_html
from ai_taint_path.output.report import build_report
from ai_taint_path.output.tour import tour_steps

from conftest import GENERATED_AT, SAMPLE
from test_html import parse

COMMANDS = {"tab", "mode", "path", "seg"}


def present(selector: str, page: str) -> list[str]:
    """The parts of a step's selector that the page does not contain."""
    missing = []
    for ident in re.findall(r"#([\w-]+)", selector):
        if f'id="{ident}"' not in page:
            missing.append(f"#{ident}")
    for attr, value in re.findall(r'\[(data-[\w-]+)(?:~?="([^"]*)")?\]', selector):
        pattern = rf'{attr}="[^"]*(?<![\w-]){re.escape(value)}(?![\w-])' if value else rf"\s{attr}[\s=>]"
        if not re.search(pattern, page):
            missing.append(f"[{attr}={value}]")
    for cls in re.findall(r"\.([\w-]+)", re.sub(r"\[[^\]]*\]", "", selector)):
        if not re.search(rf'class="[^"]*(?<![\w-]){re.escape(cls)}(?![\w-])', page):
            missing.append(f".{cls}")
    return missing


def test_the_dashboard_has_no_tour_unless_asked(report):
    page = render_html(report)
    assert "data-tour" not in page and "tourbar" not in page


def test_tour_page_is_well_formed_and_loads_nothing(report):
    page = render_html(report, tour=True)
    p = parse(page)
    assert p.errors == [] and p.stack == [] and p.comments == 0
    assert p.loads == [], "a tour without a home link must not point anywhere outside the page"
    assert max(len(line) for line in page.splitlines()) < 4000


def test_the_home_link_is_the_only_way_out(report):
    page = render_html(report, tour=True, home="./")
    assert parse(page).loads == [("a", "href", "./")] * 2  # the bar above the header and the tour's last step
    with pytest.raises(ValueError):
        render_html(report, tour=True, home="javascript:alert(1)")


def test_every_step_points_at_something_on_the_page(report):
    page = render_html(report, tour=True)
    steps = tour_steps(_View(report))
    assert len(steps) == 16
    assert steps[0]["target"] == "" and steps[-1]["target"] == "", "the tour opens and closes with a centred card"
    for step in steps:
        assert step["title"] and step["body"]
        assert present(step["target"], page) == [], step["title"]
        assert {token.split(":")[0] for token in step["setup"].split()} <= COMMANDS
        assert bool(step["do"]) or not step["click"], "a step that waits for a click says what to click"
    assert sum(step["click"] for step in steps) == 4  # a path, the scanner switch, two tabs


def test_tour_follows_the_report(report):
    text = " ".join(step["body"] + " " + step["title"] for step in tour_steps(_View(report)))
    s = report["summary"]
    assert f"{s['exposure_index']:.1f} of a possible {s['exposure_index_max']}" in text
    assert f"{s['plan']['reduction_pct']}%" in text and f"{s['ai_components']} AI components" in text
    # the path it opens is the top one through AI that a scanner under-rates: #2 in the sample
    hero = next(p for p in report["paths"] if p["rank"] == 2)
    base = next(b for b in report["baseline"]["paths"] if b["id"] == hero["id"])
    assert f"It scores {base['score']:.1f} where the real path scores {hero['score']:.1f}" in text
    assert "Ops tools server is an MCP server that answers without a login." in text


def test_tour_text_is_escaped(report):
    hostile = copy.deepcopy(report)
    hostile["environment"]["name"] = '<img src=x onerror=alert(1)>"'
    page = render_html(hostile, tour=True)
    assert "<img src=x" not in page and html.escape('<img src=x onerror=alert(1)>"') in page
    p = parse(page)
    assert p.errors == [] and p.loads == []


def test_tour_without_discovery_skips_the_ai_steps(baseline):
    report = build_report(baseline, top=10, generated_at=GENERATED_AT)
    page = render_html(report, tour=True)
    steps = tour_steps(_View(report))
    targets = [s["target"] for s in steps]
    assert "#tab-ai" not in targets and not any("data-graph" in t for t in targets)
    assert "#tab-fixes" in targets
    for step in steps:
        assert present(step["target"], page) == [], step["title"]


def test_cli_tour_flags(capsys):
    assert main(["scan", str(SAMPLE), "--format", "html", "--generated-at", GENERATED_AT, "--tour-home", "./"]) == 0
    out = capsys.readouterr().out
    assert "data-tour-start" in out and 'href="./"' in out
