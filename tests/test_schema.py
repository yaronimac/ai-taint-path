"""The JSON output is the integration contract for SOAR and ticketing tools."""

import json

import jsonschema
import pytest

from ai_taint_path.cli import main
from ai_taint_path.output.report import build_report

from conftest import GENERATED_AT, ROOT, SAMPLE

SCHEMA = json.loads((ROOT / "schema" / "scan-result.schema.json").read_text())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.FormatChecker())


def errors(doc):
    return [f"{list(e.path)}: {e.message[:200]}" for e in VALIDATOR.iter_errors(doc)]


def test_schema_is_valid():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)


def test_scan_result_matches_the_schema(report):
    assert errors(report) == []


def test_baseline_result_matches_the_schema(baseline):
    doc = build_report(baseline, top=10, generated_at=GENERATED_AT)
    assert errors(doc) == []
    assert doc["discovery"] is None and doc["inventory"] == []


def test_published_example_is_current(report):
    example = json.loads((ROOT / "examples" / "halden-scan.json").read_text())
    regenerated = json.loads(json.dumps(report))
    assert example == regenerated, "run: python -m ai_taint_path scan data/sample/halden --format json " \
                                   "--generated-at 2026-11-05T00:00:00Z --out examples/halden-scan.json"


@pytest.mark.parametrize("args", [
    ["scan", str(SAMPLE)],
    ["scan", str(SAMPLE), "--no-discovery"],
    ["discover", str(SAMPLE)],
])
def test_cli_text_output(capsys, args):
    assert main(args) == 0
    assert capsys.readouterr().out.strip()


def test_cli_json_output(capsys):
    assert main(["scan", str(SAMPLE), "--format", "json", "--top", "5"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert errors(doc) == []
    assert sum(p["top"] for p in doc["paths"]) == 5


def test_cli_discover_json(capsys):
    assert main(["discover", str(SAMPLE), "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert len(doc["flags"]) == 25 and len(doc["inventory"]) == 19
