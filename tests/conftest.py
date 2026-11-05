import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ai_taint_path.discovery.probe import FixtureTransport  # noqa: E402
from ai_taint_path.engine import scan  # noqa: E402
from ai_taint_path.model import load_environment, load_feeds  # noqa: E402
from ai_taint_path.output.report import build_report  # noqa: E402

SAMPLE = ROOT / "data" / "sample" / "halden"
GENERATED_AT = "2026-11-05T00:00:00Z"


@pytest.fixture(scope="session")
def env():
    return load_environment(SAMPLE)


@pytest.fixture(scope="session")
def feeds():
    return load_feeds()


@pytest.fixture(scope="session")
def expected():
    return json.loads((SAMPLE / "expected.json").read_text())


@pytest.fixture(scope="session")
def transport():
    return FixtureTransport.load(SAMPLE / "discovery" / "probes.json")


@pytest.fixture(scope="session")
def result(env, feeds, transport):
    return scan(env, feeds, transport=transport, transport_name="recorded probes (fixtures)")


@pytest.fixture(scope="session")
def report(result):
    return build_report(result, top=10, generated_at=GENERATED_AT)


@pytest.fixture(scope="session")
def baseline(env, feeds):
    return scan(env, feeds, use_discovery=False)
