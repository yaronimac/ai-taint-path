"""Download the public threat intelligence the engine uses, for the CVEs in the sample.

- CISA Known Exploited Vulnerabilities (KEV): official feed, falling back to
  CISA's own GitHub mirror (cisagov/kev-data).
- CVE records (title, CVSS, CWE): the CVE Program's cvelistV5 repository.
- FIRST EPSS scores: api.first.org. Skipped with a warning if unreachable;
  the engine treats a missing EPSS score as unknown, not as zero.

Run:  python scripts/refresh_feeds.py
Writes data/feeds/{kev.json, cve_records.json, epss.json}.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FINDINGS = ROOT / "data" / "sample" / "halden" / "findings.json"
FEEDS = ROOT / "data" / "feeds"

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]
CVE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}/{cve}.json"
EPSS_URL = "https://api.first.org/data/v1/epss?cve={cves}"


def fetch_json(url: str, timeout: int = 60):
    req = urllib.request.Request(url, headers={"User-Agent": "ai-taint-path/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_kev(cves: set[str]) -> dict:
    for url in KEV_URLS:
        try:
            data = fetch_json(url)
        except Exception as exc:  # network policy, outage, etc.
            print(f"  KEV: {url} unreachable ({exc.__class__.__name__}), trying next source")
            continue
        entries = [v for v in data["vulnerabilities"] if v["cveID"] in cves]
        return {
            "source": url,
            "catalogVersion": data["catalogVersion"],
            "dateReleased": data.get("dateReleased"),
            "retrieved": now(),
            "vulnerabilities": entries,
        }
    sys.exit("Could not download the KEV catalog from any source.")


def cvss_from(record: dict) -> tuple[float | None, str | None, str | None]:
    containers = [record["containers"]["cna"], *record["containers"].get("adp", [])]
    for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
        for c in containers:
            for m in c.get("metrics", []):
                if key in m:
                    return m[key].get("baseScore"), m[key].get("baseSeverity"), m[key].get("vectorString")
    return None, None, None


def load_cve_records(cves: set[str]) -> dict:
    out = {}
    for cve in sorted(cves):
        _, year, num = cve.split("-")
        url = CVE_URL.format(year=year, bucket=num[:-3] + "xxx", cve=cve)
        record = fetch_json(url)
        cna = record["containers"]["cna"]
        score, severity, vector = cvss_from(record)
        cwes = [d.get("cweId") for p in cna.get("problemTypes", []) for d in p.get("descriptions", []) if d.get("cweId")]
        out[cve] = {
            "title": cna.get("title") or cna["descriptions"][0]["value"].split(". ")[0][:160],
            "description": cna["descriptions"][0]["value"],
            "cvss": score,
            "severity": severity,
            "vector": vector,
            "cwe": sorted(set(cwes)),
            "published": record["cveMetadata"].get("datePublished"),
        }
        print(f"  CVE: {cve} cvss={score}")
    return {"source": "https://github.com/CVEProject/cvelistV5", "retrieved": now(), "records": out}


def load_epss(cves: set[str]) -> dict:
    try:
        data = fetch_json(EPSS_URL.format(cves=",".join(sorted(cves))))
    except Exception as exc:
        print(f"  EPSS: api.first.org unreachable ({exc.__class__.__name__}); scores left unknown")
        return {"source": "https://api.first.org/data/v1/epss", "retrieved": None, "scores": {}}
    scores = {row["cve"]: {"epss": float(row["epss"]), "percentile": float(row["percentile"]), "date": row["date"]} for row in data["data"]}
    return {"source": "https://api.first.org/data/v1/epss", "retrieved": now(), "scores": scores}


def main() -> None:
    findings = json.loads(FINDINGS.read_text())
    cves = {f["cve"] for f in findings if f.get("cve")}
    # CVEs the discovery agent can raise from MCP package versions it finds
    packages = json.loads((FEEDS / "mcp_packages.json").read_text())["packages"]
    cves |= {p["cve"] for p in packages}
    print(f"Refreshing feeds for {len(cves)} CVEs")
    FEEDS.mkdir(parents=True, exist_ok=True)
    (FEEDS / "kev.json").write_text(json.dumps(load_kev(cves), indent=2) + "\n")
    (FEEDS / "cve_records.json").write_text(json.dumps(load_cve_records(cves), indent=2) + "\n")
    epss_path = FEEDS / "epss.json"
    epss = load_epss(cves)
    if epss["scores"] or not epss_path.exists():
        epss_path.write_text(json.dumps(epss, indent=2) + "\n")
    print("Done.")


if __name__ == "__main__":
    main()
