"""Refresh data/frameworks/techniques.json from the official framework sources.

Discovery rules and attack-path hops cite technique IDs from MITRE ATT&CK and
MITRE ATLAS, and risk IDs from the two OWASP GenAI Top 10 lists. This script
downloads ATT&CK and ATLAS, checks that every ID the tool cites still exists
(and is not revoked or deprecated), and stores the official names so the
reports never show an ID we made up.

Run:  pip install pyyaml && python scripts/refresh_frameworks.py
"""

from __future__ import annotations

import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "frameworks" / "techniques.json"
sys.path.insert(0, str(ROOT))

from ai_taint_path.frameworks import REFERENCED  # noqa: E402

ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
ATLAS_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
UA = {"User-Agent": "ai-taint-path/0.2 (+https://github.com/yaronimac/ai-taint-path)"}

# The OWASP lists are short documents, not machine-readable feeds, so their
# names are kept here and reviewed by hand when a new edition ships.
OWASP_AGENTIC = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}
OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120) as resp:
        return resp.read()


def attack_index(bundle: dict) -> dict[str, dict]:
    index = {}
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if ref:
            index[ref["external_id"]] = {"name": obj["name"], "url": ref.get("url")}
    for tid, item in index.items():  # "Valid Accounts: Cloud Accounts", the way ATT&CK writes it
        if "." in tid and tid.split(".")[0] in index:
            item["name"] = f"{index[tid.split('.')[0]]['name']}: {item['name']}"
    return index


def atlas_index(atlas: dict) -> dict[str, dict]:
    index = {}
    for matrix in atlas["matrices"]:
        for tech in matrix["techniques"]:
            index[tech["id"]] = {"name": tech["name"], "parent": tech.get("subtechnique-of")}
    for tid, item in index.items():
        parent = item.pop("parent")
        if parent:
            item["name"] = f"{index[parent]['name']}: {item['name']}"
        item["url"] = f"https://atlas.mitre.org/techniques/{tid}"
    return index


def main() -> None:
    import yaml  # dev-only dependency, needed just for this script

    attack = attack_index(json.loads(fetch(ATTACK_URL)))
    atlas_doc = yaml.safe_load(fetch(ATLAS_URL))
    atlas = atlas_index(atlas_doc)

    missing = [t for t in REFERENCED["attack"] if t not in attack] + [t for t in REFERENCED["atlas"] if t not in atlas]
    missing += [t for t in REFERENCED["owasp_agentic"] if t not in OWASP_AGENTIC]
    missing += [t for t in REFERENCED["owasp_llm"] if t not in OWASP_LLM]
    if missing:
        sys.exit(f"These cited IDs no longer exist upstream: {missing}")

    out = {
        "sources": {
            "attack": {"url": ATTACK_URL, "retrieved": date.today().isoformat()},
            "atlas": {"url": ATLAS_URL, "version": atlas_doc.get("version"), "retrieved": date.today().isoformat()},
            "owasp_agentic": {"title": "OWASP Top 10 for Agentic Applications (December 2025)", "url": "https://genai.owasp.org/"},
            "owasp_llm": {"title": "OWASP Top 10 for LLM Applications 2025", "url": "https://genai.owasp.org/llm-top-10/"},
        },
        "attack": {t: attack[t] for t in sorted(REFERENCED["attack"])},
        "atlas": {t: atlas[t] for t in sorted(REFERENCED["atlas"])},
        "owasp_agentic": {t: {"name": n} for t, n in OWASP_AGENTIC.items()},
        "owasp_llm": {t: {"name": n} for t, n in OWASP_LLM.items()},
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, indent=2) + "\n")
    print(f"Wrote {OUT.relative_to(ROOT)}: {len(out['attack'])} ATT&CK, {len(out['atlas'])} ATLAS, "
          f"{len(out['owasp_agentic'])} OWASP Agentic, {len(out['owasp_llm'])} OWASP LLM")


if __name__ == "__main__":
    main()
