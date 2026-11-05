"""Framework IDs this tool cites, and their official names.

Every ID below is checked against the official MITRE ATT&CK and ATLAS data by
scripts/refresh_frameworks.py, which stores the names in
data/frameworks/techniques.json. Rules and path steps may only cite IDs listed
here; a test enforces it.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

CATALOG = Path(__file__).resolve().parent.parent / "data" / "frameworks" / "techniques.json"

REFERENCED: dict[str, list[str]] = {
    "attack": [
        "T1059",      # Command and Scripting Interpreter
        "T1078.002",  # Valid Accounts: Domain Accounts
        "T1078.004",  # Valid Accounts: Cloud Accounts
        "T1190",      # Exploit Public-Facing Application
        "T1195.002",  # Supply Chain Compromise: Compromise Software Supply Chain
        "T1203",      # Exploitation for Client Execution
        "T1210",      # Exploitation of Remote Services
        "T1213",      # Data from Information Repositories
        "T1213.006",  # Data from Information Repositories: Databases
        "T1552.001",  # Unsecured Credentials: Credentials In Files
        "T1563",      # Remote Service Session Hijacking
        "T1567",      # Exfiltration Over Web Service
    ],
    "atlas": [
        "AML.T0010.005",  # AI Supply Chain Compromise: AI Agent Tool
        "AML.T0051.000",  # LLM Prompt Injection: Direct
        "AML.T0051.001",  # LLM Prompt Injection: Indirect
        "AML.T0053",      # AI Agent Tool Invocation
        "AML.T0057",      # LLM Data Leakage
        "AML.T0070",      # RAG Poisoning
        "AML.T0080.000",  # AI Agent Context Poisoning: Memory
        "AML.T0083",      # Credentials from AI Agent Configuration
        "AML.T0085.000",  # Data from AI Services: RAG Databases
        "AML.T0086",      # Exfiltration via AI Agent Tool Invocation
        "AML.T0093",      # Prompt Infiltration via Public-Facing Application
        "AML.T0109",      # AI Supply Chain Rug Pull
        "AML.T0110",      # AI Agent Tool Poisoning
    ],
    "owasp_agentic": ["ASI01", "ASI02", "ASI03", "ASI04", "ASI05", "ASI06"],
    "owasp_llm": ["LLM01", "LLM02", "LLM03", "LLM04", "LLM06", "LLM08"],
}

FRAMEWORK_TITLES = {
    "attack": "MITRE ATT&CK",
    "atlas": "MITRE ATLAS",
    "owasp_agentic": "OWASP Agentic Top 10",
    "owasp_llm": "OWASP LLM Top 10 2025",
}


@lru_cache(maxsize=1)
def catalog() -> dict:
    if not CATALOG.exists():
        return {}
    return json.loads(CATALOG.read_text())


def name(framework: str, ident: str) -> str:
    """Official name for an ID, or the ID itself if the catalog is missing."""
    return catalog().get(framework, {}).get(ident, {}).get("name", ident)


def framework_of(ident: str) -> str:
    if ident.startswith("AML."):
        return "atlas"
    if ident.startswith("ASI"):
        return "owasp_agentic"
    if ident.startswith("LLM"):
        return "owasp_llm"
    return "attack"
