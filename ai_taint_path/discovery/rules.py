"""Risk rules for discovered AI components.

Each rule is deterministic and cites the evidence it fired on. Text that came
from a server or a document (tool descriptions, sampled documents) is treated
as data: it is matched against patterns, never followed or sent to a model as
instructions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..model import Finding
from .inventory import InventoryItem

HIGH_IMPACT = ("execute", "admin", "payment", "send_external", "write")
ACCESS_LABELS = {
    "execute": "runs commands", "admin": "admin", "payment": "moves money",
    "send_external": "sends outside", "write": "writes", "read": "reads",
}
_TOKENS = {
    "execute": {"shell", "exec", "execute", "bash", "sh", "powershell", "terminal", "cmd", "command", "eval", "script"},
    "admin": {"aws", "gcloud", "az", "kubectl", "k8s", "admin", "iam", "sudo", "terraform"},
    "payment": {"pay", "payment", "payments", "transfer", "wire", "refund", "bank", "payout"},
    "send_external": {"send", "email", "mail", "webhook", "post", "publish", "upload", "tweet", "sms", "slack", "notify"},
    "write": {"update", "create", "delete", "insert", "write", "apply", "set", "put", "modify", "remove", "drop",
              "match", "reconcile", "approve", "submit", "schedule", "move", "rename", "edit"},
}


def classify_tool(name: str, description: str = "", annotations: dict | None = None) -> str:
    """What a tool can do, from its name first, then its MCP annotations, then its description."""
    tokens = set(re.split(r"[_\-.\s/:]+", name.lower()))
    for access, words in _TOKENS.items():
        if tokens & words:
            return access
    annotations = annotations or {}
    if annotations.get("readOnlyHint") is True:
        return "read"
    if annotations.get("destructiveHint") is True:
        return "write"
    words = set(re.findall(r"[a-z]+", (description or "").lower()))
    for access in ("execute", "write"):
        if words & _TOKENS[access]:
            return access
    return "read"


# --- Hidden-instruction detection ------------------------------------------
SIGNALS: dict[str, list[str]] = {
    "hidden markup": [r"<\s*(important|system|secret|instructions?)\s*>", r"<!--[\s\S]{20,}?-->", r"\[/?INST\]", r"<\|im_start\|>"],
    "instruction override": [r"\bignore (all |any |the )?(previous|prior|above|earlier) (instructions|prompts?)\b", r"\bdisregard\b",
                             r"\bbefore (using|calling|replying|answering|responding)\b", r"\byou must (first|always|now)\b",
                             r"\bthis is an approved\b"],
    "concealment": [r"\bdo not (tell|mention|inform|reveal|show|disclose)\b", r"\bdon'?t (tell|mention|reveal)\b",
                    r"\bwithout (telling|informing|notifying)\b", r"\bkeep this (secret|hidden|confidential)\b"],
    "secret access": [r"~/\.(ssh|aws|config|kube|docker)\b", r"\bid_rsa\b", r"(^|\s)\.env\b", r"\bcredentials?\b",
                      r"\b(api[_ ]?keys?|passwords?|private keys?)\b", r"\bmcp\.json\b"],
    "exfiltration": [r"\b(send|email|forward|post|upload|transmit)\b[^.]{0,120}\b[\w.+-]+@[\w-]+\.[a-z]{2,}",
                     r"\b(send|post|upload|forward)\b[^.]{0,120}https?://"],
    "invisible text": [r"[​-‏⁠-⁤﻿]", r"[\U000e0000-\U000e007f]"],
    "encoded payload": [r"[A-Za-z0-9+/]{60,}={0,2}"],
}
_COMPILED = {k: [re.compile(p, re.I) for p in v] for k, v in SIGNALS.items()}


def hidden_instruction_signals(text: str | None) -> list[str]:
    """Which kinds of hidden-instruction signal a piece of untrusted text shows."""
    if not text:
        return []
    return [kind for kind, patterns in _COMPILED.items() if any(p.search(text) for p in patterns)]


def looks_poisoned(text: str | None) -> list[str]:
    """Signals, if the text should be flagged: two kinds together, or invisible text alone."""
    signals = hidden_instruction_signals(text)
    return signals if len(signals) >= 2 or "invisible text" in signals else []


def excerpt(text: str, limit: int = 180) -> str:
    """A short, single-line piece of untrusted text for evidence. Never executed or rendered as markup."""
    m = re.search(r"<\s*important\s*>|<!--|ignore|before (using|replying)", text, re.I)
    start = m.start() if m else 0
    flat = " ".join(text[start:].split())
    return flat[:limit] + ("…" if len(flat) > limit else "")


# --- Rule catalogue -----------------------------------------------------------
@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    frameworks: dict = field(default_factory=dict)
    remediation: str = ""
    tags: tuple = ()
    ease: float | None = None


def _fw(attack=(), atlas=(), agentic=(), llm=()) -> dict:
    return {"attack": list(attack), "atlas": list(atlas), "owasp_agentic": list(agentic), "owasp_llm": list(llm)}


RULES = {r.id: r for r in [
    Rule("AI-MCP-001", "MCP server answers without authentication", "high",
         _fw(atlas=["AML.T0053"], agentic=["ASI02", "ASI03"]),
         "Require authentication (OAuth 2.1 per the MCP authorization spec, or mTLS) and bind the server to a private interface.",
         ("foothold",), 0.95),
    Rule("AI-MCP-002", "MCP server exposes high-impact tools", "high",
         _fw(atlas=["AML.T0053"], agentic=["ASI02"], llm=["LLM06"]),
         "Split read and write tools into separate servers, and require human approval for the high-impact ones."),
    Rule("AI-MCP-003", "Vulnerable MCP package", "critical",
         _fw(atlas=["AML.T0010.005"], agentic=["ASI04"], llm=["LLM03"]),
         "Upgrade the package to a fixed version."),
    Rule("AI-MCP-004", "Tool description hides instructions for the model (tool poisoning)", "critical",
         _fw(atlas=["AML.T0110", "AML.T0051.001"], agentic=["ASI01", "ASI04"], llm=["LLM01"]),
         "Disconnect the server, review what agents did with it, and pin tool descriptions so changes need re-approval.",
         ("poisoned_content",)),
    Rule("AI-MCP-005", "Secret stored in plain text in an MCP client config", "high",
         _fw(attack=["T1552.001"], atlas=["AML.T0083"], agentic=["ASI03"]),
         "Rotate the secret and load it from the OS keychain or a secrets manager instead of the config file."),
    Rule("AI-MCP-006", "MCP server missing from the AI inventory", "medium",
         _fw(agentic=["ASI04"], llm=["LLM03"]),
         "Register the server with an owner and a review date, or remove it."),
    Rule("AI-MCP-007", "MCP package not pinned to a version", "medium",
         _fw(attack=["T1195.002"], atlas=["AML.T0109"], agentic=["ASI04"], llm=["LLM03"]),
         "Pin an exact, reviewed version so an update cannot change the tools without review."),
    Rule("AI-VEC-001", "Vector database answers without authentication", "high",
         _fw(attack=["T1213.006"], atlas=["AML.T0070", "AML.T0085.000"], agentic=["ASI06"], llm=["LLM08", "LLM04"]),
         "Turn on API-key or JWT authentication and allow connections only from the application that owns the data.",
         ("foothold",), 0.95),
    Rule("AI-VEC-002", "Vector database missing from the CMDB", "medium",
         _fw(llm=["LLM08"]),
         "Add the database to the CMDB with an owner, so it is patched, backed up and scanned."),
    Rule("AI-KB-001", "Knowledge base indexes content from untrusted sources", "high",
         _fw(atlas=["AML.T0070", "AML.T0051.001", "AML.T0093"], agentic=["ASI06", "ASI01"], llm=["LLM04", "LLM01"]),
         "Keep untrusted uploads out of the index, or index them separately and mark them as untrusted for the agent.",
         ("untrusted_ingestion",)),
    Rule("AI-KB-002", "Retrieval ignores source document permissions", "high",
         _fw(attack=["T1213"], atlas=["AML.T0085.000", "AML.T0057"], agentic=["ASI03"], llm=["LLM02", "LLM08"]),
         "Turn on permission-aware retrieval so answers only use documents the asker can open."),
    Rule("AI-KB-003", "Knowledge base holds a document with hidden instructions", "critical",
         _fw(atlas=["AML.T0070", "AML.T0051.001"], agentic=["ASI06", "ASI01"], llm=["LLM01", "LLM04"]),
         "Remove the document, find who uploaded it, and screen new uploads for hidden instructions.",
         ("poisoned_content",)),
    Rule("AI-AGT-001", "Agent acts on untrusted input with high-impact tools and no human approval", "critical",
         _fw(atlas=["AML.T0053"], agentic=["ASI01", "ASI02"], llm=["LLM01", "LLM06"]),
         "Require human approval for write, payment and external-send tools, or split the agent so untrusted input cannot reach them.",
         ("steerable_by_input",)),
    Rule("AI-AGT-002", "Agent keeps memory built from untrusted input", "high",
         _fw(atlas=["AML.T0080.000"], agentic=["ASI06"], llm=["LLM04"]),
         "Do not let untrusted input write to long-term memory, or review memory changes before they are used."),
    Rule("AI-AGT-003", "AI agent missing from the AI inventory", "medium",
         _fw(),
         "Register the agent with an owner, purpose and data scope, or shut it down."),
]}

PUBLIC_AUDIENCES = ("public", "external")
EASE_PUBLIC, EASE_INTERNAL = 0.7, 0.5


def _attack_for_tools(tools: list[dict]) -> list[str]:
    out = []
    access = {t.get("access") for t in tools}
    if "execute" in access:
        out.append("T1059")
    if "admin" in access:
        out.append("T1078.004")
    if any(t.get("access") in ("write", "read") and re.search(r"sql|db|query|warehouse", t["name"], re.I) for t in tools):
        out.append("T1213.006")
    if "send_external" in access:
        out.append("T1567")
    return out


def _tool_summary(tools: list[dict], only: tuple = HIGH_IMPACT) -> str:
    picked = [t for t in tools if t.get("access") in only]
    return ", ".join(f"{t['name']} ({ACCESS_LABELS.get(t['access'], t['access'])})" for t in picked)


def _merge(base: dict, **extra) -> dict:
    out = {k: list(v) for k, v in base.items()}
    for k, v in extra.items():
        out[k] = list(dict.fromkeys(out.get(k, []) + list(v)))
    return out


def flag(rule_id: str, item_id: str, title: str, evidence: list[str], *, severity=None, ease=None,
         frameworks=None, remediation=None, cve=None, component=None, tags=None, intel=None) -> Finding:
    rule = RULES[rule_id]
    return Finding(
        id="", asset=item_id, type="cve" if cve else "ai_risk", title=title, source="discovery", rule=rule_id,
        severity=severity or rule.severity, tags=list(tags if tags is not None else rule.tags),
        ease=ease if ease is not None else rule.ease, frameworks=frameworks or {k: list(v) for k, v in rule.frameworks.items()},
        evidence=evidence, remediation=remediation or rule.remediation, cve=cve, component=component, intel=intel or {},
    )


def _version_tuple(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", v)[:3])


def package_vulnerabilities(package: str | None, version: str | None, known: list[dict]) -> list[dict]:
    if not package or not version or not re.match(r"^\d", version):
        return []
    v = _version_tuple(version)
    hits = []
    for entry in known:
        if entry["package"] != package:
            continue
        if v < _version_tuple(entry.get("introduced", "0")):
            continue
        if "last_affected" in entry and v > _version_tuple(entry["last_affected"]):
            continue
        if "fixed" in entry and v >= _version_tuple(entry["fixed"]):
            continue
        hits.append(entry)
    return hits


def evaluate(inventory: list[InventoryItem], configured: list, known_packages: list[dict]) -> list[Finding]:
    """Run every rule over the inventory. `configured` is the list of servers
    read from client configs, used for package checks on the host itself."""
    out: list[Finding] = []

    for item in inventory:
        if item.kind == "mcp_server":
            high = [t for t in item.tools if t.get("access") in HIGH_IMPACT]
            if item.auth == "none":
                access = {t.get("access") for t in item.tools}
                sev = "critical" if access & {"execute", "admin"} else "high" if high else "medium"
                out.append(flag("AI-MCP-001", item.id,
                                f"{item.name} answers MCP requests without authentication",
                                [f"probe {item.endpoint}: initialize answered with no credentials",
                                 f"tools listed to an anonymous caller: {', '.join(t['name'] for t in item.tools) or 'none'}"],
                                severity=sev, frameworks=_merge(RULES["AI-MCP-001"].frameworks, attack=_attack_for_tools(item.tools))))
            if high:
                src = "probe tools/list" if item.auth == "none" else "cloud agent export (allowed_tools)"
                out.append(flag("AI-MCP-002", item.id, f"{item.name} exposes high-impact tools: {_tool_summary(item.tools)}",
                                [f"{src}: {_tool_summary(item.tools)}"],
                                frameworks=_merge(RULES["AI-MCP-002"].frameworks, attack=_attack_for_tools(high),
                                                  atlas=["AML.T0086"] if any(t["access"] == "send_external" for t in high) else [],
                                                  owasp_agentic=["ASI05"] if any(t["access"] == "execute" for t in high) else [])))
            texts = [(f"tool {t['name']} description", t.get("description", "")) for t in item.tools]
            texts.append(("server instructions", item.instructions or ""))
            for where, text in texts:
                signals = looks_poisoned(text)
                if signals:
                    out.append(flag("AI-MCP-004", item.id, f"{item.name}: {where} carries hidden instructions",
                                    [f"{where}: {', '.join(signals)}", f"excerpt (untrusted, not followed): \"{excerpt(text)}\""],
                                    frameworks=_merge(RULES["AI-MCP-004"].frameworks,
                                                      attack=["T1552.001"] if "secret access" in signals else [])))
            if item.secret_vars:
                out.append(flag("AI-MCP-005", item.id, f"{item.name}: plain-text secret in {', '.join(item.secret_vars)}",
                                [f"{e}" for e in item.evidence if e.startswith("config")] +
                                [f"variable holding a literal secret: {v} (value not recorded)" for v in item.secret_vars]))
            if not item.registered:
                where = "a third-party server outside the scan scope" if item.third_party else f"found on {item.host or item.endpoint}"
                out.append(flag("AI-MCP-006", item.id, f"{item.name} is not in the AI inventory ({where})", list(item.evidence)))
            if item.package and item.pinned is False:
                out.append(flag("AI-MCP-007", item.id, f"{item.name} runs {item.package}@{item.version or 'latest'} without a pinned version",
                                [e for e in item.evidence if e.startswith("config")]))

        elif item.kind == "vector_store":
            if item.auth == "none":
                backs = ", ".join(item.backs) or "no known knowledge base"
                out.append(flag("AI-VEC-001", item.id, f"{item.name} answers without authentication (backs {backs})",
                                [f"probe {item.endpoint}: listed collections {', '.join(item.collections)} with no credentials"],
                                severity="critical" if item.backs else "high"))
            if not item.registered:
                out.append(flag("AI-VEC-002", item.id, f"{item.name} is not in the CMDB", list(item.evidence)))

        elif item.kind == "knowledge_base":
            untrusted = [s for s in item.sources if s.get("trust") in ("external", "public")]
            if untrusted:
                out.append(flag("AI-KB-001", item.id, f"{item.name} indexes untrusted content: {', '.join(s['name'] for s in untrusted)}",
                                [f"{item.platform} export: source '{s['name']}' trust={s['trust']}" for s in untrusted]))
            if item.enforces_source_permissions is False and any(s.get("permissioned") for s in item.sources):
                restricted = [d["title"] for d in item.documents if d.get("access") not in (None, "all-staff", "public")]
                out.append(flag("AI-KB-002", item.id, f"{item.name} answers from permissioned documents without checking the asker's access",
                                [f"{item.platform} export: source permissions not enforced at retrieval"] +
                                ([f"restricted documents in the index, e.g. '{restricted[0]}'"] if restricted else [])))
            for doc in item.documents:
                signals = looks_poisoned(doc.get("text"))
                if signals:
                    out.append(flag("AI-KB-003", item.id, f"{item.name}: document {doc.get('id')} carries hidden instructions",
                                    [f"sampled document '{doc.get('title')}': {', '.join(signals)}",
                                     f"excerpt (untrusted, not followed): \"{excerpt(doc.get('text', ''))}\""]))

        elif item.kind == "agent":
            audiences = {c.get("audience") for c in item.channels}
            unapproved = [t for t in item.tools if t.get("access") in HIGH_IMPACT and not t.get("needs_approval")]
            if unapproved and item.channels:
                public = bool(audiences & set(PUBLIC_AUDIENCES))
                # Typed into a conversation: direct injection. Arrives inside an email or file: indirect.
                conversational = any(c.get("channel") in (None, "website_chat", "teams_bot", "chat") for c in item.channels)
                injection = "AML.T0051.000" if conversational else "AML.T0051.001"
                channels = ", ".join(f"{c.get('channel') or c.get('description') or c.get('asset')} ({c.get('audience')})"
                                     for c in item.channels)
                out.append(flag("AI-AGT-001", item.id,
                                f"{item.name} acts on {'/'.join(sorted(audiences))} input with {_tool_summary(unapproved)} and no human approval",
                                [f"input: {channels}", f"tools callable without approval: {_tool_summary(unapproved)}"],
                                severity="critical" if public else "high", ease=EASE_PUBLIC if public else EASE_INTERNAL,
                                frameworks=_merge(RULES["AI-AGT-001"].frameworks, atlas=[injection] +
                                                  (["AML.T0086"] if any(t["access"] == "send_external" for t in unapproved) else []))))
            if item.memory and audiences & set(PUBLIC_AUDIENCES):
                out.append(flag("AI-AGT-002", item.id, f"{item.name} keeps memory built from {'/'.join(sorted(audiences))} input",
                                [f"memory: {item.memory}"]))
            if not item.registered:
                out.append(flag("AI-AGT-003", item.id, f"{item.name} ({item.platform}) is not in the AI inventory", list(item.evidence)))

    # Vulnerable MCP packages run on the host whose config launches them
    for server in configured:
        for vuln in package_vulnerabilities(server.package, server.version, known_packages):
            out.append(flag("AI-MCP-003", server.host,
                            f"Vulnerable MCP {vuln.get('role', 'package')} {server.package} {server.version} ({vuln['cve']}) on {server.host}",
                            [f"config {server.where()}: server '{server.name}' launches {server.package}@{server.version}"],
                            cve=vuln["cve"], component=f"{server.package}@{server.version}", remediation=vuln.get("fix"),
                            frameworks=_merge(RULES["AI-MCP-003"].frameworks, attack=[vuln["attack"]] if vuln.get("attack") else []),
                            tags=[]))
    return out
