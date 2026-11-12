"""Toxic combinations: risks that are only serious together.

One discovery flag on its own (an agent with no approval step, a knowledge base
that indexes customer uploads, an open vector database) is a posture finding.
The same flags joined by a real link (the knowledge base feeds that agent, the
agent calls that server) are one attack. This module names those joins so a
reader sees one risk with a cause, not five rows in a table.

It works on the report's own lists (findings, inventory, edges, paths), so it
adds no new judgement: every ingredient is a flag or a fact the scan already
recorded. Breaking any one ingredient breaks the combination.
"""

from __future__ import annotations

LEVELS = ("critical", "high", "medium", "low")

PATTERNS = {
    "untrusted-input-unapproved-tools": "Agent acts on outside input with high-impact tools and no approval",
    "untrusted-documents-to-agent": "Untrusted documents feed an agent that can act",
    "open-vector-store-behind-agent": "Open vector database behind an agent's knowledge base",
    "poisoned-tool-to-agent": "Poisoned tool description reaches an agent with high-impact tools",
    "open-mcp-high-impact-tools": "MCP server with no login exposes high-impact tools",
}

# What each rule means as one ingredient of a combination, in a few words.
PHRASES = {
    "AI-AGT-001": "no human approval on high-impact tools",
    "AI-MCP-001": "answers without a login",
    "AI-MCP-002": "exposes high-impact tools",
    "AI-MCP-004": "a tool description carries hidden instructions",
    "AI-MCP-006": "in no inventory",
    "AI-KB-001": "indexes untrusted content",
    "AI-KB-003": "a document carries hidden instructions",
    "AI-VEC-001": "answers without authentication",
    "AI-VEC-002": "not in the CMDB",
}


def _short(name: str) -> str:
    return (name or "").split(" (")[0].strip() or name


def toxic_combinations(findings: list[dict], inventory: list[dict], edges: list[dict], paths: list[dict],
                       names: dict[str, str]) -> list[dict]:
    """Every toxic combination in the scan, worst first, with stable IDs (TC-01, TC-02, ...)."""
    flags: dict[tuple[str, str], dict] = {}
    for f in findings:
        if f.get("rule") and f.get("status", "open") == "open":
            flags.setdefault((f["asset"], f["rule"]), f)
    items = {i["id"]: i for i in inventory}

    def flag(component: str, rule: str) -> dict | None:
        return flags.get((component, rule))

    def name(node_id: str) -> str:
        return _short(names.get(node_id, node_id))

    def ingredient(component: str, f: dict) -> dict:
        return {"component": component, "text": f"{name(component)}: {PHRASES.get(f['rule'], f['title'])}",
                "finding": f["id"]}

    def linked(kind: str, src: str | None = None, dst: str | None = None) -> list[str]:
        return [e["to"] if src else e["from"] for e in edges
                if e["kind"] == kind and (src is None or e["from"] == src) and (dst is None or e["to"] == dst)]

    found: list[dict] = []

    def add(pattern: str, summary: str, parts: list[dict], core: list[str], break_with: str) -> None:
        ids = [p["finding"] for p in parts if p.get("finding")]
        sev = min((LEVELS.index(f["severity"]) for f in findings if f["id"] in ids and f.get("severity") in LEVELS),
                  default=len(LEVELS) - 1)
        on = [p["id"] for p in paths if all(c in p["nodes"] for c in core)]
        components = list(dict.fromkeys(p["component"] for p in parts))
        found.append({"pattern": pattern, "title": PATTERNS[pattern], "summary": summary, "severity": LEVELS[sev],
                      "components": components, "ingredients": parts, "findings": ids, "paths": on,
                      "break_with": break_with})

    agents_acting = {i["id"]: flag(i["id"], "AI-AGT-001") for i in inventory if i["kind"] == "agent"}
    agents_acting = {k: v for k, v in agents_acting.items() if v}

    # 1. Outside input steers an agent that can call high-impact tools with nobody approving.
    for agent, act in agents_acting.items():
        item = items[agent]
        parts = []
        for ch in item.get("channels") or []:
            via = (ch.get("channel") or "").replace("_", " ")
            where = ch.get("asset") or agent
            text = f"{name(where)}: {ch.get('audience', 'unknown')} input" + (f" via {via}" if via else "")
            parts.append({"component": where, "text": text, "finding": None})
        parts.append(ingredient(agent, act))
        for server in item.get("uses") or []:
            if (f := flag(server, "AI-MCP-002")):
                parts.append(ingredient(server, f))
        audience = " or ".join(dict.fromkeys(ch.get("audience", "outside") for ch in item.get("channels") or [])) or "outside"
        add("untrusted-input-unapproved-tools",
            f"Anyone who can send {audience} input to {name(agent)} can steer it into tools that change data or "
            f"send it out, and no person approves the call.", parts, [agent], act["id"])

    # 2. A knowledge base that indexes untrusted or poisoned documents feeds an agent that can act.
    for kb in [i["id"] for i in inventory if i["kind"] == "knowledge_base"]:
        kb_flags = [f for f in (flag(kb, "AI-KB-003"), flag(kb, "AI-KB-001")) if f]
        if not kb_flags:
            continue
        for agent in linked("retrieved_by", src=kb):
            if agent not in agents_acting:
                continue
            parts = [ingredient(kb, f) for f in kb_flags] + [ingredient(agent, agents_acting[agent])]
            poisoned = any(f["rule"] == "AI-KB-003" for f in kb_flags)
            add("untrusted-documents-to-agent",
                f"{name(agent)} reads {name(kb)}, which " + ("already holds a document with hidden instructions"
                                                            if poisoned else "indexes documents from outside")
                + ", and it can act on what it reads without approval.", parts, [kb, agent], kb_flags[0]["id"])

    # 3. An open vector database holds the vectors behind a knowledge base an acting agent reads.
    for store in [i["id"] for i in inventory if i["kind"] == "vector_store"]:
        open_flag = flag(store, "AI-VEC-001")
        if not open_flag:
            continue
        for kb in linked("backs", src=store):
            for agent in linked("retrieved_by", src=kb):
                if agent not in agents_acting:
                    continue
                parts = [ingredient(store, open_flag)]
                if (f := flag(store, "AI-VEC-002")):
                    parts.append(ingredient(store, f))
                parts.append({"component": kb, "text": f"{name(kb)}: stores its vectors there", "finding": None})
                parts.append(ingredient(agent, agents_acting[agent]))
                add("open-vector-store-behind-agent",
                    f"Anyone on the network can write to {name(store)}, which holds the vectors of {name(kb)}; "
                    f"{name(agent)} retrieves from it and can act without approval.", parts, [store, agent],
                    open_flag["id"])

    # 4. A tool description with hidden instructions is loaded by an agent that can act.
    for server in [i["id"] for i in inventory if i["kind"] == "mcp_server"]:
        poison = flag(server, "AI-MCP-004")
        if not poison:
            continue
        for agent in linked("agent_tool", dst=server):
            if agent not in agents_acting:
                continue
            parts = [ingredient(server, poison)]
            if (f := flag(server, "AI-MCP-001")):
                parts.append(ingredient(server, f))
            parts.append(ingredient(agent, agents_acting[agent]))
            add("poisoned-tool-to-agent",
                f"{name(agent)} loads the tools of {name(server)}, whose description tells the model what to do, "
                f"and it can run high-impact tools without approval.", parts, [server, agent], poison["id"])

    # 5. An MCP server with no login exposes tools that write, run commands or move money.
    for server in [i["id"] for i in inventory if i["kind"] == "mcp_server"]:
        no_login, impact = flag(server, "AI-MCP-001"), flag(server, "AI-MCP-002")
        if not (no_login and impact):
            continue
        parts = [ingredient(server, no_login), ingredient(server, impact)]
        if (f := flag(server, "AI-MCP-006")):
            parts.append(ingredient(server, f))
        add("open-mcp-high-impact-tools",
            f"Anyone who can reach {name(server)} on the network can call its high-impact tools directly, with no "
            f"agent and no login in the way." + (" Nobody has it in an inventory." if len(parts) > 2 else ""),
            parts, [server], no_login["id"])

    found.sort(key=lambda c: (LEVELS.index(c["severity"]), -len(c["paths"]), list(PATTERNS).index(c["pattern"]),
                              c["components"]))
    for i, c in enumerate(found, start=1):
        c["id"] = f"TC-{i:02d}"
    return [{"id": c.pop("id"), **c} for c in found]
