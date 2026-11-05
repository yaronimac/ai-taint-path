"""Read cloud AI platform exports: agents, their tools and knowledge bases.

Each platform's export is turned into the same two record types, so the
rules and the graph never care where an agent lives. Supported today: Azure
AI Foundry and Amazon Bedrock (simplified read-only API exports).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

PLATFORM_NAMES = {"azure_ai_foundry": "Azure AI Foundry", "aws_bedrock": "Amazon Bedrock"}


@dataclass
class CloudTool:
    kind: str  # mcp | knowledge_base
    label: str = ""
    url: str | None = None
    require_approval: bool = True
    allowed_tools: list[str] = field(default_factory=list)
    identity: str | None = None  # account name the tool acts as
    knowledge_base: str | None = None


@dataclass
class CloudAgent:
    platform: str
    name: str
    source_file: str
    channels: list[dict]  # {asset, audience, channel}
    identity: str | None
    tools: list[CloudTool]
    memory: str | None
    model: str | None = None
    description: str | None = None

    @property
    def knowledge_bases(self) -> list[str]:
        return [t.knowledge_base for t in self.tools if t.kind == "knowledge_base" and t.knowledge_base]


@dataclass
class CloudKnowledgeBase:
    platform: str
    name: str
    source_file: str
    store: dict  # {type, endpoint, auth, collection}
    sources: list[dict]  # {name, trust, asset, permissioned}
    enforces_source_permissions: bool | None
    documents: list[dict]  # {id, title, text, access}


@dataclass
class CloudEvidence:
    agents: list[CloudAgent] = field(default_factory=list)
    knowledge_bases: list[CloudKnowledgeBase] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _azure(data: dict, src: str, out: CloudEvidence) -> None:
    for a in data.get("agents", []):
        tools = []
        for t in a.get("tools", []):
            if t.get("type") == "mcp":
                tools.append(CloudTool("mcp", t.get("server_label", ""), t.get("server_url"),
                                       require_approval=t.get("require_approval", "always") != "never",
                                       allowed_tools=list(t.get("allowed_tools", [])),
                                       identity=(t.get("auth") or {}).get("identity")))
            elif t.get("knowledge_base"):
                tools.append(CloudTool("knowledge_base", t.get("type", ""), knowledge_base=t["knowledge_base"]))
        memory = a.get("memory") or {}
        out.agents.append(CloudAgent(
            "azure_ai_foundry", a["name"], src,
            channels=[{"asset": c.get("asset"), "audience": c.get("audience", "internal"), "channel": c.get("channel")}
                      for c in a.get("published_to", [])],
            identity=a.get("identity"), tools=tools,
            memory=memory.get("scope") if memory.get("enabled") else None, model=a.get("model")))
    for kb in data.get("knowledge_bases", []):
        out.knowledge_bases.append(CloudKnowledgeBase(
            "azure_ai_foundry", kb["name"], src, dict(kb.get("store", {})),
            [dict(s) for s in kb.get("sources", [])], kb.get("enforces_source_permissions"),
            [dict(d) for d in kb.get("sampled_documents", [])]))


def _bedrock(data: dict, src: str, out: CloudEvidence) -> None:
    for a in data.get("agents", []):
        tools = [CloudTool("knowledge_base", "bedrock_kb", knowledge_base=k["name"]) for k in a.get("knowledgeBases", [])]
        for group in a.get("actionGroups", []):  # action groups are the agent's tools
            for fn in group.get("functions", []):
                tools.append(CloudTool("mcp", group.get("name", ""), group.get("endpoint"),
                                       require_approval=bool(group.get("requireConfirmation")),
                                       allowed_tools=[fn.get("name")]))
        memory = a.get("memoryConfiguration") or {}
        out.agents.append(CloudAgent(
            "aws_bedrock", a["agentName"], src,
            channels=[{"asset": c.get("asset"), "audience": c.get("audience", "internal"), "channel": c.get("channel")}
                      for c in a.get("channels", [])],
            identity=a.get("agentResourceRoleArn"), tools=tools,
            memory=memory.get("scope") if memory.get("enabled") else None,
            model=a.get("foundationModel"), description=a.get("description")))
    for kb in data.get("knowledgeBases", []):
        store = kb.get("storageConfiguration", {})
        out.knowledge_bases.append(CloudKnowledgeBase(
            "aws_bedrock", kb["name"], src,
            {"type": str(store.get("type", "")).lower(), "auth": store.get("auth"), "endpoint": store.get("endpoint")},
            [{"name": d.get("name"), "trust": d.get("trust", "internal"), "asset": d.get("asset"),
              "permissioned": d.get("permissioned", False)} for d in kb.get("dataSources", [])],
            kb.get("enforcesSourcePermissions"),
            [{"id": d.get("id"), "title": d.get("title"), "text": d.get("text"), "access": d.get("sourceAccess")}
             for d in kb.get("sampledDocuments", [])]))


PARSERS = {"azure_ai_foundry": _azure, "aws_bedrock": _bedrock}


def collect(cloud_dir: Path) -> CloudEvidence:
    out = CloudEvidence()
    if not cloud_dir.exists():
        return out
    for f in sorted(cloud_dir.glob("*.json")):
        src = f"cloud/{f.name}"
        try:
            data = json.loads(f.read_text())
        except ValueError as exc:
            out.errors.append(f"{src}: not valid JSON ({exc})")
            continue
        parser = PARSERS.get(data.get("platform"))
        if not parser:
            out.errors.append(f"{src}: unknown platform {data.get('platform')!r}")
            continue
        out.files.append(src)
        parser(data, src, out)
    return out
