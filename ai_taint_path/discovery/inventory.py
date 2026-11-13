"""What discovery found: one record per AI agent, MCP server, knowledge base
and vector database, plus the evidence that shows it is there."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ..model import Edge, Finding

KIND_LABELS = {
    "agent": "AI agent",
    "mcp_server": "MCP server",
    "knowledge_base": "Knowledge base",
    "vector_store": "Vector database",
}


@dataclass
class InventoryItem:
    id: str
    kind: str  # agent | mcp_server | knowledge_base | vector_store
    name: str
    registered: bool
    platform: str | None = None
    owner: str | None = None
    host: str | None = None  # asset id it runs on
    segment: str | None = None  # network segment it is reachable from
    endpoint: str | None = None
    auth: str | None = None  # none | required | unknown | local
    third_party: bool = False
    # MCP servers
    package: str | None = None
    version: str | None = None
    pinned: bool | None = None
    tools: list[dict] = field(default_factory=list)
    instructions: str | None = None
    secret_vars: list[str] = field(default_factory=list)
    data_hosts: list[str] = field(default_factory=list)  # assets its config points at
    data_refs: dict[str, dict] = field(default_factory=dict)  # host -> variable, account and config file
    # Agents
    channels: list[dict] = field(default_factory=list)
    identity: str | None = None
    uses: list[str] = field(default_factory=list)  # MCP server ids
    knowledge_bases: list[str] = field(default_factory=list)
    memory: str | None = None
    model: str | None = None
    # Knowledge bases and vector databases
    store: dict | None = None
    sources: list[dict] = field(default_factory=list)
    enforces_source_permissions: bool | None = None
    documents: list[dict] = field(default_factory=list)
    product: str | None = None
    collections: list[str] = field(default_factory=list)
    backs: list[str] = field(default_factory=list)  # knowledge bases a vector database stores
    evidence: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return KIND_LABELS.get(self.kind, self.kind)

    def to_dict(self) -> dict:
        data = asdict(self)
        # Sampled document text stays out of reports: titles and ids are enough to act on
        data["documents"] = [{k: v for k, v in d.items() if k != "text"} for d in self.documents]
        data.pop("data_refs")  # reported on the data_access edge it explains
        return {k: v for k, v in data.items() if v not in (None, [], {}, "")}


@dataclass
class DiscoveryResult:
    inventory: list[InventoryItem]
    edges: list[Edge]
    findings: list[Finding]
    leads: list[dict]
    requests: list[dict]
    sources: dict
    mode: str = "deterministic"
    narrative: str | None = None

    def item(self, ident: str) -> InventoryItem | None:
        return next((i for i in self.inventory if i.id == ident), None)

    def summary(self) -> dict:
        kinds = {}
        for i in self.inventory:
            kinds.setdefault(i.kind, {"found": 0, "not_registered": 0})
            kinds[i.kind]["found"] += 1
            kinds[i.kind]["not_registered"] += 0 if i.registered else 1
        return {
            "by_kind": kinds,
            "found": len(self.inventory),
            "not_registered": sum(1 for i in self.inventory if not i.registered),
            "flags": len(self.findings),
            "requests_sent": len(self.requests),
            "leads_out_of_scope": sum(1 for lead in self.leads if lead["status"] == "out_of_scope"),
        }
