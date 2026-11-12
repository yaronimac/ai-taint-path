"""The environment model: nodes, edges and findings, and how they load from disk.

An environment folder holds what a security team already has (CMDB-style
assets, identities, a network map, scanner and posture findings, an AI
inventory) plus, in discovery/, the evidence the discovery agent reads.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FEEDS = ROOT / "data" / "feeds"

AI_KINDS = ("agent", "mcp_server", "knowledge_base", "vector_store")


@dataclass
class Node:
    id: str
    kind: str  # asset | identity | agent | mcp_server | knowledge_base | vector_store
    name: str
    type: str = ""
    crown_jewel: bool = False
    impact: float = 0.0
    entry_point: str | None = None  # internet | user_action
    open_channel: bool = False
    discovered: bool = False
    attrs: dict = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    kind: str
    origin: str = "static"  # static | discovery
    note: str = ""


@dataclass
class Finding:
    id: str
    asset: str
    type: str  # cve | misconfig | ai_risk
    title: str = ""
    status: str = "open"
    source: str = ""
    cve: str | None = None
    rule: str | None = None
    severity: str | None = None
    tags: list[str] = field(default_factory=list)
    ease: float | None = None
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    remediation: str | None = None
    grants_edge: dict | None = None
    component: str | None = None
    first_seen: str | None = None
    intel: dict = field(default_factory=dict)  # KEV / EPSS / CVSS facts, filled by enrichment

    @property
    def is_open(self) -> bool:
        return self.status == "open"

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v not in (None, [], {}, "")}

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        known = {f for f in cls.__dataclass_fields__}
        item = {k: v for k, v in data.items() if k in known}
        item.setdefault("type", "cve" if data.get("cve") else "misconfig")
        return cls(**item)


@dataclass
class Environment:
    path: Path
    company: dict
    nodes: dict[str, Node]
    edges: list[Edge]
    findings: list[Finding]
    registry: dict

    @property
    def discovery_dir(self) -> Path:
        return self.path / "discovery"

    def asset_for_host(self, host: str | None) -> str | None:
        """Match an IP address or hostname to an asset id."""
        if not host:
            return None
        host = host.lower()
        for node in self.nodes.values():
            if host in (a.lower() for a in node.attrs.get("addresses", [])):
                return node.id
            if host in (h.lower() for h in node.attrs.get("hostnames", [])):
                return node.id
        return None

    def segment_for_host(self, host: str | None) -> str | None:
        try:
            ip = ipaddress.ip_address(host or "")
        except ValueError:
            return None
        for node in self.nodes.values():
            cidr = node.attrs.get("cidr")
            if node.type == "network_segment" and cidr and ip in ipaddress.ip_network(cidr):
                return node.id
        return None

    def identity_by_name(self, name: str | None) -> str | None:
        for node in self.nodes.values():
            if node.kind == "identity" and name and node.attrs.get("account_name") == name:
                return node.id
        return None

    def copy(self) -> "Environment":
        return Environment(self.path, self.company, dict(self.nodes), list(self.edges), list(self.findings), self.registry)


def _asset_node(a: dict) -> Node:
    core = {"id", "name", "type", "crown_jewel", "impact", "entry_point", "open_channel"}
    return Node(
        id=a["id"], kind="asset", name=a["name"], type=a.get("type", ""),
        crown_jewel=bool(a.get("crown_jewel")), impact=float(a.get("impact", 1.0 if a.get("crown_jewel") else 0.0)),
        entry_point=a.get("entry_point"), open_channel=bool(a.get("open_channel")),
        attrs={k: v for k, v in a.items() if k not in core},
    )


def _identity_node(i: dict) -> Node:
    attrs = {k: v for k, v in i.items() if k not in {"id", "name"}}
    attrs["account_name"] = i.get("name")
    label = f"{i['name']} ({i.get('platform', 'identity').replace('_', ' ')})"
    return Node(id=i["id"], kind="identity", name=label, type=i.get("platform", ""), attrs=attrs)


def load_environment(path: str | Path) -> Environment:
    path = Path(path)

    def read(name: str, default=None):
        f = path / name
        return json.loads(f.read_text()) if f.exists() else default

    nodes: dict[str, Node] = {}
    for a in read("assets.json", []):
        nodes[a["id"]] = _asset_node(a)
    for i in read("identities.json", []):
        if i["id"] in nodes:
            raise ValueError(f"duplicate node id {i['id']}")
        nodes[i["id"]] = _identity_node(i)
    edges = [Edge(e["from"], e["to"], e["kind"]) for e in read("edges.json", [])]
    findings = [Finding.from_dict(f) for f in read("findings.json", [])]
    registry = read("ai_registry.json", {"agents": [], "mcp_servers": [], "knowledge_bases": []})
    return Environment(path, read("company.json", {}), nodes, edges, findings, registry)


@dataclass
class Feeds:
    kev: dict[str, dict]
    kev_catalog: str | None
    records: dict[str, dict]
    epss: dict[str, float]
    epss_date: str | None
    mcp_packages: list[dict]

    def describe(self) -> dict:
        return {
            "kev_catalog_version": self.kev_catalog,
            "kev_entries_used": len(self.kev),
            "cve_records": len(self.records),
            "epss": f"{len(self.epss)} scores ({self.epss_date})" if self.epss else "unavailable: CVSS used as fallback",
        }


def load_feeds(path: str | Path | None = None) -> Feeds:
    path = Path(path) if path else DEFAULT_FEEDS

    def read(name: str, default):
        f = path / name
        return json.loads(f.read_text()) if f.exists() else default

    kev = read("kev.json", {"vulnerabilities": []})
    epss = read("epss.json", {"scores": {}})
    return Feeds(
        kev={v["cveID"]: v for v in kev.get("vulnerabilities", [])},
        kev_catalog=kev.get("catalogVersion"),
        records=read("cve_records.json", {"records": {}}).get("records", {}),
        epss={k: float(v["epss"] if isinstance(v, dict) else v) for k, v in epss.get("scores", {}).items()},
        epss_date=epss.get("date") or epss.get("retrieved"),
        mcp_packages=read("mcp_packages.json", {"packages": []}).get("packages", []),
    )
