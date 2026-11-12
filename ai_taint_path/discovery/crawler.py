"""The discovery pipeline: gather evidence, follow leads, correlate, flag.

1. Read the evidence already collected: MCP client configs from hosts and
   cloud AI platform exports.
2. Turn it into leads: endpoints worth probing (registered servers, servers a
   config points at or starts on 0.0.0.0, MCP URLs in agent definitions,
   vector databases behind knowledge bases).
3. Follow the leads with read-only probes, inside the scope. By default this
   is a deterministic walk over every lead; with --agent claude, a Claude
   tool-use loop chooses which leads to follow (see agent.py). Either way the
   probes go through the same scope fence.
4. Correlate everything into one inventory, with graph edges that show how
   untrusted input can travel: who can talk to which agent, which tools an
   agent can call without approval, what a server can touch.
5. Run the risk rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..model import Edge, Environment, Feeds, load_feeds
from . import cloud as cloud_mod
from . import configs as config_mod
from .inventory import DiscoveryResult, InventoryItem
from .probe import VECTOR_PROBES, FixtureTransport, McpProbe, NotAllowed, OutOfScope, Prober, Scope, Transport, VectorProbe
from .rules import classify_tool, evaluate

KIND_ORDER = {"agent": 0, "mcp_server": 1, "knowledge_base": 2, "vector_store": 3}


@dataclass
class Evidence:
    configs: config_mod.ConfigEvidence
    cloud: cloud_mod.CloudEvidence


@dataclass
class Lead:
    url: str
    kind: str  # mcp | qdrant | weaviate
    reasons: list[str] = field(default_factory=list)
    status: str = "pending"  # probed | out_of_scope | refused | not_probed
    detail: str = ""

    def to_dict(self) -> dict:
        return {"url": self.url, "kind": self.kind, "reasons": self.reasons, "status": self.status, "detail": self.detail}


def norm(url: str | None) -> str:
    if not url:
        return ""
    p = urlparse(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    return f"{p.scheme}://{(p.hostname or '').lower()}:{port}{p.path.rstrip('/') or ''}"


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def same_server(server_name: str | None, *candidates: str | None) -> bool:
    key = re.sub(r"[^a-z0-9]", "", (server_name or "").lower())
    return bool(key) and any(key == re.sub(r"[^a-z0-9]", "", (c or "").lower()) for c in candidates)


def gather(env: Environment) -> Evidence:
    return Evidence(config_mod.collect(env.discovery_dir / "configs"), cloud_mod.collect(env.discovery_dir / "cloud"))


def build_leads(env: Environment, evidence: Evidence) -> list[Lead]:
    leads: dict[tuple[str, str], Lead] = {}

    def add(url: str, kind: str, reason: str) -> None:
        lead = leads.setdefault((norm(url), kind), Lead(url, kind))
        if reason not in lead.reasons:
            lead.reasons.append(reason)

    for s in env.registry.get("mcp_servers", []):
        if s.get("endpoint"):
            add(s["endpoint"], "mcp", f"AI inventory lists {s['id']}")
    for node in env.nodes.values():
        if node.type == "vector_store" and node.attrs.get("endpoint"):
            add(node.attrs["endpoint"], node.attrs.get("product", "unknown"), f"CMDB lists {node.id}")
    for srv in evidence.configs.servers:
        if srv.transport in ("http", "sse") and srv.url:
            add(srv.url, "mcp", f"config {srv.where()} points '{srv.name}' at it")
        if srv.listens_on_network and srv.host in env.nodes:
            bind = srv.listen_host or "0.0.0.0"
            addresses = env.nodes[srv.host].attrs.get("addresses", []) if bind in ("0.0.0.0", "::") else [bind]
            for addr in addresses:
                add(f"http://{addr}:{srv.listen_port}/mcp", "mcp",
                    f"config {srv.where()} starts '{srv.name}' listening on {bind}:{srv.listen_port}")
        if srv.remote_url:
            add(srv.remote_url, "mcp", f"config {srv.where()} bridges '{srv.name}' to a remote server")
    for agent in evidence.cloud.agents:
        for t in agent.tools:
            if t.kind == "mcp" and t.url:
                add(t.url, "mcp", f"{agent.source_file}: '{agent.name}' calls it as tool '{t.label}'")
    for kb in evidence.cloud.knowledge_bases:
        if kb.store.get("type") in VECTOR_PROBES and kb.store.get("endpoint"):
            add(kb.store["endpoint"], kb.store["type"], f"{kb.source_file}: '{kb.name}' stores its vectors there")
    return list(leads.values())


def probe_lead(prober: Prober, lead: Lead) -> McpProbe | VectorProbe | None:
    """Probe one lead through the scope fence. Never raises for scope or allowlist refusals."""
    ok, why = prober.scope.check(lead.url)
    if not ok:
        lead.status, lead.detail = "out_of_scope", why
        return None
    try:
        result = prober.probe_mcp(lead.url) if lead.kind == "mcp" else prober.probe_vector_store(lead.url, lead.kind)
    except (OutOfScope, NotAllowed) as exc:
        lead.status, lead.detail = "refused", str(exc)
        return None
    lead.status, lead.detail = "probed", result.outcome
    return result


def follow_leads(prober: Prober | None, leads: list[Lead]) -> dict[str, McpProbe | VectorProbe]:
    """Deterministic mode: probe every lead once, in order."""
    results: dict[str, McpProbe | VectorProbe] = {}
    for lead in leads:
        if prober is None:
            lead.status, lead.detail = "not_probed", "no transport (no recorded probes and not a live scan)"
            continue
        result = probe_lead(prober, lead)
        if result is not None:
            results[norm(lead.url)] = result
    return results


class _Ids:
    def __init__(self, taken: set[str]):
        self.taken = set(taken)

    def new(self, base: str, suffix: str = "") -> str:
        ident = slug(base) or "unnamed"
        if suffix and not ident.endswith(suffix.strip("-")):
            ident += suffix
        out, n = ident, 2
        while out in self.taken:
            out, n = f"{ident}-{n}", n + 1
        self.taken.add(out)
        return out


def _server_tools(raw: list[dict], source: str) -> list[dict]:
    return [{"name": t["name"], "access": classify_tool(t["name"], t.get("description", ""), t.get("annotations")),
             "description": t.get("description", ""), "source": source} for t in raw]


def correlate(env: Environment, scope: Scope, evidence: Evidence, probes: dict) -> tuple[list[InventoryItem], list[Edge]]:
    reg = env.registry
    reg_by_endpoint = {norm(s["endpoint"]): s for s in reg.get("mcp_servers", []) if s.get("endpoint")}
    reg_by_package = {s["package"]: s for s in reg.get("mcp_servers", []) if s.get("package")}
    ids = _Ids({s["id"] for s in reg.get("mcp_servers", [])} | {a["id"] for a in reg.get("agents", [])})

    servers: dict[str, InventoryItem] = {}  # key -> item (id filled in at the end)
    id_base: dict[str, str] = {}  # key -> what to name an unregistered server after
    server_identities: dict[str, set[str]] = {}
    config_key: dict[int, str] = {}  # id(ConfiguredServer) -> server key

    def server_for(url: str) -> InventoryItem:
        key = norm(url)
        if key not in servers:
            host = urlparse(url).hostname
            registered = reg_by_endpoint.get(key)
            in_scope = scope.check(url)[0]
            servers[key] = InventoryItem(
                id=registered["id"] if registered else "", kind="mcp_server",
                name=registered["name"] if registered else "", registered=bool(registered),
                owner=registered.get("owner") if registered else None,
                endpoint=url, host=env.asset_for_host(host), segment=scope.segment_for(url) if in_scope else None,
                third_party=not in_scope, auth="unknown")
            probe = probes.get(key)
            if isinstance(probe, McpProbe):
                item = servers[key]
                item.auth = probe.auth
                item.evidence.append(f"probe {url}: {probe.detail}")
                if probe.outcome == "answered":
                    item.tools = _server_tools(probe.tools, "probe tools/list")
                    item.instructions = probe.instructions
                    item.version = probe.server_version
                    item.name = item.name or f"{probe.server_name} {probe.server_version or ''}".strip()
                    item.evidence.append(f"server says it is {probe.server_name} {probe.server_version or ''}".strip())
                    id_base[key] = probe.server_name or ""
            elif not in_scope:
                servers[key].evidence.append(f"not probed: {scope.check(url)[1]}")
        return servers[key]

    # 1. Every MCP endpoint that answered a probe
    for key, probe in probes.items():
        if isinstance(probe, McpProbe) and probe.outcome in ("answered", "auth_required"):
            server_for(probe.url)

    # 2. Servers named in client configs
    for srv in evidence.configs.servers:
        cfg_note = f"config {srv.where()} ({config_mod.CLIENT_NAMES[srv.client]}): '{srv.name}'"
        if srv.transport in ("http", "sse") and srv.url:
            item = server_for(srv.url)
        elif srv.remote_url:
            item = server_for(srv.remote_url)
            item.name = item.name or f"{srv.name} (remote server at {urlparse(srv.remote_url).hostname})"
            id_base.setdefault(norm(srv.remote_url), srv.name)
            cfg_note += f" via {srv.package}@{srv.version}"
        else:
            item = None
            if srv.listens_on_network:
                for key, probe in probes.items():
                    if isinstance(probe, McpProbe) and probe.outcome == "answered" and \
                            urlparse(probe.url).port == srv.listen_port and \
                            env.asset_for_host(urlparse(probe.url).hostname) == srv.host and \
                            same_server(probe.server_name, srv.package, srv.name):
                        item = servers[key]
                        cfg_note += f" (answers at {probe.url})"
                        break
            if item is None:
                key = f"local:{srv.host}:{srv.package or srv.name}"
                registered = reg_by_package.get(srv.package or "")
                approved = registered and (not registered.get("approved_versions") or srv.version in registered["approved_versions"])
                item = servers.setdefault(key, InventoryItem(
                    id=registered["id"] if approved else "", kind="mcp_server",
                    name=registered["name"] if approved else f"{srv.package or srv.name} on {srv.host}",
                    registered=bool(approved), owner=registered.get("owner") if approved else None,
                    host=srv.host, auth="local"))
            item.package, item.version, item.pinned = srv.package or item.package, srv.version or item.version, srv.pinned
        if srv.package and item.package == srv.package:
            item.pinned = srv.pinned
        item.secret_vars = sorted(set(item.secret_vars) | set(srv.secret_vars))
        item.data_hosts = sorted(set(item.data_hosts) | set(srv.referenced_hosts))
        item.evidence.append(cfg_note)
        config_key[id(srv)] = next(k for k, v in servers.items() if v is item)

    # 3. MCP servers named in cloud agent definitions
    for agent in evidence.cloud.agents:
        for t in agent.tools:
            if t.kind != "mcp" or not t.url:
                continue
            item = server_for(t.url)
            if not item.tools and t.allowed_tools:
                item.tools = _server_tools([{"name": n} for n in t.allowed_tools], f"{agent.source_file} allowed_tools")
            if t.identity:
                server_identities.setdefault(norm(t.url), set()).add(t.identity)
            item.evidence.append(f"{agent.source_file}: used by '{agent.name}' as tool '{t.label}'")

    for key, item in servers.items():
        if not item.id:
            item.id = ids.new(id_base.get(key) or item.package or item.name or item.endpoint or "mcp", "-mcp")
        item.name = item.name or item.id
        item.evidence = list(dict.fromkeys(item.evidence))
    by_key = dict(servers)

    # 4. Agents: from cloud exports, and from the client configs on each host
    reg_agents = reg.get("agents", [])
    agents: dict[str, InventoryItem] = {}

    def registered_agent(platform=None, name=None, client=None, host=None):
        for a in reg_agents:
            if name and a.get("platform") == platform and a["name"].lower() == name.lower():
                return a
            if client and client in a.get("clients", []) and (not a.get("hosts") or host in a["hosts"]):
                return a
        return None

    kb_ids = {kb.name: slug(kb.name) for kb in evidence.cloud.knowledge_bases}
    for ca in evidence.cloud.agents:
        r = registered_agent(ca.platform, name=ca.name)
        ident = r["id"] if r else ids.new(ca.name)
        tools, uses = [], []
        for t in ca.tools:
            if t.kind == "mcp" and t.url:
                server = by_key[norm(t.url)]
                uses.append(server.id)
                allowed = t.allowed_tools or [x["name"] for x in server.tools]
                for name in allowed:
                    known = next((x for x in server.tools if x["name"] == name), None)
                    tools.append({"server": server.id, "name": name,
                                  "access": known["access"] if known else classify_tool(name),
                                  "needs_approval": t.require_approval})
        agents[ident] = InventoryItem(
            id=ident, kind="agent", name=ca.name, registered=bool(r), platform=ca.platform,
            owner=r.get("owner") if r else None, channels=list(ca.channels),
            identity=env.identity_by_name(ca.identity), uses=uses,
            knowledge_bases=[kb_ids.get(k, slug(k)) for k in ca.knowledge_bases],
            memory=ca.memory, model=ca.model, tools=tools,
            evidence=[f"{ca.source_file}: agent '{ca.name}'" + (f" ({ca.description})" if ca.description else "")])

    groups: dict[tuple[str, str], list] = {}
    for srv in evidence.configs.servers:
        groups.setdefault((srv.host, srv.client), []).append(srv)
    for (host, client), srvs in sorted(groups.items()):
        r = registered_agent(client=client, host=host)
        ident = r["id"] if r else ids.new(f"{client}-{host}")
        item = agents.get(ident)
        if item is None:
            item = agents[ident] = InventoryItem(
                id=ident, kind="agent", name=r["name"] if r else f"{config_mod.CLIENT_NAMES[client]} on {host}",
                registered=bool(r), platform=r.get("platform") if r else client, owner=r.get("owner") if r else None,
                host=host if (not r or r.get("hosts")) else None,
                channels=[dict(r["input_channel"])] if r and r.get("input_channel") else [])
        for srv in srvs:
            server = by_key[config_key[id(srv)]]
            if server.id not in item.uses:
                item.uses.append(server.id)
            asks = client in config_mod.ASKS_BEFORE_TOOL_CALLS and not srv.auto_approved
            for t in server.tools:
                item.tools.append({"server": server.id, "name": t["name"], "access": t["access"], "needs_approval": asks})
        names = ", ".join(f"'{s.name}'" + (" (auto-approved)" if s.auto_approved else "") for s in srvs)
        item.evidence.append(f"config {host}/{srvs[0].config_path} ({config_mod.CLIENT_NAMES[client]}): {names}")

    # 5. Knowledge bases and the vector databases behind them
    kbs: dict[str, InventoryItem] = {}
    registered_kbs = {k.get("name") for k in reg.get("knowledge_bases", [])}
    for kb in evidence.cloud.knowledge_bases:
        kbs[kb_ids[kb.name]] = InventoryItem(
            id=kb_ids[kb.name], kind="knowledge_base", name=kb.name, registered=kb.name in registered_kbs,
            platform=kb.platform, store=dict(kb.store), sources=[dict(s) for s in kb.sources],
            enforces_source_permissions=kb.enforces_source_permissions, documents=[dict(d) for d in kb.documents],
            evidence=[f"{kb.source_file}: knowledge base '{kb.name}' ({kb.store.get('type')})"])

    stores: dict[str, InventoryItem] = {}
    for key, probe in probes.items():
        if not isinstance(probe, VectorProbe) or probe.outcome not in ("answered", "auth_required"):
            continue
        host = urlparse(probe.url).hostname or ""
        asset = env.asset_for_host(host)
        known = asset and env.nodes[asset].type == "vector_store"
        ident = asset if known else ids.new(f"{probe.product}-{host}")
        port = urlparse(probe.url).port
        stores[key] = InventoryItem(
            id=ident, kind="vector_store", registered=bool(known), product=probe.product,
            name=env.nodes[asset].name if known else f"{probe.product.title()} vector database at {host}:{port}",
            endpoint=probe.url, host=None if known else asset, segment=scope.segment_for(probe.url), auth=probe.auth,
            collections=probe.collections, owner=env.nodes[asset].attrs.get("owner") if known else None,
            evidence=[f"probe {probe.url}: {probe.detail}"] + ([f"CMDB: {asset}"] if known else ["no CMDB asset at this address"]))
    for kb in evidence.cloud.knowledge_bases:
        store = stores.get(norm(kb.store.get("endpoint")))
        if store:
            store.backs.append(kb_ids[kb.name])
            store.evidence.append(f"{kb.source_file}: stores knowledge base '{kb.name}' (collection {kb.store.get('collection')})")

    # 6. Edges: how input and access flow through what was found
    edges: list[Edge] = []
    seen: set[tuple[str, str, str]] = set()

    def edge(src: str | None, dst: str | None, kind: str, note: str) -> None:
        if src and dst and (src, dst, kind) not in seen and src != dst:
            seen.add((src, dst, kind))
            edges.append(Edge(src, dst, kind, origin="discovery", note=note))

    for key, s in by_key.items():
        if s.segment:
            edge(s.segment, s.id, "network", f"{s.endpoint} is reachable from {s.segment}")
        runs = [t["name"] for t in s.tools if t["access"] == "execute"]
        if runs and s.host:
            edge(s.id, s.host, "executes_on", f"tool {runs[0]} runs commands on {s.host}")
        for h in s.data_hosts:
            target = env.asset_for_host(h)
            if target:
                edge(s.id, target, "data_access", f"its config connects it to {h}")
        for name in sorted(server_identities.get(key, ())):
            edge(s.id, env.identity_by_name(name), "runs_as", f"acts as {name}")
    for a in agents.values():
        for c in a.channels:
            if c.get("asset") in env.nodes:
                edge(c["asset"], a.id, "agent_input",
                     f"{c.get('channel') or c.get('description') or 'input'} ({c.get('audience')}) reaches {a.name}")
        for sid in a.uses:
            names = [t["name"] for t in a.tools if t["server"] == sid]
            edge(a.id, sid, "agent_tool", f"can call {', '.join(names) or 'its tools'}")
        for kb_id in a.knowledge_bases:
            edge(kb_id, a.id, "retrieved_by", f"{a.name} retrieves from {kb_id}")
    for kb in kbs.values():
        for s in kb.sources:
            if s.get("asset") in env.nodes and s.get("trust") in ("external", "public"):
                edge(s["asset"], kb.id, "feeds", f"{s['name']} are indexed into {kb.name}")
    for st in stores.values():
        if st.segment:
            edge(st.segment, st.id, "network", f"{st.endpoint} is reachable from {st.segment}")
        for kb_id in st.backs:
            edge(st.id, kb_id, "backs", f"holds the vectors of {kb_id}")

    inventory = sorted([*agents.values(), *by_key.values(), *kbs.values(), *stores.values()],
                       key=lambda i: (KIND_ORDER[i.kind], i.id))
    return inventory, edges


def discover(env: Environment, transport: Transport | None = None, *, feeds: Feeds | None = None,
             agent=None, transport_name: str | None = None) -> DiscoveryResult:
    """Run discovery over an environment folder. `agent` (optional) replaces the
    deterministic lead walk with an LLM that chooses which leads to probe."""
    feeds = feeds or load_feeds()
    scope = Scope.load(env.discovery_dir / "scope.json")
    if transport is None and (env.discovery_dir / "probes.json").exists():
        transport, transport_name = FixtureTransport.load(env.discovery_dir / "probes.json"), "recorded probes (fixtures)"
    prober = Prober(transport, scope) if transport is not None else None
    evidence = gather(env)
    leads = build_leads(env, evidence)
    narrative, mode = None, "deterministic"
    if agent is not None and prober is not None:
        probes, narrative = agent.run(env, evidence, leads, prober)
        mode = f"agent ({agent.describe()})"
        for lead in leads:
            if lead.status == "pending":
                lead.status, lead.detail = "not_probed", "the agent did not follow this lead"
    else:
        probes = follow_leads(prober, leads)
    inventory, edges = correlate(env, scope, evidence, probes)
    findings = evaluate(inventory, evidence.configs.servers, feeds.mcp_packages)
    findings.sort(key=lambda f: (f.rule or "", f.asset))
    for n, f in enumerate(findings, start=1):
        f.id = f"D-{n:03d}"
    return DiscoveryResult(
        inventory=inventory, edges=edges, findings=findings,
        leads=[lead.to_dict() for lead in leads], requests=prober.log if prober else [],
        sources={"config_files": evidence.configs.files, "cloud_exports": evidence.cloud.files,
                 "errors": evidence.configs.errors + evidence.cloud.errors, "scope": scope.describe(),
                 "transport": transport_name or ("live network" if transport is not None else "none")},
        mode=mode, narrative=narrative)
