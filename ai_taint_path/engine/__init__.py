"""The prioritization engine: merge what discovery found into the scanner's
view, enrich it with threat intelligence, and rank attack paths."""

from __future__ import annotations

import copy
from dataclasses import dataclass

from ..discovery import DiscoveryResult, discover
from ..model import Edge, Environment, Feeds, Finding, Node, load_feeds
from .chokepoints import ChokePoint, choke_points, remediation_plan
from .enrich import enrich
from .graph import AttackGraph
from .paths import AttackPath, exposure_index, find_paths

__all__ = ["scan", "ScanResult", "AttackGraph", "AttackPath", "ChokePoint", "find_paths", "exposure_index"]


@dataclass
class ScanResult:
    env: Environment
    feeds: Feeds
    discovery: DiscoveryResult | None
    nodes: dict[str, Node]
    edges: list[Edge]
    findings: list[Finding]
    graph: AttackGraph
    paths: list[AttackPath]
    choke_points: list[ChokePoint]
    plan: list[ChokePoint]
    baseline_paths: list[AttackPath]

    @property
    def index(self) -> float:
        return exposure_index(self.paths)

    def finding(self, fid: str) -> Finding:
        return self.graph.findings[fid]


def merge(env: Environment, result: DiscoveryResult | None) -> tuple[dict[str, Node], list[Edge], list[Finding]]:
    nodes = {k: copy.deepcopy(v) for k, v in env.nodes.items()}
    findings = [copy.deepcopy(f) for f in env.findings]
    edges = list(env.edges)
    if result is None:
        return nodes, edges, findings
    for item in result.inventory:
        attrs = {"inventory": item.to_dict()}
        if item.id in nodes:  # discovery found more about a known asset (e.g. a CMDB vector database)
            nodes[item.id].attrs.update(attrs)
            nodes[item.id].discovered = True
        else:
            nodes[item.id] = Node(item.id, item.kind, item.name, type=item.kind, discovered=True, attrs=attrs)
    edges += result.edges
    findings += [copy.deepcopy(f) for f in result.findings]
    return nodes, edges, findings


def scan(env: Environment, feeds: Feeds | None = None, *, use_discovery: bool = True, transport=None,
         agent=None, transport_name: str | None = None, plan_steps: int = 5) -> ScanResult:
    feeds = feeds or load_feeds()
    result = discover(env, transport, feeds=feeds, agent=agent, transport_name=transport_name) if use_discovery else None

    nodes, edges, findings = merge(env, result)
    enrich(findings, feeds)
    graph = AttackGraph(nodes, edges, findings)
    paths = find_paths(graph)

    # What the same engine sees without discovery: scanner, CMDB and posture data only
    base_nodes, base_edges, base_findings = merge(env, None)
    enrich(base_findings, feeds)
    baseline_paths = find_paths(AttackGraph(base_nodes, base_edges, base_findings))

    return ScanResult(env, feeds, result, nodes, edges, findings, graph, paths,
                      choke_points(graph, paths), remediation_plan(graph, plan_steps), baseline_paths)
