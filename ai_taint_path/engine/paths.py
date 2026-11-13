"""Attack paths: the easiest way from each entry point to each crown jewel.

Score = 100 x exposure x (ease of every hop) x impact of the target.

Because every ease is between 0 and 1, the easiest path is a shortest path in
disguise, so Dijkstra finds it exactly. Each (entry, crown jewel) pair keeps
only its single easiest path; ties go to fewer hops, then to node ids, so the
same input always gives the same ranking.
"""

from __future__ import annotations

import heapq
import itertools
from dataclasses import dataclass, field

from .graph import AttackGraph

TIERS = ((60, "critical"), (40, "high"), (20, "medium"), (0, "low"))
MAX_HOPS = 10


@dataclass
class Step:
    src: str | None  # None for the first step (getting in)
    dst: str
    kind: str  # "entry" or an edge kind
    ease: float
    why: str
    findings: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    origin: str = "static"
    credential: dict | None = None  # for data_access steps, when the data names the credential


@dataclass
class AttackPath:
    entry: str
    target: str
    nodes: list[str]
    steps: list[Step]
    exposure: float
    impact: float
    likelihood: float  # exposure x every ease

    @property
    def id(self) -> str:
        return f"{self.entry}->{self.target}"

    @property
    def score(self) -> float:
        return 100 * self.likelihood * self.impact

    @property
    def hops(self) -> int:
        return len(self.nodes) - 1

    @property
    def tier(self) -> str:
        return next(name for floor, name in TIERS if round(self.score, 1) >= floor)

    @property
    def findings(self) -> list[str]:
        return list(dict.fromkeys(fid for s in self.steps for fid in s.findings))

    def uses(self, node_ids) -> bool:
        return bool(set(self.nodes) & set(node_ids))


def find_paths(graph: AttackGraph, fixed: frozenset = frozenset(), max_hops: int = MAX_HOPS) -> list[AttackPath]:
    jewels = sorted(n.id for n in graph.nodes.values() if n.crown_jewel)
    counter = itertools.count()
    paths: list[AttackPath] = []
    for entry_id in sorted(graph.nodes):
        start = graph.entry(entry_id, fixed)
        if start is None:
            continue
        exposure, gate = start
        first = Step(None, entry_id, "entry", gate.ease, gate.why, gate.findings, gate.techniques)
        likelihood = exposure * gate.ease
        heap = [(round(-likelihood, 12), 0, (entry_id,), next(counter), likelihood, (first,))]
        best: dict[str, tuple[float, tuple, tuple]] = {}
        while heap:
            _, hops, path, _, like, steps = heapq.heappop(heap)
            node = path[-1]
            if node in best:
                continue
            best[node] = (like, path, steps)
            if hops >= max_hops:
                continue
            for e in graph.out.get(node, []):
                if e.dst in best or e.dst in path:
                    continue
                g = graph.gate(e, fixed)
                if g is None or g.ease <= 0:
                    continue
                nxt = like * g.ease
                step = Step(e.src, e.dst, e.kind, g.ease, g.why, g.findings, g.techniques, e.origin, e.credential)
                heapq.heappush(heap, (round(-nxt, 12), hops + 1, path + (e.dst,), next(counter), nxt, steps + (step,)))
        for target in jewels:
            if target != entry_id and target in best:
                like, path, steps = best[target]
                paths.append(AttackPath(entry_id, target, list(path), list(steps), exposure,
                                        graph.nodes[target].impact, like))
    paths.sort(key=lambda p: (round(-p.score, 9), p.hops, p.entry, p.target))
    return paths


def exposure_index(paths: list[AttackPath]) -> float:
    """Sum over crown jewels of the score of the easiest path to each (0 to 100 per jewel)."""
    worst: dict[str, float] = {}
    for p in paths:
        worst[p.target] = max(worst.get(p.target, 0.0), p.score)
    return sum(worst.values())
