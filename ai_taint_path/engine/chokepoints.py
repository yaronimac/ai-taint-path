"""Choke points: which single fix takes the most risk off the board.

For every finding that gates at least one ranked path, the engine removes it
(patched, authentication added, approval step added, privilege cut back),
recomputes every path and measures how far the exposure index falls. The
remediation plan repeats that greedily: best fix first, then the best fix
given that one is done, and so on.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .graph import AttackGraph
from .paths import AttackPath, exposure_index, find_paths


@dataclass
class ChokePoint:
    finding: str
    reduction: float
    index_after: float
    paths_closed: list[str] = field(default_factory=list)
    paths_weakened: list[str] = field(default_factory=list)


def _gating(paths: list[AttackPath]) -> list[str]:
    return sorted({fid for p in paths for s in p.steps for fid in s.findings})


def choke_points(graph: AttackGraph, paths: list[AttackPath], fixed: frozenset = frozenset(),
                 limit: int | None = None) -> list[ChokePoint]:
    base = exposure_index(paths)
    before = {p.id: p.score for p in paths}
    out = []
    for fid in _gating(paths):
        after_paths = find_paths(graph, fixed | {fid})
        after = {p.id: p.score for p in after_paths}
        index = exposure_index(after_paths)
        if base - index < 0.05:
            continue
        out.append(ChokePoint(
            fid, round(base - index, 1), round(index, 1),
            paths_closed=[pid for pid in before if pid not in after],
            paths_weakened=[pid for pid in before if pid in after and after[pid] < before[pid] - 0.05]))
    out.sort(key=lambda c: (-c.reduction, c.finding))
    return out[:limit] if limit else out


def remediation_plan(graph: AttackGraph, steps: int = 5) -> list[ChokePoint]:
    plan, fixed = [], frozenset()
    paths = find_paths(graph)
    for _ in range(steps):
        best = choke_points(graph, paths, fixed, limit=1)
        if not best:
            break
        plan.append(best[0])
        fixed = fixed | {best[0].finding}
        paths = find_paths(graph, fixed)
    return plan
