"""The attack graph: which hops an attacker can take, and how easily.

Every hop has an ease between 0 and 1 and a reason a person can check. Most
structural hops (an identity that administers an account, an agent that can
call a tool) cost nothing once you are there: the ease sits on the gates, the
findings that let an attacker in. That keeps the score explainable: fix the
gate and the hop disappears.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..model import Edge, Finding, Node

EXPOSURE = {"internet": 1.0, "user_action": 0.6}
EASE_RETRIEVAL = 0.6  # a poisoned chunk must be retrieved for a relevant question first
EASE_FEED, EASE_FEED_POISONED = 0.9, 1.0
CLOUD_IDENTITIES = ("aws_iam_role", "aws_iam_user", "entra_service_principal", "entra_managed_identity")


@dataclass
class Gate:
    ease: float
    why: str
    findings: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)


class AttackGraph:
    def __init__(self, nodes: dict[str, Node], edges: list[Edge], findings: list[Finding]):
        self.nodes = nodes
        self.out: dict[str, list[Edge]] = defaultdict(list)
        for e in edges:
            if e.src in nodes and e.dst in nodes:
                self.out[e.src].append(e)
        for lst in self.out.values():
            lst.sort(key=lambda e: (e.dst, e.kind))
        self.findings = {f.id: f for f in findings}
        self.by_asset: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            if f.is_open:
                self.by_asset[f.asset].append(f)

    def name(self, node_id: str) -> str:
        return self.nodes[node_id].name if node_id in self.nodes else node_id

    def _tagged(self, asset: str, tag: str, fixed: frozenset) -> Finding | None:
        hits = [f for f in self.by_asset.get(asset, []) if tag in f.tags and f.id not in fixed]
        return min(hits, key=lambda f: (-(f.ease or 0), f.id), default=None)

    def foothold(self, asset: str, fixed: frozenset) -> Finding | None:
        hits = [f for f in self.by_asset.get(asset, []) if "foothold" in f.tags and f.ease and f.id not in fixed]
        return min(hits, key=lambda f: (-f.ease, f.id), default=None)

    def _foothold_text(self, f: Finding) -> str:
        if f.cve:
            reason = f.intel.get("ease_reason", "")
            return f"{f.cve} on {self.name(f.asset)}: {reason}"
        return f"{f.title} ({f.rule or f.id})"

    def _cve_techniques(self, f: Finding, where: str) -> list[str]:
        if f.frameworks.get("attack"):
            return list(f.frameworks["attack"])
        return {"internet": ["T1190"], "user_action": ["T1203"]}.get(where, ["T1210"])

    def entry(self, node_id: str, fixed: frozenset = frozenset()) -> tuple[float, Gate] | None:
        """(exposure, gate) if an attacker can start here, else None."""
        node = self.nodes[node_id]
        if node.entry_point not in EXPOSURE:
            return None
        exposure = EXPOSURE[node.entry_point]
        if node.open_channel:
            return exposure, Gate(1.0, f"{node.name} takes content from anyone: no exploit needed")
        f = self.foothold(node_id, fixed)
        if f is None:
            return None
        where = "exposed to the internet" if node.entry_point == "internet" else "reached when an employee opens untrusted content"
        return exposure, Gate(f.ease, f"{self._foothold_text(f)} ({where})", [f.id],
                              self._cve_techniques(f, node.entry_point) if f.cve else _ids(f, "attack", "atlas"))

    def gate(self, e: Edge, fixed: frozenset = frozenset()) -> Gate | None:
        """How easily an attacker on e.src takes the hop to e.dst; None if they cannot."""
        src, dst = self.nodes[e.src], self.nodes[e.dst]
        k = e.kind
        if k == "network":
            if dst.type == "network_segment":
                return Gate(1.0, f"network route into {dst.name}")
            f = self.foothold(e.dst, fixed)
            if f is None:
                return None
            techniques = self._cve_techniques(f, "internal") if f.cve else _ids(f, "attack", "atlas")
            return Gate(f.ease, self._foothold_text(f), [f.id], techniques)
        if k == "agent_input":
            f = self._tagged(e.dst, "steerable_by_input", fixed)
            if f is None:
                return None
            return Gate(f.ease, f"prompt injection: {e.note or 'input'}; {dst.name} acts on it without human approval",
                        [f.id], [t for t in f.frameworks.get("atlas", []) if t.startswith("AML.T0051")])
        if k == "retrieved_by":
            f = self._tagged(e.dst, "steerable_by_input", fixed)
            if f is None:
                return None
            return Gate(EASE_RETRIEVAL, f"indirect prompt injection: {dst.name} retrieves from {src.name} and acts without approval",
                        [f.id], ["AML.T0051.001"])
        if k == "feeds":
            ingest = self._tagged(e.dst, "untrusted_ingestion", fixed)
            if ingest is None:
                return None
            poison = self._tagged(e.dst, "poisoned_content", fixed)
            why = f"anything sent to {src.name} is indexed into {dst.name}"
            if poison:
                why += "; a document with hidden instructions is already there"
            techniques = ["AML.T0070"] + (["AML.T0093"] if src.entry_point == "internet" else [])
            return Gate(EASE_FEED_POISONED if poison else EASE_FEED, why,
                        [ingest.id] + ([poison.id] if poison else []), techniques)
        if k == "admin_of":
            grant = next((f for f in self.by_asset.get(e.src, []) if "excess_privilege" in f.tags
                          and f.grants_edge == {"from": e.src, "to": e.dst}), None)
            if grant and grant.id in fixed:
                return None
            why = f"{src.name} has admin rights over {dst.name}" + (f" ({grant.title})" if grant else "")
            return Gate(1.0, why, [grant.id] if grant else [])
        if k == "runs_as":
            platform = dst.type
            tech = ["T1078.002"] if platform == "active_directory" else ["T1078.004"] if platform in CLOUD_IDENTITIES else []
            return Gate(1.0, f"{src.name} runs as {dst.name}", [], tech)
        if k == "session_hijack":
            return Gate(1.0, f"takes over remote-support sessions of {dst.name}", [], ["T1563"])
        if k == "data_access":
            return Gate(1.0, f"{src.name} holds credentials to {dst.name}", [], ["T1213.006" if dst.type == "database" else "T1213"])
        if k == "executes_on":
            return Gate(1.0, f"{e.note or 'a tool runs commands'} ({dst.name})", [], ["T1059"])
        if k == "agent_tool":
            return Gate(1.0, f"{src.name} {e.note or 'can call its tools'}", [], ["AML.T0053"])
        if k == "backs":
            return Gate(1.0, f"writing to {src.name} rewrites what {dst.name} returns", [], ["AML.T0070"])
        return Gate(1.0, e.note or k)


def _ids(f: Finding, *frameworks: str) -> list[str]:
    return [t for fw in frameworks for t in f.frameworks.get(fw, [])]
