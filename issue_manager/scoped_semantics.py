"""Pure scoped-v2 evidence semantics.

The module accepts one already-frozen graph and returns a deterministic
three-valued least-information solution.  It deliberately has no knowledge of
SQLite, permissions, HTTP, clocks, or the orchestration package.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

Truth = Literal["T", "F", "?"]
RelationKind = Literal[
    "depends_on", "derived_from", "refutes", "challenges", "supports",
    "reproduces", "amends", "duplicates", "context_for",
]

KNOWN_RELATION_KINDS = frozenset({
    "depends_on", "derived_from", "refutes", "challenges", "supports",
    "reproduces", "amends", "duplicates", "context_for",
})


class ScopedSemanticsError(ValueError):
    """Raised when a frozen graph is not safe to solve."""


@dataclass(frozen=True, slots=True)
class ScopedNode:
    node_id: str
    binding: str
    base: Truth


@dataclass(frozen=True, slots=True)
class ScopedRelation:
    relation_id: str
    version: str
    source_id: str
    target_id: str
    source_binding: str
    target_binding: str
    kind: RelationKind
    active: bool = True


@dataclass(frozen=True, slots=True)
class ScopedSnapshot:
    scope_issue_id: str
    nodes: tuple[ScopedNode, ...]
    relations: tuple[ScopedRelation, ...]
    rule_id: str = "context-currentness/scoped-v2"


@dataclass(frozen=True, slots=True)
class ScopedReason:
    code: str
    relation_id: str | None = None
    relation_version: str | None = None
    node_id: str | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ScopedSolution:
    rule_id: str
    states: Mapping[str, Truth]
    reasons: Mapping[str, tuple[ScopedReason, ...]]
    active_relations: tuple[ScopedRelation, ...]
    pending_dependencies: tuple[ScopedRelation, ...]
    diagnostics: tuple[ScopedReason, ...] = ()

    def state(self, node_id: str) -> Truth:
        return self.states[node_id]

    @property
    def in_nodes(self) -> frozenset[str]:
        return frozenset(key for key, value in self.states.items() if value == "T")

    @property
    def out_nodes(self) -> frozenset[str]:
        return frozenset(key for key, value in self.states.items() if value == "F")

    @property
    def undecided_nodes(self) -> frozenset[str]:
        return frozenset(key for key, value in self.states.items() if value == "?")


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ScopedSemanticsError(f"{field} must be a non-empty string")
    return value


def _validate(snapshot: ScopedSnapshot) -> tuple[dict[str, ScopedNode], tuple[ScopedRelation, ...]]:
    if not isinstance(snapshot, ScopedSnapshot):
        raise ScopedSemanticsError("solve expects a ScopedSnapshot")
    _text(snapshot.scope_issue_id, "scope_issue_id")
    if not isinstance(snapshot.nodes, tuple) or not isinstance(snapshot.relations, tuple):
        raise ScopedSemanticsError("snapshot nodes and relations must be immutable tuples")
    nodes: dict[str, ScopedNode] = {}
    for index, node in enumerate(snapshot.nodes):
        if not isinstance(node, ScopedNode):
            raise ScopedSemanticsError(f"nodes[{index}] must be a ScopedNode")
        _text(node.node_id, f"nodes[{index}].node_id")
        _text(node.binding, f"nodes[{index}].binding")
        if node.base not in {"T", "F", "?"}:
            raise ScopedSemanticsError(f"nodes[{index}].base must be T, F, or ?")
        if node.node_id in nodes:
            raise ScopedSemanticsError(f"duplicate node ID: {node.node_id!r}")
        nodes[node.node_id] = node
    relation_map: dict[tuple[str, str], ScopedRelation] = {}
    for index, relation in enumerate(snapshot.relations):
        if not isinstance(relation, ScopedRelation):
            raise ScopedSemanticsError(f"relations[{index}] must be a ScopedRelation")
        for field in ("relation_id", "version", "source_id", "target_id", "source_binding", "target_binding"):
            _text(getattr(relation, field), f"relations[{index}].{field}")
        if relation.kind not in KNOWN_RELATION_KINDS:
            raise ScopedSemanticsError(f"unknown relation kind: {relation.kind!r}")
        if not isinstance(relation.active, bool):
            raise ScopedSemanticsError(f"relations[{index}].active must be boolean")
        if relation.source_id not in nodes or relation.target_id not in nodes:
            raise ScopedSemanticsError(f"relation endpoint is absent: {relation.relation_id!r}")
        key = (relation.relation_id, relation.version)
        previous = relation_map.get(key)
        if previous is not None and previous != relation:
            raise ScopedSemanticsError(f"relation has conflicting contents: {relation.relation_id!r}")
        relation_map[key] = relation
    return nodes, tuple(sorted(relation_map.values(), key=lambda item: (item.relation_id, item.version)))


def _reason_key(reason: ScopedReason) -> tuple[str, str, str, str, str]:
    return (reason.code, reason.relation_id or "", reason.relation_version or "", reason.node_id or "", reason.detail)


def solve(snapshot: ScopedSnapshot) -> ScopedSolution:
    """Solve the mixed depends-on/refutes graph from the empty information set.

    Binding-mismatched ``depends_on`` relations become explicit unknown
    obligations on their consumer.  A mismatched ``refutes`` relation is
    diagnosed but cannot attack a newly bound endpoint.
    """

    nodes, relations = _validate(snapshot)
    active: list[ScopedRelation] = []
    pending_dependencies: list[ScopedRelation] = []
    diagnostics: list[ScopedReason] = []
    for relation in relations:
        if not relation.active:
            continue
        matching = (
            relation.source_binding == nodes[relation.source_id].binding
            and relation.target_binding == nodes[relation.target_id].binding
        )
        if matching:
            active.append(relation)
        elif relation.kind == "depends_on":
            pending_dependencies.append(relation)
            diagnostics.append(ScopedReason(
                "dependency_binding_mismatch", relation.relation_id, relation.version,
                relation.source_id,
            ))
        elif relation.kind == "refutes":
            diagnostics.append(ScopedReason(
                "refutation_binding_mismatch", relation.relation_id, relation.version,
                relation.target_id,
            ))
        else:
            diagnostics.append(ScopedReason(
                "relation_binding_mismatch", relation.relation_id, relation.version,
            ))

    dependencies: dict[str, list[ScopedRelation]] = {}
    attackers: dict[str, list[ScopedRelation]] = {}
    for relation in active:
        if relation.kind == "depends_on":
            dependencies.setdefault(relation.source_id, []).append(relation)
        elif relation.kind == "refutes":
            attackers.setdefault(relation.target_id, []).append(relation)
    for items in (dependencies, attackers):
        for value in items.values():
            value.sort(key=lambda item: (item.relation_id, item.version, item.source_id, item.target_id))

    in_nodes: set[str] = set()
    out_nodes: set[str] = set()
    while True:
        next_in = set(in_nodes)
        next_out = set(out_nodes)
        for node_id in sorted(nodes):
            node = nodes[node_id]
            required = dependencies.get(node_id, ())
            blocked_by_unknown_binding = any(item.source_id == node_id for item in pending_dependencies)
            all_required_in = all(item.target_id in in_nodes for item in required)
            all_attackers_out = all(item.source_id in out_nodes for item in attackers.get(node_id, ()))
            if node.base == "T" and not blocked_by_unknown_binding and all_required_in and all_attackers_out:
                next_in.add(node_id)
            if node.base == "F" or any(item.target_id in out_nodes for item in required) or any(
                item.source_id in in_nodes for item in attackers.get(node_id, ())
            ):
                next_out.add(node_id)
        if next_in == in_nodes and next_out == out_nodes:
            break
        if next_in & next_out:
            raise ScopedSemanticsError("mixed solver produced overlapping IN and OUT states")
        in_nodes, out_nodes = next_in, next_out

    states: dict[str, Truth] = {
        node_id: ("T" if node_id in in_nodes else "F" if node_id in out_nodes else "?")
        for node_id in sorted(nodes)
    }
    reasons: dict[str, tuple[ScopedReason, ...]] = {}
    for node_id in sorted(nodes):
        values: list[ScopedReason] = []
        if nodes[node_id].base == "F":
            values.append(ScopedReason("base_unavailable", node_id=node_id))
        for relation in dependencies.get(node_id, ()):
            if relation.target_id in out_nodes:
                values.append(ScopedReason("necessary_basis_failed", relation.relation_id, relation.version, relation.target_id))
            elif relation.target_id not in in_nodes:
                values.append(ScopedReason("necessary_basis_undecided", relation.relation_id, relation.version, relation.target_id))
        for relation in attackers.get(node_id, ()):
            if relation.source_id in in_nodes:
                values.append(ScopedReason("direct_refutation", relation.relation_id, relation.version, relation.source_id))
            elif relation.source_id not in out_nodes:
                values.append(ScopedReason("refuter_undecided", relation.relation_id, relation.version, relation.source_id))
        for relation in pending_dependencies:
            if relation.source_id == node_id:
                values.append(ScopedReason("necessary_binding_unknown", relation.relation_id, relation.version, relation.target_id))
        reasons[node_id] = tuple(sorted(values, key=_reason_key))

    return ScopedSolution(
        snapshot.rule_id, states, reasons, tuple(active), tuple(pending_dependencies),
        tuple(sorted(diagnostics, key=_reason_key)),
    )
