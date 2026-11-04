"""Pure projections for a solved scoped-v2 evidence graph."""

from __future__ import annotations

from collections import deque
from dataclasses import asdict
from typing import Any

from .scoped_semantics import ScopedRelation, ScopedSnapshot, ScopedSolution


def _relation_key(item: ScopedRelation) -> tuple[str, str]:
    return item.relation_id, item.version


def _relation_json(item: ScopedRelation, solution: ScopedSolution, nodes: dict[str, Any]) -> dict[str, Any]:
    return {
        "relation_id": item.relation_id,
        "version": item.version,
        "source_id": item.source_id,
        "target_id": item.target_id,
        "kind": item.kind,
        "source_binding": item.source_binding,
        "target_binding": item.target_binding,
        "binding_current": (
            item.source_binding == nodes[item.source_id].binding
            and item.target_binding == nodes[item.target_id].binding
        ),
        "source_state": solution.states[item.source_id],
        "target_state": solution.states[item.target_id],
    }


def _dependency_closure(roots: set[str], relations: tuple[ScopedRelation, ...]) -> set[str]:
    dependencies: dict[str, list[ScopedRelation]] = {}
    for item in relations:
        if item.kind == "depends_on":
            dependencies.setdefault(item.source_id, []).append(item)
    seen = set(roots)
    pending = deque(sorted(roots))
    while pending:
        current = pending.popleft()
        for item in sorted(dependencies.get(current, ()), key=_relation_key):
            if item.target_id not in seen:
                seen.add(item.target_id)
                pending.append(item.target_id)
    return seen


def project(snapshot: ScopedSnapshot, roots: list[str] | tuple[str, ...], solution: ScopedSolution) -> dict[str, Any]:
    """Return B(R), S(R), qualification/diagnostic regions, and stable K data."""

    root_ids = tuple(sorted(dict.fromkeys(roots)))
    node_ids = {item.node_id for item in snapshot.nodes}
    unknown = sorted(set(root_ids) - node_ids)
    if unknown:
        raise ValueError(f"projection root is absent from snapshot: {unknown[0]!r}")
    active = solution.active_relations
    pending = solution.pending_dependencies
    all_dependencies = tuple(sorted((*active, *pending), key=_relation_key))
    basis_ids = _dependency_closure(set(root_ids), all_dependencies)
    valid_roots = {item for item in root_ids if solution.states[item] == "T"}
    support_ids = _dependency_closure(valid_roots, all_dependencies)

    qualification = set(basis_ids)
    queue = deque(sorted(basis_ids))
    while queue:
        target = queue.popleft()
        for relation in all_dependencies:
            if relation.target_id == target and relation.kind == "refutes" and relation.source_id not in qualification:
                qualification.add(relation.source_id)
                queue.append(relation.source_id)
            if relation.source_id == target and relation.kind == "depends_on" and relation.target_id not in qualification:
                qualification.add(relation.target_id)
                queue.append(relation.target_id)
    challenges = [
        item for item in active
        if item.kind == "challenges" and item.target_id in qualification
    ]
    for item in challenges:
        qualification.add(item.source_id)

    nodes = {item.node_id: item for item in snapshot.nodes}
    gap_roots = [
        {"node_id": item, "state": solution.states[item],
         "reasons": [asdict(reason) for reason in solution.reasons[item]]}
        for item in root_ids if solution.states[item] != "T"
    ]
    support = [item for item in sorted(support_ids) if solution.states[item] == "T"]
    qualification_edges = [
        _relation_json(item, solution, nodes) for item in all_dependencies
        if item.source_id in qualification and item.target_id in qualification
    ]
    dispute_edges = [
        _relation_json(item, solution, nodes) for item in sorted(challenges, key=_relation_key)
    ]
    discovery = sorted(node_ids - qualification)
    return {
        "roots": list(root_ids),
        "basis_ids": sorted(basis_ids),
        "support_ids": support,
        "gap": gap_roots,
        "qualification_ids": sorted(qualification),
        "qualification_edges": qualification_edges,
        "related_challenges": dispute_edges,
        "discovery_ids": discovery,
        "states": {item: solution.states[item] for item in sorted(qualification)},
        "diagnostics": [asdict(reason) for reason in solution.diagnostics],
        "comparison": {
            "rule_id": snapshot.rule_id,
            "scope_issue_id": snapshot.scope_issue_id,
            "roots": list(root_ids),
            "bindings": sorted((item, nodes[item].binding) for item in qualification),
            "states": {item: solution.states[item] for item in sorted(qualification)},
            "relations": qualification_edges,
            "challenges": dispute_edges,
            "pending_dependencies": [
                item for item in qualification_edges if not item["binding_current"] and item["kind"] == "depends_on"
            ],
        },
    }
