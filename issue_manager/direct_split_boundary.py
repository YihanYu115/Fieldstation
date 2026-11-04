"""Bounded, authorization-checked snapshot for direct Evidence splitting.

This is an internal building block, not a public split operation. The caller
must use the same snapshot in the write transaction and must not treat it as
a list of conclusions affected by a split.
"""
from __future__ import annotations

import hashlib
from typing import Any

from .errors import ConflictError, ValidationError
from .store import canonical_json

MAX_NODES = 1000
MAX_RELATIONS = 5000
MAX_BYTES = 1024 * 1024


def snapshot(manager: Any, source_evidence_id: str, *, auth: Any) -> dict[str, Any]:
    """Fix direct relations and the resolver-relevant directed dependencies.

    The snapshot also fixes the source's ordinary edges, memberships and field
    mappings. Neighbor details are internal and do not confer read permission.
    Use within an existing read or write transaction for a consistent view.
    """
    auth.require("context.read")
    if not isinstance(source_evidence_id, str) or not source_evidence_id.strip():
        raise ValidationError("Source Evidence ID is required")
    conn = manager.store.conn
    manager.evidence.require_read_access(source_evidence_id, auth)
    pending = {source_evidence_id}
    visited: set[str] = set()
    evidence: dict[str, dict[str, Any]] = {}
    relations: dict[str, dict[str, Any]] = {}
    while pending:
        identity = min(pending)
        pending.remove(identity)
        if identity in visited:
            continue
        visited.add(identity)
        if len(visited) > MAX_NODES:
            raise ConflictError("Split boundary exceeds its node limit", details={"code": "split_boundary_too_large"})
        row = conn.execute("SELECT * FROM evidence_refs WHERE evidence_id=?", (identity,)).fetchone()
        if row is None:
            raise ValidationError("Split boundary contains unavailable Evidence")
        evidence[identity] = dict(row)
        predicate = ("(v.source_evidence_id=? OR v.target_evidence_id=?)" if identity == source_evidence_id else
                     "v.active=1 AND ((v.source_evidence_id=? AND v.relation_type='depends_on') OR "
                     "(v.target_evidence_id=? AND v.relation_type IN ('refutes','challenges'))) ")
        rows = conn.execute(
            "SELECT v.* FROM scoped_evidence_relation_heads h "
            "JOIN scoped_evidence_relation_versions v ON v.relation_id=h.relation_id "
            "AND v.version_id=h.current_version_id WHERE " + predicate + " ORDER BY v.relation_id LIMIT ?",
            (identity, identity, MAX_RELATIONS + 1),
        ).fetchall()
        for item in rows:
            relation = dict(item)
            relations[relation["relation_id"]] = relation
            for endpoint in (relation["source_evidence_id"], relation["target_evidence_id"]):
                if endpoint not in evidence:
                    endpoint_row = conn.execute("SELECT * FROM evidence_refs WHERE evidence_id=?", (endpoint,)).fetchone()
                    if endpoint_row is None:
                        raise ValidationError("Split boundary contains unavailable Evidence")
                    evidence[endpoint] = dict(endpoint_row)
            if relation["active"]:
                if relation["source_evidence_id"] == identity and relation["relation_type"] == "depends_on":
                    pending.add(relation["target_evidence_id"])
                if relation["target_evidence_id"] == identity and relation["relation_type"] in {"refutes", "challenges"}:
                    pending.add(relation["source_evidence_id"])
            if len(evidence) > MAX_NODES:
                raise ConflictError("Split boundary exceeds its node limit", details={"code": "split_boundary_too_large"})
        if len(relations) > MAX_RELATIONS:
            raise ConflictError("Split boundary exceeds its relation limit", details={"code": "split_boundary_too_large"})
    ordinary = [dict(row) for row in conn.execute(
        "SELECT * FROM evidence_relations WHERE consumer_evidence_id=? OR provider_evidence_id=? "
        "ORDER BY relation_id LIMIT ?", (source_evidence_id, source_evidence_id, MAX_RELATIONS + 1),
    ).fetchall()]
    if len(ordinary) + len(relations) > MAX_RELATIONS:
        raise ConflictError("Split boundary exceeds its relation limit", details={"code": "split_boundary_too_large"})
    for relation in ordinary:
        for identity in (relation["consumer_evidence_id"], relation["provider_evidence_id"]):
            row = conn.execute("SELECT * FROM evidence_refs WHERE evidence_id=?", (identity,)).fetchone()
            if row is None:
                raise ValidationError("Split boundary contains unavailable Evidence")
            evidence[identity] = dict(row)
            if len(evidence) > MAX_NODES:
                raise ConflictError("Split boundary exceeds its node limit", details={"code": "split_boundary_too_large"})
    memberships = [dict(row) for row in conn.execute(
        "SELECT * FROM issue_evidence WHERE evidence_id=? ORDER BY issue_id LIMIT ?",
        (source_evidence_id, MAX_NODES + 1),
    ).fetchall()]
    mappings = [dict(row) for row in conn.execute(
        "SELECT * FROM field_fact_mapping_versions WHERE evidence_id=? ORDER BY mapping_id LIMIT ?",
        (source_evidence_id, MAX_NODES + 1),
    ).fetchall()]
    if len(memberships) > MAX_NODES or len(mappings) > MAX_NODES:
        raise ConflictError("Split boundary exceeds its inventory limit", details={"code": "split_boundary_too_large"})
    bindings = []
    for identity in sorted(evidence):
        binding = conn.execute("SELECT * FROM evidence_source_bindings WHERE evidence_id=?", (identity,)).fetchone()
        if binding is not None:
            bindings.append(dict(binding))
    ordinary_heads = []
    for relation in ordinary:
        head = conn.execute("SELECT * FROM managed_relation_heads WHERE domain='evidence' AND relation_id=?",
                            (relation["relation_id"],)).fetchone()
        if head is not None:
            ordinary_heads.append(dict(head))
    mapping_heads = []
    for mapping in mappings:
        head = conn.execute("SELECT * FROM field_fact_mapping_heads WHERE fact_ref=?", (mapping["fact_ref"],)).fetchone()
        if head is not None:
            mapping_heads.append(dict(head))
    value = {"source_evidence_id": source_evidence_id,
             "evidence": [evidence[key] for key in sorted(evidence)],
             "scoped_relations": [relations[key] for key in sorted(relations)],
             "ordinary_relations": ordinary, "ordinary_heads": ordinary_heads,
             "source_bindings": bindings, "memberships": memberships,
             "field_mappings": mappings, "field_mapping_heads": mapping_heads}
    encoded = canonical_json(value).encode("utf-8")
    if len(encoded) > MAX_BYTES:
        raise ConflictError("Split boundary exceeds its byte limit", details={"code": "split_boundary_too_large"})
    return {"snapshot": hashlib.sha256(encoded).hexdigest(), **value}
