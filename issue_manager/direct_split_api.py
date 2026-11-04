"""Finite HTTP routes for direct splitting and immediate provenance."""
from __future__ import annotations

import json
from urllib.parse import parse_qsl

from .browse_service import MAX_COLLECTION, BrowseService
from .errors import ConflictError, PermissionError, ValidationError
from .store import canonical_json


def handles(method, parts):
    return len(parts) >= 2 and parts[:2] == ["v1", "direct-evidence-splits"]


def dispatch(manager, method, parts, body, query, auth, *, idempotency_key):
    if method == "POST" and len(parts) == 2:
        if query:
            raise ValidationError("Split writes do not accept query parameters")
        return manager.direct_splits.split(body, auth=auth, idempotency_key=idempotency_key)
    if method != "GET" or len(parts) != 4 or parts[2] not in {"boundary", "origins"}:
        raise ValidationError("Unknown direct split route")
    source = parts[3]
    if parts[2] == "boundary":
        if query:
            raise ValidationError("Boundary snapshot does not accept query parameters")
        result = manager.direct_splits.boundary(source, auth=auth)
        return {"source_evidence_id": source, "snapshot": result["snapshot"]}
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True, encoding="utf-8", errors="strict")
        values = dict(pairs)
        if len(values) != len(pairs) or set(values) - {"limit", "cursor", "expected_snapshot"}:
            raise ValueError
        limit = int(values.get("limit", "8"))
        if not 1 <= limit <= 8:
            raise ValueError
    except (ValueError, UnicodeError) as exc:
        raise ValidationError("Invalid origins page") from exc
    auth.require("context.read")
    browse = BrowseService(manager)
    with manager.store.read_transaction() as conn:
        browse._evidence(source, auth)
        entries = []
        parent = conn.execute("SELECT * FROM direct_split_origins WHERE child_evidence_id=?", (source,)).fetchone()
        if parent:
            try:
                manager.evidence.require_read_access(parent["source_evidence_id"], auth)
            except PermissionError:
                entries.append({"kind": "split_source", "restricted": True})
            else:
                current_source = manager.scoped_evidence_relations._evidence(conn, parent["source_evidence_id"])
                current_token = manager.scoped_evidence_relations._binding(current_source)[1]
                entries.append({"kind": "split_source", "evidence_id": parent["source_evidence_id"],
                            "split_id": parent["split_id"], "content_kind": parent["content_kind"],
                            "source_binding": json.loads(parent["source_binding_json"]),
                            "source_binding_token": parent["source_binding_token"],
                            "source_binding_current": current_token == parent["source_binding_token"]})
        children = conn.execute("SELECT * FROM direct_split_origins WHERE source_evidence_id=? "
                                "ORDER BY child_evidence_id LIMIT ?", (source, MAX_COLLECTION + 1)).fetchall()
        browse._budget(children)
        restricted_children = False
        for child in children:
            try:
                manager.evidence.require_read_access(child["child_evidence_id"], auth)
            except PermissionError:
                restricted_children = True
                continue
            entries.append({"kind": "split_child", "evidence_id": child["child_evidence_id"],
                            "split_id": child["split_id"], "content_kind": child["content_kind"],
                            "source_binding": json.loads(child["source_binding_json"]),
                            "source_binding_token": child["source_binding_token"]})
        if restricted_children:
            entries.append({"kind": "split_child", "restricted": True})
        mappings = conn.execute("SELECT m.mapping_id,m.fact_ref,m.version,f.packet_id, "
                                "CASE WHEN h.mapping_id=m.mapping_id THEN 1 ELSE 0 END AS is_current "
                                "FROM field_fact_mapping_versions m JOIN field_facts f USING(fact_ref) "
                                "LEFT JOIN field_fact_mapping_heads h USING(fact_ref) "
                                "WHERE m.evidence_id=? ORDER BY m.mapping_id LIMIT ?",
                                (source, MAX_COLLECTION + 1)).fetchall()
        browse._budget(mappings)
        entries.extend({"kind": "field_mapping", **dict(row), "is_current": bool(row["is_current"])} for row in mappings)
        entries.sort(key=lambda row: (row["kind"], row.get("evidence_id", row.get("mapping_id", ""))))
        page = browse._page(entries, query=["direct_split_origins", source], auth=auth, limit=limit,
                            cursor=values.get("cursor"), expected_snapshot=values.get("expected_snapshot"))
        if len(canonical_json(page).encode("utf-8")) > 15000:
            raise ConflictError("Origins page exceeds its byte limit; reduce the page size",
                                details={"code": "split_origins_too_large"})
        return page
