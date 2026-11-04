from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import TYPE_CHECKING, Any

from .errors import ConflictBindingError, ConflictError, NotFoundError, ValidationError
from .store import canonical_json, new_id, now
from .strict_json import require_strict_json

if TYPE_CHECKING:
    from .store import Store


DOMAIN_OPERATIONS = {
    "field_bundle": "resolve_field_conflict",
    "import": "resolve_import_conflict",
}
DOMAIN_RESOLUTIONS = {
    "field_bundle": {
        "accept_as_new_revision",
        "create_competing_record",
        "keep_internal",
        "needs_more_information",
        "reject_candidate",
    },
    "import": {
        "accept_as_new_revision",
        "keep_internal_and_update_mapping",
        "create_competing_record",
        "split_identity",
        "reject_candidate",
        "needs_more_information",
    },
}


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _conflict(store: Store, domain: str, conflict_id: str) -> dict[str, Any]:
    if domain not in DOMAIN_OPERATIONS:
        raise ValidationError(f"Unsupported conflict governance domain: {domain}")
    conflict = store.row(
        "SELECT * FROM integration_conflicts WHERE integration_conflict_id=? "
        "AND source_kind=?",
        (conflict_id, domain),
    )
    if not conflict:
        raise NotFoundError(f"Governed conflict not found: {conflict_id}")
    return conflict


def conflict_target(
    conn: sqlite3.Connection, domain: str, conflict: dict[str, Any], *, state_view=None
) -> tuple[str | None, str | None]:
    if domain == "field_bundle":
        if state_view is None:
            action = conn.execute(
                "SELECT action_json,target_record_instance_id,base_record_revision_id "
                "FROM field_bundle_event_actions WHERE field_bundle_event_action_id=?",
                (conflict["source_item_id"],),
            ).fetchone()
        else:
            rows = state_view.context_rows(
                "field_bundle_event_actions", "field_bundle_event_action_id",
                conflict["source_item_id"],
            )
            action = rows[0] if rows else None
        if not action:
            return None, None
        try:
            parsed = json.loads(action["action_json"])
        except (json.JSONDecodeError, TypeError):
            parsed = {}
        return (
            str(action["target_record_instance_id"] or parsed.get("record_instance_id") or "")
            or None,
            str(action["base_record_revision_id"] or parsed.get("base_record_revision_id") or "")
            or None,
        )
    if state_view is None:
        target = conn.execute(
            "SELECT internal_object_id,internal_revision_id FROM external_mapping_targets "
            "WHERE source_object_mapping_id=? AND internal_object_type='record_instance' "
            "ORDER BY linked_at LIMIT 1",
            (conflict["existing_mapping_id"],),
        ).fetchone()
    else:
        targets = [
            row for row in state_view.context_rows(
                "external_mapping_targets", "source_object_mapping_id",
                conflict["existing_mapping_id"],
            ) if row["internal_object_type"] == "record_instance"
        ]
        # ``None`` is the preview marker for a target linked during execution;
        # it must sort after persisted targets when modeling SQL's oldest
        # target selection.
        targets.sort(key=lambda row: (row.get("linked_at") is None, row.get("linked_at") or ""))
        target = targets[0] if targets else None
    if not target:
        return None, None
    return str(target["internal_object_id"]), str(target["internal_revision_id"] or "") or None


def current_revision(
    conn: sqlite3.Connection, record_instance_id: str | None, *, state_view=None
) -> str | None:
    if not record_instance_id:
        return None
    row = (
        state_view.record_instance(record_instance_id)
        if state_view is not None
        else conn.execute(
            "SELECT current_revision_id FROM record_instances WHERE record_instance_id=?",
            (record_instance_id,),
        ).fetchone()
    )
    return str(row["current_revision_id"]) if row else None


def build_resolution_operation(
    store: Store,
    domain: str,
    conflict_id: str,
    resolution: str,
    *,
    resolution_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    conflict = _conflict(store, domain, conflict_id)
    if conflict["state"] not in {"open", "needs_more_information"}:
        raise ConflictError(f"Conflict is not open: {conflict['state']}")
    if resolution not in DOMAIN_RESOLUTIONS[domain]:
        raise ValidationError(
            f"Unsupported governed {domain} conflict resolution: {resolution!r}"
        )
    payload = dict(resolution_payload or {})
    require_strict_json(payload, path="$.resolution_payload")
    if "action" in payload:
        raise ValidationError("resolution_payload must not redefine the resolution action")
    record_instance_id, base_revision_id = conflict_target(
        store.conn, domain, conflict
    )
    current = current_revision(store.conn, record_instance_id)
    operation = {
        "op": DOMAIN_OPERATIONS[domain],
        "conflict_id": conflict_id,
        "record_instance_id": record_instance_id,
        "expected_conflict_revision": int(conflict["state_revision"]),
        "expected_current_revision_id": current,
        "base_record_revision_id": base_revision_id
        or conflict.get("previous_external_hash"),
        "candidate_action_hash": conflict["candidate_external_hash"],
        "resolution": resolution,
        "resolution_payload": payload,
        "resolution_payload_hash": content_hash(payload),
    }
    return operation


def _binding_error(field: str, expected: Any, actual: Any) -> ConflictBindingError:
    return ConflictBindingError(
        f"Governed conflict operation binding changed at {field}",
        details={"field": field, "expected": expected, "actual": actual},
    )


def validate_resolution_binding(
    conn: sqlite3.Connection,
    domain: str,
    operation: dict[str, Any],
    *,
    state_view=None,
) -> dict[str, Any]:
    if operation.get("op") != DOMAIN_OPERATIONS.get(domain):
        raise _binding_error("op", DOMAIN_OPERATIONS.get(domain), operation.get("op"))
    if operation.get("resolution") not in DOMAIN_RESOLUTIONS.get(domain, set()):
        raise _binding_error(
            "resolution",
            sorted(DOMAIN_RESOLUTIONS.get(domain, set())),
            operation.get("resolution"),
        )
    conflict_id = str(operation.get("conflict_id", ""))
    conflict_row = conn.execute(
        "SELECT * FROM integration_conflicts WHERE integration_conflict_id=?",
        (conflict_id,),
    ).fetchone()
    if not conflict_row:
        raise ConflictBindingError("Governed conflict no longer exists")
    conflict = dict(conflict_row)
    if state_view is not None:
        conflict = state_view.integration_conflicts.get(conflict_id, conflict)
    checks = {
        "source_kind": (domain, conflict["source_kind"]),
        "state": ("open", conflict["state"]),
        "expected_conflict_revision": (
            int(operation.get("expected_conflict_revision", -1)),
            int(conflict["state_revision"]),
        ),
        "candidate_action_hash": (
            operation.get("candidate_action_hash"),
            conflict["candidate_external_hash"],
        ),
    }
    for field, (expected, actual) in checks.items():
        if field == "state":
            if actual not in {"open", "needs_more_information"}:
                raise _binding_error(field, "open or needs_more_information", actual)
        elif expected != actual:
            raise _binding_error(field, expected, actual)
    payload = operation.get("resolution_payload", {})
    if not isinstance(payload, dict):
        raise ValidationError("Governed resolution_payload must be an object")
    require_strict_json(payload, path="$.resolution_payload")
    if "action" in payload:
        raise ValidationError("resolution_payload must not redefine the resolution action")
    actual_payload_hash = content_hash(payload)
    if actual_payload_hash != operation.get("resolution_payload_hash"):
        raise _binding_error(
            "resolution_payload_hash",
            operation.get("resolution_payload_hash"),
            actual_payload_hash,
        )
    record_instance_id, base_revision_id = conflict_target(
        conn, domain, conflict, state_view=state_view
    )
    if record_instance_id != operation.get("record_instance_id"):
        raise _binding_error(
            "record_instance_id", operation.get("record_instance_id"), record_instance_id
        )
    actual_current = current_revision(conn, record_instance_id, state_view=state_view)
    if actual_current != operation.get("expected_current_revision_id"):
        raise _binding_error(
            "expected_current_revision_id",
            operation.get("expected_current_revision_id"),
            actual_current,
        )
    expected_base = base_revision_id or conflict.get("previous_external_hash")
    if expected_base != operation.get("base_record_revision_id"):
        raise _binding_error(
            "base_record_revision_id",
            operation.get("base_record_revision_id"),
            expected_base,
        )
    if expected_base and record_instance_id:
        if state_view is not None:
            owner_rows = state_view.context_rows(
                "record_revisions", "record_revision_id", expected_base
            )
            owner = owner_rows[0] if owner_rows else None
        else:
            owner = conn.execute(
                "SELECT record_instance_id FROM record_revisions WHERE record_revision_id=?",
                (expected_base,),
            ).fetchone()
        if not owner or owner["record_instance_id"] != record_instance_id:
            raise ConflictBindingError(
                "Governed conflict base Revision does not belong to the target Record"
            )
    return {
        "conflict": conflict,
        "record_instance_id": record_instance_id,
        "base_record_revision_id": expected_base,
        "current_revision_id": actual_current,
        "candidate_hash": conflict["candidate_external_hash"],
        "resolution_payload": payload,
        "resolution_payload_hash": actual_payload_hash,
    }


def insert_governed_receipt(
    conn: sqlite3.Connection,
    *,
    domain: str,
    operation: dict[str, Any],
    changeset_id: str,
    changeset_hash: str,
    operation_ordinal: int,
    operation_hash: str,
    review_ids: list[str],
    result: dict[str, Any],
    actor: str,
    event_id: str,
) -> dict[str, Any]:
    sorted_review_ids = sorted(set(review_ids))
    result_object_id = result.get("record_instance_id")
    result_revision_id = result.get("record_revision_id")
    result_hash = content_hash(result)
    receipt_id = new_id("conflict_receipt")
    try:
        conn.execute(
            "INSERT INTO governed_conflict_resolution_receipts("
            "receipt_id,conflict_domain,conflict_id,changeset_id,changeset_hash,"
            "operation_ordinal,operation_hash,target_object_type,target_object_id,"
            "expected_current_revision_id,candidate_hash,resolution_action,"
            "resolution_payload_hash,review_ids_json,result_object_id,result_revision_id,"
            "result_hash,applied_at,applied_by,event_id) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                receipt_id,
                domain,
                operation["conflict_id"],
                changeset_id,
                changeset_hash,
                operation_ordinal,
                operation_hash,
                "record_instance",
                operation.get("record_instance_id") or "",
                operation.get("expected_current_revision_id"),
                operation["candidate_action_hash"],
                operation["resolution"],
                operation["resolution_payload_hash"],
                canonical_json(sorted_review_ids),
                result_object_id,
                result_revision_id,
                result_hash,
                now(),
                actor,
                event_id,
            ),
        )
    except sqlite3.IntegrityError as exc:
        existing = conn.execute(
            "SELECT * FROM governed_conflict_resolution_receipts "
            "WHERE conflict_domain=? AND conflict_id=?",
            (domain, operation["conflict_id"]),
        ).fetchone()
        if existing and (
            existing["changeset_id"] == changeset_id
            and int(existing["operation_ordinal"]) == operation_ordinal
            and existing["operation_hash"] == operation_hash
        ):
            return {**dict(existing), "idempotent_replay": True}
        raise ConflictBindingError(
            "Governed ChangeSet operation or conflict was already consumed"
        ) from exc
    return {
        "receipt_id": receipt_id,
        "conflict_domain": domain,
        "conflict_id": operation["conflict_id"],
        "changeset_id": changeset_id,
        "changeset_hash": changeset_hash,
        "operation_ordinal": operation_ordinal,
        "operation_hash": operation_hash,
        "review_ids": sorted_review_ids,
        "result_hash": result_hash,
        "event_id": event_id,
        "idempotent_replay": False,
    }
