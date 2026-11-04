"""One-attempt, role-neutral execution facts for the workflow boundary.

This module is intentionally a read projection.  It does not create a
receipt, prepare a package, settle runtime, or decide whether a scientific
claim is correct.  The latter decisions belong to the independent
orchestrator after it has also observed the host process.
"""
from __future__ import annotations

import json
from typing import Any

from .errors import NotFoundError, PermissionError, ValidationError

CONTRACT = "workflow-execution-facts/v1"
MAX_BUSINESS_OUTPUTS = 16
MAX_STORED_OUTPUTS = MAX_BUSINESS_OUTPUTS + 1  # the immutable result envelope


def _json(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


def _event(conn, attempt_id: str, event_type: str):
    return conn.execute(
        "SELECT * FROM workflow_events WHERE attempt_id=? AND event_type=? "
        "ORDER BY rowid DESC LIMIT 1",
        (attempt_id, event_type),
    ).fetchone()


def _receipt_from_event(row) -> dict[str, Any] | None:
    if not row:
        return None
    value = _json(row["payload_json"], None)
    return value if isinstance(value, dict) else None


def _integrity_errors(receipt: dict[str, Any] | None, outputs: list[dict[str, Any]],
                      output_rows: dict[str, Any], attempt: dict[str, Any],
                      item: dict[str, Any], mandate: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if item["mandate_id"] != mandate["mandate_id"]:
        errors.append("item_mandate_mismatch")
    if receipt is None:
        return errors
    for field, expected in (("attempt_id", attempt["attempt_id"]),
                            ("work_item_id", item["work_item_id"])):
        if receipt.get(field) != expected:
            errors.append(f"receipt_{field}_mismatch")
    output_ids = receipt.get("output_ids")
    if not isinstance(output_ids, list) or any(not isinstance(value, str) for value in output_ids):
        return ["invalid_output_ids"]
    if not output_ids:
        errors.append("receipt_output_missing")
    if len(output_ids) > MAX_STORED_OUTPUTS:
        errors.append("output_limit_exceeded")
    if len(set(output_ids)) != len(output_ids):
        errors.append("duplicate_output_id")
    if set(output_rows) != set(output_ids):
        errors.append("receipt_output_missing")
    for output in outputs:
        if output["attempt_id"] != attempt["attempt_id"]:
            errors.append("output_attempt_mismatch")
        if output["work_item_id"] != item["work_item_id"]:
            errors.append("output_work_item_mismatch")
        if output["mandate_id"] != mandate["mandate_id"]:
            errors.append("output_mandate_mismatch")
    for field in ("evidence_ids", "assessment_ids"):
        values = receipt.get(field, [])
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            errors.append(f"invalid_{field}")
        elif any(
            (
                value not in output_rows
                or output_rows[value].get("business_action") != "record_assessment"
                or output_rows[value].get("attempt_id") != attempt["attempt_id"]
            ) if field == "assessment_ids" else not any(
                output.get("business_object_id") == value
                and output.get("business_action") == "add_evidence"
                and output.get("attempt_id") == attempt["attempt_id"]
                for output in output_rows.values()
            )
            for value in values
        ):
            errors.append(f"{field[:-4]}_output_mismatch")
    return sorted(set(errors))


def _artifact(row: dict[str, Any], receipt: dict[str, Any]) -> dict[str, Any]:
    objects = {
        item.get("id"): item
        for item in receipt.get("domain_objects", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    object_id = row.get("business_object_id")
    domain = objects.get(object_id, {})
    state = domain.get("state") if isinstance(domain, dict) else None
    if state is None and row.get("business_action") == "add_evidence":
        state = "registered" if receipt.get("published") is True else "draft"
    return {
        "output_id": row["output_id"],
        "action": row.get("business_action"),
        "kind": row["contribution_kind"],
        "object_id": object_id,
        "object_type": row.get("business_object_type"),
        "state_at_submission": state,
    }


def _assessment_transition(output_id: str, body: dict[str, Any]) -> dict[str, Any] | None:
    if body.get("contract") != "workflow-assessment-record/v1":
        return None
    required = {"issue_id", "policy", "purpose", "handled_refs", "target_before", "target_after"}
    if not required <= set(body):
        return None
    handled = body["handled_refs"]
    if not isinstance(handled, list) or any(not isinstance(value, str) for value in handled):
        return None
    before, after = body.get("target_before"), body.get("target_after")
    return {
        "assessment_id": output_id,
        "issue_id": body["issue_id"],
        "decision": body.get("decision"),
        "policy": body["policy"],
        "purpose": body["purpose"],
        "handled_refs": list(handled),
        "target_before": before,
        "target_after": after,
        "reuse_target": after if handled else None,
        "original_target_remains_assessable": bool(before is not None and before != after),
        "eligibility": "requires_fresh_coverage_query",
    }


def read(service, attempt_id: str, *, auth) -> dict[str, Any]:
    """Read all facts for one Attempt from one SQLite snapshot.

    Current scope and epoch are checked before any body-level facts are
    exposed.  Historical completion is not made unreadable merely because a
    mandate was later paused, but a revoked scope/epoch cannot read it.
    """
    service._require(auth, "workflow.read")
    with service.store.read_transaction() as conn:
        row = conn.execute("SELECT * FROM workflow_attempts WHERE attempt_id=?", (attempt_id,)).fetchone()
        if not row:
            raise NotFoundError(f"Workflow attempt not found: {attempt_id}")
        attempt = dict(row)
        item_row = conn.execute(
            "SELECT * FROM workflow_work_items WHERE work_item_id=?", (attempt["work_item_id"],)
        ).fetchone()
        mandate_row = conn.execute(
            "SELECT * FROM workflow_mandates WHERE mandate_id=?", (attempt["mandate_id"],)
        ).fetchone()
        if not item_row or not mandate_row:
            raise ValidationError("Workflow attempt has incomplete ownership references")
        item, mandate = dict(item_row), dict(mandate_row)
        service._assert_epoch(mandate, conn)
        if not service._within_scope(mandate, item["issue_id"], item["role"]):
            raise PermissionError("Execution facts are outside the current mandate scope")

        submission_event = _event(conn, attempt_id, "attempt.submit_result")
        runtime_event = _event(conn, attempt_id, "attempt.runtime_settled")
        terminal_event = conn.execute(
            "SELECT 1 FROM workflow_events WHERE attempt_id=? AND event_type IN "
            "('attempt.failed','attempt.expired','attempt.invalidated') LIMIT 1",
            (attempt_id,),
        ).fetchone()
        receipt = _receipt_from_event(submission_event)
        runtime_receipt = _receipt_from_event(runtime_event)
        if submission_event and receipt is None:
            submission_event_error = True
        else:
            submission_event_error = False
        if runtime_event and runtime_receipt is None:
            runtime_event_error = True
        else:
            runtime_event_error = False
        assessment_ids = receipt.get("assessment_ids", []) if receipt else []
        if assessment_ids:
            service._require(auth, "context.read")

        output_rows: dict[str, Any] = {}
        if receipt and isinstance(receipt.get("output_ids"), list):
            values = [value for value in receipt["output_ids"] if isinstance(value, str)]
            if values:
                placeholders = ",".join("?" for _ in values)
                rows = conn.execute(
                    f"SELECT * FROM workflow_outputs WHERE output_id IN ({placeholders})", values
                ).fetchall()
                output_rows = {row["output_id"]: dict(row) for row in rows}
        output_ids = receipt.get("output_ids", []) if receipt else []
        output_ids = output_ids if isinstance(output_ids, list) else []
        outputs = [output_rows[value] for value in output_ids
                   if isinstance(value, str) and value in output_rows]
        errors = _integrity_errors(receipt, outputs, output_rows, attempt, item, mandate)
        if submission_event_error:
            errors.append("invalid_submission_receipt")
        if runtime_event_error:
            errors.append("invalid_runtime_receipt")
        if runtime_receipt is not None:
            if runtime_receipt.get("attempt_id") != attempt_id:
                errors.append("runtime_attempt_mismatch")
            if (type(runtime_receipt.get("runtime_seconds_total")) is not int
                    or runtime_receipt["runtime_seconds_total"] != attempt["runtime_seconds_used"]):
                errors.append("runtime_total_mismatch")
        artifacts = [_artifact(row, receipt or {}) for row in outputs]

        transitions: list[dict[str, Any]] = []
        if receipt and isinstance(assessment_ids, list):
            for assessment_id in assessment_ids:
                row_for_assessment = output_rows.get(assessment_id)
                if not row_for_assessment:
                    errors.append("assessment_output_missing")
                    continue
                body = _json(row_for_assessment.get("body"), None)
                transition = _assessment_transition(assessment_id, body) if isinstance(body, dict) else None
                if transition is None:
                    errors.append("invalid_assessment_record")
                else:
                    transitions.append(transition)

        if receipt is None:
            submission_state = (
                "unknown_legacy"
                if submission_event_error
                else "absent"
                if attempt["status"] in {"claimed", "running", "submitted"} or terminal_event
                else "unknown_legacy"
            )
        else:
            submission_state = "recorded"
        if runtime_receipt is not None:
            runtime_state = "settled"
        elif runtime_event_error:
            runtime_state = "unknown_legacy"
        else:
            runtime_state = "not_settled" if attempt["status"] in {
                "succeeded", "rejected", "failed", "invalidated", "expired"
            } or terminal_event else "unknown_legacy"
        integrity = "consistent"
        if errors:
            integrity = "inconsistent"
        elif submission_state == "unknown_legacy" or runtime_state == "unknown_legacy":
            integrity = "incomplete_legacy"

        return {
            "contract": CONTRACT,
            "attempt_id": attempt_id,
            "work_item_id": item["work_item_id"],
            "mandate_id": mandate["mandate_id"],
            "observed_at": service._iso_now().isoformat(timespec="seconds"),
            "attempt": {
                "status": attempt["status"],
                "rejection_code": attempt["rejection_code"],
                "grant": {
                    "mandate_revision": attempt["mandate_revision"],
                    "fence": attempt["mandate_fence"],
                    "work_item_revision": attempt["work_item_revision"],
                },
            },
            "task": {
                "status": item["status"],
                "revision": item["revision"],
                "acceptance_status": item["acceptance_status"],
                "stop_reason": item["stop_reason"],
            },
            "mandate": {
                "status": mandate["status"],
                "revision": mandate["revision"],
                "fence": mandate["fence"],
            },
            "submission": {
                "state": submission_state,
                "receipt": receipt,
            },
            "artifacts": artifacts,
            "runtime": {
                "state": runtime_state,
                "receipt": runtime_receipt,
                "runtime_seconds_used": attempt["runtime_seconds_used"],
            },
            "assessment_transitions": transitions,
            "integrity": "inconsistent" if errors else integrity,
            "integrity_errors": sorted(set(errors)),
        }
