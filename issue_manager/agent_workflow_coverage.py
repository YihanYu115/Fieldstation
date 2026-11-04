"""Bounded authoritative coverage and atomic assessment dispatch (no role policy)."""
from __future__ import annotations

import hashlib
import json

from .agent_workflow_assessments import freeze, stored_spec, text, validate_spec
from .agent_workflow_proposals import check_current, freeze_context
from .errors import ConflictError, PermissionError, ValidationError
from .store import canonical_json


def digest(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def authorize(service, conn, mandate_id, request, auth, *, writing=False):
    service._require(auth, "workflow.read", "context.read")
    required = {"issue_id", "role", "assessment"}
    if writing:
        required |= {"producer", "event_id", "objective", "acceptance", "allowed_actions"}
    if not isinstance(request, dict) or set(request) != required:
        raise ValidationError("Expected finite assessment query/dispatch fields")
    if any(not text(request[k], 512) for k in ("issue_id", "role")):
        raise ValidationError("Expected bounded Issue and role labels")
    spec = validate_spec(request["assessment"])
    # A fresh explicit review is a separate intent, never a cache bypass flag.
    if spec["purpose"] in {"independent-check", "independent-check/"}:
        raise ValidationError("Independent checks require purpose independent-check/<host review ID>")
    mandate = service._mandate_row(conn, mandate_id)
    service._assert_epoch(mandate, conn)
    if mandate["status"] != "active" or json.loads(mandate["stop_conditions_json"]):
        raise ConflictError("Assessment dispatch requires an active mandate without unresolved stop conditions")
    if not service._within_scope(mandate, request["issue_id"], request["role"]):
        raise PermissionError("Assessment query is outside mandate scope")
    permissions = json.loads(mandate["permissions_json"])
    if "record_assessment" not in permissions["allowed_actions"]:
        raise PermissionError("Assessment query requires record_assessment scope")
    if writing:
        if any(not text(request[k], 512) for k in ("producer", "event_id", "objective")):
            raise ValidationError("Expected bounded event identity and objective")
        actions = request["allowed_actions"]
        if (not isinstance(actions, list) or not actions or
                any(not isinstance(a, str) for a in actions) or
                "record_assessment" not in actions or
                not set(actions) <= {"record_assessment", "create_proposal"}):
            raise ValidationError("Assessment dispatch accepts record_assessment and optional create_proposal")
        if not set(actions) <= set(permissions["allowed_actions"]):
            raise PermissionError("Assessment actions exceed mandate")
        if (not isinstance(request["acceptance"], list) or
                not all(text(a, 2000) for a in request["acceptance"]) or len(request["acceptance"]) > 16):
            raise ValidationError("Expected bounded acceptance criteria")
        if "workflow.manage" in auth.capabilities:
            service._require(auth, "workflow.manage")
        else:
            service._require(auth, "workflow.execute")
            if not permissions.get("can_create_work"):
                raise PermissionError("Mandate does not allow work creation")
    return mandate


def context_anchor(service, prepared):
    row = service.store.row(
        "SELECT descriptor_id,semantic_hash FROM context_input_packages WHERE package_id=?",
        (prepared["package_id"],))
    return dict(context=row, materials=digest(prepared["materials"]),
                current_conclusion=prepared["current_conclusion"],
                receipt=prepared["expected_receipt_id"])


def inspect(service, conn, mandate, request, auth, *, prepared=None):
    spec = request["assessment"]
    prepared = prepared or freeze_context(service.manager, request["issue_id"], auth,
                                          target_proposal_id=spec["target_proposal_id"])
    binding = freeze(spec, prepared)
    if prepared["resolution_errors"]:
        raise ConflictError("Assessment inputs have unresolved context errors")
    anchor = context_anchor(service, prepared)
    covered = set()
    records = []
    rows = conn.execute(
        "SELECT o.*,p.package_json FROM workflow_outputs o "
        "JOIN workflow_work_items w USING(work_item_id) "
        "JOIN workflow_work_packages p ON p.attempt_id=o.attempt_id "
        "WHERE w.issue_id=? AND o.business_action='record_assessment' ORDER BY o.rowid DESC LIMIT 257",
        (request["issue_id"],)).fetchall()
    if len(rows) > 256:
        raise ConflictError("Assessment history exceeds bounded query; explicit maintenance required")
    for row in rows:
        source = service._mandate_row(conn, row["mandate_id"])
        # Project capabilities are global; both mandates must currently admit this Issue/role/action.
        if (source["activation_epoch"] != mandate["activation_epoch"] or
                not service._within_scope(source, request["issue_id"], request["role"]) or
                "record_assessment" not in json.loads(source["permissions_json"])["allowed_actions"]):
            continue
        record = json.loads(row["body"])
        if (record.get("contract") != "workflow-assessment-record/v1" or
                record["decision"] not in {"revised", "no_change"} or
                record["target_after"] != binding["target"] or
                any(record[k] != spec[k] for k in ("policy", "purpose"))):
            continue
        package = json.loads(row["package_json"])
        if context_anchor(service, package["prepared_context"]) != anchor:
            continue
        try:
            check_current(service.manager, package)
        except ConflictError:
            continue
        event = conn.execute(
            "SELECT payload_json FROM workflow_events WHERE attempt_id=? AND event_type='attempt.submit_result'",
            (row["attempt_id"],)).fetchone()
        receipt = json.loads(event[0]) if event else {}
        if not receipt.get("published") or row["output_id"] not in receipt.get("assessment_ids", []):
            continue
        refs = {ref for ref in spec["change_refs"] if record["change_hashes"].get(ref) ==
                digest(prepared["materials"]["evidence"][ref])}
        if refs:
            covered.update(refs)
            records.append(dict(assessment_id=row["output_id"], handled_refs=sorted(refs), receipt=receipt,
                judgment={k: record[k] for k in ("decision", "reason", "evidence_refs", "policy", "purpose")}))
    remaining = set(spec["change_refs"]) - covered
    active = []
    rows = conn.execute(
        "SELECT * FROM workflow_work_items WHERE issue_id=? AND role=? "
        "AND status IN ('ready','running','checkpointed','blocked') LIMIT 257",
        (request["issue_id"], request["role"])).fetchall()
    if len(rows) > 256:
        raise ConflictError("Active assessment query exceeds bound")
    for item in rows:
        source = service._mandate_row(conn, item["mandate_id"])
        if (source["activation_epoch"] != mandate["activation_epoch"] or source["status"] != "active" or
                not service._within_scope(source, request["issue_id"], request["role"]) or
                "record_assessment" not in json.loads(source["permissions_json"])["allowed_actions"]):
            continue
        old = stored_spec(conn, item["work_item_id"])
        if not old or any(old[k] != spec[k] for k in ("target_proposal_id", "policy", "purpose")):
            continue
        saved = conn.execute(
            "SELECT payload_json FROM workflow_events WHERE work_item_id=? AND event_type='work_item.assessment_dispatch'",
            (item["work_item_id"],)).fetchone()
        if saved and json.loads(saved[0])["anchor"] != dict(context=anchor, target=binding["target"]):
            continue
        if not saved:
            previous = conn.execute(
                "SELECT p.package_json FROM workflow_work_packages p JOIN workflow_attempts a USING(attempt_id) "
                "WHERE a.work_item_id=? ORDER BY a.attempt_number DESC LIMIT 1", (item["work_item_id"],)).fetchone()
            if previous:
                package = json.loads(previous[0])
                if (context_anchor(service, package["prepared_context"]) != anchor or
                        package["assessment"]["target"] != binding["target"]):
                    continue
        refs = remaining & set(old["change_refs"])
        if refs:
            active.append(dict(work_item_id=item["work_item_id"], status=item["status"], change_refs=sorted(refs)))
            remaining -= refs
    return dict(covered_refs=sorted(covered), records=records, active_tasks=active,
                unhandled_refs=sorted(set(spec["change_refs"]) - covered),
                dispatchable_refs=sorted(remaining)), dict(context=anchor, target=binding["target"])


def query(service, mandate_id, request, *, auth):
    with service.store.transaction() as conn:
        mandate = authorize(service, conn, mandate_id, request, auth)
        return inspect(service, conn, mandate, request, auth)[0]


def dispatch(service, mandate_id, request, *, auth, idempotency_key):
    key = service._require_key(idempotency_key)
    with service.store.transaction() as conn:
        mandate = authorize(service, conn, mandate_id, request, auth, writing=True)
        payload = dict(mandate_id=mandate_id, request=request)
        operation = service._operation("assessment.dispatch", auth)
        replay = service.store.idempotency_lookup(operation, key, payload)
        if replay:
            return {**replay, "idempotent_replay": True}
        event_key = digest([request["producer"], request["event_id"]])
        event_operation = "workflow.assessment.event:" + mandate_id
        replay = service.store.idempotency_lookup(event_operation, event_key, payload)
        if replay:
            return {**replay, "event_replay": True}
        report, anchor = inspect(service, conn, mandate, request, auth)
        refs = report["dispatchable_refs"]
        if refs:
            spec = dict(request["assessment"], change_refs=refs)
            created = service.create_work_item(mandate_id, issue_id=request["issue_id"], role=request["role"],
                objective=request["objective"], acceptance=request["acceptance"],
                allowed_actions=request["allowed_actions"], assessment=spec,
                dedupe_key="assessment-event-" + event_key, auth=auth,
                idempotency_key="assessment-create-" + mandate_id + "-" + event_key)
            report.update(disposition="created" if "work_item_id" in created else "stopped", creation=created)
            if "work_item_id" in created:
                service._event(conn, mandate_id=mandate_id, work_item_id=created["work_item_id"],
                               event_type="work_item.assessment_dispatch", auth=auth, payload=dict(anchor=anchor))
        else:
            report["disposition"] = "active" if report["active_tasks"] else "covered"
        service.store.fault("workflow.after_assessment_dispatch")
        service.store.idempotency_record(conn, operation, key, payload, report)
        service.store.idempotency_record(conn, event_operation, event_key, payload, report)
        return report
