"""Source-state effects of governed conflict resolution in a virtual ledger."""
from __future__ import annotations

import json
from typing import Any

from .errors import ConflictError, ValidationError
from .record_planner import plan_record_create, plan_record_revision, public_record_plan
from .store import canonical_json


def source_row(view, table, key, identity):
    rows = view.context_rows(table, key, identity)
    if not rows:
        raise ConflictError(f"Conflict source row is missing: {table}/{identity}")
    return dict(rows[0])


def plan_governed_record_resolution(view, operation, conflict) -> dict[str, Any]:
    """Plan the Record side of a governed Field/Import resolution."""
    action = operation["resolution"]
    domain = "field_bundle" if conflict["source_kind"] == "field_bundle" else "import"
    if domain == "field_bundle":
        action_row = source_row(
            view, "field_bundle_event_actions", "field_bundle_event_action_id",
            conflict["source_item_id"],
        )
        candidate = json.loads(action_row["action_json"])
        instance = view.record_instance(str(operation["record_instance_id"]))
        if action == "accept_as_new_revision":
            result = plan_record_revision(
                view,
                record_instance_id=str(operation["record_instance_id"]),
                data=candidate["data"],
                expected_revision_id=operation.get("expected_current_revision_id"),
                profile=str(candidate.get("profile", "draft")),
                evidence_links=candidate.get("evidence_links", []),
                source_mode="field_bundle",
            )
        else:
            result = plan_record_create(
                view,
                issue_id=str(instance["issue_id"]),
                template_reference=str(instance["record_template_registration_id"]),
                data=candidate["data"],
                profile=str(candidate.get("profile", "draft")),
                evidence_links=candidate.get("evidence_links", []),
                source_mode="field_bundle",
            )
    else:
        item = source_row(view, "import_items", "import_item_id", conflict["source_item_id"])
        mapped = json.loads(conflict["mapped_candidate_json"])
        targets = [
            row for row in view.context_rows(
                "external_mapping_targets", "source_object_mapping_id",
                conflict["existing_mapping_id"],
            ) if row["internal_object_type"] == "record_instance"
        ]
        targets.sort(key=lambda row: (row.get("linked_at") is None, row.get("linked_at") or ""))
        target = targets[0] if targets else None
        if action == "accept_as_new_revision":
            if not target:
                raise ConflictError("Conflict mapping has no internal Record target")
            result = plan_record_revision(
                view,
                record_instance_id=str(target["internal_object_id"]),
                data=mapped,
                expected_revision_id=str(target["internal_revision_id"]),
                profile="draft",
                source_mode="imported",
                source_object_mapping_id=str(conflict["existing_mapping_id"]),
            )
        else:
            result = plan_record_create(
                view,
                issue_id=str(item["target_issue_id"]),
                template_reference=str(item["target_template_registration_id"]),
                data=mapped,
                profile="draft",
                source_mode="imported",
                source_object_mapping_id=str(conflict["existing_mapping_id"]),
            )
    public_result = public_record_plan(result)
    stage_source_effects(view, operation, conflict, result=public_result)
    return public_result


def stage_source_effects(view, operation, conflict, *, result):
    action = operation["resolution"]
    job_id = conflict["source_job_id"]
    if conflict["source_kind"] == "field_bundle":
        row = source_row(view, "field_bundle_event_actions", "field_bundle_event_action_id", conflict["source_item_id"])
        event = source_row(view, "field_bundle_events", "field_bundle_event_id", row["field_bundle_event_id"])
        bundle = source_row(view, "field_bundles", "field_bundle_id", job_id)
        row["state"] = "applied" if action in {"accept_as_new_revision", "create_competing_record"} else (
            "conflicted" if action == "needs_more_information" else "rejected")
        row["result_json"] = canonical_json(result)
        event.update(processing_state="needs_triage" if action == "needs_more_information" else row["state"],
                     result_json=canonical_json({"conflict_resolution": action, "result": result}),
                     state_revision=event["state_revision"] + 1)
        view.field_bundle_event_actions[row["field_bundle_event_action_id"]] = row
        view.field_bundle_events[event["field_bundle_event_id"]] = event
        unresolved = any(item["source_kind"] == "field_bundle" and item["state"] != "resolved"
                         for item in view.context_rows("integration_conflicts", "source_job_id", job_id))
        pending = any(item["processing_state"] in {"pending", "staged", "ready", "needs_triage", "failed"}
                      for item in view.context_rows("field_bundle_events", "field_bundle_id", job_id))
        bundle.update(state="needs_triage" if unresolved or pending else "applied",
                      routing_state_revision=bundle["routing_state_revision"] + 1)
        view.field_bundles[job_id] = bundle
        return
    item = source_row(view, "import_items", "import_item_id", conflict["source_item_id"])
    job = source_row(view, "import_jobs", "import_job_id", job_id)
    if action in {"accept_as_new_revision", "create_competing_record", "keep_internal_and_update_mapping"}:
        mapping_id = conflict["existing_mapping_id"]
        mapping = source_row(view, "external_object_mappings", "source_object_mapping_id", mapping_id)
        mapping.update(
            external_content_hash=conflict["candidate_external_hash"],
            latest_import_job_id=job_id,
            updated_at=None,
        )
        view.external_object_mappings[mapping_id] = mapping
    if action in {"accept_as_new_revision", "create_competing_record"}:
        mapping_id = conflict["existing_mapping_id"]
        targets = [
            row for row in view.context_rows(
                "external_mapping_targets", "source_object_mapping_id", mapping_id,
            ) if row["internal_object_type"] == "record_instance"
        ]
        targets.sort(key=lambda row: (row.get("linked_at") is None, row.get("linked_at") or ""))
        target = targets[0] if targets else None
        if action == "accept_as_new_revision":
            if target is None:
                raise ConflictError("Conflict mapping has no internal Record target")
            target = {
                **target,
                "internal_revision_id": result["record_revision_id"],
                "linked_at": None,
            }
            target_key = (
                mapping_id, target["internal_object_type"], target["internal_object_id"]
            )
        else:
            target = {
                "source_object_mapping_id": mapping_id,
                "internal_object_type": "record_instance",
                "internal_object_id": result["record_instance_id"],
                "internal_revision_id": result["record_revision_id"],
                "linked_at": None,
            }
            target_key = (mapping_id, "record_instance", result["record_instance_id"])
        view.external_mapping_targets[target_key] = target
        item.update(validation_state="applied", applied_object_type="record_instance", applied_object_id=result["record_instance_id"])
    elif action in {"keep_internal_and_update_mapping", "reject_candidate"}:
        item.update(validation_state="replayed", applied_object_type="external_mapping", applied_object_id=conflict["existing_mapping_id"])
    elif action == "split_identity":
        identity = str(operation.get("resolution_payload", {}).get("external_object_id", "")).strip()
        if not identity:
            raise ValidationError("split_identity requires external_object_id")
        item.update(external_object_id=identity, validation_state="valid")
    view.import_items[item["import_item_id"]] = item
    unresolved = any(row["source_kind"] == "import" and row["state"] != "resolved"
                     for row in view.context_rows("integration_conflicts", "source_job_id", job_id))
    job["state"] = "partially_applied" if unresolved else "validated"
    view.import_jobs[job_id] = job
