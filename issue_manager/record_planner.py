"""Shared Record planning and application for preview and real execution.

The planner deliberately allocates only preflight identities.  The application
step replaces those identities inside the caller's transaction, so preview and
execution share validation, normalization, template snapshots, and content
hash decisions without making preview a hidden write path.
"""
from __future__ import annotations

from typing import Any

from .errors import ConflictError, StaleRevisionError, ValidationError
from .record_service import SOURCE_MODES, _content_hash
from .store import canonical_json, new_id, now
from .strict_json import require_strict_json


def _blank_row(view: Any, table: str) -> dict[str, Any]:
    return {
        column[1]: None
        for column in view.manager.store.conn.execute(f'PRAGMA table_info("{table}")')
    }


def _check_template_applies(issue: dict[str, Any], template: dict[str, Any]) -> None:
    applies_to = template["definition"].get("applies_to_issue_types", [])
    applicable_ids = {
        item["target_registration_id"]
        for item in template.get("reference_locks", [])
        if item["target_kind"] == "issue_type"
        and item["json_pointer"].startswith("/applies_to_issue_types/")
    }
    if applies_to and issue.get("issue_type_registration_id") not in applicable_ids:
        raise ValidationError(
            f"Record template does not apply to Issue type {issue['issue_type']!r}"
        )


def _record_plan_common(
    view: Any,
    *,
    issue_id: str,
    template_reference: str,
    data: dict[str, Any],
    profile: str,
    evidence_links: list[dict[str, Any]],
    source_mode: str,
    source_object_mapping_id: str | None,
    for_creation: bool,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]], str]:
    require_strict_json(data, path="$.data")
    require_strict_json(evidence_links, path="$.evidence_links")
    if source_mode not in SOURCE_MODES:
        raise ValidationError(f"Unsupported record source_mode: {source_mode}")
    issue = view.issue(issue_id)
    template = view.manager.records._template(template_reference, for_creation=for_creation)
    _check_template_applies(issue, template)
    validation = view.manager.records.validate_data(
        template["registration_id"],
        data,
        profile=profile,
        evidence_links=evidence_links,
        state_view=view,
    )
    if not validation["valid"]:
        raise ValidationError("Record data failed template validation", details=validation)
    normalized_links = validation["normalized_evidence_links"]
    content_hash = _content_hash(
        {
            "template_content_hash": template["content_hash"],
            "data": data,
            "source_mode": source_mode,
            "source_object_mapping_id": source_object_mapping_id,
            "normalized_evidence_links": normalized_links,
        }
    )
    return issue, template, validation, normalized_links, content_hash


def _stage_record_links(view: Any, revision_id: str, links: list[dict[str, Any]]) -> None:
    for link in links:
        row = _blank_row(view, "record_evidence_links")
        row.update(
            record_revision_id=revision_id,
            field_path=str(link["field_path"]),
            evidence_id=str(link["evidence_id"]),
            proof_id=link.get("proof_id"),
            relation_role=str(link.get("relation_role", "supports")),
            proof_hash=link.get("proof_hash"),
            manifest_id=link.get("manifest_id"),
            manifest_hash=link.get("manifest_hash"),
            evidence_semantic_revision=link.get("evidence_semantic_revision"),
            verification_level_snapshot=link.get("verification_level_snapshot"),
            verification_state_snapshot=link.get("verification_state_snapshot"),
        )
        key = (revision_id, row["field_path"], row["evidence_id"], row["relation_role"])
        view.record_evidence_links[key] = row


def plan_record_create(
    view: Any,
    *,
    issue_id: str,
    template_reference: str,
    data: dict[str, Any],
    profile: str = "draft",
    evidence_links: list[dict[str, Any]] | None = None,
    source_mode: str = "native",
    source_object_mapping_id: str | None = None,
) -> dict[str, Any]:
    """Plan RecordService.create against an explicit read view."""
    _, template, validation, normalized_links, content_hash = _record_plan_common(
        view,
        issue_id=issue_id,
        template_reference=template_reference,
        data=data,
        profile=profile,
        evidence_links=evidence_links or [],
        source_mode=source_mode,
        source_object_mapping_id=source_object_mapping_id,
        for_creation=True,
    )
    instance_id = f"preflight-record:{len(view.record_instances)}"
    revision_id = f"preflight-record-revision:{len(view.record_revisions)}"
    snapshot_json = canonical_json(template)
    instance = _blank_row(view, "record_instances")
    instance.update(
        record_instance_id=instance_id,
        issue_id=issue_id,
        record_template_registration_id=template["registration_id"],
        record_template_snapshot_json=snapshot_json,
        created_at=None,
        created_by=None,
        current_revision_id=revision_id,
        lifecycle_status="active",
    )
    revision = _blank_row(view, "record_revisions")
    revision.update(
        record_revision_id=revision_id,
        record_instance_id=instance_id,
        revision_number=1,
        template_content_hash=template["content_hash"],
        template_snapshot_json=snapshot_json,
        data_json=canonical_json(data),
        recorded_at=None,
        recorded_by=None,
        source_mode=source_mode,
        source_object_mapping_id=source_object_mapping_id,
        supersedes_revision_id=None,
        validation_profile=profile,
        validation_result_json=canonical_json(validation),
        content_hash=content_hash,
    )
    view.record_instances[instance_id] = instance
    view.record_revisions[revision_id] = revision
    _stage_record_links(view, revision_id, normalized_links)
    return {
        "operation": "record.create",
        "issue_id": issue_id,
        "template_registration_id": template["registration_id"],
        "template_content_hash": template["content_hash"],
        "profile": profile,
        "validation": validation,
        "record_instance_id": instance_id,
        "record_revision_id": revision_id,
        "revision_number": 1,
        "content_hash": content_hash,
        "event_id": None,
        "would_write": True,
        "normalized_evidence_links": normalized_links,
        "_template": template,
        "_instance": instance,
        "_revision": revision,
    }


def plan_record_revision(
    view: Any,
    *,
    record_instance_id: str,
    data: dict[str, Any],
    expected_revision_id: str | None = None,
    profile: str = "draft",
    evidence_links: list[dict[str, Any]] | None = None,
    source_mode: str = "native",
    source_object_mapping_id: str | None = None,
) -> dict[str, Any]:
    """Plan RecordService.revise against an explicit read view."""
    instance = view.record_instance(record_instance_id)
    if instance["lifecycle_status"] != "active":
        raise ConflictError(f"Record is not active: {record_instance_id}")
    current_id = str(instance["current_revision_id"])
    if expected_revision_id and expected_revision_id != current_id:
        raise StaleRevisionError(
            f"Record current revision changed from {expected_revision_id} to {current_id}"
        )
    current = view.record_revision(current_id)
    _, template, validation, normalized_links, content_hash = _record_plan_common(
        view,
        issue_id=str(instance["issue_id"]),
        template_reference=str(instance["record_template_registration_id"]),
        data=data,
        profile=profile,
        evidence_links=evidence_links or [],
        source_mode=source_mode,
        source_object_mapping_id=source_object_mapping_id,
        for_creation=False,
    )
    if content_hash == current["content_hash"]:
        return {
            "operation": "record.revise",
            "record_instance_id": record_instance_id,
            "record_revision_id": current_id,
            "revision_number": current["revision_number"],
            "content_hash": content_hash,
            "idempotent_replay": True,
            "would_write": False,
        }
    revision_id = f"preflight-record-revision:{len(view.record_revisions)}"
    snapshot_json = canonical_json(template)
    revision_number = int(current["revision_number"]) + 1
    revision = _blank_row(view, "record_revisions")
    revision.update(
        record_revision_id=revision_id,
        record_instance_id=record_instance_id,
        revision_number=revision_number,
        template_content_hash=template["content_hash"],
        template_snapshot_json=snapshot_json,
        data_json=canonical_json(data),
        recorded_at=None,
        recorded_by=None,
        source_mode=source_mode,
        source_object_mapping_id=source_object_mapping_id,
        supersedes_revision_id=current_id,
        validation_profile=profile,
        validation_result_json=canonical_json(validation),
        content_hash=content_hash,
    )
    view.record_revisions[revision_id] = revision
    view.record_instances[record_instance_id] = {**instance, "current_revision_id": revision_id}
    _stage_record_links(view, revision_id, normalized_links)
    return {
        "operation": "record.revise",
        "record_instance_id": record_instance_id,
        "from_revision_id": current_id,
        "to_revision_number": revision_number,
        "content_hash": content_hash,
        "validation": validation,
        "record_revision_id": revision_id,
        "event_id": None,
        "idempotent_replay": False,
        "would_write": True,
        "normalized_evidence_links": normalized_links,
        "_template": template,
        "_instance": instance,
        "_current": current,
        "_revision": revision,
    }


def apply_record_plan(
    record_service: Any,
    plan: dict[str, Any],
    *,
    actor: str,
    reason: str,
) -> dict[str, Any]:
    """Apply a Record plan in the caller's transaction boundary."""
    if not plan.get("would_write", False):
        return dict(plan)
    store = record_service.store
    operation = plan["operation"]
    if operation == "record.create":
        instance_id = new_id("record")
        revision_id = new_id("record_revision")
        timestamp = now()
        template = plan["_template"]
        instance = plan["_instance"]
        revision = plan["_revision"]
        with store.transaction() as conn:
            conn.execute(
                "INSERT INTO record_instances(record_instance_id,issue_id,"
                "record_template_registration_id,record_template_snapshot_json,created_at,created_by,"
                "current_revision_id,lifecycle_status) VALUES (?,?,?,?,?,?,?, 'active')",
                (
                    instance_id, instance["issue_id"], template["registration_id"],
                    instance["record_template_snapshot_json"], timestamp, actor, revision_id,
                ),
            )
            conn.execute(
                "INSERT INTO record_revisions(record_revision_id,record_instance_id,revision_number,"
                "template_content_hash,template_snapshot_json,data_json,recorded_at,recorded_by,"
                "source_mode,source_object_mapping_id,supersedes_revision_id,validation_profile,"
                "validation_result_json,content_hash) VALUES (?,?,?,?,?,?,?,?,?,?,NULL,?,?,?)",
                (
                    revision_id, instance_id, revision["revision_number"],
                    revision["template_content_hash"], revision["template_snapshot_json"],
                    revision["data_json"], timestamp, actor, revision["source_mode"],
                    revision["source_object_mapping_id"], revision["validation_profile"],
                    revision["validation_result_json"], revision["content_hash"],
                ),
            )
            record_service._insert_links(conn, revision_id, plan["normalized_evidence_links"])
            record_service._index_revision(conn, revision_id, template["definition"], json_loads(revision["data_json"]))
            event_id = store.audit(
                conn, actor=actor, action="record.create", object_type="record_instance",
                object_id=instance_id, before_revision=None, after_revision=1, reason=reason,
                payload={**public_record_plan(plan), "record_revision_id": revision_id,
                         "content_hash": revision["content_hash"]},
            )
        return {
            **public_record_plan(plan), "record_instance_id": instance_id,
            "record_revision_id": revision_id, "revision_number": 1,
            "content_hash": revision["content_hash"], "event_id": event_id,
            "would_write": True,
        }
    if operation == "record.revise":
        instance_id = str(plan["record_instance_id"])
        revision_id = new_id("record_revision")
        timestamp = now()
        current = plan["_current"]
        revision = plan["_revision"]
        with store.transaction() as conn:
            conn.execute(
                "INSERT INTO record_revisions(record_revision_id,record_instance_id,revision_number,"
                "template_content_hash,template_snapshot_json,data_json,recorded_at,recorded_by,"
                "source_mode,source_object_mapping_id,supersedes_revision_id,validation_profile,"
                "validation_result_json,content_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    revision_id, instance_id, revision["revision_number"],
                    revision["template_content_hash"], revision["template_snapshot_json"],
                    revision["data_json"], timestamp, actor, revision["source_mode"],
                    revision["source_object_mapping_id"], current["record_revision_id"],
                    revision["validation_profile"], revision["validation_result_json"],
                    revision["content_hash"],
                ),
            )
            record_service._insert_links(conn, revision_id, plan["normalized_evidence_links"])
            record_service._index_revision(conn, revision_id, plan["_template"]["definition"], json_loads(revision["data_json"]))
            updated = conn.execute(
                "UPDATE record_instances SET current_revision_id=? WHERE record_instance_id=? "
                "AND current_revision_id=?",
                (revision_id, instance_id, current["record_revision_id"]),
            )
            if updated.rowcount != 1:
                raise StaleRevisionError("Record changed concurrently")
            event_id = store.audit(
                conn, actor=actor, action="record.revise", object_type="record_instance",
                object_id=instance_id, before_revision=int(current["revision_number"]),
                after_revision=int(current["revision_number"]) + 1, reason=reason,
                payload=public_record_plan(plan),
            )
        return {
            **public_record_plan(plan), "record_revision_id": revision_id, "event_id": event_id,
            "idempotent_replay": False, "would_write": True,
        }
    raise ValidationError(f"Unsupported Record plan operation: {operation}")


def public_record_plan(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in plan.items()
        if not key.startswith("_")
        and key not in {"operation", "normalized_evidence_links"}
    }


def json_loads(value: str) -> dict[str, Any]:
    import json

    return json.loads(value)
