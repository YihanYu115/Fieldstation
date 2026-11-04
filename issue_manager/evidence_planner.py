"""Shared planning decisions for Evidence lifecycle and quality writes."""
from __future__ import annotations

from typing import Any

from .errors import LocatorIdentityInvalidError, NotFoundError, PermissionError, ValidationError
from .evidence_identity import (
    IDENTITY_ALGORITHM,
    LOCATOR_IDENTITY_VERSION,
    identity_locator,
    legacy_identity_key,
    search_normalize_locator,
)


def plan_create(view: Any, operation: dict[str, Any]) -> dict[str, Any]:
    kind = operation.get("kind")
    allowed_kinds = {"datavault_dataset", "bridge_job", "artifact", "script", "report", "external"}
    if kind not in allowed_kinds:
        raise ValidationError(f"Unknown evidence kind: {kind}")
    locator = operation.get("locator")
    if not isinstance(locator, str):
        raise LocatorIdentityInvalidError("Evidence locator must be a string")
    try:
        exact_locator = identity_locator(locator)
    except (TypeError, ValueError) as exc:
        raise LocatorIdentityInvalidError(str(exc)) from exc
    quality_status = operation.get("quality_status", "unknown")
    allowed_quality = {"unknown", "usable", "questionable", "invalid", "unusable_for_purpose"}
    if quality_status not in allowed_quality:
        raise ValidationError(f"Unknown evidence quality status: {quality_status}")
    if kind == "datavault_dataset":
        if "::dataset=" not in locator:
            raise ValidationError("Data Vault locator must include a full path and '::dataset=<number>'")
        path_part, dataset_part = locator.rsplit("::dataset=", 1)
        if not path_part or not dataset_part.isdigit():
            raise ValidationError("Invalid Data Vault locator; expected '<full-path>::dataset=<number>'")
    question_ids = list(operation.get("addresses_question_ids", ()))
    if any(not isinstance(item, str) or not item for item in question_ids):
        raise ValidationError("addresses_question_ids must contain non-empty Question IDs")
    raw_relations = list(operation.get("related_evidence", ()))
    if any(not isinstance(item, dict) for item in raw_relations):
        raise ValidationError("related_evidence must contain relation objects")
    issue_id = operation.get("issue_id")
    if issue_id:
        issue = view.issue(str(issue_id))
        if operation.get("_direct") and issue.get("work_status") in {"void", "archived"}:
            raise NotFoundError(f"Issue not found or inactive: {issue_id}")
    normalized_locator = search_normalize_locator(exact_locator)
    identity_key = legacy_identity_key(str(kind), exact_locator)
    rows = view.context_rows("evidence_refs", "identity_key", identity_key)
    existing = rows[0] if rows else None
    attached = bool(
        issue_id
        and existing
        and view.is_evidence_attached(str(issue_id), str(existing["evidence_id"]))
        and not question_ids
        and not raw_relations
    )
    return {
        "kind": str(kind),
        "locator": locator,
        "exact_locator": exact_locator,
        "normalized_locator": normalized_locator,
        "identity_locator": exact_locator,
        "search_locator": normalized_locator,
        "locator_identity_version": LOCATOR_IDENTITY_VERSION,
        "identity_algorithm": IDENTITY_ALGORITHM,
        "identity_namespace": "legacy",
        "identity_key": identity_key,
        "issue_id": str(issue_id) if issue_id else None,
        "quality_status": str(quality_status),
        "stored_quality_status": "unusable_for_purpose" if quality_status == "invalid" else str(quality_status),
        "question_ids": question_ids,
        "relation_declarations": [dict(item) for item in raw_relations],
        "existing": existing,
        "attached": attached,
        "evidence_id": str(existing["evidence_id"]) if existing else None,
    }


def plan_maintenance(view: Any, operation: dict[str, Any]) -> dict[str, Any]:
    evidence_id = str(operation["evidence_id"])
    try:
        evidence = view.evidence(evidence_id)
    except ValidationError as exc:
        if operation.get("_direct"):
            raise NotFoundError(f"Evidence not found: {evidence_id}") from exc
        raise
    action = str(operation["op"])
    decision: dict[str, Any] = {
        "op": action,
        "evidence_id": evidence_id,
        "evidence": evidence,
    }
    if action == "reassess_evidence":
        from .evidence_service import normalize_quality_status

        quality_status = str(operation["quality_status"])
        decision["quality_status"] = quality_status
        decision["stored_quality_status"] = normalize_quality_status(quality_status)
    elif action == "void_evidence":
        decision["existing"] = evidence.get("lifecycle_status") == "void"
    elif action == "detach_evidence":
        issue_id = str(operation["issue_id"])
        if not view.is_evidence_attached(issue_id, evidence_id):
            error = NotFoundError if operation.get("_direct") else ValidationError
            raise error(f"Evidence {evidence_id} is not attached to issue {issue_id}")
        decision["issue_id"] = issue_id
    else:
        raise ValidationError(f"Unsupported Evidence maintenance operation: {action}")

    if operation.get("_enforce_review"):
        issue_id_filter: str | None = (
            str(operation["issue_id"]) if action == "detach_evidence" else None
        )
        impact = view.manager._evidence_publication_impact(evidence_id, issue_id=issue_id_filter)
        decision["impact"] = impact
        if impact and (
            action == "void_evidence"
            or decision.get("quality_status") in {"questionable", "invalid", "unusable_for_purpose"}
        ) and not operation.get("_reviewed_changeset"):
            verb = {"void_evidence": "Voiding", "detach_evidence": "Detaching", "reassess_evidence": "Evidence reassessment"}[action]
            raise PermissionError(
                f"{verb} evidence affects published knowledge ({impact['tier']}); use a reviewed ChangeSet"
            )
    return decision
