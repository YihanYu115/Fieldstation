from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

from .errors import ConflictError, ValidationError
from .store import canonical_json
from .strict_json import json_value_errors

PLANNER_ID = "legacy-policy-v11"
PLANNER_VERSION = 2
_PUBLICATION_LEVELS = {
    "declared",
    "source_verified",
    "snapshot_verified",
    "reproduced",
}


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _source_hash(value: Any) -> str:
    """Return a deterministic hash even when strict-JSON validation will reject value."""
    serialized = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=True,
        default=lambda item: f"<{type(item).__name__}>",
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _finding(
    code: str,
    *,
    source_hash: str,
    pointer: str,
    expected: str,
    actual: Any,
    classification: str = "requires_policy_mapping",
) -> dict[str, Any]:
    return {
        "classification": classification,
        "code": code,
        "subject": {"json_pointer": pointer},
        "expected": expected,
        "actual_type": type(actual).__name__,
        "source_hash": source_hash,
        "blocking": True,
    }


def _policy_input_findings(policy: Any, source_hash: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not isinstance(policy, dict):
        return [
            _finding(
                "legacy_policy_snapshot_invalid",
                source_hash=source_hash,
                pointer="",
                expected="object",
                actual=policy,
            )
        ]
    for error in json_value_errors(policy, path="$"):
        findings.append(
            {
                "classification": "blocking_corruption",
                "code": "legacy_policy_json_invalid",
                "subject": {"json_pointer": error["path"].removeprefix("$") or ""},
                "expected": "finite strict JSON value",
                "actual_type": error["code"],
                "source_hash": source_hash,
                "blocking": True,
            }
        )
    issue_types = policy.get("issue_types", {})
    if not isinstance(issue_types, dict):
        findings.append(
            _finding(
                "legacy_policy_issue_types_invalid",
                source_hash=source_hash,
                pointer="/issue_types",
                expected="object",
                actual=issue_types,
            )
        )
    else:
        for name, definition in sorted(issue_types.items(), key=lambda item: str(item[0])):
            if not isinstance(definition, dict):
                findings.append(
                    _finding(
                        "legacy_policy_issue_type_definition_invalid",
                        source_hash=source_hash,
                        pointer=f"/issue_types/{name}",
                        expected="object",
                        actual=definition,
                    )
                )
    publication = policy.get("publication", {})
    if not isinstance(publication, dict):
        findings.append(
            _finding(
                "legacy_policy_publication_invalid",
                source_hash=source_hash,
                pointer="/publication",
                expected="object",
                actual=publication,
            )
        )
    else:
        review_quorum = publication.get("review_quorum", {})
        if not isinstance(review_quorum, dict):
            findings.append(
                _finding(
                    "legacy_policy_review_quorum_invalid",
                    source_hash=source_hash,
                    pointer="/publication/review_quorum",
                    expected="object",
                    actual=review_quorum,
                )
            )
        else:
            for status, value in sorted(review_quorum.items()):
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    findings.append(
                        _finding(
                            "legacy_policy_review_quorum_invalid",
                            source_hash=source_hash,
                            pointer=f"/publication/review_quorum/{status}",
                            expected="non-negative integer",
                            actual=value,
                        )
                    )
        minimum = publication.get("report_facing_minimum_reviews", 0)
        if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0:
            findings.append(
                _finding(
                    "legacy_policy_review_quorum_invalid",
                    source_hash=source_hash,
                    pointer="/publication/report_facing_minimum_reviews",
                    expected="non-negative integer",
                    actual=minimum,
                )
            )
    requirements = policy.get("publication_requirements", {})
    if not isinstance(requirements, dict):
        findings.append(
            _finding(
                "legacy_policy_publication_requirements_invalid",
                source_hash=source_hash,
                pointer="/publication_requirements",
                expected="object",
                actual=requirements,
            )
        )
    else:
        for status, profile in sorted(requirements.items()):
            pointer = f"/publication_requirements/{status}"
            if not isinstance(profile, dict):
                findings.append(
                    _finding(
                        "legacy_policy_profile_invalid",
                        source_hash=source_hash,
                        pointer=pointer,
                        expected="object",
                        actual=profile,
                    )
                )
                continue
            for field in ("min_active_evidence", "review_quorum"):
                if field not in profile:
                    continue
                value = profile[field]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    findings.append(
                        _finding(
                            "legacy_policy_profile_invalid",
                            source_hash=source_hash,
                            pointer=f"{pointer}/{field}",
                            expected="non-negative integer",
                            actual=value,
                        )
                    )
            if (
                "minimum_verification_level" in profile
                and profile["minimum_verification_level"] not in _PUBLICATION_LEVELS
            ):
                findings.append(
                    _finding(
                        "legacy_policy_profile_invalid",
                        source_hash=source_hash,
                        pointer=f"{pointer}/minimum_verification_level",
                        expected="supported verification level",
                        actual=profile["minimum_verification_level"],
                    )
                )
    schemas = policy.get("conclusion_schemas", {})
    if not isinstance(schemas, dict):
        findings.append(
            _finding(
                "legacy_policy_conclusion_schemas_invalid",
                source_hash=source_hash,
                pointer="/conclusion_schemas",
                expected="object",
                actual=schemas,
            )
        )
    else:
        for name, schema in sorted(schemas.items()):
            if not isinstance(schema, dict):
                findings.append(
                    _finding(
                        "legacy_policy_conclusion_schema_invalid",
                        source_hash=source_hash,
                        pointer=f"/conclusion_schemas/{name}",
                        expected="object",
                        actual=schema,
                    )
                )
            elif "required" in schema and (
                not isinstance(schema["required"], list)
                or any(not isinstance(item, str) for item in schema["required"])
            ):
                findings.append(
                    _finding(
                        "legacy_policy_conclusion_schema_invalid",
                        source_hash=source_hash,
                        pointer=f"/conclusion_schemas/{name}/required",
                        expected="array of strings",
                        actual=schema["required"],
                    )
                )
    return findings


def _reference_environment(entries: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    snapshot = sorted(
        (
            {
                "registration_id": str(item.get("registration_id", "")),
                "bundle_id": str(item.get("bundle_id", "")),
                "kind": str(item.get("kind", "")),
                "content_hash": str(item.get("content_hash", "")),
                "state": str(item.get("state", "")),
            }
            for item in entries
        ),
        key=lambda item: (
            item["registration_id"],
            item["bundle_id"],
            item["kind"],
            item["content_hash"],
            item["state"],
        ),
    )
    return snapshot, _hash(snapshot)


def plan_legacy_policy_migration(
    policy_snapshot: Any,
    *,
    existing_registry_entries: Iterable[dict[str, Any]] = (),
    target_namespace: str = "local.compat.v11",
) -> dict[str, Any]:
    """Plan the exact conversion used by both v11 preflight and apply."""
    from .registry_service import (
        finalize_prepared_references,
        legacy_policy_semantic_findings,
        migrated_policy_bundle,
        prepare_bundle,
    )

    source_hash = _source_hash(policy_snapshot)
    external_entries = [dict(item) for item in existing_registry_entries]
    reference_snapshot, reference_hash = _reference_environment(external_entries)
    blockers = _policy_input_findings(policy_snapshot, source_hash)
    semantic_findings: list[dict[str, Any]] = []
    candidate_bundle: dict[str, Any] | None = None
    prepared_bundle: dict[str, Any] | None = None
    reference_locks: list[dict[str, Any]] = []
    if not blockers and isinstance(policy_snapshot, dict):
        for semantic in legacy_policy_semantic_findings(policy_snapshot):
            normalized = {
                "classification": "requires_policy_mapping",
                "code": "legacy_policy_semantics_not_declaratively_convertible",
                "subject": {"json_pointer": ""},
                "semantic_code": semantic.get("code", "unknown_policy_logic"),
                "semantic_details": semantic,
                "source_hash": source_hash,
                "blocking": True,
            }
            semantic_findings.append(normalized)
        blockers.extend(semantic_findings)
    if not blockers and isinstance(policy_snapshot, dict):
        try:
            candidate_bundle = migrated_policy_bundle(policy_snapshot)
            candidate_bundle["manifest"]["namespace"] = target_namespace
            if target_namespace.endswith(".v11"):
                candidate_bundle["manifest"]["name"] += "-v11"
            prepared_bundle = prepare_bundle(candidate_bundle, trusted_local=True)
            prepared_bundle, reference_locks = finalize_prepared_references(
                prepared_bundle, external_entries, []
            )
        except (KeyError, TypeError, ValueError, ValidationError, ConflictError) as exc:
            blockers.append(
                {
                    "classification": "requires_policy_mapping",
                    "code": "legacy_policy_bundle_prepare_invalid",
                    "subject": {"json_pointer": ""},
                    "expected": "convertible and reference-complete Feature Bundle",
                    "actual_type": type(exc).__name__,
                    "source_hash": source_hash,
                    "blocking": True,
                }
            )
    plan: dict[str, Any] = {
        "planner_id": PLANNER_ID,
        "planner_version": PLANNER_VERSION,
        "source_policy_hash": source_hash,
        "target_namespace": target_namespace,
        "reference_environment": reference_snapshot,
        "reference_environment_hash": reference_hash,
        "candidate_bundle": candidate_bundle,
        "candidate_bundle_hash": _hash(candidate_bundle) if candidate_bundle else None,
        "prepared_bundle": prepared_bundle,
        "prepared_bundle_hash": (
            str(prepared_bundle["content_hash"]) if prepared_bundle else None
        ),
        "reference_locks": reference_locks,
        "semantic_findings": semantic_findings,
        "blocking_findings": blockers,
        "safe_to_apply": not blockers and prepared_bundle is not None,
    }
    plan["plan_hash"] = _hash(plan)
    return plan


def assert_policy_plan_current(
    plan: dict[str, Any],
    policy_snapshot: Any,
    *,
    existing_registry_entries: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    if plan.get("planner_id") != PLANNER_ID or plan.get("planner_version") != PLANNER_VERSION:
        raise ValidationError("Unknown legacy Policy migration planner")
    current = plan_legacy_policy_migration(
        policy_snapshot,
        existing_registry_entries=existing_registry_entries,
        target_namespace=str(plan.get("target_namespace", "local.compat.v11")),
    )
    if current["plan_hash"] != plan.get("plan_hash"):
        raise ValidationError(
            "Legacy Policy migration plan is stale",
            details={
                "code": "migration_plan_stale",
                "planned_hash": plan.get("plan_hash"),
                "current_hash": current["plan_hash"],
            },
        )
    return current
