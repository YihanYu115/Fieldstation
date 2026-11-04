from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable

from .errors import (
    ConflictError,
    MigrationResolutionError,
    MigrationResolutionStaleError,
    NotFoundError,
    ValidationError,
)
from .integrity import (
    active_quarantines,
    digest,
    load_dependency,
    normalize_object_type,
    object_dependencies,
    object_snapshot,
    validate_object_integrity,
)
from .policy_repair import (
    POLICY_FINDING_CODES,
    apply_policy_repair_mutation,
    load_candidate,
    load_policy_subject,
    policy_repair_dependency,
)
from .store import canonical_json, new_id, now

if TYPE_CHECKING:
    from .store import Store


PROOF_FORMAT = "migration-resolution-proof/v2"

# Compatibility for extensions/tests that used the v12 internal digest helper.
_hash = digest

DependencyLoader = Callable[
    [sqlite3.Connection, dict[str, Any], dict[str, Any], dict[str, Any]],
    list[dict[str, Any]],
]
Prevalidator = Callable[
    [sqlite3.Connection, dict[str, Any], dict[str, Any], dict[str, Any]],
    dict[str, Any],
]
MutationApplier = Callable[
    [sqlite3.Connection, dict[str, Any], dict[str, Any], dict[str, Any], str],
    list[dict[str, Any]],
]
Postvalidator = Callable[
    [
        sqlite3.Connection,
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        list[dict[str, Any]],
        list[dict[str, Any]],
    ],
    dict[str, Any],
]


@dataclass(frozen=True)
class MigrationResolutionHandlerV2:
    finding_codes: frozenset[str]
    allowed_actions: frozenset[str]
    resolution_schema: dict[str, frozenset[str]]
    invariant_id: str
    invariant_version: int
    load_subject: Callable[[sqlite3.Connection, dict[str, Any]], dict[str, Any]]
    load_dependencies: DependencyLoader
    prevalidate: Prevalidator
    apply_mutation: MutationApplier
    postvalidate: Postvalidator

    @property
    def validator_id(self) -> str:
        return self.invariant_id

    @property
    def validator_version(self) -> int:
        return self.invariant_version

    @property
    def subject_loader(self) -> Callable[[sqlite3.Connection, dict[str, Any]], dict[str, Any]]:
        return self.load_subject


# Kept as a public alias for callers that imported the v12 name.
MigrationResolutionHandler = MigrationResolutionHandlerV2


def _finding_details(finding: dict[str, Any]) -> dict[str, Any]:
    value = finding.get("details")
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(finding.get("details_json") or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _object_identity(finding: dict[str, Any]) -> tuple[str, str, str | None]:
    details = _finding_details(finding)
    object_type = normalize_object_type(
        str(details.get("target_object_type", details.get("table", finding["object_type"])))
    )
    object_id = str(details.get("target_object_id", finding["object_id"]))
    if object_type == "field_bundle_action":
        object_id = str(details.get("field_bundle_event_action_id", object_id))
    column = str(details["column"]) if details.get("column") else None
    return object_type, object_id, column


def _load_object_subject(
    conn: sqlite3.Connection, finding: dict[str, Any]
) -> dict[str, Any]:
    object_type, object_id, column = _object_identity(finding)
    snapshot = object_snapshot(conn, object_type, object_id)
    return {
        "object_type": object_type,
        "object_id": object_id,
        "column": column,
        "snapshot": snapshot,
    }


def _subject_hash(subject: dict[str, Any]) -> str:
    if (
        isinstance(subject.get("snapshot"), dict)
        and subject.get("object_type")
        and subject.get("object_id")
    ):
        return digest(subject["snapshot"])
    return digest(subject)


def _policy_dependencies(
    conn: sqlite3.Connection,
    _finding: dict[str, Any],
    _subject: dict[str, Any],
    resolution: dict[str, Any],
) -> list[dict[str, Any]]:
    return policy_repair_dependency(conn, str(resolution.get("repair_id", "")))


def _object_dependencies(
    conn: sqlite3.Connection,
    finding: dict[str, Any],
    _subject: dict[str, Any],
    resolution: dict[str, Any],
) -> list[dict[str, Any]]:
    object_type, object_id, _column = _object_identity(finding)
    if resolution.get("action") == "repair_successor":
        object_id = str(resolution.get("successor_object_id", ""))
        object_type = normalize_object_type(
            str(resolution.get("successor_object_type", object_type))
        )
    dependencies = object_dependencies(conn, object_type, object_id)
    if resolution.get("action") in {"quarantine_object", "quarantine_action"}:
        quarantine_id = str(resolution.get("quarantine_id", ""))
        quarantine = load_dependency(conn, "integrity_quarantine", quarantine_id)
        if quarantine:
            dependencies.append(quarantine)
    return sorted(
        dependencies,
        key=lambda item: (item["dependency_type"], item["dependency_id"]),
    )


def _policy_prevalidate(
    conn: sqlite3.Connection,
    finding: dict[str, Any],
    subject: dict[str, Any],
    resolution: dict[str, Any],
) -> dict[str, Any]:
    if subject.get("load_error"):
        return {"valid": False, "findings": [{"code": "policy_subject_missing"}]}
    repair_id = str(resolution.get("repair_id", ""))
    try:
        candidate = load_candidate(conn, repair_id)
    except NotFoundError:
        return {
            "valid": False,
            "findings": [{"code": "policy_repair_candidate_missing", "repair_id": repair_id}],
        }
    findings: list[dict[str, Any]] = []
    if candidate["finding_id"] != finding["finding_id"]:
        findings.append({"code": "policy_repair_finding_mismatch"})
    if candidate["state"] != "validated":
        findings.append(
            {"code": "policy_repair_candidate_not_validated", "state": candidate["state"]}
        )
    if resolution.get("repair_hash") != candidate["plan_hash"]:
        findings.append({"code": "policy_repair_hash_mismatch"})
    bundle = subject.get("bundle") or {}
    if bundle.get("content_hash") != candidate["source_bundle_hash"]:
        findings.append({"code": "policy_repair_source_bundle_drift"})
    if subject.get("policy_hash") != candidate["source_policy_hash"]:
        findings.append({"code": "policy_repair_source_policy_drift"})
    return {
        "valid": not findings,
        "findings": findings,
        "repair_id": repair_id,
        "plan_hash": candidate["plan_hash"],
        "repair_mode": candidate["repair_mode"],
    }


def _object_prevalidate(
    conn: sqlite3.Connection,
    finding: dict[str, Any],
    subject: dict[str, Any],
    resolution: dict[str, Any],
) -> dict[str, Any]:
    object_type, object_id, column = _object_identity(finding)
    action = str(resolution["action"])
    findings: list[dict[str, Any]] = []
    if subject["snapshot"].get("load_error"):
        findings.append({"code": str(subject["snapshot"]["load_error"])})
    if action in {"quarantine_object", "quarantine_action"}:
        quarantine_id = str(resolution.get("quarantine_id", ""))
        quarantine = conn.execute(
            "SELECT * FROM integrity_quarantines WHERE quarantine_id=?",
            (quarantine_id,),
        ).fetchone()
        if not quarantine:
            findings.append({"code": "quarantine_receipt_missing"})
        else:
            quarantine = dict(quarantine)
            if quarantine["state"] != "active":
                findings.append({"code": "quarantine_not_active"})
            if normalize_object_type(str(quarantine["object_type"])) != object_type:
                findings.append({"code": "quarantine_object_type_mismatch"})
            if quarantine["object_id"] != object_id:
                findings.append({"code": "quarantine_object_id_mismatch"})
            if quarantine["subject_hash"] != digest(subject["snapshot"]):
                findings.append({"code": "quarantine_subject_hash_mismatch"})
            if quarantine["finding_id"] != finding["finding_id"]:
                findings.append({"code": "quarantine_finding_mismatch"})
        return {"valid": not findings, "findings": findings}
    if action == "repair_successor":
        successor_type = normalize_object_type(
            str(resolution.get("successor_object_type", object_type))
        )
        successor_id = str(resolution.get("successor_object_id", ""))
        if successor_type != object_type or successor_id == object_id:
            findings.append({"code": "repair_successor_identity_invalid"})
        validation = validate_object_integrity(
            conn, successor_type, successor_id, column=column
        )
        findings.extend(validation["findings"])
        if validation["valid"] and object_type == "record_revision":
            old = subject["snapshot"].get("revision", {})
            successor = object_snapshot(conn, object_type, successor_id).get("revision", {})
            if successor.get("record_instance_id") != old.get("record_instance_id"):
                findings.append({"code": "repair_successor_owner_mismatch"})
            if successor.get("supersedes_revision_id") != old.get("record_revision_id"):
                findings.append({"code": "repair_successor_chain_mismatch"})
        return {
            "valid": not findings,
            "findings": findings,
            "successor_validation": validation,
        }
    validation = validate_object_integrity(conn, object_type, object_id, column=column)
    findings.extend(validation["findings"])
    expected_hash = resolution.get("object_hash", resolution.get("action_hash"))
    if expected_hash and expected_hash not in {
        validation["subject_after_hash"],
        subject["snapshot"].get("row", {}).get("action_hash"),
    }:
        findings.append({"code": "object_repair_hash_mismatch"})
    return {"valid": not findings, "findings": findings, "object_validation": validation}


def _policy_apply(
    conn: sqlite3.Connection,
    _finding: dict[str, Any],
    _subject: dict[str, Any],
    resolution: dict[str, Any],
    actor: str,
) -> list[dict[str, Any]]:
    candidate = load_candidate(conn, str(resolution["repair_id"]))
    return apply_policy_repair_mutation(conn, candidate, actor=actor)


def _object_apply(
    _conn: sqlite3.Connection,
    _finding: dict[str, Any],
    _subject: dict[str, Any],
    _resolution: dict[str, Any],
    _actor: str,
) -> list[dict[str, Any]]:
    # Successor objects and quarantine overlays must already exist. The resolution
    # transaction only binds and verifies those immutable facts.
    return []


def _policy_postvalidate(
    conn: sqlite3.Connection,
    finding: dict[str, Any],
    before_subject: dict[str, Any],
    resolution: dict[str, Any],
    dependencies: list[dict[str, Any]],
    mutation_results: list[dict[str, Any]],
) -> dict[str, Any]:
    candidate = load_candidate(conn, str(resolution["repair_id"]))
    findings: list[dict[str, Any]] = []
    if candidate["state"] != "applied":
        findings.append({"code": "policy_repair_not_applied"})
    prepared_entries = {
        item["registration_id"]: item for item in candidate["prepared_bundle"]["entries"]
    }
    for old_id, new_id_value in sorted(candidate["issue_binding_map"].items()):
        if new_id_value not in prepared_entries:
            findings.append({"code": "policy_repair_binding_target_missing", "target": new_id_value})
            continue
        remaining = int(
            conn.execute(
                "SELECT COUNT(*) FROM issues WHERE issue_type_registration_id=?", (old_id,)
            ).fetchone()[0]
        )
        if remaining:
            findings.append(
                {"code": "policy_repair_binding_incomplete", "source": old_id, "count": remaining}
            )
    dependency_findings = _dependency_state_findings(dependencies)
    findings.extend(dependency_findings)
    after_subject = load_policy_subject(conn, finding)
    after_hash = _subject_hash(after_subject)
    result = {
        "valid": not findings,
        "invariant_id": "legacy-policy-exact-repair",
        "invariant_version": 3,
        # The Policy source is immutable; the controlled mutation installs an external
        # replacement and rebinds current Issues. Replays therefore validate the stable
        # post-mutation source view while the receipt separately retains the true pre-hash.
        "subject_before_hash": after_hash,
        "subject_after_hash": after_hash,
        "dependency_snapshot_hash": dependency_snapshot_hash(dependencies),
        "findings": findings,
        "result_objects": mutation_results,
        "covered_findings": candidate["plan"].get("covered_findings", []),
        "residual_findings": candidate["plan"].get("residual_findings", []),
    }
    result["postcondition_hash"] = digest(result)
    return result


def _object_postvalidate(
    conn: sqlite3.Connection,
    finding: dict[str, Any],
    before_subject: dict[str, Any],
    resolution: dict[str, Any],
    dependencies: list[dict[str, Any]],
    _mutation_results: list[dict[str, Any]],
) -> dict[str, Any]:
    object_type, object_id, column = _object_identity(finding)
    action = str(resolution["action"])
    findings = _dependency_state_findings(dependencies)
    result_objects: list[dict[str, Any]] = []
    invariant_id = "object-integrity"
    invariant_version = 2
    if action in {"quarantine_object", "quarantine_action"}:
        matches = active_quarantines(conn, object_type, object_id)
        quarantine_id = str(resolution.get("quarantine_id", ""))
        exact = next(
            (item for item in matches if item["quarantine_id"] == quarantine_id), None
        )
        if not exact:
            findings.append({"code": "quarantine_receipt_missing"})
        elif exact["subject_hash"] != digest(before_subject["snapshot"]):
            findings.append({"code": "quarantine_subject_hash_mismatch"})
        else:
            result_objects.append(
                {
                    "object_type": "integrity_quarantine",
                    "object_id": quarantine_id,
                    "content_hash": exact["subject_hash"],
                }
            )
        invariant_id = "integrity-quarantine-overlay"
    else:
        target_type = object_type
        target_id = object_id
        if action == "repair_successor":
            target_type = normalize_object_type(
                str(resolution.get("successor_object_type", object_type))
            )
            target_id = str(resolution["successor_object_id"])
        validation = validate_object_integrity(
            conn, target_type, target_id, column=column
        )
        findings.extend(validation["findings"])
        invariant_id = validation["invariant_id"]
        invariant_version = int(validation["invariant_version"])
        result_objects.extend(validation["result_objects"])
    after_subject = _load_object_subject(conn, finding)
    if _subject_hash(after_subject) != _subject_hash(before_subject):
        findings.append({"code": "migration_resolution_subject_drift"})
    result = {
        "valid": not findings,
        "invariant_id": invariant_id,
        "invariant_version": invariant_version,
        "subject_before_hash": _subject_hash(before_subject),
        "subject_after_hash": _subject_hash(after_subject),
        "dependency_snapshot_hash": dependency_snapshot_hash(dependencies),
        "findings": findings,
        "result_objects": result_objects,
    }
    result["postcondition_hash"] = digest(result)
    return result


_OBJECT_FINDING_CODES = frozenset(
    {
        "json_column_invalid",
        "historical_json_invalid",
        "legacy_policy_json_invalid",
        "field_action_identity_incoherent",
        "record_base_revision_required",
        "record_base_revision_mismatch",
        "migration_object_repair_semantics_invalid",
        "quarantine_receipt_missing",
        "migration_resolution_object_validator_unknown",
        "migration_resolution_dependency_revalidation_required",
    }
)

_POLICY_HANDLER = MigrationResolutionHandlerV2(
    finding_codes=POLICY_FINDING_CODES,
    allowed_actions=frozenset({"apply_policy_repair"}),
    resolution_schema={"apply_policy_repair": frozenset({"repair_id", "repair_hash"})},
    invariant_id="legacy-policy-exact-repair",
    invariant_version=3,
    load_subject=load_policy_subject,
    load_dependencies=_policy_dependencies,
    prevalidate=_policy_prevalidate,
    apply_mutation=_policy_apply,
    postvalidate=_policy_postvalidate,
)

_OBJECT_HANDLER = MigrationResolutionHandlerV2(
    finding_codes=_OBJECT_FINDING_CODES,
    allowed_actions=frozenset(
        {
            "repair_successor",
            "repair_from_source",
            "quarantine_object",
            "quarantine_action",
        }
    ),
    resolution_schema={
        "repair_successor": frozenset({"successor_object_id"}),
        "repair_from_source": frozenset({"object_hash"}),
        "quarantine_object": frozenset({"quarantine_id"}),
        "quarantine_action": frozenset({"quarantine_id"}),
    },
    invariant_id="object-specific-integrity",
    invariant_version=2,
    load_subject=_load_object_subject,
    load_dependencies=_object_dependencies,
    prevalidate=_object_prevalidate,
    apply_mutation=_object_apply,
    postvalidate=_object_postvalidate,
)

_HANDLERS = (_POLICY_HANDLER, _OBJECT_HANDLER)


def handler_for(code: str) -> MigrationResolutionHandlerV2 | None:
    return next((handler for handler in _HANDLERS if code in handler.finding_codes), None)


def _finding(store: Store, finding_id: str) -> dict[str, Any]:
    finding = store.row(
        "SELECT * FROM migration_findings WHERE finding_id=?", (finding_id,)
    )
    if not finding:
        raise NotFoundError(f"Migration finding not found: {finding_id}")
    finding["details"] = _finding_details(finding)
    finding["resolution"] = (
        json.loads(finding["resolution_json"]) if finding.get("resolution_json") else None
    )
    finding["receipt"] = (
        store.row(
            "SELECT * FROM migration_finding_resolution_receipts WHERE receipt_id=?",
            (finding["resolution_receipt_id"],),
        )
        if finding.get("resolution_receipt_id")
        else None
    )
    return finding


def show_finding(store: Store, finding_id: str) -> dict[str, Any]:
    finding = _finding(store, finding_id)
    handler = handler_for(str(finding["code"]))
    subject = (
        handler.load_subject(store.conn, finding)
        if handler
        else {
            "object_type": finding["object_type"],
            "object_id": finding["object_id"],
            "details": finding["details"],
        }
    )
    return {
        **finding,
        "subject": subject,
        "subject_hash": _subject_hash(subject),
        "allowed_actions": sorted(handler.allowed_actions) if handler else [],
        "invariant_id": handler.invariant_id if handler else None,
        "invariant_version": handler.invariant_version if handler else None,
        "validator_id": handler.invariant_id if handler else None,
        "validator_version": handler.invariant_version if handler else None,
        "proof_format": PROOF_FORMAT if handler else None,
    }


def actions_for_finding(store: Store, finding_id: str) -> dict[str, Any]:
    shown = show_finding(store, finding_id)
    handler = handler_for(str(shown["code"]))
    return {
        "finding_id": finding_id,
        "finding_code": shown["code"],
        "blocking": shown["classification"]
        in {"requires_policy_mapping", "blocking_corruption", "requires_triage"},
        "subject_hash": shown["subject_hash"],
        "allowed_actions": shown["allowed_actions"],
        "resolution_schema": (
            {
                action: sorted(handler.resolution_schema[action])
                for action in sorted(handler.allowed_actions)
            }
            if handler
            else {}
        ),
        "invariant_id": shown["invariant_id"],
        "invariant_version": shown["invariant_version"],
        "validator_id": shown["validator_id"],
        "validator_version": shown["validator_version"],
        "proof_format": shown["proof_format"],
    }


def _payload_error(
    resolution: dict[str, Any], handler: MigrationResolutionHandlerV2, action: str
) -> dict[str, Any] | None:
    required = handler.resolution_schema[action]
    optional = {"successor_object_type"}
    allowed = {"action", "subject_hash", "reason", *required, *optional}
    missing = sorted(required - set(resolution))
    unknown = sorted(set(resolution) - allowed)
    invalid = sorted(
        field
        for field in {"action", "subject_hash", "reason", *required}
        if field in resolution
        and (not isinstance(resolution[field], str) or not resolution[field].strip())
    )
    if missing or unknown or invalid:
        return {
            "missing_fields": missing,
            "unknown_fields": unknown,
            "invalid_string_fields": invalid,
        }
    return None


def _validation_result(
    conn: sqlite3.Connection,
    finding: dict[str, Any],
    resolution: dict[str, Any],
) -> tuple[MigrationResolutionHandlerV2 | None, dict[str, Any], dict[str, Any]]:
    handler = handler_for(str(finding["code"]))
    subject = (
        handler.load_subject(conn, finding)
        if handler
        else {
            "object_type": finding["object_type"],
            "object_id": finding["object_id"],
            "details": _finding_details(finding),
        }
    )
    subject_hash = _subject_hash(subject)
    resolution_hash = digest(resolution)
    common = {
        "finding_id": finding["finding_id"],
        "finding_code": finding["code"],
        "subject_hash": subject_hash,
        "resolution_hash": resolution_hash,
    }
    action = str(resolution.get("action", ""))
    if handler is None:
        return handler, subject, {
            **common,
            "valid": False,
            "code": "migration_resolution_handler_unknown",
            "allowed_actions": [],
        }
    if action not in handler.allowed_actions:
        return handler, subject, {
            **common,
            "valid": False,
            "code": "migration_resolution_action_unsupported",
            "allowed_actions": sorted(handler.allowed_actions),
        }
    payload_error = _payload_error(resolution, handler, action)
    if payload_error:
        return handler, subject, {
            **common,
            "valid": False,
            "code": "migration_resolution_payload_invalid",
            **payload_error,
        }
    if resolution.get("subject_hash") != subject_hash:
        return handler, subject, {
            **common,
            "valid": False,
            "code": "migration_resolution_stale",
            "supplied_subject_hash": resolution.get("subject_hash"),
        }
    if not isinstance(resolution.get("reason"), str) or not resolution["reason"].strip():
        return handler, subject, {
            **common,
            "valid": False,
            "code": "migration_resolution_reason_required",
        }
    precondition = handler.prevalidate(conn, finding, subject, resolution)
    valid = bool(precondition.get("valid"))
    return handler, subject, {
        **common,
        "valid": valid,
        "code": "migration_resolution_valid" if valid else "migration_resolution_rejected",
        "invariant_id": handler.invariant_id,
        "invariant_version": handler.invariant_version,
        "validator_id": handler.invariant_id,
        "validator_version": handler.invariant_version,
        "precondition": precondition,
    }


def validate_resolution(
    store: Store, finding_id: str, resolution: dict[str, Any]
) -> dict[str, Any]:
    if not isinstance(resolution, dict):
        raise ValidationError("Migration resolution must be an object")
    finding = _finding(store, finding_id)
    _handler, _subject, validation = _validation_result(
        store.conn, finding, resolution
    )
    return validation


def dependency_snapshot_hash(dependencies: list[dict[str, Any]]) -> str:
    stable = [
        {
            "dependency_type": item["dependency_type"],
            "dependency_id": item["dependency_id"],
            "content_hash": item["content_hash"],
            "state": item["state"],
            "required_states": sorted(item["required_states"]),
            "snapshot_hash": item["snapshot_hash"],
        }
        for item in sorted(
            dependencies,
            key=lambda value: (value["dependency_type"], value["dependency_id"]),
        )
    ]
    return digest(stable)


def postcondition_hash(postcondition: dict[str, Any]) -> str:
    return digest({key: value for key, value in postcondition.items() if key != "postcondition_hash"})


def _dependency_state_findings(
    dependencies: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in dependencies:
        if item["state"] not in item["required_states"]:
            findings.append(
                {
                    "code": "migration_resolution_dependency_state_drift",
                    "dependency_type": item["dependency_type"],
                    "dependency_id": item["dependency_id"],
                    "state": item["state"],
                    "required_states": item["required_states"],
                }
            )
    return findings


def proof_payload(
    *,
    finding_id: str,
    finding_code: str,
    subject_before_hash: str,
    subject_after_hash: str,
    resolution_hash: str,
    invariant_id: str,
    invariant_version: int,
    invariant_parameters_hash: str,
    dependency_hash: str,
    postcondition_hash: str,
    result_objects: list[dict[str, Any]],
    actor: str,
    event_id: str,
) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "finding_code": finding_code,
        "subject_before_hash": subject_before_hash,
        "subject_after_hash": subject_after_hash,
        "resolution_hash": resolution_hash,
        "invariant_id": invariant_id,
        "invariant_version": invariant_version,
        "invariant_parameters_hash": invariant_parameters_hash,
        "dependency_snapshot_hash": dependency_hash,
        "postcondition_hash": postcondition_hash,
        "result_object_hashes": sorted(
            (
                {
                    "object_type": item["object_type"],
                    "object_id": item["object_id"],
                    "content_hash": item["content_hash"],
                }
                for item in result_objects
            ),
            key=lambda item: (
                item["object_type"],
                item["object_id"],
                item["content_hash"],
            ),
        ),
        "actor": actor,
        "event_id": event_id,
    }


def _insert_attempt(
    store: Store,
    conn: sqlite3.Connection,
    *,
    finding: dict[str, Any],
    subject_hash: str,
    resolution: dict[str, Any],
    validation: dict[str, Any],
    handler: MigrationResolutionHandlerV2 | None,
    accepted: bool,
    actor: str,
    event_id: str,
) -> str:
    attempt_id = new_id("migration_attempt")
    conn.execute(
        "INSERT INTO migration_finding_resolution_attempts("
        "attempt_id,finding_id,finding_code,finding_subject_hash,action,resolution_json,"
        "resolution_hash,validator_id,validator_version,validation_result_json,"
        "validation_result_hash,accepted,created_at,created_by,event_id) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            attempt_id,
            finding["finding_id"],
            finding["code"],
            subject_hash,
            str(resolution.get("action", "")),
            canonical_json(resolution),
            digest(resolution),
            handler.invariant_id if handler else "unknown-migration-resolution-validator",
            handler.invariant_version if handler else 0,
            canonical_json(validation),
            digest(validation),
            1 if accepted else 0,
            now(),
            actor,
            event_id,
        ),
    )
    return attempt_id


def apply_resolution(
    store: Store,
    finding_id: str,
    resolution: dict[str, Any],
    *,
    actor: str,
) -> dict[str, Any]:
    if not isinstance(resolution, dict):
        raise ValidationError("Migration resolution must be an object")
    with store.transaction() as conn:
        locked = conn.execute(
            "SELECT * FROM migration_findings WHERE finding_id=?", (finding_id,)
        ).fetchone()
        if not locked:
            raise NotFoundError(f"Migration finding not found: {finding_id}")
        finding = dict(locked)
        finding["details"] = _finding_details(finding)
        if finding["state"] == "resolved":
            receipt = conn.execute(
                "SELECT r.*,a.resolution_hash FROM migration_finding_resolution_receipts r "
                "JOIN migration_finding_resolution_attempts a "
                "ON a.attempt_id=r.accepted_attempt_id WHERE r.finding_id=?",
                (finding_id,),
            ).fetchone()
            if receipt and receipt["resolution_hash"] == digest(resolution):
                return {**dict(receipt), "accepted": True, "idempotent_replay": True}
            raise ConflictError("Migration finding was already resolved with different proof")
        handler, subject, validation = _validation_result(conn, finding, resolution)
        subject_hash = _subject_hash(subject)
        accepted_precondition = bool(validation["valid"])
        if not accepted_precondition:
            existing = conn.execute(
                "SELECT * FROM migration_finding_resolution_attempts WHERE finding_id=? "
                "AND finding_subject_hash=? AND resolution_hash=? AND accepted=0",
                (finding_id, subject_hash, digest(resolution)),
            ).fetchone()
            if existing:
                return {**dict(existing), "accepted": False, "idempotent_replay": True}
            event_id = store.audit(
                conn,
                actor=actor,
                action="migration.finding.resolve_rejected",
                object_type="migration_finding",
                object_id=finding_id,
                before_revision=0,
                after_revision=0,
                reason=str(resolution.get("reason", "")),
                payload={"resolution": resolution, "validation": validation},
            )
            attempt_id = _insert_attempt(
                store,
                conn,
                finding=finding,
                subject_hash=subject_hash,
                resolution=resolution,
                validation=validation,
                handler=handler,
                accepted=False,
                actor=actor,
                event_id=event_id,
            )
            return {
                "attempt_id": attempt_id,
                "finding_id": finding_id,
                "accepted": False,
                "validation": validation,
                "event_id": event_id,
                "idempotent_replay": False,
            }
        assert handler is not None
        mutation_results = handler.apply_mutation(
            conn, finding, subject, resolution, actor
        )
        current_subject = handler.load_subject(conn, finding)
        dependencies = handler.load_dependencies(
            conn, finding, current_subject, resolution
        )
        postcondition = handler.postvalidate(
            conn,
            finding,
            subject,
            resolution,
            dependencies,
            mutation_results,
        )
        if not postcondition.get("valid") or postcondition.get("findings"):
            raise MigrationResolutionError(
                "Migration resolution postcondition failed",
                details={
                    "code": "migration_resolution_postcondition_failed",
                    "postcondition": postcondition,
                },
            )
        after_hash = _subject_hash(current_subject)
        invariant_parameters = {
            "handler_id": handler.invariant_id,
            "handler_version": handler.invariant_version,
            "action": resolution["action"],
            "read_only_replay": True,
        }
        invariant_parameters_hash = digest(invariant_parameters)
        dependency_hash = dependency_snapshot_hash(dependencies)
        postcondition_hash_value = postcondition_hash(postcondition)
        postcondition["postcondition_hash"] = postcondition_hash_value
        event_id = store.audit(
            conn,
            actor=actor,
            action="migration.finding.resolve",
            object_type="migration_finding",
            object_id=finding_id,
            before_revision=0,
            after_revision=1,
            reason=str(resolution["reason"]),
            payload={
                "resolution": resolution,
                "precondition": validation,
                "postcondition": postcondition,
                "dependencies": dependencies,
            },
        )
        validation = {
            **validation,
            "postcondition": postcondition,
            "dependency_snapshot_hash": dependency_hash,
        }
        attempt_id = _insert_attempt(
            store,
            conn,
            finding=finding,
            subject_hash=subject_hash,
            resolution=resolution,
            validation=validation,
            handler=handler,
            accepted=True,
            actor=actor,
            event_id=event_id,
        )
        receipt_id = new_id("migration_receipt")
        proof = proof_payload(
            finding_id=finding_id,
            finding_code=str(finding["code"]),
            subject_before_hash=subject_hash,
            subject_after_hash=after_hash,
            resolution_hash=digest(resolution),
            invariant_id=handler.invariant_id,
            invariant_version=handler.invariant_version,
            invariant_parameters_hash=invariant_parameters_hash,
            dependency_hash=dependency_hash,
            postcondition_hash=postcondition_hash_value,
            result_objects=postcondition.get("result_objects", []),
            actor=actor,
            event_id=event_id,
        )
        proof_hash = digest(proof)
        timestamp = now()
        conn.execute(
            "INSERT INTO migration_finding_resolution_receipts("
            "receipt_id,finding_id,accepted_attempt_id,subject_before_hash,subject_after_hash,"
            "invariant_id,invariant_version,resolved_at,resolved_by,event_id,resolution_hash,"
            "dependency_snapshot_hash,invariant_parameters_json,invariant_parameters_hash,"
            "postcondition_json,postcondition_hash,proof_hash,proof_format) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                receipt_id,
                finding_id,
                attempt_id,
                subject_hash,
                after_hash,
                handler.invariant_id,
                handler.invariant_version,
                timestamp,
                actor,
                event_id,
                digest(resolution),
                dependency_hash,
                canonical_json(invariant_parameters),
                invariant_parameters_hash,
                canonical_json(postcondition),
                postcondition_hash_value,
                proof_hash,
                PROOF_FORMAT,
            ),
        )
        for ordinal, dependency in enumerate(
            sorted(
                dependencies,
                key=lambda item: (item["dependency_type"], item["dependency_id"]),
            )
        ):
            conn.execute(
                "INSERT INTO migration_resolution_dependencies VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    receipt_id,
                    ordinal,
                    dependency["dependency_type"],
                    dependency["dependency_id"],
                    dependency["content_hash"],
                    dependency["state"],
                    canonical_json(sorted(dependency["required_states"])),
                    canonical_json(dependency["snapshot"]),
                    dependency["snapshot_hash"],
                ),
            )
        updated = conn.execute(
            "UPDATE migration_findings SET state='resolved',resolved_at=?,resolved_by=?,"
            "resolution_json=?,resolution_receipt_id=? WHERE finding_id=? AND state='open'",
            (timestamp, actor, canonical_json(resolution), receipt_id, finding_id),
        )
        if updated.rowcount != 1:
            raise MigrationResolutionStaleError(
                "Migration finding changed concurrently during resolution"
            )
        remaining = int(
            conn.execute(
                "SELECT COUNT(*) FROM migration_findings WHERE state='open' "
                "AND classification IN "
                "('requires_policy_mapping','blocking_corruption','requires_triage')"
            ).fetchone()[0]
        )
        return {
            "attempt_id": attempt_id,
            "receipt_id": receipt_id,
            "finding_id": finding_id,
            "accepted": True,
            "proof_format": PROOF_FORMAT,
            "proof_hash": proof_hash,
            "subject_before_hash": subject_hash,
            "subject_after_hash": after_hash,
            "dependency_snapshot_hash": dependency_hash,
            "postcondition": postcondition,
            "invariant_id": handler.invariant_id,
            "invariant_version": handler.invariant_version,
            "validator_id": handler.invariant_id,
            "validator_version": handler.invariant_version,
            "remaining_blockers": remaining,
            "event_id": event_id,
            "idempotent_replay": False,
        }


def _stored_dependencies(
    conn: sqlite3.Connection, receipt_id: str
) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM migration_resolution_dependencies WHERE receipt_id=? ORDER BY ordinal",
        (receipt_id,),
    ).fetchall()
    return [
        {
            **dict(row),
            "required_states": json.loads(row["required_states_json"]),
            "snapshot": json.loads(row["snapshot_json"]),
        }
        for row in rows
    ]


def replay_receipt(
    store: Store,
    receipt_id: str,
    *,
    full: bool = True,
    persist: bool = False,
    actor: str = "doctor",
) -> dict[str, Any]:
    receipt = store.row(
        "SELECT * FROM migration_finding_resolution_receipts WHERE receipt_id=?",
        (receipt_id,),
    )
    if not receipt:
        raise NotFoundError(f"Migration finding receipt not found: {receipt_id}")
    finding = store.row(
        "SELECT * FROM migration_findings WHERE finding_id=?", (receipt["finding_id"],)
    )
    attempt = store.row(
        "SELECT * FROM migration_finding_resolution_attempts WHERE attempt_id=?",
        (receipt["accepted_attempt_id"],),
    )
    findings: list[dict[str, Any]] = []
    if not finding or not attempt:
        findings.append({"code": "migration_resolution_receipt_missing"})
        return {"receipt_id": receipt_id, "valid": False, "findings": findings}
    finding["details"] = _finding_details(finding)
    try:
        resolution = json.loads(attempt["resolution_json"])
    except (json.JSONDecodeError, TypeError):
        resolution = {}
        findings.append({"code": "migration_resolution_proof_hash_mismatch"})
    resolution_hash = digest(resolution)
    if resolution_hash != attempt["resolution_hash"] or resolution_hash != receipt["resolution_hash"]:
        findings.append({"code": "migration_resolution_proof_hash_mismatch", "part": "resolution"})
    handler = handler_for(str(finding["code"]))
    if (
        not handler
        or handler.invariant_id != receipt["invariant_id"]
        or handler.invariant_version != receipt["invariant_version"]
    ):
        findings.append({"code": "migration_resolution_validator_unknown"})
    current_subject: dict[str, Any] | None = None
    if handler:
        current_subject = handler.load_subject(store.conn, finding)
        if _subject_hash(current_subject) != receipt["subject_after_hash"]:
            findings.append({"code": "migration_resolution_subject_drift"})
    stored_dependencies = _stored_dependencies(store.conn, receipt_id)
    current_dependencies: list[dict[str, Any]] = []
    for dependency in stored_dependencies:
        current = load_dependency(
            store.conn,
            str(dependency["dependency_type"]),
            str(dependency["dependency_id"]),
        )
        if not current:
            findings.append(
                {
                    "code": "migration_resolution_dependency_missing",
                    "dependency_type": dependency["dependency_type"],
                    "dependency_id": dependency["dependency_id"],
                }
            )
            continue
        current["required_states"] = dependency["required_states"]
        current_dependencies.append(current)
        if (
            current["content_hash"] != dependency["content_hash"]
            or current["snapshot_hash"] != dependency["snapshot_hash"]
        ):
            findings.append(
                {
                    "code": "migration_resolution_dependency_hash_drift",
                    "dependency_type": dependency["dependency_type"],
                    "dependency_id": dependency["dependency_id"],
                }
            )
        if current["state"] not in dependency["required_states"]:
            findings.append(
                {
                    "code": "migration_resolution_dependency_state_drift",
                    "dependency_type": dependency["dependency_type"],
                    "dependency_id": dependency["dependency_id"],
                    "state": current["state"],
                    "required_states": dependency["required_states"],
                }
            )
    if dependency_snapshot_hash(stored_dependencies) != receipt["dependency_snapshot_hash"]:
        findings.append(
            {"code": "migration_resolution_proof_hash_mismatch", "part": "dependencies"}
        )
    try:
        invariant_parameters = json.loads(receipt["invariant_parameters_json"])
        postcondition = json.loads(receipt["postcondition_json"])
    except (json.JSONDecodeError, TypeError):
        invariant_parameters = {}
        postcondition = {}
        findings.append({"code": "migration_resolution_proof_hash_mismatch", "part": "json"})
    if digest(invariant_parameters) != receipt["invariant_parameters_hash"]:
        findings.append(
            {"code": "migration_resolution_proof_hash_mismatch", "part": "invariant_parameters"}
        )
    if postcondition_hash(postcondition) != receipt["postcondition_hash"]:
        findings.append(
            {"code": "migration_resolution_proof_hash_mismatch", "part": "postcondition"}
        )
    proof = proof_payload(
        finding_id=str(finding["finding_id"]),
        finding_code=str(finding["code"]),
        subject_before_hash=str(receipt["subject_before_hash"]),
        subject_after_hash=str(receipt["subject_after_hash"]),
        resolution_hash=str(receipt["resolution_hash"]),
        invariant_id=str(receipt["invariant_id"]),
        invariant_version=int(receipt["invariant_version"]),
        invariant_parameters_hash=str(receipt["invariant_parameters_hash"]),
        dependency_hash=str(receipt["dependency_snapshot_hash"]),
        postcondition_hash=str(receipt["postcondition_hash"]),
        result_objects=postcondition.get("result_objects", []),
        actor=str(receipt["resolved_by"]),
        event_id=str(receipt["event_id"]),
    )
    if digest(proof) != receipt["proof_hash"] or receipt["proof_format"] != PROOF_FORMAT:
        findings.append({"code": "migration_resolution_proof_hash_mismatch", "part": "proof"})
    replay_postcondition: dict[str, Any] | None = None
    if full and handler and current_subject is not None and not any(
        item["code"] == "migration_resolution_dependency_missing" for item in findings
    ):
        replay_postcondition = handler.postvalidate(
            store.conn,
            finding,
            current_subject,
            resolution,
            current_dependencies,
            postcondition.get("result_objects", []),
        )
        if (
            not replay_postcondition.get("valid")
            or replay_postcondition.get("findings")
            or postcondition_hash(replay_postcondition) != receipt["postcondition_hash"]
        ):
            findings.append({"code": "migration_resolution_postcondition_failed"})
    proof_key = digest(
        {
            "proof_hash": receipt.get("proof_hash"),
            "subject_hash": _subject_hash(current_subject) if current_subject else None,
            "dependencies": dependency_snapshot_hash(current_dependencies),
        }
    )
    result: dict[str, Any] = {
        "receipt_id": receipt_id,
        "valid": not findings,
        "mode": "full" if full else "default",
        "proof_key": proof_key,
        "proof_hash": receipt.get("proof_hash"),
        "findings": findings,
        "postcondition": replay_postcondition,
        "mutation_executed": False,
    }
    result_hash = digest(result)
    result["result_hash"] = result_hash
    if persist:
        with store.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO migration_resolution_replays VALUES "
                "(?,?,?,?,?,?,?,?,?)",
                (
                    new_id("migration_replay"),
                    receipt_id,
                    proof_key,
                    "full" if full else "default",
                    canonical_json(result),
                    result_hash,
                    1 if result["valid"] else 0,
                    now(),
                    actor,
                ),
            )
    return result
