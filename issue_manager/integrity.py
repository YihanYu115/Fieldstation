from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Callable

from .errors import ConflictError, NotFoundError, ValidationError
from .registry_service import validate_json_instance
from .store import canonical_json, new_id, now
from .strict_json import json_value_errors

if TYPE_CHECKING:
    from .store import Store


QUARANTINE_SCOPES = frozenset(
    {
        "exclude_new_reports",
        "block_publication",
        "block_current_promotion",
        "block_integration_apply",
        "read_with_warning",
    }
)

_OBJECT_ALIASES = {
    "record_revisions": "record_revision",
    "record_revision": "record_revision",
    "record_instances": "record_instance",
    "record_instance": "record_instance",
    "conclusion_revisions": "conclusion_revision",
    "conclusion": "conclusion_revision",
    "conclusion_revision": "conclusion_revision",
    "field_bundles": "field_bundle",
    "field_bundle": "field_bundle",
    "field_bundle_events": "field_bundle_event",
    "field_bundle_event": "field_bundle_event",
    "field_bundle_event_actions": "field_bundle_action",
    "field_bundle_action": "field_bundle_action",
    "field_action": "field_bundle_action",
    "report_builds": "report_build",
    "report_build": "report_build",
    "artifacts": "artifact",
    "artifact": "artifact",
    "import_items": "import_item",
    "import_item": "import_item",
    "integration_conflicts": "integration_conflict",
    "integration_conflict": "integration_conflict",
}

_REQUIRED_SCOPES = {
    "record_revision": {
        "exclude_new_reports",
        "block_current_promotion",
        "read_with_warning",
    },
    "record_instance": {
        "exclude_new_reports",
        "block_current_promotion",
        "read_with_warning",
    },
    "conclusion_revision": {
        "exclude_new_reports",
        "block_publication",
        "read_with_warning",
    },
    "field_bundle": {"block_integration_apply", "read_with_warning"},
    "field_bundle_event": {"block_integration_apply", "read_with_warning"},
    "field_bundle_action": {"block_integration_apply", "read_with_warning"},
    "import_item": {"block_integration_apply", "read_with_warning"},
    "integration_conflict": {"block_integration_apply", "read_with_warning"},
    "report_build": {"exclude_new_reports", "read_with_warning"},
    "artifact": {"read_with_warning"},
}


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def normalize_object_type(object_type: str) -> str:
    return _OBJECT_ALIASES.get(object_type, object_type)


def _strict_load(raw: Any, *, path: str) -> tuple[Any, list[dict[str, Any]]]:
    try:
        value = json.loads(
            raw,
            parse_constant=lambda constant: (_ for _ in ()).throw(ValueError(constant)),
        )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        return None, [{"path": path, "code": "invalid_json", "message": type(exc).__name__}]
    return value, json_value_errors(value, path=path)


def _row(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
    found = conn.execute(sql, params).fetchone()
    return dict(found) if found else None


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [dict(item) for item in conn.execute(sql, params).fetchall()]


def object_snapshot(
    conn: sqlite3.Connection, object_type: str, object_id: str
) -> dict[str, Any]:
    kind = normalize_object_type(object_type)
    if kind == "record_revision":
        revision = _row(
            conn,
            "SELECT * FROM record_revisions WHERE record_revision_id=?",
            (object_id,),
        )
        if not revision:
            return {"object_type": kind, "object_id": object_id, "load_error": "subject_missing"}
        instance = _row(
            conn,
            "SELECT * FROM record_instances WHERE record_instance_id=?",
            (revision["record_instance_id"],),
        )
        links = _rows(
            conn,
            "SELECT * FROM record_evidence_links WHERE record_revision_id=? "
            "ORDER BY field_path,evidence_id,relation_role",
            (object_id,),
        )
        return {"object_type": kind, "revision": revision, "instance": instance, "links": links}
    if kind == "record_instance":
        instance = _row(
            conn,
            "SELECT * FROM record_instances WHERE record_instance_id=?",
            (object_id,),
        )
        if not instance:
            return {"object_type": kind, "object_id": object_id, "load_error": "subject_missing"}
        revision_id = str(instance.get("current_revision_id") or "")
        current = object_snapshot(conn, "record_revision", revision_id) if revision_id else None
        return {"object_type": kind, "instance": instance, "current": current}
    if kind == "conclusion_revision":
        conclusion = _row(
            conn,
            "SELECT * FROM conclusion_revisions WHERE conclusion_id=?",
            (object_id,),
        )
        if not conclusion:
            return {"object_type": kind, "object_id": object_id, "load_error": "subject_missing"}
        issue = _row(conn, "SELECT * FROM issues WHERE issue_id=?", (conclusion["issue_id"],))
        basis = _rows(
            conn,
            "SELECT * FROM conclusion_basis WHERE conclusion_id=? ORDER BY provider_issue_id",
            (object_id,),
        )
        evidence = _rows(
            conn,
            "SELECT * FROM conclusion_evidence_uses WHERE conclusion_id=? "
            "ORDER BY evidence_id,use_role",
            (object_id,),
        )
        return {
            "object_type": kind,
            "conclusion": conclusion,
            "issue": issue,
            "basis": basis,
            "evidence": evidence,
        }
    table_keys = {
        "field_bundle": ("field_bundles", "field_bundle_id"),
        "field_bundle_event": ("field_bundle_events", "field_bundle_event_id"),
        "field_bundle_action": (
            "field_bundle_event_actions",
            "field_bundle_event_action_id",
        ),
        "report_build": ("report_builds", "report_build_id"),
        "artifact": ("artifacts", "artifact_id"),
        "import_item": ("import_items", "import_item_id"),
        "integration_conflict": ("integration_conflicts", "integration_conflict_id"),
    }
    table_key = table_keys.get(kind)
    if not table_key:
        return {
            "object_type": kind,
            "object_id": object_id,
            "load_error": "object_integrity_validator_unknown",
        }
    table, key = table_key
    item = _row(conn, f"SELECT * FROM {table} WHERE {key}=?", (object_id,))
    if not item:
        return {"object_type": kind, "object_id": object_id, "load_error": "subject_missing"}
    result: dict[str, Any] = {"object_type": kind, "row": item}
    if kind == "field_bundle":
        result["events"] = _rows(
            conn,
            "SELECT event_index,event_hash FROM field_bundle_events "
            "WHERE field_bundle_id=? ORDER BY event_index",
            (object_id,),
        )
        result["attachments"] = _rows(
            conn,
            "SELECT attachment_path,expected_sha256,expected_size,mime_type "
            "FROM field_bundle_attachments WHERE field_bundle_id=? ORDER BY attachment_path",
            (object_id,),
        )
    if kind == "report_build":
        result["inputs"] = _rows(
            conn,
            "SELECT * FROM report_build_inputs WHERE report_build_id=? ORDER BY input_order",
            (object_id,),
        )
        artifact_id = item.get("output_artifact_id")
        result["artifact"] = (
            _row(conn, "SELECT * FROM artifacts WHERE artifact_id=?", (artifact_id,))
            if artifact_id
            else None
        )
    return result


def object_hash(conn: sqlite3.Connection, object_type: str, object_id: str) -> str:
    return digest(object_snapshot(conn, object_type, object_id))


def _field_value(data: dict[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _template_fields(definition: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = definition.get("fields", {})
    if isinstance(raw, dict):
        return {
            str(path): dict(spec)
            for path, spec in raw.items()
            if isinstance(path, str) and isinstance(spec, dict)
        }
    if isinstance(raw, list):
        return {
            str(item["path"]): {key: value for key, value in item.items() if key != "path"}
            for item in raw
            if isinstance(item, dict) and isinstance(item.get("path"), str)
        }
    return {}


def _datetime_valid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _field_errors(value: Any, spec: dict[str, Any], path: str) -> list[dict[str, Any]]:
    code = "record_field_invalid"

    def finding(message: str) -> dict[str, Any]:
        return {"code": code, "path": path, "message": message}

    field_type = str(spec.get("type", ""))
    if value is None:
        return [] if spec.get("nullable", False) else [finding("value cannot be null")]
    invalid = False
    if field_type == "string":
        invalid = not isinstance(value, str)
    elif field_type == "integer":
        invalid = isinstance(value, bool) or not isinstance(value, int)
    elif field_type == "number":
        invalid = (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        )
    elif field_type == "boolean":
        invalid = not isinstance(value, bool)
    elif field_type == "enum":
        invalid = value not in spec.get("enum", spec.get("values", []))
    elif field_type == "datetime":
        invalid = not _datetime_valid(value)
    elif field_type == "duration":
        invalid = not (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
            and value >= 0
        ) and not (isinstance(value, str) and re.fullmatch(r"P(?:\d+D)?(?:T.*)?", value))
    elif field_type in {"quantity", "uncertain_quantity"}:
        if not isinstance(value, dict):
            return [finding("quantity must be an object")]
        number = value.get("value")
        unit = value.get("unit")
        findings: list[dict[str, Any]] = []
        if (
            isinstance(number, bool)
            or not isinstance(number, (int, float))
            or not math.isfinite(float(number))
        ):
            findings.append(finding("quantity value must be finite"))
        units = spec.get("allowed_units", spec.get("units", []))
        if not isinstance(unit, str) or not unit or (units and unit not in units):
            findings.append(finding("quantity unit is invalid"))
        uncertainty = value.get("uncertainty")
        if field_type == "uncertain_quantity" and uncertainty is not None and (
            isinstance(uncertainty, bool)
            or not isinstance(uncertainty, (int, float))
            or not math.isfinite(float(uncertainty))
            or uncertainty < 0
        ):
            findings.append(finding("quantity uncertainty is invalid"))
        for time_key in ("observed_at", "valid_from", "valid_until"):
            if value.get(time_key) is not None and not _datetime_valid(value[time_key]):
                findings.append(finding(f"{time_key} must be timezone-aware ISO-8601"))
        return findings
    elif field_type == "object":
        invalid = not isinstance(value, dict)
    elif field_type == "array":
        invalid = not isinstance(value, list)
    elif field_type in {"evidence_ref", "artifact_ref", "record_ref", "issue_ref"}:
        invalid = not isinstance(value, str) or not value
    else:
        invalid = True
    return [finding(f"value does not satisfy {field_type or 'declared'} type")] if invalid else []


def _record_findings(conn: sqlite3.Connection, subject: dict[str, Any]) -> list[dict[str, Any]]:
    if subject.get("load_error"):
        return [{"code": str(subject["load_error"])}]
    revision = subject["revision"]
    instance = subject.get("instance")
    findings: list[dict[str, Any]] = []
    data, data_errors = _strict_load(revision.get("data_json"), path="$.record.data")
    template, template_errors = _strict_load(
        revision.get("template_snapshot_json"), path="$.record.template"
    )
    validation, validation_errors = _strict_load(
        revision.get("validation_result_json"), path="$.record.validation"
    )
    findings.extend({**item, "code": "record_json_invalid"} for item in data_errors)
    findings.extend({**item, "code": "record_template_snapshot_invalid"} for item in template_errors)
    findings.extend({**item, "code": "record_validation_snapshot_invalid"} for item in validation_errors)
    if findings or not isinstance(data, dict) or not isinstance(template, dict):
        return findings or [{"code": "record_object_shape_invalid"}]
    if not instance or instance.get("record_instance_id") != revision.get("record_instance_id"):
        findings.append({"code": "record_instance_ownership_invalid"})
    if template.get("content_hash") != revision.get("template_content_hash"):
        findings.append({"code": "record_template_hash_mismatch"})
    definition = template.get("definition", {})
    if not isinstance(definition, dict):
        findings.append({"code": "record_template_definition_invalid"})
        return findings
    fields = _template_fields(definition)
    profile = str(revision.get("validation_profile", "draft"))
    profile_spec = definition.get("profiles", {}).get(profile, {})
    if not isinstance(profile_spec, dict):
        findings.append({"code": "record_validation_profile_invalid", "profile": profile})
        profile_spec = {}
    required = set(profile_spec.get("required", []))
    if profile != "draft":
        required.update(path for path, spec in fields.items() if spec.get("required"))
    for path, spec in fields.items():
        present, value = _field_value(data, path)
        if not present:
            if path in required:
                findings.append({"code": "record_required_field_missing", "path": path})
            continue
        findings.extend(_field_errors(value, spec, path))
    if definition.get("additional_fields") is False:
        known = {path.split(".", 1)[0] for path in fields}
        for key in sorted(set(data) - known):
            findings.append({"code": "record_additional_field_forbidden", "path": key})
    links = subject.get("links", [])
    link_paths = {str(link.get("field_path", "")) for link in links}
    evidence_required = set(profile_spec.get("evidence_required", []))
    evidence_required.update(
        path
        for path, spec in fields.items()
        if spec.get("evidence_required") and profile in {"accepted", "canonical", "report"}
    )
    for path in sorted(evidence_required - link_paths):
        findings.append({"code": "record_evidence_required", "path": path})
    for link in links:
        evidence = _row(
            conn,
            "SELECT evidence_id,lifecycle_status,semantic_revision FROM evidence_refs "
            "WHERE evidence_id=?",
            (link.get("evidence_id"),),
        )
        if not evidence or evidence.get("lifecycle_status") != "active":
            findings.append(
                {"code": "record_evidence_link_invalid", "evidence_id": link.get("evidence_id")}
            )
            continue
        proof_id = link.get("proof_id")
        if proof_id:
            proof = _row(
                conn,
                "SELECT evidence_id,proof_hash,semantic_revision,verification_state "
                "FROM evidence_proofs WHERE proof_id=?",
                (proof_id,),
            )
            if (
                not proof
                or proof.get("evidence_id") != link.get("evidence_id")
                or proof.get("proof_hash") != link.get("proof_hash")
                or proof.get("verification_state") != "active"
                or int(proof.get("semantic_revision", -1))
                != int(link.get("evidence_semantic_revision", -2))
            ):
                findings.append({"code": "record_evidence_proof_invalid", "proof_id": proof_id})
    normalized_links = validation.get("normalized_evidence_links", []) if isinstance(validation, dict) else []
    expected_content_hash = digest(
        {
            "template_content_hash": revision.get("template_content_hash"),
            "data": data,
            "source_mode": revision.get("source_mode"),
            "source_object_mapping_id": revision.get("source_object_mapping_id"),
            "normalized_evidence_links": normalized_links,
        }
    )
    if expected_content_hash != revision.get("content_hash"):
        findings.append({"code": "record_revision_content_hash_mismatch"})
    if instance and instance.get("current_revision_id") == revision.get("record_revision_id"):
        latest = _row(
            conn,
            "SELECT record_revision_id,revision_number FROM record_revisions "
            "WHERE record_instance_id=? ORDER BY revision_number DESC LIMIT 1",
            (revision.get("record_instance_id"),),
        )
        if not latest or latest.get("record_revision_id") != revision.get("record_revision_id"):
            findings.append({"code": "record_current_pointer_invalid"})
    return findings


def _conclusion_findings(
    conn: sqlite3.Connection, subject: dict[str, Any]
) -> list[dict[str, Any]]:
    if subject.get("load_error"):
        return [{"code": str(subject["load_error"])}]
    conclusion = subject["conclusion"]
    issue = subject.get("issue")
    findings: list[dict[str, Any]] = []
    outputs, output_errors = _strict_load(
        conclusion.get("structured_outputs_json"), path="$.conclusion.structured_outputs"
    )
    limitations, limitation_errors = _strict_load(
        conclusion.get("limitations_json"), path="$.conclusion.limitations"
    )
    evidence_refs, evidence_ref_errors = _strict_load(
        conclusion.get("evidence_refs_json"), path="$.conclusion.evidence_refs"
    )
    semantics, semantic_errors = _strict_load(
        conclusion.get("issue_type_semantic_snapshot_json"), path="$.conclusion.issue_type"
    )
    findings.extend({**item, "code": "conclusion_json_invalid"} for item in output_errors)
    findings.extend({**item, "code": "conclusion_json_invalid"} for item in limitation_errors)
    findings.extend({**item, "code": "conclusion_json_invalid"} for item in evidence_ref_errors)
    findings.extend({**item, "code": "conclusion_semantic_snapshot_invalid"} for item in semantic_errors)
    if not isinstance(outputs, dict):
        findings.append({"code": "conclusion_structured_outputs_not_object"})
    if not isinstance(limitations, list):
        findings.append({"code": "conclusion_limitations_not_array"})
    if not isinstance(evidence_refs, list) or any(
        not isinstance(item, str) for item in evidence_refs
    ):
        findings.append({"code": "conclusion_evidence_refs_invalid"})
    if not isinstance(semantics, dict):
        findings.append({"code": "conclusion_semantic_snapshot_invalid"})
    profile: dict[str, Any] | None = None
    if isinstance(semantics, dict):
        if digest(semantics) != conclusion.get("issue_type_semantic_hash"):
            findings.append({"code": "conclusion_semantic_hash_mismatch"})
        definition = semantics.get("definition")
        conclusion_semantics = (
            definition.get("conclusion") if isinstance(definition, dict) else None
        )
        if not isinstance(conclusion_semantics, dict):
            findings.append({"code": "conclusion_semantic_snapshot_invalid"})
        binding = conn.execute(
            "SELECT issue_id,revision,schema_json,schema_hash FROM conclusion_rule_bindings WHERE conclusion_id=?",
            (conclusion["conclusion_id"],),
        ).fetchone()
        schema = None
        if binding is None:
            findings.append({"code": "conclusion_rule_binding_missing"})
        else:
            try:
                schema = json.loads(binding[2])
                if binding[0] != conclusion["issue_id"] or digest(schema) != binding[3]:
                    findings.append({"code": "conclusion_rule_binding_incoherent"})
                if binding[1] > 0:
                    original = conn.execute(
                        "SELECT schema_hash FROM issue_conclusion_rule_versions WHERE issue_id=? AND revision=?",
                        (binding[0], binding[1]),
                    ).fetchone()
                    if original is None or original[0] != binding[3]:
                        findings.append({"code": "conclusion_rule_binding_incoherent"})
                elif isinstance(conclusion_semantics, dict) and schema != conclusion_semantics.get("structured_outputs_schema"):
                    findings.append({"code": "conclusion_rule_binding_incoherent"})
            except (ValueError, TypeError):
                findings.append({"code": "conclusion_rule_binding_incoherent"})
        if not isinstance(schema, dict):
            findings.append({"code": "conclusion_semantic_snapshot_invalid"})
        elif isinstance(outputs, dict):
            findings.extend(
                {**item, "code": "conclusion_output_schema_invalid"}
                for item in validate_json_instance(outputs, schema, path="$.structured_outputs")
            )
        profiles = (
            conclusion_semantics.get("publication_profiles")
            if isinstance(conclusion_semantics, dict)
            else None
        )
        status = str(conclusion.get("status", ""))
        if isinstance(profiles, dict):
            candidate = profiles.get(status)
            if candidate is None and status in {"disputed", "superseded", "retracted"}:
                candidate = {
                    "min_active_evidence": 0,
                    "minimum_verification_level": "declared",
                    "review_quorum": 0,
                }
            if isinstance(candidate, dict):
                profile = candidate
            else:
                findings.append({"code": "conclusion_publication_profile_invalid"})
        else:
            findings.append({"code": "conclusion_publication_profile_invalid"})
    if not issue or issue.get("issue_id") != conclusion.get("issue_id"):
        findings.append({"code": "conclusion_issue_ownership_invalid"})
    elif (
        issue.get("issue_type_registration_id") != conclusion.get("issue_type_registration_id")
        or issue.get("issue_type_semantic_hash") != conclusion.get("issue_type_semantic_hash")
    ):
        findings.append({"code": "conclusion_issue_semantic_binding_invalid"})
    if issue and issue.get("current_conclusion_id") == conclusion.get("conclusion_id"):
        latest = _row(
            conn,
            "SELECT conclusion_id FROM conclusion_revisions WHERE issue_id=? "
            "ORDER BY revision_number DESC LIMIT 1",
            (conclusion.get("issue_id"),),
        )
        if not latest or latest.get("conclusion_id") != conclusion.get("conclusion_id"):
            findings.append({"code": "conclusion_current_pointer_invalid"})
    valid_uses: list[dict[str, Any]] = []
    for use in subject.get("evidence", []):
        evidence_id = use.get("evidence_id")
        proof_id = use.get("proof_id")
        evidence = _row(
            conn,
            "SELECT lifecycle_status,current_proof_id,semantic_revision,verification_level,"
            "verification_state,quality_status,kind,locator FROM evidence_refs WHERE evidence_id=?",
            (evidence_id,),
        )
        proof = (
            _row(
                conn,
                "SELECT evidence_id,proof_hash,semantic_revision,manifest_id,manifest_hash,"
                "verification_level,verification_state FROM evidence_proofs WHERE proof_id=?",
                (proof_id,),
            )
            if proof_id
            else None
        )
        reasons: list[str] = []
        if not evidence or evidence.get("lifecycle_status") != "active":
            reasons.append("evidence_inactive")
        if not proof_id or not proof:
            reasons.append("proof_missing")
        elif (
            proof.get("evidence_id") != evidence_id
            or proof.get("proof_hash") != use.get("proof_hash")
            or proof.get("verification_state") != "active"
            or proof.get("verification_level") != use.get("verification_level_snapshot")
            or proof.get("verification_state") != use.get("verification_state_snapshot")
            or proof.get("semantic_revision") != use.get("evidence_semantic_revision")
            or proof.get("manifest_id") != use.get("manifest_id")
            or proof.get("manifest_hash") != use.get("manifest_hash")
        ):
            reasons.append("proof_snapshot_mismatch")
        if evidence and proof and (
            evidence.get("current_proof_id") != proof_id
            or evidence.get("semantic_revision") != proof.get("semantic_revision")
            or evidence.get("verification_level") != proof.get("verification_level")
            or evidence.get("verification_state") != proof.get("verification_state")
        ):
            reasons.append("proof_pointer_incoherent")
        if reasons:
            findings.append(
                {
                    "code": "conclusion_evidence_proof_invalid",
                    "evidence_id": evidence_id,
                    "proof_id": proof_id,
                    "reasons": reasons,
                }
            )
        else:
            valid_uses.append({**use, "evidence": evidence, "proof": proof})
    if isinstance(evidence_refs, list) and all(
        isinstance(item, str) for item in evidence_refs
    ):
        valid_ids = {str(item["evidence_id"]) for item in valid_uses}
        if any(str(evidence_id) not in valid_ids for evidence_id in set(evidence_refs)):
            findings.append({"code": "conclusion_evidence_reference_invalid"})
    if profile is not None:
        findings.extend(
            _conclusion_publication_profile_findings(
                conn,
                conclusion=conclusion,
                outputs=outputs if isinstance(outputs, dict) else {},
                evidence_refs=evidence_refs if isinstance(evidence_refs, list) else [],
                valid_uses=valid_uses,
                profile=profile,
            )
        )
    return findings


_VERIFICATION_LEVEL_RANK = {
    "declared": 0,
    "source_verified": 1,
    "snapshot_verified": 2,
    "reproduced": 3,
}


def _conclusion_publication_profile_findings(
    conn: sqlite3.Connection,
    *,
    conclusion: dict[str, Any],
    outputs: dict[str, Any],
    evidence_refs: list[Any],
    valid_uses: list[dict[str, Any]],
    profile: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    minimum_evidence = profile.get("min_active_evidence", 0)
    review_quorum = profile.get("review_quorum", 0)
    minimum_level = profile.get("minimum_verification_level", "declared")
    if (
        isinstance(minimum_evidence, bool)
        or not isinstance(minimum_evidence, int)
        or minimum_evidence < 0
        or isinstance(review_quorum, bool)
        or not isinstance(review_quorum, int)
        or review_quorum < 0
        or not isinstance(minimum_level, str)
        or minimum_level not in _VERIFICATION_LEVEL_RANK
    ):
        return [{"code": "conclusion_publication_profile_invalid"}]

    active_ids = {str(item["evidence_id"]) for item in valid_uses}
    if len(active_ids) < minimum_evidence:
        findings.append(
            {
                "code": "conclusion_evidence_quorum_unsatisfied",
                "required": minimum_evidence,
                "actual": len(active_ids),
            }
        )
    eligible_support = [
        item
        for item in valid_uses
        if item.get("use_role") == "support"
        and item.get("fitness") == "fit_for_use"
        and item.get("quality_snapshot") != "invalid"
        and _VERIFICATION_LEVEL_RANK.get(str(item.get("verification_level_snapshot")), -1)
        >= _VERIFICATION_LEVEL_RANK[str(minimum_level)]
    ]
    if profile.get("reject_conflict_as_only_support"):
        eligible_support = [
            item
            for item in eligible_support
            if item.get("verification_state_snapshot") != "conflict"
        ]
    if (minimum_evidence > 0 or profile.get("require_support_fit_for_use")) and not eligible_support:
        findings.append(
            {
                "code": "conclusion_evidence_verification_unsatisfied",
                "minimum_verification_level": minimum_level,
            }
        )
    elif eligible_support and all(
        item.get("quality_snapshot") == "questionable" for item in eligible_support
    ):
        findings.append({"code": "conclusion_evidence_quality_unsatisfied"})

    if review_quorum:
        proposal = _row(
            conn,
            "SELECT proposal_hash FROM proposals WHERE proposal_id=? AND applied_conclusion_id=?",
            (conclusion.get("proposal_id"), conclusion.get("conclusion_id")),
        )
        passing = 0
        if proposal:
            passing = int(
                conn.execute(
                    "SELECT COUNT(DISTINCT reviewer_actor_id) FROM review_decisions "
                    "WHERE proposal_id=? AND decision='pass' AND proposal_hash=?",
                    (conclusion.get("proposal_id"), proposal["proposal_hash"]),
                ).fetchone()[0]
            )
        if passing < review_quorum:
            findings.append(
                {
                    "code": "conclusion_review_quorum_unsatisfied",
                    "required": review_quorum,
                    "actual": passing,
                }
            )

    raw_artifact_ids = outputs.get("artifact_ids", [])
    artifact_ids = (
        {str(item) for item in raw_artifact_ids} if isinstance(raw_artifact_ids, list) else set()
    )
    for evidence_id in set(str(item) for item in evidence_refs):
        evidence = _row(
            conn,
            "SELECT kind,locator FROM evidence_refs WHERE evidence_id=?",
            (evidence_id,),
        )
        if evidence and evidence.get("kind") == "artifact":
            artifact = _row(
                conn,
                "SELECT artifact_id FROM artifacts WHERE artifact_id=? OR storage_uri=?",
                (evidence.get("locator"), evidence.get("locator")),
            )
            if artifact:
                artifact_ids.add(str(artifact["artifact_id"]))
    frozen_artifacts = {
        artifact_id
        for artifact_id in artifact_ids
        if _row(
            conn,
            "SELECT artifact_id FROM artifacts WHERE artifact_id=? AND role='frozen'",
            (artifact_id,),
        )
    }
    waiver_id = outputs.get("waiver_id")
    waiver = (
        _row(
            conn,
            "SELECT waiver_id FROM publication_waivers WHERE waiver_id=? AND issue_id=?",
            (waiver_id, conclusion.get("issue_id")),
        )
        if waiver_id
        else None
    )
    if profile.get("require_frozen_artifact") and not frozen_artifacts:
        findings.append({"code": "conclusion_frozen_artifact_required"})
    requires_analysis = bool(profile.get("derived_result_requires_frozen_analysis")) and bool(
        outputs.get("derived_result") or artifact_ids
    )
    if profile.get("require_analysis_run_or_waiver"):
        requires_analysis = True
    frozen_run = None
    if frozen_artifacts:
        placeholders = ",".join("?" for _ in frozen_artifacts)
        frozen_run = conn.execute(
            f"SELECT ar.analysis_run_id FROM analysis_runs ar JOIN analysis_outputs ao "
            f"ON ao.analysis_run_id=ar.analysis_run_id WHERE ar.state='frozen' "
            f"AND ao.artifact_id IN ({placeholders}) LIMIT 1",
            tuple(sorted(frozen_artifacts)),
        ).fetchone()
    if requires_analysis and not frozen_run and not waiver:
        findings.append({"code": "conclusion_analysis_run_or_waiver_required"})
    if (
        outputs.get("derived_result")
        and not waiver
        and not any(item.get("verification_level_snapshot") == "reproduced" for item in eligible_support)
    ):
        findings.append({"code": "conclusion_reproduced_support_required"})
    return findings


def _field_findings(subject: dict[str, Any]) -> list[dict[str, Any]]:
    if subject.get("load_error"):
        return [{"code": str(subject["load_error"])}]
    kind = subject["object_type"]
    row = subject["row"]
    pairs = {
        "field_bundle": (),
        "field_bundle_event": (("event_json", "event_hash"),),
        "field_bundle_action": (("action_json", "action_hash"),),
    }[kind]
    findings: list[dict[str, Any]] = []
    if kind == "field_bundle":
        manifest, errors = _strict_load(
            row.get("manifest_json"), path="$.field_bundle.manifest_json"
        )
        findings.extend({**item, "code": "field_json_invalid"} for item in errors)
        if not errors and isinstance(manifest, dict):
            canonical_manifest = dict(manifest)
            canonical_manifest.pop("content_hash", None)
            expected = digest(
                {
                    "manifest": canonical_manifest,
                    "event_hashes": [item["event_hash"] for item in subject.get("events", [])],
                    "attachments": [
                        {
                            "path": item["attachment_path"],
                            "sha256": item["expected_sha256"],
                            "size": item["expected_size"],
                            "mime_type": item["mime_type"],
                        }
                        for item in subject.get("attachments", [])
                    ],
                }
            )
            if expected != row.get("content_hash"):
                findings.append(
                    {"code": "field_identity_hash_mismatch", "column": "content_hash"}
                )
    for column, hash_column in pairs:
        value, errors = _strict_load(row.get(column), path=f"$.{kind}.{column}")
        findings.extend({**item, "code": "field_json_invalid"} for item in errors)
        if not errors and digest(value) != row.get(hash_column):
            findings.append({"code": "field_identity_hash_mismatch", "column": column})
    if kind == "field_bundle_action":
        action, errors = _strict_load(row.get("action_json"), path="$.field_action")
        if not errors and isinstance(action, dict):
            if row.get("target_record_instance_id") != action.get("record_instance_id"):
                findings.append({"code": "field_action_target_mismatch"})
            if row.get("base_record_revision_id") != action.get("base_record_revision_id"):
                findings.append({"code": "field_action_base_mismatch"})
    return findings


def _report_findings(subject: dict[str, Any]) -> list[dict[str, Any]]:
    if subject.get("load_error"):
        return [{"code": str(subject["load_error"])}]
    build = subject["row"]
    findings: list[dict[str, Any]] = []
    parsed: dict[str, Any] = {}
    for column in (
        "scope_json",
        "normalized_scope_json",
        "query_json",
        "report_model_json",
        "report_template_snapshot_json",
        "renderer_snapshot_json",
        "renderer_config_json",
        "render_receipt_json",
    ):
        parsed[column], errors = _strict_load(build.get(column), path=f"$.report.{column}")
        findings.extend({**item, "code": "report_json_invalid"} for item in errors)
    checks = {
        "normalized_scope_hash": parsed.get("normalized_scope_json"),
        "report_model_hash": parsed.get("report_model_json"),
        "renderer_config_hash": parsed.get("renderer_config_json"),
    }
    for column, value in checks.items():
        if value is not None and digest(value) != build.get(column):
            findings.append({"code": "report_identity_hash_mismatch", "column": column})
    inputs = subject.get("inputs", [])
    basis_payload = {
        "template_registration_id": build.get("report_template_registration_id"),
        "template_content_hash": build.get("report_template_content_hash"),
        "renderer_hash": build.get("renderer_hash"),
        "renderer_snapshot": parsed.get("renderer_snapshot_json"),
        "renderer_config_hash": build.get("renderer_config_hash"),
        "normalized_scope": parsed.get("normalized_scope_json"),
        "normalized_scope_hash": build.get("normalized_scope_hash"),
        "query": parsed.get("query_json"),
        "query_hash": digest(parsed.get("query_json")),
        "inputs": sorted(
            (
                {
                    key: item[key]
                    for key in ("object_type", "object_id", "content_hash", "role")
                }
                for item in inputs
            ),
            key=lambda item: (item["object_type"], item["object_id"], item["role"]),
        ),
        "report_model_hash": build.get("report_model_hash"),
    }
    if digest(basis_payload) != build.get("basis_hash"):
        findings.append({"code": "report_basis_hash_mismatch"})
    artifact = subject.get("artifact")
    if build.get("state") in {"built", "published"}:
        if not artifact or artifact.get("sha256") != build.get("output_hash"):
            findings.append({"code": "report_output_artifact_mismatch"})
        receipt = parsed.get("render_receipt_json")
        if not isinstance(receipt, dict) or not receipt:
            findings.append({"code": "report_render_receipt_missing"})
    return findings


@dataclass(frozen=True)
class ObjectIntegrityValidator:
    object_type: str
    supported_columns: frozenset[str]
    invariant_id: str
    invariant_version: int
    validate_subject: Callable[[sqlite3.Connection, dict[str, Any]], list[dict[str, Any]]]


_VALIDATORS = {
    "record_revision": ObjectIntegrityValidator(
        "record_revision",
        frozenset({"data_json", "validation_result_json"}),
        "record-revision-integrity",
        2,
        _record_findings,
    ),
    "conclusion_revision": ObjectIntegrityValidator(
        "conclusion_revision",
        frozenset({"structured_outputs_json", "limitations_json"}),
        "conclusion-revision-integrity",
        2,
        _conclusion_findings,
    ),
    "field_bundle": ObjectIntegrityValidator(
        "field_bundle",
        frozenset({"manifest_json", "last_error_json"}),
        "field-bundle-integrity",
        2,
        lambda _conn, subject: _field_findings(subject),
    ),
    "field_bundle_event": ObjectIntegrityValidator(
        "field_bundle_event",
        frozenset({"event_json", "result_json"}),
        "field-bundle-event-integrity",
        2,
        lambda _conn, subject: _field_findings(subject),
    ),
    "field_bundle_action": ObjectIntegrityValidator(
        "field_bundle_action",
        frozenset({"action_json", "result_json"}),
        "field-action-integrity",
        2,
        lambda _conn, subject: _field_findings(subject),
    ),
    "report_build": ObjectIntegrityValidator(
        "report_build",
        frozenset(
            {
                "scope_json",
                "normalized_scope_json",
                "query_json",
                "report_model_json",
                "renderer_config_json",
            }
        ),
        "report-build-integrity",
        2,
        lambda _conn, subject: _report_findings(subject),
    ),
}


def validator_for(object_type: str, column: str | None = None) -> ObjectIntegrityValidator | None:
    validator = _VALIDATORS.get(normalize_object_type(object_type))
    if validator and column and column not in validator.supported_columns:
        return None
    return validator


def validate_object_integrity(
    conn: sqlite3.Connection,
    object_type: str,
    object_id: str,
    *,
    column: str | None = None,
) -> dict[str, Any]:
    kind = normalize_object_type(object_type)
    validator = validator_for(kind, column)
    subject = object_snapshot(conn, kind, object_id)
    subject_hash = digest(subject)
    if not validator:
        unknown_findings = [
            {
                "code": "object_integrity_validator_unknown",
                "object_type": kind,
                "column": column,
            }
        ]
        return {
            "valid": False,
            "invariant_id": "object-integrity-validator-unknown",
            "invariant_version": 1,
            "subject_before_hash": subject_hash,
            "subject_after_hash": subject_hash,
            "findings": unknown_findings,
            "result_objects": [],
            "postcondition_hash": digest(unknown_findings),
        }
    findings: list[dict[str, Any]] = []
    if column and not subject.get("load_error"):
        container_key = {
            "record_revision": "revision",
            "conclusion_revision": "conclusion",
            "report_build": "row",
        }.get(kind, "row")
        container = subject.get(container_key)
        if isinstance(container, dict) and column in container:
            _value, column_errors = _strict_load(
                container.get(column), path=f"$.{kind}.{column}"
            )
            findings.extend(column_errors)
    findings.extend(validator.validate_subject(conn, subject))
    result_objects = [
        {"object_type": kind, "object_id": object_id, "content_hash": subject_hash}
    ]
    result = {
        "valid": not findings,
        "invariant_id": validator.invariant_id,
        "invariant_version": validator.invariant_version,
        "subject_before_hash": subject_hash,
        "subject_after_hash": subject_hash,
        "findings": findings,
        "result_objects": result_objects,
    }
    result["postcondition_hash"] = digest(result)
    return result


def _dependency(
    dependency_type: str,
    dependency_id: str,
    snapshot: dict[str, Any],
    *,
    content_hash: str | None = None,
    state: str = "frozen",
    required_states: list[str] | None = None,
) -> dict[str, Any]:
    snapshot_hash = digest(snapshot)
    return {
        "dependency_type": dependency_type,
        "dependency_id": dependency_id,
        "content_hash": content_hash or snapshot_hash,
        "state": state,
        "required_states": sorted(required_states or [state]),
        "snapshot": snapshot,
        "snapshot_hash": snapshot_hash,
    }


def object_dependencies(
    conn: sqlite3.Connection, object_type: str, object_id: str
) -> list[dict[str, Any]]:
    kind = normalize_object_type(object_type)
    snapshot = object_snapshot(conn, kind, object_id)
    dependencies: list[dict[str, Any]] = []
    if kind == "record_revision" and not snapshot.get("load_error"):
        revision = snapshot["revision"]
        template, errors = _strict_load(
            revision.get("template_snapshot_json"), path="$.record.template"
        )
        if not errors and isinstance(template, dict):
            dependencies.append(
                _dependency(
                    "record_template_snapshot",
                    object_id,
                    template,
                    content_hash=str(revision.get("template_content_hash", "")),
                )
            )
    elif kind == "conclusion_revision" and not snapshot.get("load_error"):
        conclusion = snapshot["conclusion"]
        semantics, errors = _strict_load(
            conclusion.get("issue_type_semantic_snapshot_json"),
            path="$.conclusion.issue_type",
        )
        if not errors and isinstance(semantics, dict):
            dependencies.append(
                _dependency(
                    "issue_type_semantic_snapshot",
                    object_id,
                    semantics,
                    content_hash=str(conclusion.get("issue_type_semantic_hash", "")),
                )
            )
    elif kind == "report_build" and not snapshot.get("load_error"):
        build = snapshot["row"]
        registration_id = build.get("report_template_registration_id")
        registration = (
            _row(
                conn,
                "SELECT registration_id,bundle_id,kind,content_hash,state FROM registry_entries "
                "WHERE registration_id=?",
                (registration_id,),
            )
            if registration_id
            else None
        )
        if registration:
            dependencies.append(
                _dependency(
                    "registry_registration",
                    str(registration_id),
                    registration,
                    content_hash=str(registration["content_hash"]),
                    state=str(registration["state"]),
                    required_states=["active", "deprecated"],
                )
            )
        artifact = snapshot.get("artifact")
        if artifact:
            dependencies.append(
                _dependency(
                    "artifact",
                    str(artifact["artifact_id"]),
                    artifact,
                    content_hash=str(artifact["sha256"]),
                    state=str(artifact.get("state", artifact.get("lifecycle_status", "stored"))),
                    required_states=[
                        str(artifact.get("state", artifact.get("lifecycle_status", "stored")))
                    ],
                )
            )
    return sorted(
        dependencies,
        key=lambda item: (item["dependency_type"], item["dependency_id"]),
    )


def load_dependency(
    conn: sqlite3.Connection, dependency_type: str, dependency_id: str
) -> dict[str, Any] | None:
    if dependency_type == "extension_bundle":
        snapshot = _row(
            conn,
            "SELECT bundle_id,namespace,name,version,content_hash,state FROM extension_bundles "
            "WHERE bundle_id=?",
            (dependency_id,),
        )
        return (
            _dependency(
                dependency_type,
                dependency_id,
                snapshot,
                content_hash=str(snapshot["content_hash"]),
                state=str(snapshot["state"]),
                required_states=["active"],
            )
            if snapshot
            else None
        )
    if dependency_type == "registry_registration":
        snapshot = _row(
            conn,
            "SELECT registration_id,bundle_id,namespace,kind,name,version,content_hash,state "
            "FROM registry_entries WHERE registration_id=?",
            (dependency_id,),
        )
        return (
            _dependency(
                dependency_type,
                dependency_id,
                snapshot,
                content_hash=str(snapshot["content_hash"]),
                state=str(snapshot["state"]),
                required_states=["active", "deprecated"],
            )
            if snapshot
            else None
        )
    if dependency_type == "policy_repair_candidate":
        snapshot = _row(
            conn,
            "SELECT repair_id,finding_id,source_bundle_hash,source_policy_hash,"
            "finding_fingerprint_hash,prepared_bundle_hash,reference_locks_hash,"
            "issue_binding_map_hash,plan_hash,state FROM migration_policy_repairs WHERE repair_id=?",
            (dependency_id,),
        )
        return (
            _dependency(
                dependency_type,
                dependency_id,
                snapshot,
                content_hash=str(snapshot["plan_hash"]),
                state=str(snapshot["state"]),
                required_states=["validated", "applied"],
            )
            if snapshot
            else None
        )
    if dependency_type == "record_template_snapshot":
        snapshot = object_snapshot(conn, "record_revision", dependency_id)
        if snapshot.get("load_error"):
            return None
        revision = snapshot["revision"]
        value, errors = _strict_load(revision["template_snapshot_json"], path="$.template")
        return (
            _dependency(
                dependency_type,
                dependency_id,
                value,
                content_hash=str(revision["template_content_hash"]),
            )
            if not errors and isinstance(value, dict)
            else None
        )
    if dependency_type == "issue_type_semantic_snapshot":
        snapshot = object_snapshot(conn, "conclusion_revision", dependency_id)
        if snapshot.get("load_error"):
            return None
        conclusion = snapshot["conclusion"]
        value, errors = _strict_load(
            conclusion["issue_type_semantic_snapshot_json"], path="$.issue_type"
        )
        return (
            _dependency(
                dependency_type,
                dependency_id,
                value,
                content_hash=str(conclusion["issue_type_semantic_hash"]),
            )
            if not errors and isinstance(value, dict)
            else None
        )
    if dependency_type in {"record_revision", "conclusion_revision"}:
        snapshot = object_snapshot(conn, dependency_type, dependency_id)
        return None if snapshot.get("load_error") else _dependency(
            dependency_type, dependency_id, snapshot
        )
    if dependency_type == "artifact":
        snapshot = _row(conn, "SELECT * FROM artifacts WHERE artifact_id=?", (dependency_id,))
        return (
            _dependency(
                dependency_type,
                dependency_id,
                snapshot,
                content_hash=str(snapshot["sha256"]),
                state=str(snapshot.get("state", snapshot.get("lifecycle_status", "stored"))),
            )
            if snapshot
            else None
        )
    if dependency_type == "changeset_operation":
        if ":" not in dependency_id:
            return None
        changeset_id, ordinal = dependency_id.rsplit(":", 1)
        snapshot = _row(
            conn,
            "SELECT * FROM changeset_operations WHERE changeset_id=? AND ordinal=?",
            (changeset_id, int(ordinal)),
        )
        return _dependency(dependency_type, dependency_id, snapshot) if snapshot else None
    if dependency_type == "integrity_quarantine":
        snapshot = _row(
            conn,
            "SELECT * FROM integrity_quarantines WHERE quarantine_id=?",
            (dependency_id,),
        )
        return (
            _dependency(
                dependency_type,
                dependency_id,
                snapshot,
                content_hash=str(snapshot["subject_hash"]),
                state=str(snapshot["state"]),
                required_states=["active"],
            )
            if snapshot
            else None
        )
    return None


def active_quarantines(
    conn: sqlite3.Connection,
    object_type: str,
    object_id: str,
    *,
    scope: str | None = None,
) -> list[dict[str, Any]]:
    kind = normalize_object_type(object_type)
    rows = _rows(
        conn,
        "SELECT * FROM integrity_quarantines WHERE object_type=? AND object_id=? "
        "AND state='active' ORDER BY created_at,quarantine_id",
        (kind, object_id),
    )
    for item in rows:
        item["scope"] = json.loads(item.pop("scope_json"))
    return [item for item in rows if scope is None or scope in item["scope"]]


def assert_not_quarantined(
    conn: sqlite3.Connection,
    object_type: str,
    object_id: str,
    scope: str,
) -> None:
    quarantines = active_quarantines(conn, object_type, object_id, scope=scope)
    if quarantines:
        raise ConflictError(
            f"{normalize_object_type(object_type)} {object_id} is quarantined for {scope}",
            details={
                "code": "integrity_quarantine_enforced",
                "quarantine_ids": [item["quarantine_id"] for item in quarantines],
                "scope": scope,
            },
        )


def create_quarantine(
    store: Store,
    finding_id: str,
    *,
    scopes: list[str],
    reason: str,
    actor: str,
) -> dict[str, Any]:
    if not reason.strip():
        raise ValidationError("Quarantine reason is required")
    unknown = sorted(set(scopes) - QUARANTINE_SCOPES)
    if unknown:
        raise ValidationError(f"Unknown quarantine scope: {unknown}")
    with store.transaction() as conn:
        finding = _row(
            conn,
            "SELECT * FROM migration_findings WHERE finding_id=?",
            (finding_id,),
        )
        if not finding:
            raise NotFoundError(f"Migration finding not found: {finding_id}")
        if finding["state"] != "open":
            raise ConflictError("Quarantine can only be created for an open finding")
        kind = normalize_object_type(str(finding["object_type"]))
        if kind not in _REQUIRED_SCOPES:
            raise ValidationError(
                "No trusted quarantine policy exists for the finding object type",
                details={"code": "object_integrity_validator_unknown", "object_type": kind},
            )
        object_id = str(finding["object_id"])
        snapshot = object_snapshot(conn, kind, object_id)
        if snapshot.get("load_error"):
            raise ValidationError("Cannot quarantine a missing or unsupported subject", details=snapshot)
        effective_scopes = sorted(set(scopes) | _REQUIRED_SCOPES[kind])
        subject_hash = digest(snapshot)
        existing = _row(
            conn,
            "SELECT * FROM integrity_quarantines WHERE object_type=? AND object_id=? "
            "AND state='active'",
            (kind, object_id),
        )
        if existing:
            existing_scopes = json.loads(existing["scope_json"])
            if (
                existing["finding_id"] == finding_id
                and existing["subject_hash"] == subject_hash
                and existing_scopes == effective_scopes
            ):
                return {
                    **existing,
                    "scope": existing_scopes,
                    "idempotent_replay": True,
                }
            raise ConflictError("An active quarantine already exists for this object")
        quarantine_id = new_id("quarantine")
        event_id = store.audit(
            conn,
            actor=actor,
            action="integrity.quarantine.create",
            object_type=kind,
            object_id=object_id,
            before_revision=None,
            after_revision=None,
            reason=reason,
            payload={
                "quarantine_id": quarantine_id,
                "finding_id": finding_id,
                "subject_hash": subject_hash,
                "scope": effective_scopes,
            },
        )
        timestamp = now()
        scope_hash = digest(effective_scopes)
        conn.execute(
            "INSERT INTO integrity_quarantines VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                quarantine_id,
                kind,
                object_id,
                subject_hash,
                finding_id,
                canonical_json(effective_scopes),
                scope_hash,
                "active",
                reason,
                timestamp,
                actor,
                None,
                None,
                None,
                event_id,
            ),
        )
        return {
            "quarantine_id": quarantine_id,
            "object_type": kind,
            "object_id": object_id,
            "subject_hash": subject_hash,
            "finding_id": finding_id,
            "scope": effective_scopes,
            "scope_hash": scope_hash,
            "state": "active",
            "reason": reason,
            "created_at": timestamp,
            "created_by": actor,
            "event_id": event_id,
            "idempotent_replay": False,
        }


def show_quarantine(store: Store, quarantine_id: str) -> dict[str, Any]:
    item = store.row(
        "SELECT * FROM integrity_quarantines WHERE quarantine_id=?",
        (quarantine_id,),
    )
    if not item:
        raise NotFoundError(f"Integrity quarantine not found: {quarantine_id}")
    item["scope"] = json.loads(item.pop("scope_json"))
    item["current_subject_hash"] = object_hash(
        store.conn, item["object_type"], item["object_id"]
    )
    item["subject_hash_matches"] = item["current_subject_hash"] == item["subject_hash"]
    return item


def _receipt_finding_identity(receipt: dict[str, Any]) -> tuple[str, str]:
    try:
        details = json.loads(receipt.get("finding_details_json") or "{}")
    except (json.JSONDecodeError, TypeError):
        details = {}
    if not isinstance(details, dict):
        details = {}
    object_type = normalize_object_type(
        str(
            details.get(
                "target_object_type",
                details.get("table", receipt.get("finding_object_type", "")),
            )
        )
    )
    object_id = str(details.get("target_object_id", receipt.get("finding_object_id", "")))
    if object_type == "field_bundle_action":
        object_id = str(details.get("field_bundle_event_action_id", object_id))
    return object_type, object_id


def _successor_supersedes(
    conn: sqlite3.Connection,
    object_type: str,
    object_id: str,
    successor_id: str,
) -> bool:
    if object_type == "record_revision":
        original = _row(
            conn,
            "SELECT record_instance_id FROM record_revisions WHERE record_revision_id=?",
            (object_id,),
        )
        successor = _row(
            conn,
            "SELECT record_instance_id,supersedes_revision_id FROM record_revisions "
            "WHERE record_revision_id=?",
            (successor_id,),
        )
        return bool(
            original
            and successor
            and successor.get("record_instance_id") == original.get("record_instance_id")
            and successor.get("supersedes_revision_id") == object_id
        )
    if object_type == "conclusion_revision":
        original = _row(
            conn,
            "SELECT issue_id FROM conclusion_revisions WHERE conclusion_id=?",
            (object_id,),
        )
        successor = _row(
            conn,
            "SELECT issue_id,previous_conclusion_id FROM conclusion_revisions WHERE conclusion_id=?",
            (successor_id,),
        )
        return bool(
            original
            and successor
            and successor.get("issue_id") == original.get("issue_id")
            and successor.get("previous_conclusion_id") == object_id
        )
    # Other immutable object kinds do not expose a supersession edge. Their exact
    # original/successor binding is proven by the finding, precondition hash, result
    # object, and the mandatory full receipt replay below.
    return True


def validate_quarantine_release_receipt(
    store: Store,
    quarantine: dict[str, Any],
    repair_receipt_id: str,
    *,
    full: bool,
    actor: str,
) -> dict[str, Any]:
    conn = store.conn
    receipt = _row(
        conn,
        "SELECT r.*,a.accepted,a.resolution_json,"
        "f.object_type AS finding_object_type,f.object_id AS finding_object_id,"
        "f.details_json AS finding_details_json,f.state AS finding_state,"
        "f.resolution_receipt_id AS finding_resolution_receipt_id "
        "FROM migration_finding_resolution_receipts r "
        "JOIN migration_finding_resolution_attempts a "
        "ON a.attempt_id=r.accepted_attempt_id AND a.finding_id=r.finding_id "
        "JOIN migration_findings f ON f.finding_id=r.finding_id "
        "WHERE r.receipt_id=?",
        (repair_receipt_id,),
    )
    if (
        not receipt
        or not receipt["accepted"]
        or receipt.get("proof_format") != "migration-resolution-proof/v2"
        or not receipt.get("proof_hash")
        or receipt.get("finding_state") != "resolved"
        or receipt.get("finding_resolution_receipt_id") != repair_receipt_id
    ):
        return {
            "valid": False,
            "findings": [{"code": "quarantine_release_without_repair"}],
            "receipt": receipt,
        }
    finding_type, finding_id = _receipt_finding_identity(receipt)
    if (
        finding_type != normalize_object_type(str(quarantine["object_type"]))
        or finding_id != str(quarantine["object_id"])
    ):
        return {
            "valid": False,
            "findings": [{"code": "quarantine_release_subject_mismatch"}],
            "receipt": receipt,
        }
    if receipt.get("subject_before_hash") != quarantine.get("subject_hash"):
        return {
            "valid": False,
            "findings": [{"code": "quarantine_release_subject_hash_mismatch"}],
            "receipt": receipt,
        }
    try:
        resolution = json.loads(receipt["resolution_json"])
        postcondition = json.loads(receipt["postcondition_json"])
    except (json.JSONDecodeError, TypeError):
        return {
            "valid": False,
            "findings": [{"code": "quarantine_release_without_repair"}],
            "receipt": receipt,
        }
    if not isinstance(resolution, dict) or not isinstance(postcondition, dict):
        return {
            "valid": False,
            "findings": [{"code": "quarantine_release_without_repair"}],
            "receipt": receipt,
        }
    successor_type = normalize_object_type(
        str(resolution.get("successor_object_type", quarantine["object_type"]))
    )
    successor_id = str(resolution.get("successor_object_id", ""))
    result_objects = postcondition.get("result_objects", [])
    expected_successor_hash = (
        object_hash(conn, successor_type, successor_id) if successor_id else None
    )
    if (
        resolution.get("action") != "repair_successor"
        or successor_type != normalize_object_type(str(quarantine["object_type"]))
        or not successor_id
        or successor_id == quarantine["object_id"]
        or not postcondition.get("valid")
        or not isinstance(result_objects, list)
        or not any(
            isinstance(item, dict)
            and normalize_object_type(str(item.get("object_type", ""))) == successor_type
            and item.get("object_id") == successor_id
            and item.get("content_hash") == expected_successor_hash
            for item in result_objects
        )
        or not _successor_supersedes(
            conn,
            successor_type,
            str(quarantine["object_id"]),
            successor_id,
        )
    ):
        return {
            "valid": False,
            "findings": [{"code": "quarantine_release_successor_unbound"}],
            "receipt": receipt,
        }
    current_hash = object_hash(
        conn, str(quarantine["object_type"]), str(quarantine["object_id"])
    )
    if current_hash != quarantine["subject_hash"]:
        return {
            "valid": False,
            "findings": [
                {
                    "code": "quarantine_subject_drift",
                    "expected": quarantine["subject_hash"],
                    "actual": current_hash,
                }
            ],
            "receipt": receipt,
        }
    replay = None
    if full:
        from .migration_resolution import replay_receipt

        replay = replay_receipt(
            store,
            repair_receipt_id,
            full=True,
            persist=False,
            actor=actor,
        )
        if not replay.get("valid") or replay.get("mode") != "full":
            return {
                "valid": False,
                "findings": [
                    {
                        "code": "quarantine_release_replay_failed",
                        "replay_findings": replay.get("findings", []),
                    }
                ],
                "receipt": receipt,
                "replay": replay,
            }
    return {
        "valid": True,
        "findings": [],
        "receipt": receipt,
        "successor_object_type": successor_type,
        "successor_object_id": successor_id,
        "replay": replay,
    }


def release_quarantine(
    store: Store,
    quarantine_id: str,
    *,
    repair_receipt_id: str,
    actor: str,
) -> dict[str, Any]:
    with store.transaction() as conn:
        quarantine = _row(
            conn,
            "SELECT * FROM integrity_quarantines WHERE quarantine_id=?",
            (quarantine_id,),
        )
        if not quarantine:
            raise NotFoundError(f"Integrity quarantine not found: {quarantine_id}")
        if quarantine["state"] == "released":
            if quarantine["release_receipt_id"] != repair_receipt_id:
                raise ConflictError("Quarantine was released with a different repair proof")
        validation = validate_quarantine_release_receipt(
            store,
            quarantine,
            repair_receipt_id,
            full=True,
            actor=actor,
        )
        if not validation["valid"]:
            first = validation["findings"][0]
            if first["code"] == "quarantine_subject_drift":
                raise ConflictError(
                    "Quarantined historical subject changed",
                    details=first,
                )
            raise ValidationError(
                "Quarantine release proof is invalid",
                details={**first, "findings": validation["findings"]},
            )
        if quarantine["state"] == "released":
            return {**quarantine, "idempotent_replay": True}
        receipt = validation["receipt"]
        timestamp = now()
        event_id = store.audit(
            conn,
            actor=actor,
            action="integrity.quarantine.release",
            object_type=str(quarantine["object_type"]),
            object_id=str(quarantine["object_id"]),
            before_revision=None,
            after_revision=None,
            reason="release after accepted repair proof",
            payload={
                "quarantine_id": quarantine_id,
                "repair_receipt_id": repair_receipt_id,
                "proof_hash": receipt["proof_hash"],
            },
        )
        conn.execute(
            "UPDATE integrity_quarantines SET state='released',released_at=?,released_by=?,"
            "release_receipt_id=? WHERE quarantine_id=? AND state='active'",
            (timestamp, actor, repair_receipt_id, quarantine_id),
        )
        return {
            "quarantine_id": quarantine_id,
            "state": "released",
            "released_at": timestamp,
            "released_by": actor,
            "release_receipt_id": repair_receipt_id,
            "event_id": event_id,
            "idempotent_replay": False,
        }
