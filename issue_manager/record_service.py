from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .errors import ConflictError, NotFoundError, ValidationError
from .store import canonical_json
from .strict_json import json_value_errors

if TYPE_CHECKING:
    import sqlite3

    from .security import AuthContext
    from .service import IssueManager


FIELD_TYPES = {
    "string",
    "integer",
    "number",
    "boolean",
    "enum",
    "datetime",
    "duration",
    "quantity",
    "uncertain_quantity",
    "object",
    "array",
    "evidence_ref",
    "artifact_ref",
    "record_ref",
    "issue_ref",
}
VALIDATION_PROFILES = {"draft", "provisional", "accepted", "canonical", "report"}
SOURCE_MODES = {"native", "imported", "field_bundle", "migrated"}
QUALITY_ORDER = {"declared": 0, "estimated": 0, "observed": 1, "verified": 2, "canonical": 3}
PROOF_ORDER = {"declared": 0, "source_verified": 1, "snapshot_verified": 2, "reproduced": 3}


def _content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _field_value(data: dict[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _fields(definition: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw = definition.get("fields", {})
    if isinstance(raw, list):
        result: dict[str, dict[str, Any]] = {}
        for item in raw:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                raise ValidationError("Record template field list entries require a string path")
            result[item["path"]] = {key: value for key, value in item.items() if key != "path"}
        return result
    if not isinstance(raw, dict):
        raise ValidationError("record_template.fields must be an object or field list")
    result = {}
    for path, spec in raw.items():
        if not isinstance(path, str) or not isinstance(spec, dict):
            raise ValidationError("Record field paths must map to definition objects")
        result[path] = dict(spec)
    return result


class RecordService:
    def __init__(self, manager: IssueManager):
        self.manager = manager
        self.store = manager.store

    @staticmethod
    def _actor(auth: AuthContext | None, capability: str, fallback: str) -> str:
        if auth is None:
            return fallback
        auth.require(capability)
        return auth.actor_id

    def _template(self, reference: str, *, for_creation: bool = True) -> dict[str, Any]:
        entry = self.manager.registry.resolve(
            reference, kind="record_template", for_creation=for_creation
        )
        _fields(entry["definition"])
        return entry

    def _validate_ref(self, field_type: str, value: Any, path: str, *, state_view=None) -> str | None:
        if not isinstance(value, str) or not value:
            return f"{path} must be a non-empty {field_type} string"
        table_and_key = {
            "evidence_ref": ("evidence_refs", "evidence_id"),
            "artifact_ref": ("artifacts", "artifact_id"),
            "record_ref": ("record_instances", "record_instance_id"),
            "issue_ref": ("issues", "issue_id"),
        }[field_type]
        if state_view is not None:
            rows = state_view.context_rows(table_and_key[0], table_and_key[1], value)
            return None if rows else f"{path} references an unknown {field_type}: {value}"
        row = self.store.row(
            f"SELECT 1 AS present FROM {table_and_key[0]} WHERE {table_and_key[1]}=?", (value,)
        )
        return None if row else f"{path} references an unknown {field_type}: {value}"

    @staticmethod
    def _datetime_error(value: Any, path: str) -> str | None:
        if not isinstance(value, str):
            return f"{path} must be an ISO-8601 datetime string"
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return f"{path} is not a valid ISO-8601 datetime"
        if parsed.tzinfo is None:
            return f"{path} must include a timezone offset"
        return None

    def _validate_quantity(
        self, value: Any, spec: dict[str, Any], path: str, *, uncertain: bool, state_view=None
    ) -> list[str]:
        if not isinstance(value, dict):
            return [f"{path} must be a quantity object"]
        errors: list[str] = []
        number = value.get("value")
        if (
            isinstance(number, bool)
            or not isinstance(number, (int, float))
            or not math.isfinite(float(number))
        ):
            errors.append(f"{path}.value must be a number")
        unit = value.get("unit")
        if not isinstance(unit, str) or not unit:
            errors.append(f"{path}.unit must be a non-empty string")
        allowed_units = spec.get("allowed_units", spec.get("units", []))
        if allowed_units and unit not in allowed_units:
            errors.append(f"{path}.unit {unit!r} is not in allowed units {allowed_units}")
        if uncertain:
            uncertainty = value.get("uncertainty")
            if uncertainty is not None and (
                isinstance(uncertainty, bool)
                or not isinstance(uncertainty, (int, float))
                or not math.isfinite(float(uncertainty))
                or uncertainty < 0
            ):
                errors.append(f"{path}.uncertainty must be a non-negative number or null")
            uncertainty_kind = value.get("uncertainty_kind")
            if uncertainty_kind is not None and uncertainty_kind not in {
                "standard",
                "expanded",
                "interval",
                "unknown",
            }:
                errors.append(f"{path}.uncertainty_kind is unsupported")
        for datetime_field in ("observed_at", "valid_from", "valid_until"):
            if value.get(datetime_field) is not None:
                error = self._datetime_error(value[datetime_field], f"{path}.{datetime_field}")
                if error:
                    errors.append(error)
        if value.get("valid_from") and value.get("valid_until"):
            try:
                start = datetime.fromisoformat(
                    str(value["valid_from"]).replace("Z", "+00:00")
                )
                end = datetime.fromisoformat(
                    str(value["valid_until"]).replace("Z", "+00:00")
                )
                if start.tzinfo is not None and end.tzinfo is not None and end < start:
                    errors.append(f"{path}.valid_until precedes valid_from")
            except (TypeError, ValueError):
                # The field-specific parse errors above are the stable public result.
                pass
        evidence_refs = value.get("evidence_refs", [])
        if not isinstance(evidence_refs, list):
            errors.append(f"{path}.evidence_refs must be an array")
        else:
            for evidence_id in evidence_refs:
                error = self._validate_ref(
                    "evidence_ref", evidence_id, f"{path}.evidence_refs", state_view=state_view
                )
                if error:
                    errors.append(error)
        return errors

    def _validate_type(self, value: Any, spec: dict[str, Any], path: str, *, state_view=None) -> list[str]:
        field_type = str(spec.get("type", ""))
        if field_type not in FIELD_TYPES:
            return [f"{path} uses unsupported field type {field_type!r}"]
        if value is None:
            return [] if spec.get("nullable", False) else [f"{path} cannot be null"]
        if field_type == "string" and not isinstance(value, str):
            return [f"{path} must be a string"]
        if field_type == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
            return [f"{path} must be an integer"]
        if field_type == "number" and (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            return [f"{path} must be a number"]
        if field_type == "boolean" and not isinstance(value, bool):
            return [f"{path} must be a boolean"]
        if field_type == "enum":
            choices = spec.get("enum", spec.get("values", []))
            if value not in choices:
                return [f"{path} must be one of {choices}"]
        if field_type == "datetime":
            error = self._datetime_error(value, path)
            return [error] if error else []
        if field_type == "duration":
            if not (
                (
                    isinstance(value, (int, float))
                    and not isinstance(value, bool)
                    and math.isfinite(float(value))
                    and value >= 0
                )
                or (isinstance(value, str) and re.fullmatch(r"P(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?", value))
            ):
                return [f"{path} must be a non-negative duration or ISO-8601 duration"]
        if field_type == "quantity":
            return self._validate_quantity(value, spec, path, uncertain=False, state_view=state_view)
        if field_type == "uncertain_quantity":
            return self._validate_quantity(value, spec, path, uncertain=True, state_view=state_view)
        if field_type == "object" and not isinstance(value, dict):
            return [f"{path} must be an object"]
        if field_type == "array" and not isinstance(value, list):
            return [f"{path} must be an array"]
        if field_type in {"evidence_ref", "artifact_ref", "record_ref", "issue_ref"}:
            error = self._validate_ref(field_type, value, path, state_view=state_view)
            return [error] if error else []
        return []

    def _normalize_evidence_links(
        self,
        data: dict[str, Any],
        fields: dict[str, dict[str, Any]],
        profile_spec: dict[str, Any],
        explicit_links: list[dict[str, Any]] | None,
        *,
        state_view=None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        embedded_count = 0
        for path in fields:
            present, value = _field_value(data, path)
            if not present or not isinstance(value, dict):
                continue
            refs = value.get("evidence_refs", [])
            if refs is None:
                continue
            if not isinstance(refs, list):
                errors.append(
                    {
                        "field_path": path,
                        "code": "evidence_link",
                        "message": "embedded evidence_refs must be a list",
                    }
                )
                continue
            for evidence_id in refs:
                candidates.append(
                    {
                        "field_path": path,
                        "evidence_id": str(evidence_id),
                        "relation_role": "supports",
                        "normalization_source": "embedded",
                    }
                )
                embedded_count += 1
        for link in explicit_links or []:
            if isinstance(link, dict):
                candidates.append({**link, "normalization_source": "explicit"})
            else:
                errors.append(
                    {
                        "field_path": "",
                        "code": "evidence_link",
                        "message": "evidence link must be an object",
                    }
                )

        merged: dict[tuple[str, str, str], dict[str, Any]] = {}
        level_default = str(profile_spec.get("minimum_verification_level", "declared"))
        for candidate in candidates:
            field_path = candidate.get("field_path")
            evidence_id = candidate.get("evidence_id")
            role = str(candidate.get("relation_role", "supports"))
            if not isinstance(field_path, str) or not isinstance(evidence_id, str) or not evidence_id:
                errors.append(
                    {
                        "field_path": str(field_path or ""),
                        "code": "evidence_link",
                        "message": "evidence link requires field_path and evidence_id",
                    }
                )
                continue
            if field_path not in fields:
                errors.append(
                    {
                        "field_path": field_path,
                        "code": "evidence_field",
                        "message": "evidence link field_path is not declared by the template",
                    }
                )
                continue
            if role not in {"produced_by", "supports", "contradicts", "calibration", "context"}:
                errors.append(
                    {"field_path": field_path, "code": "evidence_role", "message": f"unsupported Evidence role {role}"}
                )
                continue
            key = (field_path, evidence_id, role)
            existing = merged.get(key)
            if existing:
                if existing.get("proof_id") and candidate.get("proof_id") and (
                    existing["proof_id"] != candidate["proof_id"]
                ):
                    errors.append(
                        {"field_path": field_path, "code": "proof_conflict", "message": "duplicate Evidence links select different Proofs"}
                    )
                elif candidate.get("proof_id"):
                    existing["proof_id"] = candidate["proof_id"]
                existing["normalization_source"] = "embedded+explicit"
                continue
            merged[key] = {
                "field_path": field_path,
                "evidence_id": evidence_id,
                "proof_id": candidate.get("proof_id"),
                "relation_role": role,
                "normalization_source": candidate.get("normalization_source", "explicit"),
            }

        normalized: list[dict[str, Any]] = []
        for key in sorted(merged):
            link = merged[key]
            path = link["field_path"]
            evidence_rows = state_view.context_rows("evidence_refs", "evidence_id", link["evidence_id"]) if state_view is not None else None
            evidence = (evidence_rows[0] if evidence_rows else None) if state_view is not None else self.store.row(
                "SELECT evidence_id,lifecycle_status,current_proof_id,semantic_revision "
                "FROM evidence_refs WHERE evidence_id=?",
                (link["evidence_id"],),
            )
            if not evidence or evidence["lifecycle_status"] != "active":
                errors.append(
                    {"field_path": path, "code": "unknown_evidence", "message": f"unknown or inactive Evidence {link['evidence_id']}"}
                )
                continue
            minimum = str(fields.get(path, {}).get("minimum_verification_level", level_default))
            proof_id = link.get("proof_id")
            if not proof_id and minimum != "declared":
                proof_id = evidence.get("current_proof_id")
            proof = None
            if proof_id:
                proof_rows = state_view.context_rows("evidence_proofs", "proof_id", proof_id) if state_view is not None else None
                proof = (proof_rows[0] if proof_rows else None) if state_view is not None else self.store.row(
                    "SELECT proof_id,evidence_id,proof_hash,manifest_id,manifest_hash,"
                    "semantic_revision,verification_level,verification_state "
                    "FROM evidence_proofs WHERE proof_id=?",
                    (proof_id,),
                )
                if not proof or proof["evidence_id"] != link["evidence_id"]:
                    errors.append(
                        {"field_path": path, "code": "proof_required", "message": "field requires a matching Proof"}
                    )
                    proof = None
                elif (
                    proof["verification_state"] != "active"
                    or int(proof["semantic_revision"]) != int(evidence["semantic_revision"])
                    or PROOF_ORDER.get(proof["verification_level"], -1)
                    < PROOF_ORDER.get(minimum, 0)
                ):
                    errors.append(
                        {"field_path": path, "code": "proof_insufficient", "message": f"Proof does not meet active {minimum}"}
                    )
            elif minimum != "declared":
                errors.append(
                    {"field_path": path, "code": "proof_required", "message": "field requires a matching Proof"}
                )
            normalized.append(
                {
                    "field_path": path,
                    "evidence_id": link["evidence_id"],
                    "proof_id": proof["proof_id"] if proof else None,
                    "relation_role": link["relation_role"],
                    "proof_hash": proof["proof_hash"] if proof else None,
                    "manifest_id": proof["manifest_id"] if proof else None,
                    "manifest_hash": proof["manifest_hash"] if proof else None,
                    "evidence_semantic_revision": (
                        int(proof["semantic_revision"]) if proof else int(evidence["semantic_revision"])
                    ),
                    "verification_level_snapshot": (
                        proof["verification_level"] if proof else "declared"
                    ),
                    "verification_state_snapshot": (
                        proof["verification_state"] if proof else "active"
                    ),
                }
            )
        receipt = {
            "input_explicit_links": len(explicit_links or []),
            "input_embedded_refs": embedded_count,
            "normalized_links": len(normalized),
            "deduplicated": len(candidates) - len(merged),
            "normalized_hash": _content_hash(normalized),
        }
        return normalized, errors, receipt

    def validate_data(
        self,
        template_reference: str,
        data: dict[str, Any],
        *,
        profile: str = "draft",
        evidence_links: list[dict[str, Any]] | None = None,
        include_embedded_evidence: bool = True,
        state_view=None,
    ) -> dict[str, Any]:
        if profile not in VALIDATION_PROFILES:
            raise ValidationError(f"Unsupported record validation profile: {profile}")
        if not isinstance(data, dict):
            raise ValidationError("Record data must be an object")
        template = self._template(template_reference, for_creation=False)
        fields = _fields(template["definition"])
        errors: list[dict[str, Any]] = [
            *json_value_errors(data, path="$.data"),
            *json_value_errors(evidence_links or [], path="$.evidence_links"),
        ]
        warnings: list[dict[str, Any]] = []
        profile_spec = template["definition"].get("profiles", {}).get(profile, {})
        if not isinstance(profile_spec, dict):
            raise ValidationError(f"Record validation profile {profile} must be an object")
        required = set(profile_spec.get("required", []))
        if profile != "draft":
            required.update(path for path, spec in fields.items() if spec.get("required"))
        for path, spec in fields.items():
            present, value = _field_value(data, path)
            if not present:
                if path in required:
                    errors.append({"field_path": path, "code": "required", "message": "field is required"})
                continue
            for message in self._validate_type(value, spec, path, state_view=state_view):
                errors.append({"field_path": path, "code": "type_or_constraint", "message": message})
        if template["definition"].get("additional_fields") is False:
            known_roots = {path.split(".", 1)[0] for path in fields}
            for key in sorted(set(data) - known_roots):
                errors.append(
                    {"field_path": key, "code": "unknown_field", "message": "field is not declared by the template"}
                )
        normalized_links, normalization_errors, normalization_receipt = (
            self._normalize_evidence_links(
                data if include_embedded_evidence else {}, fields, profile_spec, evidence_links,
                state_view=state_view,
            )
        )
        errors.extend(normalization_errors)
        link_index: dict[str, list[dict[str, Any]]] = {}
        for link in normalized_links:
            link_index.setdefault(link["field_path"], []).append(link)
        evidence_required = set(profile_spec.get("evidence_required", []))
        evidence_required.update(
            path
            for path, spec in fields.items()
            if spec.get("evidence_required") and profile in {"accepted", "canonical", "report"}
        )
        for path in sorted(evidence_required):
            links = link_index.get(path, [])
            if not links:
                errors.append(
                    {"field_path": path, "code": "evidence_required", "message": "field requires Evidence"}
                )
        return {
            "valid": not errors,
            "profile": profile,
            "template_registration_id": template["registration_id"],
            "template_content_hash": template["content_hash"],
            "errors": errors,
            "warnings": warnings,
            "normalized_evidence_links": normalized_links,
            "normalization_receipt": normalization_receipt,
        }

    def create(
        self,
        issue_id: str,
        template_reference: str,
        *,
        data: dict[str, Any] | None = None,
        profile: str = "draft",
        evidence_links: list[dict[str, Any]] | None = None,
        source_mode: str = "native",
        source_object_mapping_id: str | None = None,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "create registered record",
        dry_run: bool = False,
    ) -> dict[str, Any]:
        capability = (
            "record.publish" if profile in {"accepted", "canonical", "report"} else "record.create"
        )
        actor = self._actor(auth, capability, actor)
        from .changeset_state import StateView
        from .record_planner import apply_record_plan, plan_record_create

        def make_plan() -> dict[str, Any]:
            return plan_record_create(
                StateView(self.manager),
                issue_id=issue_id,
                template_reference=template_reference,
                data=data or {},
                profile=profile,
                evidence_links=evidence_links or [],
                source_mode=source_mode,
                source_object_mapping_id=source_object_mapping_id,
            )

        if dry_run:
            plan = make_plan()
            return {
                "issue_id": plan["issue_id"],
                "template_registration_id": plan["template_registration_id"],
                "template_content_hash": plan["template_content_hash"],
                "profile": plan["profile"],
                "validation": plan["validation"],
                "would_write": False,
            }
        # The planner reads mutable Issue, template, Evidence, and Proof state.
        # Keep that read and the applier in one write transaction so another
        # connection cannot change those inputs between planning and commit.
        with self.store.transaction():
            return apply_record_plan(self, make_plan(), actor=actor, reason=reason)

    def _insert_links(
        self, conn: sqlite3.Connection, revision_id: str, links: list[dict[str, Any]]
    ) -> None:
        for link in links:
            role = str(link.get("relation_role", "supports"))
            if role not in {"produced_by", "supports", "contradicts", "calibration", "context"}:
                raise ValidationError(f"Unsupported Record Evidence relation role: {role}")
            evidence_id = str(link.get("evidence_id", ""))
            evidence = conn.execute(
                "SELECT evidence_id FROM evidence_refs WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
            if not evidence:
                raise ValidationError(f"Unknown Evidence in Record link: {evidence_id}")
            proof_id = link.get("proof_id")
            if proof_id:
                proof = conn.execute(
                    "SELECT evidence_id FROM evidence_proofs WHERE proof_id=?", (proof_id,)
                ).fetchone()
                if not proof or proof["evidence_id"] != evidence_id:
                    raise ValidationError("Record link Proof must belong to the linked Evidence")
            conn.execute(
                "INSERT INTO record_evidence_links("
                "record_revision_id,field_path,evidence_id,proof_id,relation_role,proof_hash,"
                "manifest_id,manifest_hash,evidence_semantic_revision,"
                "verification_level_snapshot,verification_state_snapshot) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    revision_id, str(link.get("field_path", "")), evidence_id, proof_id, role,
                    link.get("proof_hash"), link.get("manifest_id"), link.get("manifest_hash"),
                    link.get("evidence_semantic_revision"),
                    link.get("verification_level_snapshot"),
                    link.get("verification_state_snapshot"),
                ),
            )

    def _index_revision(
        self,
        conn: sqlite3.Connection,
        revision_id: str,
        definition: dict[str, Any],
        data: dict[str, Any],
    ) -> int:
        count = 0
        for path, spec in _fields(definition).items():
            if not spec.get("queryable", False):
                continue
            present, value = _field_value(data, path)
            if not present or value is None:
                continue
            field_type = str(spec.get("type"))
            number_value = text_value = boolean_value = unit = observed_at = quality = None
            if field_type in {"integer", "number"}:
                number_value = float(value)
            elif field_type == "boolean":
                boolean_value = 1 if value else 0
            elif field_type in {"quantity", "uncertain_quantity"}:
                number_value = float(value["value"])
                unit = value["unit"]
                observed_at = value.get("observed_at")
                quality = value.get("quality")
            else:
                text_value = canonical_json(value) if isinstance(value, (dict, list)) else str(value)
            conn.execute(
                "INSERT INTO record_value_index(record_revision_id,field_path,value_type,"
                "number_value,text_value,boolean_value,unit_code,observed_at,quality_state) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    revision_id,
                    path,
                    field_type,
                    number_value,
                    text_value,
                    boolean_value,
                    unit,
                    observed_at,
                    quality,
                ),
            )
            count += 1
        return count

    def revise(
        self,
        record_instance_id: str,
        data: dict[str, Any],
        *,
        expected_revision_id: str | None = None,
        profile: str = "draft",
        evidence_links: list[dict[str, Any]] | None = None,
        source_mode: str = "native",
        source_object_mapping_id: str | None = None,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "revise registered record",
        dry_run: bool = False,
    ) -> dict[str, Any]:
        capability = (
            "record.publish" if profile in {"accepted", "canonical", "report"} else "record.revise"
        )
        actor = self._actor(auth, capability, actor)
        from .changeset_state import StateView
        from .integrity import assert_not_quarantined
        from .record_planner import apply_record_plan, plan_record_revision

        def make_plan() -> dict[str, Any]:
            instance = self.store.row(
                "SELECT * FROM record_instances WHERE record_instance_id=?", (record_instance_id,)
            )
            if not instance:
                raise NotFoundError(f"Record not found: {record_instance_id}")
            if instance["lifecycle_status"] != "active":
                raise ConflictError(f"Record is not active: {record_instance_id}")
            current = self.store.row(
                "SELECT * FROM record_revisions WHERE record_revision_id=?",
                (instance["current_revision_id"],),
            )
            if not current:
                raise ConflictError("Record current revision pointer is invalid")
            assert_not_quarantined(
                self.store.conn,
                "record_revision",
                str(current["record_revision_id"]),
                "block_current_promotion",
            )
            return plan_record_revision(
                StateView(self.manager),
                record_instance_id=record_instance_id,
                data=data,
                expected_revision_id=expected_revision_id,
                profile=profile,
                evidence_links=evidence_links or [],
                source_mode=source_mode,
                source_object_mapping_id=source_object_mapping_id,
            )

        if dry_run:
            plan = make_plan()
            return {
                key: value
                for key, value in plan.items()
                if not key.startswith("_")
                and key not in {"operation", "normalized_evidence_links"}
            } | {"would_write": False}
        # See create(): all mutable planner inputs and application are locked
        # together. The nested transaction in apply_record_plan is a savepoint.
        with self.store.transaction():
            return apply_record_plan(self, make_plan(), actor=actor, reason=reason)

    def show(self, record_instance_id: str) -> dict[str, Any]:
        instance = self.store.row(
            "SELECT * FROM record_instances WHERE record_instance_id=?", (record_instance_id,)
        )
        if not instance:
            raise NotFoundError(f"Record not found: {record_instance_id}")
        result = dict(instance)
        result["record_template_snapshot"] = json.loads(
            result.pop("record_template_snapshot_json")
        )
        current = self.show_revision(result["current_revision_id"])
        result["current_revision"] = current
        return result

    def show_revision(self, record_revision_id: str) -> dict[str, Any]:
        revision = self.store.row(
            "SELECT * FROM record_revisions WHERE record_revision_id=?", (record_revision_id,)
        )
        if not revision:
            raise NotFoundError(f"Record revision not found: {record_revision_id}")
        result = dict(revision)
        result["data"] = json.loads(result.pop("data_json"))
        result["template_snapshot"] = json.loads(result.pop("template_snapshot_json"))
        result["validation_result"] = json.loads(result.pop("validation_result_json"))
        result["evidence_links"] = self.store.rows(
            "SELECT * FROM record_evidence_links WHERE record_revision_id=? "
            "ORDER BY field_path,evidence_id,relation_role",
            (record_revision_id,),
        )
        from .integrity import active_quarantines

        quarantines = active_quarantines(
            self.store.conn, "record_revision", record_revision_id
        )
        result["quarantined"] = bool(quarantines)
        result["quarantines"] = quarantines
        return result

    def history(self, record_instance_id: str) -> list[dict[str, Any]]:
        if not self.store.row(
            "SELECT 1 FROM record_instances WHERE record_instance_id=?", (record_instance_id,)
        ):
            raise NotFoundError(f"Record not found: {record_instance_id}")
        return [
            self.show_revision(item["record_revision_id"])
            for item in self.store.rows(
                "SELECT record_revision_id FROM record_revisions WHERE record_instance_id=? "
                "ORDER BY revision_number",
                (record_instance_id,),
            )
        ]

    def validate_record(self, record_instance_id: str, *, profile: str) -> dict[str, Any]:
        shown = self.show(record_instance_id)
        revision = shown["current_revision"]
        return self.validate_data(
            shown["record_template_registration_id"],
            revision["data"],
            profile=profile,
            evidence_links=revision["evidence_links"],
        )

    def evidence_status(self, record_instance_id: str) -> dict[str, Any]:
        """Compare a frozen Record Revision evidence basis with current Evidence state."""
        shown = self.show(record_instance_id)
        revision = shown["current_revision"]
        statuses: list[dict[str, Any]] = []
        for link in revision["evidence_links"]:
            reasons: list[str] = []
            evidence = self.store.row(
                "SELECT evidence_id,lifecycle_status,current_proof_id,semantic_revision "
                "FROM evidence_refs WHERE evidence_id=?",
                (link["evidence_id"],),
            )
            proof = None
            manifest = None
            if not evidence or evidence["lifecycle_status"] != "active":
                reasons.append("evidence_inactive_or_missing")
            else:
                if int(evidence["semantic_revision"]) != int(
                    link.get("evidence_semantic_revision") or 0
                ):
                    reasons.append("evidence_semantic_revision_changed")
                if link.get("proof_id"):
                    proof = self.store.row(
                        "SELECT * FROM evidence_proofs WHERE proof_id=?",
                        (link["proof_id"],),
                    )
                    if not proof:
                        reasons.append("proof_missing")
                    else:
                        if proof["proof_hash"] != link.get("proof_hash"):
                            reasons.append("proof_hash_changed")
                        if proof["verification_state"] != "active":
                            reasons.append("proof_inactive")
                        if evidence.get("current_proof_id") != proof["proof_id"]:
                            reasons.append("proof_no_longer_current")
                        if proof.get("manifest_id"):
                            manifest = self.store.row(
                                "SELECT m.manifest_id,m.manifest_hash,EXISTS("
                                "SELECT 1 FROM evidence_manifests newer "
                                "WHERE newer.supersedes_manifest_id=m.manifest_id"
                                ") AS is_superseded FROM evidence_manifests m WHERE m.manifest_id=?",
                                (proof["manifest_id"],),
                            )
                            if not manifest:
                                reasons.append("manifest_missing")
                            else:
                                if manifest["manifest_hash"] != link.get("manifest_hash"):
                                    reasons.append("manifest_hash_changed")
                                if manifest.get("is_superseded"):
                                    reasons.append("manifest_superseded")
            statuses.append(
                {
                    "field_path": link["field_path"],
                    "evidence_id": link["evidence_id"],
                    "proof_id": link.get("proof_id"),
                    "manifest_id": link.get("manifest_id"),
                    "status": "stale" if reasons else "fresh",
                    "reasons": reasons,
                    "verification_level_snapshot": link.get(
                        "verification_level_snapshot"
                    ),
                    "current_evidence": evidence,
                    "current_proof": proof,
                    "current_manifest": manifest,
                }
            )
        return {
            "record_instance_id": record_instance_id,
            "record_revision_id": revision["record_revision_id"],
            "status": "stale" if any(item["reasons"] for item in statuses) else "fresh",
            "evidence": statuses,
        }

    def current_material_links(self, record_revision_id: str) -> list[dict[str, Any]]:
        """Current membership with retained version identity; no historical mutation."""
        from .context_resolver import semantic_row

        if not hasattr(self.manager, "context_maintenance"):
            return self.show_revision(record_revision_id)["evidence_links"]
        rows = self.store.rows("SELECT r.*,h.version_id AS relation_version_id FROM record_material_relations r "
                               "LEFT JOIN managed_relation_heads h ON h.domain='record' AND h.relation_id=r.relation_id "
                               "WHERE r.record_revision_id=? AND r.active=1 ORDER BY r.relation_id", (record_revision_id,))
        if any(row["relation_version_id"] is None for row in rows):
            raise ValidationError("Missing Record material relationship version")
        return [semantic_row(row, table="record_material_relations") for row in rows]

    def refresh_impact(self, record_instance_id: str) -> dict[str, Any]:
        status = self.evidence_status(record_instance_id)
        revision_id = status["record_revision_id"]
        report_builds = self.store.rows(
            "SELECT b.report_build_id,b.state FROM report_build_inputs i "
            "JOIN report_builds b ON b.report_build_id=i.report_build_id "
            "WHERE i.object_type='record_revision' AND i.object_id=? "
            "ORDER BY b.report_build_id",
            (revision_id,),
        )
        return {
            **status,
            "requires_new_revision": status["status"] == "stale",
            "affected_report_builds": report_builds,
        }

    def rebuild_index(self) -> dict[str, Any]:
        revisions = self.store.rows(
            "SELECT record_revision_id,template_snapshot_json,data_json FROM record_revisions "
            "ORDER BY record_revision_id"
        )
        with self.store.transaction() as conn:
            conn.execute("DELETE FROM record_value_index")
            indexed = 0
            for revision in revisions:
                snapshot = json.loads(revision["template_snapshot_json"])
                definition = snapshot.get("definition", snapshot)
                indexed += self._index_revision(
                    conn,
                    revision["record_revision_id"],
                    definition,
                    json.loads(revision["data_json"]),
                )
        return {"revisions": len(revisions), "indexed_values": indexed}

    def plan_template_migration(
        self, record_instance_id: str, target_template_reference: str
    ) -> dict[str, Any]:
        record = self.show(record_instance_id)
        current_template = record["record_template_snapshot"]
        target = self._template(target_template_reference)
        old_fields = _fields(current_template["definition"])
        new_fields = _fields(target["definition"])
        removed = sorted(set(old_fields) - set(new_fields))
        added = sorted(set(new_fields) - set(old_fields))
        changed = sorted(
            path
            for path in set(old_fields) & set(new_fields)
            if canonical_json(old_fields[path]) != canonical_json(new_fields[path])
        )
        declared = str(target["definition"].get("upgrade_compatibility", "migration_needed"))
        classification = "compatible" if not removed and not changed else "migration_needed"
        if declared == "incompatible":
            classification = "incompatible"
        return {
            "record_instance_id": record_instance_id,
            "source_template_registration_id": record["record_template_registration_id"],
            "target_template_registration_id": target["registration_id"],
            "classification": classification,
            "added_fields": added,
            "removed_fields": removed,
            "changed_fields": changed,
            "would_write": False,
        }
