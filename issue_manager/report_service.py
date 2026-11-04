from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import io
import json
import math
import os
from datetime import datetime
from typing import TYPE_CHECKING, Any

from .errors import ConflictError, NotFoundError, RendererEnvelopeError, ValidationError
from .registry_service import validate_json_instance
from .store import canonical_json, new_id, now
from .strict_json import json_value_errors, require_strict_json

if TYPE_CHECKING:
    from .security import AuthContext
    from .service import IssueManager


BUILTIN_RENDERERS = {
    "markdown": {"name": "core-markdown", "version": "1.0.0", "extension": "md", "mime": "text/markdown"},
    "csv": {"name": "core-csv", "version": "1.0.0", "extension": "csv", "mime": "text/csv"},
    "json": {"name": "core-json", "version": "1.0.0", "extension": "json", "mime": "application/json"},
}


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _renderer_hash(output_format: str) -> str:
    renderer = BUILTIN_RENDERERS[output_format]
    return _hash(
        {
            "renderer_kind": "builtin",
            "name": renderer["name"],
            "version": renderer["version"],
            "protocol_version": "neutral-report-model/v2",
            "media_type": renderer["mime"],
            "extension": renderer["extension"],
            "deterministic_output": True,
        }
    )


def validate_report_renderer_envelope(
    envelope: Any,
    *,
    expected_media_type: str,
    expected_extension: str,
    maximum_decoded_output_bytes: int,
) -> dict[str, Any]:
    """Validate and decode the one strict Renderer envelope used by build and rerun."""
    if not isinstance(envelope, dict):
        raise RendererEnvelopeError(
            "Report Renderer envelope must be an object",
            details={"code": "renderer_envelope_type", "path": "$.adapter_output"},
        )
    allowed = {"content_base64", "media_type", "extension", "metadata"}
    unknown = sorted(set(envelope) - allowed)
    missing = sorted({"content_base64", "media_type", "extension"} - set(envelope))
    if unknown or missing:
        raise RendererEnvelopeError(
            "Report Renderer envelope fields are invalid",
            details={
                "code": "renderer_envelope_fields",
                "path": "$.adapter_output",
                "unknown_fields": unknown,
                "missing_fields": missing,
            },
        )
    if envelope["media_type"] != expected_media_type:
        raise RendererEnvelopeError(
            "Report Renderer returned the wrong media type",
            details={
                "code": "renderer_media_type_mismatch",
                "path": "$.adapter_output.media_type",
                "expected": expected_media_type,
                "actual": envelope["media_type"],
            },
        )
    if envelope["extension"] != expected_extension:
        raise RendererEnvelopeError(
            "Report Renderer returned the wrong extension",
            details={
                "code": "renderer_extension_mismatch",
                "path": "$.adapter_output.extension",
                "expected": expected_extension,
                "actual": envelope["extension"],
            },
        )
    metadata = envelope.get("metadata", {})
    if not isinstance(metadata, dict):
        raise RendererEnvelopeError(
            "Report Renderer metadata must be an object",
            details={"code": "renderer_metadata_type", "path": "$.adapter_output.metadata"},
        )
    try:
        require_strict_json(metadata, path="$.adapter_output.metadata")
    except ValidationError as exc:
        raise RendererEnvelopeError(
            "Report Renderer metadata is not strict JSON",
            details={
                "code": "renderer_metadata_invalid",
                "path": "$.adapter_output.metadata",
                **exc.details,
            },
        ) from exc
    if not isinstance(envelope["content_base64"], str):
        raise RendererEnvelopeError(
            "Report Renderer content_base64 must be a string",
            details={"code": "renderer_base64_type", "path": "$.adapter_output.content_base64"},
        )
    try:
        content = base64.b64decode(envelope["content_base64"], validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RendererEnvelopeError(
            "Report Renderer returned invalid base64 content",
            details={"code": "renderer_base64_invalid", "path": "$.adapter_output.content_base64"},
        ) from exc
    if len(content) > maximum_decoded_output_bytes:
        raise RendererEnvelopeError(
            "Report Renderer decoded content exceeded the frozen limit",
            details={
                "code": "renderer_decoded_output_limit_exceeded",
                "path": "$.adapter_output.content_base64",
                "limit": maximum_decoded_output_bytes,
                "observed_bytes": len(content),
            },
        )
    return {
        "content": content,
        "content_hash": hashlib.sha256(content).hexdigest(),
        "decoded_bytes": len(content),
        "metadata": metadata,
        "metadata_hash": _hash(metadata),
        "media_type": expected_media_type,
        "extension": expected_extension,
    }


def _field_value(data: dict[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = data
    for piece in path.split("."):
        if not isinstance(current, dict) or piece not in current:
            return False, None
        current = current[piece]
    return True, current


class ReportService:
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
        return self.manager.registry.resolve(
            reference, kind="report_template", for_creation=for_creation
        )

    def _issue_ids(self, scope: dict[str, Any]) -> list[str]:
        """Compatibility view for callers predating persisted Scope v2."""
        return self._normalize_scope(scope, legacy_wildcard=True)[1]

    def _normalize_scope(
        self, scope: dict[str, Any], *, legacy_wildcard: bool = False
    ) -> tuple[dict[str, Any], list[str]]:
        require_strict_json(scope, path="$.scope")
        allowed = {
            "scope_version",
            "issue_ids",
            "issue_id",
            "root_issue_id",
            "issue_type_registration_ids",
            "issue_type_refs",
            "issue_type",
            "include_archived",
        }
        unknown = sorted(set(scope) - allowed)
        if unknown:
            raise ValidationError(f"Unknown report scope fields: {unknown}")
        include_archived = bool(scope.get("include_archived", False))
        normalized: dict[str, Any] = {
            "scope_version": "report-scope/v2",
            "issue_ids": [],
            "root_issue_id": None,
            "issue_type_registration_ids": [],
            "include_archived": include_archived,
        }
        selectors = sum(
            1
            for present in (
                scope.get("issue_ids") is not None or bool(scope.get("issue_id")),
                bool(scope.get("root_issue_id")),
                scope.get("issue_type_registration_ids") is not None
                or scope.get("issue_type_refs") is not None
                or bool(scope.get("issue_type")),
            )
            if present
        )
        if selectors > 1:
            raise ValidationError("Report scope must use exactly one selection mode")
        if scope.get("issue_ids") is not None:
            if not isinstance(scope["issue_ids"], list):
                raise ValidationError("report scope.issue_ids must be an array")
            normalized["issue_ids"] = sorted({str(item) for item in scope["issue_ids"]})
        elif scope.get("issue_id"):
            normalized["issue_ids"] = [str(scope["issue_id"])]
        if normalized["issue_ids"]:
            issue_ids = normalized["issue_ids"]
            placeholders = ",".join("?" for _ in issue_ids)
            rows = self.store.rows(
                f"SELECT issue_id,work_status FROM issues WHERE issue_id IN ({placeholders})",
                tuple(issue_ids),
            )
            selected = [
                row["issue_id"]
                for row in rows
                if include_archived or row["work_status"] not in {"void", "archived"}
            ]
            return normalized, sorted(selected)
        if scope.get("root_issue_id"):
            root = str(scope["root_issue_id"])
            self.manager._issue(root, active=False)
            normalized["root_issue_id"] = root
            rows = self.store.rows(
                "WITH RECURSIVE subtree(issue_id) AS (SELECT ? UNION ALL "
                "SELECT i.issue_id FROM issues i JOIN subtree s ON i.parent_issue_id=s.issue_id) "
                "SELECT s.issue_id,i.work_status FROM subtree s JOIN issues i ON i.issue_id=s.issue_id "
                "ORDER BY s.issue_id",
                (root,),
            )
            return normalized, [
                row["issue_id"]
                for row in rows
                if include_archived or row["work_status"] not in {"void", "archived"}
            ]
        registration_ids: list[str] = []
        raw_ids = scope.get("issue_type_registration_ids")
        raw_refs = scope.get("issue_type_refs")
        if raw_ids is not None:
            if not isinstance(raw_ids, list):
                raise ValidationError(
                    "report scope.issue_type_registration_ids must be an array"
                )
            for registration_id in raw_ids:
                registration_ids.append(
                    self.manager.registry.resolve(
                        str(registration_id), kind="issue_type", for_creation=False
                    )["registration_id"]
                )
        elif raw_refs is not None:
            if not isinstance(raw_refs, list):
                raise ValidationError("report scope.issue_type_refs must be an array")
            for reference in raw_refs:
                registration_ids.append(
                    self.manager.registry.resolve(
                        str(reference), kind="issue_type", for_creation=False
                    )["registration_id"]
                )
        elif scope.get("issue_type"):
            matches = self.store.rows(
                "SELECT registration_id FROM registry_entries WHERE kind='issue_type' "
                "AND name=? AND state IN ('active','deprecated') ORDER BY registration_id",
                (str(scope["issue_type"]),),
            )
            unique = sorted({item["registration_id"] for item in matches})
            if len(unique) != 1:
                raise ConflictError(
                    "Legacy bare issue_type scope is ambiguous",
                    details={
                        "code": "issue_type_scope_ambiguous",
                        "issue_type": scope["issue_type"],
                        "registration_ids": unique,
                    },
                )
            registration_ids = unique
        normalized["issue_type_registration_ids"] = sorted(set(registration_ids))
        if not registration_ids:
            if legacy_wildcard and selectors == 0:
                registrations = self.store.rows(
                    "SELECT registration_id FROM registry_entries WHERE kind='issue_type' "
                    "AND state IN ('active','deprecated') ORDER BY registration_id"
                )
                normalized["issue_type_registration_ids"] = [
                    item["registration_id"] for item in registrations
                ]
                status_clause = (
                    "" if include_archived else "WHERE work_status NOT IN ('void','archived')"
                )
                return normalized, [
                    row["issue_id"]
                    for row in self.store.rows(
                        f"SELECT issue_id FROM issues {status_clause} ORDER BY issue_id"
                    )
                ]
            return normalized, []
        placeholders = ",".join("?" for _ in registration_ids)
        status_clause = "" if include_archived else "AND work_status NOT IN ('void','archived')"
        rows = self.store.rows(
            "SELECT issue_id FROM issues WHERE issue_type_registration_id IN ("
            + placeholders
            + f") {status_clause} ORDER BY issue_id",
            tuple(registration_ids),
        )
        return normalized, [row["issue_id"] for row in rows]

    def _accepted_template_ids(
        self, definition: dict[str, Any], *, is_v2: bool = False
    ) -> set[str] | None:
        references = definition.get("record_templates", definition.get("record_template_refs"))
        if references is None:
            selection = definition.get("record_template_selection")
            if selection is None:
                return set() if is_v2 else None
            if not isinstance(selection, dict) or selection.get("mode") != "all_for_issue_types":
                raise ValidationError("Unsupported record_template_selection")
            issue_type_ids = {
                self.manager.registry.resolve(
                    str(reference), kind="issue_type", for_creation=False
                )["registration_id"]
                for reference in selection.get("issue_type_refs", [])
            }
            if not issue_type_ids:
                return set()
            placeholders = ",".join("?" for _ in issue_type_ids)
            return {
                row["owner_registration_id"]
                for row in self.store.rows(
                    "SELECT DISTINCT l.owner_registration_id FROM registry_reference_locks l "
                    "JOIN registry_entries e ON e.registration_id=l.owner_registration_id "
                    "WHERE e.kind='record_template' AND l.target_kind='issue_type' "
                    f"AND l.target_registration_id IN ({placeholders})",
                    tuple(sorted(issue_type_ids)),
                )
            }
        if not isinstance(references, list):
            raise ValidationError("report_template.record_templates must be an array")
        result: set[str] = set()
        for reference in references:
            result.add(
                self.manager.registry.resolve(
                    str(reference), kind="record_template", for_creation=False
                )["registration_id"]
            )
        return result

    @staticmethod
    def _convert(value: Any, spec: dict[str, Any], column: dict[str, Any]) -> tuple[Any, dict[str, Any] | None]:
        target_unit = column.get("unit")
        if not target_unit or not isinstance(value, dict) or "value" not in value or "unit" not in value:
            return value, None
        source_unit = value["unit"]
        number = value["value"]
        if source_unit == target_unit:
            converted = dict(value)
        else:
            factors = spec.get("unit_factors", spec.get("conversion_factors", {}))
            if not isinstance(factors, dict) or source_unit not in factors or target_unit not in factors:
                raise ValidationError(
                    f"No deterministic unit conversion is declared for {source_unit} -> {target_unit}"
                )
            converted = dict(value)
            converted["value"] = float(number) * float(factors[source_unit]) / float(
                factors[target_unit]
            )
            if isinstance(value.get("uncertainty"), (int, float)):
                converted["uncertainty"] = float(value["uncertainty"]) * float(
                    factors[source_unit]
                ) / float(factors[target_unit])
            converted["unit"] = target_unit
        digits = column.get("round")
        if digits is not None:
            converted["value"] = round(float(converted["value"]), int(digits))
            if isinstance(converted.get("uncertainty"), (int, float)):
                converted["uncertainty"] = round(float(converted["uncertainty"]), int(digits))
        return converted, {
            "from_unit": source_unit,
            "to_unit": target_unit,
            "factor_source": spec.get("unit_factors", spec.get("conversion_factors", {})).get(source_unit, 1),
            "factor_target": spec.get("unit_factors", spec.get("conversion_factors", {})).get(target_unit, 1),
        }

    @staticmethod
    def _normalize_query(
        query: dict[str, Any], allowed_fields: set[str], allowed_operators: set[str]
    ) -> list[dict[str, Any]]:
        if not query:
            return []
        filters: list[dict[str, Any]] = []
        if set(query) == {"filters"}:
            raw_filters = query["filters"]
            if not isinstance(raw_filters, list):
                raise ValidationError("report query filters must be an array")
            filters = [dict(item) for item in raw_filters if isinstance(item, dict)]
            if len(filters) != len(raw_filters):
                raise ValidationError("report query filters must be objects")
        elif "field" in query:
            filters = [dict(query)]
        else:
            for field, expression in query.items():
                if isinstance(expression, dict):
                    if len(expression) != 1:
                        raise ValidationError(
                            f"Query field {field!r} must select exactly one operator"
                        )
                    operator, value = next(iter(expression.items()))
                else:
                    operator, value = "eq", expression
                filters.append({"field": field, "operator": operator, "value": value})
        normalized: list[dict[str, Any]] = []
        for item in filters:
            unknown = sorted(set(item) - {"field", "operator", "op", "value"})
            if unknown:
                raise ValidationError(f"Unknown report query fields: {unknown}")
            field = str(item.get("field", ""))
            operator = str(item.get("operator", item.get("op", "")))
            if field not in allowed_fields:
                raise ValidationError(f"Report query field is not allowed: {field!r}")
            if operator not in allowed_operators or operator not in {
                "eq", "ne", "in", "exists", "lt", "lte", "gt", "gte"
            }:
                raise ValidationError(f"Report query operator is not allowed: {operator!r}")
            value = item.get("value")
            if operator == "in" and not isinstance(value, list):
                raise ValidationError("Report query 'in' value must be an array")
            if operator == "exists" and value is not None and not isinstance(value, bool):
                raise ValidationError("Report query 'exists' value must be boolean")
            normalized.append(
                {
                    "field": field,
                    "operator": operator,
                    "value": True if operator == "exists" and value is None else value,
                }
            )
        return sorted(
            normalized,
            key=lambda item: (item["field"], item["operator"], canonical_json(item["value"])),
        )

    @staticmethod
    def _query_evaluate(
        row: dict[str, Any], query: list[dict[str, Any]]
    ) -> tuple[bool, list[dict[str, Any]]]:
        findings: list[dict[str, Any]] = []

        def comparable(value: Any, expected: Any) -> tuple[Any, Any] | None:
            if (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and isinstance(expected, (int, float))
                and not isinstance(expected, bool)
                and math.isfinite(float(value))
                and math.isfinite(float(expected))
            ):
                return float(value), float(expected)
            if isinstance(value, str) and isinstance(expected, str):
                try:
                    left = datetime.fromisoformat(value.replace("Z", "+00:00"))
                    right = datetime.fromisoformat(expected.replace("Z", "+00:00"))
                except ValueError:
                    return None
                if left.tzinfo is None or right.tzinfo is None:
                    return None
                return left, right
            return None

        def same_json_type(left: Any, right: Any) -> bool:
            if isinstance(left, bool) or isinstance(right, bool):
                return isinstance(left, bool) and isinstance(right, bool)
            if isinstance(left, (int, float)) and isinstance(right, (int, float)):
                return True
            return type(left) is type(right)

        for condition in query:
            field = condition["field"]
            present = field in row or field in row["values"]
            value = row.get(field) if field in row else row["values"].get(field)
            if isinstance(value, dict) and "value" in value:
                value = value["value"]
            operator = condition["operator"]
            expected = condition["value"]
            if operator == "exists":
                matched = present and value is not None
                if bool(expected) != matched:
                    return False, findings
                continue
            if not present:
                return False, findings
            value_errors = json_value_errors(value, path=f"$.query.{field}")
            if value_errors:
                findings.extend(value_errors)
                return False, findings
            if operator in {"eq", "ne"}:
                if not same_json_type(value, expected):
                    findings.append(
                        {
                            "field": field,
                            "code": "query_value_invalid",
                            "message": "query values have incompatible JSON types",
                        }
                    )
                    return False, findings
                matched = value == expected if operator == "eq" else value != expected
            elif operator == "in":
                compatible = [item for item in expected if same_json_type(value, item)]
                if not compatible:
                    findings.append(
                        {
                            "field": field,
                            "code": "query_value_invalid",
                            "message": "query values have incompatible JSON types",
                        }
                    )
                    return False, findings
                matched = value in compatible
            else:
                pair = comparable(value, expected)
                if pair is None:
                    findings.append(
                        {
                            "field": field,
                            "code": "query_value_invalid",
                            "message": "ordered comparison requires finite numbers or timezone-aware timestamps",
                        }
                    )
                    return False, findings
                left, right = pair
                matched = {
                    "lt": left < right,
                    "lte": left <= right,
                    "gt": left > right,
                    "gte": left >= right,
                }[operator]
            if not matched:
                return False, findings
        return True, findings

    @staticmethod
    def _query_matches(row: dict[str, Any], query: list[dict[str, Any]]) -> bool:
        return ReportService._query_evaluate(row, query)[0]

    def _prepare_renderer(
        self,
        definition: dict[str, Any],
        *,
        output_format: str | None,
        media_type: str | None,
    ) -> dict[str, Any]:
        config = definition.get("renderer_config", {})
        if not isinstance(config, dict):
            raise ValidationError("Report renderer_config must be an object")
        require_strict_json(config, path="$.renderer_config")
        renderer_reference = definition.get(
            "renderer_reference", definition.get("renderer")
        )
        if not renderer_reference:
            selected_format = output_format or str(
                definition.get("output_format", "markdown")
            )
            if selected_format not in BUILTIN_RENDERERS:
                raise ValidationError(f"Unsupported core report format: {selected_format}")
            renderer = BUILTIN_RENDERERS[selected_format]
            if media_type and media_type != renderer["mime"]:
                raise ValidationError(
                    "Requested media type does not match the selected builtin Renderer"
                )
            snapshot = {
                "renderer_kind": "builtin",
                "name": renderer["name"],
                "version": renderer["version"],
                "protocol_version": "neutral-report-model/v2",
                "media_type": renderer["mime"],
                "extension": renderer["extension"],
                "deterministic_output": True,
            }
            snapshot["renderer_hash"] = _renderer_hash(selected_format)
            return {
                "renderer_kind": "builtin",
                "renderer_name": renderer["name"],
                "renderer_version": renderer["version"],
                "renderer_hash": snapshot["renderer_hash"],
                "renderer_registration_id": None,
                "renderer_registration_hash": None,
                "renderer_snapshot": snapshot,
                "adapter": None,
                "config": config,
                "config_hash": _hash(config),
                "adapter_limits": {},
                "adapter_limits_hash": _hash({}),
                "output_format": selected_format,
                "media_type": renderer["mime"],
                "extension": renderer["extension"],
            }
        registration = self.manager.registry.resolve(
            str(renderer_reference), kind="report_renderer", for_creation=True
        )
        descriptor = registration["definition"]
        adapter_reference = f"{descriptor['adapter_name']}@{descriptor['adapter_version']}"
        adapter = self.manager.adapters._find(adapter_reference, "report")
        verification = self.manager.adapters.verify(adapter_reference, kind="report")
        if not adapter["enabled"]:
            raise ConflictError(f"Report Renderer Adapter is disabled: {adapter_reference}")
        if not verification["ok"]:
            raise ConflictError(
                "Report Renderer Adapter failed local verification", details=verification
            )
        if descriptor["protocol_version"] != adapter["protocol_version"]:
            raise ConflictError("Report Renderer registration/Adapter protocol mismatch")
        adapter_descriptor = json.loads(adapter.get("descriptor_json", "{}"))
        adapter_limits = self.manager.adapters.limits_snapshot(adapter_descriptor)
        config_errors = validate_json_instance(
            config, descriptor["configuration_schema"], path="$.renderer_config"
        )
        if config_errors:
            raise ValidationError(
                "Report Renderer configuration is invalid",
                details={"errors": config_errors},
            )
        selected_media_type = media_type
        if not selected_media_type and output_format and "/" in output_format:
            selected_media_type = output_format
        selected_media_type = selected_media_type or descriptor["default_media_type"]
        if selected_media_type not in descriptor["supported_media_types"]:
            raise ValidationError(
                f"Report Renderer does not support media type {selected_media_type!r}"
            )
        extension = str(descriptor["default_extension"]).lstrip(".")
        snapshot = {
            "renderer_kind": "adapter",
            "registration_id": registration["registration_id"],
            "registration_content_hash": registration["content_hash"],
            "registration_state": registration["state"],
            "registration_snapshot": registration,
            "adapter_name": adapter["adapter_name"],
            "adapter_version": adapter["adapter_version"],
            "adapter_executable_hash": adapter["executable_hash"],
            "adapter_descriptor_hash": adapter["descriptor_hash"],
            "adapter_protocol_version": adapter["protocol_version"],
            "adapter_state_revision": int(adapter["state_revision"]),
            "adapter_limits": adapter_limits,
            "adapter_limits_hash": _hash(adapter_limits),
            "media_type": selected_media_type,
            "extension": extension,
            "deterministic_output": bool(descriptor["deterministic_output"]),
        }
        snapshot["renderer_hash"] = _hash(snapshot)
        return {
            "renderer_kind": "adapter",
            "renderer_name": registration["name"],
            "renderer_version": registration["version"],
            "renderer_hash": snapshot["renderer_hash"],
            "renderer_registration_id": registration["registration_id"],
            "renderer_registration_hash": registration["content_hash"],
            "renderer_snapshot": snapshot,
            "adapter": adapter,
            "config": config,
            "config_hash": _hash(config),
            "adapter_limits": adapter_limits,
            "adapter_limits_hash": _hash(adapter_limits),
            "output_format": selected_media_type,
            "media_type": selected_media_type,
            "extension": extension,
        }

    def _candidate_records(self, issue_ids: list[str]) -> list[dict[str, Any]]:
        if not issue_ids:
            return []
        placeholders = ",".join("?" for _ in issue_ids)
        return self.store.rows(
            "SELECT r.*,i.issue_type,i.title AS issue_title FROM record_instances r "
            "JOIN issues i ON i.issue_id=r.issue_id WHERE r.lifecycle_status='active' "
            f"AND r.issue_id IN ({placeholders}) ORDER BY r.issue_id,r.record_instance_id",
            tuple(issue_ids),
        )

    @staticmethod
    def _candidate_membership(records, accepted_template_ids):
        # Watch candidates before query/eligibility filtering: excluded rows can
        # become matches too. Runtime counters and audit metadata are not input.
        fields = ("record_instance_id", "current_revision_id", "issue_id",
                  "record_template_registration_id", "issue_type", "issue_title")
        return [
            {key: row[key] for key in fields}
            for row in records
            if accepted_template_ids is None or row["record_template_registration_id"] in accepted_template_ids
        ]

    @staticmethod
    def _validity_state(value, observed_at):
        try:
            expiry = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return "stale" if expiry < observed_at else "fresh"
        except (TypeError, ValueError):
            return "invalid"

    def _temporal_conditions(self, records, accepted_template_ids, columns, observed_at):
        conditions = []
        for record in records:
            if accepted_template_ids is not None and record["record_template_registration_id"] not in accepted_template_ids:
                continue
            revision = self.store.row("SELECT data_json FROM record_revisions WHERE record_revision_id=?", (record["current_revision_id"],))
            if not revision:
                raise ConflictError("Report candidate revision is missing")
            data = json.loads(revision["data_json"])
            for column in columns:
                present, value = _field_value(data, column["field_path"])
                if present and isinstance(value, dict) and value.get("valid_until"):
                    conditions.append({"record_revision_id": record["current_revision_id"],
                                       "field_path": column["field_path"], "valid_until": value["valid_until"],
                                       "state": self._validity_state(value["valid_until"], observed_at)})
        return conditions

    def _eligibility_conditions(self, records, accepted_template_ids, definition):
        from .integrity import active_quarantines

        minimum_status = definition.get("eligibility", {}).get(
            "minimum_conclusion_status", definition.get("minimum_conclusion_status"))
        conditions = []
        for record in records:
            if accepted_template_ids is not None and record["record_template_registration_id"] not in accepted_template_ids:
                continue
            condition = {
                "record_revision_id": record["current_revision_id"],
                "record_quarantines": sorted(item["quarantine_id"] for item in active_quarantines(
                    self.store.conn, "record_revision", record["current_revision_id"], scope="exclude_new_reports")),
                "blocking_obligations": sorted(self.manager.context_obligations.blocking_for_issue(record["issue_id"])),
            }
            if minimum_status:
                conclusion = self.store.row(
                    "SELECT c.conclusion_id,c.status,i.freshness FROM issues i LEFT JOIN conclusion_revisions c "
                    "ON c.conclusion_id=i.current_conclusion_id WHERE i.issue_id=?", (record["issue_id"],))
                condition["conclusion"] = conclusion
                condition["conclusion_quarantines"] = sorted(item["quarantine_id"] for item in active_quarantines(
                    self.store.conn, "conclusion_revision", conclusion["conclusion_id"], scope="exclude_new_reports"
                )) if conclusion and conclusion["conclusion_id"] else []
            conditions.append(condition)
        return conditions

    def prepare(
        self,
        template_reference: str,
        *,
        scope: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
        output_format: str | None = None,
        media_type: str | None = None,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "prepare reproducible report",
    ) -> dict[str, Any]:
        # Read the candidate range, validation inputs and renderer selection in
        # the same transaction that freezes the model. A write reservation also
        # prevents a second connection from changing facts between those reads.
        with self.store.transaction():
            return self._prepare(
                template_reference, scope=scope, query=query, output_format=output_format,
                media_type=media_type, actor=actor, auth=auth, reason=reason)

    def _prepare(
        self,
        template_reference: str,
        *,
        scope: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
        output_format: str | None = None,
        media_type: str | None = None,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "prepare reproducible report",
    ) -> dict[str, Any]:
        actor = self._actor(auth, "report.prepare", actor)
        observed_at = datetime.now().astimezone()
        template = self._template(template_reference)
        definition = template["definition"]
        scope = dict(scope or {})
        requested_query = dict(query or {})
        require_strict_json(requested_query, path="$.query")
        is_v2 = template.get("api_version") == "report-template/v2"
        normalized_scope, issue_ids = self._normalize_scope(
            scope, legacy_wildcard=not is_v2
        )
        accepted_template_ids = self._accepted_template_ids(definition, is_v2=is_v2)
        renderer_selection = self._prepare_renderer(
            definition, output_format=output_format, media_type=media_type
        )
        columns = definition.get("columns", [])
        if not isinstance(columns, list) or not columns:
            raise ValidationError("Report template requires at least one column")
        normalized_columns: list[dict[str, Any]] = []
        for raw_column in columns:
            if not isinstance(raw_column, dict) or not raw_column.get("field_path"):
                raise ValidationError("Report columns require field_path")
            normalized_columns.append(
                {
                    "field_path": str(raw_column["field_path"]),
                    "title": str(raw_column.get("title", raw_column["field_path"])),
                    **{
                        key: raw_column[key]
                        for key in ("unit", "round", "missing_policy")
                        if key in raw_column
                    },
                }
            )
        query_spec = definition.get("query", {})
        if not isinstance(query_spec, dict):
            raise ValidationError("report_template.query must be an object")
        allowed_fields = set(query_spec.get("allowed_fields", [])) or {
            "issue_id", "issue_type", "record_instance_id",
            *(column["field_path"] for column in normalized_columns),
        }
        allowed_operators = set(query_spec.get("allowed_operators", [])) or {
            "eq", "ne", "in", "exists", "lt", "lte", "gt", "gte"
        }
        normalized_query = self._normalize_query(
            requested_query, allowed_fields, allowed_operators
        )
        records = self._candidate_records(issue_ids)
        eligibility = definition.get("eligibility", {})
        if not isinstance(eligibility, dict):
            raise ValidationError("report_template.eligibility must be an object")
        minimum_status = eligibility.get(
            "minimum_conclusion_status", definition.get("minimum_conclusion_status")
        )
        minimum_verification = str(
            eligibility.get("minimum_verification_level", "declared")
        )
        if minimum_verification not in {
            "declared", "source_verified", "snapshot_verified", "reproduced"
        }:
            raise ValidationError("Unsupported Report minimum verification level")
        policy_defaults = (
            {
                "missing": "mark",
                "stale": "mark",
                "disputed": "block",
                "invalid": "block",
            }
            if is_v2
            else {
                "missing": "mark",
                "stale": "mark",
                "disputed": "mark",
                "invalid": "exclude",
            }
        )
        configured_policies = definition.get("field_policies", {})
        if not isinstance(configured_policies, dict):
            raise ValidationError("report_template.field_policies must be an object")
        policies = {**policy_defaults, **configured_policies}
        if any(value not in {"allow", "mark", "exclude", "block"} for value in policies.values()):
            raise ValidationError("Report field policies must be allow, mark, exclude, or block")
        inputs: list[dict[str, Any]] = []
        rows: list[dict[str, Any]] = []
        missing: list[dict[str, Any]] = []
        stale: list[dict[str, Any]] = []
        disputed: list[dict[str, Any]] = []
        invalid: list[dict[str, Any]] = []
        excluded: list[dict[str, Any]] = []
        blockers: list[dict[str, Any]] = []
        conversions: list[dict[str, Any]] = []
        status_order = {"draft": 0, "provisional": 1, "accepted": 2, "canonical": 3}
        proof_order = {"declared": 0, "source_verified": 1, "snapshot_verified": 2, "reproduced": 3}
        from .integrity import active_quarantines

        validation_conditions = []
        for instance in records:
            if (
                accepted_template_ids is not None
                and instance["record_template_registration_id"] not in accepted_template_ids
            ):
                excluded.append(
                    {"record_instance_id": instance["record_instance_id"], "reason": "record_template_not_selected"}
                )
                continue
            revision = self.manager.records.show_revision(instance["current_revision_id"])
            record_quarantines = active_quarantines(
                self.store.conn,
                "record_revision",
                revision["record_revision_id"],
                scope="exclude_new_reports",
            )
            if record_quarantines:
                excluded.append(
                    {
                        "record_instance_id": instance["record_instance_id"],
                        "record_revision_id": revision["record_revision_id"],
                        "reason": "integrity_quarantine",
                        "quarantine_ids": [
                            item["quarantine_id"] for item in record_quarantines
                        ],
                    }
                )
                continue
            if hasattr(self.manager, "context_obligations"):
                obligations = self.manager.context_obligations.blocking_for_issue(instance["issue_id"])
                if obligations:
                    excluded.append({"record_instance_id": instance["record_instance_id"], "reason": "independent_review_required",
                                     "obligation_ids": obligations})
                    continue
            conclusion_input = None
            if minimum_status:
                conclusion_row = self.store.row(
                    "SELECT c.*,i.current_conclusion_id,i.conclusion_status,i.freshness "
                    "FROM issues i LEFT JOIN conclusion_revisions c "
                    "ON c.conclusion_id=i.current_conclusion_id WHERE i.issue_id=?",
                    (instance["issue_id"],),
                )
                if (
                    not conclusion_row
                    or conclusion_row.get("conclusion_id") is None
                    or status_order.get(str(conclusion_row["status"]), -1)
                    < status_order.get(str(minimum_status), 0)
                    or conclusion_row["freshness"] != "fresh"
                ):
                    excluded.append(
                        {
                            "record_instance_id": instance["record_instance_id"],
                            "reason": "conclusion_status_insufficient",
                            "required": minimum_status,
                            "actual": conclusion_row.get("status") if conclusion_row else None,
                        }
                    )
                    continue
                conclusion_quarantines = active_quarantines(
                    self.store.conn,
                    "conclusion_revision",
                    str(conclusion_row["conclusion_id"]),
                    scope="exclude_new_reports",
                )
                if conclusion_quarantines:
                    excluded.append(
                        {
                            "record_instance_id": instance["record_instance_id"],
                            "reason": "integrity_quarantine",
                            "quarantine_ids": [
                                item["quarantine_id"]
                                for item in conclusion_quarantines
                            ],
                        }
                    )
                    continue
                conclusion_snapshot = dict(conclusion_row)
                conclusion_content = {
                    key: value
                    for key, value in conclusion_snapshot.items()
                    if key not in {"current_conclusion_id", "conclusion_status", "freshness"}
                }
                conclusion_input = {
                    "object_type": "conclusion",
                    "object_id": conclusion_row["conclusion_id"],
                    "content_hash": _hash(conclusion_content),
                    "role": "eligibility_conclusion",
                    "snapshot": conclusion_snapshot,
                }
            template_snapshot = revision["template_snapshot"]
            field_specs_raw = template_snapshot.get("definition", {}).get("fields", {})
            if isinstance(field_specs_raw, list):
                field_specs = {
                    item["path"]: {key: value for key, value in item.items() if key != "path"}
                    for item in field_specs_raw
                }
            else:
                field_specs = field_specs_raw
            validation_profile = str(definition.get("record_validation_profile", "report"))
            current_materials = hasattr(self.manager, "context_maintenance")
            material_links = self.manager.records.current_material_links(revision["record_revision_id"])
            if current_materials:
                revision = {**revision, "current_material_relations": material_links}
            validation = self.manager.records.validate_data(
                instance["record_template_registration_id"],
                revision["data"],
                profile=validation_profile,
                evidence_links=material_links,
                include_embedded_evidence=not current_materials,
            )
            if current_materials:
                validation_conditions.append({
                    "record_revision_id": revision["record_revision_id"],
                    "template_registration_id": instance["record_template_registration_id"],
                    "material_links": material_links,
                    "validation": validation,
                })
            invalid_paths = {
                str(item.get("field_path", "")) for item in validation["errors"]
            }
            if not is_v2 and not validation["valid"]:
                excluded.append(
                    {
                        "record_instance_id": instance["record_instance_id"],
                        "record_revision_id": revision["record_revision_id"],
                        "reason": "record_validation_failed",
                        "profile": validation_profile,
                        "errors": validation["errors"],
                    }
                )
                continue
            values: dict[str, Any] = {}
            fields_model: dict[str, Any] = {}
            origins: dict[str, Any] = {}
            exclude_row = False
            row_missing: list[dict[str, Any]] = []
            row_stale: list[dict[str, Any]] = []
            row_disputed: list[dict[str, Any]] = []
            row_invalid: list[dict[str, Any]] = []
            row_excluded: list[dict[str, Any]] = []
            row_blockers: list[dict[str, Any]] = []
            row_conversions: list[dict[str, Any]] = []
            for column in normalized_columns:
                path = column["field_path"]
                present, value = _field_value(revision["data"], path)
                field_links = [
                    link for link in material_links if link["field_path"] == path
                ]
                quality_state = "valid"
                freshness_state = "fresh"
                missing_state = "present"
                state: str | None = None
                additional_states: list[str] = []
                if not present or value is None:
                    state = "missing"
                    missing_state = "missing"
                elif path in invalid_paths:
                    state = "invalid"
                    quality_state = "invalid"
                elif isinstance(value, dict) and value.get("quality") in {"disputed", "invalid"}:
                    state = str(value["quality"])
                    quality_state = state
                if present and isinstance(value, dict) and value.get("valid_until"):
                    validity = self._validity_state(value["valid_until"], observed_at)
                    if validity == "stale":
                        freshness_state = "stale"
                        if state:
                            additional_states.append("stale")
                        else:
                            state = "stale"
                    elif validity == "invalid":
                        state = "invalid"
                        quality_state = "invalid"
                verification_level = max(
                    (str(link.get("verification_level_snapshot") or "declared") for link in field_links),
                    key=lambda level: proof_order.get(level, -1),
                    default="declared",
                )
                if (
                    present
                    and proof_order.get(verification_level, -1)
                    < proof_order[minimum_verification]
                ):
                    state = "invalid"
                    quality_state = "invalid"
                action = policies.get(state, "allow") if state else "allow"
                finding = {
                    "record_instance_id": instance["record_instance_id"],
                    "record_revision_id": revision["record_revision_id"],
                    "field_path": path,
                    "state": state,
                    "policy": action,
                }
                if state == "missing":
                    row_missing.append(finding)
                elif state == "stale":
                    row_stale.append(finding)
                elif state == "disputed":
                    row_disputed.append(finding)
                elif state == "invalid":
                    row_invalid.append(finding)
                if action == "block":
                    row_blockers.append(finding)
                if action == "exclude":
                    exclude_row = True
                    row_excluded.append({**finding, "reason": f"field_{state}"})
                action_priority = {"allow": 0, "mark": 1, "exclude": 2, "block": 3}
                for extra_state in additional_states:
                    extra_action = policies.get(extra_state, "allow")
                    extra_finding = {
                        **finding,
                        "state": extra_state,
                        "policy": extra_action,
                    }
                    if extra_state == "stale":
                        row_stale.append(extra_finding)
                    if extra_action == "block":
                        row_blockers.append(extra_finding)
                    elif extra_action == "exclude":
                        exclude_row = True
                        row_excluded.append(
                            {**extra_finding, "reason": f"field_{extra_state}"}
                        )
                    if action_priority[extra_action] > action_priority[action]:
                        action = extra_action
                converted = None
                conversion = None
                if present and value is not None:
                    try:
                        converted, conversion = self._convert(
                            value, field_specs.get(path, {}), column
                        )
                    except (TypeError, ValueError, ValidationError) as exc:
                        converted = value
                        state = "invalid"
                        action = policies["invalid"]
                        conversion_finding = {
                            "record_instance_id": instance["record_instance_id"],
                            "record_revision_id": revision["record_revision_id"],
                            "field_path": path,
                            "state": "invalid",
                            "policy": action,
                            "code": "unit_conversion_invalid",
                            "message": str(exc),
                        }
                        row_invalid.append(conversion_finding)
                        if action == "block":
                            row_blockers.append(conversion_finding)
                        elif action == "exclude":
                            exclude_row = True
                            row_excluded.append(
                                {**conversion_finding, "reason": "field_invalid"}
                            )
                    if conversion:
                        row_conversions.append(
                            {"record_revision_id": revision["record_revision_id"], "field_path": path, **conversion}
                        )
                values[path] = converted
                marker = state.upper() if state and action == "mark" else None
                display = self._display_value(converted)
                if marker:
                    display = f"[{marker}] {display}".rstrip()
                origins[path] = {
                    "record_revision_id": revision["record_revision_id"],
                    "template_registration_id": instance["record_template_registration_id"],
                    "evidence_links": field_links,
                }
                fields_model[path] = {
                    "display_value": display,
                    "raw_value": value if present else None,
                    "quality_state": quality_state,
                    "freshness_state": freshness_state,
                    "missing_state": missing_state,
                    "verification_level": verification_level,
                    "record_revision_id": revision["record_revision_id"],
                    "evidence_refs": field_links,
                    "policy_action": action,
                }
            row = {
                "issue_id": instance["issue_id"],
                "issue_type": instance["issue_type"],
                "issue_title": instance["issue_title"],
                "record_instance_id": instance["record_instance_id"],
                "record_revision_id": revision["record_revision_id"],
                "values": values,
                "fields": fields_model,
                "origins": origins,
            }
            query_matches, query_findings = self._query_evaluate(row, normalized_query)
            if not query_matches:
                excluded.append(
                    {
                        "record_instance_id": instance["record_instance_id"],
                        "reason": "query_filtered",
                        "query_findings": query_findings,
                    }
                )
                continue
            missing.extend(row_missing)
            stale.extend(row_stale)
            disputed.extend(row_disputed)
            invalid.extend(row_invalid)
            conversions.extend(row_conversions)
            blockers.extend(row_blockers)
            if exclude_row:
                excluded.extend(row_excluded)
                continue
            rows.append(row)
            inputs.append(
                {
                    "object_type": "record_revision",
                    "object_id": revision["record_revision_id"],
                    "content_hash": revision["content_hash"],
                    "role": "report_record",
                    "snapshot": revision,
                }
            )
            if conclusion_input and not any(
                item["object_type"] == "conclusion" and item["object_id"] == conclusion_input["object_id"]
                for item in inputs
            ):
                inputs.append(conclusion_input)
            for link in material_links:
                if link.get("proof_id"):
                    proof = self.store.row(
                        "SELECT * FROM evidence_proofs WHERE proof_id=?", (link["proof_id"],)
                    )
                    if proof and not any(
                        item["object_type"] == "proof" and item["object_id"] == proof["proof_id"]
                        for item in inputs
                    ):
                        inputs.append(
                            {
                                "object_type": "proof", "object_id": proof["proof_id"],
                                "content_hash": proof["proof_hash"], "role": "record_field_proof",
                                "snapshot": proof,
                            }
                        )
                        if proof.get("manifest_id"):
                            manifest = self.store.row(
                                "SELECT * FROM evidence_manifests WHERE manifest_id=?",
                                (proof["manifest_id"],),
                            )
                            if manifest and not any(
                                item["object_type"] == "manifest" and item["object_id"] == manifest["manifest_id"]
                                for item in inputs
                            ):
                                inputs.append(
                                    {
                                        "object_type": "manifest", "object_id": manifest["manifest_id"],
                                        "content_hash": manifest["manifest_hash"], "role": "proof_manifest",
                                        "snapshot": manifest,
                                    }
                                )
        if blockers:
            raise ValidationError(
                "Report field policy blocked prepare", details={"blocked_fields": blockers}
            )
        sort_fields = definition.get("sort", ["issue_id", "record_instance_id"])
        if not isinstance(sort_fields, list):
            raise ValidationError("report_template.sort must be an array")
        rows.sort(
            key=lambda row: tuple(
                canonical_json(row["values"].get(field)) if field in row["values"] else str(row.get(field, ""))
                for field in sort_fields
            )
        )
        report_model: dict[str, Any] = {
            "model_version": "issue-manager-neutral-report/v2",
            "title": str(definition.get("title", template["name"])),
            "template": {
                "registration_id": template["registration_id"],
                "content_hash": template["content_hash"],
                "reference": template["reference"],
            },
            "columns": normalized_columns,
            "rows": rows,
            "provenance": {
                "input_count": len(inputs),
                "record_revision_ids": [
                    item["object_id"] for item in inputs if item["object_type"] == "record_revision"
                ],
                "field_policies": policies,
                "normalized_query": normalized_query,
                "conversions": conversions,
                "normalized_scope": normalized_scope,
            },
        }
        if hasattr(self.manager, "context_maintenance"):
            # Preserve exact resolved identities, while retaining a dynamic
            # subtree/type range rather than freezing its old result IDs.
            watch_scope = {"include_archived": normalized_scope["include_archived"]}
            if normalized_scope["root_issue_id"]:
                watch_scope["root_issue_id"] = normalized_scope["root_issue_id"]
            elif scope.get("issue_ids") is not None or scope.get("issue_id"):
                watch_scope["issue_ids"] = normalized_scope["issue_ids"]
            elif any(key in scope for key in ("issue_type_registration_ids", "issue_type_refs", "issue_type")) or is_v2:
                watch_scope["issue_type_registration_ids"] = normalized_scope["issue_type_registration_ids"]
            report_model["provenance"]["candidate_watch"] = {
                "scope": watch_scope,
                "legacy_wildcard": not is_v2,
                "members": self._candidate_membership(records, accepted_template_ids),
                "time_conditions": self._temporal_conditions(records, accepted_template_ids, normalized_columns, observed_at),
                "eligibility_conditions": self._eligibility_conditions(records, accepted_template_ids, definition),
                "validation_conditions": validation_conditions,
            }
        model_hash = _hash(report_model)
        basis_payload = {
            "template_registration_id": template["registration_id"],
            "template_content_hash": template["content_hash"],
            "renderer_hash": renderer_selection["renderer_hash"],
            "renderer_snapshot": renderer_selection["renderer_snapshot"],
            "renderer_config_hash": renderer_selection["config_hash"],
            "normalized_scope": normalized_scope,
            "normalized_scope_hash": _hash(normalized_scope),
            "query": normalized_query,
            "query_hash": _hash(normalized_query),
            "inputs": sorted(
                ({key: item[key] for key in ("object_type", "object_id", "content_hash", "role")} for item in inputs),
                key=lambda item: (item["object_type"], item["object_id"], item["role"]),
            ),
            "report_model_hash": model_hash,
        }
        basis_hash = _hash(basis_payload)
        build_id = new_id("report_build")
        prepared_at = now()
        with self.store.transaction() as conn:
            adapter = renderer_selection["adapter"] or {}
            build_values = (
                build_id,
                template["registration_id"],
                template["content_hash"],
                canonical_json(template),
                renderer_selection["renderer_name"],
                renderer_selection["renderer_version"],
                renderer_selection["renderer_hash"],
                canonical_json(scope),
                canonical_json(normalized_scope),
                _hash(normalized_scope),
                canonical_json(normalized_query),
                canonical_json(report_model),
                model_hash,
                basis_hash,
                "prepared",
                renderer_selection["output_format"],
                None,
                None,
                None,
                prepared_at,
                None,
                actor,
                renderer_selection["renderer_kind"],
                renderer_selection["renderer_registration_id"],
                renderer_selection["renderer_registration_hash"],
                canonical_json(renderer_selection["renderer_snapshot"]),
                adapter.get("adapter_name"),
                adapter.get("adapter_version"),
                adapter.get("executable_hash"),
                adapter.get("descriptor_hash"),
                adapter.get("protocol_version"),
                adapter.get("state_revision"),
                canonical_json(renderer_selection["config"]),
                renderer_selection["config_hash"],
                renderer_selection["media_type"],
                renderer_selection["extension"],
                canonical_json({}),
                canonical_json(renderer_selection["adapter_limits"]),
                renderer_selection["adapter_limits_hash"],
            )
            conn.execute(
                "INSERT INTO report_builds(report_build_id,report_template_registration_id,"
                "report_template_content_hash,report_template_snapshot_json,renderer_name,"
                "renderer_version,renderer_hash,scope_json,normalized_scope_json,"
                "normalized_scope_hash,query_json,report_model_json,report_model_hash,basis_hash,"
                "state,output_format,output_artifact_id,output_hash,output_path,prepared_at,built_at,"
                "created_by,renderer_kind,renderer_registration_id,renderer_registration_hash,"
                "renderer_snapshot_json,adapter_name,adapter_version,adapter_executable_hash,"
                "adapter_descriptor_hash,adapter_protocol_version,adapter_state_revision,"
                "renderer_config_json,renderer_config_hash,output_media_type,output_extension,"
                "render_receipt_json,adapter_limits_json,adapter_limits_hash) VALUES ("
                + ",".join("?" for _ in build_values)
                + ")",
                build_values,
            )
            for index, item in enumerate(
                sorted(inputs, key=lambda item: (item["object_type"], item["object_id"], item["role"]))
            ):
                conn.execute(
                    "INSERT INTO report_build_inputs VALUES (?,?,?,?,?,?,?)",
                    (
                        build_id,
                        index,
                        item["object_type"],
                        item["object_id"],
                        item["content_hash"],
                        item["role"],
                        canonical_json(item["snapshot"]),
                    ),
                )
            event_id = self.store.audit(
                conn,
                actor=actor,
                action="report.prepare",
                object_type="report_build",
                object_id=build_id,
                before_revision=None,
                after_revision=1,
                reason=reason,
                payload={
                    "basis_hash": basis_hash,
                    "report_model_hash": model_hash,
                    "inputs": len(inputs),
                    "rows": len(rows),
                    "missing": missing,
                    "stale": stale,
                    "disputed": disputed,
                    "invalid": invalid,
                    "excluded": excluded,
                    "normalized_scope": normalized_scope,
                    "renderer_snapshot": renderer_selection["renderer_snapshot"],
                },
            )
        query_filtered_count = sum(
            item.get("reason") == "query_filtered" for item in excluded
        )
        return {
            "report_build_id": build_id,
            "state": "prepared",
            "report_model_hash": model_hash,
            "basis_hash": basis_hash,
            "rows": len(rows),
            "selected_record_count": len(rows),
            "query_filtered_count": query_filtered_count,
            "normalized_scope": normalized_scope,
            "normalized_scope_hash": _hash(normalized_scope),
            "renderer_snapshot": renderer_selection["renderer_snapshot"],
            "renderer_config_hash": renderer_selection["config_hash"],
            "inputs": [{key: item[key] for key in ("object_type", "object_id", "content_hash", "role")} for item in inputs],
            "missing": missing,
            "stale": stale,
            "disputed": disputed,
            "invalid": invalid,
            "excluded": excluded,
            "conversions": conversions,
            "event_id": event_id,
        }

    def _current_hash(self, object_type: str, object_id: str) -> str | None:
        if object_type == "record_revision":
            row = self.store.row(
                "SELECT r.content_hash,i.current_revision_id,i.issue_id FROM record_revisions r "
                "JOIN record_instances i ON i.record_instance_id=r.record_instance_id "
                "WHERE r.record_revision_id=?",
                (object_id,),
            )
            if not row or row["current_revision_id"] != object_id:
                return None
            if hasattr(self.manager, "context_obligations") and self.manager.context_obligations.blocking_for_issue(row["issue_id"]):
                return None
            return row["content_hash"]
        if object_type == "proof":
            row = self.store.row("SELECT proof_hash,verification_state FROM evidence_proofs WHERE proof_id=?", (object_id,))
            return row["proof_hash"] if row and row["verification_state"] == "active" else None
        if object_type == "manifest":
            row = self.store.row("SELECT manifest_hash,superseded_at FROM evidence_manifests WHERE manifest_id=?", (object_id,))
            return row["manifest_hash"] if row and not row["superseded_at"] else None
        if object_type == "conclusion":
            row = self.store.row(
                "SELECT c.* FROM conclusion_revisions c JOIN issues i ON i.issue_id=c.issue_id "
                "WHERE c.conclusion_id=? AND i.current_conclusion_id=c.conclusion_id "
                "AND i.conclusion_status=c.status AND i.freshness='fresh' "
                "AND c.status NOT IN ('disputed','retracted','superseded')",
                (object_id,),
            )
            if row and hasattr(self.manager, "context_obligations") and self.manager.context_obligations.blocking_for_issue(row["issue_id"]):
                return None
            return _hash(row) if row else None
        return None

    @staticmethod
    def _display_value(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, dict) and "value" in value:
            uncertainty = value.get("uncertainty")
            base = str(value["value"])
            if uncertainty is not None:
                base += f" ± {uncertainty}"
            if value.get("unit"):
                base += f" {value['unit']}"
            return base
        if isinstance(value, (dict, list)):
            return canonical_json(value)
        return str(value)

    def _render(self, model: dict[str, Any], output_format: str) -> bytes:
        columns = model["columns"]
        headings = ["Issue", "Record"] + [column["title"] for column in columns]
        rows = [
            [row["issue_id"], row["record_instance_id"]]
            + [
                row.get("fields", {}).get(column["field_path"], {}).get(
                    "display_value", self._display_value(row["values"].get(column["field_path"]))
                )
                for column in columns
            ]
            for row in model["rows"]
        ]
        if output_format == "json":
            return (json.dumps(model, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        if output_format == "csv":
            stream = io.StringIO(newline="")
            writer = csv.writer(stream, lineterminator="\n")
            writer.writerow(headings)
            writer.writerows(rows)
            return stream.getvalue().encode("utf-8")
        def escaped(value: Any) -> str:
            return str(value).replace("|", "\\|").replace("\n", "<br>")

        lines = [f"# {model['title']}", "", "| " + " | ".join(map(escaped, headings)) + " |", "| " + " | ".join("---" for _ in headings) + " |"]
        lines.extend("| " + " | ".join(escaped(value) for value in row) + " |" for row in rows)
        lines.extend(["", f"Report model hash: `{_hash(model)}`", ""])
        return "\n".join(lines).encode("utf-8")

    def build(
        self,
        report_build_id: str,
        *,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "build frozen report artifact",
    ) -> dict[str, Any]:
        failure = None
        result = None
        with self.store.transaction():
            try:
                result = self._build(report_build_id, actor=actor, auth=auth, reason=reason)
            except ConflictError as exc:
                # Input mismatch deliberately persists the stale transition.
                # Other failures must roll back the complete build transaction.
                if not exc.details or "changed_inputs" not in exc.details:
                    raise
                failure = exc
        if failure is not None:
            raise failure
        assert result is not None
        return result

    def _build(
        self,
        report_build_id: str,
        *,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "build frozen report artifact",
    ) -> dict[str, Any]:
        actor = self._actor(auth, "report.build", actor)
        build = self.store.row("SELECT * FROM report_builds WHERE report_build_id=?", (report_build_id,))
        if not build:
            raise NotFoundError(f"Report build not found: {report_build_id}")
        if build["state"] in {"built", "published"}:
            return {
                "report_build_id": report_build_id,
                "state": build["state"],
                "output_artifact_id": build["output_artifact_id"],
                "output_hash": build["output_hash"],
                "output_path": build["output_path"],
                "idempotent_replay": True,
            }
        if build["state"] != "prepared":
            raise ConflictError(f"Report cannot be built from state {build['state']}")
        inputs = self.store.rows(
            "SELECT * FROM report_build_inputs WHERE report_build_id=? ORDER BY input_order",
            (report_build_id,),
        )
        changed: list[dict[str, Any]] = []
        if hasattr(self.manager, "context_maintenance"):
            from .context_resolver import normalized_equal

            prepared_model = json.loads(build["report_model_json"])
            watch = prepared_model.get("provenance", {}).get("candidate_watch")
            if watch is None:
                changed.append({"object_type": "report_query", "object_id": report_build_id,
                                "code": "report_candidate_snapshot_missing", "recovery_action": "prepare"})
            else:
                _, candidate_issues = self._normalize_scope(watch["scope"], legacy_wildcard=watch["legacy_wildcard"])
                frozen_template = json.loads(build["report_template_snapshot_json"])
                accepted = self._accepted_template_ids(
                    frozen_template["definition"], is_v2=frozen_template.get("api_version") == "report-template/v2")
                candidate_records = self._candidate_records(candidate_issues)
                if "validation_conditions" not in watch:
                    changed.append({"object_type": "report_validation", "object_id": report_build_id,
                                    "code": "report_validation_snapshot_missing", "recovery_action": "prepare"})
                else:
                    for condition in watch["validation_conditions"]:
                        revision_id = condition["record_revision_id"]
                        revision = self.manager.records.show_revision(revision_id)
                        links = self.manager.records.current_material_links(revision_id)
                        validation = self.manager.records.validate_data(
                            condition["template_registration_id"], revision["data"],
                            profile=condition["validation"]["profile"], evidence_links=links,
                            include_embedded_evidence=False)
                        if not normalized_equal(condition["material_links"], links) or not normalized_equal(
                                condition["validation"], validation):
                            changed.append({"object_type": "report_validation", "object_id": revision_id,
                                            "code": "report_validation_changed", "recovery_action": "prepare"})
                if "eligibility_conditions" not in watch:
                    changed.append({"object_type": "report_eligibility", "object_id": report_build_id,
                                    "code": "report_eligibility_snapshot_missing", "recovery_action": "prepare"})
                elif not normalized_equal(watch["eligibility_conditions"], self._eligibility_conditions(
                        candidate_records, accepted, frozen_template["definition"])):
                    changed.append({"object_type": "report_eligibility", "object_id": report_build_id,
                                    "code": "report_eligibility_changed", "recovery_action": "prepare"})
                members = self._candidate_membership(candidate_records, accepted)
                if not normalized_equal(watch["members"], members):
                    changed.append({"object_type": "report_query", "object_id": report_build_id,
                                    "code": "report_candidate_membership_changed", "recovery_action": "prepare"})
                if "time_conditions" not in watch:
                    changed.append({"object_type": "report_time", "object_id": report_build_id,
                                    "code": "report_time_snapshot_missing", "recovery_action": "prepare"})
                else:
                    temporal = self._temporal_conditions(candidate_records, accepted,
                                                         prepared_model["columns"], datetime.now().astimezone())
                    if not normalized_equal(watch["time_conditions"], temporal):
                        changed.append({"object_type": "report_time", "object_id": report_build_id,
                                        "code": "report_time_condition_changed", "recovery_action": "prepare"})
        for item in inputs:
            if item["object_type"] == "record_revision":
                from .context_resolver import normalized_equal

                snapshot = json.loads(item["snapshot_json"])
                if hasattr(self.manager, "context_maintenance") and "current_material_relations" not in snapshot:
                    changed.append({"object_type": "record_material_relations", "object_id": item["object_id"],
                                    "code": "record_material_snapshot_missing", "recovery_action": "prepare"})
                elif "current_material_relations" in snapshot and not normalized_equal(
                    snapshot["current_material_relations"], self.manager.records.current_material_links(item["object_id"])
                ):
                    changed.append({"object_type": "record_material_relations", "object_id": item["object_id"],
                                    "code": "record_material_membership_changed"})
            current = self._current_hash(item["object_type"], item["object_id"])
            if current != item["content_hash"]:
                changed.append(
                    {
                        "object_type": item["object_type"],
                        "object_id": item["object_id"],
                        "prepared_hash": item["content_hash"],
                        "current_hash": current,
                    }
                )
        template = self.manager.registry.resolve(
            build["report_template_registration_id"],
            kind="report_template",
            for_creation=False,
        )
        template_actual_hash = _hash(
            {
                key: template[key]
                for key in (
                    "namespace",
                    "kind",
                    "name",
                    "version",
                    "api_version",
                    "definition",
                )
            }
        )
        if (
            template["content_hash"] != build["report_template_content_hash"]
            or template_actual_hash != template["content_hash"]
        ):
            changed.append(
                {"object_type": "report_template", "object_id": template["registration_id"], "prepared_hash": build["report_template_content_hash"], "current_hash": template["content_hash"]}
            )
        prepared_template = json.loads(build["report_template_snapshot_json"])
        if template.get("state") != prepared_template.get("state"):
            changed.append(
                {
                    "object_type": "report_template_state",
                    "object_id": template["registration_id"],
                    "prepared_hash": str(prepared_template.get("state")),
                    "current_hash": str(template.get("state")),
                }
            )
        renderer_snapshot = json.loads(build["renderer_snapshot_json"])
        renderer_payload = {
            key: value
            for key, value in renderer_snapshot.items()
            if key != "renderer_hash"
        }
        if _hash(renderer_payload) != build["renderer_hash"]:
            changed.append(
                {
                    "object_type": "renderer_snapshot",
                    "object_id": build["renderer_name"],
                    "prepared_hash": build["renderer_hash"],
                    "current_hash": _hash(renderer_payload),
                }
            )
        if (
            build["renderer_kind"] == "builtin"
            and _renderer_hash(build["output_format"]) != build["renderer_hash"]
        ):
            changed.append(
                {
                    "object_type": "renderer_implementation",
                    "object_id": build["renderer_name"],
                    "prepared_hash": build["renderer_hash"],
                    "current_hash": _renderer_hash(build["output_format"]),
                }
            )
        adapter_reference = None
        if build["renderer_kind"] == "adapter":
            registration = self.manager.registry.resolve(
                build["renderer_registration_id"],
                kind="report_renderer",
                for_creation=False,
            )
            registration_actual_hash = _hash(
                {
                    key: registration[key]
                    for key in (
                        "namespace",
                        "kind",
                        "name",
                        "version",
                        "api_version",
                        "definition",
                    )
                }
            )
            if (
                registration["content_hash"] != build["renderer_registration_hash"]
                or registration_actual_hash != registration["content_hash"]
                or registration["state"] != renderer_snapshot.get("registration_state")
            ):
                changed.append(
                    {
                        "object_type": "renderer_registration",
                        "object_id": registration["registration_id"],
                        "prepared_hash": build["renderer_registration_hash"],
                        "current_hash": registration["content_hash"],
                    }
                )
            adapter_reference = f"{build['adapter_name']}@{build['adapter_version']}"
            adapter = self.manager.adapters._find_exact(
                kind="report",
                name=str(build["adapter_name"]),
                version=str(build["adapter_version"]),
                executable_hash=str(build["adapter_executable_hash"]),
            )
            if adapter is None:
                changed.append(
                    {
                        "object_type": "adapter_install",
                        "object_id": adapter_reference,
                        "prepared_hash": build["adapter_executable_hash"],
                        "current_hash": None,
                        "code": "renderer_adapter_snapshot_unresolvable",
                    }
                )
                adapter = {
                    "executable_hash": None,
                    "descriptor_hash": None,
                    "protocol_version": None,
                    "state_revision": -1,
                    "enabled": 0,
                }
                verification = {"ok": False}
            else:
                verification = self.manager.adapters._verify_row(adapter)
            prepared_adapter = (
                build["adapter_executable_hash"],
                build["adapter_descriptor_hash"],
                build["adapter_protocol_version"],
                int(build["adapter_state_revision"]),
            )
            current_adapter = (
                adapter["executable_hash"],
                adapter["descriptor_hash"],
                adapter["protocol_version"],
                int(adapter["state_revision"]),
            )
            if not adapter["enabled"] or not verification["ok"] or current_adapter != prepared_adapter:
                changed.append(
                    {
                        "object_type": "adapter_install",
                        "object_id": adapter_reference,
                        "prepared_hash": canonical_json(prepared_adapter),
                        "current_hash": canonical_json(current_adapter),
                        "enabled": bool(adapter["enabled"]),
                        "verification": verification,
                    }
                )
            config = json.loads(build["renderer_config_json"])
            config_errors = validate_json_instance(
                config,
                registration["definition"]["configuration_schema"],
                path="$.renderer_config",
            )
            if config_errors or _hash(config) != build["renderer_config_hash"]:
                changed.append(
                    {
                        "object_type": "renderer_config",
                        "object_id": report_build_id,
                        "prepared_hash": build["renderer_config_hash"],
                        "current_hash": _hash(config),
                        "errors": config_errors,
                    }
                )
            limits = json.loads(build["adapter_limits_json"])
            if (
                _hash(limits) != build["adapter_limits_hash"]
                or (
                    "adapter_limits" in renderer_snapshot
                    and renderer_snapshot.get("adapter_limits") != limits
                )
                or (
                    "adapter_limits_hash" in renderer_snapshot
                    and renderer_snapshot.get("adapter_limits_hash")
                    != build["adapter_limits_hash"]
                )
            ):
                changed.append(
                    {
                        "object_type": "adapter_limits",
                        "object_id": report_build_id,
                        "prepared_hash": build["adapter_limits_hash"],
                        "current_hash": _hash(limits),
                    }
                )
        if changed:
            with self.store.transaction() as conn:
                conn.execute("UPDATE report_builds SET state='stale' WHERE report_build_id=?", (report_build_id,))
            raise ConflictError("Report inputs changed after prepare", details={"changed_inputs": changed})
        model = json.loads(build["report_model_json"])
        if _hash(model) != build["report_model_hash"]:
            raise ConflictError("Stored neutral report model hash is invalid")
        render_receipt: dict[str, Any]
        if build["renderer_kind"] == "builtin":
            content = self._render(model, build["output_format"])
            render_receipt = {
                "renderer_kind": "builtin",
                "renderer_hash": build["renderer_hash"],
                "model_hash": build["report_model_hash"],
            }
        else:
            assert adapter_reference is not None
            execution = self.manager.adapters.execute(
                adapter_reference,
                kind="report",
                payload={
                    "neutral_report_model": model,
                    "neutral_report_model_hash": build["report_model_hash"],
                    "renderer_config": json.loads(build["renderer_config_json"]),
                    "renderer_config_hash": build["renderer_config_hash"],
                    "output_media_type": build["output_media_type"],
                    "output_extension": build["output_extension"],
                },
                expected_identity={
                    "adapter_name": build["adapter_name"],
                    "adapter_version": build["adapter_version"],
                    "adapter_executable_hash": build["adapter_executable_hash"],
                    "adapter_descriptor_hash": build["adapter_descriptor_hash"],
                    "adapter_protocol_version": build["adapter_protocol_version"],
                    "adapter_state_revision": int(build["adapter_state_revision"]),
                },
                limits=json.loads(build["adapter_limits_json"]),
            )
            validated = validate_report_renderer_envelope(
                execution["result"],
                expected_media_type=build["output_media_type"],
                expected_extension=build["output_extension"],
                maximum_decoded_output_bytes=int(
                    json.loads(build["adapter_limits_json"])[
                        "maximum_decoded_output_bytes"
                    ]
                ),
            )
            content = validated["content"]
            metadata = validated["metadata"]
            render_receipt = {
                "renderer_kind": "adapter",
                "renderer_registration_id": build["renderer_registration_id"],
                "renderer_hash": build["renderer_hash"],
                "adapter": adapter_reference,
                "adapter_executable_hash": execution["executable_hash"],
                "adapter_descriptor_hash": execution["descriptor_hash"],
                "model_hash": build["report_model_hash"],
                "metadata": metadata,
                "metadata_hash": validated["metadata_hash"],
                "decoded_bytes": validated["decoded_bytes"],
                "adapter_limits_hash": build["adapter_limits_hash"],
            }
        if hasattr(self.manager, "context_maintenance"):
            # SQLite reservations cannot stop wall-clock conditions changing
            # while an external renderer runs. Recheck before writing outputs.
            temporal = self._temporal_conditions(candidate_records, accepted,
                                                 prepared_model["columns"], datetime.now().astimezone())
            if not normalized_equal(watch["time_conditions"], temporal):
                with self.store.transaction() as conn:
                    conn.execute("UPDATE report_builds SET state='stale' WHERE report_build_id=?", (report_build_id,))
                raise ConflictError("Report time conditions changed during rendering", details={"changed_inputs": [
                    {"object_type": "report_time", "object_id": report_build_id,
                     "code": "report_time_condition_changed", "phase": "after_render", "recovery_action": "prepare"}]})
        output_hash = hashlib.sha256(content).hexdigest()
        object_path = self.store.ledger_dir / "artifacts" / "objects" / "sha256" / output_hash[:2] / output_hash
        existing_artifact = self.store.row("SELECT * FROM artifacts WHERE sha256=?", (output_hash,))
        if existing_artifact and (
            existing_artifact["size"] != len(content)
            or existing_artifact["storage_uri"] != object_path.relative_to(self.store.ledger_dir).as_posix()
            or not object_path.is_file()
        ):
            raise ConflictError("Existing report Artifact metadata or storage is inconsistent",
                                details={"code": "report_artifact_storage_mismatch", "artifact_id": existing_artifact["artifact_id"]})
        if object_path.exists():
            if not object_path.is_file() or object_path.read_bytes() != content:
                raise ConflictError("Content-addressed report object does not match rendered content",
                                    details={"code": "report_object_content_mismatch", "sha256": output_hash})
        else:
            object_path.parent.mkdir(parents=True, exist_ok=True)
            object_temporary = object_path.with_suffix(f".tmp-{new_id('report')}")
            try:
                object_temporary.write_bytes(content)
                if object_temporary.read_bytes() != content:
                    raise ConflictError("Stored report content changed", details={"code": "report_object_content_mismatch"})
                os.replace(object_temporary, object_path)
            finally:
                object_temporary.unlink(missing_ok=True)
        output_dir = self.store.ledger_dir / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{report_build_id}.{build['output_extension']}"
        temporary = output_path.with_suffix(
            f".{build['output_extension']}.tmp-{os.getpid()}"
        )
        temporary.write_bytes(content)
        os.replace(temporary, output_path)
        artifact_id = existing_artifact["artifact_id"] if existing_artifact else new_id("artifact")
        built_at = now()
        with self.store.transaction() as conn:
            if not existing_artifact:
                conn.execute(
                    "INSERT INTO artifacts(artifact_id,kind,role,mime_type,sha256,size,storage_uri,"
                    "original_locator,created_at,created_by,frozen_at) VALUES (?,?,'frozen',?,?,?,?,?,?,?,?)",
                    (
                        artifact_id,
                        f"report-{build['output_extension']}",
                        build["output_media_type"],
                        output_hash,
                        len(content),
                        object_path.relative_to(self.store.ledger_dir).as_posix(),
                        str(output_path),
                        built_at,
                        actor,
                        built_at,
                    ),
                )
            conn.execute(
                "INSERT OR IGNORE INTO artifact_locations VALUES (?,?,?)",
                (artifact_id, str(output_path), built_at),
            )
            conn.execute(
                "UPDATE report_builds SET state='built',output_artifact_id=?,output_hash=?,"
                "output_path=?,built_at=?,render_receipt_json=? "
                "WHERE report_build_id=? AND state='prepared'",
                (
                    artifact_id,
                    output_hash,
                    str(output_path),
                    built_at,
                    canonical_json({**render_receipt, "output_hash": output_hash}),
                    report_build_id,
                ),
            )
            event_id = self.store.audit(
                conn,
                actor=actor,
                action="report.build",
                object_type="report_build",
                object_id=report_build_id,
                before_revision=1,
                after_revision=2,
                reason=reason,
                payload={
                    "basis_hash": build["basis_hash"],
                    "report_model_hash": build["report_model_hash"],
                    "output_hash": output_hash,
                    "output_artifact_id": artifact_id,
                    "renderer_hash": build["renderer_hash"],
                    "render_receipt": render_receipt,
                },
            )
        self.manager.artifacts._write_manifest(artifact_id)
        return {
            "report_build_id": report_build_id,
            "state": "built",
            "basis_hash": build["basis_hash"],
            "report_model_hash": build["report_model_hash"],
            "output_hash": output_hash,
            "output_artifact_id": artifact_id,
            "output_path": str(output_path),
            "event_id": event_id,
            "renderer_snapshot": renderer_snapshot,
            "render_receipt": {**render_receipt, "output_hash": output_hash},
            "idempotent_replay": False,
        }

    def show(self, report_build_id: str) -> dict[str, Any]:
        build = self.store.row("SELECT * FROM report_builds WHERE report_build_id=?", (report_build_id,))
        if not build:
            raise NotFoundError(f"Report build not found: {report_build_id}")
        result = dict(build)
        for source, target in (
            ("report_template_snapshot_json", "report_template_snapshot"),
            ("scope_json", "scope"),
            ("normalized_scope_json", "normalized_scope"),
            ("query_json", "query"),
            ("report_model_json", "report_model"),
            ("renderer_snapshot_json", "renderer_snapshot"),
            ("renderer_config_json", "renderer_config"),
            ("render_receipt_json", "render_receipt"),
        ):
            result[target] = json.loads(result.pop(source))
        result["inputs"] = []
        for item in self.store.rows(
            "SELECT * FROM report_build_inputs WHERE report_build_id=? ORDER BY input_order",
            (report_build_id,),
        ):
            item["snapshot"] = json.loads(item.pop("snapshot_json"))
            result["inputs"].append(item)
        from .integrity import active_quarantines

        quarantines = active_quarantines(
            self.store.conn, "report_build", report_build_id
        )
        if result.get("output_artifact_id"):
            quarantines.extend(
                active_quarantines(
                    self.store.conn,
                    "artifact",
                    str(result["output_artifact_id"]),
                )
            )
        result["quarantined"] = bool(quarantines)
        result["quarantines"] = quarantines
        return result

    def renderer_identity(self, report_build_id: str) -> dict[str, Any]:
        shown = self.show(report_build_id)
        snapshot = shown["renderer_snapshot"]
        findings: list[dict[str, Any]] = []
        unavailable = False
        snapshot_payload = {key: value for key, value in snapshot.items() if key != "renderer_hash"}
        actual_snapshot_hash = _hash(snapshot_payload)
        if actual_snapshot_hash != shown["renderer_hash"]:
            findings.append(
                {
                    "code": "renderer_snapshot_hash_mismatch",
                    "expected": shown["renderer_hash"],
                    "actual": actual_snapshot_hash,
                }
            )
        if shown["renderer_kind"] == "builtin":
            if _renderer_hash(shown["output_format"]) != shown["renderer_hash"]:
                findings.append({"code": "renderer_builtin_identity_drift"})
        else:
            registration = self.store.row(
                "SELECT * FROM registry_entries WHERE registration_id=?",
                (shown["renderer_registration_id"],),
            )
            if not registration:
                unavailable = True
                findings.append({"code": "renderer_registration_unavailable"})
            else:
                try:
                    definition = json.loads(registration["definition_json"])
                    registration_hash = _hash(
                        {
                            "namespace": registration["namespace"],
                            "kind": registration["kind"],
                            "name": registration["name"],
                            "version": registration["version"],
                            "api_version": registration["api_version"],
                            "definition": definition,
                        }
                    )
                except (json.JSONDecodeError, TypeError, ValidationError):
                    registration_hash = None
                registration_checks = {
                    "registration_content_hash": (
                        shown["renderer_registration_hash"],
                        registration["content_hash"],
                    ),
                    "registration_actual_hash": (
                        shown["renderer_registration_hash"],
                        registration_hash,
                    ),
                    "registration_state": (
                        snapshot.get("registration_state"),
                        registration["state"],
                    ),
                }
                for code, (expected, actual) in registration_checks.items():
                    if expected != actual:
                        findings.append(
                            {"code": code, "expected": expected, "actual": actual}
                        )
            adapter = self.manager.adapters._find_exact(
                kind="report",
                name=str(shown["adapter_name"]),
                version=str(shown["adapter_version"]),
                executable_hash=str(shown["adapter_executable_hash"]),
            )
            if adapter is None:
                unavailable = True
                findings.append({"code": "renderer_adapter_snapshot_unresolvable"})
            else:
                verification = self.manager.adapters._verify_row(adapter)
                adapter_checks = {
                    "adapter_descriptor_hash": (
                        shown["adapter_descriptor_hash"],
                        adapter["descriptor_hash"],
                    ),
                    "adapter_protocol_version": (
                        shown["adapter_protocol_version"],
                        adapter["protocol_version"],
                    ),
                    "adapter_state_revision": (
                        int(shown["adapter_state_revision"]),
                        int(adapter["state_revision"]),
                    ),
                    "adapter_enabled": (True, bool(adapter["enabled"])),
                    "adapter_verified": (True, bool(verification["ok"])),
                }
                for code, (expected, actual) in adapter_checks.items():
                    if expected != actual:
                        findings.append(
                            {"code": code, "expected": expected, "actual": actual}
                        )
            limits = shown["adapter_limits_json"]
            try:
                parsed_limits = json.loads(limits)
            except (json.JSONDecodeError, TypeError):
                parsed_limits = None
            if (
                parsed_limits is None
                or _hash(parsed_limits) != shown["adapter_limits_hash"]
                or (
                    "adapter_limits" in snapshot
                    and snapshot.get("adapter_limits") != parsed_limits
                )
                or (
                    "adapter_limits_hash" in snapshot
                    and snapshot.get("adapter_limits_hash")
                    != shown["adapter_limits_hash"]
                )
            ):
                findings.append({"code": "adapter_limit_snapshot_invalid"})
        if _hash(shown["renderer_config"]) != shown["renderer_config_hash"]:
            findings.append({"code": "renderer_config_hash_mismatch"})
        if (
            snapshot.get("media_type") != shown["output_media_type"]
            or snapshot.get("extension") != shown["output_extension"]
        ):
            findings.append({"code": "renderer_output_identity_mismatch"})
        return {
            "report_build_id": report_build_id,
            "status": "unavailable" if unavailable else ("drifted" if findings else "matched"),
            "findings": findings,
            "renderer_kind": shown["renderer_kind"],
            "renderer_hash": shown["renderer_hash"],
            "renderer_registration_id": shown["renderer_registration_id"],
            "adapter_executable_hash": shown["adapter_executable_hash"],
            "adapter_descriptor_hash": shown["adapter_descriptor_hash"],
            "adapter_state_revision": shown["adapter_state_revision"],
            "renderer_config_hash": shown["renderer_config_hash"],
            "adapter_limits_hash": shown["adapter_limits_hash"],
            "output_media_type": shown["output_media_type"],
            "output_extension": shown["output_extension"],
        }

    def reproduce(
        self, report_build_id: str, *, rerun_renderer: bool = False
    ) -> dict[str, Any]:
        shown = self.show(report_build_id)
        model_hash_valid = _hash(shown["report_model"]) == shown["report_model_hash"]
        artifact_verification: dict[str, Any]
        if shown["output_artifact_id"]:
            artifact_verification = self.manager.artifacts.verify(
                shown["output_artifact_id"]
            )
            artifact_hash_valid = bool(
                artifact_verification["ok"]
                and artifact_verification["expected_sha256"] == shown["output_hash"]
            )
        else:
            artifact_verification = {
                "artifact_id": None,
                "ok": False,
                "exists": False,
                "sha256": None,
                "expected_sha256": shown["output_hash"],
            }
            artifact_hash_valid = False
        identity = self.renderer_identity(report_build_id)
        actual_hash: str | None = None
        attempted = False
        envelope_valid: bool | None = None
        output_hash_match: bool | None = None
        deterministic = bool(shown["renderer_snapshot"].get("deterministic_output", True))
        should_rerun = shown["renderer_kind"] == "builtin" or rerun_renderer
        if shown["renderer_kind"] == "builtin":
            if identity["status"] == "matched":
                content = self._render(shown["report_model"], shown["output_format"])
                actual_hash = hashlib.sha256(content).hexdigest()
                attempted = True
                envelope_valid = True
                output_hash_match = shown["output_hash"] in {None, actual_hash}
        elif should_rerun and identity["status"] == "matched":
            adapter_reference = f"{shown['adapter_name']}@{shown['adapter_version']}"
            execution = self.manager.adapters.execute(
                adapter_reference,
                kind="report",
                payload={
                    "neutral_report_model": shown["report_model"],
                    "neutral_report_model_hash": shown["report_model_hash"],
                    "renderer_config": shown["renderer_config"],
                    "renderer_config_hash": shown["renderer_config_hash"],
                    "output_media_type": shown["output_media_type"],
                    "output_extension": shown["output_extension"],
                },
                expected_identity={
                    "adapter_name": shown["adapter_name"],
                    "adapter_version": shown["adapter_version"],
                    "adapter_executable_hash": shown["adapter_executable_hash"],
                    "adapter_descriptor_hash": shown["adapter_descriptor_hash"],
                    "adapter_protocol_version": shown["adapter_protocol_version"],
                    "adapter_state_revision": int(shown["adapter_state_revision"]),
                },
                limits=json.loads(shown["adapter_limits_json"]),
            )
            validated = validate_report_renderer_envelope(
                execution["result"],
                expected_media_type=shown["output_media_type"],
                expected_extension=shown["output_extension"],
                maximum_decoded_output_bytes=int(
                    json.loads(shown["adapter_limits_json"])[
                        "maximum_decoded_output_bytes"
                    ]
                ),
            )
            actual_hash = validated["content_hash"]
            attempted = True
            envelope_valid = True
            output_hash_match = (
                shown["output_hash"] in {None, actual_hash} if deterministic else None
            )
        if attempted and deterministic:
            execution_reproducible: bool | str | None = bool(
                identity["status"] == "matched"
                and envelope_valid
                and output_hash_match
            )
        elif attempted:
            execution_reproducible = "not_applicable"
        elif should_rerun:
            execution_reproducible = False
        else:
            execution_reproducible = None
        legacy_reproducible = bool(model_hash_valid and artifact_hash_valid)
        if should_rerun:
            legacy_reproducible = legacy_reproducible and (
                execution_reproducible is True
                or execution_reproducible == "not_applicable"
            )
        return {
            "report_build_id": report_build_id,
            "artifact_integrity": {
                "model_hash_valid": model_hash_valid,
                "artifact_hash_valid": artifact_hash_valid,
                "artifact_verification": artifact_verification,
            },
            "renderer_identity": identity,
            "rerun": {
                "requested": rerun_renderer,
                "attempted": attempted,
                "envelope_valid": envelope_valid,
                "deterministic_output": deterministic,
                "output_hash_match": output_hash_match,
                "actual_output_hash": actual_hash,
            },
            "execution_reproducible": execution_reproducible,
            "reproducible": legacy_reproducible,
            "reproducible_deprecated": True,
            "expected_output_hash": shown["output_hash"],
            "actual_output_hash": actual_hash,
            "report_model_hash_valid": model_hash_valid,
            "renderer_rerun": attempted,
            "renderer_snapshot": shown["renderer_snapshot"],
            "basis_hash": shown["basis_hash"],
        }

    def explain_field(
        self, report_build_id: str, row: int | str, field_path: str
    ) -> dict[str, Any]:
        shown = self.show(report_build_id)
        rows = shown["report_model"]["rows"]
        selected: dict[str, Any] | None = None
        if isinstance(row, int):
            if row < 0 or row >= len(rows):
                raise NotFoundError(f"Report row index is out of range: {row}")
            selected = rows[row]
        else:
            selected = next(
                (
                    item
                    for item in rows
                    if item.get("record_instance_id") == row
                    or item.get("record_revision_id") == row
                ),
                None,
            )
        if not selected:
            raise NotFoundError(f"Report row not found: {row}")
        field = selected.get("fields", {}).get(field_path)
        if not field:
            raise NotFoundError(f"Report field not found: {field_path}")
        origin = selected.get("origins", {}).get(field_path, {})
        conversions = [
            item
            for item in shown["report_model"].get("provenance", {}).get("conversions", [])
            if item.get("record_revision_id") == selected.get("record_revision_id")
            and item.get("field_path") == field_path
        ]
        return {
            "report_build_id": report_build_id,
            "row": row,
            "field_path": field_path,
            "field": field,
            "record_revision_id": selected["record_revision_id"],
            "evidence_proof_manifest": origin.get("evidence_links", []),
            "policy_action": field["policy_action"],
            "unit_conversions": conversions,
            "basis_hash": shown["basis_hash"],
        }
