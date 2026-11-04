from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable

from .errors import ConflictError, NotFoundError, PermissionError, ValidationError
from .store import canonical_json, new_id, now
from .strict_json import json_value_errors, require_strict_json

if TYPE_CHECKING:
    import sqlite3

    from .security import AuthContext
    from .service import IssueManager


BUNDLE_FORMAT = "issue-manager-feature-bundle/v1"
SUPPORTED_KINDS = {
    "issue_type",
    "issue_template",
    "evidence_intake_template",
    "question_template",
    "conclusion_summary_template",
    "record_template",
    "report_template",
    "routing_profile",
    "mapping_profile",
    "unit_catalog",
    "import_adapter",
    "report_renderer",
}
EXECUTABLE_KINDS = {"import_adapter"}
_IDENTITY = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")
_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
_FULL_REF = re.compile(
    r"^(?P<namespace>[a-z0-9][a-z0-9._-]*)/(?P<kind>[a-z_]+)/"
    r"(?P<name>[a-z0-9][a-z0-9._-]*)@(?P<version>[^@/]+)$"
)
_FORBIDDEN_KEYS = {
    "eval",
    "python",
    "python_code",
    "dynamic_import",
    "sql",
    "shell",
    "shell_command",
    "environment_variable",
    "secret",
    "secret_name",
    "network_url",
    "fetch_url",
}
_FORBIDDEN_TEXT = ("__import__(", "eval(", "exec(", "subprocess.", "os.system(")
_PUBLICATION_STATUSES = {
    "draft",
    "provisional",
    "accepted",
    "canonical",
    "disputed",
    "superseded",
    "retracted",
}
_REFERENCE_KEYS: dict[str, str] = {
    "allowed_children": "issue_type",
    "applies_to_issue_types": "issue_type",
    "issue_type": "issue_type",
    "target_issue_type": "issue_type",
    "target_issue_types": "issue_type",
    "issue_type_refs": "issue_type",
    "record_templates": "record_template",
    "record_template_refs": "record_template",
    "record_template": "record_template",
    "target_record_template": "record_template",
    "target_template": "record_template",
    "renderer": "report_renderer",
    "renderer_reference": "report_renderer",
    "unit_catalog": "unit_catalog",
    "evidence_intake_template": "evidence_intake_template",
    "question_template": "question_template",
    "conclusion_summary_template": "conclusion_summary_template",
}


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _semver(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise ValidationError(f"Invalid semantic version: {value!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _version_matches(version: str, expression: str) -> bool:
    actual = _semver(version)
    for raw_clause in (part.strip() for part in expression.split(",")):
        if not raw_clause or raw_clause == "*":
            continue
        match = re.fullmatch(r"(>=|<=|>|<|==|=|\^|~)?\s*(\d+\.\d+(?:\.\d+)?)", raw_clause)
        if not match:
            raise ValidationError(f"Unsupported version range clause: {raw_clause!r}")
        operator = match.group(1) or "="
        pieces = [int(part) for part in match.group(2).split(".")]
        while len(pieces) < 3:
            pieces.append(0)
        wanted = tuple(pieces)
        if operator in {"=", "=="} and actual != wanted:
            return False
        if operator == ">=" and actual < wanted:
            return False
        if operator == "<=" and actual > wanted:
            return False
        if operator == ">" and actual <= wanted:
            return False
        if operator == "<" and actual >= wanted:
            return False
        if operator == "^" and not (actual >= wanted and actual < (wanted[0] + 1, 0, 0)):
            return False
        if operator == "~" and not (
            actual >= wanted and actual < (wanted[0], wanted[1] + 1, 0)
        ):
            return False
    return True


def _validate_declarative(value: Any, *, path: str = "definition") -> None:
    require_strict_json(value, path=path)
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, str):
        lowered = value.casefold()
        if any(marker in lowered for marker in _FORBIDDEN_TEXT):
            raise ValidationError(f"Executable expression is forbidden at {path}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_declarative(item, path=f"{path}[{index}]")
        return
    if not isinstance(value, dict):
        raise ValidationError(f"Registry value at {path} is not JSON-compatible")
    for key, item in value.items():
        if not isinstance(key, str):
            raise ValidationError(f"Registry object key at {path} must be a string")
        if key.casefold() in _FORBIDDEN_KEYS:
            raise ValidationError(f"Forbidden executable registry key at {path}.{key}")
        _validate_declarative(item, path=f"{path}.{key}")


def _validate_json_schema_definition(schema: Any, *, path: str) -> None:
    """Validate the deliberately small JSON-Schema subset accepted by the core."""
    if not isinstance(schema, dict):
        raise ValidationError(f"{path} must be an object")
    if not schema:
        return
    allowed = {
        "type", "required", "properties", "additionalProperties", "items", "enum",
        "minimum", "maximum", "minItems", "maxItems", "description",
    }
    unknown = sorted(set(schema) - allowed)
    if unknown:
        raise ValidationError(f"Unsupported schema fields at {path}: {unknown}")
    schema_type = schema.get("type")
    if schema_type not in {"object", "array", "string", "number", "integer", "boolean", "null"}:
        raise ValidationError(f"Unsupported schema type at {path}: {schema_type!r}")
    if "enum" in schema and (
        not isinstance(schema["enum"], list) or not schema["enum"]
    ):
        raise ValidationError(f"{path}.enum must be a non-empty array")
    if schema_type == "object":
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list) or any(
            not isinstance(item, str) for item in required
        ):
            raise ValidationError(f"{path} object schema has invalid properties/required")
        if not set(required).issubset(properties):
            raise ValidationError(f"{path}.required references undeclared properties")
        additional = schema.get("additionalProperties", True)
        if not isinstance(additional, bool):
            raise ValidationError(f"{path}.additionalProperties must be boolean")
        for name, child in properties.items():
            if not isinstance(name, str):
                raise ValidationError(f"{path}.properties keys must be strings")
            _validate_json_schema_definition(child, path=f"{path}.properties.{name}")
    if schema_type == "array":
        if "items" not in schema:
            raise ValidationError(f"{path}.items is required for arrays")
        _validate_json_schema_definition(schema["items"], path=f"{path}.items")


def build_issue_type_semantics(
    name: str,
    api_version: str,
    definition: dict[str, Any],
    *,
    legacy_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the frozen issue-type/v2 semantics for native and legacy registrations."""
    if api_version == "issue-type/v3":
        allowed = {
            "allowed_children",
            "rollup_mode",
            "conclusion",
            "rollup_policy",
            "evidence_intake_template",
            "question_template",
            "conclusion_summary_template",
        }
        unknown = sorted(set(definition) - allowed)
        if unknown:
            raise ValidationError(f"Unknown issue-type/v3 fields: {unknown}")
        base = build_issue_type_semantics(
            name,
            "issue-type/v2",
            {
                key: definition[key]
                for key in ("allowed_children", "rollup_mode", "conclusion")
                if key in definition
            },
        )
        from .rollup_service import RollupService

        base["rollup_policy"] = RollupService.normalize_policy(
            definition.get("rollup_policy", {"mode": "local_only"})
        )
        for key in (
            "evidence_intake_template",
            "question_template",
            "conclusion_summary_template",
        ):
            value = definition.get(key)
            if value is not None and not isinstance(value, str):
                raise ValidationError(f"issue-type/v3 {key} must be an exact registry reference")
            if value is not None:
                base[key] = value
        return base
    if api_version == "issue-type/v2":
        allowed = {"allowed_children", "rollup_mode", "conclusion"}
        unknown = sorted(set(definition) - allowed)
        if unknown:
            raise ValidationError(f"Unknown issue-type/v2 fields: {unknown}")
        children = definition.get("allowed_children", [])
        if not isinstance(children, list) or any(not isinstance(item, str) for item in children):
            raise ValidationError("issue-type/v2 allowed_children must be a string array")
        rollup_mode = definition.get("rollup_mode", "semantic")
        if rollup_mode not in {"semantic", "mechanical", "mixed"}:
            raise ValidationError(f"Unsupported issue type rollup_mode: {rollup_mode!r}")
        conclusion = definition.get("conclusion", {})
        if not isinstance(conclusion, dict):
            raise ValidationError("issue-type/v2 conclusion must be an object")
        unknown_conclusion = sorted(
            set(conclusion)
            - {"structured_outputs_schema", "publication_profiles", "report_facing"}
        )
        if unknown_conclusion:
            raise ValidationError(
                f"Unknown issue-type/v2 conclusion fields: {unknown_conclusion}"
            )
        schema = conclusion.get(
            "structured_outputs_schema",
            {"type": "object", "properties": {}, "additionalProperties": True},
        )
        _validate_json_schema_definition(schema, path="conclusion.structured_outputs_schema")
        profiles = conclusion.get("publication_profiles", {})
        if not isinstance(profiles, dict):
            raise ValidationError("conclusion.publication_profiles must be an object")
        normalized_profiles: dict[str, dict[str, Any]] = {}
        profile_fields = {
            "min_active_evidence",
            "minimum_verification_level",
            "review_quorum",
            "require_support_fit_for_use",
            "reject_conflict_as_only_support",
            "require_frozen_artifact",
            "require_analysis_run_or_waiver",
            "derived_result_requires_frozen_analysis",
        }
        for status, raw_profile in profiles.items():
            if status not in _PUBLICATION_STATUSES or not isinstance(raw_profile, dict):
                raise ValidationError(f"Invalid publication profile: {status!r}")
            unknown_profile = sorted(set(raw_profile) - profile_fields)
            if unknown_profile:
                raise ValidationError(
                    f"Unknown publication profile fields for {status}: {unknown_profile}"
                )
            profile = dict(raw_profile)
            for integer_key in ("min_active_evidence", "review_quorum"):
                value = profile.get(integer_key, 0)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ValidationError(f"{status}.{integer_key} must be a non-negative integer")
                profile[integer_key] = value
            level = profile.get("minimum_verification_level", "declared")
            if level not in {"declared", "source_verified", "snapshot_verified", "reproduced"}:
                raise ValidationError(f"Unsupported verification level in {status}: {level!r}")
            profile["minimum_verification_level"] = level
            normalized_profiles[str(status)] = profile
        if "provisional" not in normalized_profiles:
            normalized_profiles["provisional"] = {
                "min_active_evidence": 0,
                "minimum_verification_level": "declared",
                "review_quorum": 0,
            }
        return {
            "allowed_children": list(children),
            "rollup_mode": rollup_mode,
            "conclusion": {
                "structured_outputs_schema": schema,
                "publication_profiles": normalized_profiles,
                "report_facing": bool(conclusion.get("report_facing", False)),
            },
        }

    policy = legacy_policy
    if policy is None:
        from .compatibility import COMPAT_POLICY

        policy = COMPAT_POLICY
    schema_name = definition.get("conclusion_schema")
    legacy_schemas = policy.get("conclusion_schemas", {})
    legacy_schema = (
        legacy_schemas.get(str(schema_name), {})
        if isinstance(legacy_schemas, dict) and schema_name is not None
        else {}
    )
    required = list(legacy_schema.get("required", [])) if isinstance(legacy_schema, dict) else []
    properties: dict[str, Any] = {str(item): {} for item in required}
    publication = policy.get("publication", {}) if isinstance(policy, dict) else {}
    requirements = policy.get("publication_requirements", {}) if isinstance(policy, dict) else {}
    review_quorum = publication.get("review_quorum", {}) if isinstance(publication, dict) else {}
    legacy_profiles: dict[str, dict[str, Any]] = {}
    for status in _PUBLICATION_STATUSES:
        base = requirements.get(status, {}) if isinstance(requirements, dict) else {}
        if not isinstance(base, dict):
            base = {}
        profile = dict(base)
        profile["review_quorum"] = int(profile.get("review_quorum", review_quorum.get(status, 0)))
        profile.setdefault("min_active_evidence", 0)
        profile.setdefault("minimum_verification_level", "declared")
        legacy_profiles[status] = profile
    report_facing = name == "report_scope"
    if report_facing and isinstance(requirements.get("report_scope"), dict):
        for status in legacy_profiles:
            legacy_profiles[status].update(requirements["report_scope"])
        minimum_reviews = int(publication.get("report_facing_minimum_reviews", 0))
        for status in legacy_profiles:
            legacy_profiles[status]["review_quorum"] = max(
                int(legacy_profiles[status].get("review_quorum", 0)), minimum_reviews
            )
    return build_issue_type_semantics(
        name,
        "issue-type/v2",
        {
            "allowed_children": list(definition.get("allowed_children", [])),
            "rollup_mode": definition.get("rollup_mode", "semantic"),
            "conclusion": {
                "structured_outputs_schema": {
                    "type": "object",
                    "required": required,
                    "properties": properties,
                    "additionalProperties": True,
                },
                "publication_profiles": legacy_profiles,
                "report_facing": report_facing,
            },
        },
    )


def validate_json_instance(value: Any, schema: dict[str, Any], *, path: str = "$") -> list[dict[str, str]]:
    strict_errors = json_value_errors(value, path=path)
    if strict_errors:
        return strict_errors
    errors: list[dict[str, str]] = []
    if not schema:
        return errors
    expected = str(schema.get("type", ""))
    matches = {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "number": isinstance(value, (int, float))
        and not isinstance(value, bool)
        and (not isinstance(value, float) or math.isfinite(value)),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)
    if not matches:
        return [{"path": path, "code": "type", "message": f"expected {expected}"}]
    if "enum" in schema and value not in schema["enum"]:
        errors.append({"path": path, "code": "enum", "message": "value is not allowed"})
    if expected == "object":
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                errors.append({"path": f"{path}.{name}", "code": "required", "message": "field is required"})
        if schema.get("additionalProperties") is False:
            for name in sorted(set(value) - set(properties)):
                errors.append({"path": f"{path}.{name}", "code": "unknown", "message": "additional field is forbidden"})
        for name, child in properties.items():
            if name in value:
                errors.extend(validate_json_instance(value[name], child, path=f"{path}.{name}"))
    elif expected == "array":
        if "minItems" in schema and len(value) < int(schema["minItems"]):
            errors.append({"path": path, "code": "minItems", "message": "array is too short"})
        if "maxItems" in schema and len(value) > int(schema["maxItems"]):
            errors.append({"path": path, "code": "maxItems", "message": "array is too long"})
        for index, item in enumerate(value):
            errors.extend(validate_json_instance(item, schema["items"], path=f"{path}[{index}]"))
    elif expected in {"number", "integer"}:
        if "minimum" in schema and value < schema["minimum"]:
            errors.append({"path": path, "code": "minimum", "message": "number is too small"})
        if "maximum" in schema and value > schema["maximum"]:
            errors.append({"path": path, "code": "maximum", "message": "number is too large"})
    return errors


def _validate_report_template_v2(definition: dict[str, Any]) -> None:
    allowed = {
        "title", "record_templates", "record_template_refs", "columns", "sort",
        "output_format", "record_validation_profile", "eligibility", "field_policies",
        "query", "renderer", "renderer_reference", "renderer_config", "unit_catalog",
        "record_template_selection",
    }
    unknown = sorted(set(definition) - allowed)
    if unknown:
        raise ValidationError(f"Unknown report-template/v2 fields: {unknown}")
    eligibility = definition.get("eligibility", {})
    if not isinstance(eligibility, dict) or set(eligibility) - {
        "minimum_conclusion_status", "minimum_verification_level"
    }:
        raise ValidationError("report-template/v2 eligibility has unsupported fields")
    policies = definition.get("field_policies", {})
    if (
        not isinstance(policies, dict)
        or set(policies) - {"missing", "stale", "disputed", "invalid"}
        or any(value not in {"allow", "mark", "exclude", "block"} for value in policies.values())
    ):
        raise ValidationError("report-template/v2 field_policies are invalid")
    query = definition.get("query", {})
    if not isinstance(query, dict) or set(query) - {"allowed_fields", "allowed_operators"}:
        raise ValidationError("report-template/v2 query has unsupported fields")
    if any(
        not isinstance(query.get(key, []), list)
        or any(not isinstance(item, str) for item in query.get(key, []))
        for key in ("allowed_fields", "allowed_operators")
    ):
        raise ValidationError("report-template/v2 query allowlists must be string arrays")
    references = definition.get("record_templates", definition.get("record_template_refs"))
    selection = definition.get("record_template_selection")
    if references is None and selection is None:
        raise ValidationError(
            "report-template/v2 requires record_templates or record_template_selection"
        )
    if references is not None and (
        not isinstance(references, list)
        or any(not isinstance(item, str) for item in references)
    ):
        raise ValidationError("report-template/v2 record_templates must be a string array")
    if selection is not None:
        if references is not None:
            raise ValidationError(
                "record_templates and record_template_selection are mutually exclusive"
            )
        if (
            not isinstance(selection, dict)
            or set(selection) != {"mode", "issue_type_refs"}
            or selection.get("mode") != "all_for_issue_types"
            or not isinstance(selection.get("issue_type_refs"), list)
            or not selection["issue_type_refs"]
            or any(not isinstance(item, str) for item in selection["issue_type_refs"])
        ):
            raise ValidationError(
                "record_template_selection must use all_for_issue_types with exact refs"
            )
    renderer_reference = definition.get("renderer_reference", definition.get("renderer"))
    if renderer_reference is not None and not isinstance(renderer_reference, str):
        raise ValidationError("report-template/v2 renderer_reference must be a string")
    if not isinstance(definition.get("renderer_config", {}), dict):
        raise ValidationError("report-template/v2 renderer_config must be an object")


def _validate_report_renderer(definition: dict[str, Any]) -> None:
    required = {
        "adapter_name",
        "adapter_version",
        "protocol_version",
        "supported_media_types",
        "default_media_type",
        "default_extension",
        "configuration_schema",
        "deterministic_output",
    }
    unknown = sorted(set(definition) - required)
    missing = sorted(required - set(definition))
    if missing or unknown:
        raise ValidationError(
            f"report_renderer definition fields are invalid; missing={missing}, unknown={unknown}"
        )
    for key in ("adapter_name", "adapter_version", "protocol_version", "default_media_type"):
        if not isinstance(definition[key], str) or not definition[key].strip():
            raise ValidationError(f"report_renderer {key} cannot be blank")
    media_types = definition["supported_media_types"]
    if (
        not isinstance(media_types, list)
        or not media_types
        or any(not isinstance(item, str) or "/" not in item for item in media_types)
        or definition["default_media_type"] not in media_types
    ):
        raise ValidationError("report_renderer supported/default media types are invalid")
    extension = definition["default_extension"]
    if (
        not isinstance(extension, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,15}", extension.lstrip("."))
    ):
        raise ValidationError("report_renderer default_extension is invalid")
    if not isinstance(definition["deterministic_output"], bool):
        raise ValidationError("report_renderer deterministic_output must be boolean")
    _validate_json_schema_definition(
        definition["configuration_schema"], path="report_renderer.configuration_schema"
    )


def _reference_locations(value: Any, *, pointer: str = "") -> list[tuple[str, str, str]]:
    result: list[tuple[str, str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child_pointer = f"{pointer}/{key.replace('~', '~0').replace('/', '~1')}"
            kind = _REFERENCE_KEYS.get(key)
            if kind and isinstance(item, str):
                result.append((child_pointer, kind, item))
            elif kind and isinstance(item, list):
                for index, reference in enumerate(item):
                    if isinstance(reference, str):
                        result.append((f"{child_pointer}/{index}", kind, reference))
            result.extend(_reference_locations(item, pointer=child_pointer))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            result.extend(_reference_locations(item, pointer=f"{pointer}/{index}"))
    return result


def _resolve_reference_from_entries(
    reference: str,
    kind: str,
    owner: dict[str, Any],
    entries: Iterable[dict[str, Any]],
    dependency_bundle_ids: set[str],
    *,
    strict: bool,
) -> tuple[dict[str, Any], str] | None:
    pool = list(entries)
    if reference.startswith("reg_"):
        matches = [item for item in pool if item["registration_id"] == reference]
        source = "explicit_full_ref"
    else:
        full = _FULL_REF.fullmatch(reference)
        if full:
            parts = full.groupdict()
            if parts["kind"] != kind:
                raise ValidationError(
                    f"Reference {reference!r} is kind {parts['kind']}, expected {kind}"
                )
            matches = [
                item for item in pool
                if item["namespace"] == parts["namespace"] and item["kind"] == kind
                and item["name"] == parts["name"] and item["version"] == parts["version"]
            ]
            source = "explicit_full_ref"
        else:
            name, version = reference.rsplit("@", 1) if "@" in reference else (reference, None)
            same = [
                item for item in pool
                if item["bundle_id"] == owner["bundle_id"] and item["kind"] == kind
                and item["name"] == name and (version is None or item["version"] == version)
            ]
            if same:
                matches, source = same, "same_bundle"
            else:
                matches = [
                    item for item in pool
                    if item["bundle_id"] in dependency_bundle_ids and item["kind"] == kind
                    and item["name"] == name and (version is None or item["version"] == version)
                ]
                source = "dependency_lock"
    if len(matches) != 1:
        if strict:
            raise ValidationError(
                f"Reference {reference!r} for {kind} resolves to {len(matches)} registrations"
            )
        return None
    target = matches[0]
    if target["kind"] != kind:
        raise ValidationError(f"Reference {reference!r} is not kind {kind}")
    return target, source


def build_reference_locks(
    owner: dict[str, Any],
    definition: dict[str, Any],
    entries: Iterable[dict[str, Any]],
    dependencies: Iterable[dict[str, Any]],
    *,
    strict: bool = True,
) -> list[dict[str, Any]]:
    dependency_ids = {
        str(item.get("resolved_bundle_id", "")) for item in dependencies
    }
    locks: list[dict[str, Any]] = []
    for pointer, kind, reference in _reference_locations(definition):
        resolved = _resolve_reference_from_entries(
            reference, kind, owner, entries, dependency_ids, strict=strict
        )
        if resolved is None:
            continue
        target, source = resolved
        locks.append(
            {
                "owner_registration_id": owner["registration_id"],
                "json_pointer": pointer,
                "target_registration_id": target["registration_id"],
                "target_kind": target["kind"],
                "target_content_hash": target["content_hash"],
                "resolution_source": source,
            }
        )
    return locks


def _load_registration_file(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"Cannot read registration file {path}: {exc}") from exc
    if isinstance(value, dict) and "registrations" in value:
        value = value["registrations"]
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValidationError(f"Registration file {path} must contain an object or object list")
    return [dict(item) for item in value]


def load_bundle(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    if isinstance(source, dict):
        if "manifest" in source:
            return {
                "manifest": dict(source["manifest"]),
                "registrations": [dict(item) for item in source.get("registrations", [])],
            }
        return {"manifest": dict(source), "registrations": []}
    path = Path(source).resolve()
    manifest_path = path / "manifest.json" if path.is_dir() else path
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"Cannot read bundle manifest {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ValidationError("Bundle manifest must be a JSON object")
    root = manifest_path.parent
    registrations: list[dict[str, Any]] = []
    references = manifest.get("registrations", [])
    if not isinstance(references, list):
        raise ValidationError("manifest.registrations must be an array")
    for reference in references:
        if not isinstance(reference, str) or Path(reference).is_absolute() or ".." in Path(reference).parts:
            raise ValidationError(f"Unsafe registration path: {reference!r}")
        registrations.extend(_load_registration_file(root / reference))
    return {"manifest": manifest, "registrations": registrations}


def _validate_v14_template(kind: str, api_version: str, definition: dict[str, Any]) -> None:
    expected_api = {
        "evidence_intake_template": "evidence-intake-template/v1",
        "question_template": "question-template/v1",
        "conclusion_summary_template": "conclusion-summary-template/v1",
    }[kind]
    if api_version != expected_api:
        raise ValidationError(f"Unsupported {kind} API version: {api_version!r}")
    if kind == "evidence_intake_template":
        allowed = {
            "applies_to_issue_types",
            "question_kinds",
            "required_fields",
            "optional_fields",
            "artifact_requirements",
            "locator_requirements",
            "manifest_requirements",
            "analysis_summary_requirements",
            "allowed_relation_types",
            "default_evidence_role",
            "quality_requirements",
            "proof_requirements",
            "field_help",
            "examples",
            "clarification_questions",
            "deprecated",
        }
        unknown = sorted(set(definition) - allowed)
        if unknown:
            raise ValidationError(f"Unknown Evidence Intake Template fields: {unknown}")
        required = definition.get("required_fields", [])
        optional = definition.get("optional_fields", [])
        for name, value in (("required_fields", required), ("optional_fields", optional)):
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise ValidationError(f"Evidence Intake Template {name} must be a string array")
        if set(required) & set(optional):
            raise ValidationError("Evidence Intake Template fields cannot be both required and optional")
        relations = definition.get("allowed_relation_types", [])
        supported_relations = {
            "depends_on",
            "derived_from",
            "reproduces",
            "supports",
            "challenges",
            "amends",
            "duplicates",
            "context_for",
        }
        if not isinstance(relations, list) or any(item not in supported_relations for item in relations):
            raise ValidationError("Evidence Intake Template has an invalid relation type")
    elif kind == "question_template":
        allowed = {"applies_to_issue_types", "questions", "deprecated"}
        unknown = sorted(set(definition) - allowed)
        if unknown:
            raise ValidationError(f"Unknown Question Template fields: {unknown}")
        questions = definition.get("questions", [])
        if not isinstance(questions, list):
            raise ValidationError("Question Template questions must be an array")
        keys: set[str] = set()
        for index, question in enumerate(questions):
            if not isinstance(question, dict):
                raise ValidationError(f"Question Template item {index} must be an object")
            unknown_question = sorted(
                set(question)
                - {
                    "question_key",
                    "prompt",
                    "motivation",
                    "question_kind",
                    "priority",
                    "expected_evidence",
                    "required",
                    "output_fields",
                }
            )
            if unknown_question:
                raise ValidationError(
                    f"Unknown Question Template item fields: {unknown_question}"
                )
            key = question.get("question_key")
            if not isinstance(key, str) or not key or key in keys:
                raise ValidationError("Question Template question_key must be unique and non-empty")
            keys.add(key)
            if not isinstance(question.get("prompt"), str) or not question["prompt"].strip():
                raise ValidationError("Question Template prompt cannot be empty")
    else:
        allowed = {
            "applies_to_issue_types",
            "sections",
            "field_labels",
            "question_mappings",
            "limitation_display",
            "deprecated",
        }
        unknown = sorted(set(definition) - allowed)
        if unknown:
            raise ValidationError(f"Unknown Conclusion Summary Template fields: {unknown}")
        if not isinstance(definition.get("sections", []), list):
            raise ValidationError("Conclusion Summary Template sections must be an array")


def prepare_bundle(
    source: str | Path | dict[str, Any], *, trusted_local: bool = False
) -> dict[str, Any]:
    loaded = load_bundle(source)
    manifest = loaded["manifest"]
    required = {"bundle_format", "namespace", "name", "version", "core_api"}
    missing = sorted(required - set(manifest))
    if missing:
        raise ValidationError(f"Bundle manifest is missing fields: {missing}")
    if manifest["bundle_format"] != BUNDLE_FORMAT:
        raise ValidationError(f"Unsupported bundle format: {manifest['bundle_format']!r}")
    namespace = str(manifest["namespace"])
    name = str(manifest["name"])
    version = str(manifest["version"])
    if not _IDENTITY.fullmatch(namespace) or not _IDENTITY.fullmatch(name):
        raise ValidationError("Bundle namespace and name must use stable lowercase identifiers")
    if not _VERSION.fullmatch(version):
        raise ValidationError(f"Invalid bundle version: {version!r}")
    core_api_range = str(manifest["core_api"])
    if not (
        _version_matches("0.9.0", core_api_range)
        or _version_matches("0.8.4", core_api_range)
    ):
        raise ValidationError(
            f"Bundle core_api {manifest['core_api']!r} includes neither Manager 0.9.0 "
            "nor the supported 0.8.4 compatibility contract"
        )
    dependencies = manifest.get("dependencies", [])
    if not isinstance(dependencies, list):
        raise ValidationError("manifest.dependencies must be an array")

    prepared_entries: list[dict[str, Any]] = []
    identities: set[tuple[str, str, str]] = set()
    for raw in loaded["registrations"]:
        kind = str(raw.get("kind", ""))
        entry_name = str(raw.get("name", ""))
        entry_version = str(raw.get("version", version))
        api_version = str(raw.get("api_version", f"{kind}/v1"))
        if kind not in SUPPORTED_KINDS:
            raise ValidationError(f"Unsupported registration kind: {kind!r}")
        if kind in EXECUTABLE_KINDS and not trusted_local:
            raise PermissionError(
                f"Executable registration {kind!r} requires trusted local installation"
            )
        if not _IDENTITY.fullmatch(entry_name) or not _VERSION.fullmatch(entry_version):
            raise ValidationError(f"Invalid registration identity: {entry_name}@{entry_version}")
        definition = raw.get("definition")
        if not isinstance(definition, dict):
            raise ValidationError(f"Registration {kind}/{entry_name} definition must be an object")
        _validate_declarative(definition)
        if kind == "issue_type":
            build_issue_type_semantics(entry_name, api_version, definition)
        if kind == "report_template" and api_version == "report-template/v2":
            _validate_report_template_v2(definition)
        if kind == "report_renderer":
            _validate_report_renderer(definition)
        if kind in {
            "evidence_intake_template",
            "question_template",
            "conclusion_summary_template",
        }:
            _validate_v14_template(kind, api_version, definition)
        identity = (kind, entry_name, entry_version)
        if identity in identities:
            raise ConflictError(f"Duplicate registration in bundle: {kind}/{entry_name}@{entry_version}")
        identities.add(identity)
        content = {
            "namespace": namespace,
            "kind": kind,
            "name": entry_name,
            "version": entry_version,
            "api_version": api_version,
            "definition": definition,
        }
        content_hash = _hash(content)
        prepared_entries.append(
            {
                **content,
                "registration_id": f"reg_{content_hash[:32]}",
                "content_hash": content_hash,
            }
        )
    if not prepared_entries:
        raise ValidationError("Feature bundle must contain at least one registration")
    canonical_manifest = dict(manifest)
    canonical_manifest.pop("content_hash", None)
    bundle_hash = _hash(
        {
            "manifest": canonical_manifest,
            "entries": sorted(
                (
                    {
                        "identity": (
                            item["namespace"],
                            item["kind"],
                            item["name"],
                            item["version"],
                        ),
                        "content_hash": item["content_hash"],
                    }
                    for item in prepared_entries
                ),
                key=lambda item: item["identity"],
            ),
        }
    )
    return {
        "manifest": canonical_manifest,
        "entries": prepared_entries,
        "content_hash": bundle_hash,
        "bundle_id": f"bundle_{bundle_hash[:32]}",
    }


def _replace_json_pointer(document: dict[str, Any], pointer: str, value: Any) -> None:
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:]]
    current: Any = document
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    final = parts[-1]
    if isinstance(current, list):
        current[int(final)] = value
    else:
        current[final] = value


def finalize_prepared_references(
    prepared: dict[str, Any],
    external_entries: Iterable[dict[str, Any]],
    dependency_locks: Iterable[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Canonicalize every known registration reference before hashing and persistence."""
    pending_bundle = "__pending_bundle__"
    entries = [{**item, "bundle_id": pending_bundle} for item in prepared["entries"]]
    external = [dict(item) for item in external_entries]
    dependencies = [dict(item) for item in dependency_locks]
    all_entries = [*entries, *external]
    dependency_ids = {str(item["resolved_bundle_id"]) for item in dependencies}
    original_sources: dict[tuple[str, str, str, str, str], str] = {}
    for entry in entries:
        definition = json.loads(canonical_json(entry["definition"]))
        for pointer, kind, reference in _reference_locations(definition):
            resolved = _resolve_reference_from_entries(
                reference,
                kind,
                entry,
                all_entries,
                dependency_ids,
                strict=True,
            )
            assert resolved is not None
            target, source = resolved
            original_sources[
                (
                    entry["namespace"],
                    entry["kind"],
                    entry["name"],
                    entry["version"],
                    pointer,
                )
            ] = source
            exact = (
                f"{target['namespace']}/{target['kind']}/{target['name']}@{target['version']}"
            )
            _replace_json_pointer(definition, pointer, exact)
        entry["definition"] = definition
        content = {
            key: entry[key]
            for key in ("namespace", "kind", "name", "version", "api_version", "definition")
        }
        entry["content_hash"] = _hash(content)
        entry["registration_id"] = f"reg_{entry['content_hash'][:32]}"
    canonical_manifest = prepared["manifest"]
    bundle_hash = _hash(
        {
            "manifest": canonical_manifest,
            "entries": sorted(
                (
                    {
                        "identity": (
                            item["namespace"], item["kind"], item["name"], item["version"]
                        ),
                        "content_hash": item["content_hash"],
                    }
                    for item in entries
                ),
                key=lambda item: item["identity"],
            ),
        }
    )
    bundle_id = f"bundle_{bundle_hash[:32]}"
    for entry in entries:
        entry["bundle_id"] = bundle_id
    all_final = [*entries, *external]
    locks: list[dict[str, Any]] = []
    for entry in entries:
        entry_locks = build_reference_locks(
            entry, entry["definition"], all_final, dependencies, strict=True
        )
        for lock in entry_locks:
            key = (
                entry["namespace"],
                entry["kind"],
                entry["name"],
                entry["version"],
                lock["json_pointer"],
            )
            lock["resolution_source"] = original_sources.get(
                key, lock["resolution_source"]
            )
        locks.extend(entry_locks)
    return {
        **prepared,
        "entries": entries,
        "content_hash": bundle_hash,
        "bundle_id": bundle_id,
    }, locks


def install_prepared_bundle(
    conn: sqlite3.Connection,
    prepared: dict[str, Any],
    *,
    actor: str,
    state: str = "installed",
    lock_snapshot: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    manifest = prepared["manifest"]
    existing = conn.execute(
        "SELECT bundle_id,content_hash,state FROM extension_bundles "
        "WHERE namespace=? AND name=? AND version=?",
        (manifest["namespace"], manifest["name"], manifest["version"]),
    ).fetchone()
    if existing:
        if existing["content_hash"] != prepared["content_hash"]:
            raise ConflictError(
                "An immutable bundle version already exists with different content"
            )
        return {
            "bundle_id": existing["bundle_id"],
            "content_hash": existing["content_hash"],
            "state": existing["state"],
            "idempotent_replay": True,
        }
    timestamp = now()
    conn.execute(
        "INSERT INTO extension_bundles(bundle_id,namespace,name,version,bundle_format,"
        "core_api_range,manifest_json,content_hash,state,installed_at,installed_by,"
        "activated_at,disabled_reason,lock_snapshot_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            prepared["bundle_id"],
            manifest["namespace"],
            manifest["name"],
            manifest["version"],
            manifest["bundle_format"],
            manifest["core_api"],
            canonical_json(manifest),
            prepared["content_hash"],
            state,
            timestamp,
            actor,
            timestamp if state == "active" else None,
            "",
            canonical_json(lock_snapshot or []),
        ),
    )
    for entry in prepared["entries"]:
        conn.execute(
            "INSERT INTO registry_entries(registration_id,bundle_id,namespace,kind,name,"
            "version,api_version,definition_json,content_hash,state,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                entry["registration_id"],
                prepared["bundle_id"],
                entry["namespace"],
                entry["kind"],
                entry["name"],
                entry["version"],
                entry["api_version"],
                canonical_json(entry["definition"]),
                entry["content_hash"],
                state,
                timestamp,
            ),
        )
    return {
        "bundle_id": prepared["bundle_id"],
        "content_hash": prepared["content_hash"],
        "state": state,
        "registrations": len(prepared["entries"]),
        "idempotent_replay": False,
    }


def install_compatibility_bundle(conn: sqlite3.Connection) -> dict[str, Any] | None:
    from .compatibility import compatibility_bundle

    actor_row = conn.execute(
        "SELECT actor_id FROM actors ORDER BY CASE WHEN actor_id='organizer-agent' THEN 0 ELSE 1 END,"
        "actor_id LIMIT 1"
    ).fetchone()
    if not actor_row:
        return None
    actor = str(actor_row["actor_id"] if hasattr(actor_row, "keys") else actor_row[0])
    prepared = prepare_bundle(compatibility_bundle(), trusted_local=True)
    prepared, reference_locks = finalize_prepared_references(prepared, [], [])
    result = install_prepared_bundle(conn, prepared, actor=actor, state="active")
    timestamp = now()
    for entry in prepared["entries"]:
        conn.execute(
            "INSERT OR IGNORE INTO registry_bindings(binding_id,binding_scope_type,"
            "binding_scope_id,registration_id,is_default,bound_at,bound_by,reviewed_changeset_id) "
            "VALUES (?,?,?,?,1,?,?,NULL)",
            (
                f"binding_{entry['content_hash'][:32]}",
                "global",
                "",
                entry["registration_id"],
                timestamp,
                actor,
            ),
        )
    has_reference_locks = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='registry_reference_locks'"
    ).fetchone()
    if has_reference_locks:
        for lock in reference_locks:
            conn.execute(
                "INSERT OR IGNORE INTO registry_reference_locks VALUES (?,?,?,?,?,?,?)",
                (
                    lock["owner_registration_id"], lock["json_pointer"],
                    lock["target_registration_id"], lock["target_kind"],
                    lock["target_content_hash"], lock["resolution_source"], now(),
                ),
            )
    issue_entries = {
        entry["name"]: entry for entry in prepared["entries"] if entry["kind"] == "issue_type"
    }
    for name, entry in issue_entries.items():
        conn.execute(
            "UPDATE issues SET issue_type_registration_id=?,issue_type_content_hash=? "
            "WHERE issue_type=? AND issue_type_registration_id IS NULL",
            (entry["registration_id"], entry["content_hash"], name),
        )
    return result


def migrated_policy_bundle(policy: dict[str, Any]) -> dict[str, Any]:
    """Represent an arbitrary v8 policy losslessly as a local compatibility bundle."""
    policy_hash = _hash(policy)
    registrations: list[dict[str, Any]] = []
    issue_types = policy.get("issue_types", {})
    if not isinstance(issue_types, dict):
        raise ValidationError("Custom policy issue_types must be an object")
    for name, definition in sorted(issue_types.items()):
        if not isinstance(definition, dict):
            raise ValidationError(f"Custom policy Issue type {name!r} must be an object")
        registrations.append(
            {
                "kind": "issue_type",
                "name": str(name),
                "version": "1.0.0",
                "api_version": "issue-type/v2",
                "definition": build_issue_type_semantics(
                    str(name), "issue-type/v1", dict(definition), legacy_policy=policy
                ),
            }
        )
    registrations.append(
        {
            "kind": "routing_profile",
            "name": "legacy-policy-snapshot",
            "version": "1.0.0",
            "api_version": "routing-profile/v1",
            "definition": {
                "migration_mode": "lossless-v8-policy-snapshot",
                "policy_content_hash": policy_hash,
                "policy_snapshot": policy,
            },
        }
    )
    return {
        "manifest": {
            "bundle_format": BUNDLE_FORMAT,
            "namespace": "local.compat",
            "name": f"migrated-policy-{policy_hash[:12]}",
            "version": "1.0.0",
            "core_api": ">=0.8,<0.9",
            "description": "Lossless schema v8 custom policy migration candidate",
            "registrations": [],
            "dependencies": [],
            "source_policy_hash": policy_hash,
        },
        "registrations": registrations,
    }


def legacy_policy_semantic_findings(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Return v8 policy constructs that issue-type/v2 cannot prove equivalent."""
    from .default_policy import DEFAULT_POLICY

    findings: list[dict[str, Any]] = []
    unknown_top = sorted(set(policy) - set(DEFAULT_POLICY))
    if unknown_top:
        findings.append(
            {"code": "unknown_policy_sections", "fields": unknown_top}
        )
    issue_types = policy.get("issue_types", {})
    allowed_issue_fields = {
        "allowed_children",
        "rollup_mode",
        "conclusion_schema",
        "default_child_templates",
    }
    if isinstance(issue_types, dict):
        for name, definition in sorted(issue_types.items()):
            if not isinstance(definition, dict):
                findings.append(
                    {"code": "issue_type_definition_invalid", "issue_type": str(name)}
                )
                continue
            unknown = sorted(set(definition) - allowed_issue_fields)
            if unknown:
                findings.append(
                    {
                        "code": "unknown_issue_type_logic",
                        "issue_type": str(name),
                        "fields": unknown,
                    }
                )
    publication = policy.get("publication", {})
    default_publication = DEFAULT_POLICY.get("publication", {})
    if isinstance(publication, dict) and isinstance(default_publication, dict):
        unknown = sorted(set(publication) - set(default_publication))
        if unknown:
            findings.append(
                {"code": "unknown_publication_logic", "fields": unknown}
            )
    requirements = policy.get("publication_requirements", {})
    default_requirements = DEFAULT_POLICY.get("publication_requirements", {})
    if isinstance(requirements, dict) and isinstance(default_requirements, dict):
        unknown = sorted(set(requirements) - set(default_requirements))
        if unknown:
            findings.append(
                {"code": "unknown_publication_profiles", "profiles": unknown}
            )
    schemas = policy.get("conclusion_schemas", {})
    if isinstance(schemas, dict):
        for name, schema in sorted(schemas.items()):
            if not isinstance(schema, dict) or set(schema) - {"required"}:
                findings.append(
                    {
                        "code": "custom_conclusion_schema_not_declarative",
                        "schema": str(name),
                    }
                )
    return findings


def install_migrated_policy_bundle(
    conn: sqlite3.Connection,
    policy: dict[str, Any],
    *,
    migration_plan: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    from .default_policy import DEFAULT_POLICY

    if canonical_json(policy) == canonical_json(DEFAULT_POLICY):
        return None
    actor_row = conn.execute(
        "SELECT actor_id FROM actors ORDER BY CASE WHEN actor_id='organizer-agent' THEN 0 ELSE 1 END,"
        "actor_id LIMIT 1"
    ).fetchone()
    if not actor_row:
        return None
    actor = str(actor_row["actor_id"] if hasattr(actor_row, "keys") else actor_row[0])
    if migration_plan is None:
        from .migration_planner import plan_legacy_policy_migration

        migration_plan = plan_legacy_policy_migration(
            policy, target_namespace="local.compat"
        )
    if (
        not migration_plan.get("safe_to_apply")
        or migration_plan.get("source_policy_hash") != _hash(policy)
        or not migration_plan.get("prepared_bundle")
        or migration_plan["prepared_bundle"]["content_hash"]
        != migration_plan.get("prepared_bundle_hash")
    ):
        raise ValidationError(
            "Legacy Policy migration plan is not safe to apply",
            details={"findings": migration_plan.get("blocking_findings", [])},
        )
    prepared = migration_plan["prepared_bundle"]
    reference_locks = migration_plan["reference_locks"]
    result = install_prepared_bundle(conn, prepared, actor=actor, state="active")
    has_reference_locks = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='registry_reference_locks'"
    ).fetchone()
    if has_reference_locks:
        for lock in reference_locks:
            conn.execute(
                "INSERT OR IGNORE INTO registry_reference_locks VALUES (?,?,?,?,?,?,?)",
                (
                    lock["owner_registration_id"], lock["json_pointer"],
                    lock["target_registration_id"], lock["target_kind"],
                    lock["target_content_hash"], lock["resolution_source"], now(),
                ),
            )
    issue_entries = {
        entry["name"]: entry for entry in prepared["entries"] if entry["kind"] == "issue_type"
    }
    for name, entry in issue_entries.items():
        conn.execute(
            "UPDATE issues SET issue_type_registration_id=?,issue_type_content_hash=? "
            "WHERE issue_type=?",
            (entry["registration_id"], entry["content_hash"], name),
        )
    return {**result, "policy_hash": _hash(policy), "migration_candidate": True}


class RegistryService:
    def __init__(self, manager: IssueManager):
        self.manager = manager
        self.store = manager.store
        from .project_component import installation

        if installation(self.store):
            # Portable installations retain the exact registry snapshot and cannot bootstrap writes.
            return
        with self.store.transaction() as conn:
            install_compatibility_bundle(conn)

    @staticmethod
    def _require(auth: AuthContext | None, capability: str) -> str:
        if auth is None:
            return "organizer-agent"
        auth.require(capability)
        return auth.actor_id

    def validate_bundle(
        self, source: str | Path | dict[str, Any], *, trusted_local: bool = False
    ) -> dict[str, Any]:
        prepared, locks, reference_locks = self._prepare_bundle(
            source, trusted_local=trusted_local
        )
        return {
            "valid": True,
            "bundle_id": prepared["bundle_id"],
            "namespace": prepared["manifest"]["namespace"],
            "name": prepared["manifest"]["name"],
            "version": prepared["manifest"]["version"],
            "content_hash": prepared["content_hash"],
            "registrations": [
                {
                    key: entry[key]
                    for key in ("registration_id", "kind", "name", "version", "content_hash")
                }
                for entry in prepared["entries"]
            ],
            "dependency_lock": locks,
            "reference_locks": reference_locks,
        }

    def _prepare_bundle(
        self, source: str | Path | dict[str, Any], *, trusted_local: bool
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
        prepared = prepare_bundle(source, trusted_local=trusted_local)
        locks = self._resolve_dependencies(prepared["manifest"].get("dependencies", []))
        dependency_ids = [item["resolved_bundle_id"] for item in locks]
        external_entries: list[dict[str, Any]] = []
        for bundle_id in dependency_ids:
            external_entries.extend(
                self.store.rows("SELECT * FROM registry_entries WHERE bundle_id=?", (bundle_id,))
            )
        prepared, reference_locks = finalize_prepared_references(
            prepared, external_entries, locks
        )
        return prepared, locks, reference_locks

    def _resolve_dependencies(self, dependencies: Iterable[Any]) -> list[dict[str, Any]]:
        locks: list[dict[str, Any]] = []
        for raw in dependencies:
            if isinstance(raw, str):
                match = re.fullmatch(r"([^/]+)/([^@]+)@(.+)", raw)
                if not match:
                    raise ValidationError(f"Invalid bundle dependency: {raw!r}")
                namespace, name, version_range = match.groups()
            elif isinstance(raw, dict):
                namespace = str(raw.get("namespace", ""))
                name = str(raw.get("name", ""))
                version_range = str(raw.get("version", raw.get("version_range", "*")))
            else:
                raise ValidationError("Bundle dependency must be a string or object")
            candidates = self.store.rows(
                "SELECT bundle_id,version,content_hash,state FROM extension_bundles "
                "WHERE namespace=? AND name=? AND state IN ('installed','active','deprecated')",
                (namespace, name),
            )
            compatible = [row for row in candidates if _version_matches(row["version"], version_range)]
            if not compatible:
                raise ValidationError(
                    f"Unresolved bundle dependency {namespace}/{name}@{version_range}"
                )
            selected = max(compatible, key=lambda row: _semver(row["version"]))
            locks.append(
                {
                    "namespace": namespace,
                    "name": name,
                    "declared_range": version_range,
                    "resolved_bundle_id": selected["bundle_id"],
                    "resolved_version": selected["version"],
                    "resolved_content_hash": selected["content_hash"],
                }
            )
        return sorted(locks, key=lambda item: (item["namespace"], item["name"]))

    def install_bundle(
        self,
        source: str | Path | dict[str, Any],
        *,
        auth: AuthContext | None = None,
        trusted_local: bool = False,
        reason: str = "install immutable feature bundle",
    ) -> dict[str, Any]:
        actor = self._require(auth, "registry.install")
        prepared, locks, reference_locks = self._prepare_bundle(
            source, trusted_local=trusted_local
        )
        with self.store.transaction() as conn:
            result = install_prepared_bundle(conn, prepared, actor=actor, lock_snapshot=locks)
            if not result.get("idempotent_replay"):
                for lock in locks:
                    conn.execute(
                        "INSERT INTO registry_dependencies VALUES (?,?,?,?,?,?,?,?)",
                        (
                            new_id("dependency"),
                            prepared["bundle_id"],
                            lock["namespace"],
                            lock["name"],
                            lock["declared_range"],
                            lock["resolved_bundle_id"],
                            lock["resolved_version"],
                            lock["resolved_content_hash"],
                        ),
                    )
                for lock in reference_locks:
                    conn.execute(
                        "INSERT INTO registry_reference_locks VALUES (?,?,?,?,?,?,?)",
                        (
                            lock["owner_registration_id"], lock["json_pointer"],
                            lock["target_registration_id"], lock["target_kind"],
                            lock["target_content_hash"], lock["resolution_source"], now(),
                        ),
                    )
                self.store.audit(
                    conn,
                    actor=actor,
                    action="registry.bundle.install",
                    object_type="extension_bundle",
                    object_id=result["bundle_id"],
                    before_revision=None,
                    after_revision=1,
                    reason=reason,
                    payload={**result, "dependency_lock": locks},
                )
        return {
            **result,
            "dependency_lock": locks,
            "reference_locks": reference_locks,
        }

    def _transition_bundle(
        self,
        bundle_id: str,
        target: str,
        *,
        auth: AuthContext | None,
        reason: str,
    ) -> dict[str, Any]:
        capability = {
            "active": "registry.activate",
            "deprecated": "registry.deprecate",
            "disabled": "registry.disable",
            "retired": "registry.deprecate",
        }[target]
        actor = self._require(auth, capability)
        bundle = self.store.row("SELECT * FROM extension_bundles WHERE bundle_id=?", (bundle_id,))
        if not bundle:
            raise NotFoundError(f"Bundle not found: {bundle_id}")
        allowed = {
            "installed": {"active", "disabled"},
            "active": {"deprecated", "disabled"},
            "deprecated": {"retired", "disabled"},
            "disabled": set(),
            "retired": set(),
        }
        if target == bundle["state"]:
            return {"bundle_id": bundle_id, "state": target, "idempotent_replay": True}
        if target not in allowed[bundle["state"]]:
            raise ConflictError(f"Invalid bundle lifecycle transition {bundle['state']} -> {target}")
        timestamp = now()
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE extension_bundles SET state=?,activated_at=COALESCE(activated_at,?),"
                "disabled_reason=? WHERE bundle_id=?",
                (target, timestamp, reason if target == "disabled" else "", bundle_id),
            )
            conn.execute("UPDATE registry_entries SET state=? WHERE bundle_id=?", (target, bundle_id))
            event_id = self.store.audit(
                conn,
                actor=actor,
                action=f"registry.bundle.{target}",
                object_type="extension_bundle",
                object_id=bundle_id,
                before_revision=None,
                after_revision=None,
                reason=reason,
                payload={"from": bundle["state"], "to": target},
            )
        return {"bundle_id": bundle_id, "state": target, "event_id": event_id}

    def activate_bundle(
        self, bundle_id: str, *, auth: AuthContext | None = None, reason: str = "activate bundle"
    ) -> dict[str, Any]:
        return self._transition_bundle(bundle_id, "active", auth=auth, reason=reason)

    def deprecate_bundle(
        self, bundle_id: str, *, auth: AuthContext | None = None, reason: str = "deprecate bundle"
    ) -> dict[str, Any]:
        return self._transition_bundle(bundle_id, "deprecated", auth=auth, reason=reason)

    def disable_bundle(
        self, bundle_id: str, *, auth: AuthContext | None = None, reason: str
    ) -> dict[str, Any]:
        return self._transition_bundle(bundle_id, "disabled", auth=auth, reason=reason)

    def retire_bundle(
        self, bundle_id: str, *, auth: AuthContext | None = None, reason: str
    ) -> dict[str, Any]:
        return self._transition_bundle(bundle_id, "retired", auth=auth, reason=reason)

    def list_bundles(self) -> list[dict[str, Any]]:
        return self.store.rows(
            "SELECT bundle_id,namespace,name,version,content_hash,state,installed_at,installed_by,"
            "activated_at,disabled_reason FROM extension_bundles ORDER BY namespace,name,version"
        )

    def show_bundle(self, bundle_id: str) -> dict[str, Any]:
        bundle = self.store.row("SELECT * FROM extension_bundles WHERE bundle_id=?", (bundle_id,))
        if not bundle:
            raise NotFoundError(f"Bundle not found: {bundle_id}")
        result = dict(bundle)
        result["manifest"] = json.loads(result.pop("manifest_json"))
        result["dependency_lock"] = json.loads(result.pop("lock_snapshot_json"))
        result["registrations"] = self.list_entries(bundle_id=bundle_id)
        return result

    def list_entries(
        self, *, bundle_id: str | None = None, kind: str | None = None
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if bundle_id:
            clauses.append("bundle_id=?")
            params.append(bundle_id)
        if kind:
            if kind not in SUPPORTED_KINDS:
                raise ValidationError(f"Unsupported registration kind: {kind}")
            clauses.append("kind=?")
            params.append(kind)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        return self.store.rows(
            "SELECT registration_id,bundle_id,namespace,kind,name,version,api_version,"
            f"content_hash,state,created_at FROM registry_entries{where} "
            "ORDER BY namespace,kind,name,version",
            tuple(params),
        )

    def show_entry(self, registration_id: str) -> dict[str, Any]:
        entry = self.store.row(
            "SELECT * FROM registry_entries WHERE registration_id=?", (registration_id,)
        )
        if not entry:
            raise NotFoundError(f"Registration not found: {registration_id}")
        result = dict(entry)
        result["definition"] = json.loads(result.pop("definition_json"))
        result["reference"] = (
            f"{result['namespace']}/{result['kind']}/{result['name']}@{result['version']}"
        )
        result["reference_locks"] = self.store.rows(
            "SELECT json_pointer,target_registration_id,target_kind,target_content_hash,"
            "resolution_source FROM registry_reference_locks WHERE owner_registration_id=? "
            "ORDER BY json_pointer",
            (registration_id,),
        )
        if result["kind"] == "issue_type":
            result["semantic_definition"] = build_issue_type_semantics(
                result["name"], result["api_version"], result["definition"]
            )
            result["semantic_hash"] = _hash(result["semantic_definition"])
        return result

    def _ancestor_ids(self, issue_id: str) -> list[str]:
        ancestors: list[str] = []
        current = issue_id
        seen: set[str] = set()
        while current and current not in seen:
            seen.add(current)
            row = self.store.row("SELECT parent_issue_id FROM issues WHERE issue_id=?", (current,))
            if not row:
                break
            current = row.get("parent_issue_id") or ""
            if current:
                ancestors.append(current)
        return ancestors

    def resolve(
        self,
        reference: str,
        *,
        kind: str | None = None,
        issue_id: str | None = None,
        for_creation: bool = True,
        allow_latest: bool = False,
    ) -> dict[str, Any]:
        if reference.startswith("reg_"):
            entry = self.show_entry(reference)
            if kind and entry["kind"] != kind:
                raise ValidationError(f"Registration {reference} is not kind {kind}")
            if for_creation and entry["state"] != "active":
                raise ConflictError(f"Registration {reference} is not active")
            return entry
        match = _FULL_REF.fullmatch(reference)
        if match:
            parts = match.groupdict()
            if kind and parts["kind"] != kind:
                raise ValidationError(
                    f"Registration reference {reference!r} is kind {parts['kind']}, not {kind}"
                )
            if parts["version"] == "latest" and not allow_latest:
                raise ValidationError("Floating 'latest' cannot be used for persisted objects")
            params: list[Any] = [parts["namespace"], parts["kind"], parts["name"]]
            sql = (
                "SELECT registration_id FROM registry_entries WHERE namespace=? AND kind=? AND name=?"
            )
            if parts["version"] != "latest":
                sql += " AND version=?"
                params.append(parts["version"])
            rows = self.store.rows(sql, tuple(params))
            if parts["version"] == "latest" and rows:
                rows.sort(
                    key=lambda row: _semver(self.show_entry(row["registration_id"])["version"]),
                    reverse=True,
                )
            if not rows:
                raise NotFoundError(f"Registration not found: {reference}")
            selected_entry = self.show_entry(rows[0]["registration_id"])
            if kind and selected_entry["kind"] != kind:
                raise ValidationError(
                    f"Registration {selected_entry['registration_id']} is not kind {kind}"
                )
            if for_creation and selected_entry["state"] != "active":
                raise ConflictError(
                    f"Registration {selected_entry['registration_id']} is not active"
                )
            return selected_entry
        if "@" in reference:
            name, version = reference.rsplit("@", 1)
        else:
            name, version = reference, None
        if not kind:
            raise ValidationError("A short registration reference requires an explicit kind")
        candidates = self.store.rows(
            "SELECT e.registration_id,b.binding_scope_type,b.binding_scope_id,b.is_default "
            "FROM registry_entries e JOIN registry_bindings b "
            "ON b.registration_id=e.registration_id WHERE e.kind=? AND e.name=? "
            + ("AND e.version=? " if version else "")
            + ("AND e.state='active' " if for_creation else "")
            + "ORDER BY e.registration_id",
            tuple([kind, name] + ([version] if version else [])),
        )
        levels: list[list[dict[str, Any]]] = []
        if issue_id:
            levels.append(
                [
                    item
                    for item in candidates
                    if item["binding_scope_type"] == "issue"
                    and item["binding_scope_id"] == issue_id
                ]
            )
            for ancestor in self._ancestor_ids(issue_id):
                levels.append(
                    [
                        item
                        for item in candidates
                        if item["binding_scope_type"] == "issue_subtree"
                        and item["binding_scope_id"] == ancestor
                    ]
                )
        levels.append(
            [
                item
                for item in candidates
                if item["binding_scope_type"] == "global" and item["binding_scope_id"] == ""
            ]
        )
        for level in levels:
            defaults = [item for item in level if item["is_default"]]
            selected_candidates = defaults or level
            unique = sorted(
                {item["registration_id"] for item in selected_candidates}
            )
            if len(unique) > 1:
                raise ConflictError(
                    f"Ambiguous registration binding for {kind}/{name}: {unique}"
                )
            if unique:
                return self.show_entry(unique[0])
        raise NotFoundError(f"No bound registration for {kind}/{reference}")

    def bind(
        self,
        reference: str,
        *,
        scope_type: str = "global",
        scope_id: str = "",
        is_default: bool = True,
        reviewed_changeset_id: str | None = None,
        auth: AuthContext | None = None,
        reason: str = "bind registration",
    ) -> dict[str, Any]:
        actor = self._require(auth, "registry.bind")
        if scope_type not in {"global", "issue_subtree", "issue"}:
            raise ValidationError(f"Unsupported binding scope: {scope_type}")
        if scope_type == "global" and scope_id:
            raise ValidationError("Global binding scope_id must be empty")
        if scope_type != "global":
            self.manager._issue(scope_id, active=False)
        entry = self.resolve(reference, for_creation=True)
        if is_default:
            conflicts = self.store.rows(
                "SELECT b.binding_id,e.registration_id FROM registry_bindings b "
                "JOIN registry_entries e ON e.registration_id=b.registration_id "
                "WHERE b.binding_scope_type=? AND b.binding_scope_id=? AND b.is_default=1 "
                "AND e.namespace=? AND e.kind=? AND e.name=? AND e.registration_id<>?",
                (
                    scope_type,
                    scope_id,
                    entry["namespace"],
                    entry["kind"],
                    entry["name"],
                    entry["registration_id"],
                ),
            )
            if conflicts:
                raise ConflictError(
                    "A different default version is already bound at the same precedence"
                )
        existing = self.store.row(
            "SELECT binding_id FROM registry_bindings WHERE binding_scope_type=? "
            "AND binding_scope_id=? AND registration_id=?",
            (scope_type, scope_id, entry["registration_id"]),
        )
        if existing:
            return {**existing, "registration_id": entry["registration_id"], "idempotent_replay": True}
        binding_id = new_id("binding")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO registry_bindings VALUES (?,?,?,?,?,?,?,?)",
                (
                    binding_id,
                    scope_type,
                    scope_id,
                    entry["registration_id"],
                    1 if is_default else 0,
                    now(),
                    actor,
                    reviewed_changeset_id,
                ),
            )
            event_id = self.store.audit(
                conn,
                actor=actor,
                action="registry.binding.apply",
                object_type="registry_binding",
                object_id=binding_id,
                before_revision=None,
                after_revision=1,
                reason=reason,
                payload={
                    "scope_type": scope_type,
                    "scope_id": scope_id,
                    "registration_id": entry["registration_id"],
                    "is_default": is_default,
                    "reviewed_changeset_id": reviewed_changeset_id,
                },
            )
        return {
            "binding_id": binding_id,
            "registration_id": entry["registration_id"],
            "event_id": event_id,
            "idempotent_replay": False,
        }

    @staticmethod
    def _format_value(value: Any, context: dict[str, Any]) -> Any:
        if isinstance(value, str):
            try:
                return value.format_map(context)
            except KeyError as exc:
                raise ValidationError(f"Issue template references unknown parameter {exc}") from exc
        if isinstance(value, list):
            return [RegistryService._format_value(item, context) for item in value]
        if isinstance(value, dict):
            return {
                key: RegistryService._format_value(item, context) for key, item in value.items()
            }
        return value

    def instantiate_issue_template(
        self,
        reference: str,
        parameters: dict[str, Any],
        *,
        actor: str = "organizer-agent",
        reason: str = "instantiate registered issue template",
        dry_run: bool = False,
    ) -> dict[str, Any]:
        entry = self.resolve(reference, kind="issue_template", for_creation=True)
        definition = entry["definition"]
        parameter_specs = definition.get("parameters", {})
        if not isinstance(parameter_specs, dict):
            raise ValidationError("Issue template parameters definition must be an object")
        for name, spec in parameter_specs.items():
            if isinstance(spec, dict) and spec.get("required") and name not in parameters:
                raise ValidationError(f"Missing issue template parameter: {name}")
        unknown = sorted(set(parameters) - set(parameter_specs))
        if unknown:
            raise ValidationError(f"Unknown issue template parameters: {unknown}")
        operations: list[dict[str, Any]] = []
        for raw_node in definition.get("nodes", []):
            if not isinstance(raw_node, dict):
                raise ValidationError("Issue template nodes must be objects")
            repeats = parameters.get(str(raw_node.get("repeat")), []) if raw_node.get("repeat") else [None]
            if not isinstance(repeats, list):
                raise ValidationError(f"Template repeat {raw_node.get('repeat')} must be an array")
            for repeated in repeats:
                context = dict(parameters)
                if raw_node.get("repeat"):
                    context[str(raw_node.get("as", "item"))] = repeated
                node = {key: value for key, value in raw_node.items() if key not in {"repeat", "as", "children_for_each", "child"}}
                operations.append(self._format_value(node, context))
                child_values = raw_node.get("children_for_each", [])
                child_spec = raw_node.get("child")
                if child_values and not isinstance(child_spec, dict):
                    raise ValidationError("children_for_each requires a child object")
                for child_value in child_values:
                    operations.append(
                        self._format_value(child_spec, {**context, "child_name": child_value})
                    )
        collisions = [
            op["id"]
            for op in operations
            if self.store.row("SELECT issue_id FROM issues WHERE issue_id=?", (op["id"],))
        ]
        if collisions:
            raise ConflictError(f"Issue template would collide with existing issues: {collisions}")
        preview = {
            "template_reference": entry["reference"],
            "template_registration_id": entry["registration_id"],
            "template_content_hash": entry["content_hash"],
            "parameters": parameters,
            "operations": operations,
            "count": len(operations),
        }
        if dry_run:
            return {**preview, "would_write": False}
        with self.store.transaction() as conn:
            for operation in operations:
                type_reference = str(operation["issue_type"])
                if not type_reference.startswith("reg_") and not _FULL_REF.fullmatch(type_reference):
                    type_reference = (
                        f"{entry['namespace']}/issue_type/{type_reference}@{entry['version']}"
                    )
                type_entry = self.resolve(
                    type_reference, kind="issue_type", for_creation=True
                )
                self.manager.create_issue(
                    operation["id"],
                    type_entry["name"],
                    operation.get("title"),
                    parent_issue_id=operation.get("parent"),
                    scope=operation.get("scope", {}),
                    topic=operation.get("topic"),
                    actor=actor,
                    reason=reason,
                    issue_type_registration_id=type_entry["registration_id"],
                )
            parent_relation = definition.get("parent_relation")
            if parent_relation:
                if not isinstance(parent_relation, dict):
                    raise ValidationError("parent_relation must be an object")
                for operation in operations:
                    if operation.get("parent"):
                        self.manager._insert_relation(
                            conn,
                            consumer=operation["parent"],
                            provider=operation["id"],
                            relation_type=str(parent_relation.get("relation_type", "rolls_up_from")),
                            impact_policy=str(parent_relation.get("impact_policy", "hard")),
                            actor=actor,
                            reason="registered issue template parent relation",
                        )
            event_id = self.store.audit(
                conn,
                actor=actor,
                action="registry.issue_template.instantiate",
                object_type="issue_template",
                object_id=entry["registration_id"],
                before_revision=None,
                after_revision=1,
                reason=reason,
                payload=preview,
            )
        return {**preview, "event_id": event_id, "would_write": True}

    def doctor(self) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        drifted_registration_ids: set[str] = set()
        for entry in self.store.rows("SELECT * FROM registry_entries ORDER BY registration_id"):
            expected = _hash(
                {
                    "namespace": entry["namespace"],
                    "kind": entry["kind"],
                    "name": entry["name"],
                    "version": entry["version"],
                    "api_version": entry["api_version"],
                    "definition": json.loads(entry["definition_json"]),
                }
            )
            if expected != entry["content_hash"]:
                drifted_registration_ids.add(entry["registration_id"])
                findings.append(
                    {
                        "code": "registry_entry_hash_drift",
                        "registration_id": entry["registration_id"],
                        "expected": expected,
                        "actual": entry["content_hash"],
                    }
                )
        unresolved = self.store.rows(
            "SELECT i.issue_id,i.issue_type FROM issues i LEFT JOIN registry_entries e "
            "ON e.registration_id=i.issue_type_registration_id "
            "WHERE i.issue_type_registration_id IS NULL OR e.registration_id IS NULL"
        )
        findings.extend(
            {"code": "issue_registration_unresolved", **item} for item in unresolved
        )
        for lock in self.store.rows(
            "SELECT l.*,o.kind AS owner_kind,t.kind AS actual_target_kind,"
            "t.content_hash AS actual_target_hash FROM registry_reference_locks l "
            "LEFT JOIN registry_entries o ON o.registration_id=l.owner_registration_id "
            "LEFT JOIN registry_entries t ON t.registration_id=l.target_registration_id "
            "ORDER BY l.owner_registration_id,l.json_pointer"
        ):
            if (
                not lock.get("owner_kind")
                or lock.get("actual_target_kind") != lock["target_kind"]
                or (
                    lock.get("actual_target_hash") != lock["target_content_hash"]
                    and lock["target_registration_id"] not in drifted_registration_ids
                )
            ):
                findings.append(
                    {
                        "code": "registry_reference_lock_incoherent",
                        "owner_registration_id": lock["owner_registration_id"],
                        "json_pointer": lock["json_pointer"],
                        "target_registration_id": lock["target_registration_id"],
                    }
                )
        return {"ok": not findings, "findings": findings, "checked_entries": len(self.list_entries())}
