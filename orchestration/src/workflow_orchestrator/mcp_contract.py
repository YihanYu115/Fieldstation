"""Shared, role-independent MCP contracts. No domain state or credentials live here."""
from __future__ import annotations

import hashlib
import json
import math
import re
from copy import deepcopy
from importlib.metadata import PackageNotFoundError, version
from typing import Any

from .client import WorkflowAPIError

CONTRACT_VERSION = "workflow-mcp/v2"
MAX_RESULT_BYTES = 64 * 1024
OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["contract_version"],
    "properties": {
        "contract_version": {"const": CONTRACT_VERSION},
        "status": {"type": "string"},
        "acceptance": {"description": "Tool-specific acceptance or workflow contract."},
        "state": {"description": "Tool-specific state; trigger runs distinguish accepted, launch intent, running, unknown and terminal outcomes."},
        "launch_intent": {"type": "boolean"},
        "attempt": {"type": ["string", "null"]},
        "generation": {"type": ["integer", "null"]},
        "receipt": {"type": ["object", "null"]},
        "diagnostic": {"type": ["string", "null"]},
        "code": {"type": "string"},
        "error": {"type": "string"},
        "operation": {"type": "string"},
        "layer": {"type": "string"},
        "message": {"type": "string"},
        "fields": {"type": "array", "items": {"type": "object"}},
        "fields_truncated": {"type": "boolean"},
        "retry_policy": {"enum": ["correct_arguments", "host_required", "retry_read",
                                    "recover_original", "reread_and_decide", "stop",
                                    "read_smaller_page"]},
        "effect": {"enum": ["committed", "not_committed", "unknown", "not_applicable"]},
        "delivery_id": {"type": "string"},
        "phase": {"type": "string"},
        "budget": {"type": "object"},
        "delivery": {"type": "object"},
        "page": {"type": "object", "required": ["count", "has_more", "next_cursor",
                "page_complete", "collection_complete"], "properties": {
                    "count": {"type": "integer", "minimum": 0},
                    "has_more": {"type": "boolean"},
                    "next_cursor": {}, "page_complete": {"type": "boolean"},
                    "collection_complete": {"type": "boolean"}, "version": {},
                }, "additionalProperties": True},
    },
    "allOf": [{"if": {"properties": {"status": {"const": "needs_attention"}},
                        "required": ["status"]},
               "then": {"required": ["code", "operation", "layer", "message", "fields",
                                     "retry_policy", "effect"]}}],
    "additionalProperties": True,
}
CONNECTION_TOOL = {
    "name": "get_connection_info",
    "description": "Read this connection's configured scope, tools and contract hash. Configuration is not proof of HTTP authorization. No credentials are returned.",
    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
}


class ContractError(ValueError):
    def __init__(self, code: str, message: str, *, fields: list[dict[str, Any]] | None = None,
                 fields_truncated: bool = False):
        super().__init__(message)
        self.code = code
        self.fields = fields or []
        self.fields_truncated = fields_truncated


def reference_id(value: Any, kind: str, field: str) -> str:
    """Accept a canonical ID or the exact declared typed reference, never prose/URIs.

    This is syntax adaptation only. Callers retain all authority/visibility checks.
    """
    if isinstance(value, str):
        prefix = kind + ":"
        candidate = value[len(prefix):] if value.startswith(prefix) else value
        if (candidate and candidate == candidate.strip() and ":" not in candidate
                and not any(c.isspace() or ord(c) < 32 for c in candidate)):
            return candidate
    raise ContractError("invalid_arguments", "Use the canonical ID or a " + kind + ":<id> reference",
                        fields=[{"path": "/" + field, "rule": "reference_type", "expected_kind": kind}])


def definitions(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = deepcopy(items)
    if not any(t["name"] == CONNECTION_TOOL["name"] for t in result):
        result.append(deepcopy(CONNECTION_TOOL))
    for item in result:
        item["outputSchema"] = deepcopy(OUTPUT_SCHEMA)
    return result


def validate(items: list[dict[str, Any]], name: str, arguments: Any) -> None:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise RuntimeError("Install the orchestration mcp extra to validate MCP contracts") from exc
    tool = next((t for t in items if t["name"] == name), None)
    if tool is None:
        raise ContractError("tool_not_available", "Tool is not advertised by this connection")
    errors = sorted(Draft202012Validator(tool["inputSchema"]).iter_errors(arguments),
                    key=lambda error: (tuple(str(p) for p in error.absolute_path),
                                       str(error.validator), str(error.message)))
    expanded: list[Any] = []
    for error in errors:
        if error.validator == 'oneOf' and isinstance(error.instance, dict):
            branches = error.schema.get('oneOf', [])
            matches = [i for i, branch in enumerate(branches)
                       if branch.get('properties', {}).get('type', {}).get('const') == error.instance.get('type')
                       and 'const' in branch.get('properties', {}).get('type', {})]
            if len(matches) == 1:
                expanded.extend(child for child in error.context if list(child.schema_path)[0] == matches[0])
                continue
            allowed = [b.get('properties', {}).get('type', {}).get('const') for b in branches]
            if allowed and all(isinstance(v, str) for v in allowed):
                error._origin_allowed = allowed
        expanded.append(error)
    errors = expanded
    if errors:
        fields = []
        fields_truncated = len(errors) > 8
        for error in errors[:8]:
            path = "/" + "/".join(str(v).replace("~", "~0").replace("/", "~1") for v in error.absolute_path) if error.absolute_path else ""
            field: dict[str, Any] = {"path": path, "rule": error.validator}
            if hasattr(error, '_origin_allowed'):
                field.update(path=(path + '/type')[:512], rule='enum', allowed=error._origin_allowed)
            if error.validator == "required" and isinstance(error.instance, dict):
                missing = sorted(v for v in error.validator_value if v not in error.instance)
                fields_truncated |= len(missing) > 8 or any(len(str(key)) > 160 for key in missing)
                field["missing"] = [str(key)[:160] for key in missing[:8]]
                field["path"] = path + "/" + str(missing[0]).replace("~", "~0").replace("/", "~1") if missing else path
            elif error.validator == "additionalProperties" and isinstance(error.instance, dict):
                unknown = sorted(set(error.instance) - set(error.schema.get("properties", {})))
                fields_truncated |= len(unknown) > 8 or any(len(str(key)) > 160 for key in unknown)
                field["unknown"] = [str(key)[:160] for key in unknown[:8]]
                field["path"] = path + "/" + str(field["unknown"][0]).replace("~", "~0").replace("/", "~1") if field["unknown"] else path
            elif error.validator == "type":
                field["expected_type"] = error.validator_value
            elif error.validator == "enum":
                field["allowed"] = error.validator_value
            elif error.validator == "pattern":
                field["expected_pattern"] = error.validator_value
            elif error.validator in {"maxItems", "minItems", "maxLength", "minLength"}:
                field.update(expected_limit=error.validator_value, actual=len(error.instance),
                             unit="items" if "Items" in error.validator else "unicode_code_points")
            elif error.validator in {"maximum", "minimum", "exclusiveMaximum", "exclusiveMinimum"}:
                # Never copy an arbitrary instance into the public error.
                if (isinstance(error.instance, (int, float)) and not isinstance(error.instance, bool)
                        and (isinstance(error.instance, int) or math.isfinite(error.instance))):
                    field.update(expected_limit=error.validator_value, actual=error.instance,
                                 unit="utf8_bytes" if path.endswith("/max_bytes") else "number")
            fields.append(field)
            fields_truncated |= len(field["path"]) > 512
            field["path"] = field["path"][:512]
        validation_error = ContractError("invalid_arguments", "Arguments do not match the advertised schema",
                            fields=fields, fields_truncated=fields_truncated)
        if (name == "read_field_review" and any(f["path"] == "/max_bytes" for f in fields)
                and "maximum" in tool["inputSchema"]["properties"]["max_bytes"]):
            schema = tool["inputSchema"]["properties"]["max_bytes"]
            setattr(validation_error, "budget", {"minimum": schema["minimum"], "maximum": schema["maximum"],
                                    "default": schema["default"], "unit": "utf8_bytes"})
            setattr(validation_error, "guidance", "Omit max_bytes for the default page; use next_read to continue")
            if isinstance(arguments, dict):
                setattr(validation_error, "next_step", {"tool": name,
                    "arguments": {k: v for k, v in arguments.items() if k != "max_bytes"
                                  and k in tool["inputSchema"]["properties"]}})
        raise validation_error


def validate_schema(schema: dict[str, Any]) -> None:
    """Validate a public input/output schema using the optional MCP dependency."""
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise RuntimeError("Install the orchestration mcp extra to validate MCP contracts") from exc
    Draft202012Validator.check_schema(schema)


def connection_info(surface: str, tools: list[dict[str, Any]], binding: dict[str, Any]) -> dict[str, Any]:
    raw = json.dumps(tools, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    try:
        package_version = version("issue-workflow-orchestrator")
    except PackageNotFoundError:
        package_version = "source"
    return {
        "contract_version": CONTRACT_VERSION, "surface": surface,
        "tools_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "tools_hash_algorithm": "sha256(utf8(json.dumps(tools,ensure_ascii=false,sort_keys=true,separators=(',',':'))))",
        "tools": [t["name"] for t in tools], "binding": binding,
        "authorization_check": "not_performed", "max_result_bytes": MAX_RESULT_BYTES,
        "configuration_check": "valid", "stdio_check": "running",
        "package_version": package_version,
    }


def failure(exc: Exception, *, operation: str, write: bool = False) -> dict[str, Any]:
    code = getattr(exc, "code", "internal_error")
    fields = getattr(exc, "fields", [])
    fields_truncated = bool(getattr(exc, "fields_truncated", False))
    layer = "adapter"
    policy = "stop"
    effect = "unknown" if write else "not_applicable"
    message = str(exc) if code != "internal_error" else "Operation failed; ask the host to inspect diagnostics"
    if isinstance(exc, WorkflowAPIError):
        layer = "http"
        message = "Issue Manager rejected the request" if exc.status < 500 else "Delivery outcome requires reconciliation"
        # Only finite, recognized rules and paths are safe to forward. Never copy
        # arbitrary HTTP messages/details (which may contain a signed URL or SQL).
        if exc.status == 400 and exc.details.get("origin_contract") == "field-origin/v1":
            rules = {"type", "nonWhitespace", "maxLength", "losslessLocator", "validUtf8Json",
                     "additionalProperties", "required", "registeredAttachment", "serverState", "enum"}
            raw_fields = exc.details.get("fields", [])
            raw_fields = raw_fields if isinstance(raw_fields, list) else []
            fields = [{"path": f["path"], "rule": f["rule"]}
                      for f in raw_fields[:8]
                      if isinstance(f, dict) and isinstance(f.get("rule"), str) and f["rule"] in rules
                      and isinstance(f.get("path"), str)
                      and re.fullmatch(r"/(?:origin|unresolved/[0-9]{1,3}/origin|attachment_refs/[0-9]{1,3})(?:/(?:type|attachment_ref|part_locator|quoted_text))?", f["path"])]
            if fields:
                message = "Attachment anchor failed the indicated contract rule; references must match exactly and verification state is server-only"
                policy = "correct_arguments"
                fields_truncated = len(raw_fields) > len(fields)
        if exc.retryable:
            policy = "recover_original" if write else "retry_read"
            if write:
                effect = "unknown"
        elif exc.status in {401, 403}:
            policy = "host_required"
            if write:
                effect = "not_committed"
        elif exc.status == 409:
            policy = "reread_and_decide"
            if write:
                effect = "not_committed"
        elif write and exc.status < 500:
            effect = "not_committed"
    elif isinstance(exc, (TimeoutError, OSError)):
        code, layer = "transport_error", "transport"
        message = "Connection failed; recover the original delivery before starting another"
        policy = "recover_original" if write else "retry_read"
        effect = "unknown" if write else "not_applicable"
    elif getattr(exc, "status", None) is not None:
        status = getattr(exc, "status")
        layer = "http"
        message = "Remote source rejected the request" if status < 500 else "Remote outcome requires original-identity reconciliation"
        if status in {401, 403}:
            policy = "host_required"
            effect = "not_committed" if write else "not_applicable"
        elif status == 409:
            policy = "reread_and_decide"
            effect = "not_committed" if write else "not_applicable"
        elif status >= 500:
            policy = "recover_original" if write else "retry_read"
            effect = "unknown" if write else "not_applicable"
        elif write:
            effect = "not_committed"
    elif code in {"invalid_arguments", "invalid_input", "invalid_origin", "invalid_page", "invalid_kind"}:
        policy = "correct_arguments"
        if write:
            effect = "not_committed"
    elif code == "packet_too_large":
        policy, effect = "correct_arguments", "not_committed"
    elif code in {"missing_configuration", "invalid_configuration", "missing_visibility", "packet_not_visible", "forbidden", "wrong_holder"}:
        policy = "host_required"
        if write:
            effect = "not_committed"
    elif code in {"stale_revision", "version_conflict", "intent_conflict", "idempotency_conflict", "snapshot_changed"}:
        policy = "reread_and_decide"
    elif code in {"recovery_required", "execution_unknown", "execution_unavailable",
                  "source_unavailable", "source_http_error", "stale_observation"}:
        policy, effect = "recover_original", "unknown" if write else "not_applicable"
    elif code == "response_too_large":
        policy = "read_smaller_page"
    if isinstance(exc, ContractError) and write:
        effect = "not_committed"
    phase = getattr(exc, "phase", "validation" if isinstance(exc, ContractError) else None)
    effect = getattr(exc, "effect", effect)
    if effect == "not_committed" and phase in {"intent_persistence", "rejection_persistence"}:
        policy = "host_required"
    if effect == "unknown" and getattr(exc, "delivery_id", None):
        policy = "recover_original"
    if isinstance(exc, WorkflowAPIError) and exc.status < 500 and not exc.retryable:
        if operation == "submit_field_packet" and exc.status not in {401, 403, 409}:
            policy = "correct_arguments"
    # Static operation preconditions only: never echo HTTP details, infer an
    # object's identity, or turn a refusal/unknown result into a retry permit.
    guidance = None
    local_operation = operation.removeprefix("board__")
    if effect == "not_committed":
        if (operation == "curate_field_item" and code == "not_found"
                and isinstance(exc, WorkflowAPIError) and exc.status == 404):
            guidance = ("Check packet_id and related_evidence target_ref against original receipts or mappings. "
                "target_kind=evidence_id requires an existing Evidence ID; artifact labels/URIs are source anchors. "
                "fact_ref requires an existing mapping in this packet. Do not widen scope or invent an ID.")
        elif code == "wrong_holder" and local_operation == "handle_handoff":
            guidance = ("Only the receiving mailbox may handle an incoming handoff. "
                "A reply to your outgoing question is input for the current work's adoption/sufficiency judgment; "
                "use its existing business exit.")
        elif code == "wrong_holder" and local_operation in {"withdraw_handoff", "replace_handoff"}:
            guidance = "Only the original sender may withdraw or replace its own pending handoff; terminal handoffs cannot reopen."
        elif (code == "invalid_transition" and isinstance(exc, ContractError)
                and operation in {"save_contribution", "save_working_conclusion"}):
            guidance = ("A declared request disposition ends new writes. Save remaining content before adoption/completion. "
                "If the original delivery is unfinished, recover that original intent instead.")
    return {
        "contract_version": CONTRACT_VERSION, "status": "needs_attention",
        "error": code, "code": code, "operation": operation, "layer": layer,
        "message": message, "fields": fields, "retry_policy": policy,
        "fields_truncated": fields_truncated,
        **({"guidance": guidance} if guidance else {}),
        "retryable": policy in {"recover_original", "retry_read"},
        "effect": effect, "saved": True if effect == "committed" else (False if effect == "not_committed" else None),
        **({"http_status": getattr(exc, "status")} if getattr(exc, "status", None) is not None else {}),
        **({"delivery_id": getattr(exc, "delivery_id")} if getattr(exc, "delivery_id", None) else {}),
        **({"phase": phase} if phase else {}),
        **{key: getattr(exc, key) for key in ("budget", "guidance", "next_step", "matched_count",
                                              "origin_pointer", "origin_candidates")
           if hasattr(exc, key)},
    }


def reference(kind: str, object_id: str, tool: str, arguments: dict[str, Any],
              *, scope: str | None = None, version: Any = None,
              readability: str = "available") -> dict[str, Any]:
    return {"kind": kind, "id": object_id, "scope_issue_id": scope, "version": version,
            "readability": readability,
            "read": {"tool": tool, "arguments": arguments}}


def page(items: list[Any], cursor: Any, *, version: Any = None) -> dict[str, Any]:
    return {"count": len(items), "has_more": cursor is not None, "next_cursor": cursor,
            "page_complete": True, "collection_complete": cursor is None, "version": version}


def response(value: dict[str, Any], *, operation: str, write: bool = False) -> tuple[dict[str, Any], str, bool]:
    result = {**value, "contract_version": CONTRACT_VERSION}
    is_error = result.get("status") == "needs_attention" or "error" in result
    if is_error:
        result.setdefault("code", result.get("error", "operation_failed"))
        result.setdefault("layer", "adapter")
        result.setdefault("retry_policy", "stop")
        result.setdefault("effect", "unknown" if write else "not_applicable")
        result.setdefault("fields", [])
        result.setdefault("fields_truncated", False)
        result.setdefault("operation", operation)
        result.setdefault("message", "Operation needs attention")
    elif write:
        result.setdefault("delivery", {"state": "committed", "replayed": bool(result.get("delivery_replayed")),
                                       "current_state_verified": False})
    if "items" in result and isinstance(result["items"], list):
        result.setdefault("page", page(result["items"], result.get("next_cursor"),
                                       version=result.get("curation_version")))
    serialized = json.dumps(result, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    if len(serialized.encode("utf-8")) > MAX_RESULT_BYTES:
        fallback = failure(ContractError("response_too_large", "Read a smaller page or a specific source"),
                           operation=operation)
        if write and is_error:
            fallback.update({key: result[key] for key in (
                "code", "error", "layer", "retry_policy", "effect", "saved", "http_status", "delivery_id"
            ) if key in result})
            fallback["message"] = "Delivery response exceeded the output budget; use its delivery status or recovery tool"
            if fallback.get("effect") == "unknown":
                fallback["retry_policy"] = "recover_original"
        elif write:
            fallback.update(effect="committed", saved=True, retry_policy="stop",
                            message="Delivery committed; query its compact status using delivery_id",
                            delivery={"state": "committed", "replayed": False,
                                      "current_state_verified": False})
            if result.get("delivery_id") is not None:
                fallback["delivery_id"] = result["delivery_id"]
            fallback["object_refs"] = {k: result[k] for k in (
                "conclusion_id", "packet_id", "review_id", "evidence_id", "round_id", "task_ids"
            ) if k in result}
        result = fallback
        serialized = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        is_error = True
    return result, serialized, is_error
