"""HTTP adapter for scoped-v2 frozen material packages and views."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, unquote_to_bytes

from .errors import NotFoundError, PermissionError, ValidationError


def handles(method: str, parts: list[str]) -> bool:
    return len(parts) >= 2 and parts[:2] == ["v1", "currentness"]


def _decode(value: str) -> str:
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ValidationError("Malformed URL escape in currentness path")
    try:
        decoded = unquote_to_bytes(value).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValidationError("Currentness path is not valid UTF-8") from exc
    if not decoded.strip():
        raise ValidationError("Currentness path parameter must be non-empty")
    return decoded


def _query(raw_query: str | dict[str, Any] | None) -> dict[str, str]:
    if raw_query is None:
        return {}
    if isinstance(raw_query, dict):
        result: dict[str, str] = {}
        for key, value in raw_query.items():
            if isinstance(value, list):
                if len(value) != 1:
                    raise ValidationError("Duplicate currentness query parameter")
                value = value[0]
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValidationError("Currentness query parameters must be strings")
            result[key] = value
        return result
    if re.search(r"%(?![0-9a-fA-F]{2})", raw_query):
        raise ValidationError("Malformed URL escape in currentness query")
    try:
        pairs = parse_qsl(
            raw_query,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=4,
        ) if raw_query else []
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValidationError("Invalid currentness query string") from exc
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("Duplicate currentness query parameter")
        result[key] = value
    return result


def _require_fields(body: dict[str, Any], allowed: set[str]) -> None:
    unknown = set(body) - allowed
    if unknown:
        raise ValidationError("Unknown context fields", details={"fields": sorted(unknown)})


def dispatch(
    manager: Any,
    method: str,
    parts: list[str],
    body: dict[str, Any],
    auth: Any,
    *,
    query: str | dict[str, Any] | None = None,
    idempotency_key: str | None = None,
) -> Any:
    auth.require("context.read")
    if auth.platform_id:
        raise PermissionError("Whole-context packages require an unscoped ledger principal")
    service = manager.context_maintenance

    if method == "POST" and parts == ["v1", "currentness", "prepare"]:
        auth.require("conclusion.propose")
        _require_fields(body, {"issue_id", "basis", "evidence_ids", "basis_mode", "descriptor"})
        issue_id = body.get("issue_id")
        if not isinstance(issue_id, str) or not issue_id:
            raise ValidationError("Context preparation needs an issue ID")
        manager._issue(issue_id)
        basis_mode = body.get("basis_mode")
        if basis_mode is not None and basis_mode != "current-basis":
            raise ValidationError("basis_mode must be current-basis")
        package = service.prepare(
            issue_id,
            basis=body.get("basis", []),
            evidence_ids=body["evidence_ids"] if "evidence_ids" in body else None,
            descriptor=body.get("descriptor"),
            actor=auth.actor_id,
        )
        materials = package["actual_input"].get("materials", {})
        for evidence_id in service._package_evidence_ids(materials):
            manager.evidence.require_read_access(evidence_id, auth)
        package["actual_input"] = {
            "summary": {
                "issue_id": issue_id,
                "candidate_states": materials.get("candidate_states", []),
                "evidence_ids": sorted(materials.get("evidence", {})),
                "provider_count": len(materials.get("providers", [])),
                "roots": materials.get("roots", []),
                "support_ids": materials.get("support_ids", []),
                "gap": materials.get("gap", []),
                "related_challenges": materials.get("related_challenges", []),
                "discovery_ids": materials.get("discovery_ids", []),
            },
            "presentation": "use POST /v1/currentness/packages/{id}/views",
        }
        return package

    if (
        method == "POST"
        and len(parts) == 5
        and parts[:3] == ["v1", "currentness", "packages"]
        and parts[4] == "views"
    ):
        auth.require("conclusion.propose")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValidationError("Context views require an Idempotency-Key")
        _require_fields(body, {"budget_bytes", "presentation_rule_id"})
        return service.create_view(
            _decode(parts[3]),
            auth=auth,
            budget_bytes=body.get("budget_bytes", 32768),
            presentation_rule_id=body.get("presentation_rule_id", "scoped-summary/v1"),
            idempotency_key=idempotency_key,
        )

    if method == "GET" and len(parts) == 4 and parts[2] == "views":
        values = _query(query)
        if set(values) - {"cursor"}:
            raise ValidationError("Unknown view query parameter")
        cursor_text = values.get("cursor")
        cursor: int | None = None
        if cursor_text is not None:
            try:
                cursor = int(cursor_text)
            except ValueError as exc:
                raise ValidationError("View cursor must be an integer") from exc
        return service.view(_decode(parts[3]), auth=auth, cursor=cursor)

    if method == "GET" and len(parts) == 7 and parts[2] == "views" and parts[4] == "entries":
        values = _query(query)
        if set(values) - {"cursor"}:
            raise ValidationError("Unknown frozen view entry query parameter")
        return service.entry(
            _decode(parts[3]), _decode(parts[5]), _decode(parts[6]),
            auth=auth, cursor=values.get("cursor"),
        )

    if method == "GET" and len(parts) == 6 and parts[2] == "views" and parts[4] == "materials":
        values = _query(query)
        if set(values) - {"cursor", "mode"}:
            raise ValidationError("Unknown view material query parameter")
        mode = values.get("mode", "selected")
        if mode not in {"selected", "excluded"}:
            raise ValidationError("mode must be selected or excluded")
        return service.material_page(
            _decode(parts[3]), _decode(parts[5]), auth=auth,
            cursor=values.get("cursor"), mode=mode,
        )

    if method == "GET" and len(parts) == 4 and parts[2] == "packages":
        auth.require("conclusion.propose")
        package = service.package(_decode(parts[3]))
        for evidence_id in service._package_evidence_ids(
            package["actual_input"].get("materials", {})
        ):
            manager.evidence.require_read_access(evidence_id, auth)
        return package

    raise NotFoundError("Unknown scoped-v2 currentness endpoint")
