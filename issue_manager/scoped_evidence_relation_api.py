"""Narrow HTTP adapter for the S2 scoped relation service."""
from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl

from .errors import ValidationError


def handles(method: str, parts: list[str]) -> bool:
    return len(parts) >= 2 and parts[:2] == ["v1", "scoped-evidence-relations"]


def _strict(body: dict[str, Any], allowed: set[str]) -> None:
    unknown = set(body) - allowed
    if unknown:
        raise ValidationError(f"Unknown request fields: {sorted(unknown)}")


def _string(body: dict[str, Any], name: str, *, required: bool = True) -> str | None:
    if name not in body:
        if required:
            raise ValidationError(f"{name} is required")
        return None
    value = body[name]
    if not isinstance(value, str):
        raise ValidationError(f"{name} must be a string")
    return value


def _integer(body: dict[str, Any], name: str) -> int:
    value = body.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{name} must be an integer")
    return value


def _boolean(body: dict[str, Any], name: str, *, default: bool = False) -> bool:
    value = body.get(name, default)
    if not isinstance(value, bool):
        raise ValidationError(f"{name} must be boolean")
    return value


def _query(query: str, allowed: set[str]) -> dict[str, str]:
    values = parse_qsl(query, keep_blank_values=True, strict_parsing=False)
    result: dict[str, str] = {}
    for name, value in values:
        if name not in allowed:
            raise ValidationError(f"Unknown query parameter: {name}")
        if name in result:
            raise ValidationError(f"Duplicate query parameter: {name}")
        result[name] = value
    return result


def _query_integer(values: dict[str, str], name: str, default: int) -> int:
    raw = values.get(name)
    if raw is None or not raw:
        return default
    try:
        return int(raw, 10)
    except ValueError as exc:
        raise ValidationError(f"{name} must be an integer") from exc


def dispatch(manager: Any, method: str, parts: list[str], body: dict[str, Any], auth: Any,
              idempotency_key: str | None, *, query: str = "") -> Any:
    service = manager.scoped_evidence_relations
    if method == "GET" and len(parts) == 2:
        values = _query(query, {"scope_issue_id", "source_evidence_id", "limit", "max_bytes",
                                "cursor", "expected_snapshot", "relation_id"})
        scope_issue_id = values.get("scope_issue_id")
        source_evidence_id = values.get("source_evidence_id")
        if not scope_issue_id or not source_evidence_id:
            raise ValidationError("scope_issue_id and source_evidence_id are required")
        return service.from_source(
            scope_issue_id=scope_issue_id,
            source_evidence_id=source_evidence_id,
            auth=auth,
            limit=_query_integer(values, "limit", 8),
            max_bytes=_query_integer(values, "max_bytes", 16_384),
            cursor=values.get("cursor"),
            expected_snapshot=values.get("expected_snapshot"),
            relation_id=values.get("relation_id"),
        )
    if method == "GET" and len(parts) == 4 and parts[2] == "bindings":
        return service.binding(parts[3], auth=auth)
    if method == "GET" and len(parts) == 3:
        return service.show(parts[2], auth=auth)
    if method == "GET" and len(parts) == 4 and parts[3] == "history":
        values = _query(query, {"limit", "cursor"})
        cursor = _query_integer(values, "cursor", 0) if "cursor" in values else None
        return service.history(parts[2], auth=auth, limit=_query_integer(values, "limit", 50), cursor=cursor)
    if method != "POST":
        raise ValidationError("Unsupported scoped relation method")
    if len(parts) == 2:
        _strict(body, {"scope_issue_id", "source_evidence_id", "target_evidence_id", "relation_type", "rationale", "impact_policy", "expected_source_token", "expected_target_token"})
        return service.create(scope_issue_id=_string(body, "scope_issue_id"), source_evidence_id=_string(body, "source_evidence_id"), target_evidence_id=_string(body, "target_evidence_id"), relation_type=_string(body, "relation_type"), rationale=_string(body, "rationale"), impact_policy=_string(body, "impact_policy", required=False), expected_source_token=_string(body, "expected_source_token"), expected_target_token=_string(body, "expected_target_token"), auth=auth, idempotency_key=idempotency_key)
    if len(parts) == 4 and parts[3] in {"deactivate", "reactivate"}:
        _strict(body, {"expected_version_id", "reason"})
        handler = service.deactivate if parts[3] == "deactivate" else service.reactivate
        return handler(parts[2], expected_version_id=_string(body, "expected_version_id"), reason=_string(body, "reason"), auth=auth, idempotency_key=idempotency_key)
    if len(parts) == 4 and parts[3] == "revise":
        _strict(body, {"expected_version_id", "rationale", "impact_policy", "expected_source_token", "expected_target_token", "rebind"})
        rationale = _string(body, "rationale", required=False)
        impact_policy = _string(body, "impact_policy", required=False)
        source_token = _string(body, "expected_source_token", required=False)
        target_token = _string(body, "expected_target_token", required=False)
        return service.revise(parts[2], expected_version_id=_string(body, "expected_version_id"), rationale=rationale, impact_policy=impact_policy, expected_source_token=source_token, expected_target_token=target_token, rebind=_boolean(body, "rebind"), auth=auth, idempotency_key=idempotency_key)
    if len(parts) == 3 and parts[2] != "preview-selection":
        raise ValidationError("Scoped relation revise requires the /revise suffix")
    if parts == ["v1", "scoped-evidence-relations", "preview-selection"]:
        _strict(body, {"scope_issue_id", "seed_evidence_ids", "maximum_nodes", "maximum_relations"})
        seeds = body.get("seed_evidence_ids")
        if not isinstance(seeds, list) or any(not isinstance(item, str) for item in seeds):
            raise ValidationError("seed_evidence_ids must be an array of strings")
        return service.preview_selection(scope_issue_id=_string(body, "scope_issue_id"), seed_evidence_ids=seeds, maximum_nodes=_integer(body, "maximum_nodes"), maximum_relations=_integer(body, "maximum_relations"), auth=auth)
    raise ValidationError("Unknown scoped relation route")
