"""Small project editing HTTP surface. Domain writes remain in existing services."""

from __future__ import annotations

import json
from typing import Any

from .errors import PermissionError, ValidationError
from .security import AuthContext
from .service import IssueManager


def handles(method: str, parts: list[str]) -> bool:
    return (method, "/".join(parts)) in {
        ("POST", "v1/issues"),
        ("POST", "v1/intake"),
        ("GET", "v1/project/editor"),
        ("GET", "v1/evidence"),
        ("GET", "v1/intake"),
    } or (method == "GET" and len(parts) == 3 and parts[:2] == ["v1", "intake"])


def text_field(body: dict[str, Any], key: str, *, required: bool = False) -> str:
    value = body.get(key, "")
    if not isinstance(value, str) or (required and not value.strip()):
        raise ValidationError(
            f"{key} must be a non-empty string" if required else f"{key} must be a string"
        )
    return value


def dispatch(
    manager: IssueManager,
    method: str,
    parts: list[str],
    query: dict[str, list[str]],
    body: dict[str, Any],
    auth: AuthContext,
    credential: str,
    idempotency_key: str | None,
) -> Any:
    if auth.platform_id:
        raise PermissionError("Project editing endpoints require an unscoped project principal")
    if method == "POST":
        key = f"desktop-http:{auth.actor_id}:{auth.run_id}:{idempotency_key}"
        if parts == ["v1", "issues"]:
            auth.require("issue.write")
            for field in ("parent_issue_id", "issue_type_registration_id"):
                if body.get(field) is not None:
                    text_field(body, field, required=True)
            if body.get("scope") is not None and not isinstance(body["scope"], dict):
                raise ValidationError("scope must be an object")
            return manager.create_issue(
                text_field(body, "issue_id", required=True),
                text_field(body, "issue_type", required=True),
                text_field(body, "title", required=True),
                parent_issue_id=body.get("parent_issue_id"),
                scope=body.get("scope"),
                actor=auth.actor_id,
                reason=text_field(body, "reason"),
                idempotency_key=key,
                issue_type_registration_id=body.get("issue_type_registration_id"),
            )
        auth.require("intake.submit")
        packet = body.get("packet")
        if not isinstance(packet, dict):
            raise ValidationError("packet must be an object")
        return manager.intake.submit(packet, credential=credential, idempotency_key=key)
    auth.require("context.read")
    if parts == ["v1", "project", "editor"]:
        return {
            "capabilities": sorted(auth.capabilities),
            "issue_types": sorted(manager.policy.data.get("issue_types", {})),
            "evidence_kinds": [
                "external",
                "script",
                "report",
                "artifact",
                "datavault_dataset",
                "bridge_job",
            ],
            "relation_defaults": manager.policy.evidence_relation_defaults(),
        }
    if len(parts) == 3:
        return manager.intake.show(parts[2])
    try:
        limit = int(query.get("limit", ["100"])[0])
        offset = int(query.get("offset", ["0"])[0])
    except ValueError as exc:
        raise ValidationError("limit and offset must be integers") from exc
    if not 1 <= limit <= 200 or offset < 0:
        raise ValidationError("limit must be 1..200 and offset must be non-negative")
    search = query.get("q", [""])[0]
    if parts == ["v1", "evidence"]:
        rows = manager.store.rows(
            "SELECT evidence_id,kind,locator,declared_source_locator,"
            "coalesce(declared_source_locator,locator) AS source_locator,"
            "CASE WHEN declared_source_locator IS NULL THEN 'source' ELSE 'internal_identity' END AS locator_role,"
            "short_description,quality_status,lifecycle_status,created_at "
            "FROM evidence_refs WHERE instr(lower(locator || ' ' || coalesce(declared_source_locator,'') || ' ' || short_description || ' ' || evidence_id),lower(?))>0 "
            "ORDER BY created_at DESC,evidence_id DESC LIMIT ? OFFSET ?",
            (search, limit + 1, offset),
        )
        # Fetch memberships in one bounded query per metadata page, including
        # evidence attached to several Issues. This is a projection, not new storage.
        memberships: dict[str, list[str]] = {row["evidence_id"]: [] for row in rows}
        if memberships:
            placeholders = ",".join("?" for _ in memberships)
            for link in manager.store.rows(
                f"SELECT evidence_id,issue_id FROM issue_evidence WHERE evidence_id IN ({placeholders}) ORDER BY issue_id",
                tuple(memberships),
            ):
                memberships[link["evidence_id"]].append(link["issue_id"])
        for row in rows:
            row["issue_ids"] = memberships[row["evidence_id"]]
    else:
        rows = manager.store.rows(
            "SELECT packet_id,request_id,status,packet_json,created_at FROM intake_packets "
            "WHERE instr(lower(packet_json),lower(?))>0 "
            "ORDER BY created_at DESC,packet_id DESC LIMIT ? OFFSET ?",
            (search, limit + 1, offset),
        )
        for row in rows:
            packet = json.loads(row.pop("packet_json"))
            row["packet"] = packet
    return {
        "items": rows[:limit],
        "has_more": len(rows) > limit,
        "next_offset": offset + min(limit, len(rows)),
    }
