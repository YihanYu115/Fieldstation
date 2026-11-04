"""Finite public HTTP contract for atomic scoped Evidence contributions."""

from __future__ import annotations

from typing import Any

from .errors import ValidationError
from .evidence_identity import identity_locator


def handles(method: str, parts: list[str]) -> bool:
    return method == "POST" and parts == ["v1", "scoped-evidence-contributions"]


def _required_string(body: dict[str, Any], name: str) -> str:
    value = body.get(name)
    if not isinstance(value, str) or (value == "" if name == "source" else not value.strip()):
        raise ValidationError(f"{name} must be a non-empty string")
    if name == "source":
        try:
            identity_locator(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"source is invalid: {exc}") from exc
    return value


def dispatch(manager: Any, body: dict[str, Any], auth: Any, *, idempotency_key: str | None) -> Any:
    if not isinstance(body, dict):
        raise ValidationError("Scoped contribution body must be an object")
    allowed = {"issue_id", "kind", "source", "description", "reason", "related_evidence"}
    unknown = set(body) - allowed
    if unknown:
        raise ValidationError("Unknown scoped contribution fields", details={"fields": sorted(unknown)})
    related = body.get("related_evidence", [])
    if not isinstance(related, list):
        raise ValidationError("related_evidence must be an array")
    return manager.add_scoped_evidence_contribution(
        issue_id=_required_string(body, "issue_id"),
        kind=_required_string(body, "kind"),
        locator=_required_string(body, "source"),
        description=_required_string(body, "description"),
        reason=_required_string(body, "reason"),
        related_evidence=related,
        actor=auth.actor_id,
        auth=auth,
        idempotency_key=idempotency_key,
    )
