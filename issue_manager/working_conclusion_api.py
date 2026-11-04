"""Narrow HTTP adapter for direct provisional working conclusions."""

from .errors import ValidationError


def handles(method, parts):
    return method == "POST" and len(parts) == 4 and parts[:2] == ["v1", "issues"] and parts[3] == "working-conclusion"


def dispatch(manager, body, auth, *, idempotency_key):
    auth.require("conclusion.record")
    if not isinstance(body, dict):
        raise ValidationError("Working conclusion body must be an object")
    allowed = {
        "issue_id", "expected_current_conclusion_id", "expected_conclusion_revision",
        "package_id", "view_id", "statement", "evidence_refs", "reason",
        "structured_outputs", "confidence", "applicability", "limitations", "expected_rule_revision",
    }
    unknown = set(body) - allowed
    if unknown:
        raise ValidationError("Unknown working conclusion fields", details={"fields": sorted(unknown)})
    if not isinstance(idempotency_key, str) or not idempotency_key.strip():
        raise ValidationError("Working conclusions require an Idempotency-Key")
    return manager.record_working_conclusion(body, auth=auth, idempotency_key=idempotency_key)
