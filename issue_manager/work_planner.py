"""Shared planning decisions for working-history mutations."""
from __future__ import annotations

from typing import Any

from .errors import NotFoundError, ValidationError
from .service import ENTRY_TYPES


def plan_append(view: Any, operation: dict[str, Any]) -> dict[str, Any]:
    issue_id = str(operation["issue_id"])
    issue = view.issue(issue_id)
    if issue.get("work_status") in {"void", "archived"}:
        raise NotFoundError(f"Issue not found or inactive: {issue_id}")
    simulation = bool(operation.get("_simulation"))
    entry_type = str(operation.get("entry_type", "note"))
    if not simulation and entry_type not in ENTRY_TYPES:
        raise ValidationError(f"Unknown entry type: {entry_type}")
    body = operation.get("body", "")
    if not simulation and (not isinstance(body, str) or not body.strip()):
        raise ValidationError("Working entry body cannot be empty")
    refs = list(dict.fromkeys(str(evidence_id) for evidence_id in operation.get("evidence_refs", [])))
    if not simulation:
        for evidence_id in refs:
            evidence = view.evidence(evidence_id)
            if evidence.get("lifecycle_status") != "active":
                raise ValidationError(f"Evidence does not exist or is void: {evidence_id}")
    return {
        "issue_id": issue_id,
        "body": body,
        "entry_type": entry_type,
        "evidence_refs": refs,
        "before_working_revision": int(issue["working_revision"]),
        "working_revision": int(issue["working_revision"]) + 1,
        "conclusion_revision": issue["conclusion_revision"],
        "propagates": False,
    }
