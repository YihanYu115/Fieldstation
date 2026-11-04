"""Shared planning decisions for Question mutations."""
from __future__ import annotations

from typing import Any

from .errors import ConflictError, NotFoundError, ValidationError
from .question_service import _TRANSITIONS, QUESTION_KINDS
from .strict_json import require_strict_json

QUESTION_TARGETS = {
    "start": "in_progress",
    "block": "blocked",
    "defer": "deferred",
    "cancel": "cancelled",
    "reopen": "open",
}


def plan_create(view: Any, operation: dict[str, Any]) -> dict[str, Any]:
    issue_id = str(operation["issue_id"])
    view.issue(issue_id)
    prompt = operation.get("prompt")
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValidationError("Question prompt cannot be empty")
    kind = str(operation.get("question_kind", "experiment"))
    if kind not in QUESTION_KINDS:
        raise ValidationError(f"Unknown Question kind: {kind!r}")
    priority = operation.get("priority", 50)
    if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 100:
        raise ValidationError("Question priority must be an integer between 0 and 100")
    expected = operation.get("expected_evidence", [])
    if not isinstance(expected, list):
        raise ValidationError("expected_evidence must be an array")
    require_strict_json(expected, path="$.expected_evidence")
    question_id = operation.get("question_id")
    simulation = bool(operation.get("_simulation") or operation.get("_idempotency_probe"))
    if question_id and not simulation:
        existing = view.question_row(str(question_id))
        if existing:
            raise ConflictError(f"Question already exists: {question_id}")
    question_key = operation.get("question_key")
    if question_key is not None and not simulation and any(
        row.get("question_key") == question_key
        for row in view.context_rows("issue_questions", "issue_id", issue_id)
    ):
        raise ConflictError(f"Question key already exists in Issue: {question_key}")
    return {
        "issue_id": issue_id,
        "prompt": prompt.strip(),
        "question_id": str(question_id) if question_id else None,
        "question_key": question_key,
        "motivation": str(operation.get("motivation", "")),
        "question_kind": kind,
        "priority": priority,
        "expected_evidence": expected,
    }


def plan_transition(view: Any, operation: dict[str, Any]) -> dict[str, Any]:
    question_id = str(operation["question_id"])
    question = view.question(question_id)
    action = str(operation["action"])
    target = operation.get("target") or QUESTION_TARGETS.get(action)
    if target is None:
        raise ValidationError(f"Unsupported Question transition: {action}")
    target = str(target)
    if target not in _TRANSITIONS[question["status"]]:
        raise ConflictError(
            f"Question cannot transition from {question['status']!r} to {target!r}"
        )
    reason = str(operation.get("reason", ""))
    if target in {"blocked", "deferred", "cancelled", "open"} and not reason.strip():
        raise ValidationError(f"Question transition to {target!r} requires a reason")
    return {
        "question_id": question_id,
        "question": question,
        "action": action,
        "target": target,
        "reason": reason,
    }


def plan_answer(view: Any, operation: dict[str, Any]) -> dict[str, Any]:
    question_id = str(operation["question_id"])
    conclusion_id = str(operation["conclusion_id"])
    question = view.question(question_id)
    rows = view.context_rows("conclusion_revisions", "conclusion_id", conclusion_id)
    conclusion = rows[0] if rows else None
    if not conclusion:
        error = NotFoundError if operation.get("_direct") else ValidationError
        raise error(f"Conclusion not found: {conclusion_id}")
    if conclusion["issue_id"] != question["issue_id"]:
        raise ValidationError(
            "Question answer Conclusion must belong to the same Issue and exact revision"
        )
    if conclusion["status"] in {"disputed", "superseded", "retracted"}:
        raise ValidationError("Withdrawn Conclusion cannot answer a Question")
    return {"question_id": question_id, "conclusion_id": conclusion_id, "question": question}
