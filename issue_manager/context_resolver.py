"""Shared canonical comparison, subscription and domain row helpers."""

from __future__ import annotations

import json
from typing import Any

from .context_journal import NON_SEMANTIC
from .store import canonical_json


def subscription_key(table: str, column: str, value: Any) -> str:
    return canonical_json([table, column, value])


def normalized_equal(left, right):
    """Compare normalized JSON structures without Python's True == 1 alias."""
    return canonical_json(left) == canonical_json(right)


def semantic_row(row: dict[str, Any], *, table: str = "") -> dict[str, Any]:
    result = {}
    workflow_fields = {"status", "priority", "answer_conclusion_id", "status_reason"} if table == "issue_questions" else set()
    if table in {"evidence_applicability_decision_versions", "evidence_applicability_decision_heads"}:
        workflow_fields |= {
            "changeset_id", "qualification_json", "head_revision", "head_updated_at",
            "head_updated_by", "__simulated_validated__",
        }
    if table == "intake_packets":
        workflow_fields = set(row) - {"packet_id", "packet_version", "packet_json", "packet_hash"}
    for key, value in row.items():
        if key in NON_SEMANTIC or key in workflow_fields:
            continue
        if key.endswith("_json") and isinstance(value, str):
            value = json.loads(value)
        result[key] = value
    return result
