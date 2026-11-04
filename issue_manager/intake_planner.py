"""Shared planning decisions for attaching an Intake packet to an Issue."""
from __future__ import annotations

from typing import Any

from .errors import NotFoundError, ValidationError


def plan_attach(view: Any, operation: dict[str, Any]) -> dict[str, Any]:
    issue_id = str(operation["issue_id"])
    issue = view.issue(issue_id)
    if issue.get("work_status") in {"void", "archived"}:
        raise NotFoundError(f"Issue not found or inactive: {issue_id}")
    packet_id = str(operation["packet_id"])
    packet = view.manager.store.row(
        "SELECT packet_id,packet_json,status,routing_state FROM intake_packets WHERE packet_id=?",
        (packet_id,),
    )
    if not packet:
        error = NotFoundError if operation.get("_direct") else ValidationError
        raise error(f"Intake packet not found: {packet_id}")
    return {"packet_id": packet_id, "issue_id": issue_id, "issue": issue, "packet": packet}
