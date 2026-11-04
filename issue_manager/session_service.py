from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import ValidationError
from .store import canonical_json, now

if TYPE_CHECKING:
    from .service import IssueManager


class SessionService:
    """Durable capture followed by best-effort, atomic derived maintenance."""

    MODES = {"auto", "capture", "maintain"}

    def __init__(self, manager: "IssueManager"):
        self.manager = manager
        self.store = manager.store

    def commit(
        self,
        packet: dict[str, Any],
        *,
        mode: str = "auto",
        credential: str | Path,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        if mode not in self.MODES:
            raise ValidationError("Session commit mode must be auto, capture, or maintain")
        capture = self.manager.intake.submit(
            packet,
            credential=credential,
            idempotency_key=idempotency_key or str(packet.get("request_id", "")) or None,
        )
        packet_id = capture["packet_id"]
        view = self.manager.intake._v2_view(packet)
        hints = view.get("routing_hints", {})
        components = hints.get("components", [])
        if not isinstance(components, list):
            components = [components]
        qubit = str(components[0]) if len(components) == 1 else None
        sample = str(hints.get("sample") or "")
        topic = str(hints.get("topic") or "")
        routing = (
            self.manager.resolve(sample=sample, qubit=qubit, topic=topic)
            if sample and topic
            else {
                "status": "ambiguous",
                "match": None,
                "candidates": [],
                "query": {"sample": sample, "qubit": qubit, "topic": topic},
            }
        )
        routing_state = routing["status"]
        if routing_state not in {"unique", "multiple", "not_found"}:
            routing_state = "ambiguous"
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE intake_packets SET routing_state=?,routing_snapshot_json=?,"
                "routing_policy_version=?,updated_at=? WHERE packet_id=?",
                (
                    routing_state,
                    canonical_json(routing),
                    self.manager.policy.version,
                    now(),
                    packet_id,
                ),
            )
        base = {
            "packet_id": packet_id,
            "capture_state": "persisted",
            "routing": routing,
            "changeset_id": None,
            "risk": None,
            "maintenance_state": "captured",
            "affected_issues": [],
            "deferred_proposals": [],
            "deferred_changesets": [],
            "pending_questions": [],
            "idempotent_replay": bool(capture.get("idempotent_replay")),
        }
        if mode == "capture":
            return base
        if routing.get("status") != "unique":
            return {
                **base,
                "maintenance_state": "deferred_to_inbox",
                "pending_questions": ["Routing is not unique; triage is required"],
            }
        issue_id = routing["match"]["issue_id"]
        proposed = view.get("proposed_changes", [])
        if not isinstance(proposed, list):
            raise ValidationError("proposed_changes must be a list")
        operations = [dict(item) for item in proposed]
        if not any(item.get("op") == "attach_packet" for item in operations):
            operations.insert(
                0, {"op": "attach_packet", "packet_id": packet_id, "issue_id": issue_id}
            )
        for operation in operations:
            if operation.get("op") == "attach_packet":
                operation.setdefault("packet_id", packet_id)
                operation.setdefault("issue_id", issue_id)
            elif operation.get("op") in {
                "attach_evidence",
                "append_work",
                "add_alias",
                "add_tag",
                "propose_conclusion",
                "refresh_issue",
                "mark_needs_review",
            }:
                operation.setdefault("issue_id", issue_id)
        issue = self.manager._issue(issue_id)
        changeset = {
            "changeset_version": 1,
            "source_packet_ids": [packet_id],
            "intent": "maintain-experiment-record",
            "expected_revisions": {
                issue_id: {
                    "working_revision": issue["working_revision"],
                    "conclusion_revision": issue["conclusion_revision"],
                }
            },
            "operations": operations,
        }
        try:
            existing_changeset = self.store.row(
                "SELECT changeset_id,risk_tier,risk_reasons_json FROM changesets "
                "WHERE source_packet_ids_json=? AND intent='maintain-experiment-record' "
                "ORDER BY created_at DESC LIMIT 1",
                (canonical_json([packet_id]),),
            )
            if existing_changeset:
                created = {
                    "changeset_id": existing_changeset["changeset_id"],
                    "risk": {
                        "tier": existing_changeset["risk_tier"],
                        "reasons": json.loads(existing_changeset["risk_reasons_json"]),
                        "required_reviews": 2
                        if existing_changeset["risk_tier"] == "T3"
                        else (1 if existing_changeset["risk_tier"] == "T2" else 0),
                    },
                }
            else:
                created = self.manager.changesets.create(
                    changeset,
                    credential=credential,
                    idempotency_key=f"session:{packet_id}:{canonical_json(operations)}",
                )
            current_changeset = self.manager.changesets.show(created["changeset_id"])
            if current_changeset["state"] == "applied":
                return {
                    **base,
                    "changeset_id": created["changeset_id"],
                    "risk": {
                        "tier": current_changeset["risk_tier"],
                        "reasons": current_changeset["risk_reasons"],
                        "required_reviews": 2
                        if current_changeset["risk_tier"] == "T3"
                        else (1 if current_changeset["risk_tier"] == "T2" else 0),
                    },
                    "maintenance_state": "applied",
                    "changeset_result": current_changeset,
                    "idempotent_replay": True,
                }
            if current_changeset["state"] == "awaiting_review":
                return {
                    **base,
                    "changeset_id": created["changeset_id"],
                    "risk": created["risk"],
                    "maintenance_state": "awaiting_review",
                    "deferred_changesets": [created["changeset_id"]],
                }
            validated = self.manager.changesets.validate(
                created["changeset_id"], credential=credential
            )
            result = {
                **base,
                "changeset_id": created["changeset_id"],
                "risk": created["risk"],
            }
            if validated["state"] == "awaiting_review":
                return {
                    **result,
                    "maintenance_state": "awaiting_review",
                    "deferred_changesets": [created["changeset_id"]],
                }
            applied = self.manager.changesets.apply(
                created["changeset_id"],
                credential=credential,
                idempotency_key=f"session-apply:{packet_id}",
            )
            affected_ids = {
                str(operation.get("issue_id") or operation.get("consumer"))
                for operation in operations
                if operation.get("issue_id") or operation.get("consumer")
            }
            affected = []
            for affected_id in sorted(affected_ids):
                try:
                    current = self.manager._issue(affected_id, active=False)
                except Exception:
                    continue
                affected.append(
                    {
                        "issue_id": affected_id,
                        "working_revision": current["working_revision"],
                        "conclusion_revision": current["conclusion_revision"],
                        "freshness": current["freshness"],
                    }
                )
            return {
                **result,
                "maintenance_state": "applied",
                "affected_issues": affected,
                "changeset_result": applied,
            }
        except Exception as exc:
            with self.store.transaction() as conn:
                conn.execute(
                    "UPDATE intake_packets SET status='pending',last_triage_error=?,updated_at=? "
                    "WHERE packet_id=? AND status NOT IN ('completed','rejected','merged')",
                    (str(exc), now(), packet_id),
                )
                conn.execute(
                    "UPDATE triage_tasks SET state='retry',last_error=?,updated_at=? "
                    "WHERE packet_id=? AND state NOT IN ('completed','rejected')",
                    (str(exc), now(), packet_id),
                )
            if mode == "maintain":
                return {
                    **base,
                    "maintenance_state": "deferred_to_inbox",
                    "pending_questions": [str(exc)],
                }
            return {
                **base,
                "maintenance_state": "deferred_to_inbox",
                "pending_questions": [str(exc)],
            }
