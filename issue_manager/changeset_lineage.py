from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .errors import ConflictError, NotFoundError, ValidationError


class ChangeSetLineageMixin:
    """Audited replacement and abandonment lifecycle for immutable ChangeSets."""

    credentials: Any
    store: Any

    def _lifecycle_event(
        self,
        changeset_id: str,
        *,
        conn: sqlite3.Connection | None = None,
    ) -> dict[str, Any] | None:
        active = conn or self.store.conn
        value = active.execute(
            "SELECT event_id,timestamp,actor,action,reason,payload_json FROM audit_events "
            "WHERE object_type='changeset' AND object_id=? "
            "AND action IN ('changeset.supersede','changeset.abandon') "
            "ORDER BY rowid DESC LIMIT 1",
            (changeset_id,),
        ).fetchone()
        if not value:
            return None
        event = dict(value)
        event["payload"] = json.loads(event.pop("payload_json"))
        return event

    def replacement_chain(self, changeset_id: str) -> list[dict[str, Any]]:
        if not self.store.row("SELECT 1 FROM changesets WHERE changeset_id=?", (changeset_id,)):
            raise NotFoundError(f"ChangeSet not found: {changeset_id}")
        ancestors: list[str] = []
        current: str | None = changeset_id
        seen: set[str] = set()
        while current and current not in seen:
            seen.add(current)
            ancestors.append(current)
            parent = self.store.row(
                "SELECT parent_changeset_id FROM changesets WHERE changeset_id=?",
                (current,),
            )
            current = (
                str(parent["parent_changeset_id"])
                if parent and parent.get("parent_changeset_id")
                else None
            )
        chain_ids = list(reversed(ancestors))
        current = chain_ids[-1]
        while current:
            lifecycle = self._lifecycle_event(current)
            replacement = (
                lifecycle.get("payload", {}).get("replacement_changeset_id")
                if lifecycle and lifecycle["action"] == "changeset.supersede"
                else None
            )
            if not replacement or replacement in chain_ids:
                break
            chain_ids.append(str(replacement))
            current = str(replacement)
        result: list[dict[str, Any]] = []
        for item_id in chain_ids:
            row = self.store.row(
                "SELECT changeset_id,parent_changeset_id,state,last_error,created_at,updated_at "
                "FROM changesets WHERE changeset_id=?",
                (item_id,),
            )
            if not row:
                continue
            lifecycle = self._lifecycle_event(item_id)
            row["storage_state"] = row["state"]
            row["lifecycle"] = lifecycle
            if lifecycle:
                row["state"] = (
                    "superseded" if lifecycle["action"] == "changeset.supersede" else "abandoned"
                )
            result.append(row)
        return result

    def replacement_chains_for_issue(self, issue_id: str) -> list[list[dict[str, Any]]]:
        relevant: list[str] = []
        for row in self.store.rows(
            "SELECT changeset_id,changeset_json FROM changesets ORDER BY created_at"
        ):
            payload = json.loads(row["changeset_json"])
            expectations = payload.get("expected_revisions", {})
            operations = payload.get("operations", [])
            touches_issue = issue_id in expectations or any(
                isinstance(operation, dict)
                and issue_id
                in {
                    operation.get("issue_id"),
                    operation.get("consumer"),
                    operation.get("provider"),
                }
                for operation in operations
            )
            if touches_issue:
                relevant.append(row["changeset_id"])
        chains: list[list[dict[str, Any]]] = []
        seen: set[tuple[str, ...]] = set()
        for changeset_id in relevant:
            chain = self.replacement_chain(changeset_id)
            identity = tuple(item["changeset_id"] for item in chain)
            if identity not in seen and (
                len(chain) > 1 or any(item.get("lifecycle") for item in chain)
            ):
                seen.add(identity)
                chains.append(chain)
        return chains

    def _ensure_actionable(
        self,
        changeset_id: str,
        *,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        lifecycle = self._lifecycle_event(changeset_id, conn=conn)
        if lifecycle:
            state = "superseded" if lifecycle["action"] == "changeset.supersede" else "abandoned"
            raise ConflictError(
                f"ChangeSet is {state} and cannot be mutated",
                details={"lifecycle": lifecycle},
            )

    def supersede(
        self,
        changeset_id: str,
        replacement_changeset_id: str,
        *,
        reason: str,
        credential: str | Path,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "changeset.submit")
        if not reason.strip():
            raise ValidationError("Superseding a ChangeSet requires a reason")
        with self.store.transaction() as conn:
            original = conn.execute(
                "SELECT * FROM changesets WHERE changeset_id=?", (changeset_id,)
            ).fetchone()
            replacement = conn.execute(
                "SELECT * FROM changesets WHERE changeset_id=?",
                (replacement_changeset_id,),
            ).fetchone()
            if not original:
                raise NotFoundError(f"ChangeSet not found: {changeset_id}")
            if not replacement:
                raise NotFoundError(f"Replacement ChangeSet not found: {replacement_changeset_id}")
            self._ensure_actionable(changeset_id, conn=conn)
            if original["state"] == "applied":
                raise ConflictError("An applied ChangeSet cannot be superseded")
            if replacement_changeset_id == changeset_id:
                raise ValidationError("A ChangeSet cannot replace itself")
            if replacement["parent_changeset_id"] != changeset_id:
                raise ValidationError(
                    "Replacement ChangeSet must declare parent_changeset_id as the superseded ChangeSet"
                )
            existing_link = conn.execute(
                "SELECT object_id FROM audit_events WHERE object_type='changeset' "
                "AND action='changeset.supersede' AND payload_json LIKE ? LIMIT 1",
                (f'%"replacement_changeset_id":"{replacement_changeset_id}"%',),
            ).fetchone()
            if existing_link:
                raise ConflictError(
                    "Replacement ChangeSet is already linked to another superseded ChangeSet"
                )
            payload = {
                "changeset_id": changeset_id,
                "previous_state": original["state"],
                "replacement_changeset_id": replacement_changeset_id,
                "replacement_state": replacement["state"],
                "actor_id": auth.actor_id,
                "run_id": auth.run_id,
            }
            event_id = self.store.audit(
                conn,
                actor=auth.actor_id,
                action="changeset.supersede",
                object_type="changeset",
                object_id=changeset_id,
                before_revision=None,
                after_revision=None,
                reason=reason.strip(),
                payload=payload,
            )
        return {
            **payload,
            "state": "superseded",
            "reason": reason.strip(),
            "event_id": event_id,
            "replacement_chain": self.replacement_chain(changeset_id),
        }

    def abandon(
        self,
        changeset_id: str,
        *,
        reason: str,
        credential: str | Path,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "changeset.submit")
        if not reason.strip():
            raise ValidationError("Abandoning a ChangeSet requires a reason")
        with self.store.transaction() as conn:
            changeset = conn.execute(
                "SELECT * FROM changesets WHERE changeset_id=?", (changeset_id,)
            ).fetchone()
            if not changeset:
                raise NotFoundError(f"ChangeSet not found: {changeset_id}")
            self._ensure_actionable(changeset_id, conn=conn)
            if changeset["state"] == "applied":
                raise ConflictError("An applied ChangeSet cannot be abandoned")
            payload = {
                "changeset_id": changeset_id,
                "previous_state": changeset["state"],
                "actor_id": auth.actor_id,
                "run_id": auth.run_id,
            }
            event_id = self.store.audit(
                conn,
                actor=auth.actor_id,
                action="changeset.abandon",
                object_type="changeset",
                object_id=changeset_id,
                before_revision=None,
                after_revision=None,
                reason=reason.strip(),
                payload=payload,
            )
        return {
            **payload,
            "state": "abandoned",
            "reason": reason.strip(),
            "event_id": event_id,
        }
