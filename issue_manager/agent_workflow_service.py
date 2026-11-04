"""Fenced, project-persistent orchestration for bounded human/agent collaboration."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from .errors import ConflictError, NotFoundError, PermissionError, ValidationError
from .store import canonical_json, new_id, now

if TYPE_CHECKING:
    import sqlite3

    from .security import AuthContext
    from .service import IssueManager


ROLES = {
    "material_curator",
    "local_researcher",
    "conclusion_maintainer",
    "scope_planner",
    "reviewer",
}
AUTONOMY_MODES = {"advise_only", "assigned_only", "bounded_autonomy"}
SUPPORTED_ACTIONS = {"append_work", "add_evidence", "create_proposal", "create_verification", "record_assessment", "relate_evidence"}
DEFAULT_BUDGET = {
    "max_work_items": 20,
    "max_attempts": 40,
    "max_commits": 20,
    "max_runtime_seconds": 3600,
    "max_context_bytes": 2_000_000,
}
MODE_PERMISSIONS = {
    "advise_only": {
        "can_propose_work": True,
        "can_create_work": False,
        "can_execute": False,
        "can_commit": False,
    },
    "assigned_only": {
        "can_propose_work": False,
        "can_create_work": False,
        "can_execute": True,
        "can_commit": True,
    },
    "bounded_autonomy": {
        "can_propose_work": True,
        "can_create_work": True,
        "can_execute": True,
        "can_commit": True,
    },
}


def _decode(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    for source, target, fallback in (
        ("scope_json", "scope", {}),
        ("permissions_json", "permissions", {}),
        ("budget_json", "budget", {}),
        ("stop_conditions_json", "stop_conditions", {}),
        ("acceptance_json", "acceptance", []),
        ("allowed_actions_json", "allowed_actions", []),
        ("package_json", "package", {}),
        ("payload_json", "payload", {}),
    ):
        if source in result:
            result[target] = json.loads(result.pop(source) or canonical_json(fallback))
    return result


class WorkflowService:
    """State machine and atomic ledger-commit gateway for workflow v1."""

    def __init__(self, manager: IssueManager):
        self.manager = manager
        self.store = manager.store

    @staticmethod
    def _require_key(idempotency_key: str | None) -> str:
        if not idempotency_key or not idempotency_key.strip():
            raise ValidationError("Workflow writes require a stable idempotency_key")
        return idempotency_key.strip()

    @staticmethod
    def _require(auth: AuthContext, *capabilities: str) -> None:
        for capability in capabilities:
            auth.require(capability)

    @staticmethod
    def _operation(name: str, auth: AuthContext) -> str:
        return f"workflow.{name}:{auth.actor_id}:{auth.run_id}"

    def _current_epoch(self, conn: sqlite3.Connection | None = None) -> int:
        connection = conn or self.store.conn
        row = connection.execute(
            "SELECT token_epoch FROM manager_metadata WHERE singleton=1"
        ).fetchone()
        if not row:
            raise ValidationError("Manager metadata is unavailable")
        return int(row[0])

    @staticmethod
    def _iso_now() -> datetime:
        return datetime.now().astimezone()

    @classmethod
    def _expired(cls, value: str) -> bool:
        return datetime.fromisoformat(value) <= cls._iso_now()

    @staticmethod
    def _validate_scope(scope: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(scope, dict):
            raise ValidationError("Workflow scope must be an object")
        unknown = set(scope) - {"issue_ids", "roles"}
        if unknown:
            raise ValidationError(f"Unknown workflow scope fields: {sorted(unknown)}")
        issue_ids = scope.get("issue_ids")
        if not isinstance(issue_ids, list) or not issue_ids or not all(
            isinstance(value, str) and value for value in issue_ids
        ):
            raise ValidationError("Workflow scope.issue_ids must be a non-empty string array")
        if len(set(issue_ids)) != len(issue_ids):
            raise ValidationError("Workflow scope.issue_ids contains duplicates")
        roles = scope.get("roles", sorted(ROLES))
        if not isinstance(roles, list) or not roles or not set(roles) <= ROLES:
            raise ValidationError("Workflow scope.roles contains an unsupported role")
        if len(set(roles)) != len(roles):
            raise ValidationError("Workflow scope.roles contains duplicates")
        return {"issue_ids": list(issue_ids), "roles": list(roles)}

    @staticmethod
    def _validate_budget(budget: dict[str, Any] | None) -> dict[str, int]:
        value = {**DEFAULT_BUDGET, **(budget or {})}
        if set(value) != set(DEFAULT_BUDGET):
            raise ValidationError(f"Workflow budget fields must be {sorted(DEFAULT_BUDGET)}")
        if any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in value.values()):
            raise ValidationError("Workflow budget values must be non-negative integers")
        return value

    @staticmethod
    def _snapshot(row: dict[str, Any]) -> dict[str, Any]:
        return {
            key: row[key]
            for key in (
                "mandate_id",
                "goal",
                "autonomy_mode",
                "scope_json",
                "permissions_json",
                "budget_json",
                "stop_conditions_json",
                "status",
                "revision",
                "fence",
                "activation_epoch",
                "work_items_created",
                "attempts_started",
                "commits_used",
                "runtime_seconds_used",
                "context_bytes_used",
                "stop_reason",
            )
        }

    def _record_revision(
        self,
        conn: sqlite3.Connection,
        mandate: dict[str, Any],
        *,
        event_type: str,
        auth: AuthContext,
    ) -> None:
        conn.execute(
            "INSERT INTO workflow_mandate_revisions VALUES (?,?,?,?,?,?,?)",
            (
                new_id("workflow_revision"),
                mandate["mandate_id"],
                mandate["revision"],
                event_type,
                canonical_json(self._snapshot(mandate)),
                auth.actor_id,
                now(),
            ),
        )

    def _event(
        self,
        conn: sqlite3.Connection,
        *,
        mandate_id: str,
        event_type: str,
        auth: AuthContext,
        work_item_id: str | None = None,
        attempt_id: str | None = None,
        before_state: str | None = None,
        after_state: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> str:
        event_id = new_id("workflow_event")
        conn.execute(
            "INSERT INTO workflow_events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                mandate_id,
                work_item_id,
                attempt_id,
                event_type,
                auth.actor_id,
                auth.run_id,
                before_state,
                after_state,
                canonical_json(payload or {}),
                now(),
            ),
        )
        return event_id

    @staticmethod
    def _mandate_row(conn: sqlite3.Connection, mandate_id: str) -> dict[str, Any]:
        row = conn.execute(
            "SELECT * FROM workflow_mandates WHERE mandate_id=?", (mandate_id,)
        ).fetchone()
        if not row:
            raise NotFoundError(f"Workflow mandate not found: {mandate_id}")
        return dict(row)

    @staticmethod
    def _item_row(conn: sqlite3.Connection, work_item_id: str) -> dict[str, Any]:
        row = conn.execute(
            "SELECT * FROM workflow_work_items WHERE work_item_id=?", (work_item_id,)
        ).fetchone()
        if not row:
            raise NotFoundError(f"Workflow work item not found: {work_item_id}")
        return dict(row)

    @staticmethod
    def _attempt_row(conn: sqlite3.Connection, attempt_id: str) -> dict[str, Any]:
        row = conn.execute(
            "SELECT * FROM workflow_attempts WHERE attempt_id=?", (attempt_id,)
        ).fetchone()
        if not row:
            raise NotFoundError(f"Workflow attempt not found: {attempt_id}")
        return dict(row)

    def _assert_epoch(self, mandate: dict[str, Any], conn: sqlite3.Connection) -> None:
        if int(mandate["activation_epoch"]) != self._current_epoch(conn):
            raise PermissionError(
                "Workflow mandate belongs to an inactive project token epoch; human reauthorization is required"
            )

    @staticmethod
    def _assert_expected(actual: int, expected: int, label: str) -> None:
        if actual != expected:
            raise ConflictError(f"Stale {label}: expected {expected}, current {actual}")

    @staticmethod
    def _within_scope(mandate: dict[str, Any], issue_id: str, role: str) -> bool:
        scope = json.loads(mandate["scope_json"])
        return issue_id in scope["issue_ids"] and role in scope["roles"]

    @staticmethod
    def _budget(mandate: dict[str, Any]) -> dict[str, int]:
        return json.loads(mandate["budget_json"])

    def _block_for_budget(
        self,
        conn: sqlite3.Connection,
        mandate: dict[str, Any],
        *,
        reason: str,
        auth: AuthContext,
    ) -> None:
        before = mandate["status"]
        mandate.update(
            status="blocked",
            stop_reason=reason,
            revision=int(mandate["revision"]) + 1,
            fence=int(mandate["fence"]) + 1,
            updated_at=now(),
            updated_by=auth.actor_id,
        )
        conn.execute(
            "UPDATE workflow_mandates SET status=?,stop_reason=?,revision=?,fence=?,updated_at=?,updated_by=? "
            "WHERE mandate_id=?",
            (
                mandate["status"],
                reason,
                mandate["revision"],
                mandate["fence"],
                mandate["updated_at"],
                mandate["updated_by"],
                mandate["mandate_id"],
            ),
        )
        conn.execute(
            "UPDATE workflow_attempts SET status='invalidated',rejection_code='budget_exhausted',ended_at=? "
            "WHERE mandate_id=? AND status IN ('claimed','running','submitted')",
            (mandate["updated_at"], mandate["mandate_id"]),
        )
        conn.execute(
            "UPDATE workflow_work_items SET status='blocked',revision=revision+1,updated_at=?,stop_reason=? "
            "WHERE mandate_id=? AND status IN ('ready','running','checkpointed')",
            (mandate["updated_at"], reason, mandate["mandate_id"]),
        )
        self._record_revision(conn, mandate, event_type="budget_blocked", auth=auth)
        self._event(
            conn,
            mandate_id=mandate["mandate_id"],
            event_type="mandate.budget_blocked",
            auth=auth,
            before_state=before,
            after_state="blocked",
            payload={"reason": reason},
        )

    @staticmethod
    def _inputs(conn, work_item_id):
        row = conn.execute(
            "SELECT payload_json FROM workflow_events WHERE work_item_id=? "
            "AND event_type='work_item.inputs' ORDER BY rowid LIMIT 1",
            (work_item_id,),
        ).fetchone()
        return json.loads(row[0])["inputs"] if row else []

    def submit_result(self, attempt_id: str, **arguments) -> dict[str, Any]:
        from .agent_workflow_results import submit_result

        return submit_result(self, attempt_id, **arguments)

    @staticmethod
    def _input_updates(conn, item, current_revision):
        previous = conn.execute(
            "SELECT issue_working_revision FROM workflow_attempts WHERE work_item_id=? "
            "ORDER BY attempt_number DESC LIMIT 1", (item["work_item_id"],)
        ).fetchone()
        if not previous or previous[0] == current_revision:
            return {"notice": "", "notes": []}
        # Bounded excerpts help re-evaluation; the worker may request missing context in M2.
        rows = conn.execute(
            "SELECT w.entry_id,w.body FROM audit_events a JOIN working_entries w "
            "ON w.entry_id=json_extract(a.payload_json,'$.entry_id') "
            "WHERE a.object_type='issue' AND a.object_id=? AND a.action='work.append' "
            "AND a.after_revision>? ORDER BY a.rowid DESC LIMIT 8",
            (item["issue_id"], previous[0]),
        ).fetchall()
        return {
            "notice": "问题记录已变化。以下为最多八条新增工作记录的节选；"
                      "请重新核对草稿，依据不足时交还并指出缺口。",
            "notes": [{"ref": "work:" + r["entry_id"], "text": r["body"][:2000]}
                      for r in reversed(rows)],
        }

    def create_mandate(
        self,
        *,
        goal: str,
        autonomy_mode: str,
        scope: dict[str, Any],
        allowed_actions: list[str] | None,
        budget: dict[str, Any] | None,
        stop_conditions: dict[str, Any] | None,
        auth: AuthContext,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require(auth, "workflow.manage")
        key = self._require_key(idempotency_key)
        if autonomy_mode not in AUTONOMY_MODES:
            raise ValidationError(f"Unknown autonomy mode: {autonomy_mode}")
        if not isinstance(goal, str) or not goal.strip():
            raise ValidationError("Workflow mandate goal is required")
        normalized_scope = self._validate_scope(scope)
        normalized_budget = self._validate_budget(budget)
        actions = sorted(set(allowed_actions or ["append_work"]))
        if not actions or not set(actions) <= SUPPORTED_ACTIONS:
            raise ValidationError(f"Unsupported workflow actions: {sorted(set(actions) - SUPPORTED_ACTIONS)}")
        conditions = {} if stop_conditions is None else stop_conditions
        if not isinstance(conditions, dict):
            raise ValidationError("stop_conditions must be an object")
        payload = {
            "goal": goal.strip(),
            "autonomy_mode": autonomy_mode,
            "scope": normalized_scope,
            "allowed_actions": actions,
            "budget": normalized_budget,
            "stop_conditions": conditions,
        }
        operation = self._operation("mandate.create", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            for issue_id in normalized_scope["issue_ids"]:
                if not conn.execute("SELECT 1 FROM issues WHERE issue_id=?", (issue_id,)).fetchone():
                    raise NotFoundError(f"Issue not found: {issue_id}")
            mandate_id = new_id("mandate")
            timestamp = now()
            row = {
                "mandate_id": mandate_id,
                "goal": payload["goal"],
                "autonomy_mode": autonomy_mode,
                "scope_json": canonical_json(normalized_scope),
                "permissions_json": canonical_json(
                    {**MODE_PERMISSIONS[autonomy_mode], "allowed_actions": actions}
                ),
                "budget_json": canonical_json(normalized_budget),
                "stop_conditions_json": canonical_json(conditions),
                "status": "active",
                "revision": 1,
                "fence": 1,
                "activation_epoch": self._current_epoch(conn),
                "work_items_created": 0,
                "attempts_started": 0,
                "commits_used": 0,
                "runtime_seconds_used": 0,
                "context_bytes_used": 0,
                "stop_reason": None,
                "created_at": timestamp,
                "created_by": auth.actor_id,
                "updated_at": timestamp,
                "updated_by": auth.actor_id,
            }
            conn.execute(
                f"INSERT INTO workflow_mandates ({','.join(row)}) VALUES ({','.join('?' for _ in row)})",
                tuple(row.values()),
            )
            self._record_revision(conn, row, event_type="created", auth=auth)
            event_id = self._event(
                conn,
                mandate_id=mandate_id,
                event_type="mandate.created",
                auth=auth,
                after_state="active",
                payload=payload,
            )
            response = {"mandate_id": mandate_id, "revision": 1, "fence": 1, "event_id": event_id}
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response

    def show_mandate(self, mandate_id: str, *, auth: AuthContext) -> dict[str, Any]:
        self._require(auth, "workflow.read")
        mandate = self.store.row("SELECT * FROM workflow_mandates WHERE mandate_id=?", (mandate_id,))
        if not mandate:
            raise NotFoundError(f"Workflow mandate not found: {mandate_id}")
        items = [
            _decode(row)
            for row in self.store.rows(
                "SELECT * FROM workflow_work_items WHERE mandate_id=? ORDER BY rowid",
                (mandate_id,),
            )
        ]
        result = _decode(mandate)
        result["requires_reauthorization"] = int(mandate["activation_epoch"]) != self._current_epoch()
        result["work_items"] = items
        return result

    def list_mandates(self, *, auth: AuthContext) -> list[dict[str, Any]]:
        self._require(auth, "workflow.read")
        epoch = self._current_epoch()
        rows = self.store.rows("SELECT * FROM workflow_mandates ORDER BY created_at,mandate_id")
        result = []
        for row in rows:
            item = _decode(row)
            item["requires_reauthorization"] = int(row["activation_epoch"]) != epoch
            result.append(item)
        return result

    def show_work_item(self, work_item_id: str, *, auth: AuthContext) -> dict[str, Any]:
        from .agent_workflow_assessments import stored_spec

        self._require(auth, "workflow.read")
        item = self.store.row(
            "SELECT * FROM workflow_work_items WHERE work_item_id=?", (work_item_id,)
        )
        if not item:
            raise NotFoundError(f"Workflow work item not found: {work_item_id}")
        attempts = self.store.rows(
            "SELECT * FROM workflow_attempts WHERE work_item_id=? ORDER BY attempt_number",
            (work_item_id,),
        )
        outputs = self.store.rows(
            "SELECT * FROM workflow_outputs WHERE work_item_id=? ORDER BY rowid",
            (work_item_id,),
        )
        issue = self.store.row(
            "SELECT working_revision,freshness,current_conclusion_id FROM issues WHERE issue_id=?",
            (item["issue_id"],),
        )
        return {
            **_decode(item),
            "attempts": attempts,
            "outputs": outputs,
            "issue_state": dict(issue) if issue else None,
            "assessment": stored_spec(self.store.conn, work_item_id),
        }

    def execution_facts(self, attempt_id: str, *, auth: AuthContext) -> dict[str, Any]:
        """Return the bounded, one-attempt facts contract used by orchestrators."""
        from .agent_workflow_facts import read

        return read(self, attempt_id, auth=auth)

    def dispatchable_work(
        self,
        mandate_id: str,
        *,
        auth: AuthContext,
        roles: list[str] | None = None,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        self._require(auth, "workflow.read", "workflow.execute")
        if not 1 <= limit <= 100:
            raise ValidationError("Dispatch limit must be between 1 and 100")
        requested_roles = roles or sorted(ROLES)
        if not set(requested_roles) <= ROLES:
            raise ValidationError("Dispatch filter contains an unsupported role")
        mandate = self.store.row(
            "SELECT * FROM workflow_mandates WHERE mandate_id=?", (mandate_id,)
        )
        if not mandate:
            raise NotFoundError(f"Workflow mandate not found: {mandate_id}")
        if (
            mandate["status"] != "active"
            or int(mandate["activation_epoch"]) != self._current_epoch()
            or not json.loads(mandate["permissions_json"]).get("can_execute")
        ):
            return []
        placeholders = ",".join("?" for _ in requested_roles)
        return [
            _decode(row)
            for row in self.store.rows(
                "SELECT * FROM workflow_work_items WHERE mandate_id=? AND status='ready' "
                f"AND role IN ({placeholders}) ORDER BY created_at,work_item_id LIMIT ?",
                (mandate_id, *requested_roles, limit),
            )
        ]

    def revise_mandate(
        self,
        mandate_id: str,
        *,
        expected_revision: int,
        autonomy_mode: str,
        scope: dict[str, Any],
        allowed_actions: list[str],
        budget: dict[str, Any],
        stop_conditions: dict[str, Any],
        reason: str,
        auth: AuthContext,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require(auth, "workflow.manage")
        key = self._require_key(idempotency_key)
        if autonomy_mode not in AUTONOMY_MODES:
            raise ValidationError(f"Unknown autonomy mode: {autonomy_mode}")
        normalized_scope = self._validate_scope(scope)
        normalized_budget = self._validate_budget(budget)
        actions = sorted(set(allowed_actions))
        if not actions or not set(actions) <= SUPPORTED_ACTIONS:
            raise ValidationError("Mandate revision contains an unsupported action")
        if not isinstance(stop_conditions, dict):
            raise ValidationError("stop_conditions must be an object")
        payload = {
            "mandate_id": mandate_id,
            "expected_revision": expected_revision,
            "autonomy_mode": autonomy_mode,
            "scope": normalized_scope,
            "allowed_actions": actions,
            "budget": normalized_budget,
            "stop_conditions": stop_conditions,
            "reason": reason,
        }
        operation = self._operation("mandate.revise", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            mandate = self._mandate_row(conn, mandate_id)
            self._assert_expected(int(mandate["revision"]), expected_revision, "mandate revision")
            if mandate["status"] in {"completed", "cancelled"}:
                raise ConflictError("A terminal mandate cannot be revised")
            for issue_id in normalized_scope["issue_ids"]:
                if not conn.execute("SELECT 1 FROM issues WHERE issue_id=?", (issue_id,)).fetchone():
                    raise NotFoundError(f"Issue not found: {issue_id}")
            used = {
                "max_work_items": int(mandate["work_items_created"]),
                "max_attempts": int(mandate["attempts_started"]),
                "max_commits": int(mandate["commits_used"]),
                "max_runtime_seconds": int(mandate["runtime_seconds_used"]),
                "max_context_bytes": int(mandate["context_bytes_used"]),
            }
            if any(normalized_budget[name] < amount for name, amount in used.items()):
                raise ValidationError("A mandate budget cannot be revised below already consumed usage")
            timestamp = now()
            mandate.update(
                autonomy_mode=autonomy_mode,
                scope_json=canonical_json(normalized_scope),
                permissions_json=canonical_json(
                    {**MODE_PERMISSIONS[autonomy_mode], "allowed_actions": actions}
                ),
                budget_json=canonical_json(normalized_budget),
                stop_conditions_json=canonical_json(stop_conditions),
                revision=expected_revision + 1,
                fence=int(mandate["fence"]) + 1,
                activation_epoch=self._current_epoch(conn),
                updated_at=timestamp,
                updated_by=auth.actor_id,
                stop_reason=None,
            )
            conn.execute(
                "UPDATE workflow_mandates SET autonomy_mode=?,scope_json=?,permissions_json=?,budget_json=?,"
                "stop_conditions_json=?,revision=?,fence=?,activation_epoch=?,updated_at=?,updated_by=?,"
                "stop_reason=NULL WHERE mandate_id=?",
                (
                    mandate["autonomy_mode"],
                    mandate["scope_json"],
                    mandate["permissions_json"],
                    mandate["budget_json"],
                    mandate["stop_conditions_json"],
                    mandate["revision"],
                    mandate["fence"],
                    mandate["activation_epoch"],
                    timestamp,
                    auth.actor_id,
                    mandate_id,
                ),
            )
            attempts = conn.execute(
                "SELECT attempt_id,work_item_id FROM workflow_attempts WHERE mandate_id=? "
                "AND status IN ('claimed','running','submitted')",
                (mandate_id,),
            ).fetchall()
            conn.execute(
                "UPDATE workflow_attempts SET status='invalidated',rejection_code='mandate_revised',ended_at=? "
                "WHERE mandate_id=? AND status IN ('claimed','running','submitted')",
                (timestamp, mandate_id),
            )
            affected_item_ids = {row["work_item_id"] for row in attempts}
            for work_item_id in affected_item_ids:
                affected = self._item_row(conn, work_item_id)
                in_scope = self._within_scope(mandate, affected["issue_id"], affected["role"])
                actions_in_scope = set(json.loads(affected["allowed_actions_json"])) <= set(actions)
                target = "ready" if in_scope and actions_in_scope else "blocked"
                stop_reason = None if target == "ready" else "mandate revision removed this work from scope"
                conn.execute(
                    "UPDATE workflow_work_items SET status=?,revision=revision+1,updated_at=?,stop_reason=? "
                    "WHERE work_item_id=?",
                    (target, timestamp, stop_reason, work_item_id),
                )
            self._record_revision(conn, mandate, event_type="revised", auth=auth)
            event_id = self._event(
                conn,
                mandate_id=mandate_id,
                event_type="mandate.revised",
                auth=auth,
                payload={"reason": reason, "invalidated_attempt_ids": [row["attempt_id"] for row in attempts]},
            )
            response = {
                "mandate_id": mandate_id,
                "revision": mandate["revision"],
                "fence": mandate["fence"],
                "invalidated_attempt_ids": [row["attempt_id"] for row in attempts],
                "event_id": event_id,
            }
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response

    def _create_item(
        self,
        conn: sqlite3.Connection,
        *,
        mandate: dict[str, Any],
        issue_id: str,
        role: str,
        objective: str,
        acceptance: list[str],
        allowed_actions: list[str],
        dedupe_key: str,
        status: str,
        stop_reason: str | None,
        auth: AuthContext,
    ) -> dict[str, Any]:
        existing = conn.execute(
            "SELECT * FROM workflow_work_items WHERE mandate_id=? AND dedupe_key=?",
            (mandate["mandate_id"], dedupe_key),
        ).fetchone()
        expected = {
            "issue_id": issue_id,
            "role": role,
            "objective": objective,
            "acceptance_json": canonical_json(acceptance),
            "allowed_actions_json": canonical_json(allowed_actions),
        }
        if existing:
            row = dict(existing)
            if any(row[key] != value for key, value in expected.items()):
                raise ConflictError("Work-item dedupe key was already used with different content")
            return {"work_item_id": row["work_item_id"], "status": row["status"], "existing": True}
        budget = self._budget(mandate)
        if int(mandate["work_items_created"]) >= budget["max_work_items"]:
            self._block_for_budget(
                conn, mandate, reason="max_work_items exhausted", auth=auth
            )
            return {
                "mandate_id": mandate["mandate_id"],
                "status": "blocked",
                "reason": "max_work_items exhausted",
            }
        work_item_id = new_id("work_item")
        timestamp = now()
        conn.execute(
            "INSERT INTO workflow_work_items("
            "work_item_id,mandate_id,dedupe_key,issue_id,role,objective,acceptance_json,"
            "allowed_actions_json,status,acceptance_status,revision,proposed_by,created_at,updated_at,"
            "stop_reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                work_item_id,
                mandate["mandate_id"],
                dedupe_key,
                issue_id,
                role,
                objective,
                canonical_json(acceptance),
                canonical_json(allowed_actions),
                status,
                "pending",
                1,
                auth.actor_id,
                timestamp,
                timestamp,
                stop_reason,
            ),
        )
        mandate["work_items_created"] = int(mandate["work_items_created"]) + 1
        conn.execute(
            "UPDATE workflow_mandates SET work_items_created=?,updated_at=?,updated_by=? WHERE mandate_id=?",
            (mandate["work_items_created"], timestamp, auth.actor_id, mandate["mandate_id"]),
        )
        event_id = self._event(
            conn,
            mandate_id=mandate["mandate_id"],
            work_item_id=work_item_id,
            event_type="work_item.created" if status == "ready" else "work_item.proposed",
            auth=auth,
            after_state=status,
            payload={**expected, "dedupe_key": dedupe_key, "stop_reason": stop_reason},
        )
        return {"work_item_id": work_item_id, "status": status, "event_id": event_id, "existing": False}

    def create_work_item(
        self,
        mandate_id: str,
        *,
        issue_id: str,
        role: str,
        objective: str,
        acceptance: list[str] | None,
        allowed_actions: list[str] | None,
        dedupe_key: str,
        auth: AuthContext,
        idempotency_key: str,
        inputs: list[dict[str, str]] | None = None,
        assessment: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from .agent_workflow_contracts import validate_inputs

        inputs = validate_inputs([] if inputs is None else inputs)
        key = self._require_key(idempotency_key)
        if role not in ROLES or not objective.strip() or not dedupe_key.strip():
            raise ValidationError("Work item requires a supported role, objective, and dedupe_key")
        acceptance = acceptance or []
        if not isinstance(acceptance, list) or not all(isinstance(value, str) for value in acceptance):
            raise ValidationError("Work item acceptance must be a string array")
        actions = sorted(set(allowed_actions or ["append_work"]))
        if not set(actions) <= SUPPORTED_ACTIONS:
            raise ValidationError("Work item contains an unsupported action")
        assessment_action = "record_assessment" in actions
        if (assessment is not None) != assessment_action:
            raise ValidationError("Assessment binding and record_assessment action must be supplied together")
        if assessment is not None:
            from .agent_workflow_assessments import validate_spec
            validate_spec(assessment)
        payload: dict[str, Any] = {
            "mandate_id": mandate_id,
            "issue_id": issue_id,
            "role": role,
            "objective": objective.strip(),
            "acceptance": acceptance,
            "allowed_actions": actions,
            "dedupe_key": dedupe_key.strip(),
        }
        if inputs:
            payload["inputs"] = inputs
        if assessment is not None:
            payload["assessment"] = assessment
        operation = self._operation("work_item.create", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            mandate = self._mandate_row(conn, mandate_id)
            self._assert_epoch(mandate, conn)
            if mandate["status"] != "active":
                raise ConflictError("Work items can only be created under an active mandate")
            if not conn.execute("SELECT 1 FROM issues WHERE issue_id=?", (issue_id,)).fetchone():
                raise NotFoundError(f"Issue not found: {issue_id}")
            if not self._within_scope(mandate, issue_id, role):
                raise PermissionError("Work item is outside the mandate scope")
            mandate_permissions = json.loads(mandate["permissions_json"])
            if not set(actions) <= set(mandate_permissions["allowed_actions"]):
                raise PermissionError("Work item action is outside the mandate action scope")
            if "workflow.manage" in auth.capabilities:
                self._require(auth, "workflow.manage")
            else:
                self._require(auth, "workflow.execute")
                permissions = json.loads(mandate["permissions_json"])
                if not permissions.get("can_create_work"):
                    raise PermissionError("Mandate does not allow autonomous work-item creation")
            response = self._create_item(
                conn,
                mandate=mandate,
                issue_id=issue_id,
                role=role,
                objective=objective.strip(),
                acceptance=acceptance,
                allowed_actions=actions,
                dedupe_key=dedupe_key.strip(),
                status="ready",
                stop_reason=None,
                auth=auth,
            )
            if response.get("work_item_id"):
                from .agent_workflow_assessments import stored_spec

                if response.get("existing") and stored_spec(conn, response["work_item_id"]) != assessment:
                    raise ConflictError("Work-item dedupe key has different assessment binding")
                if assessment is not None and not response.get("existing"):
                    self._event(conn, mandate_id=mandate_id, work_item_id=response["work_item_id"],
                                event_type="work_item.assessment", auth=auth,
                                payload={"assessment": assessment})
                stored = self._inputs(conn, response["work_item_id"])
                if response.get("existing") and stored != inputs:
                    raise ConflictError("Work-item dedupe key has different inputs")
                if inputs and not response.get("existing"):
                    self._event(conn, mandate_id=mandate_id,
                                work_item_id=response["work_item_id"],
                                event_type="work_item.inputs", auth=auth,
                                payload={"inputs": inputs})
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response

    def propose_work_item(
        self,
        mandate_id: str,
        *,
        issue_id: str,
        role: str,
        objective: str,
        acceptance: list[str] | None,
        dedupe_key: str,
        auth: AuthContext,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require(auth, "workflow.execute")
        key = self._require_key(idempotency_key)
        if role not in ROLES or not objective.strip() or not dedupe_key.strip():
            raise ValidationError("Work proposal requires a supported role, objective, and dedupe_key")
        acceptance = acceptance or []
        if not isinstance(acceptance, list) or not all(isinstance(value, str) for value in acceptance):
            raise ValidationError("Work proposal acceptance must be a string array")
        payload = {
            "mandate_id": mandate_id,
            "issue_id": issue_id,
            "role": role,
            "objective": objective.strip(),
            "acceptance": acceptance,
            "dedupe_key": dedupe_key.strip(),
        }
        operation = self._operation("work_item.propose", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            mandate = self._mandate_row(conn, mandate_id)
            self._assert_epoch(mandate, conn)
            permissions = json.loads(mandate["permissions_json"])
            if mandate["status"] != "active" or not permissions.get("can_propose_work"):
                raise PermissionError("Mandate does not allow work proposals")
            if not conn.execute("SELECT 1 FROM issues WHERE issue_id=?", (issue_id,)).fetchone():
                raise NotFoundError(f"Issue not found: {issue_id}")
            in_scope = self._within_scope(mandate, issue_id, role)
            response = self._create_item(
                conn,
                mandate=mandate,
                issue_id=issue_id,
                role=role,
                objective=objective.strip(),
                acceptance=acceptance,
                allowed_actions=["append_work"],
                dedupe_key=dedupe_key.strip(),
                status="proposed",
                stop_reason=None if in_scope else "outside mandate scope; human decision required",
                auth=auth,
            )
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response

    def authorize_work_item(
        self,
        work_item_id: str,
        *,
        expected_revision: int,
        auth: AuthContext,
        idempotency_key: str,
        reason: str = "",
    ) -> dict[str, Any]:
        self._require(auth, "workflow.manage")
        key = self._require_key(idempotency_key)
        payload = {"work_item_id": work_item_id, "expected_revision": expected_revision}
        if reason:
            payload["reason"] = reason
        operation = self._operation("work_item.authorize", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            item = self._item_row(conn, work_item_id)
            mandate = self._mandate_row(conn, item["mandate_id"])
            self._assert_epoch(mandate, conn)
            self._assert_expected(int(item["revision"]), expected_revision, "work item revision")
            if item["status"] not in {"proposed", "blocked"} or mandate["status"] != "active":
                raise ConflictError("Only a proposed or blocked item under an active mandate can be authorized")
            if item["status"] == "blocked" and not reason.strip():
                raise ValidationError("Unblocking requires the resolved waiting condition")
            if mandate["autonomy_mode"] == "advise_only":
                raise PermissionError("Revise an advise-only mandate before authorizing execution")
            if not self._within_scope(mandate, item["issue_id"], item["role"]):
                raise PermissionError("Proposed work remains outside the mandate scope")
            new_revision = expected_revision + 1
            conn.execute(
                "UPDATE workflow_work_items SET status='ready',revision=?,updated_at=?,stop_reason=NULL "
                "WHERE work_item_id=?",
                (new_revision, now(), work_item_id),
            )
            event_id = self._event(
                conn,
                mandate_id=item["mandate_id"],
                work_item_id=work_item_id,
                event_type="work_item.authorized",
                auth=auth,
                before_state=item["status"],
                after_state="ready",
                payload={"revision": new_revision, "reason": reason},
            )
            response = {"work_item_id": work_item_id, "status": "ready", "revision": new_revision, "event_id": event_id}
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response

    def claim(
        self,
        work_item_id: str,
        *,
        expected_revision: int,
        lease_seconds: int,
        auth: AuthContext,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require(auth, "workflow.execute", "workflow.read")
        key = self._require_key(idempotency_key)
        if not 1 <= lease_seconds <= 3600:
            raise ValidationError("lease_seconds must be between 1 and 3600")
        payload = {
            "work_item_id": work_item_id,
            "expected_revision": expected_revision,
            "lease_seconds": lease_seconds,
        }
        operation = self._operation("attempt.claim", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            item = self._item_row(conn, work_item_id)
            mandate = self._mandate_row(conn, item["mandate_id"])
            self._assert_epoch(mandate, conn)
            self._assert_expected(int(item["revision"]), expected_revision, "work item revision")
            permissions = json.loads(mandate["permissions_json"])
            if mandate["status"] != "active" or not permissions.get("can_execute"):
                raise PermissionError("Mandate is not authorized for execution")
            if item["status"] != "ready":
                raise ConflictError(f"Work item is not ready: {item['status']}")
            budget = self._budget(mandate)
            if int(mandate["attempts_started"]) >= budget["max_attempts"]:
                self._block_for_budget(conn, mandate, reason="max_attempts exhausted", auth=auth)
                response = {
                    "mandate_id": mandate["mandate_id"],
                    "work_item_id": work_item_id,
                    "status": "blocked",
                    "reason": "max_attempts exhausted",
                }
                self.store.idempotency_record(conn, operation, key, payload, response)
                return response
            issue = conn.execute(
                "SELECT issue_id,working_revision,current_conclusion_id,freshness FROM issues WHERE issue_id=?",
                (item["issue_id"],),
            ).fetchone()
            if not issue:
                raise NotFoundError(f"Issue not found: {item['issue_id']}")
            outputs = [
                _decode(dict(row))
                for row in conn.execute(
                    "SELECT * FROM workflow_outputs WHERE work_item_id=? ORDER BY rowid",
                    (work_item_id,),
                ).fetchall()
            ]
            attempt_number = int(
                conn.execute(
                    "SELECT COALESCE(MAX(attempt_number),0)+1 FROM workflow_attempts WHERE work_item_id=?",
                    (work_item_id,),
                ).fetchone()[0]
            )
            attempt_id = new_id("attempt")
            package_id = new_id("work_package")
            item_revision = expected_revision + 1
            package = {
                "contract": "agent-work-package/v1",
                "mandate": {
                    "mandate_id": mandate["mandate_id"],
                    "revision": mandate["revision"],
                    "fence": mandate["fence"],
                    "goal": mandate["goal"],
                    "scope": json.loads(mandate["scope_json"]),
                    "permissions": permissions,
                    "remaining_budget": {
                        "attempts": budget["max_attempts"] - int(mandate["attempts_started"]) - 1,
                        "commits": budget["max_commits"] - int(mandate["commits_used"]),
                        "runtime_seconds": budget["max_runtime_seconds"]
                        - int(mandate["runtime_seconds_used"]),
                        "context_bytes": budget["max_context_bytes"]
                        - int(mandate["context_bytes_used"]),
                    },
                },
                "work_item": {
                    "work_item_id": work_item_id,
                    "revision": item_revision,
                    "role": item["role"],
                    "objective": item["objective"],
                    "acceptance": json.loads(item["acceptance_json"]),
                    "allowed_actions": json.loads(item["allowed_actions_json"]),
                },
                "attempt": {
                    "attempt_id": attempt_id,
                    "attempt_number": attempt_number,
                    "actor_id": auth.actor_id,
                    "run_id": auth.run_id,
                },
                "input_baseline": {
                    "issue_id": issue["issue_id"],
                    "working_revision": issue["working_revision"],
                    "current_conclusion_id": issue["current_conclusion_id"],
                    "freshness": issue["freshness"],
                },
                "prior_outputs": outputs,
                "inputs": self._inputs(conn, work_item_id),
                "input_updates": self._input_updates(conn, item, issue["working_revision"]),
            }
            if set(package["work_item"]["allowed_actions"]) & {"create_proposal", "create_verification", "record_assessment", "relate_evidence"}:
                from .agent_workflow_proposals import freeze_context

                if set(package["work_item"]["allowed_actions"]) & {"record_assessment", "relate_evidence"}:
                    self._require(auth, "context.read")
                if set(package["work_item"]["allowed_actions"]) & {"create_proposal", "create_verification"}:
                    self._require(auth, "conclusion.propose")
                from .agent_workflow_assessments import stored_spec

                spec = stored_spec(conn, work_item_id)
                package["prepared_context"] = freeze_context(self.manager, issue["issue_id"], auth,
                    target_proposal_id=spec["target_proposal_id"] if spec and "target_proposal_id" in spec else None)
                if spec is not None:
                    dispatch_binding = conn.execute(
                        "SELECT payload_json FROM workflow_events WHERE work_item_id=? "
                        "AND event_type='work_item.assessment_dispatch'", (work_item_id,)).fetchone()
                    if dispatch_binding:
                        from .agent_workflow_coverage import inspect

                        coverage, current_anchor = inspect(self, conn, mandate,
                            dict(issue_id=issue["issue_id"], role=item["role"], assessment=spec),
                            auth, prepared=package["prepared_context"])
                        if json.loads(dispatch_binding[0])["anchor"] != current_anchor:
                            raise ConflictError("Assessment dispatch inputs changed; dispatch a new event")
                        if not coverage["unhandled_refs"]:
                            raise ConflictError("Assessment changes are already covered; dispatch again")
                        spec = dict(spec, change_refs=coverage["unhandled_refs"])
                        package["assessment_context"] = dict(covered_refs=coverage["covered_refs"],
                                                               records=coverage["records"])
                    from .agent_workflow_assessments import freeze as freeze_assessment

                    package["assessment"] = freeze_assessment(spec, package["prepared_context"])
            package_json = canonical_json(package)
            byte_count = len(package_json.encode("utf-8"))
            if int(mandate["context_bytes_used"]) + byte_count > budget["max_context_bytes"]:
                self._block_for_budget(conn, mandate, reason="max_context_bytes exhausted", auth=auth)
                response = {
                    "mandate_id": mandate["mandate_id"],
                    "work_item_id": work_item_id,
                    "status": "blocked",
                    "reason": "max_context_bytes exhausted",
                }
                self.store.idempotency_record(conn, operation, key, payload, response)
                return response
            timestamp = self._iso_now()
            lease_until = (timestamp + timedelta(seconds=lease_seconds)).isoformat(timespec="seconds")
            conn.execute(
                "INSERT INTO workflow_attempts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    attempt_id,
                    work_item_id,
                    mandate["mandate_id"],
                    attempt_number,
                    "claimed",
                    auth.actor_id,
                    auth.run_id,
                    mandate["revision"],
                    mandate["fence"],
                    item_revision,
                    issue["working_revision"],
                    lease_until,
                    timestamp.isoformat(timespec="seconds"),
                    0,
                    byte_count,
                    None,
                    timestamp.isoformat(timespec="seconds"),
                    None,
                ),
            )
            conn.execute(
                "INSERT INTO workflow_work_packages VALUES (?,?,?,?,?,?)",
                (
                    package_id,
                    attempt_id,
                    package_json,
                    hashlib.sha256(package_json.encode("utf-8")).hexdigest(),
                    byte_count,
                    timestamp.isoformat(timespec="seconds"),
                ),
            )
            conn.execute(
                "UPDATE workflow_work_items SET status='running',revision=?,updated_at=? WHERE work_item_id=?",
                (item_revision, timestamp.isoformat(timespec="seconds"), work_item_id),
            )
            conn.execute(
                "UPDATE workflow_mandates SET attempts_started=attempts_started+1,"
                "context_bytes_used=context_bytes_used+?,updated_at=?,updated_by=? WHERE mandate_id=?",
                (byte_count, timestamp.isoformat(timespec="seconds"), auth.actor_id, mandate["mandate_id"]),
            )
            event_id = self._event(
                conn,
                mandate_id=mandate["mandate_id"],
                work_item_id=work_item_id,
                attempt_id=attempt_id,
                event_type="attempt.claimed",
                auth=auth,
                before_state="ready",
                after_state="running",
                payload={"package_id": package_id, "lease_until": lease_until, "byte_count": byte_count},
            )
            response = {
                "attempt_id": attempt_id,
                "package_id": package_id,
                "lease_until": lease_until,
                "mandate_revision": mandate["revision"],
                "mandate_fence": mandate["fence"],
                "work_item_revision": item_revision,
                "package": package,
                "event_id": event_id,
            }
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response

    def _assert_live_attempt(
        self,
        conn: sqlite3.Connection,
        attempt_id: str,
        *,
        auth: AuthContext,
        expected_mandate_revision: int,
        expected_fence: int,
        expected_work_item_revision: int,
    ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        attempt = self._attempt_row(conn, attempt_id)
        item = self._item_row(conn, attempt["work_item_id"])
        mandate = self._mandate_row(conn, attempt["mandate_id"])
        self._assert_epoch(mandate, conn)
        if attempt["actor_id"] != auth.actor_id or attempt["run_id"] != auth.run_id:
            raise PermissionError("Attempt is held by another actor/run")
        if attempt["status"] not in {"claimed", "running"}:
            raise ConflictError(f"Attempt is not active: {attempt['status']}")
        if self._expired(attempt["lease_until"]):
            raise ConflictError("Attempt lease has expired")
        self._assert_expected(int(mandate["revision"]), expected_mandate_revision, "mandate revision")
        self._assert_expected(int(mandate["fence"]), expected_fence, "mandate fence")
        self._assert_expected(int(item["revision"]), expected_work_item_revision, "work item revision")
        if (
            int(attempt["mandate_revision"]) != expected_mandate_revision
            or int(attempt["mandate_fence"]) != expected_fence
            or int(attempt["work_item_revision"]) != expected_work_item_revision
        ):
            raise ConflictError("Attempt token does not match the current workflow revisions")
        if mandate["status"] != "active":
            raise PermissionError("Mandate is not active")
        return attempt, item, mandate

    def checkpoint(
        self,
        attempt_id: str,
        *,
        body: str,
        expected_mandate_revision: int,
        expected_fence: int,
        expected_work_item_revision: int,
        auth: AuthContext,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require(auth, "workflow.execute")
        key = self._require_key(idempotency_key)
        if not body.strip():
            raise ValidationError("Checkpoint body is required")
        payload = {
            "attempt_id": attempt_id,
            "body": body,
            "expected_mandate_revision": expected_mandate_revision,
            "expected_fence": expected_fence,
            "expected_work_item_revision": expected_work_item_revision,
        }
        operation = self._operation("attempt.checkpoint", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            attempt, item, mandate = self._assert_live_attempt(
                conn,
                attempt_id,
                auth=auth,
                expected_mandate_revision=expected_mandate_revision,
                expected_fence=expected_fence,
                expected_work_item_revision=expected_work_item_revision,
            )
            output_id = new_id("workflow_output")
            conn.execute(
                "INSERT INTO workflow_outputs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    output_id,
                    mandate["mandate_id"],
                    item["work_item_id"],
                    attempt_id,
                    auth.actor_id,
                    auth.run_id,
                    "draft",
                    body,
                    None,
                    None,
                    None,
                    now(),
                ),
            )
            conn.execute(
                "UPDATE workflow_attempts SET status='running',heartbeat_at=? WHERE attempt_id=?",
                (now(), attempt_id),
            )
            conn.execute(
                "UPDATE workflow_work_items SET status='checkpointed',updated_at=? WHERE work_item_id=?",
                (now(), item["work_item_id"]),
            )
            event_id = self._event(
                conn,
                mandate_id=mandate["mandate_id"],
                work_item_id=item["work_item_id"],
                attempt_id=attempt_id,
                event_type="attempt.checkpointed",
                auth=auth,
                before_state=attempt["status"],
                after_state="running",
                payload={"output_id": output_id},
            )
            response = {"attempt_id": attempt_id, "output_id": output_id, "event_id": event_id}
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response

    def renew(
        self,
        attempt_id: str,
        *,
        expected_mandate_revision: int,
        expected_fence: int,
        expected_work_item_revision: int,
        lease_seconds: int,
        runtime_seconds_delta: int,
        context_bytes_delta: int,
        auth: AuthContext,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require(auth, "workflow.execute")
        key = self._require_key(idempotency_key)
        if not 1 <= lease_seconds <= 3600:
            raise ValidationError("lease_seconds must be between 1 and 3600")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (runtime_seconds_delta, context_bytes_delta)
        ):
            raise ValidationError("Usage deltas must be non-negative integers")
        payload = {
            "attempt_id": attempt_id,
            "expected_mandate_revision": expected_mandate_revision,
            "expected_fence": expected_fence,
            "expected_work_item_revision": expected_work_item_revision,
            "lease_seconds": lease_seconds,
            "runtime_seconds_delta": runtime_seconds_delta,
            "context_bytes_delta": context_bytes_delta,
        }
        operation = self._operation("attempt.renew", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            attempt, item, mandate = self._assert_live_attempt(
                conn,
                attempt_id,
                auth=auth,
                expected_mandate_revision=expected_mandate_revision,
                expected_fence=expected_fence,
                expected_work_item_revision=expected_work_item_revision,
            )
            budget = self._budget(mandate)
            new_runtime = int(mandate["runtime_seconds_used"]) + runtime_seconds_delta
            new_context = int(mandate["context_bytes_used"]) + context_bytes_delta
            if new_runtime > budget["max_runtime_seconds"]:
                self._block_for_budget(
                    conn, mandate, reason="max_runtime_seconds exhausted", auth=auth
                )
                response: dict[str, Any] = {
                    "attempt_id": attempt_id,
                    "status": "blocked",
                    "reason": "max_runtime_seconds exhausted",
                }
                self.store.idempotency_record(conn, operation, key, payload, response)
                return response
            if new_context > budget["max_context_bytes"]:
                self._block_for_budget(
                    conn, mandate, reason="max_context_bytes exhausted", auth=auth
                )
                response = {
                    "attempt_id": attempt_id,
                    "status": "blocked",
                    "reason": "max_context_bytes exhausted",
                }
                self.store.idempotency_record(conn, operation, key, payload, response)
                return response
            timestamp = self._iso_now()
            lease_until = (timestamp + timedelta(seconds=lease_seconds)).isoformat(timespec="seconds")
            conn.execute(
                "UPDATE workflow_attempts SET status='running',lease_until=?,heartbeat_at=?,"
                "runtime_seconds_used=runtime_seconds_used+?,context_bytes_used=context_bytes_used+? "
                "WHERE attempt_id=?",
                (
                    lease_until,
                    timestamp.isoformat(timespec="seconds"),
                    runtime_seconds_delta,
                    context_bytes_delta,
                    attempt_id,
                ),
            )
            conn.execute(
                "UPDATE workflow_mandates SET runtime_seconds_used=?,context_bytes_used=?,updated_at=?,"
                "updated_by=? WHERE mandate_id=?",
                (
                    new_runtime,
                    new_context,
                    timestamp.isoformat(timespec="seconds"),
                    auth.actor_id,
                    mandate["mandate_id"],
                ),
            )
            event_id = self._event(
                conn,
                mandate_id=mandate["mandate_id"],
                work_item_id=item["work_item_id"],
                attempt_id=attempt_id,
                event_type="attempt.renewed",
                auth=auth,
                before_state=attempt["status"],
                after_state="running",
                payload={
                    "lease_until": lease_until,
                    "runtime_seconds_delta": runtime_seconds_delta,
                    "context_bytes_delta": context_bytes_delta,
                },
            )
            response = {
                "attempt_id": attempt_id,
                "status": "running",
                "lease_until": lease_until,
                "runtime_seconds_used": new_runtime,
                "context_bytes_used": new_context,
                "event_id": event_id,
            }
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response

    def fail_attempt(
        self,
        attempt_id: str,
        *,
        reason: str,
        expected_mandate_revision: int,
        expected_fence: int,
        expected_work_item_revision: int,
        auth: AuthContext,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require(auth, "workflow.execute")
        key = self._require_key(idempotency_key)
        if not reason.strip():
            raise ValidationError("Attempt failure reason is required")
        payload = {
            "attempt_id": attempt_id,
            "reason": reason.strip(),
            "expected_mandate_revision": expected_mandate_revision,
            "expected_fence": expected_fence,
            "expected_work_item_revision": expected_work_item_revision,
        }
        operation = self._operation("attempt.fail", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            attempt, item, mandate = self._assert_live_attempt(
                conn,
                attempt_id,
                auth=auth,
                expected_mandate_revision=expected_mandate_revision,
                expected_fence=expected_fence,
                expected_work_item_revision=expected_work_item_revision,
            )
            timestamp = now()
            conn.execute(
                "UPDATE workflow_attempts SET status='failed',rejection_code='worker_failed',ended_at=? "
                "WHERE attempt_id=?",
                (timestamp, attempt_id),
            )
            budget = self._budget(mandate)
            if int(mandate["attempts_started"]) >= budget["max_attempts"]:
                self._block_for_budget(conn, mandate, reason="max_attempts exhausted", auth=auth)
                target = "blocked"
                new_revision = int(item["revision"]) + 1
            else:
                target = "ready"
                new_revision = int(item["revision"]) + 1
                conn.execute(
                    "UPDATE workflow_work_items SET status='ready',revision=?,updated_at=?,stop_reason=? "
                    "WHERE work_item_id=?",
                    (new_revision, timestamp, reason.strip(), item["work_item_id"]),
                )
            event_id = self._event(
                conn,
                mandate_id=mandate["mandate_id"],
                work_item_id=item["work_item_id"],
                attempt_id=attempt_id,
                event_type="attempt.failed",
                auth=auth,
                before_state=attempt["status"],
                after_state="failed",
                payload={"reason": reason.strip(), "work_item_status": target},
            )
            response = {
                "attempt_id": attempt_id,
                "status": "failed",
                "work_item_id": item["work_item_id"],
                "work_item_status": target,
                "work_item_revision": new_revision,
                "event_id": event_id,
            }
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response

    def pause(
        self,
        mandate_id: str,
        *,
        expected_revision: int,
        takeover: bool,
        reason: str,
        auth: AuthContext,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require(auth, "workflow.manage")
        key = self._require_key(idempotency_key)
        payload = {
            "mandate_id": mandate_id,
            "expected_revision": expected_revision,
            "takeover": takeover,
            "reason": reason,
        }
        operation = self._operation("mandate.pause", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            mandate = self._mandate_row(conn, mandate_id)
            self._assert_expected(int(mandate["revision"]), expected_revision, "mandate revision")
            if mandate["status"] != "active":
                raise ConflictError(f"Only an active mandate can be paused: {mandate['status']}")
            before = mandate["status"]
            target = "taken_over" if takeover else "paused"
            timestamp = now()
            mandate.update(
                status=target,
                revision=expected_revision + 1,
                fence=int(mandate["fence"]) + 1,
                stop_reason=reason or None,
                updated_at=timestamp,
                updated_by=auth.actor_id,
            )
            conn.execute(
                "UPDATE workflow_mandates SET status=?,revision=?,fence=?,stop_reason=?,updated_at=?,updated_by=? "
                "WHERE mandate_id=?",
                (
                    target,
                    mandate["revision"],
                    mandate["fence"],
                    mandate["stop_reason"],
                    timestamp,
                    auth.actor_id,
                    mandate_id,
                ),
            )
            attempts = conn.execute(
                "SELECT attempt_id,work_item_id,status FROM workflow_attempts WHERE mandate_id=? "
                "AND status IN ('claimed','running','submitted')",
                (mandate_id,),
            ).fetchall()
            conn.execute(
                "UPDATE workflow_attempts SET status='invalidated',rejection_code='mandate_paused',ended_at=? "
                "WHERE mandate_id=? AND status IN ('claimed','running','submitted')",
                (timestamp, mandate_id),
            )
            conn.execute(
                "UPDATE workflow_work_items SET status='human_owned',revision=revision+1,updated_at=? "
                "WHERE mandate_id=? AND status IN ('running','checkpointed')",
                (timestamp, mandate_id),
            )
            self._record_revision(conn, mandate, event_type="taken_over" if takeover else "paused", auth=auth)
            event_id = self._event(
                conn,
                mandate_id=mandate_id,
                event_type="mandate.taken_over" if takeover else "mandate.paused",
                auth=auth,
                before_state=before,
                after_state=target,
                payload={"reason": reason, "invalidated_attempt_ids": [row["attempt_id"] for row in attempts]},
            )
            response = {
                "mandate_id": mandate_id,
                "status": target,
                "revision": mandate["revision"],
                "fence": mandate["fence"],
                "invalidated_attempt_ids": [row["attempt_id"] for row in attempts],
                "event_id": event_id,
            }
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response

    def _commit_append_work(
        self,
        conn: sqlite3.Connection,
        *,
        mandate: dict[str, Any],
        item: dict[str, Any],
        attempt_id: str | None,
        body: str,
        contribution_kind: str,
        expected_issue_working_revision: int,
        auth: AuthContext,
        key: str,
    ) -> tuple[dict[str, Any], str]:
        auth.require("work.write")
        if "append_work" not in json.loads(item["allowed_actions_json"]):
            raise PermissionError("Work item does not allow append_work")
        issue = conn.execute(
            "SELECT working_revision FROM issues WHERE issue_id=?", (item["issue_id"],)
        ).fetchone()
        if not issue:
            raise NotFoundError(f"Issue not found: {item['issue_id']}")
        self._assert_expected(
            int(issue["working_revision"]), expected_issue_working_revision, "Issue working revision"
        )
        entry = self.manager.append_work(
            item["issue_id"],
            body,
            entry_type="note",
            actor=auth.actor_id,
            reason=f"workflow {contribution_kind} output",
            idempotency_key=f"workflow-ledger:{attempt_id or 'human'}:{auth.actor_id}:{key}",
        )
        output_id = new_id("workflow_output")
        conn.execute(
            "INSERT INTO workflow_outputs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                output_id,
                mandate["mandate_id"],
                item["work_item_id"],
                attempt_id,
                auth.actor_id,
                auth.run_id,
                contribution_kind,
                body,
                "append_work",
                "working_entry",
                entry["entry_id"],
                now(),
            ),
        )
        return entry, output_id

    def human_commit_partial(
        self,
        work_item_id: str,
        *,
        body: str,
        expected_mandate_revision: int,
        expected_work_item_revision: int,
        expected_issue_working_revision: int,
        auth: AuthContext,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require(auth, "workflow.manage", "workflow.commit")
        key = self._require_key(idempotency_key)
        if not body.strip():
            raise ValidationError("Partial output body is required")
        payload = {
            "work_item_id": work_item_id,
            "body": body,
            "expected_mandate_revision": expected_mandate_revision,
            "expected_work_item_revision": expected_work_item_revision,
            "expected_issue_working_revision": expected_issue_working_revision,
        }
        operation = self._operation("human.partial_commit", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            item = self._item_row(conn, work_item_id)
            mandate = self._mandate_row(conn, item["mandate_id"])
            self._assert_epoch(mandate, conn)
            self._assert_expected(int(mandate["revision"]), expected_mandate_revision, "mandate revision")
            self._assert_expected(int(item["revision"]), expected_work_item_revision, "work item revision")
            if mandate["status"] not in {"paused", "taken_over"} or item["status"] != "human_owned":
                raise ConflictError("Human partial commit requires a paused/taken-over human-owned work item")
            budget = self._budget(mandate)
            if int(mandate["commits_used"]) >= budget["max_commits"]:
                self._block_for_budget(conn, mandate, reason="max_commits exhausted", auth=auth)
                response = {
                    "mandate_id": mandate["mandate_id"],
                    "work_item_id": work_item_id,
                    "status": "blocked",
                    "reason": "max_commits exhausted",
                }
                self.store.idempotency_record(conn, operation, key, payload, response)
                return response
            entry, output_id = self._commit_append_work(
                conn,
                mandate=mandate,
                item=item,
                attempt_id=None,
                body=body,
                contribution_kind="partial",
                expected_issue_working_revision=expected_issue_working_revision,
                auth=auth,
                key=key,
            )
            mandate["commits_used"] = int(mandate["commits_used"]) + 1
            mandate["revision"] = int(mandate["revision"]) + 1
            mandate["updated_at"] = now()
            mandate["updated_by"] = auth.actor_id
            item_revision = int(item["revision"]) + 1
            conn.execute(
                "UPDATE workflow_mandates SET commits_used=?,revision=?,updated_at=?,updated_by=? WHERE mandate_id=?",
                (
                    mandate["commits_used"],
                    mandate["revision"],
                    mandate["updated_at"],
                    auth.actor_id,
                    mandate["mandate_id"],
                ),
            )
            conn.execute(
                "UPDATE workflow_work_items SET revision=?,updated_at=? WHERE work_item_id=?",
                (item_revision, now(), work_item_id),
            )
            self._record_revision(conn, mandate, event_type="human_partial_commit", auth=auth)
            event_id = self._event(
                conn,
                mandate_id=mandate["mandate_id"],
                work_item_id=work_item_id,
                event_type="human.partial_committed",
                auth=auth,
                before_state="human_owned",
                after_state="human_owned",
                payload={"output_id": output_id, "entry_id": entry["entry_id"]},
            )
            response = {
                "work_item_id": work_item_id,
                "mandate_revision": mandate["revision"],
                "work_item_revision": item_revision,
                "output_id": output_id,
                "entry_id": entry["entry_id"],
                "event_id": event_id,
            }
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response

    def resume(
        self,
        mandate_id: str,
        *,
        expected_revision: int,
        reason: str,
        auth: AuthContext,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require(auth, "workflow.manage")
        key = self._require_key(idempotency_key)
        payload = {"mandate_id": mandate_id, "expected_revision": expected_revision, "reason": reason}
        operation = self._operation("mandate.resume", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            mandate = self._mandate_row(conn, mandate_id)
            self._assert_expected(int(mandate["revision"]), expected_revision, "mandate revision")
            imported_active = (
                mandate["status"] == "active"
                and int(mandate["activation_epoch"]) != self._current_epoch(conn)
            )
            if mandate["status"] not in {"paused", "taken_over", "blocked"} and not imported_active:
                raise ConflictError(f"Mandate cannot be resumed from {mandate['status']}")
            budget = self._budget(mandate)
            if (
                int(mandate["attempts_started"]) >= budget["max_attempts"]
                or int(mandate["commits_used"]) >= budget["max_commits"]
                or int(mandate["runtime_seconds_used"]) >= budget["max_runtime_seconds"]
                or int(mandate["context_bytes_used"]) >= budget["max_context_bytes"]
            ):
                raise ConflictError("Mandate budget must be revised before it can resume")
            before = mandate["status"]
            mandate.update(
                status="active",
                revision=expected_revision + 1,
                fence=int(mandate["fence"]) + 1,
                activation_epoch=self._current_epoch(conn),
                stop_reason=None,
                updated_at=now(),
                updated_by=auth.actor_id,
            )
            conn.execute(
                "UPDATE workflow_mandates SET status='active',revision=?,fence=?,activation_epoch=?,"
                "stop_reason=NULL,updated_at=?,updated_by=? WHERE mandate_id=?",
                (
                    mandate["revision"],
                    mandate["fence"],
                    mandate["activation_epoch"],
                    mandate["updated_at"],
                    auth.actor_id,
                    mandate_id,
                ),
            )
            rows = conn.execute(
                "SELECT work_item_id FROM workflow_work_items WHERE mandate_id=? AND status='human_owned'",
                (mandate_id,),
            ).fetchall()
            conn.execute(
                "UPDATE workflow_work_items SET status='ready',revision=revision+1,updated_at=?,stop_reason=NULL "
                "WHERE mandate_id=? AND status='human_owned'",
                (now(), mandate_id),
            )
            stale_attempts = conn.execute(
                "SELECT attempt_id,work_item_id FROM workflow_attempts WHERE mandate_id=? "
                "AND status IN ('claimed','running','submitted')",
                (mandate_id,),
            ).fetchall()
            conn.execute(
                "UPDATE workflow_attempts SET status='invalidated',rejection_code='reauthorized',ended_at=? "
                "WHERE mandate_id=? AND status IN ('claimed','running','submitted')",
                (now(), mandate_id),
            )
            for stale in stale_attempts:
                conn.execute(
                    "UPDATE workflow_work_items SET status='ready',revision=revision+1,updated_at=? "
                    "WHERE work_item_id=? AND status IN ('running','checkpointed')",
                    (now(), stale["work_item_id"]),
                )
            self._record_revision(conn, mandate, event_type="resumed", auth=auth)
            event_id = self._event(
                conn,
                mandate_id=mandate_id,
                event_type="mandate.resumed",
                auth=auth,
                before_state=before,
                after_state="active",
                payload={
                    "reason": reason,
                    "readied_work_item_ids": [row["work_item_id"] for row in rows]
                    + [row["work_item_id"] for row in stale_attempts],
                    "invalidated_attempt_ids": [row["attempt_id"] for row in stale_attempts],
                },
            )
            response = {
                "mandate_id": mandate_id,
                "status": "active",
                "revision": mandate["revision"],
                "fence": mandate["fence"],
                "readied_work_item_ids": [row["work_item_id"] for row in rows]
                + [row["work_item_id"] for row in stale_attempts],
                "event_id": event_id,
            }
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response

    def commit(
        self,
        attempt_id: str,
        *,
        body: str,
        expected_mandate_revision: int,
        expected_fence: int,
        expected_work_item_revision: int,
        expected_issue_working_revision: int,
        auth: AuthContext,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require(auth, "workflow.execute", "workflow.commit")
        key = self._require_key(idempotency_key)
        if not body.strip():
            raise ValidationError("Final output body is required")
        payload = {
            "attempt_id": attempt_id,
            "body": body,
            "expected_mandate_revision": expected_mandate_revision,
            "expected_fence": expected_fence,
            "expected_work_item_revision": expected_work_item_revision,
            "expected_issue_working_revision": expected_issue_working_revision,
        }
        operation = self._operation("attempt.commit", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            attempt, item, mandate = self._assert_live_attempt(
                conn,
                attempt_id,
                auth=auth,
                expected_mandate_revision=expected_mandate_revision,
                expected_fence=expected_fence,
                expected_work_item_revision=expected_work_item_revision,
            )
            permissions = json.loads(mandate["permissions_json"])
            if not permissions.get("can_commit"):
                raise PermissionError("Mandate does not allow agent commits")
            if int(attempt["issue_working_revision"]) != expected_issue_working_revision:
                raise ConflictError("Commit input does not match the attempt work package")
            current_issue_revision = int(
                conn.execute(
                    "SELECT working_revision FROM issues WHERE issue_id=?", (item["issue_id"],)
                ).fetchone()[0]
            )
            if current_issue_revision != expected_issue_working_revision:
                timestamp = now()
                conn.execute(
                    "UPDATE workflow_attempts SET status='rejected',rejection_code='input_stale',ended_at=? "
                    "WHERE attempt_id=?",
                    (timestamp, attempt_id),
                )
                conn.execute(
                    "UPDATE workflow_work_items SET status='ready',revision=revision+1,updated_at=? "
                    "WHERE work_item_id=?",
                    (timestamp, item["work_item_id"]),
                )
                event_id = self._event(
                    conn,
                    mandate_id=mandate["mandate_id"],
                    work_item_id=item["work_item_id"],
                    attempt_id=attempt_id,
                    event_type="attempt.rejected",
                    auth=auth,
                    before_state=attempt["status"],
                    after_state="rejected",
                    payload={
                        "code": "input_stale",
                        "expected_issue_working_revision": expected_issue_working_revision,
                        "current_issue_working_revision": current_issue_revision,
                    },
                )
                response = {
                    "attempt_id": attempt_id,
                    "work_item_id": item["work_item_id"],
                    "status": "rejected",
                    "reason": "input_stale",
                    "current_issue_working_revision": current_issue_revision,
                    "work_item_revision": int(item["revision"]) + 1,
                    "event_id": event_id,
                }
                self.store.idempotency_record(conn, operation, key, payload, response)
                return response
            budget = self._budget(mandate)
            if int(mandate["commits_used"]) >= budget["max_commits"]:
                self._block_for_budget(conn, mandate, reason="max_commits exhausted", auth=auth)
                response = {
                    "mandate_id": mandate["mandate_id"],
                    "attempt_id": attempt_id,
                    "status": "blocked",
                    "reason": "max_commits exhausted",
                }
                self.store.idempotency_record(conn, operation, key, payload, response)
                return response
            entry, output_id = self._commit_append_work(
                conn,
                mandate=mandate,
                item=item,
                attempt_id=attempt_id,
                body=body,
                contribution_kind="final",
                expected_issue_working_revision=expected_issue_working_revision,
                auth=auth,
                key=key,
            )
            timestamp = now()
            conn.execute(
                "UPDATE workflow_attempts SET status='succeeded',ended_at=?,heartbeat_at=? WHERE attempt_id=?",
                (timestamp, timestamp, attempt_id),
            )
            conn.execute(
                "UPDATE workflow_work_items SET status='completed',revision=revision+1,updated_at=? "
                "WHERE work_item_id=?",
                (timestamp, item["work_item_id"]),
            )
            mandate["commits_used"] = int(mandate["commits_used"]) + 1
            mandate["revision"] = int(mandate["revision"]) + 1
            mandate["updated_at"] = timestamp
            mandate["updated_by"] = auth.actor_id
            conn.execute(
                "UPDATE workflow_mandates SET commits_used=?,revision=?,updated_at=?,updated_by=? WHERE mandate_id=?",
                (
                    mandate["commits_used"],
                    mandate["revision"],
                    timestamp,
                    auth.actor_id,
                    mandate["mandate_id"],
                ),
            )
            self._record_revision(conn, mandate, event_type="agent_commit", auth=auth)
            event_id = self._event(
                conn,
                mandate_id=mandate["mandate_id"],
                work_item_id=item["work_item_id"],
                attempt_id=attempt_id,
                event_type="attempt.committed",
                auth=auth,
                before_state=attempt["status"],
                after_state="succeeded",
                payload={"output_id": output_id, "entry_id": entry["entry_id"]},
            )
            response = {
                "attempt_id": attempt_id,
                "work_item_id": item["work_item_id"],
                "status": "succeeded",
                "mandate_revision": mandate["revision"],
                "work_item_revision": int(item["revision"]) + 1,
                "output_id": output_id,
                "entry_id": entry["entry_id"],
                "event_id": event_id,
            }
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response

    def reconcile_expired(
        self,
        mandate_id: str,
        *,
        auth: AuthContext,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require(auth, "workflow.manage")
        key = self._require_key(idempotency_key)
        payload = {"mandate_id": mandate_id}
        operation = self._operation("attempt.reconcile_expired", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            mandate = self._mandate_row(conn, mandate_id)
            timestamp = self._iso_now().isoformat(timespec="seconds")
            rows = conn.execute(
                "SELECT attempt_id,work_item_id FROM workflow_attempts WHERE mandate_id=? "
                "AND status IN ('claimed','running','submitted') AND lease_until<=?",
                (mandate_id, timestamp),
            ).fetchall()
            for row in rows:
                conn.execute(
                    "UPDATE workflow_attempts SET status='expired',rejection_code='lease_expired',ended_at=? "
                    "WHERE attempt_id=?",
                    (timestamp, row["attempt_id"]),
                )
                target = (
                    "ready"
                    if mandate["status"] == "active"
                    and int(mandate["activation_epoch"]) == self._current_epoch(conn)
                    else "human_owned"
                )
                conn.execute(
                    "UPDATE workflow_work_items SET status=?,revision=revision+1,updated_at=? "
                    "WHERE work_item_id=?",
                    (target, timestamp, row["work_item_id"]),
                )
                self._event(
                    conn,
                    mandate_id=mandate_id,
                    work_item_id=row["work_item_id"],
                    attempt_id=row["attempt_id"],
                    event_type="attempt.expired",
                    auth=auth,
                    before_state="running",
                    after_state=target,
                )
            response = {"mandate_id": mandate_id, "expired_attempt_ids": [row["attempt_id"] for row in rows]}
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response

    def review_work_item(
        self,
        work_item_id: str,
        *,
        decision: str,
        expected_revision: int,
        retry: bool,
        reason: str,
        auth: AuthContext,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require(auth, "workflow.manage")
        key = self._require_key(idempotency_key)
        if decision not in {"pass", "fail"}:
            raise ValidationError("Workflow acceptance decision must be pass or fail")
        payload = {
            "work_item_id": work_item_id,
            "decision": decision,
            "expected_revision": expected_revision,
            "retry": retry,
            "reason": reason,
        }
        operation = self._operation("work_item.review", auth)
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay:
                return {**replay, "idempotent_replay": True}
            item = self._item_row(conn, work_item_id)
            self._assert_expected(int(item["revision"]), expected_revision, "work item revision")
            if item["status"] != "completed":
                raise ConflictError("Only a completed work item can be accepted or rejected")
            status = "completed" if decision == "pass" else ("ready" if retry else "blocked")
            acceptance_status = "passed" if decision == "pass" else "failed"
            new_revision = expected_revision + 1
            conn.execute(
                "UPDATE workflow_work_items SET status=?,acceptance_status=?,revision=?,updated_at=?,stop_reason=? "
                "WHERE work_item_id=?",
                (status, acceptance_status, new_revision, now(), None if decision == "pass" else reason, work_item_id),
            )
            event_id = self._event(
                conn,
                mandate_id=item["mandate_id"],
                work_item_id=work_item_id,
                event_type="work_item.accepted" if decision == "pass" else "work_item.rejected",
                auth=auth,
                before_state="completed",
                after_state=status,
                payload={"decision": decision, "reason": reason, "retry": retry},
            )
            response = {
                "work_item_id": work_item_id,
                "status": status,
                "acceptance_status": acceptance_status,
                "revision": new_revision,
                "event_id": event_id,
            }
            self.store.idempotency_record(conn, operation, key, payload, response)
        return response
