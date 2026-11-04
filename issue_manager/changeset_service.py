from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .changeset_engine import (
    OPERATION_DEFINITIONS,
    ChangeSetOperationEngine,
    ExecutionContext,
    simulate_operation,
)
from .changeset_execution import ChangeSetExecutionMixin
from .changeset_lineage import ChangeSetLineageMixin
from .changeset_operations import (
    operation_catalog,
    operation_spec,
)
from .changeset_preflight import ChangeSetPreflightMixin
from .changeset_state import StateView
from .errors import (
    ConflictError,
    IssueManagerError,
    LeaseExpiredError,
    NotFoundError,
    PermissionError,
    ValidationError,
)
from .risk import TIER_VALUE, ExecutionGrant, NormalizedMutation, RiskAssessment, RiskPolicy
from .security import AuthContext, CredentialResolver
from .store import canonical_json, new_id, now

if TYPE_CHECKING:
    from .service import IssueManager


class ChangeSetService(
    ChangeSetLineageMixin,
    ChangeSetPreflightMixin,
    ChangeSetExecutionMixin,
):
    def __init__(self, manager: "IssueManager"):
        self.manager = manager
        self.store = manager.store
        self.credentials = CredentialResolver(self.store)
        self.risk_policy = RiskPolicy(manager)
        self.operation_engine = ChangeSetOperationEngine(self)

    def create(
        self,
        changeset: dict[str, Any],
        *,
        credential: str | Path,
        idempotency_key: str | None = None,
        parent_changeset_id: str | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "changeset.submit")
        return self._create(changeset, auth=auth, idempotency_key=idempotency_key,
                            parent_changeset_id=parent_changeset_id)

    def _create(self, changeset, *, auth, idempotency_key=None, parent_changeset_id=None):
        """Internal authenticated entry; no credentials are manufactured for composition."""
        auth.require("changeset.submit")
        if changeset.get("changeset_version") != 1:
            raise ValidationError("Only changeset_version 1 is supported")
        if not isinstance(changeset.get("intent"), str) or not changeset["intent"].strip():
            raise ValidationError("ChangeSet requires a non-empty intent")
        payload = json.loads(canonical_json(changeset))
        for operation in payload.get("operations", []) if isinstance(payload.get("operations"), list) else []:
            if isinstance(operation, dict) and operation.get("op") == "intake_relation" and operation.get("action") == "add":
                provenance = {"actor_id": auth.actor_id, "run_id": auth.run_id}
                if "provenance" in operation and operation["provenance"] != provenance:
                    raise PermissionError("Intake relationship provenance must match the authenticated proposer")
                operation["provenance"] = provenance
        source_packets = payload.get("source_packet_ids", [])
        if not isinstance(source_packets, list):
            raise ValidationError("source_packet_ids must be a list")
        request_payload = {
            "changeset": payload,
            "parent_changeset_id": parent_changeset_id,
            "actor_id": auth.actor_id,
            "run_id": auth.run_id,
        }
        replay = self.store.idempotency_lookup("changeset.create", idempotency_key, request_payload)
        if replay:
            return {**replay, "idempotent_replay": True}
        for packet_id in source_packets:
            if not self.store.row("SELECT 1 FROM intake_packets WHERE packet_id=?", (packet_id,)):
                raise ValidationError(f"ChangeSet source packet does not exist: {packet_id}")
        if parent_changeset_id and not self.store.row(
            "SELECT state FROM changesets WHERE changeset_id=?", (parent_changeset_id,)
        ):
            raise ValidationError(f"Parent ChangeSet does not exist: {parent_changeset_id}")
        if parent_changeset_id:
            parent = self.show(parent_changeset_id)
            if parent["state"] == "applied":
                raise ConflictError("An applied ChangeSet cannot be replaced")
        risk_evaluation = self.risk_policy.assess_with_trace(payload)
        assessment = risk_evaluation.assessment
        changeset_id = new_id("changeset")
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        result = {
            "changeset_id": changeset_id,
            "parent_changeset_id": parent_changeset_id,
            "state": "draft",
            "changeset_hash": digest,
            "risk": assessment.as_dict(),
            "risk_trace": list(risk_evaluation.trace),
            "source_packet_ids": source_packets,
        }
        expectations = payload.get("expected_revisions", {})
        if not isinstance(expectations, dict):
            raise ValidationError("expected_revisions must be an object")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO changesets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    changeset_id,
                    parent_changeset_id,
                    1,
                    payload["intent"],
                    canonical_json(source_packets),
                    canonical_json(payload),
                    digest,
                    "draft",
                    assessment.tier,
                    canonical_json(list(assessment.reasons)),
                    auth.actor_id,
                    auth.run_id,
                    now(),
                    now(),
                    None,
                    None,
                ),
            )
            for index, operation in enumerate(payload["operations"]):
                operation_json = canonical_json(operation)
                conn.execute(
                    "INSERT INTO changeset_operations VALUES (?,?,?,?,?,NULL)",
                    (
                        changeset_id,
                        index,
                        operation_json,
                        hashlib.sha256(operation_json.encode("utf-8")).hexdigest(),
                        "pending",
                    ),
                )
            for issue_id, expected in expectations.items():
                if not isinstance(expected, dict):
                    raise ValidationError(f"Expected revision for {issue_id} must be an object")
                self.manager._issue(issue_id, active=False)
                conn.execute(
                    "INSERT INTO changeset_issue_expectations VALUES (?,?,?,?)",
                    (
                        changeset_id,
                        issue_id,
                        expected.get("working_revision"),
                        expected.get("conclusion_revision"),
                    ),
                )
            conn.execute(
                "INSERT INTO changeset_risk_assessments VALUES (?,?,?,?,?,?)",
                (
                    new_id("risk"),
                    changeset_id,
                    assessment.tier,
                    canonical_json(list(assessment.reasons)),
                    self.manager.policy.version,
                    now(),
                ),
            )
            self.store.idempotency_record(
                conn, "changeset.create", idempotency_key, request_payload, result
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="changeset.create",
                object_type="changeset",
                object_id=changeset_id,
                before_revision=None,
                after_revision=0,
                reason="",
                payload=result,
            )
        return result

    def show(self, changeset_id: str) -> dict[str, Any]:
        row = self.store.row("SELECT * FROM changesets WHERE changeset_id=?", (changeset_id,))
        if not row:
            raise NotFoundError(f"ChangeSet not found: {changeset_id}")
        row["changeset"] = json.loads(row.pop("changeset_json"))
        row["source_packet_ids"] = json.loads(row.pop("source_packet_ids_json"))
        row["risk_reasons"] = json.loads(row.pop("risk_reasons_json"))
        row["last_error_details"] = None
        if row.get("last_error"):
            try:
                decoded_error = json.loads(row["last_error"])
            except (TypeError, json.JSONDecodeError):
                decoded_error = {"code": "operation_failed", "message": row["last_error"]}
            if isinstance(decoded_error, dict):
                row["last_error_details"] = decoded_error
        row["operations"] = [
            {
                **item,
                "operation": json.loads(item.pop("operation_json")),
                "result": json.loads(item.pop("result_json")) if item.get("result_json") else None,
            }
            for item in self.store.rows(
                "SELECT * FROM changeset_operations WHERE changeset_id=? ORDER BY ordinal",
                (changeset_id,),
            )
        ]
        row["expectations"] = self.store.rows(
            "SELECT * FROM changeset_issue_expectations WHERE changeset_id=? ORDER BY issue_id",
            (changeset_id,),
        )
        row["reviews"] = [
            {**review, "review_status": "current"}
            for review in self.store.rows(
                "SELECT * FROM changeset_review_decisions WHERE changeset_id=? ORDER BY created_at",
                (changeset_id,),
            )
        ]
        stale_review_events = self.store.rows(
            "SELECT event_id,timestamp,payload_json FROM audit_events "
            "WHERE object_type='changeset' AND object_id=? "
            "AND action='changeset.review.stale' ORDER BY rowid",
            (changeset_id,),
        )
        for event in stale_review_events:
            payload = json.loads(event["payload_json"])
            row["reviews"].append(
                {
                    **payload["review"],
                    "review_status": "stale",
                    "stale_event_id": event["event_id"],
                    "stale_at": event["timestamp"],
                    "stale_reason": payload["reason"],
                    "superseded_by_risk_snapshot": payload["current_risk_snapshot"],
                }
            )
        row["risk_assessment_history"] = self.store.rows(
            "SELECT * FROM changeset_risk_assessments WHERE changeset_id=? "
            "ORDER BY assessed_at,assessment_id",
            (changeset_id,),
        )
        for assessment in row["risk_assessment_history"]:
            assessment["reasons"] = json.loads(assessment.pop("reasons_json"))
        lifecycle = self._lifecycle_event(changeset_id)
        row["storage_state"] = row["state"]
        row["lifecycle"] = lifecycle
        if lifecycle:
            row["state"] = (
                "superseded" if lifecycle["action"] == "changeset.supersede" else "abandoned"
            )
        row["replacement_chain"] = self.replacement_chain(changeset_id)
        return row

    def list_changesets(self, state: str | None = None) -> list[dict[str, Any]]:
        items = self.store.rows(
            "SELECT changeset_id,intent,state,risk_tier,created_by,created_at,updated_at "
            "FROM changesets ORDER BY created_at DESC"
        )
        for item in items:
            lifecycle = self._lifecycle_event(item["changeset_id"])
            item["storage_state"] = item["state"]
            item["lifecycle"] = lifecycle
            if lifecycle:
                item["state"] = (
                    "superseded" if lifecycle["action"] == "changeset.supersede" else "abandoned"
                )
        return [item for item in items if not state or item["state"] == state]

    def operation_catalog(self, *, auth: AuthContext) -> dict[str, Any]:
        return operation_catalog(capabilities=auth.capabilities)

    def operation_guide(self, op: str, *, auth: AuthContext) -> dict[str, Any]:
        spec = operation_spec(op)
        return spec.guide(available=spec.required_capability in auth.capabilities)

    def preview(self, changeset_id: str) -> dict[str, Any]:
        shown = self.show(changeset_id)
        assessment = RiskAssessment(shown["risk_tier"], tuple(shown["risk_reasons"]))
        return {
            "changeset_id": changeset_id,
            "state": shown["state"],
            "risk": assessment.as_dict(),
            "operation_count": len(shown["operations"]),
            "operations": [item["operation"] for item in shown["operations"]],
            "would_apply_immediately": assessment.required_reviews == 0,
            "atomic": True,
        }

    def _validate_expectations(self, conn: Any, changeset_id: str) -> None:
        for expected in conn.execute(
            "SELECT * FROM changeset_issue_expectations WHERE changeset_id=?", (changeset_id,)
        ).fetchall():
            issue = conn.execute(
                "SELECT working_revision,conclusion_revision FROM issues WHERE issue_id=?",
                (expected["issue_id"],),
            ).fetchone()
            if not issue:
                raise ConflictError(f"Expected Issue no longer exists: {expected['issue_id']}")
            for column in ("working_revision", "conclusion_revision"):
                expected_value = expected[f"expected_{column}"]
                if expected_value is not None and issue[column] != expected_value:
                    raise ConflictError(
                        f"ChangeSet optimistic lock failed for {expected['issue_id']} {column}: "
                        f"expected {expected_value}, current {issue[column]}"
                    )

    @staticmethod
    def _validate_governed_operations(
        conn: sqlite3.Connection, operations: list[dict[str, Any]]
    ) -> None:
        from .conflict_governance import validate_resolution_binding

        for operation in operations:
            if operation.get("op") == "resolve_field_conflict":
                validate_resolution_binding(conn, "field_bundle", operation)
            elif operation.get("op") == "resolve_import_conflict":
                validate_resolution_binding(conn, "import", operation)

    @staticmethod
    def _validate_operation_rows(shown: dict[str, Any]) -> None:
        operations = shown["changeset"]["operations"]
        stored = shown["operations"]
        if len(operations) != len(stored):
            raise ConflictError("ChangeSet operation ledger does not match its payload")
        for ordinal, (operation, row) in enumerate(zip(operations, stored, strict=True)):
            operation_json = canonical_json(operation)
            operation_hash = hashlib.sha256(operation_json.encode("utf-8")).hexdigest()
            if (
                int(row["ordinal"]) != ordinal
                or row["operation"] != operation
                or row["operation_hash"] != operation_hash
            ):
                raise ConflictError(f"ChangeSet operation {ordinal} hash or payload does not match")

    @staticmethod
    def _risk_snapshot(assessment: RiskAssessment, policy_version: int) -> dict[str, Any]:
        return {
            "risk_tier": assessment.tier,
            "risk_reasons": list(assessment.reasons),
            "policy_version": policy_version,
        }

    def _stored_risk_snapshot(self, changeset: dict[str, Any]) -> dict[str, Any]:
        latest = self.store.row(
            "SELECT risk_tier,reasons_json,policy_version FROM changeset_risk_assessments "
            "WHERE changeset_id=? ORDER BY rowid DESC LIMIT 1",
            (changeset["changeset_id"],),
        )
        if not latest:
            raise ConflictError("ChangeSet has no persisted risk assessment history")
        assessment_reasons = json.loads(latest["reasons_json"])
        current_reasons = changeset.get("risk_reasons")
        if current_reasons is None:
            current_reasons = json.loads(changeset["risk_reasons_json"])
        if (
            changeset["risk_tier"] != latest["risk_tier"]
            or list(current_reasons) != assessment_reasons
        ):
            raise ConflictError("Stored ChangeSet risk fields do not match its assessment history")
        return {
            "risk_tier": latest["risk_tier"],
            "risk_reasons": assessment_reasons,
            "policy_version": int(latest["policy_version"]),
        }

    def _assert_current_policy_version(self, changeset: dict[str, Any]) -> None:
        stored = self._stored_risk_snapshot(changeset)
        current = self.manager.policy.version
        if stored["policy_version"] != current:
            raise ConflictError(
                "ChangeSet policy version changed; validate it again before review or apply",
                details={
                    "recovery_action": "validate",
                    "stored_policy_version": stored["policy_version"],
                    "current_policy_version": current,
                },
            )

    def _persist_runtime_risk_upgrade(
        self,
        changeset_id: str,
        *,
        auth: AuthContext,
        assessment: RiskAssessment,
        details: dict[str, Any],
    ) -> None:
        snapshot = self._risk_snapshot(assessment, self.manager.policy.version)
        with self.store.transaction() as conn:
            changeset = conn.execute(
                "SELECT state,risk_tier,risk_reasons_json FROM changesets WHERE changeset_id=?",
                (changeset_id,),
            ).fetchone()
            if not changeset or changeset["state"] == "applied":
                return
            stale_reviews = [
                dict(review)
                for review in conn.execute(
                    "SELECT * FROM changeset_review_decisions WHERE changeset_id=?",
                    (changeset_id,),
                ).fetchall()
            ]
            for review in stale_reviews:
                self.store.audit(
                    conn,
                    actor=auth.actor_id,
                    action="changeset.review.stale",
                    object_type="changeset",
                    object_id=changeset_id,
                    before_revision=None,
                    after_revision=None,
                    reason="Runtime operation risk exceeded the reviewed snapshot",
                    payload={
                        "review": review,
                        "reason": "runtime_risk_upgrade",
                        "current_risk_snapshot": snapshot,
                        "operation_ordinal": details["operation_ordinal"],
                        "operation": details["operation"],
                    },
                )
            conn.execute(
                "DELETE FROM changeset_review_decisions WHERE changeset_id=?",
                (changeset_id,),
            )
            conn.execute(
                "INSERT INTO changeset_risk_assessments VALUES (?,?,?,?,?,?)",
                (
                    new_id("risk"),
                    changeset_id,
                    assessment.tier,
                    canonical_json(list(assessment.reasons)),
                    self.manager.policy.version,
                    now(),
                ),
            )
            state = "awaiting_review" if assessment.required_reviews else "validated"
            conn.execute(
                "UPDATE changesets SET state=?,risk_tier=?,risk_reasons_json=?,updated_at=?,"
                "last_error=? WHERE changeset_id=?",
                (
                    state,
                    assessment.tier,
                    canonical_json(list(assessment.reasons)),
                    now(),
                    canonical_json(
                        {
                            "code": "runtime_risk_upgrade",
                            "message": "Runtime operation risk exceeded the reviewed snapshot",
                            "details": details,
                        }
                    ),
                    changeset_id,
                ),
            )
            conn.execute(
                "UPDATE changeset_review_assignments SET state='released',released_at=?,"
                "last_error='runtime risk changed; a new review is required' "
                "WHERE changeset_id=? AND state IN ('assigned','submitted')",
                (now(), changeset_id),
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="changeset.risk.runtime_upgrade",
                object_type="changeset",
                object_id=changeset_id,
                before_revision=None,
                after_revision=None,
                reason="Runtime operation risk exceeded the reviewed snapshot",
                payload={
                    **details,
                    "previous_risk": {
                        "tier": changeset["risk_tier"],
                        "reasons": json.loads(changeset["risk_reasons_json"]),
                    },
                    "current_risk_snapshot": snapshot,
                    "stale_review_ids": [review["review_id"] for review in stale_reviews],
                },
            )

    def validate(self, changeset_id: str, *, credential: str | Path) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "changeset.submit")
        shown = self.show(changeset_id)
        if shown["state"] not in {"draft", "failed", "validated", "awaiting_review"}:
            raise ConflictError(f"ChangeSet cannot be validated from state {shown['state']}")
        actual_hash = hashlib.sha256(canonical_json(shown["changeset"]).encode("utf-8")).hexdigest()
        if actual_hash != shown["changeset_hash"]:
            raise ConflictError("Stored ChangeSet content hash mismatch")
        self._validate_operation_rows(shown)
        preflight = self._preflight_operations(shown["changeset"]["operations"])
        fresh_assessment = preflight["assessment"]
        fresh_snapshot = self._risk_snapshot(fresh_assessment, self.manager.policy.version)
        risk_changed = fresh_snapshot != self._stored_risk_snapshot(shown)
        self._check_operation_capabilities(shown["changeset"]["operations"], auth)
        with self.store.transaction() as conn:
            self._validate_expectations(conn, changeset_id)
            self._validate_governed_operations(conn, shown["changeset"]["operations"])
            state = "awaiting_review" if fresh_assessment.required_reviews else "validated"
            conn.execute(
                "UPDATE changesets SET state=?,risk_tier=?,risk_reasons_json=?,updated_at=?,"
                "last_error=NULL WHERE changeset_id=?",
                (
                    state,
                    fresh_assessment.tier,
                    canonical_json(list(fresh_assessment.reasons)),
                    now(),
                    changeset_id,
                ),
            )
            if risk_changed:
                stale_reviews = [
                    dict(review)
                    for review in conn.execute(
                        "SELECT * FROM changeset_review_decisions WHERE changeset_id=?",
                        (changeset_id,),
                    ).fetchall()
                ]
                for review in stale_reviews:
                    self.store.audit(
                        conn,
                        actor=auth.actor_id,
                        action="changeset.review.stale",
                        object_type="changeset",
                        object_id=changeset_id,
                        before_revision=None,
                        after_revision=None,
                        reason="ChangeSet risk snapshot changed during validation",
                        payload={
                            "review": review,
                            "reason": "risk_snapshot_changed",
                            "current_risk_snapshot": fresh_snapshot,
                        },
                    )
                conn.execute(
                    "DELETE FROM changeset_review_decisions WHERE changeset_id=?",
                    (changeset_id,),
                )
                conn.execute(
                    "INSERT INTO changeset_risk_assessments VALUES (?,?,?,?,?,?)",
                    (
                        new_id("risk"),
                        changeset_id,
                        fresh_assessment.tier,
                        canonical_json(list(fresh_assessment.reasons)),
                        self.manager.policy.version,
                        now(),
                    ),
                )
                conn.execute(
                    "UPDATE changeset_review_assignments SET state='released',released_at=?,"
                    "last_error='risk snapshot changed; a new review is required' "
                    "WHERE changeset_id=? AND state IN ('assigned','submitted')",
                    (now(), changeset_id),
                )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="changeset.preflight",
                object_type="changeset",
                object_id=changeset_id,
                before_revision=None,
                after_revision=None,
                reason="Sequential operation validation and risk simulation",
                payload={
                    "risk": fresh_assessment.as_dict(),
                    "risk_trace": preflight["trace"],
                    "risk_changed": risk_changed,
                },
            )
        return {
            "changeset_id": changeset_id,
            "valid": True,
            "state": state,
            "risk": fresh_assessment.as_dict(),
            "risk_trace": preflight["trace"],
            "risk_changed": risk_changed,
        }

    @staticmethod
    def _required_capability(operation: dict[str, Any]) -> str:
        return operation_spec(str(operation["op"])).required_capability

    def _check_operation_capabilities(
        self, operations: list[dict[str, Any]], auth: AuthContext
    ) -> None:
        for operation in operations:
            auth.require(self._required_capability(operation))
            if operation["op"] in {"propose_conclusion", "refresh_issue"}:
                auth.require("proposal.apply")

    def claim_review(
        self,
        changeset_id: str,
        *,
        credential: str | Path,
        lease_minutes: int = 15,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "proposal.review")
        changeset = self.store.row("SELECT * FROM changesets WHERE changeset_id=?", (changeset_id,))
        if not changeset:
            raise NotFoundError(f"ChangeSet not found: {changeset_id}")
        self._ensure_actionable(changeset_id)
        if changeset["state"] != "awaiting_review":
            raise ConflictError(f"ChangeSet is {changeset['state']}, not awaiting review")
        self._check_review_independence(changeset, auth)
        lease_until = (
            datetime.now().astimezone() + timedelta(minutes=max(1, lease_minutes))
        ).isoformat(timespec="seconds")
        assignment_id = new_id("changeset_assignment")
        lease_generation = 1
        try:
            with self.store.transaction() as conn:
                locked = conn.execute(
                    "SELECT state FROM changesets WHERE changeset_id=?", (changeset_id,)
                ).fetchone()
                if not locked or locked["state"] != "awaiting_review":
                    raise ConflictError("ChangeSet is no longer claimable for review")
                existing = conn.execute(
                    "SELECT * FROM changeset_review_assignments "
                    "WHERE changeset_id=? AND reviewer_run_id=?",
                    (changeset_id, auth.run_id),
                ).fetchone()
                if existing and existing["state"] == "assigned" and existing["lease_until"] > now():
                    return {**dict(existing), "idempotent_replay": True}
                if existing and existing["state"] == "submitted":
                    raise ConflictError("Review was already completed by this reviewer run")
                if existing:
                    assignment_id = existing["assignment_id"]
                    lease_generation = int(existing["lease_generation"]) + 1
                    conn.execute(
                        "UPDATE changeset_review_assignments SET state='assigned',claimed_at=?,"
                        "lease_until=?,heartbeat_at=?,released_at=NULL,"
                        "lease_generation=?,last_error=NULL WHERE assignment_id=?",
                        (now(), lease_until, now(), lease_generation, assignment_id),
                    )
                else:
                    conn.execute(
                        "INSERT INTO changeset_review_assignments(assignment_id,changeset_id,"
                        "reviewer_actor_id,reviewer_run_id,state,claimed_at,lease_until,heartbeat_at,"
                        "released_at,lease_generation,last_error) "
                        "VALUES (?,?,?,?,'assigned',?,?,?,NULL,1,NULL)",
                        (
                            assignment_id,
                            changeset_id,
                            auth.actor_id,
                            auth.run_id,
                            now(),
                            lease_until,
                            now(),
                        ),
                    )
        except sqlite3.IntegrityError as exc:
            existing = self.store.row(
                "SELECT * FROM changeset_review_assignments "
                "WHERE changeset_id=? AND reviewer_run_id=?",
                (changeset_id, auth.run_id),
            )
            if existing and existing["state"] == "assigned" and existing["lease_until"] > now():
                return {**existing, "idempotent_replay": True}
            raise ConflictError("Review assignment conflicted with another claim") from exc
        return {
            "assignment_id": assignment_id,
            "changeset_id": changeset_id,
            "lease_until": lease_until,
            "lease_generation": lease_generation,
        }

    def heartbeat_review(
        self,
        changeset_id: str,
        *,
        credential: str | Path,
        lease_minutes: int = 15,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "proposal.review")
        lease_until = (
            datetime.now().astimezone() + timedelta(minutes=max(1, lease_minutes))
        ).isoformat(timespec="seconds")
        with self.store.transaction() as conn:
            self._ensure_actionable(changeset_id, conn=conn)
            assignment = conn.execute(
                "SELECT * FROM changeset_review_assignments WHERE changeset_id=? "
                "AND reviewer_actor_id=? AND reviewer_run_id=? AND state='assigned'",
                (changeset_id, auth.actor_id, auth.run_id),
            ).fetchone()
            if not assignment:
                raise ConflictError("No active ChangeSet review assignment exists")
            if assignment["lease_until"] <= now():
                raise LeaseExpiredError("ChangeSet review lease expired; reclaim it")
            conn.execute(
                "UPDATE changeset_review_assignments SET lease_until=?,heartbeat_at=? "
                "WHERE assignment_id=?",
                (lease_until, now(), assignment["assignment_id"]),
            )
        return {
            "assignment_id": assignment["assignment_id"],
            "changeset_id": changeset_id,
            "lease_until": lease_until,
            "lease_generation": assignment["lease_generation"],
        }

    def release_review(self, changeset_id: str, *, credential: str | Path) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "proposal.review")
        with self.store.transaction() as conn:
            self._ensure_actionable(changeset_id, conn=conn)
            assignment = conn.execute(
                "SELECT * FROM changeset_review_assignments WHERE changeset_id=? "
                "AND reviewer_actor_id=? AND reviewer_run_id=?",
                (changeset_id, auth.actor_id, auth.run_id),
            ).fetchone()
            if not assignment:
                raise ConflictError("No ChangeSet review assignment exists for this run")
            if assignment["state"] == "submitted":
                raise ConflictError("A completed review cannot be released")
            released_at = assignment["released_at"] or now()
            replay = assignment["state"] == "released"
            if not replay:
                conn.execute(
                    "UPDATE changeset_review_assignments SET state='released',released_at=? "
                    "WHERE assignment_id=?",
                    (released_at, assignment["assignment_id"]),
                )
        return {
            "assignment_id": assignment["assignment_id"],
            "changeset_id": changeset_id,
            "state": "released",
            "released_at": released_at,
            "idempotent_replay": replay,
        }

    def _check_review_independence(self, changeset: dict[str, Any], auth: AuthContext) -> None:
        if auth.actor_id == changeset["created_by"] or auth.run_id == changeset["created_run_id"]:
            raise PermissionError("A ChangeSet creator cannot review its own ChangeSet")
        if hasattr(self.manager, "context_obligations"):
            operations = json.loads(changeset["changeset_json"])["operations"]
            opened = {op["obligation_id"]: op for op in operations if op["op"] == "context_obligation" and op["action"] == "open"}
            for operation in operations:
                if operation["op"] == "context_obligation" and operation["action"] in {"complete", "cancel"}:
                    duty = self.manager.context_obligations.get(operation["obligation_id"]) or opened.get(operation["obligation_id"])
                    if duty:
                        self.manager.context_obligations.assert_independent(duty["conclusion_id"], auth.actor_id, auth.run_id)
        creator_run = self.store.row(
            "SELECT lineage_json FROM agent_runs WHERE run_id=?", (changeset["created_run_id"],)
        )
        lineage = set(json.loads((creator_run or {}).get("lineage_json", "[]")))
        lineage.add(changeset["created_run_id"])
        if auth.run_id in lineage or changeset["created_run_id"] in auth.lineage:
            raise PermissionError("Reviewer is in the ChangeSet creator's delegation lineage")
        self._assert_current_policy_version(changeset)
        assessment = RiskAssessment(
            changeset["risk_tier"],
            tuple(json.loads(changeset["risk_reasons_json"])),
        )
        risk_snapshot_json = canonical_json(
            self._risk_snapshot(assessment, self.manager.policy.version)
        )
        duplicate = self.store.row(
            "SELECT review_id FROM changeset_review_decisions WHERE changeset_id=? "
            "AND reviewer_actor_id=? AND risk_snapshot_json=?",
            (changeset["changeset_id"], auth.actor_id, risk_snapshot_json),
        )
        if duplicate:
            raise ConflictError("Each ChangeSet review must come from a distinct actor")

    def submit_review(
        self,
        changeset_id: str,
        *,
        decision: str,
        rationale: str,
        credential: str | Path,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "proposal.review")
        changeset = self.store.row("SELECT * FROM changesets WHERE changeset_id=?", (changeset_id,))
        if not changeset:
            raise NotFoundError(f"ChangeSet not found: {changeset_id}")
        self._ensure_actionable(changeset_id)
        if decision not in {"pass", "reject"} or not rationale.strip():
            raise ValidationError("ChangeSet review requires pass/reject and a rationale")
        assignment = self.store.row(
            "SELECT * FROM changeset_review_assignments WHERE changeset_id=? AND reviewer_actor_id=? "
            "AND reviewer_run_id=?",
            (changeset_id, auth.actor_id, auth.run_id),
        )
        request_payload = {
            "changeset_id": changeset_id,
            "changeset_hash": changeset["changeset_hash"],
            "risk_snapshot": self._risk_snapshot(
                RiskAssessment(
                    changeset["risk_tier"],
                    tuple(json.loads(changeset["risk_reasons_json"])),
                ),
                self.manager.policy.version,
            ),
            "reviewer_actor_id": auth.actor_id,
            "reviewer_run_id": auth.run_id,
            "assignment_id": assignment["assignment_id"] if assignment else None,
            "decision": decision,
            "rationale": rationale,
        }
        replay = self.store.idempotency_lookup(
            "changeset.review.submit", idempotency_key, request_payload
        )
        if replay:
            return {**replay, "idempotent_replay": True}
        if changeset["state"] != "awaiting_review":
            raise ConflictError(f"ChangeSet is {changeset['state']}, not awaiting review")
        self._check_review_independence(changeset, auth)
        if not assignment or assignment["state"] != "assigned":
            raise PermissionError("ChangeSet review requires a current assignment lease")
        if assignment["lease_until"] <= now():
            raise LeaseExpiredError("ChangeSet review assignment lease has expired")
        review_id = new_id("changeset_review")
        with self.store.transaction() as conn:
            locked_value = conn.execute(
                "SELECT * FROM changesets WHERE changeset_id=?", (changeset_id,)
            ).fetchone()
            if not locked_value:
                raise NotFoundError(f"ChangeSet not found: {changeset_id}")
            locked_changeset = dict(locked_value)
            if locked_changeset["state"] != "awaiting_review":
                raise ConflictError(
                    f"ChangeSet is {locked_changeset['state']}, not awaiting review"
                )
            self._assert_current_policy_version(locked_changeset)
            self._check_review_independence(locked_changeset, auth)
            locked_assignment = conn.execute(
                "SELECT * FROM changeset_review_assignments WHERE changeset_id=? "
                "AND reviewer_actor_id=? AND reviewer_run_id=? AND state='assigned'",
                (changeset_id, auth.actor_id, auth.run_id),
            ).fetchone()
            if not locked_assignment or locked_assignment["lease_until"] <= now():
                raise LeaseExpiredError("ChangeSet review requires a current assignment lease")
            conn.execute(
                "INSERT INTO changeset_review_decisions(review_id,changeset_id,"
                "reviewer_actor_id,reviewer_run_id,decision,rationale,changeset_hash,"
                "risk_snapshot_json,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    review_id,
                    changeset_id,
                    auth.actor_id,
                    auth.run_id,
                    decision,
                    rationale,
                    locked_changeset["changeset_hash"],
                    canonical_json(
                        self._risk_snapshot(
                            RiskAssessment(
                                locked_changeset["risk_tier"],
                                tuple(json.loads(locked_changeset["risk_reasons_json"])),
                            ),
                            self.manager.policy.version,
                        )
                    ),
                    now(),
                ),
            )
            conn.execute(
                "UPDATE changeset_review_assignments SET state='submitted' WHERE assignment_id=?",
                (locked_assignment["assignment_id"],),
            )
            if decision == "reject":
                conn.execute(
                    "UPDATE changesets SET state='rejected',last_error=?,updated_at=? WHERE changeset_id=?",
                    (rationale, now(), changeset_id),
                )
            passes = int(
                conn.execute(
                    "SELECT COUNT(DISTINCT reviewer_actor_id) FROM changeset_review_decisions "
                    "WHERE changeset_id=? AND decision='pass' AND changeset_hash=? "
                    "AND risk_snapshot_json=?",
                    (
                        changeset_id,
                        locked_changeset["changeset_hash"],
                        canonical_json(
                            self._risk_snapshot(
                                RiskAssessment(
                                    locked_changeset["risk_tier"],
                                    tuple(json.loads(locked_changeset["risk_reasons_json"])),
                                ),
                                self.manager.policy.version,
                            )
                        ),
                    ),
                ).fetchone()[0]
            )
            result = {
                "review_id": review_id,
                "changeset_id": changeset_id,
                "decision": decision,
                "pass_count": passes,
                "required_reviews": (
                    2
                    if locked_changeset["risk_tier"] == "T3"
                    else (1 if locked_changeset["risk_tier"] == "T2" else 0)
                ),
                "assignment_id": assignment["assignment_id"],
            }
            self.store.idempotency_record(
                conn,
                "changeset.review.submit",
                idempotency_key,
                request_payload,
                result,
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="changeset.review.submit",
                object_type="changeset",
                object_id=changeset_id,
                before_revision=None,
                after_revision=None,
                reason=rationale,
                payload=result,
            )
        return result

    def apply(
        self,
        changeset_id: str,
        *,
        credential: str | Path,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "changeset.submit")
        shown = self.show(changeset_id)
        if shown["state"] in {"draft", "failed"}:
            self.validate(changeset_id, credential=credential)
            shown = self.show(changeset_id)
        request_payload = {"changeset_id": changeset_id, "changeset_hash": shown["changeset_hash"]}
        replay = self.store.idempotency_lookup("changeset.apply", idempotency_key, request_payload)
        if replay:
            return {**replay, "idempotent_replay": True}
        if shown["state"] == "applied":
            return {"changeset_id": changeset_id, "state": "applied", "idempotent_replay": True}
        self._validate_operation_rows(shown)
        if shown["state"] not in {"validated", "awaiting_review"}:
            raise ConflictError(f"ChangeSet cannot be applied from state {shown['state']}")
        self._check_operation_capabilities(shown["changeset"]["operations"], auth)
        results: list[dict[str, Any]] = []
        try:
            with self.store.transaction() as conn:
                locked = dict(
                    conn.execute(
                        "SELECT * FROM changesets WHERE changeset_id=?", (changeset_id,)
                    ).fetchone()
                )
                if locked["state"] == "applied":
                    return {
                        "changeset_id": changeset_id,
                        "state": "applied",
                        "idempotent_replay": True,
                    }
                if locked["state"] not in {"validated", "awaiting_review"}:
                    raise ConflictError(
                        f"ChangeSet changed to state {locked['state']} while awaiting apply"
                    )
                if locked["changeset_hash"] != shown["changeset_hash"]:
                    raise ConflictError("ChangeSet changed while awaiting apply")
                self._assert_current_policy_version(locked)
                current_assessment = self.risk_policy.assess(shown["changeset"])
                if current_assessment.tier != locked["risk_tier"] or list(
                    current_assessment.reasons
                ) != json.loads(locked["risk_reasons_json"]):
                    raise ConflictError(
                        "ChangeSet risk changed before apply; validate it again",
                        details={
                            "recovery_action": "validate",
                            "stored_risk": {
                                "tier": locked["risk_tier"],
                                "reasons": json.loads(locked["risk_reasons_json"]),
                            },
                            "current_risk": current_assessment.as_dict(),
                        },
                    )
                required_reviews = current_assessment.required_reviews
                current_risk_snapshot_json = canonical_json(
                    self._risk_snapshot(current_assessment, self.manager.policy.version)
                )
                locked_reviews = [
                    dict(row)
                    for row in conn.execute(
                        "SELECT * FROM changeset_review_decisions WHERE changeset_id=? "
                        "AND decision='pass' AND changeset_hash=? AND risk_snapshot_json=? "
                        "ORDER BY created_at",
                        (
                            changeset_id,
                            locked["changeset_hash"],
                            current_risk_snapshot_json,
                        ),
                    ).fetchall()
                ]
                if len({row["reviewer_actor_id"] for row in locked_reviews}) < required_reviews:
                    raise PermissionError(
                        f"ChangeSet requires {required_reviews} independent passing review(s)"
                    )
                self._validate_expectations(conn, changeset_id)
                self._validate_governed_operations(conn, shown["changeset"]["operations"])
                conn.execute(
                    "UPDATE changesets SET state='applying',updated_at=? WHERE changeset_id=?",
                    (now(), changeset_id),
                )
                runtime_view = StateView(self.manager)
                for index, operation in enumerate(shown["changeset"]["operations"]):
                    self.store.fault(f"changeset.before_operation.{index}")
                    operation_assessment, _ = self.risk_policy.assess_operation(
                        operation, runtime_view
                    )
                    if TIER_VALUE[operation_assessment.tier] > TIER_VALUE[current_assessment.tier]:
                        escalated_assessment = RiskAssessment(
                            tier=operation_assessment.tier,
                            reasons=tuple(
                                sorted(
                                    set(current_assessment.reasons)
                                    | set(operation_assessment.reasons)
                                )
                            ),
                        )
                        raise ConflictError(
                            "Runtime operation risk exceeded the reviewed ChangeSet snapshot; "
                            "all operations were rolled back and new review is required",
                            details={
                                "runtime_risk_upgrade": True,
                                "recovery_action": "review",
                                "operation_ordinal": index,
                                "operation": operation["op"],
                                "reviewed_risk": current_assessment.as_dict(),
                                "operation_risk": operation_assessment.as_dict(),
                                "upgraded_risk": escalated_assessment.as_dict(),
                                "pre_state": runtime_view.pre_state(operation),
                            },
                        )
                    mutation = NormalizedMutation(
                        operation=f"changeset.{operation['op']}",
                        target={"changeset_id": changeset_id},
                        requested_state=operation,
                        actor_id=auth.actor_id,
                        run_id=auth.run_id,
                        source="changeset.apply",
                        request_id=idempotency_key or changeset_id,
                    )
                    grant = self.manager._issue_execution_grant(
                        mutation,
                        current_assessment,
                        changeset_id=changeset_id,
                        changeset_hash=locked["changeset_hash"],
                    )
                    # Model from the same pre-state used for risk, before the
                    # write moves version heads and invalidates its own CAS.
                    simulate_operation(runtime_view, operation)
                    result = self._apply_operation(
                        changeset_id,
                        operation,
                        auth,
                        credential,
                        locked_reviews,
                        grant,
                        operation_ordinal=index,
                        changeset_hash=locked["changeset_hash"],
                    )
                    results.append(result)
                    conn.execute(
                        "UPDATE changeset_operations SET state='applied',result_json=? WHERE changeset_id=? AND ordinal=?",
                        (canonical_json(result), changeset_id, index),
                    )
                    self.store.fault(f"changeset.after_operation.{index}")
                response = {
                    "changeset_id": changeset_id,
                    "state": "applied",
                    "risk": {"tier": shown["risk_tier"], "reasons": shown["risk_reasons"]},
                    "results": results,
                }
                conn.execute(
                    "UPDATE changesets SET state='applied',applied_at=?,updated_at=?,last_error=NULL WHERE changeset_id=?",
                    (now(), now(), changeset_id),
                )
                self.store.idempotency_record(
                    conn, "changeset.apply", idempotency_key, request_payload, response
                )
                self.store.audit(
                    conn,
                    actor=auth.actor_id,
                    action="changeset.apply",
                    object_type="changeset",
                    object_id=changeset_id,
                    before_revision=0,
                    after_revision=1,
                    reason="",
                    payload=response,
                )
            return response
        except Exception as exc:
            # Missing review quorum is an actionable precondition, not an
            # execution attempt. Keep the ChangeSet reviewable while the HTTP
            # request ledger records the denied apply.
            if isinstance(exc, PermissionError):
                raise
            if isinstance(exc, ConflictError) and exc.details.get("runtime_risk_upgrade"):
                upgraded = exc.details["upgraded_risk"]
                self._persist_runtime_risk_upgrade(
                    changeset_id,
                    auth=auth,
                    assessment=RiskAssessment(str(upgraded["tier"]), tuple(upgraded["reasons"])),
                    details=exc.details,
                )
                raise
            error = {
                "code": exc.code if isinstance(exc, IssueManagerError) else "internal_error",
                "message": str(exc),
                "details": exc.details if isinstance(exc, IssueManagerError) else {},
                "exception_type": type(exc).__name__,
                "recovery_action": (
                    exc.details.get("recovery_action")
                    if isinstance(exc, IssueManagerError)
                    else "inspect_and_retry_or_replace"
                ),
            }
            with self.store.transaction() as conn:
                conn.execute(
                    "UPDATE changesets SET state='failed',last_error=?,updated_at=? WHERE changeset_id=? AND state<>'applied'",
                    (canonical_json(error), now(), changeset_id),
                )
                for packet_id in shown["source_packet_ids"]:
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
                self.store.audit(
                    conn,
                    actor=auth.actor_id,
                    action="changeset.apply.failed",
                    object_type="changeset",
                    object_id=changeset_id,
                    before_revision=0,
                    after_revision=0,
                    reason=str(exc),
                    payload=error,
                )
            raise

    def _apply_operation(
        self,
        changeset_id: str,
        operation: dict[str, Any],
        auth: AuthContext,
        credential: str | Path,
        reviews: list[dict[str, Any]],
        grant: ExecutionGrant,
        *,
        operation_ordinal: int,
        changeset_hash: str,
    ) -> dict[str, Any]:
        if operation.get("op") not in OPERATION_DEFINITIONS:
            raise AssertionError(f"Unhandled ChangeSet operation {operation.get('op')}")
        context = ExecutionContext(
            changeset_id=changeset_id,
            auth=auth,
            credential=credential,
            reviews=reviews,
            grant=grant,
            operation_ordinal=operation_ordinal,
            changeset_hash=changeset_hash,
        )
        return self.operation_engine.execute(operation, context)
