from __future__ import annotations

import hashlib
import sqlite3
from contextlib import nullcontext
from typing import TYPE_CHECKING, Any, List

from .errors import ConflictError, NotFoundError, ValidationError
from .repositories import ConclusionRepository, IssueRepository, QuestionRepository
from .store import canonical_json, new_id, now
from .strict_json import require_strict_json

if TYPE_CHECKING:
    from .service import IssueManager


QUESTION_KINDS = {
    "experiment",
    "analysis",
    "data_gap",
    "conflict",
    "verification",
    "decision",
}
QUESTION_STATUSES = {
    "open",
    "in_progress",
    "blocked",
    "answered",
    "deferred",
    "cancelled",
}
QUESTION_LINK_TYPES = {"addresses", "supports", "challenges", "context"}
_TRANSITIONS = {
    "open": {"in_progress", "blocked", "deferred", "cancelled", "answered"},
    "in_progress": {"open", "blocked", "deferred", "cancelled", "answered"},
    "blocked": {"open", "in_progress", "deferred", "cancelled", "answered"},
    "answered": {"open"},
    "deferred": {"open", "cancelled"},
    "cancelled": {"open"},
}


class QuestionService:
    """Lifecycle owner for first-class Issue Questions."""

    def __init__(self, manager: IssueManager):
        self.manager = manager
        self.store = manager.store
        self.questions = QuestionRepository(self.store)
        self.issues = IssueRepository(self.store)
        self.conclusions = ConclusionRepository(self.store)

    @staticmethod
    def _validate_priority(priority: int) -> None:
        if isinstance(priority, bool) or not isinstance(priority, int) or not 0 <= priority <= 100:
            raise ValidationError("Question priority must be an integer between 0 and 100")

    @staticmethod
    def _snapshot(question: dict[str, Any]) -> dict[str, Any]:
        return {
            "question_id": question["question_id"],
            "issue_id": question["issue_id"],
            "question_key": question.get("question_key"),
            "prompt": question["prompt"],
            "motivation": question.get("motivation", ""),
            "question_kind": question["question_kind"],
            "status": question["status"],
            "priority": question["priority"],
            "expected_evidence": question.get("expected_evidence", []),
            "answer_conclusion_id": question.get("answer_conclusion_id"),
            "status_reason": question.get("status_reason", ""),
        }

    def _record_revision(
        self,
        conn: sqlite3.Connection,
        question: dict[str, Any],
        *,
        actor: str,
    ) -> str:
        snapshot = self._snapshot(question)
        snapshot_hash = hashlib.sha256(
            canonical_json(snapshot).encode("utf-8")
        ).hexdigest()
        conn.execute(
            "INSERT INTO issue_question_revisions("
            "question_id,revision_number,prompt,motivation,question_kind,status,priority,"
            "expected_evidence_json,answer_conclusion_id,status_reason,snapshot_hash,created_at,created_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                question["question_id"],
                question["current_revision"],
                question["prompt"],
                question.get("motivation", ""),
                question["question_kind"],
                question["status"],
                question["priority"],
                canonical_json(question.get("expected_evidence", [])),
                question.get("answer_conclusion_id"),
                question.get("status_reason", ""),
                snapshot_hash,
                now(),
                actor,
            ),
        )
        return snapshot_hash

    def _record_event(
        self,
        conn: sqlite3.Connection,
        question: dict[str, Any],
        *,
        event_type: str,
        from_status: str | None,
        actor: str,
        reason: str,
        payload: dict[str, Any] | None = None,
    ) -> str:
        event_id = new_id("question_event")
        conn.execute(
            "INSERT INTO issue_question_events VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                question["question_id"],
                event_type,
                from_status,
                question["status"],
                question["current_revision"],
                reason,
                canonical_json(payload or {}),
                now(),
                actor,
            ),
        )
        return event_id

    def create(
        self,
        issue_id: str,
        prompt: str,
        *,
        question_id: str | None = None,
        question_key: str | None = None,
        motivation: str = "",
        question_kind: str = "experiment",
        priority: int = 50,
        expected_evidence: List[Any] | None = None,
        source_kind: str | None = None,
        source_id: str | None = None,
        template_registration_id: str | None = None,
        template_content_hash: str | None = None,
        template_snapshot: dict[str, Any] | None = None,
        actor: str = "organizer-agent",
        reason: str = "",
        idempotency_key: str | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        from .changeset_state import StateView
        from .question_planner import plan_create

        decision = plan_create(
            StateView(self.manager),
            {
                "issue_id": issue_id,
                "prompt": prompt,
                "question_id": question_id,
                "question_key": question_key,
                "motivation": motivation,
                "question_kind": question_kind,
                "priority": priority,
                "expected_evidence": [] if expected_evidence is None else expected_evidence,
                "_idempotency_probe": idempotency_key is not None and conn is None,
            },
        )
        issue_id = decision["issue_id"]
        prompt = decision["prompt"]
        question_id = decision["question_id"]
        question_key = decision["question_key"]
        motivation = decision["motivation"]
        question_kind = decision["question_kind"]
        priority = decision["priority"]
        expected = decision["expected_evidence"]
        template_value = {} if template_snapshot is None else template_snapshot
        require_strict_json(template_value, path="$.template_snapshot")
        payload = {
            "issue_id": issue_id,
            "prompt": prompt.strip(),
            "question_key": question_key,
            "motivation": motivation,
            "question_kind": question_kind,
            "priority": priority,
            "expected_evidence": expected,
            "source_kind": source_kind,
            "source_id": source_id,
            "template_registration_id": template_registration_id,
            "template_content_hash": template_content_hash,
        }
        if conn is None:
            replay = self.store.idempotency_lookup(
                "question.create", idempotency_key, payload
            )
            if replay:
                return {**replay, "idempotent_replay": True}
        question_id_value = question_id or new_id("question")
        timestamp = now()
        question = {
            "question_id": question_id_value,
            "issue_id": issue_id,
            "question_key": question_key,
            "prompt": prompt.strip(),
            "motivation": motivation.strip(),
            "question_kind": question_kind,
            "status": "open",
            "priority": priority,
            "expected_evidence": expected,
            "source_kind": source_kind,
            "source_id": source_id,
            "answer_conclusion_id": None,
            "current_revision": 1,
            "template_registration_id": template_registration_id,
            "template_content_hash": template_content_hash,
            "template_snapshot": template_value,
            "status_reason": reason,
            "created_at": timestamp,
            "created_by": actor,
            "updated_at": timestamp,
            "updated_by": actor,
        }
        transaction = self.store.transaction() if conn is None else nullcontext(conn)
        try:
            with transaction as active:
                active.execute(
                    "INSERT INTO issue_questions("
                    "question_id,issue_id,question_key,prompt,motivation,question_kind,status,"
                    "priority,expected_evidence_json,source_kind,source_id,answer_conclusion_id,"
                    "current_revision,template_registration_id,template_content_hash,"
                    "template_snapshot_json,status_reason,created_at,created_by,updated_at,updated_by) "
                    "VALUES (?,?,?,?,?,?,'open',?,?,?,?,NULL,1,?,?,?,?,?,?,?,?)",
                    (
                        question_id_value,
                        issue_id,
                        question_key,
                        question["prompt"],
                        question["motivation"],
                        question_kind,
                        priority,
                        canonical_json(expected),
                        source_kind,
                        source_id,
                        template_registration_id,
                        template_content_hash,
                        canonical_json(template_value),
                        reason,
                        timestamp,
                        actor,
                        timestamp,
                        actor,
                    ),
                )
                snapshot_hash = self._record_revision(active, question, actor=actor)
                event_id = self._record_event(
                    active,
                    question,
                    event_type="create",
                    from_status=None,
                    actor=actor,
                    reason=reason,
                    payload={"snapshot_hash": snapshot_hash},
                )
                audit_id = self.store.audit(
                    active,
                    actor=actor,
                    action="question.create",
                    object_type="issue_question",
                    object_id=question_id_value,
                    before_revision=None,
                    after_revision=1,
                    reason=reason,
                    payload=payload,
                )
                response = {
                    **question,
                    "question_version": "issue-question/v1",
                    "snapshot_hash": snapshot_hash,
                    "event_id": event_id,
                    "audit_event_id": audit_id,
                }
                if conn is None:
                    self.store.idempotency_record(
                        active,
                        "question.create",
                        idempotency_key,
                        payload,
                        response,
                    )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "Question identity or template key already exists",
                details={"question_id": question_id_value, "question_key": question_key},
            ) from exc
        return response

    def instantiate_template(
        self,
        issue_id: str,
        semantic_snapshot: dict[str, Any],
        *,
        actor: str,
        conn: sqlite3.Connection,
    ) -> list[dict[str, Any]]:
        return [self.create(issue_id, **spec, actor=actor, conn=conn)
                for spec in self.template_creation_specs(semantic_snapshot)]

    def template_creation_specs(self, semantic_snapshot: dict[str, Any]) -> list[dict[str, Any]]:
        reference = semantic_snapshot.get("definition", {}).get("question_template")
        if not reference:
            return []
        entry = self.manager.registry.resolve(
            str(reference), kind="question_template", for_creation=False
        )
        specs: list[dict[str, Any]] = []
        for raw in entry["definition"].get("questions", []):
            specs.append(
                dict(
                    prompt=raw["prompt"], question_key=raw["question_key"],
                    motivation=str(raw.get("motivation", "")), question_kind=str(raw.get("question_kind", "experiment")),
                    priority=int(raw.get("priority", 50)), expected_evidence=list(raw.get("expected_evidence", [])),
                    source_kind="question_template", source_id=entry["registration_id"],
                    template_registration_id=entry["registration_id"], template_content_hash=entry["content_hash"],
                    template_snapshot={
                        "api_version": entry["api_version"],
                        "question": raw,
                        "required": bool(raw.get("required", False)),
                    },
                    reason="Created from frozen Question Template",
                )
            )
        return specs

    def show(self, question_id: str) -> dict[str, Any]:
        question = self.questions.require(question_id)
        question["answer_freshness"] = self._answer_freshness(question)
        question["evidence_links"] = self.questions.evidence_links(question_id)
        question["question_version"] = "issue-question/v1"
        return question

    def list(
        self,
        issue_id: str,
        *,
        statuses: tuple[str, ...] = (),
        question_kind: str | None = None,
        minimum_priority: int | None = None,
    ) -> list[dict[str, Any]]:
        self.issues.require(issue_id)
        unknown = set(statuses) - QUESTION_STATUSES
        if unknown:
            raise ValidationError(f"Unknown Question statuses: {sorted(unknown)}")
        if question_kind is not None and question_kind not in QUESTION_KINDS:
            raise ValidationError(f"Unknown Question kind: {question_kind!r}")
        items = self.questions.list_for_issue(
            issue_id,
            statuses=statuses,
            question_kind=question_kind,
            minimum_priority=minimum_priority,
        )
        for item in items:
            item["answer_freshness"] = self._answer_freshness(item)
            item["question_version"] = "issue-question/v1"
        return items

    def _answer_freshness(self, question: dict[str, Any]) -> str:
        conclusion_id = question.get("answer_conclusion_id")
        if not conclusion_id:
            return "unanswered"
        row = self.store.row(
            "SELECT c.status,i.current_conclusion_id,i.freshness FROM conclusion_revisions c "
            "JOIN issues i ON i.issue_id=c.issue_id WHERE c.conclusion_id=?",
            (conclusion_id,),
        )
        if not row:
            return "missing"
        if (
            row["current_conclusion_id"] != conclusion_id
            or row["freshness"] != "fresh"
            or row["status"] in {"disputed", "superseded", "retracted"}
        ):
            return "stale"
        return "fresh"

    def edit(
        self,
        question_id: str,
        *,
        prompt: str | None = None,
        motivation: str | None = None,
        priority: int | None = None,
        expected_evidence: List[Any] | None = None,
        actor: str = "organizer-agent",
        reason: str = "",
    ) -> dict[str, Any]:
        question = self.questions.require(question_id)
        if prompt is not None:
            if not prompt.strip():
                raise ValidationError("Question prompt cannot be empty")
            question["prompt"] = prompt.strip()
        if motivation is not None:
            question["motivation"] = motivation.strip()
        if priority is not None:
            self._validate_priority(priority)
            question["priority"] = priority
        if expected_evidence is not None:
            if not isinstance(expected_evidence, list):
                raise ValidationError("expected_evidence must be an array")
            require_strict_json(expected_evidence, path="$.expected_evidence")
            question["expected_evidence"] = expected_evidence
        question["current_revision"] += 1
        question["updated_at"] = now()
        question["updated_by"] = actor
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE issue_questions SET prompt=?,motivation=?,priority=?,"
                "expected_evidence_json=?,current_revision=?,updated_at=?,updated_by=? "
                "WHERE question_id=?",
                (
                    question["prompt"],
                    question["motivation"],
                    question["priority"],
                    canonical_json(question["expected_evidence"]),
                    question["current_revision"],
                    question["updated_at"],
                    actor,
                    question_id,
                ),
            )
            snapshot_hash = self._record_revision(conn, question, actor=actor)
            event_id = self._record_event(
                conn,
                question,
                event_type="edit",
                from_status=question["status"],
                actor=actor,
                reason=reason,
                payload={"snapshot_hash": snapshot_hash},
            )
            self.store.audit(
                conn,
                actor=actor,
                action="question.edit",
                object_type="issue_question",
                object_id=question_id,
                before_revision=question["current_revision"] - 1,
                after_revision=question["current_revision"],
                reason=reason,
                payload=self._snapshot(question),
            )
        return {**self.show(question_id), "event_id": event_id, "snapshot_hash": snapshot_hash}

    def _transition(
        self,
        question_id: str,
        to_status: str,
        *,
        event_type: str,
        actor: str,
        reason: str,
        answer_conclusion_id: str | None = None,
    ) -> dict[str, Any]:
        if to_status not in QUESTION_STATUSES:
            raise ValidationError(f"Unknown Question status: {to_status!r}")
        question = self.questions.require(question_id)
        from_status = question["status"]
        if to_status == from_status:
            return {**self.show(question_id), "existing": True}
        from .changeset_state import StateView
        from .question_planner import plan_transition

        plan_transition(
            StateView(self.manager),
            {
                "question_id": question_id,
                "action": event_type,
                "target": to_status,
                "reason": reason,
            },
        )
        if to_status == "answered" and not answer_conclusion_id:
            raise ValidationError("Answered Question requires an exact Conclusion revision")
        if to_status != "answered":
            answer_conclusion_id = None
        question["status"] = to_status
        question["answer_conclusion_id"] = answer_conclusion_id
        question["status_reason"] = reason.strip()
        question["current_revision"] += 1
        question["updated_at"] = now()
        question["updated_by"] = actor
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE issue_questions SET status=?,answer_conclusion_id=?,status_reason=?,"
                "current_revision=?,updated_at=?,updated_by=? WHERE question_id=?",
                (
                    to_status,
                    answer_conclusion_id,
                    question["status_reason"],
                    question["current_revision"],
                    question["updated_at"],
                    actor,
                    question_id,
                ),
            )
            snapshot_hash = self._record_revision(conn, question, actor=actor)
            event_id = self._record_event(
                conn,
                question,
                event_type=event_type,
                from_status=from_status,
                actor=actor,
                reason=reason,
                payload={
                    "answer_conclusion_id": answer_conclusion_id,
                    "snapshot_hash": snapshot_hash,
                },
            )
            audit_id = self.store.audit(
                conn,
                actor=actor,
                action=f"question.{event_type}",
                object_type="issue_question",
                object_id=question_id,
                before_revision=question["current_revision"] - 1,
                after_revision=question["current_revision"],
                reason=reason,
                payload={"from_status": from_status, "to_status": to_status},
            )
        return {
            **self.show(question_id),
            "event_id": event_id,
            "audit_event_id": audit_id,
            "snapshot_hash": snapshot_hash,
        }

    def start(self, question_id: str, *, actor: str, reason: str = "") -> dict[str, Any]:
        return self._transition(
            question_id, "in_progress", event_type="start", actor=actor, reason=reason
        )

    def block(self, question_id: str, *, actor: str, reason: str) -> dict[str, Any]:
        return self._transition(
            question_id, "blocked", event_type="block", actor=actor, reason=reason
        )

    def defer(self, question_id: str, *, actor: str, reason: str) -> dict[str, Any]:
        return self._transition(
            question_id, "deferred", event_type="defer", actor=actor, reason=reason
        )

    def cancel(self, question_id: str, *, actor: str, reason: str) -> dict[str, Any]:
        return self._transition(
            question_id, "cancelled", event_type="cancel", actor=actor, reason=reason
        )

    def reopen(self, question_id: str, *, actor: str, reason: str) -> dict[str, Any]:
        if not reason.strip():
            raise ValidationError("Reopening a Question requires a reason")
        return self._transition(
            question_id, "open", event_type="reopen", actor=actor, reason=reason
        )

    def answer(
        self,
        question_id: str,
        conclusion_id: str,
        *,
        actor: str,
        reason: str = "",
    ) -> dict[str, Any]:
        from .changeset_state import StateView
        from .question_planner import plan_answer

        plan_answer(
            StateView(self.manager),
            {"question_id": question_id, "conclusion_id": conclusion_id, "_direct": True},
        )
        return self._transition(
            question_id,
            "answered",
            event_type="answer",
            actor=actor,
            reason=reason,
            answer_conclusion_id=conclusion_id,
        )

    def attach_evidence(
        self,
        question_id: str,
        evidence_id: str,
        *,
        link_type: str = "addresses",
        rationale: str = "",
        actor: str = "organizer-agent",
        conn: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        if link_type not in QUESTION_LINK_TYPES:
            raise ValidationError(f"Unknown Question Evidence link type: {link_type!r}")
        question = self.questions.require(question_id, conn=conn)
        evidence = (
            conn.execute(
                "SELECT evidence_id FROM evidence_refs WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
            if conn is not None
            else self.store.row(
                "SELECT evidence_id FROM evidence_refs WHERE evidence_id=?", (evidence_id,)
            )
        )
        if not evidence:
            raise NotFoundError(f"Evidence not found: {evidence_id}")
        transaction = self.store.transaction() if conn is None else nullcontext(conn)
        with transaction as active:
            versioned = hasattr(self.manager, "context_maintenance")
            relation_id = new_id("question_relation") if versioned else None
            existing = None if versioned else active.execute(
                "SELECT active FROM issue_question_evidence_links "
                "WHERE question_id=? AND evidence_id=? AND link_type=?",
                (question_id, evidence_id, link_type),
            ).fetchone()
            if existing:
                if not existing["active"]:
                    active.execute(
                        "UPDATE issue_question_evidence_links SET active=1,rationale=? "
                        "WHERE question_id=? AND evidence_id=? AND link_type=?",
                        (rationale, question_id, evidence_id, link_type),
                    )
            else:
                columns = "question_id,evidence_id,link_type,rationale,active,created_at,created_by"
                values: tuple[Any, ...] = (question_id, evidence_id, link_type, rationale, 1, now(), actor)
                if versioned:
                    columns = "relation_id," + columns
                    values = (relation_id, *values)
                active.execute(
                    f"INSERT INTO issue_question_evidence_links ({columns}) "
                    f"VALUES ({','.join('?' for _ in values)})", values
                )
            link_payload = {"evidence_id": evidence_id, "link_type": link_type}
            if relation_id is not None:
                link_payload["relation_id"] = relation_id
            event_id = self._record_event(
                active,
                question,
                event_type="attach_evidence",
                from_status=question["status"],
                actor=actor,
                reason=rationale,
                payload=link_payload,
            )
            self.store.audit(
                active,
                actor=actor,
                action="question.attach_evidence",
                object_type="issue_question",
                object_id=question_id,
                before_revision=question["current_revision"],
                after_revision=question["current_revision"],
                reason=rationale,
                payload=link_payload,
            )
        return {
            "question_id": question_id,
            "evidence_id": evidence_id,
            "link_type": link_type,
            "event_id": event_id,
            "existing": bool(existing),
            "relation_id": relation_id,
        }
