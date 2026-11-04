from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from typing import Any, ClassVar, Iterator

from .errors import NotFoundError
from .store import Store


def _json_row(
    row: sqlite3.Row | dict[str, Any], conversions: dict[str, tuple[str, Any]]
) -> dict[str, Any]:
    result = dict(row)
    for source, (target, fallback) in conversions.items():
        if source in result:
            value = result.pop(source)
            result[target] = json.loads(value) if value is not None else fallback
    if "active" in result:
        result["active"] = bool(result["active"])
    return result


class UnitOfWork:
    """One explicit top-level transaction shared by application services."""

    def __init__(self, store: Store):
        self.store = store

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.store.transaction() as conn:
            yield conn


class IssueRepository:
    def __init__(self, store: Store):
        self.store = store

    def get(
        self, issue_id: str, *, conn: sqlite3.Connection | None = None
    ) -> dict[str, Any] | None:
        row = (
            conn.execute("SELECT * FROM issues WHERE issue_id=?", (issue_id,)).fetchone()
            if conn is not None
            else self.store.row("SELECT * FROM issues WHERE issue_id=?", (issue_id,))
        )
        if not row:
            return None
        return _json_row(
            row,
            {
                "scope_json": ("scope", {}),
                "issue_type_snapshot_json": ("issue_type_snapshot", {}),
                "issue_type_semantic_snapshot_json": ("issue_type_semantic_snapshot", {}),
            },
        )

    def require(
        self, issue_id: str, *, conn: sqlite3.Connection | None = None
    ) -> dict[str, Any]:
        issue = self.get(issue_id, conn=conn)
        if not issue:
            raise NotFoundError(f"Issue not found: {issue_id}")
        return issue

    def list_active_providers(
        self, issue_id: str, *, conn: sqlite3.Connection | None = None
    ) -> list[dict[str, Any]]:
        sql = (
            "SELECT r.*,p.current_conclusion_id,p.conclusion_revision,p.conclusion_status,"
            "p.freshness,p.normalized_scope_key FROM relations r "
            "JOIN issues p ON p.issue_id=r.provider_issue_id "
            "WHERE r.consumer_issue_id=? AND r.active=1 "
            "ORDER BY r.provider_issue_id,r.relation_type"
        )
        rows = (
            conn.execute(sql, (issue_id,)).fetchall()
            if conn is not None
            else self.store.rows(sql, (issue_id,))
        )
        return [_json_row(row, {}) for row in rows]


class RelationRepository:
    def __init__(self, store: Store):
        self.store = store

    def list_for_issue(self, issue_id: str) -> list[dict[str, Any]]:
        return [
            _json_row(row, {})
            for row in self.store.rows(
                "SELECT * FROM relations WHERE consumer_issue_id=? OR provider_issue_id=? "
                "ORDER BY consumer_issue_id,provider_issue_id,relation_type",
                (issue_id, issue_id),
            )
        ]


class ConclusionRepository:
    def __init__(self, store: Store):
        self.store = store

    def get(self, conclusion_id: str) -> dict[str, Any] | None:
        row = self.store.row(
            "SELECT * FROM conclusion_revisions WHERE conclusion_id=?", (conclusion_id,)
        )
        if not row:
            return None
        return _json_row(
            row,
            {
                "structured_outputs_json": ("structured_outputs", {}),
                "limitations_json": ("limitations", []),
                "evidence_refs_json": ("evidence_refs", []),
                "issue_type_semantic_snapshot_json": ("issue_type_semantic_snapshot", {}),
            },
        )

    def current_for_issue(self, issue_id: str) -> dict[str, Any] | None:
        row = self.store.row(
            "SELECT c.* FROM issues i JOIN conclusion_revisions c "
            "ON c.conclusion_id=i.current_conclusion_id WHERE i.issue_id=?",
            (issue_id,),
        )
        return (
            _json_row(
                row,
                {
                    "structured_outputs_json": ("structured_outputs", {}),
                    "limitations_json": ("limitations", []),
                    "evidence_refs_json": ("evidence_refs", []),
                },
            )
            if row
            else None
        )


class QuestionRepository:
    _CONVERSIONS: ClassVar[dict[str, tuple[str, Any]]] = {
        "expected_evidence_json": ("expected_evidence", []),
        "template_snapshot_json": ("template_snapshot", {}),
    }

    def __init__(self, store: Store):
        self.store = store

    def get(
        self, question_id: str, *, conn: sqlite3.Connection | None = None
    ) -> dict[str, Any] | None:
        row = (
            conn.execute(
                "SELECT * FROM issue_questions WHERE question_id=?", (question_id,)
            ).fetchone()
            if conn is not None
            else self.store.row(
                "SELECT * FROM issue_questions WHERE question_id=?", (question_id,)
            )
        )
        return _json_row(row, self._CONVERSIONS) if row else None

    def require(
        self, question_id: str, *, conn: sqlite3.Connection | None = None
    ) -> dict[str, Any]:
        question = self.get(question_id, conn=conn)
        if not question:
            raise NotFoundError(f"Question not found: {question_id}")
        return question

    def list_for_issue(
        self,
        issue_id: str,
        *,
        statuses: tuple[str, ...] = (),
        question_kind: str | None = None,
        minimum_priority: int | None = None,
    ) -> list[dict[str, Any]]:
        clauses = ["issue_id=?"]
        params: list[Any] = [issue_id]
        if statuses:
            clauses.append("status IN (" + ",".join("?" for _ in statuses) + ")")
            params.extend(statuses)
        if question_kind:
            clauses.append("question_kind=?")
            params.append(question_kind)
        if minimum_priority is not None:
            clauses.append("priority>=?")
            params.append(minimum_priority)
        rows = self.store.rows(
            "SELECT * FROM issue_questions WHERE "
            + " AND ".join(clauses)
            + " ORDER BY priority DESC,created_at,question_id",
            tuple(params),
        )
        return [_json_row(row, self._CONVERSIONS) for row in rows]

    def evidence_links(self, question_id: str) -> list[dict[str, Any]]:
        return [
            _json_row(row, {})
            for row in self.store.rows(
                "SELECT * FROM issue_question_evidence_links WHERE question_id=? "
                "AND active=1 ORDER BY created_at,evidence_id,link_type",
                (question_id,),
            )
        ]


class EvidenceRelationRepository:
    def __init__(self, store: Store):
        self.store = store

    def get(
        self, relation_id: str, *, conn: sqlite3.Connection | None = None
    ) -> dict[str, Any] | None:
        row = (
            conn.execute(
                "SELECT * FROM evidence_relations WHERE relation_id=?", (relation_id,)
            ).fetchone()
            if conn is not None
            else self.store.row(
                "SELECT * FROM evidence_relations WHERE relation_id=?", (relation_id,)
            )
        )
        return _json_row(row, {}) if row else None

    def require(
        self, relation_id: str, *, conn: sqlite3.Connection | None = None
    ) -> dict[str, Any]:
        relation = self.get(relation_id, conn=conn)
        if not relation:
            raise NotFoundError(f"Evidence relation not found: {relation_id}")
        return relation

    def list(
        self,
        *,
        evidence_id: str | None = None,
        provider_evidence_id: str | None = None,
        consumer_evidence_id: str | None = None,
        active_only: bool = True,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if evidence_id:
            clauses.append("(provider_evidence_id=? OR consumer_evidence_id=?)")
            params.extend([evidence_id, evidence_id])
        if provider_evidence_id:
            clauses.append("provider_evidence_id=?")
            params.append(provider_evidence_id)
        if consumer_evidence_id:
            clauses.append("consumer_evidence_id=?")
            params.append(consumer_evidence_id)
        if active_only:
            clauses.append("active=1")
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        return [
            _json_row(row, {})
            for row in self.store.rows(
                "SELECT * FROM evidence_relations"
                + where
                + " ORDER BY created_at,relation_id",
                tuple(params),
            )
        ]


class ContextQueries:
    def __init__(self, store: Store):
        self.store = store

    def legacy_candidates(self, issue_id: str) -> list[dict[str, Any]]:
        return [
            _json_row(row, {"candidate_json": ("candidate", {})})
            for row in self.store.rows(
                "SELECT * FROM legacy_v14_candidates WHERE issue_id=? "
                "AND state='pending_review' ORDER BY candidate_kind,created_at",
                (issue_id,),
            )
        ]

    def relation_impacts(self, issue_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        return [
            _json_row(row, {"details_json": ("details", {})})
            for row in self.store.rows(
                "SELECT * FROM evidence_relation_impacts WHERE affected_issue_id=? "
                "ORDER BY created_at DESC LIMIT ?",
                (issue_id, limit),
            )
        ]
