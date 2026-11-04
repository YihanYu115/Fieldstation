from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import defaultdict, deque
from contextlib import nullcontext
from typing import TYPE_CHECKING, Any, List

from .changeset_state import StateView
from .errors import ConflictError, CycleError, NotFoundError, ValidationError
from .evidence_relation_impact import plan_change
from .policy import (
    EVIDENCE_IMPACT_POLICIES,
    EVIDENCE_RELATION_TYPES,
)
from .repositories import EvidenceRelationRepository
from .store import canonical_json, new_id, now

if TYPE_CHECKING:
    from .service import IssueManager


RELATION_TYPES = EVIDENCE_RELATION_TYPES
IMPACT_POLICIES = EVIDENCE_IMPACT_POLICIES


class EvidenceRelationService:
    """Owns Evidence lineage, hard-cycle safety, and deterministic impacts."""

    def __init__(self, manager: IssueManager):
        self.manager = manager
        self.store = manager.store
        self.repository = EvidenceRelationRepository(self.store)

    def _evidence(
        self, evidence_id: str, *, conn: sqlite3.Connection | None = None
    ) -> dict[str, Any]:
        row = (
            conn.execute(
                "SELECT * FROM evidence_refs WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
            if conn is not None
            else self.store.row("SELECT * FROM evidence_refs WHERE evidence_id=?", (evidence_id,))
        )
        if not row:
            raise NotFoundError(f"Evidence not found: {evidence_id}")
        return dict(row)

    @staticmethod
    def _snapshot_hash(evidence: dict[str, Any]) -> str:
        snapshot = {
            "evidence_id": evidence["evidence_id"],
            "identity_key": evidence.get("identity_key"),
            "lifecycle_status": evidence.get("lifecycle_status"),
            "quality_status": evidence.get("quality_status"),
            "semantic_revision": evidence.get("semantic_revision"),
            "current_proof_id": evidence.get("current_proof_id"),
            "content_hash": evidence.get("content_hash"),
        }
        return hashlib.sha256(canonical_json(snapshot).encode("utf-8")).hexdigest()

    def _hard_edges(
        self,
        *,
        conn: sqlite3.Connection | None = None,
        include: tuple[str, str] | None = None,
    ) -> dict[str, list[str]]:
        sql = (
            "SELECT consumer_evidence_id,provider_evidence_id FROM evidence_relations "
            "WHERE active=1 AND impact_policy='hard'"
        )
        rows = conn.execute(sql).fetchall() if conn is not None else self.store.rows(sql)
        graph: dict[str, list[str]] = defaultdict(list)
        for row in rows:
            graph[row["consumer_evidence_id"]].append(row["provider_evidence_id"])
        if include:
            graph[include[0]].append(include[1])
        return graph

    @staticmethod
    def _path(
        graph: dict[str, list[str]], start: str, target: str, *, maximum: int = 500
    ) -> list[str] | None:
        queue: deque[tuple[str, list[str]]] = deque([(start, [start])])
        seen: set[str] = set()
        while queue and len(seen) < maximum:
            current, path = queue.popleft()
            if current == target:
                return path
            if current in seen:
                continue
            seen.add(current)
            for following in sorted(graph.get(current, [])):
                if following not in path:
                    queue.append((following, [*path, following]))
        return None

    def _validate_cycle(
        self,
        consumer: str,
        provider: str,
        *,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        graph = self._hard_edges(conn=conn, include=(consumer, provider))
        path = self._path(graph, provider, consumer)
        if path:
            stable_path = [consumer, *path]
            raise CycleError(
                "Hard Evidence relation would create a cycle: " + " -> ".join(stable_path),
                stable_path,
            )

    def _risk(
        self,
        consumer_evidence_id: str,
        provider_evidence_id: str,
        impact_policy: str,
        *,
        state_view: StateView | None = None,
    ) -> dict[str, Any]:
        view = state_view or StateView(self.manager)
        left_keys = view.evidence_samples(consumer_evidence_id)
        right_keys = view.evidence_samples(provider_evidence_id)
        left_statuses = view.evidence_publication_statuses(consumer_evidence_id)
        right_statuses = view.evidence_publication_statuses(provider_evidence_id)
        published = bool(left_statuses or right_statuses)
        canonical = "canonical" in left_statuses or "canonical" in right_statuses
        # Conservative any-pair semantics: when either endpoint is attached to
        # multiple samples, one differing consumer/provider pair is enough to
        # make the relation cross-sample. Target, phase, and pilot-run fields do
        # not participate in this decision.
        cross_sample = bool(left_keys and right_keys and len(left_keys | right_keys) > 1)
        tier = "T1"
        reasons: list[str] = []
        if impact_policy == "hard":
            tier = "T2"
            reasons.append("hard Evidence dependency")
        if published:
            tier = "T2"
            reasons.append("Evidence is used by a published Conclusion")
        if cross_sample or canonical:
            tier = "T3"
            reasons.append("cross-sample or canonical impact")
        return {
            "tier": tier,
            "required_reviews": 2 if tier == "T3" else (1 if tier == "T2" else 0),
            "cross_sample": cross_sample,
            "cross_sample_semantics": "any_endpoint_sample_pair_differs",
            "consumer_samples": sorted(sample.value for sample in left_keys),
            "provider_samples": sorted(sample.value for sample in right_keys),
            "published_impact": published,
            "reasons": reasons,
        }

    def resolve_impact(
        self, relation_type: str, impact_policy: str | None = None
    ) -> dict[str, str]:
        """Resolve one Evidence relation impact against the current Policy."""

        if relation_type not in RELATION_TYPES:
            raise ValidationError(f"Unknown Evidence relation type: {relation_type!r}")
        return self.manager.policy.resolve_evidence_relation_impact(
            relation_type, impact_policy
        )

    def assess_add(
        self,
        consumer_evidence_id: str,
        provider_evidence_id: str,
        relation_type: str,
        *,
        impact_policy: str | None = None,
        state_view: StateView | None = None,
    ) -> dict[str, Any]:
        if consumer_evidence_id == provider_evidence_id:
            raise ValidationError("Evidence relation endpoints must be different")
        resolved = self.resolve_impact(relation_type, impact_policy)
        effective = resolved["effective"]
        lookup = state_view.evidence if state_view is not None else self._evidence
        lookup(consumer_evidence_id)
        lookup(provider_evidence_id)
        return self._risk(
            consumer_evidence_id,
            provider_evidence_id,
            effective,
            state_view=state_view,
        )

    def validate_add(
        self,
        consumer_evidence_id: str,
        provider_evidence_id: str,
        relation_type: str,
        *,
        impact_policy: str | None = None,
        state_view: StateView | None = None,
    ) -> dict[str, str]:
        """Validate relation semantics without classifying governance risk."""

        if consumer_evidence_id == provider_evidence_id:
            raise ValidationError("Evidence relation endpoints must be different")
        resolved = self.resolve_impact(relation_type, impact_policy)
        lookup = state_view.evidence if state_view is not None else self._evidence
        lookup(consumer_evidence_id)
        lookup(provider_evidence_id)
        if resolved["effective"] == "hard" and state_view is None:
            self._validate_cycle(consumer_evidence_id, provider_evidence_id)
        return resolved

    def validate_change(
        self,
        relation_id: str,
        *,
        target_active: bool | None = None,
        state_view: StateView | None = None,
    ) -> dict[str, Any]:
        """Validate lifecycle/cycle invariants without governance assessment."""

        relation = (
            state_view.evidence_relation(relation_id)
            if state_view is not None
            else self.repository.require(relation_id)
        )
        if relation is None:
            raise NotFoundError(f"Evidence relation not found: {relation_id}")
        if target_active and not bool(relation["active"]) and relation["impact_policy"] == "hard":
            self._validate_cycle(
                str(relation["consumer_evidence_id"]),
                str(relation["provider_evidence_id"]),
                conn=None,
            )
        return dict(relation)

    def add(
        self,
        consumer_evidence_id: str,
        provider_evidence_id: str,
        relation_type: str,
        *,
        impact_policy: str | None = None,
        rationale: str = "",
        actor: str = "organizer-agent",
        run_id: str | None = None,
        request_id: str | None = None,
        template_registration_id: str | None = None,
        template_content_hash: str | None = None,
        idempotency_key: str | None = None,
        conn: sqlite3.Connection | None = None,
        _allocated_relation_id: str | None = None,
    ) -> dict[str, Any]:
        if consumer_evidence_id == provider_evidence_id:
            raise ValidationError("Evidence relation endpoints must be different")
        resolved = self.resolve_impact(relation_type, impact_policy)
        requested = resolved["requested"]
        effective = resolved["effective"]
        consumer = self._evidence(consumer_evidence_id, conn=conn)
        provider = self._evidence(provider_evidence_id, conn=conn)
        if effective == "hard":
            self._validate_cycle(consumer_evidence_id, provider_evidence_id, conn=conn)
        relation_id = _allocated_relation_id or new_id("evidence_relation")
        timestamp = now()
        transaction = self.store.transaction() if conn is None else nullcontext(conn)
        try:
            with transaction as active:
                request_payload = {
                    "consumer_evidence_id": consumer_evidence_id,
                    "provider_evidence_id": provider_evidence_id,
                    "relation_type": relation_type, "impact_policy": requested,
                    "rationale": rationale, "template_registration_id": template_registration_id,
                    "template_content_hash": template_content_hash,
                }
                replay = self.store.idempotency_lookup("evidence_relation.add", idempotency_key, request_payload)
                if replay:
                    return {**replay, "idempotent_replay": True}
                existing = active.execute(
                    "SELECT * FROM evidence_relations WHERE consumer_evidence_id=? "
                    "AND provider_evidence_id=? AND relation_type=?",
                    (consumer_evidence_id, provider_evidence_id, relation_type),
                ).fetchone()
                if existing and not hasattr(self.manager, "context_maintenance"):
                    result = dict(existing)
                    result["active"] = bool(result["active"])
                    if not result["active"]:
                        raise ConflictError(
                            "Evidence relation exists but is inactive; reactivate it explicitly",
                            details={"relation_id": result["relation_id"]},
                        )
                    if result["impact_policy"] != effective:
                        raise ConflictError(
                            "Evidence relation already exists with a different impact policy",
                            details={"relation_id": result["relation_id"]},
                        )
                    return {**result, "existing": True}
                active.execute(
                    "INSERT INTO evidence_relations("
                    "relation_id,consumer_evidence_id,provider_evidence_id,relation_type,"
                    "impact_policy,rationale,active,provider_snapshot_hash,consumer_snapshot_hash,"
                    "template_registration_id,template_content_hash,actor_id,run_id,request_id,"
                    "created_at,updated_at) VALUES (?,?,?,?,?,?,1,?,?,?,?,?,?,?,?,?)",
                    (
                        relation_id,
                        consumer_evidence_id,
                        provider_evidence_id,
                        relation_type,
                        effective,
                        rationale,
                        self._snapshot_hash(provider),
                        self._snapshot_hash(consumer),
                        template_registration_id,
                        template_content_hash,
                        actor,
                        run_id,
                        request_id,
                        timestamp,
                        timestamp,
                    ),
                )
                event_id = new_id("evidence_relation_event")
                after = {
                    "relation_id": relation_id,
                    "consumer_evidence_id": consumer_evidence_id,
                    "provider_evidence_id": provider_evidence_id,
                    "relation_type": relation_type,
                    "impact_policy": effective,
                    "active": True,
                }
                active.execute(
                    "INSERT INTO evidence_relation_events VALUES (?,?,?,'{}',?,?,?,?)",
                    (
                        event_id,
                        relation_id,
                        "create",
                        canonical_json(after),
                        rationale,
                        timestamp,
                        actor,
                    ),
                )
                impacts = self.propagate_change(
                    provider_evidence_id,
                    source_event_type="evidence_relation_lifecycle",
                    source_event_id=event_id,
                    conn=active,
                    delta_relation=after,
                )
                audit_id = self.store.audit(
                    active,
                    actor=actor,
                    action="evidence_relation.create",
                    object_type="evidence_relation",
                    object_id=relation_id,
                    before_revision=None,
                    after_revision=1,
                    reason=rationale,
                    payload={**after, "impacts": impacts},
                )
                result = {
                    **after,
                    "event_id": event_id,
                    "audit_event_id": audit_id,
                    "impacts": impacts,
                }
                self.store.idempotency_record(
                    active, "evidence_relation.add", idempotency_key, request_payload, result
                )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("Evidence relation conflicts with persisted lineage") from exc
        return result

    def list(
        self,
        *,
        evidence_id: str | None = None,
        provider_evidence_id: str | None = None,
        consumer_evidence_id: str | None = None,
        active_only: bool = True,
    ) -> List[dict[str, Any]]:
        return self.repository.list(
            evidence_id=evidence_id,
            provider_evidence_id=provider_evidence_id,
            consumer_evidence_id=consumer_evidence_id,
            active_only=active_only,
        )

    def _change_active(
        self,
        relation_id: str,
        active_value: bool,
        *,
        actor: str,
        reason: str,
    ) -> dict[str, Any]:
        if not reason.strip():
            raise ValidationError("Evidence relation lifecycle change requires a reason")
        relation = self.repository.require(relation_id)
        if bool(relation["active"]) == active_value:
            return {**relation, "existing": True}
        if active_value and relation["impact_policy"] == "hard":
            self._validate_cycle(relation["consumer_evidence_id"], relation["provider_evidence_id"])
        timestamp = now()
        before = dict(relation)
        after = {**relation, "active": active_value, "updated_at": timestamp}
        event_type = "reactivate" if active_value else "deactivate"
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE evidence_relations SET active=?,updated_at=? WHERE relation_id=?",
                (int(active_value), timestamp, relation_id),
            )
            event_id = new_id("evidence_relation_event")
            conn.execute(
                "INSERT INTO evidence_relation_events VALUES (?,?,?,?,?,?,?,?)",
                (
                    event_id,
                    relation_id,
                    event_type,
                    canonical_json(before),
                    canonical_json(after),
                    reason,
                    timestamp,
                    actor,
                ),
            )
            impacts = self.propagate_change(
                relation["provider_evidence_id"],
                source_event_type="evidence_relation_lifecycle",
                source_event_id=event_id,
                conn=conn,
                delta_relation=(after if active_value else before),
            )
            audit_id = self.store.audit(
                conn,
                actor=actor,
                action=f"evidence_relation.{event_type}",
                object_type="evidence_relation",
                object_id=relation_id,
                before_revision=1,
                after_revision=1,
                reason=reason,
                payload={"before": before, "after": after, "impacts": impacts},
            )
        return {
            **after,
            "event_id": event_id,
            "audit_event_id": audit_id,
            "impacts": impacts,
        }

    def deactivate(self, relation_id: str, *, actor: str, reason: str) -> dict[str, Any]:
        return self._change_active(relation_id, False, actor=actor, reason=reason)

    def reactivate(self, relation_id: str, *, actor: str, reason: str) -> dict[str, Any]:
        return self._change_active(relation_id, True, actor=actor, reason=reason)

    def _enqueue_refresh(
        self,
        conn: sqlite3.Connection,
        *,
        issue_id: str,
        trigger_issue_id: str | None,
        hard: bool,
    ) -> str:
        existing = conn.execute(
            "SELECT refresh_task_id,state FROM refresh_tasks WHERE issue_id=? AND state IN "
            "('pending','blocked','ready','proposed','awaiting_approval')",
            (issue_id,),
        ).fetchone()
        timestamp = now()
        if existing:
            task_id = str(existing["refresh_task_id"])
            existing_state = str(existing["state"])
            merged_state = "blocked" if hard or existing_state == "blocked" else "pending"
            conn.execute(
                "UPDATE refresh_tasks SET reason_type='dependency_changed',trigger_issue_id=?,"
                "priority=MAX(priority,?),state=?,coalesced_events=coalesced_events+1,"
                "updated_at=? WHERE refresh_task_id=?",
                (
                    trigger_issue_id,
                    80 if hard else 60,
                    merged_state,
                    timestamp,
                    task_id,
                ),
            )
        else:
            task_id = new_id("refresh")
            conn.execute(
                "INSERT INTO refresh_tasks("
                "refresh_task_id,issue_id,reason_type,trigger_issue_id,from_revision,to_revision,"
                "priority,state,coalesced_events,created_at,updated_at) "
                "VALUES (?,?,'dependency_changed',?,0,0,?,?,1,?,?)",
                (
                    task_id,
                    issue_id,
                    trigger_issue_id,
                    80 if hard else 60,
                    "blocked" if hard else "pending",
                    timestamp,
                    timestamp,
                ),
            )
        conn.execute(
            "INSERT INTO refresh_task_events VALUES (?,?,?,0,0,'dependency_changed',?)",
            (new_id("rte"), task_id, trigger_issue_id, timestamp),
        )
        return task_id

    def propagate_change(
        self,
        provider_evidence_id: str,
        *,
        source_event_type: str,
        source_event_id: str | None = None,
        conn: sqlite3.Connection | None = None,
        delta_relation: dict[str, Any] | None = None,
        maximum_nodes: int = 200,
    ) -> List[dict[str, Any]]:
        self._evidence(provider_evidence_id, conn=conn)
        transaction = self.store.transaction() if conn is None else nullcontext(conn)
        impacts: list[dict[str, Any]] = []
        with transaction as active:
            relation_rows = [
                dict(row)
                for row in active.execute(
                    "SELECT * FROM evidence_relations WHERE active=1 "
                    "AND impact_policy IN ('hard','soft') ORDER BY relation_id"
                ).fetchall()
            ]
            consumer_ids = sorted(
                {str(row["consumer_evidence_id"]) for row in relation_rows}
            )
            if delta_relation is not None:
                consumer_ids = sorted(
                    {*consumer_ids, str(delta_relation["consumer_evidence_id"])}
                )
            affected_targets: dict[str, list[dict[str, Any]]] = {}
            for consumer_id in consumer_ids:
                affected_targets[consumer_id] = [
                    {
                        "issue_id": row["issue_id"],
                        "conclusion_id": row["current_conclusion_id"],
                    }
                    for row in active.execute(
                        "SELECT DISTINCT i.issue_id,i.current_conclusion_id FROM issues i "
                        "LEFT JOIN issue_evidence ie ON ie.issue_id=i.issue_id "
                        "LEFT JOIN conclusion_evidence_uses u "
                        "ON u.conclusion_id=i.current_conclusion_id "
                        "WHERE ie.evidence_id=? OR u.evidence_id=? ORDER BY i.issue_id",
                        (consumer_id, consumer_id),
                    ).fetchall()
                ]
            provider_ids = {
                str(row["provider_evidence_id"]) for row in relation_rows
            }
            provider_ids.add(provider_evidence_id)
            provider_issue_ids = {
                evidence_id: (
                    str(row["issue_id"]) if row else None
                )
                for evidence_id in provider_ids
                for row in [
                    active.execute(
                        "SELECT issue_id FROM issue_evidence WHERE evidence_id=? "
                        "ORDER BY issue_id LIMIT 1",
                        (evidence_id,),
                    ).fetchone()
                ]
            }
            try:
                planned = plan_change(
                    provider_evidence_id,
                    relations=relation_rows,
                    affected_targets=affected_targets,
                    provider_issue_ids=provider_issue_ids,
                    source_event_type=source_event_type,
                    source_event_id=source_event_id,
                    delta_relation=delta_relation,
                    maximum_nodes=maximum_nodes,
                )
            except ValueError as exc:
                raise ValidationError(str(exc)) from exc
            for fact in planned:
                issue_id = fact["affected_issue_id"]
                hard = fact["impact_policy"] == "hard"
                key_payload = {
                    "source_event_type": fact["source_event_type"],
                    "source_event_id": fact["source_event_id"],
                    "relation_id": fact["relation_id"],
                    "provider_evidence_id": fact["provider_evidence_id"],
                    "consumer_evidence_id": fact["consumer_evidence_id"],
                    "affected_issue_id": issue_id,
                    "affected_conclusion_id": fact["affected_conclusion_id"],
                }
                impact_key = hashlib.sha256(
                    canonical_json(key_payload).encode("utf-8")
                ).hexdigest()
                impact_id = f"evidence_impact_{impact_key[:32]}"
                existing_impact = active.execute(
                    "SELECT impact_policy,refresh_task_id,disposition FROM evidence_relation_impacts "
                    "WHERE impact_id=?",
                    (impact_id,),
                ).fetchone()
                if existing_impact:
                    impacts.append(
                        {
                            **key_payload,
                            "impact_id": impact_id,
                            "impact_policy": existing_impact["impact_policy"],
                            "refresh_task_id": existing_impact["refresh_task_id"],
                            "disposition": existing_impact["disposition"],
                        }
                    )
                    continue
                task_id = None
                disposition = "recorded"
                if issue_id:
                    task_id = self._enqueue_refresh(
                        active,
                        issue_id=str(issue_id),
                        trigger_issue_id=fact["trigger_issue_id"],
                        hard=hard,
                    )
                    if not hasattr(self.manager, "context_maintenance"):
                        current = active.execute(
                            "SELECT freshness FROM issues WHERE issue_id=?",
                            (issue_id,),
                        ).fetchone()
                        current_freshness = str(current["freshness"]) if current else "fresh"
                        requested_freshness = "stale" if hard else "impact_review"
                        if current_freshness in {"stale", "blocked"}:
                            requested_freshness = current_freshness
                        active.execute(
                            "UPDATE issues SET freshness=?,updated_at=? WHERE issue_id=?",
                            (requested_freshness, now(), issue_id),
                        )
                    disposition = "refresh_enqueued"
                active.execute(
                    "INSERT OR IGNORE INTO evidence_relation_impacts("
                    "impact_id,source_event_type,source_event_id,relation_id,"
                    "provider_evidence_id,consumer_evidence_id,affected_issue_id,"
                    "affected_conclusion_id,refresh_task_id,impact_policy,disposition,"
                    "details_json,impact_key,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        impact_id,
                        fact["source_event_type"],
                        fact["source_event_id"],
                        fact["relation_id"],
                        fact["provider_evidence_id"],
                        fact["consumer_evidence_id"],
                        issue_id,
                        fact["affected_conclusion_id"],
                        task_id,
                        fact["impact_policy"],
                        disposition,
                        canonical_json(
                            {
                                "relation_type": fact["relation_type"],
                                "rationale": fact["rationale"],
                            }
                        ),
                        impact_key,
                        now(),
                    ),
                )
                impacts.append(
                    {
                        **key_payload,
                        "impact_id": impact_id,
                        "impact_policy": fact["impact_policy"],
                        "refresh_task_id": task_id,
                        "disposition": disposition,
                    }
                )
        return impacts

    def impacts(
        self,
        *,
        evidence_id: str | None = None,
        relation_id: str | None = None,
        limit: int = 200,
    ) -> List[dict[str, Any]]:
        if limit < 1 or limit > 1000:
            raise ValidationError("Evidence impact limit must be between 1 and 1000")
        clauses: list[str] = []
        params: list[Any] = []
        if evidence_id:
            clauses.append("(provider_evidence_id=? OR consumer_evidence_id=?)")
            params.extend([evidence_id, evidence_id])
        if relation_id:
            clauses.append("relation_id=?")
            params.append(relation_id)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(limit)
        rows = self.store.rows(
            "SELECT * FROM evidence_relation_impacts" + where + " ORDER BY created_at DESC LIMIT ?",
            tuple(params),
        )
        for row in rows:
            row["details"] = json.loads(row.pop("details_json"))
        return rows
