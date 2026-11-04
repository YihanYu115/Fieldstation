from __future__ import annotations

import hashlib
from typing import Any

from .changeset_engine import ExecutionContext
from .errors import ConflictError, ValidationError
from .store import canonical_json, new_id, now


class ChangeSetExecutionMixin:
    """Operation executors addressed by the shared operation registry."""

    manager: Any
    store: Any

    def _execute_context_obligation(self, operation: dict[str, Any], *, context: ExecutionContext) -> dict[str, Any]:
        return self.manager.context_obligations.execute(operation, actor=context.auth.actor_id,
                                                       changeset_id=context.changeset_id, reviews=context.reviews)

    def _execute_context_rule_upgrade(self, operation: dict[str, Any], *, context: ExecutionContext) -> dict[str, Any]:
        return self.manager.context_rules.activate(operation, actor=context.auth.actor_id)

    def _execute_context_relation(self, operation: dict[str, Any], *, context: ExecutionContext) -> dict[str, Any]:
        return self.manager.context_relations.execute(operation, actor=context.auth.actor_id)

    def _execute_evidence_applicability_decision(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.evidence_applicability.changeset_planner.execute(
            operation, context=context
        )

    def _execute_question_relation(self, operation: dict[str, Any], *, context: ExecutionContext) -> dict[str, Any]:
        return self.manager.question_relations.execute(operation, actor=context.auth.actor_id)

    def _execute_intake_relation(self, operation: dict[str, Any], *, context: ExecutionContext) -> dict[str, Any]:
        return self.manager.intake_relations.execute(operation, actor=context.auth.actor_id)

    def _execute_record_relation(self, operation: dict[str, Any], *, context: ExecutionContext) -> dict[str, Any]:
        return self.manager.record_relations.execute(operation, actor=context.auth.actor_id)

    def _execute_replace_relation(self, operation: dict[str, Any], *, context: ExecutionContext) -> dict[str, Any]:
        if operation["domain"] == "evidence":
            context.auth.require("evidence.relation.write")
        return self.manager.relation_versions.replace(operation, actor=context.auth.actor_id)

    def _execute_context_change(self, operation: dict[str, Any], *, context: ExecutionContext) -> dict[str, Any]:
        return self.manager.context_maintenance.execute_change(
            operation, actor=context.auth.actor_id,
            identity={"run_id": context.auth.run_id, "changeset_id": context.changeset_id},
        )

    def _execute_create_issue(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.create_issue(
            operation["issue_id"],
            operation["issue_type"],
            operation.get("title"),
            parent_issue_id=operation.get("parent_issue_id"),
            scope=operation.get("scope"),
            topic=operation.get("topic"),
            canonical_alias=operation.get("canonical_alias"),
            actor=context.auth.actor_id,
        )

    def _execute_create_question(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.questions.create(
            operation["issue_id"],
            operation["prompt"],
            question_id=operation.get("question_id"),
            question_key=operation.get("question_key"),
            motivation=operation.get("motivation", ""),
            question_kind=operation.get("question_kind", "experiment"),
            priority=int(operation.get("priority", 50)),
            expected_evidence=operation.get("expected_evidence", []),
            actor=context.auth.actor_id,
            reason=operation.get("reason", "reviewed ChangeSet"),
        )

    def _execute_transition_question(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        transitions = {
            "start": self.manager.questions.start,
            "block": self.manager.questions.block,
            "defer": self.manager.questions.defer,
            "cancel": self.manager.questions.cancel,
            "reopen": self.manager.questions.reopen,
        }
        action = str(operation["action"])
        if action not in transitions:
            raise ValidationError(f"Unsupported Question transition: {action!r}")
        return transitions[action](
            operation["question_id"],
            actor=context.auth.actor_id,
            reason=operation.get("reason", "reviewed ChangeSet"),
        )

    def _execute_answer_question(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.questions.answer(
            operation["question_id"],
            operation["conclusion_id"],
            actor=context.auth.actor_id,
            reason=operation.get("reason", "reviewed ChangeSet"),
        )

    def _execute_add_evidence_relation(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.evidence_relations.add(
            operation["consumer_evidence_id"],
            operation["provider_evidence_id"],
            operation["relation_type"],
            impact_policy=operation.get("impact_policy"),
            rationale=operation.get("rationale", ""),
            actor=context.auth.actor_id,
            run_id=context.auth.run_id,
            request_id=context.changeset_id,
            _allocated_relation_id=operation.get("relation_id"),
        )

    def _execute_deactivate_evidence_relation(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.evidence_relations.deactivate(
            operation["relation_id"],
            actor=context.auth.actor_id,
            reason=operation.get("reason", "reviewed ChangeSet"),
        )

    def _execute_reactivate_evidence_relation(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.evidence_relations.reactivate(
            operation["relation_id"],
            actor=context.auth.actor_id,
            reason=operation.get("reason", "reviewed ChangeSet"),
        )

    def _execute_attach_packet(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        packet_id = operation["packet_id"]
        task = self.manager.intake._task(packet_id)
        if task["state"] != "claimed" or task["claimed_run_id"] != context.auth.run_id:
            self.manager.intake.claim(packet_id, credential=context.credential)
        result = self.manager.intake.attach(
            packet_id, operation["issue_id"], credential=context.credential
        )
        link_types = self.manager.intake.active_link_types(packet_id)
        default_disposition = (
            "challenges_current"
            if "challenges" in link_types
            else ("amends_previous" if "amends" in link_types else "no_impact")
        )
        self.manager.intake.disposition(
            packet_id,
            str(operation.get("disposition", default_disposition)),
            reason=str(
                operation.get(
                    "disposition_reason",
                    "Packet attached to working history; no conclusion mutation was requested",
                )
            ),
            issue_id=operation["issue_id"],
            proposal_id=operation.get("proposal_id"),
            evidence_request_id=operation.get("evidence_request_id"),
            credential=context.credential,
        )
        self.manager.intake.complete(packet_id, credential=context.credential)
        return result

    def _execute_attach_evidence(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        if operation.get("evidence_id"):
            evidence = self.store.row(
                "SELECT * FROM evidence_refs WHERE evidence_id=? AND lifecycle_status='active'",
                (operation["evidence_id"],),
            )
            if not evidence:
                raise ValidationError(f"Active evidence not found: {operation['evidence_id']}")
            self.manager._issue(operation["issue_id"])
            with self.store.transaction() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO issue_evidence VALUES (?,?,?,?)",
                    (
                        operation["issue_id"],
                        operation["evidence_id"],
                        now(),
                        context.auth.actor_id,
                    ),
                )
                self.manager.original_access_bindings.admit_evidence(
                    operation["issue_id"], operation["evidence_id"])
            return {"issue_id": operation["issue_id"], "evidence_id": operation["evidence_id"]}
        evidence = operation.get("evidence", operation)
        return self.manager.add_evidence(
            kind=evidence["kind"],
            locator=evidence["locator"],
            issue_id=operation["issue_id"],
            description=evidence.get("description", ""),
            quality_status=evidence.get("quality_status", "unknown"),
            actor=context.auth.actor_id,
        )

    def _execute_append_work(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.append_work(
            operation["issue_id"],
            operation["body"],
            entry_type=operation.get("entry_type", "note"),
            evidence_refs=operation.get("evidence_refs", []),
            actor=context.auth.actor_id,
        )

    def _execute_add_alias(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.add_alias(
            operation["issue_id"], operation["alias"], actor=context.auth.actor_id
        )

    def _execute_add_tag(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.add_tag(
            operation["issue_id"], operation["tag"], actor=context.auth.actor_id
        )

    def _execute_add_relation(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.add_relation(
            operation["consumer"],
            operation["provider"],
            operation["relation_type"],
            impact_policy=operation.get("impact_policy"),
            actor=context.auth.actor_id,
            reason=operation.get("reason", ""),
            _execution_grant=context.grant,
        )

    def _execute_set_relation_impact(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.set_relation_impact(
            operation["relation_id"],
            operation["impact_policy"],
            actor=context.auth.actor_id,
            reason=operation.get("reason", "reviewed ChangeSet"),
            _execution_grant=context.grant,
        )

    def _execute_deactivate_relation(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.deactivate_relation(
            operation["relation_id"],
            actor=context.auth.actor_id,
            reason=operation.get("reason", "reviewed ChangeSet"),
            _execution_grant=context.grant,
        )

    def _execute_reactivate_relation(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.reactivate_relation(
            operation["relation_id"],
            actor=context.auth.actor_id,
            reason=operation.get("reason", "reviewed ChangeSet"),
            _execution_grant=context.grant,
        )

    def _execute_publication(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        proposal = dict(operation.get("proposal", operation))
        proposal.pop("op", None)
        created = self.manager.proposals.create(
            proposal,
            credential=context.credential,
            source_changeset_id=context.changeset_id,
            risk_tier=("T3" if len(context.reviews) >= 2 else ("T2" if context.reviews else None)),
            risk_reasons=["source-changeset-review"] if context.reviews else None,
        )
        self.manager.proposals.validate(created["proposal_id"], credential=context.credential)
        if created["required_reviews"]:
            proposal_row = self.store.row(
                "SELECT * FROM proposals WHERE proposal_id=?", (created["proposal_id"],)
            )
            if proposal_row is None:
                raise ConflictError("Proposal disappeared while applying ChangeSet")
            snapshot = self.manager.proposals._decode_snapshot(proposal_row["basis_snapshot_token"])
            with self.store.transaction() as conn:
                for review in context.reviews[: created["required_reviews"]]:
                    conn.execute(
                        "INSERT INTO review_assignments(assignment_id,proposal_id,"
                        "reviewer_actor_id,reviewer_run_id,state,claimed_at,lease_until,"
                        "heartbeat_at,attempt_count,last_error) "
                        "VALUES (?,?,?,?,'submitted',?,?,?,1,NULL)",
                        (
                            new_id("review_assignment"),
                            created["proposal_id"],
                            review["reviewer_actor_id"],
                            review["reviewer_run_id"],
                            now(),
                            now(),
                            now(),
                        ),
                    )
                    conn.execute(
                        "INSERT INTO review_decisions(review_id,proposal_id,reviewer_actor_id,"
                        "reviewer_run_id,decision,rationale,evidence_sufficiency,proposal_hash,"
                        "basis_snapshot_json,created_at,changeset_hash,policy_risk_snapshot) "
                        "VALUES (?,?,?,?, 'pass',?,?,?,?,?,?,?)",
                        (
                            new_id("review"),
                            created["proposal_id"],
                            review["reviewer_actor_id"],
                            review["reviewer_run_id"],
                            review["rationale"],
                            "approved with ChangeSet review",
                            proposal_row["proposal_hash"],
                            canonical_json(snapshot),
                            now(),
                            review["changeset_hash"],
                            review["risk_snapshot_json"],
                        ),
                    )
                conn.execute(
                    "UPDATE proposals SET state='review_passed',updated_at=? WHERE proposal_id=?",
                    (now(), created["proposal_id"]),
                )
        return self.manager.proposals.apply(created["proposal_id"], credential=context.credential)

    def _execute_mark_needs_review(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        del context
        issue = self.manager._issue(operation["issue_id"])
        with self.store.transaction() as conn:
            task_id = self.manager._enqueue_refresh(
                conn,
                issue_id=issue["issue_id"],
                trigger_issue_id=issue["issue_id"],
                from_revision=issue["conclusion_revision"],
                to_revision=issue["conclusion_revision"],
                reason_type="manual",
                priority=int(operation.get("priority", 50)),
            )
        return {"issue_id": issue["issue_id"], "refresh_task_id": task_id}

    def _execute_reassess_evidence(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.reassess_evidence(
            operation["evidence_id"],
            operation["quality_status"],
            actor=context.auth.actor_id,
            reason=operation.get("reason", "reviewed ChangeSet"),
            _reviewed_changeset=True,
        )

    def _execute_void_evidence(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.void_evidence(
            operation["evidence_id"],
            actor=context.auth.actor_id,
            reason=operation.get("reason", "reviewed ChangeSet"),
            _reviewed_changeset=True,
        )

    def _execute_detach_evidence(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.detach_evidence(
            operation["evidence_id"],
            operation["issue_id"],
            actor=context.auth.actor_id,
            reason=operation.get("reason", "reviewed ChangeSet"),
            _reviewed_changeset=True,
        )

    def _execute_migrate_evidence_source(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.evidence._reviewed_migrate_source(
            operation["evidence_id"],
            operation["new_platform_id"],
            reason=operation.get("reason", "reviewed source platform migration"),
            auth=context.auth,
            changeset_id=context.changeset_id,
            review_ids=[review["review_id"] for review in context.reviews],
        )

    def _execute_resolve_evidence_conflict(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.evidence._reviewed_resolve_conflict(
            operation["evidence_id"],
            accepted_attestation_ids=list(operation.get("accepted_attestation_ids", [])),
            retained_attestation_ids=list(operation.get("retained_attestation_ids", [])),
            rejected_attestation_ids=list(operation.get("rejected_attestation_ids", [])),
            rationale=str(operation.get("rationale", "")),
            auth=context.auth,
        )

    def _execute_resolve_evidence_identity_ambiguity(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        return self.manager.evidence._reviewed_resolve_identity_ambiguity(
            operation["ambiguity_id"],
            decision=str(operation["decision"]),
            rationale=str(operation.get("rationale", "")),
            platform_id=operation.get("platform_id"),
            locator=operation.get("locator"),
            auth=context.auth,
            changeset_id=context.changeset_id,
            review_ids=[review["review_id"] for review in context.reviews],
        )

    def _execute_governed_conflict(
        self, operation: dict[str, Any], *, context: ExecutionContext
    ) -> dict[str, Any]:
        operation_json = canonical_json(operation)
        governance = {
            "changeset_id": context.changeset_id,
            "changeset_hash": context.changeset_hash,
            "operation_ordinal": context.operation_ordinal,
            "operation_hash": hashlib.sha256(operation_json.encode("utf-8")).hexdigest(),
            "review_ids": [review["review_id"] for review in context.reviews],
            "operation": operation,
        }
        decision = {
            "action": operation["resolution"],
            **dict(operation.get("resolution_payload", {})),
        }
        if operation["op"] == "resolve_field_conflict":
            return self.manager.field_bundles.resolve_conflict(
                operation["conflict_id"],
                decision,
                expected_revision=int(operation["expected_conflict_revision"]),
                actor=context.auth.actor_id,
                reason=str(operation.get("reason", "reviewed governed ChangeSet")),
                _governance=governance,
            )
        conflict = self.store.row(
            "SELECT source_job_id FROM integration_conflicts "
            "WHERE integration_conflict_id=? AND source_kind='import'",
            (operation["conflict_id"],),
        )
        if not conflict:
            raise ConflictError(f"Import conflict not found: {operation['conflict_id']}")
        return self.manager.imports.resolve_conflict(
            conflict["source_job_id"],
            operation["conflict_id"],
            decision,
            expected_revision=int(operation["expected_conflict_revision"]),
            actor=context.auth.actor_id,
            reason=str(operation.get("reason", "reviewed governed ChangeSet")),
            _governance=governance,
        )
