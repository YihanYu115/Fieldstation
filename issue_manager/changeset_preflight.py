from __future__ import annotations

from typing import Any

from .changeset_engine import operation_definition
from .changeset_operations import validate_operation_shape
from .changeset_state import StateView
from .errors import ConflictError, ValidationError


class ChangeSetPreflightMixin:
    """Semantic validators addressed by the shared operation registry."""

    manager: Any
    store: Any
    operation_engine: Any

    def _validate_operation_semantics(
        self,
        operation: dict[str, Any],
        *,
        ordinal: int,
        state_view: StateView | None = None,
    ) -> None:
        """Compatibility entry point for one operation's semantic validation."""

        validate_operation_shape(operation, ordinal=ordinal)
        definition = operation_definition(str(operation["op"]))
        validator = getattr(self, f"_validate_{definition.validator}")
        validator(operation, state_view=state_view or StateView(self.manager), ordinal=ordinal)

    def _validate_create_issue(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        issue_id = str(operation["issue_id"])
        if issue_id in state_view.virtual_issues:
            raise ConflictError(f"Issue already exists in this ChangeSet: {issue_id}")
        parent_id = operation.get("parent_issue_id")
        self.manager.create_issue(
            issue_id,
            operation["issue_type"],
            operation.get("title"),
            parent_issue_id=parent_id,
            scope=operation.get("scope"),
            topic=operation.get("topic"),
            canonical_alias=operation.get("canonical_alias"),
            issue_type_registration_id=operation.get("issue_type_registration_id"),
            dry_run=True,
            _state_view=state_view,
        )

    def _validate_issue_exists(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        state_view.issue(str(operation["issue_id"]))

    def _validate_attach_packet(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        from .intake_planner import plan_attach

        plan_attach(state_view, operation)

    def _validate_attach_evidence(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        state_view.issue(str(operation["issue_id"]))
        if operation.get("evidence_id"):
            evidence = state_view.evidence(str(operation["evidence_id"]))
            if evidence["lifecycle_status"] != "active":
                raise ValidationError(f"Active evidence not found: {operation['evidence_id']}")
            return
        evidence = operation.get("evidence", operation)
        if not isinstance(evidence, dict):
            raise ValidationError("attach_evidence evidence must be an object")
        from .evidence_planner import plan_create

        plan_create(state_view, {**evidence, "issue_id": operation["issue_id"]})

    def _validate_append_work(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        from .work_planner import plan_append

        plan_append(state_view, operation)

    def _validate_issue_text(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        state_view.issue(str(operation["issue_id"]))
        field = "alias" if operation["op"] == "add_alias" else "tag"
        if not str(operation[field]).strip():
            raise ValidationError(f"{operation['op']} requires a non-empty {field}")

    def _validate_add_relation(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        from .issue_relation_planner import plan_add

        decision = plan_add(state_view, operation)
        if decision["hard_cycle"]:
            raise ValidationError("Hard Issue relation would create a cycle")

    def _validate_issue_relation_lifecycle(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        from .issue_relation_planner import plan_lifecycle

        decision = plan_lifecycle(state_view, operation)
        relation = decision["relation"]
        if bool(relation["active"]) == (operation["op"] == "reactivate_relation"):
            return
        if decision["hard_cycle"]:
            raise ValidationError("Reactivated hard Issue relation would create a cycle")

    def _validate_proposal(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        proposal = dict(operation.get("proposal", operation))
        proposal.pop("op", None)
        token = proposal.get("basis_snapshot_token")
        if token is not None:
            if not isinstance(token, str) or not token:
                raise ValidationError("basis_snapshot_token must be a non-empty string")
            self.manager.proposals.verify_snapshot(token, proposal, require_current=True, state_view=state_view)
        self.manager.validate_proposal(proposal, refresh=operation["op"] == "refresh_issue", state_view=state_view)

    def _validate_evidence_maintenance(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        from .evidence_planner import plan_maintenance

        plan_maintenance(state_view, operation)

    def _validate_migrate_evidence_source(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        self.manager.evidence.preview_source_migration(
            str(operation["evidence_id"]), operation["new_platform_id"],
            reason=operation.get("reason", "reviewed ChangeSet"), state_view=state_view)

    def _validate_resolve_evidence_conflict(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        evidence = state_view.evidence(str(operation["evidence_id"]))
        if evidence["verification_state"] != "conflict":
            raise ConflictError("Evidence is not in verification conflict")
        self.manager.evidence.preview_conflict_resolution(
            str(operation["evidence_id"]), accepted_attestation_ids=operation.get("accepted_attestation_ids", []),
            retained_attestation_ids=operation.get("retained_attestation_ids", []),
            rejected_attestation_ids=operation.get("rejected_attestation_ids", []),
            rationale=operation.get("rationale", ""), state_view=state_view)

    def _validate_resolve_evidence_identity_ambiguity(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        rows = state_view.context_rows("evidence_identity_ambiguities", "ambiguity_id", operation["ambiguity_id"])
        ambiguity = rows[0] if rows else None
        if not ambiguity:
            raise ValidationError(
                f"Evidence identity ambiguity not found: {operation['ambiguity_id']}"
            )
        if ambiguity["state"] != "open":
            raise ConflictError("Evidence identity ambiguity is not open")
        allowed = {
            "confirm_same_object",
            "bind_existing_to_platform",
            "split_future_identity",
            "void_incorrect_reference",
            "waive_migration_blocker",
        }
        if operation["decision"] not in allowed:
            raise ValidationError(
                f"Unsupported identity ambiguity decision: {operation['decision']}"
            )
        if not str(operation.get("rationale", "")).strip():
            raise ValidationError("Identity ambiguity resolution requires a rationale")
        self.manager.evidence.preview_identity_resolution(operation, state_view=state_view)

    def _validate_governed_conflict(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        from .conflict_governance import validate_resolution_binding

        domain = "field_bundle" if operation["op"] == "resolve_field_conflict" else "import"
        validate_resolution_binding(self.store.conn, domain, operation, state_view=state_view)

    def _validate_create_question(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        from .question_planner import plan_create

        plan_create(state_view, operation)

    def _validate_transition_question(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        from .question_planner import plan_transition

        plan_transition(state_view, operation)

    def _validate_answer_question(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        from .question_planner import plan_answer

        plan_answer(state_view, operation)

    def _validate_add_evidence_relation(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        if "relation_id" in operation:
            identity = operation["relation_id"]
            if not isinstance(identity, str) or not identity.strip() or state_view.evidence_relation(identity):
                raise ConflictError("Evidence relation identity is invalid or already exists")
        consumer = str(operation["consumer_evidence_id"])
        provider = str(operation["provider_evidence_id"])
        relation_type = str(operation["relation_type"])
        self.manager.evidence_relations.validate_add(
            consumer,
            provider,
            relation_type,
            impact_policy=operation.get("impact_policy"),
            state_view=state_view,
        )
        if consumer == provider:
            raise ValidationError("Evidence relation endpoints must be different")
        relation_key = (consumer, provider, relation_type)
        if not hasattr(self.manager, "context_maintenance") and (relation_key in state_view.new_evidence_relations or self.store.row(
            "SELECT 1 FROM evidence_relations WHERE consumer_evidence_id=? "
            "AND provider_evidence_id=? AND relation_type=?",
            relation_key,
        )):
            raise ConflictError("This Evidence relation already exists")
        effective = self.manager.evidence_relations.resolve_impact(
            relation_type, operation.get("impact_policy")
        )["effective"]
        if effective == "hard" and state_view.hard_evidence_cycle(consumer, provider):
            raise ValidationError("Hard Evidence relation would create a cycle")

    def _validate_evidence_relation_lifecycle(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        relation = state_view.evidence_relation(str(operation["relation_id"]))
        if not relation:
            raise ValidationError(f"Evidence relation not found: {operation['relation_id']}")
        target_active = operation["op"] == "reactivate_evidence_relation"
        if bool(relation["active"]) == target_active:
            return
        if (
            target_active
            and relation["impact_policy"] == "hard"
            and state_view.hard_evidence_cycle(
                str(relation["consumer_evidence_id"]),
                str(relation["provider_evidence_id"]),
            )
        ):
            raise ValidationError("Reactivated hard Evidence relation would create a cycle")

    def _preflight_operations(self, operations: list[dict[str, Any]]) -> dict[str, Any]:
        return self.operation_engine.preflight(operations)

    def _validate_context_change(self, operation: dict[str, Any], *, state_view: StateView, ordinal: int) -> None:
        del ordinal
        self.manager.context_maintenance.validate_change(operation, state_view=state_view)

    def _validate_context_obligation(self, operation: dict[str, Any], *, state_view: StateView, ordinal: int) -> None:
        del ordinal
        self.manager.context_obligations.preview(operation, state_view=state_view)

    def _validate_context_rule_upgrade(self, operation: dict[str, Any], *, state_view: StateView, ordinal: int) -> None:
        del ordinal
        self.manager.context_rules.preview(operation, state_view=state_view)

    def _validate_context_relation(self, operation: dict[str, Any], *, state_view: StateView, ordinal: int) -> None:
        del ordinal
        self.manager.context_relations.preview(operation, state_view=state_view)

    def _validate_evidence_applicability_decision(
        self, operation: dict[str, Any], *, state_view: StateView, ordinal: int
    ) -> None:
        del ordinal
        self.manager.evidence_applicability.changeset_planner.plan(
            operation, state_view=state_view
        )

    def _validate_question_relation(self, operation: dict[str, Any], *, state_view: StateView, ordinal: int) -> None:
        self.manager.question_relations.preview(operation, state_view=state_view)

    def _validate_intake_relation(self, operation: dict[str, Any], *, state_view: StateView, ordinal: int) -> None:
        self.manager.intake_relations.preview(operation, state_view=state_view)

    def _validate_record_relation(self, operation: dict[str, Any], *, state_view: StateView, ordinal: int) -> None:
        self.manager.record_relations.preview(operation, state_view=state_view)

    def _validate_replace_relation(self, operation: dict[str, Any], *, state_view: StateView, ordinal: int) -> None:
        del ordinal
        self.manager.relation_versions.preview(operation, state_view=state_view)
