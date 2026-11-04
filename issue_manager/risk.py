from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .changeset_engine import OPERATION_DEFINITIONS, operation_definition, simulate_operation
from .changeset_state import StateView
from .errors import ValidationError
from .scope_identity import SampleKey

if TYPE_CHECKING:
    from .service import IssueManager


TIER_VALUE = {"T0": 0, "T1": 1, "T2": 2, "T3": 3}


@dataclass(frozen=True)
class RiskAssessment:
    tier: str
    reasons: tuple[str, ...]

    @property
    def required_reviews(self) -> int:
        return 2 if self.tier == "T3" else (1 if self.tier == "T2" else 0)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "reasons": list(self.reasons),
            "required_reviews": self.required_reviews,
        }


@dataclass(frozen=True)
class NormalizedMutation:
    """Canonical mutation description produced by a trusted command registry."""

    operation: str
    target: dict[str, Any]
    requested_state: dict[str, Any]
    actor_id: str
    run_id: str
    source: str
    request_id: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "target": self.target,
            "requested_state": self.requested_state,
            "actor_id": self.actor_id,
            "run_id": self.run_id,
            "source": self.source,
            "request_id": self.request_id,
        }


@dataclass(frozen=True)
class ExecutionGrant:
    """Opaque, Manager-issued authorization for a normalized mutation."""

    mutation: NormalizedMutation
    assessment: RiskAssessment
    changeset_id: str | None
    changeset_hash: str | None
    authority: object


@dataclass(frozen=True)
class RiskEvaluation:
    assessment: RiskAssessment
    trace: tuple[dict[str, Any], ...]


class RiskPolicy:
    """Deterministic T0-T3 classification; callers cannot lower this result."""

    OPERATIONS = frozenset(OPERATION_DEFINITIONS)

    def __init__(self, manager: "IssueManager"):
        self.manager = manager

    def assess_mutation(self, mutation: NormalizedMutation) -> RiskAssessment:
        """Assess a single normalized operation from current and requested state."""

        name = mutation.operation
        if name == "relation.add":
            operation = {
                "op": "add_relation",
                **mutation.target,
                **mutation.requested_state,
            }
        elif name in {
            "relation.set_impact",
            "relation.deactivate",
            "relation.reactivate",
        }:
            relation_id = str(mutation.target.get("relation_id", ""))
            relation = self.manager.store.row(
                "SELECT * FROM relations WHERE relation_id=?", (relation_id,)
            )
            if not relation:
                raise ValidationError(f"Relation not found: {relation_id}")
            mapping = {
                "relation.set_impact": "set_relation_impact",
                "relation.deactivate": "deactivate_relation",
                "relation.reactivate": "reactivate_relation",
            }
            operation = {
                "op": mapping[name],
                "relation_id": relation_id,
                **mutation.requested_state,
            }
        else:
            raise ValidationError(f"Unsupported normalized mutation: {name!r}")
        return self.assess({"operations": [operation]})

    @staticmethod
    def _promote(current: str, candidate: str) -> str:
        return candidate if TIER_VALUE[candidate] > TIER_VALUE[current] else current

    @staticmethod
    def promotes(current: str, candidate: str) -> bool:
        return TIER_VALUE[candidate] > TIER_VALUE[current]

    @staticmethod
    def assessment(tier: str, reasons: set[str] | tuple[str, ...]) -> RiskAssessment:
        return RiskAssessment(tier=tier, reasons=tuple(sorted(reasons)))

    def _issue_context(
        self,
        operation: dict[str, Any],
        state_view: StateView,
    ) -> tuple[str, set[str], set[SampleKey]]:
        tier = "T0"
        reasons: set[str] = set()
        samples: set[SampleKey] = set()
        name = str(operation["op"])
        if name == "create_issue":
            sample = SampleKey.from_scope(operation.get("scope", {}))
            if sample:
                samples.add(sample)
            if operation.get("issue_type") == "report_scope":
                tier = "T3"
                reasons.add("report-facing-issue")
            return tier, reasons, samples
        issue_id = operation.get("issue_id") or operation.get("consumer")
        if not issue_id:
            return tier, reasons, samples
        try:
            issue = state_view.issue(str(issue_id))
        except Exception:
            return tier, reasons, samples
        sample = SampleKey.from_scope(issue.get("scope", {}))
        if sample:
            samples.add(sample)
        if issue["issue_type"] == "report_scope":
            tier = "T3"
            reasons.add("report-facing-issue")
        return tier, reasons, samples

    def assess_operation(
        self,
        operation: dict[str, Any],
        state_view: StateView,
    ) -> tuple[RiskAssessment, set[SampleKey]]:
        definition = operation_definition(str(operation["op"]))
        tier = definition.base_tier
        reasons: set[str] = set()
        issue_tier, issue_reasons, samples = self._issue_context(operation, state_view)
        tier = self._promote(tier, issue_tier)
        reasons.update(issue_reasons)
        evaluator = getattr(self, f"_risk_{definition.risk_model}")
        candidate, candidate_reasons, candidate_samples = evaluator(
            operation,
            state_view,
            tier,
        )
        tier = self._promote(tier, candidate)
        reasons.update(candidate_reasons)
        samples.update(candidate_samples)
        return self.assessment(tier, reasons), samples

    @staticmethod
    def _risk_standard(
        operation: dict[str, Any], state_view: StateView, tier: str
    ) -> tuple[str, set[str], set[SampleKey]]:
        del operation, state_view
        return tier, set(), set()

    @staticmethod
    def _risk_create_issue(
        operation: dict[str, Any], state_view: StateView, tier: str
    ) -> tuple[str, set[str], set[SampleKey]]:
        del operation, state_view
        return tier, set(), set()

    def _risk_evidence_maintenance(
        self, operation: dict[str, Any], state_view: StateView, tier: str
    ) -> tuple[str, set[str], set[SampleKey]]:
        evidence_id = str(operation.get("evidence_id", ""))
        impact = self.manager._evidence_publication_impact(
            evidence_id,
            issue_id=(operation.get("issue_id") if operation["op"] == "detach_evidence" else None),
        )
        statuses = state_view.evidence_publication_statuses(evidence_id)
        if impact:
            tier = self._promote(tier, str(impact["tier"]))
        if statuses:
            tier = self._promote(tier, "T3" if "canonical" in statuses else "T2")
        reasons = {"published-evidence-maintenance"} if impact or statuses else set()
        return tier, reasons, set()

    @staticmethod
    def _risk_evidence_governance(
        operation: dict[str, Any], state_view: StateView, tier: str
    ) -> tuple[str, set[str], set[SampleKey]]:
        del operation, state_view
        return tier, {"evidence-ownership-or-conflict-resolution"}, set()

    @staticmethod
    def _risk_formal_governance(
        operation: dict[str, Any], state_view: StateView, tier: str
    ) -> tuple[str, set[str], set[SampleKey]]:
        del operation, state_view
        return tier, {"formal-record-conflict-resolution"}, set()

    def _risk_question(
        self, operation: dict[str, Any], state_view: StateView, tier: str
    ) -> tuple[str, set[str], set[SampleKey]]:
        name = str(operation["op"])
        question_issue_id = (
            str(operation.get("issue_id", ""))
            if name == "create_question"
            else str(state_view.question(str(operation.get("question_id", "")))["issue_id"])
        )
        issue = state_view.issue(question_issue_id)
        samples: set[SampleKey] = set()
        sample = SampleKey.from_scope(issue.get("scope", {}))
        if sample:
            samples.add(sample)
        reasons: set[str] = set()
        if issue["issue_type"] == "report_scope":
            tier = "T3"
            reasons.add("report-facing-question")
        elif name == "answer_question":
            conclusion = self.manager.store.row(
                "SELECT status FROM conclusion_revisions WHERE conclusion_id=?",
                (str(operation.get("conclusion_id", "")),),
            )
            if not conclusion:
                raise ValidationError(f"Conclusion not found: {operation.get('conclusion_id', '')}")
            if conclusion["status"] == "canonical":
                tier = "T3"
                reasons.add("canonical-question-answer")
            elif conclusion["status"] in {"accepted", "provisional"}:
                tier = self._promote(tier, "T2")
                reasons.add("published-question-answer")
        else:
            reasons.add("question-lifecycle-change")
        return tier, reasons, samples

    @staticmethod
    def _risk_direct_evidence_relation(
        operation: dict[str, Any], state_view: StateView, tier: str
    ) -> tuple[str, set[str], set[SampleKey]]:
        del operation, state_view
        return tier, set(), set()

    def _risk_add_relation(
        self, operation: dict[str, Any], state_view: StateView, tier: str
    ) -> tuple[str, set[str], set[SampleKey]]:
        samples: set[SampleKey] = set()
        try:
            sample = state_view.sample_for_issue(str(operation.get("provider", "")))
            if sample:
                samples.add(sample)
        except Exception:
            pass
        impact = operation.get("impact_policy")
        if impact is None and operation.get("relation_type"):
            impact = self.manager.policy.default_impact(str(operation["relation_type"]))
        reasons: set[str] = set()
        if impact == "hard":
            tier = "T3"
            reasons.add("hard-dependency-change")
        return tier, reasons, samples

    def _risk_issue_relation_lifecycle(
        self, operation: dict[str, Any], state_view: StateView, tier: str
    ) -> tuple[str, set[str], set[SampleKey]]:
        relation_id = str(operation.get("relation_id", ""))
        relation = state_view.issue_relation(relation_id)
        if not relation:
            raise ValidationError(f"Relation not found: {relation_id}")
        samples: set[SampleKey] = set()
        for column in ("consumer_issue_id", "provider_issue_id"):
            sample = state_view.sample_for_issue(str(relation[column]))
            if sample:
                samples.add(sample)
        before_hard = bool(relation["active"]) and relation["impact_policy"] == "hard"
        name = str(operation["op"])
        if name == "set_relation_impact":
            after_hard = bool(relation["active"]) and operation.get("impact_policy") == "hard"
        elif name == "deactivate_relation":
            after_hard = False
        else:
            after_hard = relation["impact_policy"] == "hard"
        if before_hard or after_hard:
            return "T3", {"hard-dependency-change"}, samples
        return tier, {"soft-relation-change"}, samples

    def _risk_publication(
        self, operation: dict[str, Any], state_view: StateView, tier: str
    ) -> tuple[str, set[str], set[SampleKey]]:
        proposal = operation.get("proposal", operation)
        samples: set[SampleKey] = set()
        for basis in proposal.get("basis", []):
            if not isinstance(basis, dict) or not basis.get("issue_id"):
                continue
            try:
                sample = state_view.sample_for_issue(str(basis["issue_id"]))
            except Exception:
                continue
            if sample:
                samples.add(sample)
        status = proposal.get("status", "provisional")
        reasons: set[str] = set()
        if status == "canonical":
            tier = "T3"
            reasons.add("canonical-publication")
        elif status in {"accepted", "disputed", "superseded", "retracted"}:
            tier = self._promote(tier, "T2")
            reasons.add(f"published-status-{status}")
        else:
            reasons.add("provisional-only")
        return tier, reasons, samples

    def _risk_context_change(self, operation: dict[str, Any], state_view: StateView, tier: str):
        from collections import deque

        if self.manager.store.conn.in_transaction:
            self.manager.context_maintenance.flush()
        self.manager.context_maintenance.validate_change(operation, state_view=state_view)
        pending = deque(item["conclusion_id"] for item in operation.get("items", []))
        if operation["action"] in {"verify", "select"}:
            for item in operation["items"]:
                if operation["action"] == "verify":
                    package_id = item["package_id"]
                else:
                    receipt = self.manager.store.row(
                        "SELECT package_id FROM basis_receipts WHERE receipt_id=?", (item["receipt_id"],)
                    )
                    if receipt is None:
                        raise ValidationError("Selected basis receipt does not exist")
                    package_id = receipt["package_id"]
                package = self.manager.context_maintenance.package(package_id)
                resolved = self.manager.context_maintenance._resolver_for(package["descriptor"]).resolve(package["descriptor"], state_view=state_view)
                pending.extend(provider for provider, _ in resolved.contributions)
        seen = set()
        reasons = {"context-receipt-change"}
        samples = set()
        while pending:
            conclusion_id = pending.popleft()
            if conclusion_id in seen:
                continue
            seen.add(conclusion_id)
            conclusion = self.manager.store.row(
                "SELECT issue_id,status FROM conclusion_revisions WHERE conclusion_id=?", (conclusion_id,)
            )
            if not conclusion:
                raise ValidationError(f"Conclusion not found: {conclusion_id}")
            issue = state_view.issue(conclusion["issue_id"])
            sample = state_view.sample_for_issue(conclusion["issue_id"])
            if sample:
                samples.add(sample)
            if conclusion["status"] == "canonical" or self.manager.issue_report_facing(issue):
                tier = "T3"
                reasons.add("canonical-or-report-facing-context")
            elif conclusion["status"] in {"accepted", "disputed", "retracted", "superseded"}:
                tier = self._promote(tier, "T2")
                reasons.add("accepted-or-withdrawn-context")
            pending.extend(row["consumer_conclusion_id"] for row in self.manager.store.rows(
                "SELECT DISTINCT consumer_conclusion_id FROM currentness_edge_contributions "
                "WHERE provider_conclusion_id=?", (conclusion_id,)
            ))
        if len(samples) > 1:
            tier = "T3"
            reasons.add("cross-sample-context")
        return tier, reasons, samples

    def _risk_context_rule_upgrade(self, operation: dict[str, Any], state_view: StateView, tier: str):
        del tier
        self.manager.context_rules.preview(operation, state_view=state_view)
        return "T3", {"global-context-rule-upgrade"}, set()

    def _risk_question_relation(self, operation: dict[str, Any], state_view: StateView, tier: str):
        from .context_resolver import subscription_key

        preview = self.manager.question_relations.preview(operation, state_view=state_view)
        issues: set[str] = set()
        pending: set[str] = set()
        for row in (preview["before"], preview["after"]):
            if row is None:
                continue
            issues.add(state_view.question(row["question_id"])["issue_id"])
            issues.update(item["issue_id"] for item in state_view.context_rows("issue_evidence", "evidence_id", row["evidence_id"]))
            pending.update(item["conclusion_id"] for item in self.manager.store.rows(
                "SELECT conclusion_id FROM context_subscriptions WHERE subscription_key=?",
                (subscription_key("issue_question_evidence_links", "question_id", row["question_id"]),)))
        return self._risk_material_consumers(issues, pending, state_view, tier, "question-material-change")

    def _risk_intake_relation(self, operation, state_view, tier):
        from .context_resolver import subscription_key

        preview = self.manager.intake_relations.preview(operation, state_view=state_view)
        issues: set[str] = set()
        pending: set[str] = set()
        for row in (preview["before"], preview["after"]):
            if row is None:
                continue
            for field in ("source_packet_id", "target_packet_id"):
                packet_id = row[field]
                packet = self.manager.store.row("SELECT attached_issue_id FROM intake_packets WHERE packet_id=?", (packet_id,))
                if packet and packet["attached_issue_id"]:
                    issues.add(packet["attached_issue_id"])
                issues.update(item["issue_id"] for item in state_view.context_rows("working_entries", "source_packet_id", packet_id))
                for scope in ("source_packet_id", "target_packet_id"):
                    pending.update(item["conclusion_id"] for item in self.manager.store.rows(
                        "SELECT conclusion_id FROM context_subscriptions WHERE subscription_key=?",
                        (subscription_key("intake_packet_links", scope, packet_id),)))
        return self._risk_material_consumers(issues, pending, state_view, tier, "intake-material-change")

    def _risk_material_consumers(self, issues, pending, state_view, tier, reason):
        seen = set()
        reasons, samples = {reason}, set()
        for identity in issues:
            pending.update(row["conclusion_id"] for row in self.manager.store.rows(
                "SELECT conclusion_id FROM conclusion_revisions WHERE issue_id=?", (identity,)))
        while pending:
            identity = pending.pop()
            if identity in seen:
                continue
            seen.add(identity)
            row = self.manager.store.row("SELECT issue_id,status FROM conclusion_revisions WHERE conclusion_id=?", (identity,))
            if row:
                issues.add(row["issue_id"])
                if row["status"] == "canonical":
                    tier = "T3"
                elif row["status"] in {"accepted", "disputed", "retracted", "superseded"}:
                    tier = self._promote(tier, "T2")
            pending.update(row["consumer_conclusion_id"] for row in self.manager.store.rows(
                "SELECT consumer_conclusion_id FROM currentness_edge_contributions WHERE provider_conclusion_id=?", (identity,)))
        for identity in issues:
            sample = state_view.sample_for_issue(identity)
            if sample:
                samples.add(sample)
            if self.manager.issue_report_facing(state_view.issue(identity)):
                tier = "T3"
        if len(samples) > 1:
            tier = "T3"
        return tier, reasons, samples

    def _risk_record_relation(self, operation, state_view, tier):
        from .context_resolver import subscription_key

        preview = self.manager.record_relations.preview(operation, state_view=state_view)
        issues: set[str] = set()
        pending: set[str] = set()
        for row in (preview["before"], preview["after"]):
            if row is None:
                continue
            record = self.manager.store.row(
                "SELECT i.issue_id FROM record_revisions r JOIN record_instances i USING(record_instance_id) WHERE r.record_revision_id=?",
                (row["record_revision_id"],))
            if record:
                issues.add(record["issue_id"])
            issues.update(item["issue_id"] for item in state_view.context_rows("issue_evidence", "evidence_id", row["evidence_id"]))
            pending.update(item["conclusion_id"] for item in self.manager.store.rows(
                "SELECT conclusion_id FROM context_subscriptions WHERE subscription_key=?",
                (subscription_key("record_material_relations", "record_revision_id", row["record_revision_id"]),)))
        return self._risk_material_consumers(issues, pending, state_view, tier, "record-material-change")

    def _risk_context_obligation(self, operation: dict[str, Any], state_view: StateView, tier: str):
        item = self.manager.context_obligations.preview(operation, state_view=state_view)["after"]
        conclusion = self.manager.store.row("SELECT issue_id,status FROM conclusion_revisions WHERE conclusion_id=?", (item["conclusion_id"],))
        if conclusion is None:
            raise ValidationError("Review obligation conclusion does not exist")
        tier = self._promote(tier, "T2" if operation["action"] in {"complete", "cancel"} or conclusion["status"] == "accepted" else "T1")
        if conclusion["status"] == "canonical" or self.manager.issue_report_facing(state_view.issue(conclusion["issue_id"])):
            tier = "T3"
        sample = state_view.sample_for_issue(conclusion["issue_id"])
        return tier, {"independent-review-obligation"}, {sample} if sample else set()

    def _risk_evidence_applicability_decision(
        self, operation: dict[str, Any], state_view: StateView, tier: str
    ):
        planner = self.manager.evidence_applicability.changeset_planner
        plan = planner.plan(operation, state_view=state_view)
        issues: set[str] = set()
        pending: set[str] = set()
        target_samples: set[SampleKey] = set()
        # Replacements may move both the Scope and fixed target. Risk is the
        # union of consumers on both sides, independent of include/exclude.
        for version in (plan.get("before_version"), plan.get("after_version")):
            if not version:
                continue
            scope_issue = version.get("scope_issue_id")
            if scope_issue:
                issues.add(str(scope_issue))
            evidence_id = version.get("target_evidence_id")
            if not evidence_id:
                continue
            issues.update(
                str(row["issue_id"])
                for row in state_view.context_rows("issue_evidence", "evidence_id", evidence_id)
            )
            for row in self.manager.store.rows(
                "SELECT DISTINCT c.issue_id,c.conclusion_id FROM conclusion_evidence_uses u "
                "JOIN conclusion_revisions c ON c.conclusion_id=u.conclusion_id "
                "WHERE u.evidence_id=?", (evidence_id,),
            ):
                issues.add(str(row["issue_id"]))
                if row["conclusion_id"]:
                    pending.add(str(row["conclusion_id"]))
            target_samples.update(state_view.evidence_samples(str(evidence_id)))

        tier, reasons, consumer_samples = self._risk_material_consumers(
            issues, pending, state_view, tier, "scoped-applicability-change"
        )
        reasons.add("applicability-include-or-exclude")
        samples = consumer_samples | target_samples
        if len(samples) > 1:
            tier = "T3"
            reasons.add("cross-sample-applicability-consumers")
        return tier, reasons, samples

    def _risk_replace_relation(self, operation: dict[str, Any], state_view: StateView, tier: str):
        preview = self.manager.relation_versions.preview(operation, state_view=state_view)
        reasons, samples = {"relation-version-replacement"}, set()
        for relation in (preview["before"], preview["after"]):
            if relation["impact_policy"] == "hard":
                tier = "T3"
                reasons.add("hard-relation-replacement")
            if preview["domain"] == "issue":
                for key in ("consumer_issue_id", "provider_issue_id"):
                    sample = state_view.sample_for_issue(relation[key])
                    if sample:
                        samples.add(sample)
                    if self.manager.issue_report_facing(state_view.issue(relation[key])):
                        tier = "T3"
                        reasons.add("report-facing-relation")
            else:
                risk = self.manager.evidence_relations.assess_add(
                    relation["consumer_evidence_id"], relation["provider_evidence_id"],
                    relation["relation_type"], impact_policy=relation["impact_policy"], state_view=state_view)
                tier = self._promote(tier, risk["tier"])
                reasons.update(risk["reasons"])
        if len(samples) > 1:
            tier = "T3"
            reasons.add("cross-sample-replacement")
        return tier, reasons, samples

    def _risk_context_relation(self, operation: dict[str, Any], state_view: StateView, tier: str):
        import json

        from .context_resolver import subscription_key

        if self.manager.store.conn.in_transaction:
            self.manager.context_maintenance.flush()
        preview = self.manager.context_relations.preview(operation, state_view=state_view)
        keys = {row[column] for row in (preview["before"], preview["after"]) if row
                for column in ("source_key", "target_key")}
        conclusions: set[str] = set()
        issues: set[str] = set()
        for key in keys:
            for column in ("source_key", "target_key"):
                conclusions.update(row["conclusion_id"] for row in self.manager.store.rows(
                    "SELECT conclusion_id FROM context_subscriptions WHERE subscription_key=?",
                    (subscription_key("context_relations", column, key),)))
        # Assess retained endpoints too, including a relationship version that
        # currently has no subscribers. Typed endpoint recursion is finite.
        pending, visited = list(keys), set()
        while pending:
            key = pending.pop()
            if key in visited:
                continue
            visited.add(key)
            kind, identity = json.loads(key)
            if kind == "conclusion_version":
                conclusions.add(identity)
            elif kind == "record_version":
                row = self.manager.store.row(
                    "SELECT i.issue_id FROM record_revisions r JOIN record_instances i ON i.record_instance_id=r.record_instance_id "
                    "WHERE r.record_revision_id=?", (identity,))
                if row:
                    issues.add(row["issue_id"])
            elif kind == "relation_version":
                row = state_view.material_version(identity)
                if not row:
                    raise ValidationError("Missing material relationship version")
                definition = json.loads(row["definition_json"])
                if row["domain"] == "context":
                    pending.extend((definition["source_key"], definition["target_key"]))
                elif row["domain"] == "issue":
                    issues.update((definition["consumer_issue_id"], definition["provider_issue_id"]))
                elif row["domain"] == "question":
                    issues.add(state_view.question(definition["question_id"])["issue_id"])
                elif row["domain"] == "record":
                    record = self.manager.store.row(
                        "SELECT i.issue_id FROM record_revisions r JOIN record_instances i USING(record_instance_id) WHERE r.record_revision_id=?",
                        (definition["record_revision_id"],))
                    if record:
                        issues.add(record["issue_id"])
                elif row["domain"] == "intake":
                    for field in ("source_packet_id", "target_packet_id"):
                        packet = self.manager.store.row("SELECT attached_issue_id FROM intake_packets WHERE packet_id=?", (definition[field],))
                        if packet and packet["attached_issue_id"]:
                            issues.add(packet["attached_issue_id"])
                else:
                    for field in ("consumer_evidence_id", "provider_evidence_id"):
                        issues.update(item["issue_id"] for item in self.manager.store.rows(
                            "SELECT issue_id FROM issue_evidence WHERE evidence_id=?", (definition[field],)))
        reasons, samples = {"material-relation-change"}, set()
        pending, seen = list(conclusions), set()
        while pending:
            identity = pending.pop()
            if identity in seen:
                continue
            seen.add(identity)
            row = self.manager.store.row("SELECT issue_id,status FROM conclusion_revisions WHERE conclusion_id=?", (identity,))
            if not row:
                raise ValidationError("Missing material conclusion")
            issues.add(row["issue_id"])
            if row["status"] == "canonical":
                tier = "T3"
                reasons.add("canonical-material")
            elif row["status"] in {"accepted", "disputed", "retracted", "superseded"}:
                tier = self._promote(tier, "T2")
                reasons.add("accepted-or-withdrawn-material")
            pending.extend(item["consumer_conclusion_id"] for item in self.manager.store.rows(
                "SELECT consumer_conclusion_id FROM currentness_edge_contributions WHERE provider_conclusion_id=?", (identity,)))
        for identity in issues:
            sample = state_view.sample_for_issue(identity)
            if sample:
                samples.add(sample)
            if self.manager.issue_report_facing(state_view.issue(identity)):
                tier = "T3"
                reasons.add("report-facing-material")
        if len(samples) > 1:
            tier = "T3"
            reasons.add("cross-sample-material")
        return self._promote(tier, "T1"), reasons, samples

    @staticmethod
    def _risk_append_work(
        operation: dict[str, Any], state_view: StateView, tier: str
    ) -> tuple[str, set[str], set[SampleKey]]:
        del operation, state_view
        return tier, {"append-only-work"}, set()

    def assess_with_trace(
        self,
        changeset: dict[str, Any],
        *,
        state_view: StateView | None = None,
    ) -> RiskEvaluation:
        operations = changeset.get("operations")
        if not isinstance(operations, list) or not operations:
            raise ValidationError("ChangeSet operations must be a non-empty list")
        tier = "T0"
        reasons: set[str] = set()
        samples: set[SampleKey] = set()
        view = state_view or StateView(self.manager)
        for ordinal, operation in enumerate(operations):
            if not isinstance(operation, dict):
                raise ValidationError("Each ChangeSet operation must be an object")
            operation_definition(str(operation.get("op")))
            operation_assessment, operation_samples = self.assess_operation(operation, view)
            view.record(
                ordinal=ordinal,
                operation=operation,
                risk=operation_assessment.as_dict(),
            )
            tier = self._promote(tier, operation_assessment.tier)
            reasons.update(operation_assessment.reasons)
            samples.update(operation_samples)
            simulate_operation(view, operation)
        if len(samples) > 1:
            tier = "T3"
            reasons.add("cross-sample-change")
        if not reasons:
            reasons.add("capture-only")
        return RiskEvaluation(self.assessment(tier, reasons), tuple(view.trace))

    def assess(
        self,
        changeset: dict[str, Any],
        *,
        state_view: StateView | None = None,
    ) -> RiskAssessment:
        return self.assess_with_trace(changeset, state_view=state_view).assessment
