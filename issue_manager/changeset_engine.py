from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .changeset_operations import CHANGESET_OPERATION_SPECS, validate_operation_shape
from .changeset_state import StateView
from .errors import ConflictError, NotFoundError, ValidationError
from .scope_identity import SampleKey

if TYPE_CHECKING:
    from .risk import ExecutionGrant
    from .security import AuthContext
    from .service import IssueManager


@dataclass(frozen=True)
class OperationDefinition:
    """One authoritative ChangeSet operation runtime contract."""

    op: str
    validator: str
    risk_model: str
    simulator: str
    executor: str
    base_tier: str = "T1"


def _definition(
    op: str,
    *,
    validator: str,
    risk_model: str = "standard",
    simulator: str = "noop",
    executor: str | None = None,
    base_tier: str = "T1",
) -> OperationDefinition:
    return OperationDefinition(
        op=op,
        validator=validator,
        risk_model=risk_model,
        simulator=simulator,
        executor=executor or op,
        base_tier=base_tier,
    )


OPERATION_DEFINITIONS: dict[str, OperationDefinition] = {
    item.op: item
    for item in (
        _definition("context_obligation", validator="context_obligation", risk_model="context_obligation", simulator="context_obligation"),
        _definition("context_rule_upgrade", validator="context_rule_upgrade", risk_model="context_rule_upgrade", simulator="context_rule_upgrade"),
        _definition("replace_relation", validator="replace_relation", risk_model="replace_relation", simulator="replace_relation"),
        _definition("context_relation", validator="context_relation", risk_model="context_relation", simulator="context_relation"),
        _definition("evidence_applicability_decision", validator="evidence_applicability_decision",
                    risk_model="evidence_applicability_decision", simulator="evidence_applicability_decision"),
        _definition("question_relation", validator="question_relation", risk_model="question_relation", simulator="question_relation"),
        _definition("intake_relation", validator="intake_relation", risk_model="intake_relation", simulator="intake_relation"),
        _definition("record_relation", validator="record_relation", risk_model="record_relation", simulator="record_relation"),
        _definition("context_change", validator="context_change", risk_model="context_change", simulator="context_change"),
        _definition(
            "create_issue",
            validator="create_issue",
            risk_model="create_issue",
            simulator="create_issue",
        ),
        _definition("attach_packet", validator="attach_packet", simulator="attach_packet"),
        _definition(
            "attach_evidence",
            validator="attach_evidence",
            simulator="attach_evidence",
        ),
        _definition(
            "append_work",
            validator="append_work",
            risk_model="append_work",
            simulator="append_work",
            base_tier="T0",
        ),
        _definition("add_alias", validator="issue_text"),
        _definition("add_tag", validator="issue_text"),
        _definition(
            "add_relation",
            validator="add_relation",
            risk_model="add_relation",
            simulator="add_relation",
        ),
        _definition(
            "set_relation_impact",
            validator="issue_relation_lifecycle",
            risk_model="issue_relation_lifecycle",
            simulator="set_relation_impact",
        ),
        _definition(
            "deactivate_relation",
            validator="issue_relation_lifecycle",
            risk_model="issue_relation_lifecycle",
            simulator="issue_relation_lifecycle",
        ),
        _definition(
            "reactivate_relation",
            validator="issue_relation_lifecycle",
            risk_model="issue_relation_lifecycle",
            simulator="issue_relation_lifecycle",
        ),
        _definition(
            "propose_conclusion",
            validator="proposal",
            risk_model="publication",
            simulator="publication",
            executor="publication",
        ),
        _definition(
            "refresh_issue",
            validator="proposal",
            risk_model="publication",
            simulator="publication",
            executor="publication",
        ),
        _definition("mark_needs_review", validator="issue_exists"),
        _definition(
            "reassess_evidence",
            validator="evidence_maintenance",
            risk_model="evidence_maintenance",
            simulator="reassess_evidence",
        ),
        _definition(
            "void_evidence",
            validator="evidence_maintenance",
            risk_model="evidence_maintenance",
            simulator="void_evidence",
        ),
        _definition(
            "detach_evidence",
            validator="evidence_maintenance",
            risk_model="evidence_maintenance",
            simulator="detach_evidence",
        ),
        _definition(
            "migrate_evidence_source",
            validator="migrate_evidence_source",
            risk_model="evidence_governance",
            simulator="migrate_evidence_source",
            base_tier="T3",
        ),
        _definition(
            "resolve_evidence_conflict",
            validator="resolve_evidence_conflict",
            risk_model="evidence_governance",
            simulator="resolve_evidence_conflict",
            base_tier="T3",
        ),
        _definition(
            "resolve_evidence_identity_ambiguity",
            validator="resolve_evidence_identity_ambiguity",
            simulator="resolve_evidence_identity_ambiguity",
            risk_model="evidence_governance",
            base_tier="T3",
        ),
        _definition(
            "resolve_field_conflict",
            validator="governed_conflict",
            simulator="governed_conflict",
            risk_model="formal_governance",
            executor="governed_conflict",
            base_tier="T3",
        ),
        _definition(
            "resolve_import_conflict",
            validator="governed_conflict",
            simulator="governed_conflict",
            risk_model="formal_governance",
            executor="governed_conflict",
            base_tier="T3",
        ),
        _definition(
            "create_question",
            validator="create_question",
            risk_model="question",
            simulator="create_question",
        ),
        _definition(
            "transition_question",
            validator="transition_question",
            risk_model="question",
            simulator="transition_question",
        ),
        _definition(
            "answer_question",
            validator="answer_question",
            risk_model="question",
            simulator="answer_question",
        ),
        _definition(
            "add_evidence_relation",
            validator="add_evidence_relation",
            risk_model="direct_evidence_relation",
            simulator="add_evidence_relation",
        ),
        _definition(
            "deactivate_evidence_relation",
            validator="evidence_relation_lifecycle",
            risk_model="direct_evidence_relation",
            simulator="evidence_relation_lifecycle",
        ),
        _definition(
            "reactivate_evidence_relation",
            validator="evidence_relation_lifecycle",
            risk_model="direct_evidence_relation",
            simulator="evidence_relation_lifecycle",
        ),
    )
}


def operation_definition(op: str) -> OperationDefinition:
    try:
        return OPERATION_DEFINITIONS[op]
    except KeyError as exc:
        raise ValidationError(f"Unsupported ChangeSet operation: {op!r}") from exc


def _simulate_noop(view: StateView, operation: dict[str, Any]) -> None:
    del view, operation


def _simulate_attach_packet(view: StateView, operation: dict[str, Any]) -> None:
    import json

    from .intake_planner import plan_attach
    from .store import canonical_json

    try:
        decision = plan_attach(view, operation)
    except (NotFoundError, ValidationError):
        # Risk assessment remains conservative for unresolved targets; the
        # authoritative preflight reports the concrete semantic failure.
        return
    packet_id = decision["packet_id"]
    packet = decision["packet"]
    evidence = view.manager.store.rows(
        "SELECT evidence_id FROM intake_evidence WHERE packet_id=? ORDER BY ordinal", (packet_id,))
    if any(row["evidence_id"] is None for row in evidence):
        raise ValidationError("Packet evidence identity must be resolved before context preflight")
    evidence_ids = [row["evidence_id"] for row in evidence]
    for evidence_id in evidence_ids:
        _simulate_attach_evidence(view, {"issue_id": operation["issue_id"], "evidence_id": evidence_id})
    _simulate_append_work(view, {"issue_id": operation["issue_id"], "entry_type": "observation",
                               "body": view.manager.intake._packet_work_body(json.loads(packet["packet_json"])),
                               "evidence_refs": evidence_ids})
    view.appended_work[-1]["source_packet_id"] = packet_id
    view.appended_work[-1]["evidence_refs_json"] = canonical_json(evidence_ids)
    link_types = view.manager.intake.active_link_types(packet_id, state_view=view)
    default = "challenges_current" if "challenges" in link_types else (
        "amends_previous" if "amends" in link_types else "no_impact")
    row = {"packet_id": packet_id, "issue_id": decision["issue_id"], "conclusion_id": None,
           "disposition": str(operation.get("disposition", default)),
           "proposal_id": operation.get("proposal_id"), "evidence_request_id": operation.get("evidence_request_id"),
           "reason": str(operation.get("disposition_reason",
                         "Packet attached to working history; no conclusion mutation was requested")).strip()}
    existing = view.triage_dispositions.get(packet_id) or view.manager.store.row(
        "SELECT * FROM triage_dispositions WHERE packet_id=?", (packet_id,))
    if existing and any(existing.get(key) != value for key, value in row.items()):
        raise ConflictError("Triage disposition is append-only and already exists")
    view.triage_dispositions[packet_id] = existing or {**row, "created_by": None, "created_run_id": None, "created_at": None}


def _simulate_append_work(view: StateView, operation: dict[str, Any]) -> None:
    from .store import canonical_json
    from .work_planner import plan_append

    decision = plan_append(view, {**operation, "_simulation": True})
    view.appended_work.append({
        "entry_id": f"preflight-work:{len(view.appended_work)}",
        "issue_id": decision["issue_id"], "entry_type": decision["entry_type"],
        "body": decision["body"],
        "evidence_refs_json": canonical_json(decision["evidence_refs"]),
        "policy_version": view.manager.policy.version, "amends_entry_id": None, "source_packet_id": None,
        "created_at": None, "created_by": None,
    })


def _simulate_create_issue(view: StateView, operation: dict[str, Any]) -> None:
    import json

    issue_id = str(operation["issue_id"])
    preview = view.manager.create_issue(issue_id, operation["issue_type"], operation.get("title"),
                                        parent_issue_id=operation.get("parent_issue_id"), scope=operation.get("scope"),
                                        topic=operation.get("topic"), canonical_alias=operation.get("canonical_alias"),
                                        issue_type_registration_id=operation.get("issue_type_registration_id"),
                                        dry_run=True, _state_view=view)
    view.virtual_issues[issue_id] = {**preview["issue_row"], "scope": dict(operation.get("scope") or {})}
    view.rollup_policies[issue_id] = view.manager.rollup.snapshot_row(
        issue_id, json.loads(preview["issue_row"]["issue_type_snapshot_json"]))
    for spec in view.manager.questions.template_creation_specs(json.loads(preview["issue_row"]["issue_type_snapshot_json"])):
        _simulate_create_question(view, {"issue_id": issue_id, **spec})


def _simulate_attach_evidence(view: StateView, operation: dict[str, Any]) -> None:
    evidence_id = operation.get("evidence_id")
    if not evidence_id:
        from .context_evidence_preview import stage_evidence

        evidence_id = stage_evidence(view, operation.get("evidence", operation))
    issue_id = str(operation["issue_id"])
    evidence_id = str(evidence_id)
    view.evidence_attachment_removals.discard((issue_id, evidence_id))
    view.evidence_attachment_additions.add((issue_id, evidence_id))


def _proposal_evidence_ids(operation: dict[str, Any]) -> set[str]:
    proposal = operation.get("proposal", operation)
    evidence_ids = {
        str(evidence_id) for evidence_id in proposal.get("evidence_refs", []) if evidence_id
    }
    evidence_ids.update(
        str(item["evidence_id"])
        for item in proposal.get("evidence_uses", []) or []
        if isinstance(item, dict) and item.get("evidence_id")
    )
    return evidence_ids


def _simulate_publication(view: StateView, operation: dict[str, Any]) -> None:
    from .store import canonical_json

    proposal = operation.get("proposal", operation)
    status = str(proposal.get("status", "provisional"))
    issue_id = proposal["issue_id"]
    issue = view.issue(issue_id)
    identity = f"preflight-conclusion:{len(view.published_conclusions)}"
    revision = issue["conclusion_revision"] + 1
    row: dict[str, Any] = {column[1]: None for column in view.manager.store.conn.execute("PRAGMA table_info(conclusion_revisions)")}
    row.update({"conclusion_id": identity, "issue_id": issue_id, "revision_number": revision,
                "status": status, "statement": proposal["statement"].strip(),
                "structured_outputs_json": canonical_json(proposal.get("structured_outputs", {})),
                "limitations_json": canonical_json(proposal.get("limitations", [])),
                "evidence_refs_json": canonical_json(proposal.get("evidence_refs", [])),
                "confidence": proposal.get("confidence"), "applicability": proposal.get("applicability"),
                "change_summary": proposal.get("change_summary", ""), "policy_version": view.manager.policy.version,
                "previous_conclusion_id": issue["current_conclusion_id"]})
    view.published_conclusions[identity] = row
    token = proposal.get("basis_snapshot_token")
    if token:
        package_id = view.manager.proposals._decode_snapshot(token).get("context_package_id")
        if package_id:
            view.verified_packages[identity] = package_id
    head = view.published_issue_rows.get(issue_id) or view.manager.store.row("SELECT * FROM issues WHERE issue_id=?", (issue_id,))
    if head is not None:
        view.published_issue_rows[issue_id] = {**head, "current_conclusion_id": identity,
                                             "conclusion_revision": revision, "conclusion_status": status}
    if issue_id in view.virtual_issues:
        view.virtual_issues[issue_id].update(current_conclusion_id=identity, conclusion_revision=revision, conclusion_status=status)
    view.published_evidence_uses[issue_id] = _proposal_evidence_ids(operation)
    for evidence_id in _proposal_evidence_ids(operation):
        view.publication_status_additions.setdefault(evidence_id, set()).add(status)


def _simulate_governed_conflict(view: StateView, operation: dict[str, Any]) -> None:
    from .conflict_governance import validate_resolution_binding

    domain = "field_bundle" if operation["op"] == "resolve_field_conflict" else "import"
    binding = validate_resolution_binding(view.manager.store.conn, domain, operation, state_view=view)
    conflict = binding["conflict"]
    view.integration_conflicts[operation["conflict_id"]] = {
        **conflict, "state": "needs_more_information" if operation["resolution"] == "needs_more_information" else "resolved",
        "state_revision": conflict["state_revision"] + 1, "resolution_action": operation["resolution"],
        "resolution_reason": operation.get("reason", "reviewed governed ChangeSet")}
    if operation["resolution"] in {"accept_as_new_revision", "create_competing_record"}:
        from .context_conflict_preview import plan_governed_record_resolution

        view.governed_results[operation["conflict_id"]] = plan_governed_record_resolution(
            view, operation, conflict
        )
    else:
        from .context_conflict_preview import stage_source_effects

        stage_source_effects(view, operation, conflict, result={})


def _simulate_identity_resolution(view: StateView, operation: dict[str, Any]) -> None:
    from .context_evidence_preview import stage_identity_resolution

    stage_identity_resolution(view, operation)


def _simulate_resolve_evidence_conflict(view: StateView, operation: dict[str, Any]) -> None:
    from .context_evidence_preview import stage_conflict_resolution

    stage_conflict_resolution(view, operation)


def _simulate_migrate_evidence_source(view: StateView, operation: dict[str, Any]) -> None:
    from .context_evidence_preview import stage_source_migration

    stage_source_migration(view, operation)


def _simulate_reassess_evidence(view: StateView, operation: dict[str, Any]) -> None:
    from .evidence_planner import plan_maintenance

    decision = plan_maintenance(view, operation)
    view.evidence_quality[decision["evidence_id"]] = decision["stored_quality_status"]


def _simulate_void_evidence(view: StateView, operation: dict[str, Any]) -> None:
    from .evidence_planner import plan_maintenance

    decision = plan_maintenance(view, operation)
    if not decision["existing"]:
        view.evidence_lifecycle[decision["evidence_id"]] = "void"


def _simulate_detach_evidence(view: StateView, operation: dict[str, Any]) -> None:
    from .evidence_planner import plan_maintenance

    decision = plan_maintenance(view, operation)
    key = (decision["issue_id"], decision["evidence_id"])
    view.evidence_attachment_additions.discard(key)
    view.evidence_attachment_removals.add(key)


def _simulate_create_question(view: StateView, operation: dict[str, Any]) -> None:
    from .question_planner import plan_create
    from .store import canonical_json

    decision = plan_create(view, {**operation, "_simulation": True})
    question_id = decision["question_id"] or f"preflight-question:{len(view.virtual_questions)}"
    row: dict[str, Any] = {column[1]: None for column in view.manager.store.conn.execute("PRAGMA table_info(issue_questions)")}
    row.update({
        "question_id": str(question_id),
         "issue_id": decision["issue_id"],
         "prompt": decision["prompt"],
         "motivation": decision["motivation"].strip(),
         "question_kind": decision["question_kind"],
         "priority": decision["priority"],
         "question_key": decision["question_key"],
         "status": "open", "current_revision": 1,
         "expected_evidence_json": canonical_json(decision["expected_evidence"]),
        "source_kind": operation.get("source_kind"), "source_id": operation.get("source_id"),
        "template_registration_id": operation.get("template_registration_id"),
        "template_content_hash": operation.get("template_content_hash"),
        "template_snapshot_json": canonical_json(operation.get("template_snapshot", {})),
        "status_reason": operation.get("reason", "reviewed ChangeSet"),
    })
    view.virtual_questions[str(question_id)] = row


def _simulate_transition_question(view: StateView, operation: dict[str, Any]) -> None:
    from .question_planner import plan_transition

    decision = plan_transition(view, operation)
    view.question_status[decision["question_id"]] = decision["target"]


def _simulate_answer_question(view: StateView, operation: dict[str, Any]) -> None:
    from .question_planner import plan_answer

    decision = plan_answer(view, operation)
    view.question_status[decision["question_id"]] = "answered"


def _simulate_set_relation_impact(view: StateView, operation: dict[str, Any]) -> None:
    from .issue_relation_planner import plan_impact

    decision = plan_impact(view, operation)
    if decision["hard_cycle"]:
        raise ValidationError("Hard Issue relation would create a cycle")
    view.issue_relation_impact[str(operation["relation_id"])] = str(operation["impact_policy"])
    if hasattr(view.manager, "context_maintenance"):
        relation = view.issue_relation(str(operation["relation_id"]))
        if relation is None:
            raise ValidationError("Issue relationship does not exist")
        view.stage_legacy_relation("issue", relation)


def _simulate_add_relation(view: StateView, operation: dict[str, Any]) -> None:
    from .issue_relation_planner import plan_add

    decision = plan_add(view, operation)
    consumer = decision["consumer"]
    provider = decision["provider"]
    relation_type = decision["relation_type"]
    view.new_issue_relations.add((consumer, provider, relation_type))
    impact = decision["impact_policy"]
    row: dict[str, Any] = {column[1]: None for column in view.manager.store.conn.execute("PRAGMA table_info(relations)")}
    row.update({"relation_id": f"preflight-issue-relation:{len(view.issue_relation_rows)}",
                "consumer_issue_id": consumer, "provider_issue_id": provider, "relation_type": relation_type,
                "impact_policy": impact, "active": 1, "reason": decision["reason"],
                "policy_version": view.manager.policy.version})
    view.stage_new_relation("issue", row)
    if impact == "hard":
        view.new_hard_issue_edges.add((consumer, provider))


def _simulate_issue_relation_lifecycle(view: StateView, operation: dict[str, Any]) -> None:
    from .issue_relation_planner import plan_lifecycle

    decision = plan_lifecycle(view, operation)
    if decision["hard_cycle"]:
        raise ValidationError("Reactivated hard Issue relation would create a cycle")
    view.issue_relation_active[str(operation["relation_id"])] = (
        operation["op"] == "reactivate_relation"
    )


def _simulate_evidence_relation_lifecycle(view: StateView, operation: dict[str, Any]) -> None:
    view.evidence_relation_active[str(operation["relation_id"])] = (
        operation["op"] == "reactivate_evidence_relation"
    )


def _simulate_add_evidence_relation(view: StateView, operation: dict[str, Any]) -> None:
    consumer = str(operation["consumer_evidence_id"])
    provider = str(operation["provider_evidence_id"])
    relation_type = str(operation["relation_type"])
    view.new_evidence_relations.add((consumer, provider, relation_type))
    effective = view.manager.evidence_relations.resolve_impact(
        relation_type, operation.get("impact_policy")
    )["effective"]
    row: dict[str, Any] = {column[1]: None for column in view.manager.store.conn.execute("PRAGMA table_info(evidence_relations)")}
    row.update({"relation_id": operation.get("relation_id") or f"preflight-evidence-relation:{len(view.evidence_relation_rows)}",
                "consumer_evidence_id": consumer, "provider_evidence_id": provider, "relation_type": relation_type,
                "impact_policy": effective, "active": 1, "rationale": operation.get("rationale", ""),
                "provider_snapshot_hash": view.manager.evidence_relations._snapshot_hash(view.evidence(provider)),
                "consumer_snapshot_hash": view.manager.evidence_relations._snapshot_hash(view.evidence(consumer))})
    view.stage_new_relation("evidence", row)
    if effective == "hard":
        view.new_hard_evidence_edges.add((consumer, provider))


def _simulate_context_relation(view: StateView, operation: dict[str, Any]) -> None:
    preview = view.manager.context_relations.preview(operation, state_view=view)
    version = preview["after_version"]
    view.context_relation_rows[operation["relation_id"]] = preview["after"]
    view.material_versions[version["version_id"]] = version
    view.material_heads[("context", operation["relation_id"])] = version


def _simulate_question_relation(view: StateView, operation: dict[str, Any]) -> None:
    preview = view.manager.question_relations.preview(operation, state_view=view)
    version = preview["after_version"]
    view.question_relation_rows[operation["relation_id"]] = preview["after"]
    view.material_versions[version["version_id"]] = version
    view.material_heads[("question", operation["relation_id"])] = version


def _simulate_intake_relation(view: StateView, operation: dict[str, Any]) -> None:
    preview = view.manager.intake_relations.preview(operation, state_view=view)
    version = preview["after_version"]
    view.intake_relation_rows[operation["link_id"]] = preview["after"]
    view.material_versions[version["version_id"]] = version
    view.material_heads[("intake", operation["link_id"])] = version


def _simulate_record_relation(view: StateView, operation: dict[str, Any]) -> None:
    preview = view.manager.record_relations.preview(operation, state_view=view)
    view.record_relation_rows[operation["relation_id"]] = preview["after"]
    version = preview["after_version"]
    view.material_versions[version["version_id"]] = version
    view.material_heads[("record", operation["relation_id"])] = version


def _simulate_replace_relation(view: StateView, operation: dict[str, Any]) -> None:
    preview = view.manager.relation_versions.preview(operation, state_view=view)
    view.stage_legacy_relation(preview["domain"], preview["after"])
    if preview["domain"] == "issue":
        view.issue_relation_impact[operation["relation_id"]] = preview["after"]["impact_policy"]


def _simulate_context_change(view: StateView, operation: dict[str, Any]) -> None:
    view.manager.context_maintenance.validate_change(operation, state_view=view)
    for item in operation["items"]:
        if operation["action"] == "verify":
            # A generated receipt cannot be named in another operation until
            # the caller has its real identity. Never guess that identity.
            view.selected_receipts[item["conclusion_id"]] = None
            view.verified_packages[item["conclusion_id"]] = item["package_id"]
        elif operation["action"] == "select":
            view.selected_receipts[item["conclusion_id"]] = item["receipt_id"]
            view.verified_packages.pop(item["conclusion_id"], None)
        else:
            view.receipt_eligibility[item["receipt_id"]] = operation["action"] == "restore"


def _simulate_context_rule_upgrade(view: StateView, operation: dict[str, Any]) -> None:
    preview = view.manager.context_rules.preview(operation, state_view=view)
    view.context_rule = {key: preview[key] for key in ("rule_id", "definition_json", "created_at")}


def _simulate_context_obligation(view: StateView, operation: dict[str, Any]) -> None:
    preview = view.manager.context_obligations.preview(operation, state_view=view)
    view.obligations[operation["obligation_id"]] = preview["after"]


def _simulate_evidence_applicability_decision(view: StateView, operation: dict[str, Any]) -> None:
    view.manager.evidence_applicability.changeset_planner.simulate(operation, state_view=view)


_SIMULATORS = {
    "record_relation": _simulate_record_relation,
    "intake_relation": _simulate_intake_relation,
    "question_relation": _simulate_question_relation,
    "attach_packet": _simulate_attach_packet,
    "append_work": _simulate_append_work,
    "context_obligation": _simulate_context_obligation,
    "context_rule_upgrade": _simulate_context_rule_upgrade,
    "context_change": _simulate_context_change,
    "replace_relation": _simulate_replace_relation,
    "context_relation": _simulate_context_relation,
    "evidence_applicability_decision": _simulate_evidence_applicability_decision,
    "noop": _simulate_noop,
    "governed_conflict": _simulate_governed_conflict,
    "create_issue": _simulate_create_issue,
    "attach_evidence": _simulate_attach_evidence,
    "publication": _simulate_publication,
    "void_evidence": _simulate_void_evidence,
    "reassess_evidence": _simulate_reassess_evidence,
    "migrate_evidence_source": _simulate_migrate_evidence_source,
    "resolve_evidence_conflict": _simulate_resolve_evidence_conflict,
    "resolve_evidence_identity_ambiguity": _simulate_identity_resolution,
    "detach_evidence": _simulate_detach_evidence,
    "create_question": _simulate_create_question,
    "transition_question": _simulate_transition_question,
    "answer_question": _simulate_answer_question,
    "add_relation": _simulate_add_relation,
    "set_relation_impact": _simulate_set_relation_impact,
    "issue_relation_lifecycle": _simulate_issue_relation_lifecycle,
    "evidence_relation_lifecycle": _simulate_evidence_relation_lifecycle,
    "add_evidence_relation": _simulate_add_evidence_relation,
}


def simulate_operation(view: StateView, operation: dict[str, Any]) -> None:
    definition = operation_definition(str(operation["op"]))
    _SIMULATORS[definition.simulator](view, operation)


@dataclass(frozen=True)
class ExecutionContext:
    changeset_id: str
    auth: AuthContext
    credential: str | Path
    reviews: list[dict[str, Any]]
    grant: ExecutionGrant
    operation_ordinal: int
    changeset_hash: str


class ChangeSetOperationEngine:
    """Shared validate/risk/simulate/execute dispatch for ChangeSets."""

    def __init__(self, service: Any):
        self.service = service
        self.manager: IssueManager = service.manager
        self._assert_runtime_contracts()

    def _assert_runtime_contracts(self) -> None:
        missing: list[str] = []
        for definition in OPERATION_DEFINITIONS.values():
            checks = (
                ("validator", self.service, f"_validate_{definition.validator}"),
                ("risk", self.service.risk_policy, f"_risk_{definition.risk_model}"),
                ("executor", self.service, f"_execute_{definition.executor}"),
            )
            for kind, owner, attribute in checks:
                if not callable(getattr(owner, attribute, None)):
                    missing.append(f"{definition.op}.{kind}={attribute}")
            if definition.simulator not in _SIMULATORS:
                missing.append(f"{definition.op}.simulator={definition.simulator}")
        if missing:
            raise RuntimeError(
                "Incomplete ChangeSet operation runtime contracts: " + ", ".join(missing)
            )

    def contract_manifest(self) -> dict[str, dict[str, str]]:
        return {
            op: {
                "validator": definition.validator,
                "risk_model": definition.risk_model,
                "simulator": definition.simulator,
                "executor": definition.executor,
                "base_tier": definition.base_tier,
            }
            for op, definition in OPERATION_DEFINITIONS.items()
        }

    def preflight(self, operations: list[dict[str, Any]]) -> dict[str, Any]:
        view = StateView(self.manager)
        tier = "T0"
        reasons: set[str] = set()
        samples: set[SampleKey] = set()
        for ordinal, operation in enumerate(operations):
            try:
                validate_operation_shape(operation, ordinal=ordinal)
                definition = operation_definition(str(operation["op"]))
                validator = getattr(self.service, f"_validate_{definition.validator}")
                validator(operation, state_view=view, ordinal=ordinal)
                assessment, operation_samples = self.service.risk_policy.assess_operation(
                    operation, view
                )
                view.record(ordinal=ordinal, operation=operation, risk=assessment.as_dict())
                if self.service.risk_policy.promotes(tier, assessment.tier):
                    tier = assessment.tier
                reasons.update(assessment.reasons)
                samples.update(operation_samples)
                simulate_operation(view, operation)
            except (ValidationError, ConflictError, NotFoundError) as exc:
                details = {
                    "operation_ordinal": ordinal,
                    "op": operation.get("op") if isinstance(operation, dict) else None,
                    "cause_code": exc.code,
                    **exc.details,
                }
                error_type = ConflictError if isinstance(exc, ConflictError) else ValidationError
                raise error_type(
                    f"ChangeSet operation {ordinal} preflight failed: {exc}",
                    details=details,
                ) from exc
        if len(samples) > 1:
            tier = "T3"
            reasons.add("cross-sample-change")
        if not reasons:
            reasons.add("capture-only")
        return {
            "assessment": self.service.risk_policy.assessment(tier, reasons),
            "trace": view.trace,
            "state_view": view,
        }

    def execute(
        self,
        operation: dict[str, Any],
        context: ExecutionContext,
    ) -> dict[str, Any]:
        definition = operation_definition(str(operation["op"]))
        executor = getattr(self.service, f"_execute_{definition.executor}")
        return executor(operation, context=context)


def assert_operation_registry_complete() -> None:
    schema_ops = set(CHANGESET_OPERATION_SPECS)
    runtime_ops = set(OPERATION_DEFINITIONS)
    if schema_ops != runtime_ops:
        raise RuntimeError(
            "ChangeSet operation schema/runtime registry mismatch: "
            f"schema_only={sorted(schema_ops - runtime_ops)}, "
            f"runtime_only={sorted(runtime_ops - schema_ops)}"
        )


assert_operation_registry_complete()
