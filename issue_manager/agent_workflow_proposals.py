"""Finite domain proposal operations, independent of workflow role labels."""
from __future__ import annotations

import json

from .errors import ConflictError, ValidationError


def freeze_context(manager, issue_id, auth, *, target_proposal_id=None):
    prepared = manager.prepare_refresh(issue_id, actor=auth.actor_id)
    package = prepared["context_input_package"]
    actual = package["actual_input"]
    current = prepared["current_conclusion"]
    currentness = manager.context_maintenance.show(current["conclusion_id"]) if current else None
    selected = manager.store.row(
        "SELECT receipt_id FROM basis_receipt_selections WHERE conclusion_id=?",
        (current["conclusion_id"],)) if current else None
    materials = actual.get("model_materials", actual.get("materials", {}))
    evidence_ids = set(materials.get("evidence", {}))
    sources = {}
    for evidence_id in sorted(evidence_ids):
        # Follow authoritative output linkage, never a participant-supplied locator.
        row = manager.store.row(
            "SELECT o.body,p.package_json,w.work_item_id FROM workflow_outputs o "
            "JOIN workflow_work_items w ON w.work_item_id=o.work_item_id "
            "JOIN workflow_work_packages p ON p.attempt_id=o.attempt_id "
            "WHERE o.business_object_type='evidence' AND o.business_action='add_evidence' "
            "AND o.business_object_id=? AND w.issue_id=? ORDER BY o.rowid LIMIT 1",
            (evidence_id, issue_id))
        if row:
            source_ref = json.loads(row["body"])["source_ref"]
            attachment = next((m for m in json.loads(row["package_json"])["inputs"]
                               if m["ref"] == source_ref), None)
            if attachment:
                sources[evidence_id] = dict(source_ref=source_ref, text=attachment["text"],
                    attachment_id=row["work_item_id"] + ":" + source_ref)
    rows = manager.store.rows(
        "SELECT proposal_id,proposal_hash,proposal_json,state FROM proposals WHERE issue_id=? "
        "AND state IN ('draft','validated','under_review','review_passed') ORDER BY rowid DESC LIMIT 9",
        (issue_id,))
    selected_rows = rows[:8]
    if target_proposal_id and not any(r["proposal_id"] == target_proposal_id for r in selected_rows):
        explicit = manager.store.row(
            "SELECT proposal_id,proposal_hash,proposal_json,state FROM proposals WHERE issue_id=? AND proposal_id=? "
            "AND state IN ('draft','validated','under_review','review_passed')", (issue_id, target_proposal_id))
        if explicit:
            selected_rows = [explicit, *selected_rows[:7]]
    drafts = []
    for row in selected_rows:
        payload = json.loads(row["proposal_json"])
        # Old drafts must not reintroduce Evidence excluded by the active resolver.
        if set(payload.get("evidence_refs", [])) <= evidence_ids:
            drafts.append(dict(proposal_id=row["proposal_id"], proposal_hash=row["proposal_hash"],
                               state=row["state"], proposal=payload))
    descriptor_row = manager.store.row(
        "SELECT d.definition_json FROM context_input_packages p "
        "JOIN context_descriptors d USING(descriptor_id) WHERE p.package_id=?",
        (package["package_id"],),
    )
    descriptor = json.loads(descriptor_row["definition_json"]) if descriptor_row else {}
    return dict(package_id=package["package_id"], materials=materials, descriptor=descriptor,
                evidence_sources=sources, prior_proposals=drafts,
                prior_proposals_truncated=len(rows) > 8,
                resolution_errors=package["resolution_errors"],
                current_conclusion=current, currentness=currentness,
                expected_receipt_id=selected["receipt_id"] if selected else "",
                proposal_template=prepared["proposal_template"])


def check_source(contribution, package):
    prepared = package.get("prepared_context")
    if not prepared or contribution["package_id"] != prepared["package_id"]:
        raise ValidationError("Proposal must reference this attempt's frozen context package")
    sources = prepared["materials"].get("evidence", {})
    if not set(contribution["evidence_refs"]) <= set(sources):
        raise ValidationError("Proposal Evidence is outside frozen model materials")
    if contribution["action"] == "create_verification" and not prepared["current_conclusion"]:
        raise ValidationError("Verification needs an existing frozen conclusion")
    if "revises_proposal_id" in contribution and contribution["revises_proposal_id"] not in {
            p["proposal_id"] for p in prepared.get("prior_proposals", [])}:
        raise ValidationError("Revision source is outside this attempt's frozen proposals")


def check_current(manager, package, contribution=None):
    prepared = package["prepared_context"]
    issue_id = package["input_baseline"]["issue_id"]
    manager.context_maintenance.verify_package(prepared["package_id"], issue_id)
    current = manager._issue(issue_id)
    if current["current_conclusion_id"] != package["input_baseline"]["current_conclusion_id"]:
        raise ConflictError("Conclusion changed after claim")
    if prepared["current_conclusion"]:
        row = manager.store.row("SELECT receipt_id FROM basis_receipt_selections WHERE conclusion_id=?",
                                (current["current_conclusion_id"],))
        if (row["receipt_id"] if row else "") != prepared["expected_receipt_id"]:
            raise ConflictError("Selected receipt changed after claim")
    if contribution and "revises_proposal_id" in contribution:
        frozen = next(p for p in prepared["prior_proposals"]
                      if p["proposal_id"] == contribution["revises_proposal_id"])
        current_draft = manager.store.row("SELECT proposal_hash,state FROM proposals WHERE proposal_id=?",
                                          (frozen["proposal_id"],))
        if not current_draft or any(current_draft[k] != frozen[k] for k in ("proposal_hash", "state")):
            raise ConflictError("Revision source changed after claim")


def create(manager, contribution, package, auth, key):
    """Save a pending domain object only. Validation/apply remain separate authorized steps."""
    prepared = package["prepared_context"]
    if contribution["action"] == "create_proposal":
        proposal = {**prepared["proposal_template"], **contribution["content"],
                    "evidence_refs": contribution["evidence_refs"]}
        if "revises_proposal_id" in contribution:
            parent = next(p for p in prepared["prior_proposals"]
                          if p["proposal_id"] == contribution["revises_proposal_id"])
            proposal["revision_of"] = {k: parent[k] for k in ("proposal_id", "proposal_hash")}
        # The signature covers the prepared providers/package; check without regenerating it.
        manager.proposals.verify_snapshot(proposal["basis_snapshot_token"], proposal)
        receipt = manager.proposals._create(proposal, auth=auth, idempotency_key=key)
        return "proposal", receipt["proposal_id"]
    operation = dict(op="context_change", action="verify", reason=contribution["reason"],
                     items=[dict(conclusion_id=prepared["current_conclusion"]["conclusion_id"],
                                 package_id=prepared["package_id"],
                                 expected_receipt_id=prepared["expected_receipt_id"])])
    manager.context_maintenance.validate_change(operation)
    issue_id = package["input_baseline"]["issue_id"]
    changeset = dict(changeset_version=1, intent=contribution["reason"], operations=[operation],
                     expected_revisions={issue_id: dict(
                         working_revision=package["input_baseline"]["working_revision"],
                         conclusion_revision=prepared["proposal_template"]["expected_conclusion_revision"])})
    receipt = manager.changesets._create(changeset, auth=auth, idempotency_key=key)
    return "changeset", receipt["changeset_id"]
