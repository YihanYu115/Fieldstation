"""Read-only currentness over the ancestor region of a simulated conclusion."""

from __future__ import annotations

import json

from .context_resolver import normalized_equal


def is_current(view, conclusion_id):
    """A conclusion is clean iff none of its reachable predecessors is a root.

    Traverse direct dependencies with a visited set. In particular an unrooted
    cycle is clean; cached dirty labels are never used as roots. No persistent
    cache, receipt, or maintenance revision is written by this query.
    """
    if not conclusion_id:
        return False
    manager = view.manager
    pending, seen = [conclusion_id], set()
    while pending:
        identity = pending.pop()
        if identity in seen:
            continue
        seen.add(identity)
        conclusion = view.published_conclusions.get(identity) or manager.store.row(
            "SELECT issue_id FROM conclusion_revisions WHERE conclusion_id=?", (identity,))
        if not conclusion:
            return False
        package_id = view.verified_packages.get(identity)
        if package_id is None:
            selected = manager.store.row("SELECT receipt_id FROM basis_receipt_selections WHERE conclusion_id=?", (identity,))
            receipt_id = view.selected_receipts.get(identity, selected["receipt_id"] if selected else None)
            receipt = manager.store.row(
                "SELECT r.package_id,e.eligible FROM basis_receipts r JOIN basis_receipt_eligibility e USING(receipt_id) "
                "WHERE r.receipt_id=? AND r.conclusion_id=?", (receipt_id, identity)) if receipt_id else None
            if not receipt or not view.receipt_eligibility.get(receipt_id, receipt["eligible"]):
                return False
            package_id = receipt["package_id"]
        package = manager.store.row(
            "SELECT p.semantic_context_json,d.definition_json FROM context_input_packages p "
            "JOIN context_descriptors d USING(descriptor_id) WHERE package_id=?", (package_id,))
        if not package:
            return False
        definition = json.loads(package["definition_json"])
        if identity not in view.verified_packages and identity not in view.selected_receipts:
            selected_context = manager.store.row(
                "SELECT d.definition_json FROM conclusion_context_selections s JOIN context_descriptors d USING(descriptor_id) "
                "WHERE s.conclusion_id=?", (identity,))
            definition = (json.loads(selected_context["definition_json"]) if selected_context
                          else manager.context_maintenance.default_descriptor(conclusion["issue_id"]))
        resolved = manager.context_maintenance.scoped_v2_resolver.resolve(
            definition, tolerate_errors=True, state_view=view)
        if resolved.errors or not resolved.complete or not normalized_equal(
                resolved.semantic, json.loads(package["semantic_context_json"])):
            return False
        pending.extend(provider for provider, _ in resolved.contributions)
    return True
