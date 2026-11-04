"""Authority-based reference; deliberately shares the product selector only.

Manual scenario assertions must separately establish selector intent. No cached
root, subscription or contribution is used to construct the expected result.
"""
import json
import os
from pathlib import Path

from issue_manager.context_resolver import normalized_equal


def reference(manager):
    service = manager.context_maintenance
    local, contributions, contexts, reasons = set(), set(), {}, {}
    for node in manager.store.rows("SELECT conclusion_id,issue_id FROM conclusion_revisions"):
        identity = node["conclusion_id"]
        selected = manager.store.row(
            "SELECT definition_json FROM conclusion_context_selections "
            "JOIN context_descriptors USING(descriptor_id) WHERE conclusion_id=?", (identity,))
        descriptor = json.loads(selected["definition_json"]) if selected else service.default_descriptor(node["issue_id"])
        resolved = service.scoped_v2_resolver.resolve(descriptor)
        contexts[identity] = resolved.semantic
        contributions.update((p, identity, key) for p, key in resolved.contributions)
        receipt = manager.store.row(
            "SELECT semantic_context_json,eligible FROM basis_receipt_selections "
            "JOIN basis_receipts USING(receipt_id) JOIN context_input_packages USING(package_id) "
            "LEFT JOIN basis_receipt_eligibility USING(receipt_id) WHERE basis_receipt_selections.conclusion_id=?",
            (identity,))
        codes = [error["code"] for error in resolved.errors]
        if not receipt:
            codes.append("basis_receipt_missing")
        elif not receipt["eligible"]:
            codes.append("basis_receipt_ineligible")
        elif not normalized_equal(json.loads(receipt["semantic_context_json"]), resolved.semantic):
            codes.append("context_mismatch")
        reasons[identity] = codes
        if codes:
            local.add(identity)
    edges = {(p, c) for p, c, _ in contributions}
    dirty = set(local)
    while True:
        following = dirty | {c for p, c in edges if p in dirty}
        if following == dirty:
            break
        dirty = following
    return dict(local=local, edges=edges, contributions=contributions,
                dirty=dirty, contexts=contexts, reasons=reasons)


def record(label, value):
    directory = os.environ.get("MAINTENANCE_ACCEPTANCE_EVIDENCE")
    if directory:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)
        with (path / "scenarios.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"label": label, **value}, ensure_ascii=False,
                                    default=lambda v: sorted(v)) + "\n")


def check(test, label, roots, contributions):
    manager = test.manager
    expected = reference(manager)
    test.assertEqual(expected["local"], roots, label)
    test.assertEqual(expected["contributions"], contributions, label)
    actual = manager.store.rows("SELECT * FROM conclusion_currentness")
    test.assertEqual({r["conclusion_id"] for r in actual if r["needs_update"]}, expected["dirty"], label)
    test.assertEqual({r["conclusion_id"] for r in actual if r["local_mismatch"]}, roots, label)
    test.assertEqual({tuple(r) for r in manager.store.conn.execute(
        "SELECT provider_conclusion_id,consumer_conclusion_id,contribution_id FROM currentness_edge_contributions")},
        contributions, label)
    for row in actual:
        test.assertEqual(row["maintenance_state"], "ready", label)
        test.assertEqual([r["code"] for r in json.loads(row["reason_json"])], expected["reasons"][row["conclusion_id"]], label)
    audit = manager.context_maintenance.audit()
    test.assertTrue(audit["ok"], audit)
    record(label, {"expected": expected, "actual": actual, "audit": audit})
    return expected
