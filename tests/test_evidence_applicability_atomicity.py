from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from issue_manager.errors import ConflictError
from issue_manager.service import IssueManager


class EvidenceApplicabilityAtomicityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = IssueManager.initialize(Path(self.temp.name) / "ledger")
        self.store = self.manager.store
        self.organizer = self.manager.credentials.path_for("organizer-agent")
        self.manager.create_issue("atomic-issue", "investigation", scope={"sample": "atomic"})
        self.target_id = self.manager.add_evidence(
            kind="external", locator="urn:atomic:target", issue_id="atomic-issue"
        )["evidence_id"]
        self.basis_id = self.manager.add_evidence(
            kind="external", locator="urn:atomic:basis", issue_id="atomic-issue"
        )["evidence_id"]

    def tearDown(self):
        self.manager.close()
        self.temp.cleanup()

    def _definition(self, effect="exclude"):
        target = self.store.row(
            "SELECT semantic_revision,current_proof_id,current_manifest_id FROM evidence_refs WHERE evidence_id=?",
            (self.target_id,),
        )
        basis = self.store.row(
            "SELECT semantic_revision,current_proof_id,current_manifest_id FROM evidence_refs WHERE evidence_id=?",
            (self.basis_id,),
        )
        basis_snapshot = {
            "semantic_revision": int(basis["semantic_revision"]),
            "proof_id": basis["current_proof_id"],
            "manifest_id": basis["current_manifest_id"],
        }
        return {
            "scope": {"kind": "issue_conclusion", "issue_id": "atomic-issue"},
            "target": {
                "kind": "evidence_version", "evidence_id": self.target_id,
                "binding": "fixed", "semantic_revision": int(target["semantic_revision"]),
                "proof_id": target["current_proof_id"], "manifest_id": target["current_manifest_id"],
            },
            "effect": effect,
            "basis": [{"kind": "evidence_version", "evidence_id": self.basis_id,
                       **basis_snapshot, "snapshot": basis_snapshot}],
        }

    def _operation(self, key="atomic-key", effect="exclude"):
        return {
            "op": "evidence_applicability_decision", "action": "add", "decision_key": key,
            "expected_version_id": "", "expected_active": False,
            "definition": self._definition(effect), "reason": "Atomic Q write test",
        }

    def _create_and_validate(self, operation, *, intent="atomic test"):
        created = self.manager.changesets.create(
            {"changeset_version": 1, "intent": intent, "operations": [operation]},
            credential=self.organizer,
        )
        self.manager.changesets.validate(created["changeset_id"], credential=self.organizer)
        return created

    def test_every_q_write_fault_rolls_back_version_head_and_operation_audit(self):
        fault_points = (
            "evidence_applicability.before_version_insert",
            "evidence_applicability.after_version_insert",
            "evidence_applicability.before_head_write",
            "evidence_applicability.after_head_write",
            "evidence_applicability.before_audit",
            "evidence_applicability.after_audit",
        )
        for index, fault_point in enumerate(fault_points):
            with self.subTest(fault_point=fault_point):
                operation = self._operation(key=f"fault-{index}")
                created = self._create_and_validate(operation)

                def inject(point):
                    if point == fault_point:
                        raise RuntimeError(f"injected {point}")

                self.store.fault_injector = inject
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    self.manager.changesets.apply(created["changeset_id"], credential=self.organizer)
                self.store.fault_injector = None
                self.assertIsNone(self.store.row(
                    "SELECT decision_version_id FROM evidence_applicability_decision_versions WHERE decision_key=?",
                    (f"fault-{index}",),
                ))
                self.assertIsNone(self.store.row(
                    "SELECT decision_key FROM evidence_applicability_decision_heads WHERE decision_key=?",
                    (f"fault-{index}",),
                ))
                self.assertEqual(self.store.row(
                    "SELECT COUNT(*) AS n FROM audit_events WHERE object_type='evidence_applicability_decision' "
                    "AND object_id=?", (f"fault-{index}",),
                )["n"], 0)

    def test_same_idempotency_key_rejects_different_changeset_content(self):
        first = self._create_and_validate(self._operation("idem-one"), intent="first Q payload")
        first_result = self.manager.changesets.apply(
            first["changeset_id"], credential=self.organizer, idempotency_key="same-q-idempotency"
        )
        replay = self.manager.changesets.apply(
            first["changeset_id"], credential=self.organizer, idempotency_key="same-q-idempotency"
        )
        self.assertEqual({key: value for key, value in replay.items() if key != "idempotent_replay"}, first_result)
        self.assertTrue(replay["idempotent_replay"])

        second = self._create_and_validate(self._operation("idem-two", effect="include"), intent="different Q payload")
        with self.assertRaises(ConflictError):
            self.manager.changesets.apply(
                second["changeset_id"], credential=self.organizer, idempotency_key="same-q-idempotency"
            )
        self.assertIsNone(self.store.row(
            "SELECT decision_key FROM evidence_applicability_decision_heads WHERE decision_key='idem-two'"
        ))

    def test_failed_replace_or_lifecycle_head_update_rolls_back_to_old_version(self):
        initial = self._create_and_validate(self._operation("head-update-fault"))
        self.manager.changesets.apply(initial["changeset_id"], credential=self.organizer)
        replace_operation = {
            "op": "evidence_applicability_decision", "action": "replace",
            "decision_key": "head-update-fault", "expected_version_id": "applicability:head-update-fault:1",
            "expected_active": True, "definition": self._definition("include"),
            "reason": "Try a replacement that will roll back",
        }
        replace = self._create_and_validate(replace_operation)

        def fail_after_head(point):
            if point == "evidence_applicability.after_head_write":
                raise RuntimeError("fail after head update")

        self.store.fault_injector = fail_after_head
        with self.assertRaisesRegex(RuntimeError, "after head update"):
            self.manager.changesets.apply(replace["changeset_id"], credential=self.organizer)
        self.store.fault_injector = None
        head = self.store.row(
            "SELECT decision_version_id,active,head_revision FROM evidence_applicability_decision_heads "
            "WHERE decision_key='head-update-fault'"
        )
        self.assertEqual(dict(head), {
            "decision_version_id": "applicability:head-update-fault:1", "active": 1, "head_revision": 1,
        })
        self.assertEqual(self.store.row(
            "SELECT COUNT(*) AS n FROM evidence_applicability_decision_versions "
            "WHERE decision_key='head-update-fault'"
        )["n"], 1)

        disable = {
            "op": "evidence_applicability_decision", "action": "disable",
            "decision_key": "head-update-fault", "expected_version_id": "applicability:head-update-fault:1",
            "expected_active": True, "reason": "Try a disable that will roll back",
        }
        disable_cs = self._create_and_validate(disable)
        self.store.fault_injector = fail_after_head
        with self.assertRaisesRegex(RuntimeError, "after head update"):
            self.manager.changesets.apply(disable_cs["changeset_id"], credential=self.organizer)
        self.store.fault_injector = None
        after_disable = self.store.row(
            "SELECT decision_version_id,active,head_revision FROM evidence_applicability_decision_heads "
            "WHERE decision_key='head-update-fault'"
        )
        self.assertEqual(dict(after_disable), dict(head))

    def test_same_decision_key_cannot_add_different_definition_or_leave_orphan_version(self):
        first = self._create_and_validate(self._operation("duplicate-key", effect="exclude"))
        self.manager.changesets.apply(first["changeset_id"], credential=self.organizer)
        with self.assertRaises(ConflictError):
            self.manager.changesets.create(
                {"changeset_version": 1, "intent": "conflicting key", "operations": [
                    self._operation("duplicate-key", effect="include")
                ]},
                credential=self.organizer,
            )
        self.assertEqual(self.store.row(
            "SELECT COUNT(*) AS n FROM evidence_applicability_decision_versions WHERE decision_key='duplicate-key'"
        )["n"], 1)


if __name__ == "__main__":
    unittest.main()
