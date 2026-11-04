from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from issue_manager.errors import ConflictError, ValidationError
from issue_manager.service import IssueManager
from issue_manager.store import now


class EvidenceApplicabilityChangeSetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = IssueManager.initialize(Path(self.temp.name) / "ledger")
        self.store = self.manager.store
        self.organizer = self.manager.credentials.path_for("organizer-agent")
        self.reviewers = [
            self.manager.credentials.path_for("review-agent-1"),
            self.manager.credentials.path_for("review-agent-2"),
        ]
        self.manager.create_issue("issue-a", "investigation", scope={"sample": "A"})
        self.target_id = self.manager.add_evidence(
            kind="external", locator="urn:applicability:target", issue_id="issue-a"
        )["evidence_id"]
        self.basis_id = self.manager.add_evidence(
            kind="external", locator="urn:applicability:basis", issue_id="issue-a"
        )["evidence_id"]

    def tearDown(self):
        self.manager.close()
        self.temp.cleanup()

    def _evidence_basis(self, evidence_id: str | None = None):
        evidence_id = evidence_id or self.basis_id
        row = self.store.row(
            "SELECT semantic_revision,current_proof_id,current_manifest_id FROM evidence_refs WHERE evidence_id=?",
            (evidence_id,),
        )
        snapshot = {
            "semantic_revision": int(row["semantic_revision"]),
            "proof_id": row["current_proof_id"],
            "manifest_id": row["current_manifest_id"],
        }
        return {
            "kind": "evidence_version",
            "evidence_id": evidence_id,
            **snapshot,
            "snapshot": snapshot,
        }

    def _definition(self, *, effect="exclude", scope="issue-a", target_id=None):
        target_id = target_id or self.target_id
        row = self.store.row(
            "SELECT semantic_revision,current_proof_id,current_manifest_id FROM evidence_refs WHERE evidence_id=?",
            (target_id,),
        )
        return {
            "scope": {"kind": "issue_conclusion", "issue_id": scope},
            "target": {
                "kind": "evidence_version",
                "evidence_id": target_id,
                "binding": "fixed",
                "semantic_revision": int(row["semantic_revision"]),
                "proof_id": row["current_proof_id"],
                "manifest_id": row["current_manifest_id"],
            },
            "effect": effect,
            "basis": [self._evidence_basis()],
        }

    def _op(self, action, key="decision-a", *, expected_version="", expected_active=False,
            definition=None, reason=None):
        operation = {
            "op": "evidence_applicability_decision",
            "action": action,
            "decision_key": key,
            "expected_version_id": expected_version,
            "expected_active": expected_active,
            "reason": reason or f"Reviewed applicability {action}",
        }
        if definition is not None:
            operation["definition"] = definition
        return operation

    def _create(self, operations):
        return self.manager.changesets.create(
            {"changeset_version": 1, "intent": "Q write test", "operations": operations},
            credential=self.organizer,
        )

    def _apply(self, operations, *, idempotency_key=None):
        created = self._create(operations)
        checked = self.manager.changesets.validate(created["changeset_id"], credential=self.organizer)
        required = checked["risk"]["required_reviews"]
        for reviewer in self.reviewers[:required]:
            self.manager.changesets.claim_review(created["changeset_id"], credential=reviewer)
            self.manager.changesets.submit_review(
                created["changeset_id"], decision="pass", rationale="Reviewed Q risk",
                credential=reviewer,
            )
        result = self.manager.changesets.apply(
            created["changeset_id"], credential=self.organizer,
            idempotency_key=idempotency_key,
        )
        return created, checked, result

    def _head(self, key="decision-a"):
        return self.store.row(
            "SELECT v.*,h.active,h.head_revision FROM evidence_applicability_decision_heads h "
            "JOIN evidence_applicability_decision_versions v USING(decision_key,decision_version_id) "
            "WHERE h.decision_key=?", (key,),
        )

    def test_four_actions_write_versions_heads_audit_and_frozen_qualification(self):
        add = self._op("add", definition=self._definition(effect="exclude"))
        created, checked, applied = self._apply([add], idempotency_key="q-add-once")
        self.assertEqual(checked["risk"]["tier"], "T1")
        first = self._head()
        self.assertEqual(first["decision_version_id"], "applicability:decision-a:1")
        self.assertEqual(first["active"], 1)
        qualified = json.loads(first["qualification_json"])
        changeset_row = self.store.row(
            "SELECT created_run_id FROM changesets WHERE changeset_id=?", (created["changeset_id"],)
        )
        self.assertEqual(qualified, {
            "actor_id": "organizer-agent",
            "run_id": changeset_row["created_run_id"],
            "capability": "evidence.applicability.write",
            "changeset_id": created["changeset_id"],
            "changeset_hash": created["changeset_hash"],
            "risk_tier": "T1",
            "review_ids": [],
            "rule_id": "evidence-applicability/v1",
            "validation_results": {name: True for name in ("scope", "target", "basis", "capability", "risk", "reviews")},
        })
        self.assertEqual(self.manager.evidence_applicability.projection(
            scope_issue_id="issue-a", evidence_ids=[self.target_id]
        )["excluded"], [self.target_id])
        replay = self.manager.changesets.apply(
            created["changeset_id"], credential=self.organizer, idempotency_key="q-add-once"
        )
        self.assertEqual({key: value for key, value in replay.items() if key != "idempotent_replay"}, applied)
        self.assertTrue(replay["idempotent_replay"])

        replacement = self._op(
            "replace", expected_version=first["decision_version_id"], expected_active=True,
            definition=self._definition(effect="include"),
        )
        self._apply([replacement])
        current = self._head()
        self.assertEqual(current["decision_version_id"], "applicability:decision-a:2")
        self.assertEqual(current["previous_version_id"], first["decision_version_id"])
        self.assertEqual(current["head_revision"], 2)

        disable = self._op("disable", expected_version=current["decision_version_id"], expected_active=True)
        self._apply([disable])
        current = self._head()
        self.assertEqual(current["active"], 0)
        self.assertEqual(current["head_revision"], 3)

        enable = self._op("enable", expected_version=current["decision_version_id"], expected_active=False)
        self._apply([enable])
        current = self._head()
        self.assertEqual(current["active"], 1)
        self.assertEqual(current["head_revision"], 4)
        self.assertEqual(self.store.row(
            "SELECT COUNT(*) AS n FROM audit_events WHERE object_type='evidence_applicability_decision' "
            "AND object_id='decision-a'"
        )["n"], 4)

    def test_same_batch_add_replace_and_add_disable_match_database_projection(self):
        add = self._op("add", key="batch-replace", definition=self._definition(effect="exclude"))
        replace = self._op(
            "replace", key="batch-replace", expected_version="applicability:batch-replace:1",
            expected_active=True, definition=self._definition(effect="include"),
        )
        ops = [add, replace]
        simulated = self.manager.changesets._preflight_operations(ops)["state_view"].applicability_projection(
            "issue-a", [self.target_id]
        )
        _, _, applied = self._apply(ops)
        actual = self.manager.evidence_applicability.projection(
            scope_issue_id="issue-a", evidence_ids=[self.target_id]
        )
        self.assertEqual(simulated, actual)
        self.assertEqual(actual["included"], [self.target_id])
        self.assertEqual(applied["results"][1]["decision_version_id"], "applicability:batch-replace:2")

        add = self._op("add", key="batch-disable", definition=self._definition(effect="exclude"))
        disable = self._op(
            "disable", key="batch-disable", expected_version="applicability:batch-disable:1",
            expected_active=True,
        )
        ops = [add, disable]
        simulated = self.manager.changesets._preflight_operations(ops)["state_view"].applicability_projection(
            "issue-a", [self.target_id]
        )
        self._apply(ops)
        actual = self.manager.evidence_applicability.projection(
            scope_issue_id="issue-a", evidence_ids=[self.target_id]
        )
        self.assertEqual(simulated, actual)
        self.assertEqual(actual["included"], [self.target_id])

    def test_replace_then_enable_uses_overlay_version_and_active_cas(self):
        self._apply([self._op("add", definition=self._definition())])
        self._apply([self._op("disable", expected_version="applicability:decision-a:1", expected_active=True)])
        replace = self._op(
            "replace", expected_version="applicability:decision-a:1", expected_active=False,
            definition=self._definition(effect="exclude"),
        )
        enable = self._op(
            "enable", expected_version="applicability:decision-a:2", expected_active=False,
        )
        self._apply([replace, enable])
        head = self._head()
        self.assertEqual(head["decision_version_id"], "applicability:decision-a:2")
        self.assertEqual(head["active"], 1)
        self.assertEqual(head["head_revision"], 4)
        self.assertEqual(self.manager.evidence_applicability.projection(
            scope_issue_id="issue-a", evidence_ids=[self.target_id]
        )["excluded"], [self.target_id])

    def test_stale_head_target_and_basis_are_rejected_during_locked_apply(self):
        self._apply([self._op("add", definition=self._definition())])
        stale_replace = self._op(
            "replace", expected_version="applicability:decision-a:1", expected_active=True,
            definition=self._definition(effect="include"),
        )
        stale_cs = self._create([stale_replace])
        self.manager.changesets.validate(stale_cs["changeset_id"], credential=self.organizer)
        self._apply([self._op(
            "replace", expected_version="applicability:decision-a:1", expected_active=True,
            definition=self._definition(effect="include"),
        )],)
        with self.assertRaises(ConflictError):
            self.manager.changesets.apply(stale_cs["changeset_id"], credential=self.organizer)

        target_row = self.store.row(
            "SELECT semantic_revision,current_proof_id,current_manifest_id FROM evidence_refs WHERE evidence_id=?",
            (self.target_id,),
        )
        stale_target_op = self._op("add", key="stale-target", definition=self._definition())
        stale_target_cs = self._create([stale_target_op])
        self.manager.changesets.validate(stale_target_cs["changeset_id"], credential=self.organizer)
        self.store.conn.execute(
            "UPDATE evidence_refs SET semantic_revision=semantic_revision+1 WHERE evidence_id=?", (self.target_id,)
        )
        with self.assertRaises(ConflictError):
            self.manager.changesets.apply(stale_target_cs["changeset_id"], credential=self.organizer)
        self.store.conn.execute(
            "UPDATE evidence_refs SET semantic_revision=? WHERE evidence_id=?",
            (target_row["semantic_revision"], self.target_id),
        )

        # Use an unproved current Evidence revision so a mutation after review
        # invalidates the exact typed basis snapshot during the locked recheck.
        self.store.conn.execute(
            "UPDATE evidence_refs SET current_proof_id=NULL,current_manifest_id=NULL WHERE evidence_id=?",
            (self.basis_id,),
        )
        stale_basis_op = self._op("add", key="stale-basis", definition=self._definition())
        stale_basis_cs = self._create([stale_basis_op])
        self.manager.changesets.validate(stale_basis_cs["changeset_id"], credential=self.organizer)
        self.store.conn.execute(
            "UPDATE evidence_refs SET semantic_revision=semantic_revision+1 WHERE evidence_id=?", (self.basis_id,)
        )
        with self.assertRaises(ConflictError):
            self.manager.changesets.apply(stale_basis_cs["changeset_id"], credential=self.organizer)

    def test_client_cannot_forge_qualification_or_derived_fields(self):
        for field in ("qualification", "state", "freshness", "currentness", "needs_update"):
            operation = self._op("add", key=f"forged-{field}", definition=self._definition())
            operation[field] = {"trusted": True}
            with self.subTest(field=field), self.assertRaises(ValidationError):
                self.manager.changesets._preflight_operations([operation])

    def test_tiered_and_symmetric_risk_rules(self):
        policy = self.manager.changesets.risk_policy
        include = self._op("add", key="risk", definition=self._definition(effect="include"))
        exclude = self._op("add", key="risk", definition=self._definition(effect="exclude"))
        self.assertEqual(policy.assess({"operations": [include]}).tier, "T1")
        self.assertEqual(policy.assess({"operations": [include]}).tier,
                         policy.assess({"operations": [exclude]}).tier)

        self.store.conn.execute(
            "INSERT INTO conclusion_revisions(conclusion_id,issue_id,revision_number,status,statement,"
            "change_summary,created_at,created_by,policy_version) VALUES (?,?,1,'draft','draft',?,?,?,?)",
            ("risk-conclusion-draft", "issue-a", "risk fixture", now(), "organizer-agent", self.manager.policy.version),
        )
        self.assertEqual(policy.assess({"operations": [include]}).tier, "T1")
        for revision, status in enumerate(("accepted", "disputed", "retracted", "superseded"), start=2):
            self.store.conn.execute(
                "INSERT INTO conclusion_revisions(conclusion_id,issue_id,revision_number,status,statement,"
                "change_summary,created_at,created_by,policy_version) VALUES (?,?,?,?,?,?,?,?,?)",
                (f"risk-conclusion-{status}", "issue-a", revision, status, status,
                 "risk fixture", now(), "organizer-agent", self.manager.policy.version),
            )
        self.assertEqual(policy.assess({"operations": [include]}).tier, "T2")
        self.store.conn.execute(
            "INSERT INTO conclusion_revisions(conclusion_id,issue_id,revision_number,status,statement,"
            "change_summary,created_at,created_by,policy_version) VALUES (?,?,6,'canonical','canonical',?,?,?,?)",
            ("risk-conclusion-canonical", "issue-a", "risk fixture", now(), "organizer-agent", self.manager.policy.version),
        )
        self.assertEqual(policy.assess({"operations": [include]}).tier, "T3")
        self.manager.create_issue("report-issue", "report_scope", scope={"sample": "A"})
        report = self._op(
            "add", key="report-facing", definition=self._definition(scope="report-issue")
        )
        self.assertEqual(policy.assess({"operations": [report]}).tier, "T3")

        self.manager.create_issue("issue-b", "investigation", scope={"sample": "B"})
        self.store.conn.execute(
            "INSERT INTO issue_evidence(issue_id,evidence_id,attached_at,attached_by) VALUES (?,?,?,?)",
            ("issue-b", self.target_id, now(), "organizer-agent"),
        )
        cross_sample = self._op("add", key="cross-sample", definition=self._definition(scope="issue-a"))
        self.assertEqual(policy.assess({"operations": [cross_sample]}).tier, "T3")

    def test_t3_review_receipts_are_frozen_and_do_not_write_currentness(self):
        self.manager.create_issue("report-for-qualification", "report_scope", scope={"sample": "A"})
        currentness_before = self.store.rows("SELECT * FROM conclusion_currentness ORDER BY conclusion_id")
        freshness_before = self.store.row("SELECT freshness FROM issues WHERE issue_id='report-for-qualification'")
        operation = self._op(
            "add", key="reviewed-t3", definition=self._definition(scope="report-for-qualification")
        )
        created, checked, _ = self._apply([operation])
        self.assertEqual(checked["risk"]["tier"], "T3")
        decision = self.manager.evidence_applicability.list(
            scope_issue_id="report-for-qualification"
        )[0]
        self.assertEqual(len(decision["qualification"]["review_ids"]), 2)
        self.assertEqual(decision["qualification"]["changeset_hash"], created["changeset_hash"])
        self.assertEqual(decision["qualification"]["risk_tier"], "T3")
        self.assertEqual(decision["validation_errors"], [])
        self.assertEqual(
            self.store.rows("SELECT * FROM conclusion_currentness ORDER BY conclusion_id"),
            currentness_before,
        )
        self.assertEqual(
            self.store.row("SELECT freshness FROM issues WHERE issue_id='report-for-qualification'"),
            freshness_before,
        )

    def test_registry_schema_is_strict_and_runtime_is_complete(self):
        manifest = self.manager.changesets.operation_engine.contract_manifest()
        self.assertIn("evidence_applicability_decision", manifest)
        self.assertEqual(manifest["evidence_applicability_decision"]["validator"], "evidence_applicability_decision")
        schema = self.manager.changesets.operation_guide(
            "evidence_applicability_decision",
            auth=self.manager.credentials.resolve(self.organizer, "changeset.submit"),
        )["schema"]
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["action"]["enum"], ["add", "replace", "disable", "enable"])


if __name__ == "__main__":
    unittest.main()
