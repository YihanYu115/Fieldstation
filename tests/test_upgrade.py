from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from issue_manager.errors import ConflictError, NotFoundError, PermissionError
from issue_manager.service import IssueManager
from issue_manager.store import Store


class UpgradeWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = Path(self.temp.name) / "issue_ledger"
        self.manager = IssueManager.initialize(self.ledger, context_rule="scoped-v2")
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.manager.close)
        self.organizer = self.manager.credentials.path_for("organizer-agent")
        self.review1 = self.manager.credentials.path_for("review-agent-1")
        self.review2 = self.manager.credentials.path_for("review-agent-2")
        self.maintenance = self.manager.credentials.path_for("maintenance-agent")
        self.manager.evidence.register_platform(
            "test-platform",
            display_name="Test platform",
            capabilities=["manifest", "metadata", "existence"],
            credential=self.maintenance,
        )
        executor = self.manager.credentials.issue_actor(
            actor_id="test-platform-executor",
            actor_kind="maintenance_agent",
            capabilities=set(),
            profiles={"platform-evidence-executor"},
            principal_kind="service",
            platform_id="test-platform",
            maintenance_credential=self.maintenance,
        )
        self.executor = executor["credential_path"]


    def _verified_use(self, evidence_id: str) -> dict[str, str]:
        manifest = self.manager.evidence.submit_manifest(
            evidence_id,
            {
                "manifest_version": 1,
                "platform_id": "test-platform",
                "content_identity": {},
                "data_profile": {},
                "execution": {},
                "summary": {},
                "preview_artifact_ids": [],
                "mutable_source": True,
            },
            credential=self.executor,
        )
        self.manager.evidence.attest(
            evidence_id,
            attestation_type="metadata",
            method="test adapter",
            input_snapshot={"manifest_id": manifest["manifest_id"]},
            result={"exists": True},
            manifest_id=manifest["manifest_id"],
            credential=self.executor,
        )
        return {"evidence_id": evidence_id, "use_role": "support", "fitness": "fit_for_use"}

    def _publish(self, issue_id: str, statement: str, basis: list[dict] | None = None) -> dict:
        issue = self.manager.show_issue(issue_id)
        proposal = {
            "issue_id": issue_id,
            "expected_conclusion_revision": issue["conclusion_revision"],
            "status": "provisional",
            "statement": statement,
            "structured_outputs": {},
            "limitations": [],
            "basis": basis or [],
        }
        created = self.manager.proposals.create(proposal, credential=self.organizer)
        self.manager.proposals.validate(created["proposal_id"], credential=self.organizer)
        return self.manager.proposals.apply(created["proposal_id"], credential=self.organizer)

    def test_high_impact_publish_requires_persisted_independent_review(self) -> None:
        self.manager.create_issue("episode", "episode", "Episode")
        self._publish("episode", "working conclusion")
        accepted = {
            "issue_id": "episode",
            "expected_conclusion_revision": 1,
            "status": "accepted",
            "statement": "accepted conclusion",
            "structured_outputs": {},
            "limitations": [],
            "basis": [],
        }
        with self.assertRaises(PermissionError):
            self.manager.publish_conclusion(accepted, actor="Alice")

        evidence = self.manager.add_evidence(
            kind="datavault_dataset",
            locator="/episode::dataset=1",
            issue_id="episode",
        )
        accepted["evidence_refs"] = [evidence["evidence_id"]]
        accepted["evidence_uses"] = [self._verified_use(evidence["evidence_id"])]
        created = self.manager.proposals.create(accepted, credential=self.organizer)
        proposal_id = created["proposal_id"]
        validated = self.manager.proposals.validate(proposal_id, credential=self.organizer)
        self.assertEqual(validated["state"], "under_review")
        with self.assertRaises(PermissionError):
            self.manager.proposals.submit_review(
                proposal_id,
                decision="pass",
                rationale="self review",
                evidence_sufficiency="sufficient",
                credential=self.organizer,
            )
        self.manager.proposals.claim_review(proposal_id, credential=self.review1)
        reviewed = self.manager.proposals.submit_review(
            proposal_id,
            decision="pass",
            rationale="independent scientific review",
            evidence_sufficiency="sufficient",
            credential=self.review1,
        )
        self.assertEqual(reviewed["proposal_state"], "review_passed")
        applied = self.manager.proposals.apply(proposal_id, credential=self.organizer)
        self.assertEqual(applied["status"], "accepted")
        self.assertEqual(
            self.manager.proposals.apply(proposal_id, credential=self.organizer)["conclusion_id"],
            applied["conclusion_id"],
        )

    def test_soft_basis_change_after_prepare_rejects_apply(self) -> None:
        self.manager.create_issue("provider", "episode", "Provider")
        self.manager.create_issue("consumer", "investigation", "Consumer")
        self.manager.add_relation("consumer", "provider", "depends_on", impact_policy="soft")
        self._publish("provider", "provider r1")
        package = self.manager.prepare_refresh("consumer")
        proposal = package["proposal_template"]
        proposal["statement"] = "uses provider r1"
        proposal["change_summary"] = "prepared"
        created = self.manager.proposals.create(proposal, credential=self.organizer)
        self.manager.proposals.validate(created["proposal_id"], credential=self.organizer)
        self._publish("provider", "provider r2")
        with self.assertRaises(ConflictError):
            self.manager.proposals.apply(created["proposal_id"], credential=self.organizer)

    def test_intake_idempotency_lease_and_bidirectional_trace(self) -> None:
        self.manager.create_issue("sample", "sample", "Sample")
        self.manager.create_issue("q1", "qubit", "Q1", parent_issue_id="sample")
        self.manager.create_issue("excitation", "capability", "Excitation", parent_issue_id="q1")
        packet = {
            "packet_version": 1,
            "request_id": "run-42-packet-1",
            "target": {"sample": "dualC", "qubits": ["q1"]},
            "topic": "excitation",
            "question": "Which candidate is the transition?",
            "actions": ["spectroscopy", "rabihigh"],
            "observations": ["4.6 GHz gives regular Rabi oscillation"],
            "interpretation": ["temporarily prefer 4.6 GHz"],
            "alternatives": ["4.1/4.5 GHz may be multiphoton"],
            "confidence": "medium",
            "next_action": "low-power retest",
            "evidence": [{"kind": "datavault_dataset", "locator": "/dualC::dataset=9865"}],
        }
        experiment = self.manager.credentials.path_for("experiment-agent")
        first = self.manager.intake.submit(packet, credential=experiment)
        replay = self.manager.intake.submit(packet, credential=experiment)
        self.assertTrue(replay["idempotent_replay"])
        self.assertEqual(first["packet_id"], replay["packet_id"])

        issued = self.manager.credentials.issue_actor(
            actor_id="organizer-agent-2",
            actor_kind="organizer_agent",
            capabilities={"triage.manage"},
            maintenance_credential=self.maintenance,
        )
        self.manager.intake.claim(first["packet_id"], credential=self.organizer)
        with self.assertRaises(ConflictError):
            self.manager.intake.claim(first["packet_id"], credential=issued["credential_path"])
        attached = self.manager.intake.create_episode(
            first["packet_id"],
            parent_issue_id="excitation",
            issue_id="multipeak",
            title="Multi-peak episode",
            credential=self.organizer,
        )
        self.manager.intake.disposition(
            first["packet_id"],
            "no_impact",
            reason="Packet was attached as working evidence only",
            issue_id="multipeak",
            credential=self.organizer,
        )
        self.manager.intake.complete(first["packet_id"], credential=self.organizer)
        history = self.manager.history("multipeak")
        self.assertEqual(history["working_entries"][0]["source_packet_id"], first["packet_id"])
        shown = self.manager.intake.show(first["packet_id"])
        self.assertEqual(shown["attached_issue_id"], "multipeak")
        self.assertEqual(shown["evidence"][0]["evidence_id"], attached["evidence_ids"][0])

    def test_resolver_context_and_artifact_integrity(self) -> None:
        self.manager.scaffold(sample="dualC", qubits=["q1"])
        resolved = self.manager.resolve(sample="dualC", qubit="q1", topic="excitation")
        self.assertEqual(resolved["status"], "unique")
        self.assertEqual(resolved["match"]["issue_id"], "dualC-q1-excitation")
        context = self.manager.context(
            resolved["match"]["issue_id"], "design-experiment", max_nodes=2
        )
        self.assertIn("preflight", context)
        self.assertLessEqual(len(context["dependency_closure"]["nodes"]), 2)

        source = Path(self.temp.name) / "figure.txt"
        source.write_text("figure payload", encoding="utf-8")
        first = self.manager.artifacts.add(source, role="evidence", credential=self.maintenance)
        second = self.manager.artifacts.add(source, role="evidence", credential=self.maintenance)
        self.assertEqual(first["artifact_id"], second["artifact_id"])
        self.assertTrue(second["deduplicated"])
        self.manager.artifacts.freeze(first["artifact_id"], credential=self.maintenance)
        self.assertTrue(self.manager.artifacts.verify(first["artifact_id"])["ok"])
        stored = self.manager.artifacts.show(first["artifact_id"])
        (self.ledger / stored["storage_uri"]).write_text("corrupt", encoding="utf-8")
        self.assertFalse(self.manager.doctor()["ok"])

    def test_backup_restore_round_trip(self) -> None:
        self.manager.create_issue("before", "episode", "Before")
        expected_tables = {
            "evidence_applicability_decision_versions",
            "evidence_applicability_decision_heads",
        }
        current_tables = {
            row[0]
            for row in self.manager.store.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        self.assertTrue(expected_tables <= current_tables)
        backup = Store.create_backup(self.ledger, label="round-trip")
        self.assertTrue(Store.verify_backup(self.ledger, backup["backup_id"])["ok"])
        self.manager.create_issue("after", "episode", "After")
        self.manager.close()
        Store.restore_backup(self.ledger, backup["backup_id"])
        self.manager = IssueManager(self.ledger)
        try:
            self.assertIsNotNone(self.manager.show_issue("before"))
            restored_tables = {
                row[0]
                for row in self.manager.store.conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            self.assertTrue(expected_tables <= restored_tables)
            self.assertTrue(
                self.manager.context_rules.active()["rule_id"].startswith("context-currentness/scoped-v2:")
            )
            with self.assertRaises(NotFoundError):
                self.manager.show_issue("after")
        finally:
            self.manager.close()


if __name__ == "__main__":
    unittest.main()
