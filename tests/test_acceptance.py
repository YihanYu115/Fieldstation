from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from issue_manager.errors import ConflictError, CycleError
from issue_manager.service import IssueManager


class IssueManagerAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = Path(self.temp.name) / "issue_ledger"
        self.manager = IssueManager.initialize(self.ledger)
        self.organizer_credential = self.manager.credentials.path_for("organizer-agent")
        self.maintenance_credential = self.manager.credentials.path_for("maintenance-agent")
        self.review_credentials = [
            self.manager.credentials.path_for("review-agent-1"),
            self.manager.credentials.path_for("review-agent-2"),
        ]
        self.manager.evidence.register_platform(
            "test-platform",
            display_name="Test platform",
            capabilities=["manifest", "metadata", "preview"],
            credential=self.maintenance_credential,
        )
        executor = self.manager.credentials.issue_actor(
            actor_id="test-platform-executor",
            actor_kind="maintenance_agent",
            capabilities=set(),
            profiles={"platform-evidence-executor"},
            principal_kind="service",
            platform_id="test-platform",
            maintenance_credential=self.maintenance_credential,
        )
        self.executor_credential = executor["credential_path"]
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.manager.close)
        self._build_chain()

    def _snapshot_use(
        self, evidence_id: str, *, digest: str, artifact_id: str
    ) -> dict[str, str]:
        artifact = self.manager.artifacts.show(artifact_id)
        scoped = self.manager.artifacts.add_scoped_content(
            (self.ledger / artifact["storage_uri"]).read_bytes(),
            filename="acceptance-snapshot.bin",
            mime_type=artifact["mime_type"],
            role="frozen",
            auth=self.manager.credentials.resolve(self.executor_credential),
        )
        self.assertEqual(scoped["artifact_id"], artifact_id)
        manifest = self.manager.evidence.submit_manifest(
            evidence_id,
            {
                "manifest_version": 1,
                "platform_id": "test-platform",
                "content_identity": {"algorithm": "sha256", "digest": digest},
                "data_profile": {},
                "execution": {},
                "summary": {},
                "preview_artifact_ids": [],
                "mutable_source": False,
            },
            credential=self.executor_credential,
        )
        self.manager.evidence.attest(
            evidence_id,
            attestation_type="snapshot",
            method="acceptance fixture",
            input_snapshot={"manifest_id": manifest["manifest_id"]},
            result={"exists": True},
            manifest_id=manifest["manifest_id"],
            artifact_ids=[artifact_id],
            credential=self.executor_credential,
        )
        return {
            "evidence_id": evidence_id,
            "use_role": "support",
            "fitness": "fit_for_use",
        }

    def _build_chain(self) -> None:
        m = self.manager
        m.create_issue("sample", "sample", "Pilot sample")
        m.create_issue("q1", "qubit", "Q1", parent_issue_id="sample")
        m.create_issue("excitation", "capability", "Q1 excitation", parent_issue_id="q1")
        m.create_issue("episode", "episode", "Low-power retest", parent_issue_id="excitation")
        m.create_issue("coherence", "capability", "Q1 coherence", parent_issue_id="q1")
        m.create_issue("interaction", "interaction", "Q1-Q2 coupling", parent_issue_id="sample")
        m.add_relation("sample", "q1", "rolls_up_from")
        m.add_relation("q1", "excitation", "rolls_up_from")
        m.add_relation("excitation", "episode", "rolls_up_from")
        m.add_relation("interaction", "coherence", "depends_on")

    def _publish(
        self,
        issue_id: str,
        statement: str,
        *,
        basis: list[dict] | None = None,
        expected: int | None = None,
        refresh: bool = False,
        status: str = "provisional",
    ) -> dict:
        issue = self.manager.show_issue(issue_id)
        inputs = self.manager.context_maintenance.prepare(issue_id, basis=basis or [])
        proposal = {
            "issue_id": issue_id,
            "expected_conclusion_revision": issue["conclusion_revision"]
            if expected is None
            else expected,
            "status": status,
            "statement": statement,
            "structured_outputs": {},
            "confidence": "medium",
            "applicability": "pilot",
            "limitations": [],
            "change_summary": statement,
            "basis": basis or [],
            "basis_snapshot_token": self.manager.proposals.make_snapshot_token(
                issue_id, issue["conclusion_revision"] if expected is None else expected,
                basis or [], context_package_id=inputs["package_id"],
            ),
        }
        created = self.manager.proposals.create(proposal, credential=self.organizer_credential)
        self.manager.proposals.validate(
            created["proposal_id"], credential=self.organizer_credential
        )
        return self.manager.proposals.apply(
            created["proposal_id"], credential=self.organizer_credential
        )

    def _refresh(self, issue_id: str, statement: str) -> dict:
        package = self.manager.prepare_refresh(issue_id)
        proposal = package["proposal_template"]
        proposal["statement"] = statement
        proposal["change_summary"] = statement
        created = self.manager.proposals.create(proposal, credential=self.organizer_credential)
        self.manager.proposals.validate(
            created["proposal_id"], credential=self.organizer_credential
        )
        return self.manager.proposals.apply(
            created["proposal_id"], credential=self.organizer_credential
        )

    def _persist_review_apply(self, proposal: dict, reviews: int) -> dict:
        created = self.manager.proposals.create(proposal, credential=self.organizer_credential)
        self.manager.proposals.validate(
            created["proposal_id"], credential=self.organizer_credential
        )
        for index in range(reviews):
            self.manager.proposals.claim_review(
                created["proposal_id"], credential=self.review_credentials[index]
            )
            self.manager.proposals.submit_review(
                created["proposal_id"],
                decision="pass",
                rationale=f"independent review {index + 1}",
                evidence_sufficiency="sufficient for requested status",
                credential=self.review_credentials[index],
            )
        return self.manager.proposals.apply(
            created["proposal_id"], credential=self.organizer_credential
        )

    def test_working_entry_and_dataset_do_not_propagate(self) -> None:
        evidence = self.manager.add_evidence(
            kind="datavault_dataset",
            locator="/YuYihan/20260701_dualC::dataset=9865",
            issue_id="episode",
        )
        result = self.manager.append_work(
            "episode", "ordinary low-value attempt", evidence_refs=[evidence["evidence_id"]]
        )
        self.assertEqual(result["working_revision"], 1)
        self.assertEqual(result["conclusion_revision"], 0)
        self.assertFalse(result["propagates"])
        self.assertEqual(self.manager.show_issue("excitation")["freshness"], "fresh")
        self.assertEqual(self.manager.refresh_plan()["order"], [])

    def test_bottom_up_invalidation_and_refresh(self) -> None:
        self._publish("episode", "Initial judgment")
        self._refresh("excitation", "Initial excitation")
        self._refresh("q1", "Initial Q1")
        self._refresh("sample", "Initial sample")
        self._publish("episode", "Temporarily accept 4.6 GHz")
        self.assertEqual(self.manager.show_issue("excitation")["freshness"], "stale")
        self.assertEqual(self.manager.show_issue("q1")["currentness"]["currentness"], "needs_update")
        self.assertEqual(self.manager.show_issue("sample")["currentness"]["currentness"], "needs_update")
        self.assertEqual(self.manager.refresh_plan()["order"], ["excitation"])

        excitation_result = self._refresh("excitation", "Q1 excitation is 4.6 GHz")
        self.assertEqual(excitation_result["basis"][0]["conclusion_revision"], 2)
        self.assertEqual(self.manager.show_issue("excitation")["freshness"], "fresh")
        self.assertEqual(self.manager.show_issue("q1")["freshness"], "stale")

        self._refresh("q1", "Q1 summary reviewed")
        self.assertEqual(self.manager.show_issue("q1")["freshness"], "fresh")
        self.assertEqual(self.manager.show_issue("sample")["freshness"], "stale")

        self._refresh("sample", "Sample summary reviewed")
        self.assertEqual(self.manager.stale(), [])
        sample_conclusion = self.manager.get_current_conclusion("sample")
        self.assertEqual(sample_conclusion["basis"][0]["issue_id"], "q1")

    def test_soft_dependency_enters_impact_review_only(self) -> None:
        self._publish("coherence", "T1 has a frequency-dependent dip")
        interaction = self.manager.show_issue("interaction")
        self.assertIsNone(interaction["current_conclusion"])
        reason = self.manager.why_stale("interaction")
        self.assertEqual(reason["tasks"][0]["reason_type"], "dependency_changed")
        self.assertNotIn("wrong", str(reason).lower())

    def test_notify_relation_does_not_change_freshness_or_create_refresh_task(self) -> None:
        self.manager.create_issue(
            "observer", "investigation", "Notification-only observer", parent_issue_id="sample"
        )
        self.manager.add_relation("observer", "episode", "depends_on", impact_policy="notify")
        result = self._publish("episode", "candidate changed")
        notified = next(item for item in result["propagation"] if item["issue_id"] == "observer")
        self.assertIsNone(notified["refresh_task_id"])
        self.assertEqual(self.manager.show_issue("observer")["freshness"], "fresh")
        self.assertIsNone(
            self.manager.store.row("SELECT * FROM refresh_tasks WHERE issue_id='observer'")
        )

    def test_relation_added_after_provider_publication_creates_review_task(self) -> None:
        self._publish("episode", "published before the relation exists")
        self.manager.create_issue(
            "late-consumer", "investigation", "Late consumer", parent_issue_id="sample"
        )
        preview = self.manager.add_relation("late-consumer", "episode", "depends_on", dry_run=True)
        self.assertEqual(preview["refresh_tasks_created_now"], 1)
        self.assertTrue(
            any(
                item["issue_id"] == "late-consumer"
                for item in preview["affected_if_provider_changes_after_add"]
            )
        )
        result = self.manager.add_relation("late-consumer", "episode", "depends_on")
        self.assertIsNotNone(result["refresh_task_id"])
        self.assertIsNone(self.manager.show_issue("late-consumer")["current_conclusion"])

    def test_fast_updates_coalesce_task_but_keep_all_revisions(self) -> None:
        self._publish("episode", "revision one")
        self._publish("episode", "revision two")
        self._publish("episode", "revision three")
        tasks = self.manager.store.rows(
            "SELECT * FROM refresh_tasks WHERE issue_id='excitation' AND state IN ('pending','blocked','ready')"
        )
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["from_revision"], 0)
        self.assertEqual(tasks[0]["to_revision"], 3)
        self.assertEqual(tasks[0]["coalesced_events"], 3)
        task_events = self.manager.store.rows(
            "SELECT * FROM refresh_task_events WHERE refresh_task_id=?",
            (tasks[0]["refresh_task_id"],),
        )
        self.assertEqual(len(task_events), 3)
        self.assertEqual(len(self.manager.history("episode")["conclusions"]), 3)

    def test_optimistic_lock_rejects_stale_agent_proposal(self) -> None:
        stale = {
            "issue_id": "episode",
            "expected_conclusion_revision": 0,
            "status": "provisional",
            "statement": "prepared against revision zero",
            "structured_outputs": {},
            "limitations": [],
            "basis": [],
        }
        self._publish("episode", "another actor publishes first")
        with self.assertRaises(ConflictError):
            self.manager.validate_proposal(stale, refresh=False)

    def test_hard_cycle_dry_run_explains_and_commit_rejects(self) -> None:
        preview = self.manager.add_relation("episode", "sample", "rolls_up_from", dry_run=True)
        self.assertFalse(preview["valid"])
        self.assertEqual(preview["cycle_path"][0], "episode")
        with self.assertRaises(CycleError):
            self.manager.add_relation("episode", "sample", "rolls_up_from")

    def test_report_facing_consumer_gets_high_priority_review(self) -> None:
        self.manager.create_issue(
            "report", "report_scope", "Pilot report", parent_issue_id="sample"
        )
        self.manager.add_relation("report", "excitation", "rolls_up_from")
        self._publish("episode", "4.6 GHz provider conclusion")
        self._refresh("excitation", "4.6 GHz working conclusion")
        task = self.manager.store.row(
            "SELECT * FROM refresh_tasks WHERE issue_id='report' AND state IN ('pending','blocked','ready')"
        )
        self.assertEqual(task["priority"], 90)
        self.assertIsNone(self.manager.show_issue("report")["current_conclusion"])

        script = Path(self.temp.name) / "report_analysis.py"
        script.write_text("print('rebuild report')\n", encoding="utf-8")
        figure = Path(self.temp.name) / "report_figure.txt"
        figure.write_text("figure", encoding="utf-8")
        method = self.manager.artifacts.register_method(
            script, name="report-analysis", credential=self.maintenance_credential
        )
        artifact = self.manager.artifacts.add(
            figure, role="evidence", credential=self.maintenance_credential
        )
        self.manager.artifacts.link(
            artifact["artifact_id"],
            object_type="platform_source",
            object_id="test-platform",
            link_role="owned_by",
            credential=self.maintenance_credential,
        )
        run = self.manager.artifacts.register_run(
            method["method_id"],
            inputs=[{"type": "dataset", "id": "/pilot::dataset=1"}],
            outputs=[artifact["artifact_id"]],
            config={},
            environment={},
            credential=self.maintenance_credential,
        )
        self.manager.artifacts.freeze_run(
            run["analysis_run_id"], credential=self.maintenance_credential
        )
        evidence = self.manager.add_evidence(
            kind="artifact",
            locator=artifact["artifact_id"],
            issue_id="report",
        )
        evidence_uses = [
            self._snapshot_use(
                evidence["evidence_id"],
                digest=artifact["sha256"],
                artifact_id=artifact["artifact_id"],
            )
        ]
        package = self.manager.prepare_refresh("report")
        proposal = package["proposal_template"]
        proposal["statement"] = "Report basis manifest"
        proposal["structured_outputs"] = {
            "report_locator": "reports/pilot.md", "artifact_ids": [artifact["artifact_id"]],
        }
        proposal["evidence_refs"] = [evidence["evidence_id"]]
        proposal["evidence_uses"] = evidence_uses
        proposal["change_summary"] = "Record report basis"
        applied = self._persist_review_apply(proposal, reviews=2)
        self.assertEqual(applied["status"], "provisional")
        manifest = self.manager.report_basis("report")
        self.assertFalse(manifest["needs_review"])
        self.assertEqual(manifest["basis"][0]["conclusion_revision"], 1)
        self.assertTrue(manifest["analysis_provenance"][0]["traceable"])
        self.assertEqual(manifest["analysis_provenance"][0]["inputs"][0]["input_type"], "dataset")

        self._publish("episode", "4.61 GHz revised provider conclusion")
        self._refresh("excitation", "4.61 GHz revised conclusion")
        changed_manifest = self.manager.report_basis("report")
        self.assertTrue(changed_manifest["needs_review"])
        self.assertTrue(changed_manifest["basis"][0]["changed"])

    def test_retraction_can_preserve_historical_basis_for_audit(self) -> None:
        self._publish("episode", "episode revision one")
        self._refresh("excitation", "excitation using episode revision one")
        self._publish("episode", "episode revision two")
        current = self.manager.get_current_conclusion("excitation")
        reason = "old basis is no longer usable"
        proposal = {
            "issue_id": "excitation",
            "expected_conclusion_revision": 1,
            "status": "retracted",
            "statement": current["statement"],
            "structured_outputs": current["structured_outputs"],
            "confidence": current["confidence"],
            "applicability": current["applicability"],
            "limitations": current["limitations"],
            "evidence_refs": current["evidence_refs"],
            "change_summary": reason,
            "basis": [
                {
                    **basis,
                    "basis_mode": "historical",
                    "historical_reason": reason,
                }
                for basis in current["basis"]
            ],
        }
        result = self._persist_review_apply(proposal, reviews=1)
        self.assertEqual(result["status"], "retracted")
        current = self.manager.get_current_conclusion("excitation")
        self.assertEqual(current["basis"][0]["conclusion_revision"], 1)

    def test_doctor_detects_and_repairs_freshness_cache_drift(self) -> None:
        self.manager.store.conn.execute(
            "UPDATE issues SET freshness='blocked' WHERE issue_id='episode'"
        )
        self.manager.store.conn.commit()
        check = self.manager.doctor(fix=False)
        self.assertFalse(check["ok"])
        self.assertEqual(self.manager.show_issue("episode")["freshness"], "blocked")
        fixed = self.manager.doctor(fix=True)
        self.assertTrue(fixed["ok"])
        self.assertEqual(self.manager.show_issue("episode")["freshness"], "fresh")

    def test_export_writes_readable_projections(self) -> None:
        self._publish("episode", "4.6 GHz")
        result = self.manager.export()
        self.assertTrue((self.ledger / "exports" / "issues" / "episode.md").exists())
        self.assertTrue((self.ledger / "exports" / "tree.md").exists())
        self.assertTrue((self.ledger / "exports" / "stale.md").exists())
        graph = (self.ledger / "exports" / "graph.mmd").read_text(encoding="utf-8")
        self.assertIn("rolls_up_from:hard", graph)
        self.assertEqual(result["issue_count"], 6)


if __name__ == "__main__":
    unittest.main()
