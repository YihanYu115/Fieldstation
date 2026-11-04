from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from issue_manager import IssueManager
from issue_manager.errors import ConflictError, PermissionError


class WorkflowFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "ledger"
        self.manager = IssueManager.initialize(self.root)
        self.manager.create_issue("workflow-issue", "investigation", "Workflow issue")
        self.manager.create_issue("outside-issue", "investigation", "Outside issue")
        self.maintenance = self.manager.credentials.path_for("maintenance-agent")
        human = self.manager.credentials.issue_actor(
            actor_id="workflow-human",
            actor_kind="organizer_agent",
            principal_kind="human",
            capabilities={
                "context.read",
                "work.write",
                "workflow.read",
                "workflow.manage",
                "workflow.commit",
            },
            maintenance_credential=self.maintenance,
        )
        self.human_path = Path(human["credential_path"])
        self.human = self.manager.credentials.resolve(self.human_path)
        self.agent_path = self.manager.credentials.path_for("experiment-agent")
        self.agent = self.manager.credentials.resolve(self.agent_path)

    def tearDown(self) -> None:
        self.manager.close()
        self.temporary.cleanup()

    def mandate(self, *, mode: str = "assigned_only", budget=None):
        return self.manager.workflow.create_mandate(
            goal="Produce a bounded project note",
            autonomy_mode=mode,
            scope={"issue_ids": ["workflow-issue"], "roles": sorted(
                {
                    "material_curator",
                    "local_researcher",
                    "conclusion_maintainer",
                    "scope_planner",
                    "reviewer",
                }
            )},
            allowed_actions=["append_work"],
            budget=budget,
            stop_conditions={"stop_when": "accepted"},
            auth=self.human,
            idempotency_key=f"mandate-{mode}-{budget}",
        )

    def item(self, mandate_id: str, *, key: str = "assigned-one"):
        return self.manager.workflow.create_work_item(
            mandate_id,
            issue_id="workflow-issue",
            role="local_researcher",
            objective="Compute and record a small result",
            acceptance=["partial contribution retained", "final contribution uses latest state"],
            allowed_actions=["append_work"],
            dedupe_key=key,
            auth=self.human,
            idempotency_key="create-" + key,
        )


class AgentWorkflowTests(WorkflowFixture):


    def test_pause_takeover_partial_commit_and_resume(self) -> None:
        mandate = self.mandate()
        item = self.item(mandate["mandate_id"])
        claimed = self.manager.workflow.claim(
            item["work_item_id"],
            expected_revision=1,
            lease_seconds=300,
            auth=self.agent,
            idempotency_key="claim-first",
        )
        checkpoint = self.manager.workflow.checkpoint(
            claimed["attempt_id"],
            body="Agent draft before human takeover",
            expected_mandate_revision=1,
            expected_fence=1,
            expected_work_item_revision=2,
            auth=self.agent,
            idempotency_key="checkpoint-first",
        )
        self.assertTrue(checkpoint["output_id"].startswith("workflow_output_"))

        paused = self.manager.workflow.pause(
            mandate["mandate_id"],
            expected_revision=1,
            takeover=True,
            reason="Human will add an observed partial result",
            auth=self.human,
            idempotency_key="take-over",
        )
        self.assertEqual(paused["status"], "taken_over")
        self.assertEqual(paused["fence"], 2)
        with self.assertRaises((ConflictError, PermissionError)):
            self.manager.workflow.commit(
                claimed["attempt_id"],
                body="Late output from the fenced worker",
                expected_mandate_revision=1,
                expected_fence=1,
                expected_work_item_revision=2,
                expected_issue_working_revision=0,
                auth=self.agent,
                idempotency_key="late-commit",
            )
        self.assertEqual(
            self.manager.store.row(
                "SELECT COUNT(*) AS n FROM working_entries WHERE issue_id='workflow-issue'"
            )["n"],
            0,
        )

        partial = self.manager.workflow.human_commit_partial(
            item["work_item_id"],
            body="Human measured the first half: value=21.",
            expected_mandate_revision=2,
            expected_work_item_revision=3,
            expected_issue_working_revision=0,
            auth=self.human,
            idempotency_key="human-partial",
        )
        replay = self.manager.workflow.human_commit_partial(
            item["work_item_id"],
            body="Human measured the first half: value=21.",
            expected_mandate_revision=2,
            expected_work_item_revision=3,
            expected_issue_working_revision=0,
            auth=self.human,
            idempotency_key="human-partial",
        )
        self.assertEqual(partial["entry_id"], replay["entry_id"])
        self.assertTrue(replay["idempotent_replay"])

        resumed = self.manager.workflow.resume(
            mandate["mandate_id"],
            expected_revision=3,
            reason="Continue from the human contribution",
            auth=self.human,
            idempotency_key="resume-after-human",
        )
        second = self.manager.workflow.claim(
            item["work_item_id"],
            expected_revision=5,
            lease_seconds=300,
            auth=self.agent,
            idempotency_key="claim-second",
        )
        package = second["package"]
        self.assertEqual(package["input_baseline"]["working_revision"], 1)
        self.assertEqual(
            [output["body"] for output in package["prior_outputs"]],
            ["Agent draft before human takeover", "Human measured the first half: value=21."],
        )
        self.assertEqual(second["mandate_fence"], resumed["fence"])

        completed = self.manager.workflow.commit(
            second["attempt_id"],
            body="Agent continued from value=21 and completed the result: value=42.",
            expected_mandate_revision=4,
            expected_fence=3,
            expected_work_item_revision=6,
            expected_issue_working_revision=1,
            auth=self.agent,
            idempotency_key="final-commit",
        )
        replay = self.manager.workflow.commit(
            second["attempt_id"],
            body="Agent continued from value=21 and completed the result: value=42.",
            expected_mandate_revision=4,
            expected_fence=3,
            expected_work_item_revision=6,
            expected_issue_working_revision=1,
            auth=self.agent,
            idempotency_key="final-commit",
        )
        self.assertEqual(completed["entry_id"], replay["entry_id"])
        self.assertEqual(
            self.manager.store.row(
                "SELECT COUNT(*) AS n FROM working_entries WHERE issue_id='workflow-issue'"
            )["n"],
            2,
        )
        reviewed = self.manager.workflow.review_work_item(
            item["work_item_id"],
            decision="pass",
            expected_revision=7,
            retry=False,
            reason="Both parts are present",
            auth=self.human,
            idempotency_key="accept-final",
        )
        self.assertEqual(reviewed["acceptance_status"], "passed")

    def test_related_input_change_rejects_attempt_but_unrelated_change_does_not(self) -> None:
        mandate = self.mandate()
        item = self.item(mandate["mandate_id"])
        claimed = self.manager.workflow.claim(
            item["work_item_id"],
            expected_revision=1,
            lease_seconds=300,
            auth=self.agent,
            idempotency_key="claim-stale",
        )
        self.manager.append_work("outside-issue", "Unrelated note")
        accepted = self.manager.workflow.commit(
            claimed["attempt_id"],
            body="Result unaffected by the other Issue",
            expected_mandate_revision=1,
            expected_fence=1,
            expected_work_item_revision=2,
            expected_issue_working_revision=0,
            auth=self.agent,
            idempotency_key="commit-unrelated",
        )
        self.assertEqual(accepted["status"], "succeeded")

        second_item = self.item(mandate["mandate_id"], key="assigned-two")
        second = self.manager.workflow.claim(
            second_item["work_item_id"],
            expected_revision=1,
            lease_seconds=300,
            auth=self.agent,
            idempotency_key="claim-related",
        )
        self.manager.append_work("workflow-issue", "Concurrent human contribution")
        rejected = self.manager.workflow.commit(
            second["attempt_id"],
            body="Stale result",
            expected_mandate_revision=2,
            expected_fence=1,
            expected_work_item_revision=2,
            expected_issue_working_revision=1,
            auth=self.agent,
            idempotency_key="commit-related",
        )
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["reason"], "input_stale")

    def test_autonomy_modes_scope_and_budget(self) -> None:
        advise = self.mandate(mode="advise_only")
        proposal = self.manager.workflow.propose_work_item(
            advise["mandate_id"],
            issue_id="outside-issue",
            role="scope_planner",
            objective="Suggest a related investigation",
            acceptance=[],
            dedupe_key="outside-suggestion",
            auth=self.agent,
            idempotency_key="outside-suggestion",
        )
        self.assertEqual(proposal["status"], "proposed")
        proposed = self.manager.workflow.show_work_item(proposal["work_item_id"], auth=self.human)
        self.assertIn("outside mandate scope", proposed["stop_reason"])

        assigned = self.mandate(mode="assigned_only")
        with self.assertRaises(PermissionError):
            self.manager.workflow.create_work_item(
                assigned["mandate_id"],
                issue_id="workflow-issue",
                role="local_researcher",
                objective="Agent-created item must be rejected",
                acceptance=[],
                allowed_actions=["append_work"],
                dedupe_key="agent-not-allowed",
                auth=self.agent,
                idempotency_key="agent-not-allowed",
            )

        bounded = self.mandate(
            mode="bounded_autonomy",
            budget={
                "max_work_items": 1,
                "max_attempts": 2,
                "max_commits": 1,
                "max_runtime_seconds": 60,
                "max_context_bytes": 100_000,
            },
        )
        created = self.manager.workflow.create_work_item(
            bounded["mandate_id"],
            issue_id="workflow-issue",
            role="material_curator",
            objective="Autonomously prepare one bounded item",
            acceptance=[],
            allowed_actions=["append_work"],
            dedupe_key="bounded-one",
            auth=self.agent,
            idempotency_key="bounded-one",
        )
        self.assertEqual(created["status"], "ready")
        blocked = self.manager.workflow.create_work_item(
            bounded["mandate_id"],
            issue_id="workflow-issue",
            role="reviewer",
            objective="This exceeds the work item budget",
            acceptance=[],
            allowed_actions=["append_work"],
            dedupe_key="bounded-two",
            auth=self.agent,
            idempotency_key="bounded-two",
        )
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(
            self.manager.workflow.show_mandate(bounded["mandate_id"], auth=self.human)["status"],
            "blocked",
        )

    def test_restart_expiry_budget_stop_and_acceptance_retry_are_persistent(self) -> None:
        mandate = self.mandate(
            budget={
                "max_work_items": 2,
                "max_attempts": 2,
                "max_commits": 2,
                "max_runtime_seconds": 3,
                "max_context_bytes": 100_000,
            }
        )
        item = self.item(mandate["mandate_id"])
        claimed = self.manager.workflow.claim(
            item["work_item_id"],
            expected_revision=1,
            lease_seconds=300,
            auth=self.agent,
            idempotency_key="claim-before-restart",
        )
        self.manager.store.conn.execute(
            "UPDATE workflow_attempts SET lease_until='2000-01-01T00:00:00+00:00' WHERE attempt_id=?",
            (claimed["attempt_id"],),
        )
        self.manager.store.conn.commit()
        self.manager.close()
        self.manager = IssueManager(self.root)
        self.human = self.manager.credentials.resolve(self.human_path)
        self.agent = self.manager.credentials.resolve(self.agent_path)
        expired = self.manager.workflow.reconcile_expired(
            mandate["mandate_id"], auth=self.human, idempotency_key="recover-expired"
        )
        self.assertEqual(expired["expired_attempt_ids"], [claimed["attempt_id"]])
        recovered = self.manager.workflow.show_work_item(item["work_item_id"], auth=self.human)
        self.assertEqual(recovered["status"], "ready")

        second = self.manager.workflow.claim(
            item["work_item_id"],
            expected_revision=3,
            lease_seconds=300,
            auth=self.agent,
            idempotency_key="claim-after-restart",
        )
        blocked = self.manager.workflow.renew(
            second["attempt_id"],
            expected_mandate_revision=1,
            expected_fence=1,
            expected_work_item_revision=4,
            lease_seconds=300,
            runtime_seconds_delta=4,
            context_bytes_delta=0,
            auth=self.agent,
            idempotency_key="exhaust-runtime",
        )
        self.assertEqual(blocked["status"], "blocked")
        persisted = self.manager.workflow.show_mandate(mandate["mandate_id"], auth=self.human)
        self.assertEqual(persisted["status"], "blocked")
        self.assertEqual(persisted["fence"], 2)

        retry_mandate = self.mandate()
        retry_item = self.item(retry_mandate["mandate_id"], key="review-retry")
        retry_claim = self.manager.workflow.claim(
            retry_item["work_item_id"],
            expected_revision=1,
            lease_seconds=300,
            auth=self.agent,
            idempotency_key="review-retry-claim",
        )
        self.manager.workflow.commit(
            retry_claim["attempt_id"],
            body="Candidate result that needs correction",
            expected_mandate_revision=1,
            expected_fence=1,
            expected_work_item_revision=2,
            expected_issue_working_revision=0,
            auth=self.agent,
            idempotency_key="review-retry-commit",
        )
        rejected = self.manager.workflow.review_work_item(
            retry_item["work_item_id"],
            decision="fail",
            expected_revision=3,
            retry=True,
            reason="Acceptance check found a correctable gap",
            auth=self.human,
            idempotency_key="review-retry-reject",
        )
        self.assertEqual(rejected["status"], "ready")
        self.assertEqual(rejected["acceptance_status"], "failed")

    def test_business_and_workflow_rows_rollback_together(self) -> None:
        mandate = self.mandate()
        item = self.item(mandate["mandate_id"])
        claimed = self.manager.workflow.claim(
            item["work_item_id"],
            expected_revision=1,
            lease_seconds=300,
            auth=self.agent,
            idempotency_key="claim-fault",
        )
        original = self.manager.append_work

        def fail_after_business_write(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("injected after ledger write")

        self.manager.append_work = fail_after_business_write  # type: ignore[method-assign]
        with self.assertRaisesRegex(RuntimeError, "injected"):
            self.manager.workflow.commit(
                claimed["attempt_id"],
                body="Must roll back",
                expected_mandate_revision=1,
                expected_fence=1,
                expected_work_item_revision=2,
                expected_issue_working_revision=0,
                auth=self.agent,
                idempotency_key="faulted-commit",
            )
        self.manager.append_work = original  # type: ignore[method-assign]
        self.assertEqual(self.manager.store.row("SELECT COUNT(*) AS n FROM working_entries")["n"], 0)
        self.assertEqual(self.manager.store.row("SELECT COUNT(*) AS n FROM workflow_outputs")["n"], 0)
        self.assertEqual(
            self.manager.store.row(
                "SELECT status FROM workflow_attempts WHERE attempt_id=?", (claimed["attempt_id"],)
            )["status"],
            "claimed",
        )


if __name__ == "__main__":
    unittest.main()
