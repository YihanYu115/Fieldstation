from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from issue_manager import IssueManager


class AgentWorkflowConcurrencyTests(unittest.TestCase):
    def test_pause_and_commit_have_one_linearized_winner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ledger"
            setup = IssueManager.initialize(root)
            setup.create_issue("race", "investigation", "Pause/commit race")
            maintenance = setup.credentials.path_for("maintenance-agent")
            human = setup.credentials.issue_actor(
                actor_id="race-human",
                actor_kind="organizer_agent",
                principal_kind="human",
                capabilities={
                    "context.read",
                    "work.write",
                    "workflow.read",
                    "workflow.manage",
                    "workflow.commit",
                },
                maintenance_credential=maintenance,
            )
            human_path = Path(human["credential_path"])
            agent_path = setup.credentials.path_for("experiment-agent")
            human_auth = setup.credentials.resolve(human_path)
            agent_auth = setup.credentials.resolve(agent_path)
            mandate = setup.workflow.create_mandate(
                goal="Race safely",
                autonomy_mode="assigned_only",
                scope={"issue_ids": ["race"], "roles": ["local_researcher"]},
                allowed_actions=["append_work"],
                budget=None,
                stop_conditions={},
                auth=human_auth,
                idempotency_key="race-mandate",
            )
            item = setup.workflow.create_work_item(
                mandate["mandate_id"],
                issue_id="race",
                role="local_researcher",
                objective="Race commit against takeover",
                acceptance=[],
                allowed_actions=["append_work"],
                dedupe_key="race-item",
                auth=human_auth,
                idempotency_key="race-item",
            )
            claimed = setup.workflow.claim(
                item["work_item_id"],
                expected_revision=1,
                lease_seconds=300,
                auth=agent_auth,
                idempotency_key="race-claim",
            )
            setup.close()

            barrier = threading.Barrier(2)
            outcomes: list[tuple[str, str]] = []
            lock = threading.Lock()

            def commit() -> None:
                manager = IssueManager(root)
                try:
                    auth = manager.credentials.resolve(agent_path)
                    barrier.wait()
                    manager.workflow.commit(
                        claimed["attempt_id"],
                        body="A fully atomic winning commit",
                        expected_mandate_revision=1,
                        expected_fence=1,
                        expected_work_item_revision=2,
                        expected_issue_working_revision=0,
                        auth=auth,
                        idempotency_key="race-commit",
                    )
                except Exception as exc:  # the loser must be an explicit conflict
                    with lock:
                        outcomes.append(("commit", exc.__class__.__name__))
                else:
                    with lock:
                        outcomes.append(("commit", "success"))
                finally:
                    manager.close()

            def pause() -> None:
                manager = IssueManager(root)
                try:
                    auth = manager.credentials.resolve(human_path)
                    barrier.wait()
                    manager.workflow.pause(
                        mandate["mandate_id"],
                        expected_revision=1,
                        takeover=True,
                        reason="Concurrent human takeover",
                        auth=auth,
                        idempotency_key="race-pause",
                    )
                except Exception as exc:
                    with lock:
                        outcomes.append(("pause", exc.__class__.__name__))
                else:
                    with lock:
                        outcomes.append(("pause", "success"))
                finally:
                    manager.close()

            threads = [threading.Thread(target=commit), threading.Thread(target=pause)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=15)
            self.assertEqual(sum(result == "success" for _, result in outcomes), 1, outcomes)

            check = IssueManager(root)
            try:
                attempt = check.store.row(
                    "SELECT status FROM workflow_attempts WHERE attempt_id=?", (claimed["attempt_id"],)
                )
                entries = check.store.row("SELECT COUNT(*) AS n FROM working_entries")["n"]
                outputs = check.store.row(
                    "SELECT COUNT(*) AS n FROM workflow_outputs WHERE business_object_id IS NOT NULL"
                )["n"]
                self.assertIn(attempt["status"], {"succeeded", "invalidated"})
                self.assertEqual(entries, 1 if attempt["status"] == "succeeded" else 0)
                self.assertEqual(outputs, entries)
            finally:
                check.close()


if __name__ == "__main__":
    unittest.main()
