from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from issue_manager import IssueManager
from issue_manager.changeset_state import StateView
from issue_manager.record_planner import plan_record_create, plan_record_revision


def planner_bundle() -> dict:
    return {
        "manifest": {
            "bundle_format": "issue-manager-feature-bundle/v1",
            "namespace": "org.example.planner",
            "name": "planner-tests",
            "version": "1.0.0",
            "core_api": ">=0.8,<0.9",
            "registrations": [],
            "dependencies": [],
        },
        "registrations": [
            {
                "kind": "issue_type",
                "name": "sample",
                "definition": {"allowed_children": [], "rollup_mode": "semantic"},
            },
            {
                "kind": "record_template",
                "name": "sample-record",
                "definition": {
                    "applies_to_issue_types": ["sample"],
                    "fields": {"value": {"type": "integer", "queryable": True}},
                    "profiles": {"draft": {"required": ["value"]}},
                },
            },
        ],
    }


class RecordPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.manager = IssueManager.initialize(self.root / "ledger")
        installed = self.manager.registry.install_bundle(planner_bundle())
        self.manager.registry.activate_bundle(installed["bundle_id"])
        issue_type = self.manager.registry.resolve(
            "org.example.planner/issue_type/sample@1.0.0"
        )
        self.template = self.manager.registry.resolve(
            "org.example.planner/record_template/sample-record@1.0.0"
        )
        self.manager.create_issue(
            "sample-1", "sample", issue_type_registration_id=issue_type["registration_id"]
        )

    def tearDown(self) -> None:
        self.manager.close()
        self.temporary.cleanup()

    def test_same_overlay_plan_is_reused_without_database_side_effects(self) -> None:
        counts_before = {
            table: self.manager.store.row(f"SELECT COUNT(*) AS count FROM {table}")["count"]
            for table in ("record_instances", "record_revisions", "record_value_index")
        }
        view = StateView(self.manager)
        created = plan_record_create(
            view,
            issue_id="sample-1",
            template_reference=self.template["registration_id"],
            data={"value": 1},
        )
        revised = plan_record_revision(
            view,
            record_instance_id=created["record_instance_id"],
            expected_revision_id=created["record_revision_id"],
            data={"value": 2},
        )
        self.assertEqual(revised["from_revision_id"], created["record_revision_id"])
        self.assertEqual(
            {
                table: self.manager.store.row(f"SELECT COUNT(*) AS count FROM {table}")["count"]
                for table in counts_before
            },
            counts_before,
        )

    def test_real_application_preserves_history_and_rolls_back_on_commit_failure(self) -> None:
        created = self.manager.records.create(
            "sample-1", self.template["registration_id"], data={"value": 1}
        )
        before = {
            table: self.manager.store.row(f"SELECT COUNT(*) AS count FROM {table}")["count"]
            for table in ("record_instances", "record_revisions", "record_value_index")
        }

        self.manager.store.before_commit = lambda: (_ for _ in ()).throw(RuntimeError("abort"))
        with self.assertRaises(RuntimeError):
            self.manager.records.revise(
                created["record_instance_id"], {"value": 2},
                expected_revision_id=created["record_revision_id"],
            )
        self.manager.store.before_commit = None
        self.assertEqual(
            {
                table: self.manager.store.row(f"SELECT COUNT(*) AS count FROM {table}")["count"]
                for table in before
            },
            before,
        )

        revised = self.manager.records.revise(
            created["record_instance_id"], {"value": 2},
            expected_revision_id=created["record_revision_id"],
        )
        self.assertEqual(len(self.manager.records.history(created["record_instance_id"])), 2)
        self.assertEqual(
            self.manager.store.row(
                "SELECT number_value FROM record_value_index WHERE record_revision_id=? AND field_path='value'",
                (revised["record_revision_id"],),
            )["number_value"],
            2.0,
        )

    def test_two_connections_serialize_record_planning_and_application(self) -> None:
        created = self.manager.records.create(
            "sample-1", self.template["registration_id"], data={"value": 1}
        )
        other_ready = threading.Event()
        other_started = threading.Event()
        other_boundary = threading.Event()
        start_other = threading.Event()
        other_errors: list[BaseException] = []
        other_results: list[dict] = []

        def contender() -> None:
            other = IssueManager(self.root / "ledger")
            original_transaction = other.store.transaction

            def observed_transaction():
                other_boundary.set()
                return original_transaction()

            other.store.transaction = observed_transaction  # type: ignore[method-assign]
            other_ready.set()
            try:
                self.assertTrue(start_other.wait(5), "second connection was not released")
                other_started.set()
                other_results.append(
                    other.records.revise(
                        created["record_instance_id"],
                        {"value": 3},
                    )
                )
            except BaseException as exc:  # report worker failures in the test thread
                other_errors.append(exc)
            finally:
                other.close()

        original_plan = __import__(
            "issue_manager.record_planner", fromlist=["plan_record_revision"]
        ).plan_record_revision

        def gated_plan(*args, **kwargs):
            planned = original_plan(*args, **kwargs)
            if threading.current_thread() is not threading.main_thread():
                # A correct implementation reaches the transaction boundary
                # before this planner. The old implementation reached this
                # point first, exposing the stale-plan race.
                other_boundary.set()
            return planned

        worker = threading.Thread(target=contender, name="record-contender")
        worker.start()
        self.assertTrue(other_ready.wait(5), "second connection did not initialize")
        try:
            with (
                patch("issue_manager.record_planner.plan_record_revision", gated_plan),
            ):
                # Hold the first connection's write transaction while the
                # contender reaches its plan/transaction boundary. Under the
                # fixed implementation, the contender cannot plan until this
                # transaction commits; the old implementation planned first.
                with self.manager.store.transaction():
                    start_other.set()
                    self.assertTrue(other_started.wait(5), "second connection did not start")
                    self.assertTrue(
                        other_boundary.wait(5),
                        "second connection did not reach its transaction/planner boundary",
                    )
                    first = self.manager.records.revise(
                        created["record_instance_id"],
                        {"value": 2},
                        expected_revision_id=created["record_revision_id"],
                    )
                    self.assertEqual(first["from_revision_id"], created["record_revision_id"])
            worker.join(10)
            self.assertFalse(worker.is_alive(), "second connection did not finish")
        finally:
            worker.join(10)
        self.assertEqual(other_errors, [])
        self.assertEqual(len(other_results), 1)
        self.assertEqual(
            len(self.manager.records.history(created["record_instance_id"])), 3
        )


if __name__ == "__main__":
    unittest.main()
