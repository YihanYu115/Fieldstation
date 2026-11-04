from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from issue_manager.errors import (
    ValidationError,
)
from issue_manager.schema import SCHEMA_VERSION
from issue_manager.service import IssueManager
from issue_manager.store import Store


class V073MigrationTests(unittest.TestCase):
    def test_backup_transaction_and_request_defensive_branches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            self.assertEqual(Store.list_backups(missing), [])
            invalid_manifest = missing / "backups" / "backup_invalid" / "manifest.json"
            invalid_manifest.parent.mkdir(parents=True)
            invalid_manifest.write_text("{not-json", encoding="utf-8", newline="\n")
            self.assertTrue(Store.list_backups(missing)[0]["invalid_manifest"])

            root = Path(directory) / "ledger"
            manager = IssueManager.initialize(root)
            source = Path(directory) / "artifact.txt"
            source.write_text("artifact", encoding="utf-8", newline="\n")
            try:
                artifact = manager.artifacts.add(
                    source,
                    role="evidence",
                    credential=manager.credentials.path_for("maintenance-agent"),
                )
                backup = Store.create_backup(root, mode="full", label="coverage")
                backed_object = root / "backups" / backup["backup_id"] / artifact["storage_uri"]
                backed_object.write_text("tampered", encoding="utf-8", newline="\n")
                verified = Store.verify_backup(root, backup["backup_id"])
                self.assertIn(artifact["artifact_id"], verified["artifact_mismatches"])
                with self.assertRaises(ValidationError):
                    Store.restore_backup(root, backup["backup_id"])

                live_object = root / artifact["storage_uri"]
                live_object.unlink()
                with self.assertRaises(ValidationError):
                    Store.create_backup(root, mode="full", label="missing-object")

                with manager.store.transaction() as conn:
                    with self.assertRaisesRegex(RuntimeError, "nested rollback"):
                        with manager.store.transaction():
                            raise RuntimeError("nested rollback")
                    conn.execute("SELECT 1")

                payload = {"request": "state"}
                run_id = manager.store.row(
                    "SELECT run_id FROM agent_runs WHERE actor_id='organizer-agent' "
                    "AND ended_at IS NULL LIMIT 1"
                )["run_id"]
                with manager.store.transaction() as conn:
                    manager.store.api_request_begin(
                        conn,
                        request_id="request-in-progress",
                        idempotency_key="state-in-progress",
                        actor_id="organizer-agent",
                        run_id=run_id,
                        method="POST",
                        route="/state",
                        operation="state.test",
                        payload=payload,
                    )
                self.assertEqual(
                    manager.store.api_request_lookup(
                        actor_id="organizer-agent",
                        run_id=run_id,
                        idempotency_key="state-in-progress",
                        payload=payload,
                    )["state"],
                    "in_progress",
                )
                with manager.store.transaction() as conn:
                    conn.execute(
                        "UPDATE api_requests SET state='failed' WHERE request_id='request-in-progress'"
                    )
                self.assertIsNone(
                    manager.store.api_request_lookup(
                        actor_id="organizer-agent",
                        run_id=run_id,
                        idempotency_key="state-in-progress",
                        payload=payload,
                    )
                )

                with manager.store.transaction() as conn:
                    conn.execute("DELETE FROM audit_events")
                self.assertEqual(
                    manager.store.verify_audit_chain()[0]["code"],
                    "audit_event_count_mismatch",
                )
            finally:
                manager.close()

            with mock.patch.object(
                Store,
                "verify_backup",
                return_value={"ok": True, "schema_version": SCHEMA_VERSION + 1},
            ):
                with self.assertRaises(ValidationError):
                    Store.restore_backup(root, "old-schema")
