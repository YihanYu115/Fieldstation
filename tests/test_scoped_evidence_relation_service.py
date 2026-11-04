from __future__ import annotations

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from issue_manager import IssueManager
from issue_manager.direct_split_boundary import snapshot
from issue_manager.errors import (
    ConflictError,
    IdempotencyConflictError,
    PermissionError,
    ValidationError,
)


class ScopedEvidenceRelationServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.manager = IssueManager.initialize(Path(self.temp.name) / "ledger")
        self.manager.create_issue("scope", "investigation", "Scope")
        self.auth = self.manager.credentials.resolve(
            self.manager.credentials.path_for("organizer-agent"), "evidence.relation.write"
        )
        self.read_auth = self.manager.credentials.resolve(
            self.manager.credentials.path_for("organizer-agent"), "context.read"
        )
        self.a = self.manager.add_evidence(kind="external", locator="urn:s2:a", issue_id="scope")["evidence_id"]
        self.b = self.manager.add_evidence(kind="external", locator="urn:s2:b")["evidence_id"]

    def tearDown(self) -> None:
        self.manager.close()
        self.temp.cleanup()

    def tokens(self) -> tuple[str, str]:
        return (
            self.manager.scoped_evidence_relations.binding(self.a, auth=self.read_auth)["token"],
            self.manager.scoped_evidence_relations.binding(self.b, auth=self.read_auth)["token"],
        )

    def create(self, key: str = "create") -> dict:
        source, target = self.tokens()
        return self.manager.scoped_evidence_relations.create(
            scope_issue_id="scope", source_evidence_id=self.a, target_evidence_id=self.b,
            relation_type="refutes", rationale="bounded reason", auth=self.auth,
            expected_source_token=source, expected_target_token=target,
            idempotency_key=key,
        )

    def test_create_show_history_and_scope_isolation(self) -> None:
        result = self.create()
        self.assertEqual(result["revision"], 1)
        shown = self.manager.scoped_evidence_relations.show(result["relation_id"], auth=self.read_auth)
        self.assertTrue(shown["binding_current"])
        history = self.manager.scoped_evidence_relations.history(result["relation_id"], auth=self.read_auth)
        self.assertEqual([item["revision"] for item in history["items"]], [1])
        self.assertEqual(self.manager.store.conn.execute(
            "SELECT COUNT(*) FROM scoped_evidence_relation_heads"
        ).fetchone()[0], 1)

    def test_same_endpoints_can_have_multiple_relation_identities(self) -> None:
        first = self.create("one")
        second = self.manager.scoped_evidence_relations.create(
            scope_issue_id="scope", source_evidence_id=self.a, target_evidence_id=self.b,
            relation_type="supports", rationale="second identity", auth=self.auth,
            expected_source_token=self.tokens()[0], expected_target_token=self.tokens()[1],
            idempotency_key="two",
        )
        self.assertNotEqual(first["relation_id"], second["relation_id"])

    def test_binding_changes_make_create_and_rebind_stale(self) -> None:
        source, target = self.tokens()
        self.manager.store.conn.execute(
            "UPDATE evidence_refs SET content_hash='changed' WHERE evidence_id=?", (self.a,)
        )
        with self.assertRaises(ConflictError):
            self.manager.scoped_evidence_relations.create(
                scope_issue_id="scope", source_evidence_id=self.a, target_evidence_id=self.b,
                relation_type="refutes", rationale="stale", auth=self.auth,
                expected_source_token=source, expected_target_token=target, idempotency_key="stale",
            )

    def test_lifecycle_is_full_revision_chain_and_expected_head_is_cas(self) -> None:
        first = self.create()
        second = self.manager.scoped_evidence_relations.deactivate(
            first["relation_id"], expected_version_id=first["version_id"], reason="withdraw",
            auth=self.auth, idempotency_key="deactivate",
        )
        self.assertEqual(second["revision"], 2)
        with self.assertRaises(ConflictError):
            self.manager.scoped_evidence_relations.reactivate(
                first["relation_id"], expected_version_id=first["version_id"], reason="bad",
                auth=self.auth, idempotency_key="wrong-head",
            )
        third = self.manager.scoped_evidence_relations.reactivate(
            first["relation_id"], expected_version_id=second["version_id"], reason="restore",
            auth=self.auth, idempotency_key="reactivate",
        )
        self.assertEqual(third["revision"], 3)
        rows = self.manager.store.rows(
            "SELECT revision,previous_version_id FROM scoped_evidence_relation_versions "
            "WHERE relation_id=? ORDER BY revision", (first["relation_id"],)
        )
        self.assertEqual([(row["revision"], row["previous_version_id"]) for row in rows],
                         [(1, None), (2, first["version_id"]), (3, second["version_id"])])

    def test_unchanged_transition_still_requires_head_and_records_replay(self) -> None:
        first = self.create()
        unchanged = self.manager.scoped_evidence_relations.reactivate(
            first["relation_id"], expected_version_id=first["version_id"], reason="already active",
            auth=self.auth, idempotency_key="same",
        )
        self.assertTrue(unchanged["unchanged"])
        self.assertEqual(self.manager.scoped_evidence_relations.reactivate(
            first["relation_id"], expected_version_id=first["version_id"], reason="already active",
            auth=self.auth, idempotency_key="same",
        ), unchanged)

    def test_outer_failure_rolls_back_transition_and_its_receipt(self) -> None:
        first = self.create()
        arguments = dict(
            expected_version_id=first["version_id"], reason="withdraw",
            auth=self.auth, idempotency_key="outer-rollback",
        )
        with self.assertRaisesRegex(RuntimeError, "abort outer transaction"):
            with self.manager.store.transaction():
                self.manager.scoped_evidence_relations.deactivate(first["relation_id"], **arguments)
                raise RuntimeError("abort outer transaction")

        shown = self.manager.scoped_evidence_relations.show(first["relation_id"], auth=self.read_auth)
        self.assertTrue(shown["active"])
        self.assertEqual(shown["version_id"], first["version_id"])
        history = self.manager.scoped_evidence_relations.history(first["relation_id"], auth=self.read_auth)
        self.assertEqual([item["revision"] for item in history["items"]], [1])
        retried = self.manager.scoped_evidence_relations.deactivate(first["relation_id"], **arguments)
        self.assertFalse(retried["active"])
        self.assertEqual(retried["revision"], 2)
        self.assertEqual(self.manager.scoped_evidence_relations.deactivate(
            first["relation_id"], **arguments
        ), retried)

    def test_split_boundary_ignores_unrelated_transitive_edges(self) -> None:
        first = self.create()
        with self.manager.store.read_transaction():
            before = snapshot(self.manager, self.a, auth=self.read_auth)
        self.assertEqual([r["relation_id"] for r in before["scoped_relations"]], [first["relation_id"]])
        third = self.manager.add_evidence(kind="external", locator="urn:s2:c")["evidence_id"]
        target_token = self.manager.scoped_evidence_relations.binding(third, auth=self.read_auth)["token"]
        self.manager.scoped_evidence_relations.create(
            scope_issue_id="scope", source_evidence_id=self.b, target_evidence_id=third,
            relation_type="depends_on", rationale="transitive edge", auth=self.auth,
            expected_source_token=self.tokens()[1], expected_target_token=target_token,
            idempotency_key="transitive",
        )
        with self.manager.store.read_transaction():
            after = snapshot(self.manager, self.a, auth=self.read_auth)
        self.assertEqual(before["snapshot"], after["snapshot"])
        self.assertEqual({e["evidence_id"] for e in after["evidence"]}, {self.a, self.b})

    def test_split_boundary_does_not_disclose_unreadable_neighbor(self) -> None:
        self.create()
        original = self.manager.evidence.require_read_access

        def authorize(identity, auth):
            if identity == self.b:
                raise PermissionError("private " + identity)
            original(identity, auth)

        with patch.object(self.manager.evidence, "require_read_access", side_effect=authorize):
            with self.manager.store.read_transaction():
                result = snapshot(self.manager, self.a, auth=self.read_auth)
        self.assertTrue(result["snapshot"])

    def test_browse_neighbors_redacts_unreadable_relation_identity(self) -> None:
        from issue_manager.browse_service import BrowseService

        relation = self.create()
        original = self.manager.evidence.require_read_access

        def authorize(identity, auth):
            if identity == self.b:
                raise PermissionError("private " + identity)
            original(identity, auth)

        with patch.object(self.manager.evidence, "require_read_access", side_effect=authorize):
            result = BrowseService(self.manager).read("neighbors", self.a, auth=self.read_auth)
        self.assertEqual(result["items"], [{"layer": "scoped-v2", "restricted": True,
                                            "diagnostic": "read_forbidden"}])
        self.assertNotIn(self.b, str(result))
        self.assertNotIn(relation["relation_id"], str(result))

    def test_same_idempotency_key_with_different_payload_is_rejected(self) -> None:
        self.create("same-key")
        with self.assertRaises(IdempotencyConflictError):
            source, target = self.tokens()
            self.manager.scoped_evidence_relations.create(
                scope_issue_id="scope", source_evidence_id=self.a, target_evidence_id=self.b,
                relation_type="refutes", rationale="different", auth=self.auth,
                expected_source_token=source, expected_target_token=target, idempotency_key="same-key",
            )

    def test_revise_only_allows_limited_fields_and_rebinds_explicitly(self) -> None:
        first = self.create()
        revised = self.manager.scoped_evidence_relations.revise(
            first["relation_id"], expected_version_id=first["version_id"], rationale="updated",
            auth=self.auth, idempotency_key="revise",
        )
        self.assertEqual(revised["revision"], 2)
        self.assertEqual(revised["source_evidence_id"], self.a)
        unchanged = self.manager.scoped_evidence_relations.revise(
            first["relation_id"], expected_version_id=revised["version_id"],
            auth=self.auth, idempotency_key="unchanged-revise",
        )
        self.assertTrue(unchanged["unchanged"])

    def test_invalid_structure_is_rejected_without_rows(self) -> None:
        source, target = self.tokens()
        with self.assertRaises(ValidationError):
            self.manager.scoped_evidence_relations.create(
                scope_issue_id="scope", source_evidence_id=self.a, target_evidence_id=self.b,
                relation_type="not-a-kind", rationale="bad", auth=self.auth,
                expected_source_token=source, expected_target_token=target, idempotency_key="bad",
            )
        self.assertEqual(self.manager.store.conn.execute(
            "SELECT COUNT(*) FROM scoped_evidence_relation_versions"
        ).fetchone()[0], 0)

    def test_hard_dependency_cycle_is_preserved_for_the_solver_across_scopes(self) -> None:
        self.manager.create_issue("other-scope", "investigation", "Other scope")
        source, target = self.tokens()
        first = self.manager.scoped_evidence_relations.create(
            scope_issue_id="scope", source_evidence_id=self.a, target_evidence_id=self.b,
            relation_type="depends_on", rationale="hard edge", auth=self.auth,
            expected_source_token=source, expected_target_token=target, idempotency_key="hard-1",
        )
        second = self.manager.scoped_evidence_relations.create(
            scope_issue_id="other-scope", source_evidence_id=self.b, target_evidence_id=self.a,
            relation_type="depends_on", rationale="cycle", auth=self.auth,
            expected_source_token=target, expected_target_token=source, idempotency_key="hard-2",
        )
        self.assertEqual(first["impact_policy"], "hard")
        self.assertEqual(second["impact_policy"], "hard")
        preview = self.manager.scoped_evidence_relations.preview_selection(
            scope_issue_id="scope", seed_evidence_ids=[self.a], maximum_nodes=10,
            maximum_relations=10, auth=self.read_auth,
        )
        statuses = {item["candidate_id"]: item["status"] for item in preview["selection"]["candidates"]}
        self.assertEqual(statuses[self.a], "unresolved")
        self.assertEqual(statuses[self.b], "unresolved")

    def test_self_relation_is_stored_and_self_refutation_is_not_a_write_error(self) -> None:
        token = self.manager.scoped_evidence_relations.binding(self.a, auth=self.read_auth)["token"]
        relation = self.manager.scoped_evidence_relations.create(
            scope_issue_id="scope", source_evidence_id=self.a, target_evidence_id=self.a,
            relation_type="refutes", rationale="self challenge retained for review", auth=self.auth,
            expected_source_token=token, expected_target_token=token, idempotency_key="self-refutes",
        )
        preview = self.manager.scoped_evidence_relations.preview_selection(
            scope_issue_id="scope", seed_evidence_ids=[self.a], maximum_nodes=10,
            maximum_relations=10, auth=self.read_auth,
        )
        states = {item["candidate_id"]: item["status"] for item in preview["selection"]["candidates"]}
        self.assertEqual(states[self.a], "unresolved")
        self.assertIn(relation["relation_id"], {item["relation_id"] for item in preview["projection"]["qualification_edges"]})

    def test_preview_keeps_stale_saved_binding_and_does_not_implicitly_rebind(self) -> None:
        relation = self.create()
        self.manager.store.conn.execute(
            "UPDATE evidence_refs SET content_hash='changed' WHERE evidence_id=?", (self.a,)
        )
        preview = self.manager.scoped_evidence_relations.preview_selection(
            scope_issue_id="scope", seed_evidence_ids=[self.b], maximum_nodes=10,
            maximum_relations=10, auth=self.read_auth,
        )
        selected = {item["candidate_id"]: item for item in preview["selection"]["candidates"]}
        self.assertEqual(selected[self.b]["status"], "included")
        self.assertTrue(any(item["code"] == "refutation_binding_mismatch" for item in preview["discovery"]["diagnostics"]))
        self.assertFalse(self.manager.scoped_evidence_relations.show(relation["relation_id"], auth=self.read_auth)["binding_current"])

    def test_binding_token_changes_for_all_version_basis_fields(self) -> None:
        before = self.manager.scoped_evidence_relations.binding(self.a, auth=self.read_auth)["token"]
        updates = {
            "semantic_revision": 1,
            "current_proof_id": self.manager.store.row(
                "SELECT current_proof_id FROM evidence_refs WHERE evidence_id=?", (self.b,)
            )["current_proof_id"],
            "content_hash": "hash_changed",
            "lifecycle_status": "void",
            "quality_status": "questionable",
        }
        for field, value in updates.items():
            self.manager.store.conn.execute(f"UPDATE evidence_refs SET {field}=? WHERE evidence_id=?", (value, self.a))
            after = self.manager.scoped_evidence_relations.binding(self.a, auth=self.read_auth)["token"]
            self.assertNotEqual(before, after, field)
            before = after

    def test_revise_to_hard_allows_cycle_for_the_solver(self) -> None:
        first = self.create("soft-edge")
        reverse = self.manager.scoped_evidence_relations.create(
            scope_issue_id="scope", source_evidence_id=self.b, target_evidence_id=self.a,
            relation_type="refutes", impact_policy="hard", rationale="hard reverse", auth=self.auth,
            expected_source_token=self.tokens()[1], expected_target_token=self.tokens()[0], idempotency_key="hard-reverse",
        )
        self.assertEqual(reverse["impact_policy"], "hard")
        revised = self.manager.scoped_evidence_relations.revise(
            first["relation_id"], expected_version_id=first["version_id"], impact_policy="hard",
            auth=self.auth, idempotency_key="make-hard",
        )
        self.assertEqual(revised["revision"], 2)

    def test_version_rows_and_invalid_head_moves_are_database_protected(self) -> None:
        first = self.create()
        with self.assertRaises(sqlite3.IntegrityError):
            self.manager.store.conn.execute(
                "UPDATE scoped_evidence_relation_versions SET rationale='tampered' WHERE version_id=?",
                (first["version_id"],),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.manager.store.conn.execute(
                "DELETE FROM scoped_evidence_relation_versions WHERE version_id=?", (first["version_id"],)
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.manager.store.conn.execute(
                "UPDATE scoped_evidence_relation_heads SET current_version_id=? WHERE relation_id=?",
                (first["version_id"], first["relation_id"]),
            )

    def test_same_user_key_isolated_by_actor_and_run(self) -> None:
        first = self.create("shared-key")
        other = self.manager.credentials.resolve(
            self.manager.credentials.path_for("experiment-agent"), "evidence.relation.write"
        )
        source, target = self.tokens()
        second = self.manager.scoped_evidence_relations.create(
            scope_issue_id="scope", source_evidence_id=self.a, target_evidence_id=self.b,
            relation_type="supports", rationale="other actor", auth=other,
            expected_source_token=source, expected_target_token=target, idempotency_key="shared-key",
        )
        self.assertNotEqual(first["relation_id"], second["relation_id"])
        self.assertNotEqual(first["actor_id"], second["actor_id"])

    def test_lifecycle_writes_require_endpoint_visibility(self) -> None:
        first = self.create("visibility")
        hidden = replace(self.auth, platform_id="platform-without-access")
        for operation in ("deactivate", "revise"):
            with self.subTest(operation=operation):
                with self.assertRaises(Exception):
                    if operation == "deactivate":
                        self.manager.scoped_evidence_relations.deactivate(
                            first["relation_id"], expected_version_id=first["version_id"], reason="hidden",
                            auth=hidden, idempotency_key="hidden-deactivate",
                        )
                    else:
                        self.manager.scoped_evidence_relations.revise(
                            first["relation_id"], expected_version_id=first["version_id"], rationale="hidden",
                            auth=hidden, idempotency_key="hidden-revise",
                        )

    def test_fault_windows_roll_back_and_same_key_retry_succeeds(self) -> None:
        for index, point in enumerate((
            "scoped_relation.after_version", "scoped_relation.after_head",
            "scoped_relation.before_receipt", "scoped_relation.after_receipt_before_commit",
            )):
            with self.subTest(point=point):
                key = f"fault-{index}"
                before = tuple(
                    self.manager.store.conn.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in (
                        "scoped_evidence_relation_versions",
                        "scoped_evidence_relation_heads",
                        "audit_events",
                        "request_idempotency",
                    )
                )
                self.manager.store.fault_injector = lambda current, expected=point: (_ for _ in ()).throw(RuntimeError(expected)) if current == expected else None
                with self.assertRaisesRegex(RuntimeError, point):
                    self.create(key)
                self.manager.store.fault_injector = None
                after = tuple(
                    self.manager.store.conn.execute(
                        f"SELECT COUNT(*) FROM {table}"
                    ).fetchone()[0]
                    for table in (
                        "scoped_evidence_relation_versions",
                        "scoped_evidence_relation_heads",
                        "audit_events",
                        "request_idempotency",
                    )
                )
                self.assertEqual(after, before)
                retry = self.create(key)
                self.assertEqual(retry["revision"], 1)

    def test_two_connections_compete_for_one_head(self) -> None:
        first = self.create("concurrent-create")
        ledger = Path(self.temp.name) / "ledger"

        def revise_from_new_connection(key: str) -> str:
            manager = IssueManager(ledger)
            try:
                auth = manager.credentials.resolve(
                    manager.credentials.path_for("organizer-agent"), "evidence.relation.write"
                )
                manager.scoped_evidence_relations.revise(
                    first["relation_id"], expected_version_id=first["version_id"],
                    rationale=key, auth=auth, idempotency_key=key,
                )
                return "success"
            except ConflictError:
                return "conflict"
            finally:
                manager.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(revise_from_new_connection, ("race-a", "race-b")))
        self.assertEqual(sorted(outcomes), ["conflict", "success"])


if __name__ == "__main__":
    unittest.main()
