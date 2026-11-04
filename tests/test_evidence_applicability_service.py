from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from issue_manager.errors import NotFoundError
from issue_manager.evidence_applicability import APPLICABILITY_RULE_ID
from issue_manager.service import IssueManager
from issue_manager.store import canonical_json, now


def _basis(
    evidence_id: str,
    semantic_revision: int = 0,
    proof_id: str | None = None,
    manifest_id: str | None = None,
) -> list[dict]:
    return [
        {
            "kind": "evidence_version",
            "evidence_id": evidence_id,
            "semantic_revision": semantic_revision,
            "proof_id": proof_id,
            "manifest_id": manifest_id,
            "snapshot": {
                "semantic_revision": semantic_revision,
                "proof_id": proof_id,
                "manifest_id": manifest_id,
            },
        }
    ]


class EvidenceApplicabilityServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = IssueManager.initialize(Path(self.temp.name) / "ledger", context_rule="scoped-v2")
        self.store = self.manager.store
        self.actor_id = "applicability-test-actor"
        self.run_id = "applicability-test-run"
        self.issue_id = "applicability-test-issue"
        self.store.conn.execute(
            "INSERT INTO actors(actor_id,actor_kind,display_name,credential_hash,active,created_at) "
            "VALUES (?,'organizer_agent','Applicability test actor','unique-test-credential',1,?)",
            (self.actor_id, now()),
        )
        self.store.conn.execute(
            "INSERT INTO agent_runs(run_id,actor_id,parent_run_id,lineage_json,started_at,ended_at) "
            "VALUES (?,?,NULL,'[]',?,NULL)",
            (self.run_id, self.actor_id, now()),
        )
        self.store.conn.execute(
            "INSERT INTO issues(issue_id,title,issue_type,created_at,created_by,updated_at,policy_version) "
            "VALUES (?,?, 'test',?,?,?,?)",
            (
                self.issue_id,
                "Applicability test",
                now(),
                self.actor_id,
                now(),
                self.manager.policy.version,
            ),
        )
        self.target_id = self.manager.add_evidence(
            kind="external",
            locator="urn:test:target",
            issue_id=self.issue_id,
            actor="organizer-agent",
            reason="test target",
        )["evidence_id"]
        self.basis_id = self.manager.add_evidence(
            kind="external",
            locator="urn:test:basis",
            issue_id=self.issue_id,
            actor="organizer-agent",
            reason="test basis",
        )["evidence_id"]
        self.changeset_id = "applicability-test-cs"
        self.changeset_hash = "applicability-test-hash"
        self.store.conn.execute(
            "INSERT INTO changesets(changeset_id,changeset_version,intent,changeset_json,changeset_hash,"
            "state,risk_tier,created_by,created_run_id,created_at,updated_at) "
            "VALUES (?,1,'test','{}',?,'applied','T1',?,?,?,?)",
            (self.changeset_id, self.changeset_hash, self.actor_id, self.run_id, now(), now()),
        )
        self.conclusion_id = "applicability-test-conclusion"
        self.store.conn.execute(
            "INSERT INTO conclusion_revisions(conclusion_id,issue_id,revision_number,status,statement,"
            "change_summary,created_at,created_by,policy_version) VALUES (?,?,1,'draft','test conclusion',"
            "'fixture',?,?,?)",
            (self.conclusion_id, self.issue_id, now(), self.actor_id, self.manager.policy.version),
        )
        self.bundle_id = "applicability-test-bundle"
        self.store.conn.execute(
            "INSERT INTO extension_bundles(bundle_id,namespace,name,version,bundle_format,core_api_range,"
            "manifest_json,content_hash,state,installed_at,installed_by) "
            "VALUES (?,'tests','applicability','1','test','*','{}','applicability-test-bundle-hash',"
            "'installed',?,?)",
            (self.bundle_id, now(), self.actor_id),
        )
        self.record_template_id = "applicability-test-record-template"
        self.store.conn.execute(
            "INSERT INTO registry_entries(registration_id,bundle_id,namespace,kind,name,version,api_version,"
            "definition_json,content_hash,state,created_at) "
            "VALUES (?,?,'tests','record_template','Applicability fixture','1','v1','{}',"
            "'applicability-test-record-template-hash','installed',?)",
            (self.record_template_id, self.bundle_id, now()),
        )
        self.record_instance_id = "applicability-test-record-instance"
        self.record_revision_id = "applicability-test-record-revision"
        self.store.conn.execute(
            "INSERT INTO record_instances(record_instance_id,issue_id,record_template_registration_id,"
            "record_template_snapshot_json,created_at,created_by,current_revision_id,lifecycle_status) "
            "VALUES (?,?,?,'{}',?,?,?,'active')",
            (
                self.record_instance_id,
                self.issue_id,
                self.record_template_id,
                now(),
                self.actor_id,
                self.record_revision_id,
            ),
        )
        self.store.conn.execute(
            "INSERT INTO record_revisions(record_revision_id,record_instance_id,revision_number,"
            "template_content_hash,template_snapshot_json,data_json,recorded_at,recorded_by,source_mode,"
            "validation_profile,validation_result_json,content_hash) "
            "VALUES (?,?,1,'record-template-hash','{}','{}',?,?,'native','test','{}','record-content-hash')",
            (self.record_revision_id, self.record_instance_id, now(), self.actor_id),
        )
        self.relation_version_id = "applicability-test-relation-version"
        self.store.conn.execute(
            "INSERT INTO managed_relation_versions(version_id,domain,relation_id,version_number,contract_version,"
            "definition_json) VALUES (?,'issue','applicability-test-relation',1,'v1','{}')",
            (self.relation_version_id,),
        )
        self.currentness_before = self.store.rows(
            "SELECT * FROM conclusion_currentness ORDER BY conclusion_id"
        )

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def _qualification(self, *, valid=True):
        if not valid:
            return {"authorized": True}
        return {
            "actor_id": self.actor_id,
            "run_id": self.run_id,
            "capability": "evidence.applicability.write",
            "changeset_id": self.changeset_id,
            "changeset_hash": self.changeset_hash,
            "risk_tier": "T1",
            "review_ids": [],
            "rule_id": APPLICABILITY_RULE_ID,
            "validation_results": {
                "scope": True,
                "target": True,
                "basis": True,
                "capability": True,
                "risk": True,
                "reviews": True,
            },
        }

    def _insert_decision(
        self,
        key: str,
        version: int,
        effect: str,
        *,
        basis: list[dict] | None = None,
        qualification: dict | None = None,
        active: bool = True,
        previous: str | None = None,
        as_head: bool = True,
        target_snapshot: dict | None = None,
    ) -> str:
        decision_id = f"applicability:{key}:{version}"
        current = self.store.row(
            "SELECT semantic_revision,current_proof_id,current_manifest_id FROM evidence_refs WHERE evidence_id=?",
            (self.target_id,),
        )
        basis_current = self.store.row(
            "SELECT semantic_revision,current_proof_id,current_manifest_id FROM evidence_refs WHERE evidence_id=?",
            (self.basis_id,),
        )
        target_snapshot = target_snapshot or {
            "semantic_revision": current["semantic_revision"],
            "proof_id": current["current_proof_id"],
            "manifest_id": current["current_manifest_id"],
        }
        payload = {
            "decision_version_id": decision_id,
            "decision_key": key,
            "version_number": version,
            "previous_version_id": previous,
            "scope_kind": "issue_conclusion",
            "scope_issue_id": self.issue_id,
            "target_binding": "fixed",
            "target_evidence_id": self.target_id,
            "target_semantic_revision": target_snapshot["semantic_revision"],
            "target_proof_id": target_snapshot["proof_id"],
            "target_manifest_id": target_snapshot["manifest_id"],
            "effect": effect,
            "basis_json": canonical_json(
                basis
                if basis is not None
                else _basis(
                    self.basis_id,
                    int(basis_current["semantic_revision"]),
                    basis_current["current_proof_id"],
                    basis_current["current_manifest_id"],
                )
            ),
            "rule_id": APPLICABILITY_RULE_ID,
            "qualification_json": canonical_json(
                qualification if qualification is not None else self._qualification()
            ),
            "reason": f"test {key} v{version}",
            "changeset_id": self.changeset_id,
            "created_at": now(),
            "created_by": self.actor_id,
            "run_id": self.run_id,
        }
        columns = ",".join(payload)
        marks = ",".join("?" for _ in payload)
        self.store.conn.execute(
            f"INSERT INTO evidence_applicability_decision_versions({columns}) VALUES ({marks})",
            tuple(payload.values()),
        )
        if as_head:
            self.store.conn.execute(
                "INSERT INTO evidence_applicability_decision_heads(decision_key,decision_version_id,active,"
                "head_revision,updated_at,updated_by) VALUES (?,?,?,1,?,?)",
                (key, decision_id, int(active), now(), self.actor_id),
            )
        return decision_id

    def test_issue_manager_wires_read_only_list_show_projection_and_why(self):
        active_rule_before = self.manager.context_rules.active()["rule_id"]
        old_id = self._insert_decision("same-key", 1, "exclude", as_head=False)
        current_id = self._insert_decision("same-key", 2, "include", previous=old_id)
        listed = self.manager.evidence_applicability.list(scope_issue_id=self.issue_id)
        self.assertEqual([item["decision_version_id"] for item in listed], [current_id])
        self.assertEqual(listed[0]["validation_errors"], [])
        shown = self.manager.evidence_applicability.show("same-key")
        self.assertEqual(
            [item["decision_version_id"] for item in shown["versions"]], [old_id, current_id]
        )
        self.assertEqual(shown["versions"][0]["active"], None)
        self.assertEqual(shown["versions"][1]["active"], True)

        projection = self.manager.evidence_applicability.projection(
            scope_issue_id=self.issue_id, evidence_ids=[self.target_id]
        )
        self.assertEqual(projection["included"], [self.target_id])
        self.assertEqual(projection["evidence"][0]["decision_version_ids"], [current_id])
        why = self.manager.evidence_applicability.why(
            scope_issue_id=self.issue_id, evidence_id=self.target_id
        )
        self.assertEqual(why["state"], "included")
        self.assertTrue(why["selected"])
        self.assertEqual(self.manager.context_rules.active()["rule_id"], active_rule_before)
        self.assertTrue(active_rule_before.startswith("context-currentness/scoped-v2:"))

    def test_new_project_curator_profile_does_not_grant_general_changeset_submission(self):
        curator_profile = {
            row["capability"]
            for row in self.store.rows(
                "SELECT capability FROM profile_capabilities WHERE profile_name='evidence-curator'"
            )
        }
        self.assertEqual(curator_profile, {"context.read", "evidence.applicability.write"})
        organizer = {
            row["capability"]
            for row in self.store.rows(
                "SELECT capability FROM actor_capabilities WHERE actor_id='organizer-agent'"
            )
        }
        maintenance = {
            row["capability"]
            for row in self.store.rows(
                "SELECT capability FROM actor_capabilities WHERE actor_id='maintenance-agent'"
            )
        }
        self.assertTrue({"context.read", "evidence.applicability.write"} <= maintenance)
        self.assertNotIn("changeset.submit", maintenance)
        self.assertIn("changeset.submit", organizer)

    def test_v18_trigger_accepts_all_five_typed_basis_shapes(self):
        source_version = self._insert_decision("basis-source", 1, "include", as_head=False)
        basis_by_kind = [
            _basis(
                self.basis_id,
                int(
                    self.store.row(
                        "SELECT semantic_revision FROM evidence_refs WHERE evidence_id=?",
                        (self.basis_id,),
                    )["semantic_revision"]
                ),
                self.store.row(
                    "SELECT current_proof_id FROM evidence_refs WHERE evidence_id=?",
                    (self.basis_id,),
                )["current_proof_id"],
                self.store.row(
                    "SELECT current_manifest_id FROM evidence_refs WHERE evidence_id=?",
                    (self.basis_id,),
                )["current_manifest_id"],
            )[0],
            {"kind": "conclusion_version", "conclusion_id": self.conclusion_id},
            {"kind": "record_version", "record_revision_id": self.record_revision_id},
            {"kind": "relation_version", "version_id": self.relation_version_id},
            {"kind": "applicability_decision_version", "decision_version_id": source_version},
        ]
        for index, typed_basis in enumerate(basis_by_kind):
            with self.subTest(kind=typed_basis["kind"]):
                self._insert_decision(f"basis-kind-{index}", 1, "include", basis=[typed_basis])
        projection = self.manager.evidence_applicability.projection(
            scope_issue_id=self.issue_id, evidence_ids=[self.target_id]
        )
        item = projection["evidence"][0]
        self.assertEqual(item["state"], "included")
        self.assertEqual(len(item["decision_version_ids"]), 5)
        self.assertEqual(item["errors"], [])

    def test_v18_trigger_rejects_invalid_basis_and_target_definitions(self):
        current = self.store.row(
            "SELECT semantic_revision,current_proof_id,current_manifest_id FROM evidence_refs WHERE evidence_id=?",
            (self.target_id,),
        )
        invalid_rows = [
            ("empty", []),
            ("unknown-kind", [{"kind": "free_text", "id": "x"}]),
            ("missing-field", [{"kind": "conclusion_version"}]),
            (
                "self-reference",
                [
                    {
                        "kind": "applicability_decision_version",
                        "decision_version_id": "applicability:self-reference:1",
                    }
                ],
            ),
        ]
        for key, basis_value in invalid_rows:
            with self.subTest(key=key), self.assertRaises(sqlite3.IntegrityError):
                self._insert_decision(key, 1, "exclude", basis=basis_value, as_head=False)
        with self.assertRaises(sqlite3.IntegrityError):
            self._insert_decision(
                "wrong-target-snapshot",
                1,
                "exclude",
                as_head=False,
                target_snapshot={
                    "semantic_revision": int(current["semantic_revision"]) + 1,
                    "proof_id": current["current_proof_id"],
                    "manifest_id": current["current_manifest_id"],
                },
            )

    def test_database_inserted_valid_basis_is_read_and_reduced_by_service(self):
        decision_id = self._insert_decision("real-v18-row", 1, "exclude")
        shown = self.manager.evidence_applicability.show(decision_id)
        self.assertEqual(shown["versions"][0]["validation_errors"], [])
        projection = self.manager.evidence_applicability.projection(
            scope_issue_id=self.issue_id, evidence_ids=[self.target_id]
        )
        item = projection["evidence"][0]
        self.assertEqual(item["state"], "excluded")
        self.assertEqual(item["decision_version_ids"], [decision_id])

    def test_fixed_target_revision_change_is_nonmatching_and_defaults_to_included(self):
        decision_id = self._insert_decision("fixed-old", 1, "exclude")
        self.store.conn.execute(
            "UPDATE evidence_refs SET semantic_revision=semantic_revision+1 WHERE evidence_id=?",
            (self.target_id,),
        )
        why = self.manager.evidence_applicability.why(
            scope_issue_id=self.issue_id, evidence_id=self.target_id
        )
        self.assertEqual(why["state"], "included")
        self.assertEqual(why["decision_version_ids"], [])
        self.assertEqual(why["nonmatching_decision_version_ids"], [decision_id])
        self.assertEqual(why["nonmatching_heads"][0]["reason"], "fixed_target_snapshot_mismatch")

    def test_basis_or_qualification_that_cannot_be_explained_is_unresolved(self):
        self._insert_decision(
            "bad-basis",
            1,
            "exclude",
            basis=[{"kind": "conclusion_version", "conclusion_id": "missing-c"}],
        )
        self._insert_decision(
            "bad-qualification", 1, "exclude", qualification=self._qualification(valid=False)
        )
        projection = self.manager.evidence_applicability.projection(
            scope_issue_id=self.issue_id, evidence_ids=[self.target_id]
        )
        item = projection["evidence"][0]
        self.assertEqual(item["state"], "unresolved")
        self.assertIn("basis_conclusion_version_missing", item["errors"])
        self.assertIn("qualification_actor_id_missing", item["errors"])
        self.assertEqual(item["qualified_effects"], [])

    def test_scope_isolation_and_inactive_heads(self):
        other_issue = "applicability-other-issue"
        self.store.conn.execute(
            "INSERT INTO issues(issue_id,title,issue_type,created_at,created_by,updated_at,policy_version) "
            "VALUES (?, 'Other scope', 'test', ?, ?, ?, ?)",
            (other_issue, now(), self.actor_id, now(), self.manager.policy.version),
        )
        # Build an otherwise identical row in a distinct scope.
        decision_id = self._insert_decision("inactive-exclude", 1, "exclude", active=False)
        inactive = self.manager.evidence_applicability.why(
            scope_issue_id=self.issue_id, evidence_id=self.target_id
        )
        self.assertEqual(inactive["state"], "included")
        self.assertEqual(inactive["inactive_heads"][0]["decision_version_id"], decision_id)

        scoped = self._insert_decision("other-scope", 1, "exclude", as_head=False)
        row = self.store.row(
            "SELECT * FROM evidence_applicability_decision_versions WHERE decision_version_id=?",
            (scoped,),
        )
        # Versions are immutable. Insert a separate valid version directly under
        # the other Issue so this test checks query/evaluator scope isolation.
        other_version = dict(row)
        other_version["decision_key"] = "other-scope"
        other_version["decision_version_id"] = "applicability:other-scope:2"
        other_version["version_number"] = 2
        other_version["previous_version_id"] = scoped
        other_version["scope_issue_id"] = other_issue
        columns = list(other_version)
        self.store.conn.execute(
            f"INSERT INTO evidence_applicability_decision_versions({','.join(columns)}) "
            f"VALUES ({','.join('?' for _ in columns)})",
            tuple(other_version[column] for column in columns),
        )
        self.store.conn.execute(
            "INSERT INTO evidence_applicability_decision_heads(decision_key,decision_version_id,active,"
            "head_revision,updated_at,updated_by) VALUES ('other-scope','applicability:other-scope:2',1,1,?,?)",
            (now(), self.actor_id),
        )
        own_scope = self.manager.evidence_applicability.why(
            scope_issue_id=self.issue_id, evidence_id=self.target_id
        )
        self.assertEqual(own_scope["state"], "included")
        self.assertNotIn("applicability:other-scope:2", own_scope["decision_version_ids"])

    def test_projection_is_read_only_and_creates_no_projection_or_currentness_state(self):
        self._insert_decision("exclude", 1, "exclude")
        before_versions = self.store.row(
            "SELECT COUNT(*) AS n FROM evidence_applicability_decision_versions"
        )["n"]
        before_heads = self.store.row(
            "SELECT COUNT(*) AS n FROM evidence_applicability_decision_heads"
        )["n"]
        before_currentness = self.store.rows(
            "SELECT * FROM conclusion_currentness ORDER BY conclusion_id"
        )
        before_tables = {
            row["name"]
            for row in self.store.rows("SELECT name FROM sqlite_master WHERE type='table'")
        }
        self.manager.evidence_applicability.projection(
            scope_issue_id=self.issue_id, evidence_ids=[self.target_id]
        )
        self.assertEqual(
            self.store.row("SELECT COUNT(*) AS n FROM evidence_applicability_decision_versions")[
                "n"
            ],
            before_versions,
        )
        self.assertEqual(
            self.store.row("SELECT COUNT(*) AS n FROM evidence_applicability_decision_heads")["n"],
            before_heads,
        )
        self.assertEqual(
            self.store.rows("SELECT * FROM conclusion_currentness ORDER BY conclusion_id"),
            before_currentness,
        )
        after_tables = {
            row["name"]
            for row in self.store.rows("SELECT name FROM sqlite_master WHERE type='table'")
        }
        self.assertEqual(after_tables, before_tables)
        self.assertNotIn("evidence_applicability_projection", after_tables)
        self.assertEqual(self.currentness_before, before_currentness)

    def test_unknown_scope_and_evidence_fail_with_clear_not_found(self):
        with self.assertRaises(NotFoundError):
            self.manager.evidence_applicability.projection(
                scope_issue_id="missing-issue", evidence_ids=[]
            )
        with self.assertRaises(NotFoundError):
            self.manager.evidence_applicability.projection(
                scope_issue_id=self.issue_id, evidence_ids=["missing-evidence"]
            )


if __name__ == "__main__":
    unittest.main()
