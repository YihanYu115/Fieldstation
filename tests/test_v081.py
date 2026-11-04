from __future__ import annotations

import hashlib
import shutil
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from context_fixtures import apply_reviewed_changeset

from issue_manager import IssueManager
from issue_manager.adapter_service import ADAPTER_PROTOCOL
from issue_manager.errors import ConflictError, ValidationError
from issue_manager.field_bundle_service import FIELD_BUNDLE_VERSION
from issue_manager.import_service import BUILTIN_ADAPTERS, _adapter_hash
from issue_manager.store import now


def v81_bundle(namespace: str = "org.example.v81") -> dict:
    record_ref = f"{namespace}/record_template/measurement@1.0.0"
    specimen_ref = f"{namespace}/issue_type/specimen@1.0.0"
    return {
        "manifest": {
            "bundle_format": "issue-manager-feature-bundle/v1",
            "namespace": namespace,
            "name": "v81-tests",
            "version": "1.0.0",
            "core_api": ">=0.8,<0.9",
            "registrations": [],
            "dependencies": [],
        },
        "registrations": [
            {
                "kind": "issue_type",
                "name": "parent",
                "api_version": "issue-type/v2",
                "definition": {
                    "allowed_children": [specimen_ref],
                    "rollup_mode": "semantic",
                    "conclusion": {
                        "structured_outputs_schema": {
                            "type": "object",
                            "properties": {"result": {"type": "string"}},
                            "additionalProperties": False,
                        },
                        "publication_profiles": {
                            "provisional": {
                                "min_active_evidence": 0,
                                "minimum_verification_level": "declared",
                                "review_quorum": 0,
                            }
                        },
                        "report_facing": False,
                    },
                },
            },
            {
                "kind": "issue_type",
                "name": "specimen",
                "api_version": "issue-type/v2",
                "definition": {
                    "allowed_children": [],
                    "rollup_mode": "semantic",
                    "conclusion": {
                        "structured_outputs_schema": {
                            "type": "object",
                            "properties": {"result": {"type": "string"}},
                            "additionalProperties": False,
                        },
                        "publication_profiles": {
                            "provisional": {
                                "min_active_evidence": 0,
                                "minimum_verification_level": "declared",
                                "review_quorum": 0,
                            }
                        },
                        "report_facing": False,
                    },
                },
            },
            {
                "kind": "record_template",
                "name": "measurement",
                "definition": {
                    "applies_to_issue_types": [specimen_ref],
                    "additional_fields": False,
                    "fields": {
                        "name": {"type": "string", "required": True, "queryable": True},
                        "measurement": {
                            "type": "quantity",
                            "allowed_units": ["m"],
                            "evidence_required": False,
                            "queryable": True,
                        },
                        "optional": {"type": "string", "nullable": True},
                    },
                    "profiles": {
                        "draft": {"required": ["name"]},
                        "report": {
                            "required": ["name"],
                            "minimum_verification_level": "declared",
                        },
                        "accepted": {
                            "required": ["name", "measurement"],
                            "minimum_verification_level": "source_verified",
                        },
                    },
                },
            },
            {
                "kind": "mapping_profile",
                "name": "measurement-map",
                "definition": {
                    "external_object_type": "measurement-row",
                    "external_object_id_field": "external_id",
                    "target_template_ref": record_ref,
                    "mappings": [
                        {"source": "name", "target": "name", "required": True}
                    ],
                },
            },
            {
                "kind": "report_template",
                "name": "summary",
                "api_version": "report-template/v2",
                "definition": {
                    "title": "V81 summary",
                    "record_templates": [record_ref],
                    "record_validation_profile": "report",
                    "columns": [
                        {"field_path": "name", "title": "Name"},
                        {"field_path": "measurement", "title": "Measurement"},
                        {"field_path": "optional", "title": "Optional"},
                    ],
                    "sort": ["issue_id", "name"],
                    "eligibility": {
                        "minimum_conclusion_status": "provisional",
                        "minimum_verification_level": "declared",
                    },
                    "field_policies": {
                        "missing": "mark",
                        "stale": "mark",
                        "disputed": "exclude",
                        "invalid": "block",
                    },
                    "query": {
                        "allowed_fields": ["issue_id", "name", "measurement", "optional"],
                        "allowed_operators": ["eq", "ne", "in", "exists", "lt", "lte", "gt", "gte"],
                    },
                    "output_format": "json",
                },
            },
        ],
    }


class V081CoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.manager = IssueManager.initialize(self.root / "ledger", context_rule="scoped-v2")
        installed = self.manager.registry.install_bundle(v81_bundle())
        self.manager.registry.activate_bundle(installed["bundle_id"])
        self.specimen = self.manager.registry.resolve(
            "org.example.v81/issue_type/specimen@1.0.0"
        )
        self.record_template = self.manager.registry.resolve(
            "org.example.v81/record_template/measurement@1.0.0"
        )
        self.manager.create_issue(
            "sample-a",
            "specimen",
            issue_type_registration_id=self.specimen["registration_id"],
        )
        self.organizer = self.manager.credentials.path_for("organizer-agent")

    def tearDown(self) -> None:
        self.manager.close()
        self.temporary.cleanup()

    def publish(self, statement: str) -> dict:
        prepared = self.manager.prepare_refresh("sample-a")
        issue = self.manager.show_issue("sample-a")
        proposal = self.manager.proposals.create(
            {
                "issue_id": "sample-a",
                "expected_conclusion_revision": issue["conclusion_revision"],
                "status": "provisional",
                "statement": statement,
                "basis_snapshot_token": prepared["proposal_template"]["basis_snapshot_token"],
                "structured_outputs": {"result": statement},
                "limitations": [],
                "evidence_refs": [],
                "basis": [],
            },
            credential=self.organizer,
        )
        self.manager.proposals.validate(proposal["proposal_id"], credential=self.organizer)
        return self.manager.proposals.apply(
            proposal["proposal_id"], credential=self.organizer
        )

    def import_bundle(self, *, owner: str, external_id: str, name: str) -> dict:
        adapter = "json-records-v1"
        return {
            "bundle_format": "issue-manager-import-bundle/v1",
            "source_namespace": "external.lab",
            "source_owner": owner,
            "source_system": "fixture",
            "adapter": {
                "name": adapter,
                "version": BUILTIN_ADAPTERS[adapter]["version"],
                "hash": _adapter_hash(adapter),
            },
            "source_files": [],
            "items": [
                {
                    "raw_location": "items[0]",
                    "raw": {"external_id": external_id, "name": name},
                }
            ],
        }

    def test_registered_semantics_namespace_and_kind_locks(self) -> None:
        published = self.publish("registered semantics")
        self.assertEqual(published["status"], "provisional")
        conclusion = self.manager.get_current_conclusion("sample-a")
        self.assertEqual(
            conclusion["issue_type_registration_id"], self.specimen["registration_id"]
        )
        shown = self.manager.registry.show_entry(self.record_template["registration_id"])
        self.assertTrue(shown["reference_locks"])
        with self.assertRaises(ValidationError):
            self.manager.registry.resolve(
                "org.example.v81/report_template/summary@1.0.0",
                kind="record_template",
            )

        second = self.manager.registry.install_bundle(v81_bundle("org.example.other"))
        self.manager.registry.activate_bundle(second["bundle_id"])
        other_type = self.manager.registry.resolve(
            "org.example.other/issue_type/specimen@1.0.0"
        )
        self.manager.create_issue(
            "sample-b",
            "specimen",
            issue_type_registration_id=other_type["registration_id"],
        )
        with self.assertRaises(ValidationError):
            self.manager.records.create(
                "sample-b", self.record_template["registration_id"], data={"name": "B"}
            )

    def test_embedded_evidence_normalizes_and_verified_profile_blocks_declared(self) -> None:
        evidence = self.manager.add_evidence(
            kind="external", locator="fixture:evidence:1", issue_id="sample-a"
        )
        data = {
            "name": "A",
            "measurement": {
                "value": 1.0,
                "unit": "m",
                "evidence_refs": [evidence["evidence_id"]],
            },
        }
        rejected = self.manager.records.validate_data(
            self.record_template["registration_id"], data, profile="accepted"
        )
        self.assertTrue(
            {"proof_required", "proof_insufficient"}
            & {item["code"] for item in rejected["errors"]}
        )
        created = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data=data, profile="draft"
        )
        revision = self.manager.records.show_revision(created["record_revision_id"])
        self.assertEqual(revision["evidence_links"][0]["evidence_id"], evidence["evidence_id"])
        self.assertEqual(
            revision["validation_result"]["normalization_receipt"]["input_embedded_refs"],
            1,
        )
        self.assertEqual(self.manager.records.evidence_status(created["record_instance_id"])["status"], "fresh")

    def test_record_material_membership_preserves_frozen_snapshot(self) -> None:
        evidence = self.manager.add_evidence(kind="external", locator="urn:record:material-snapshot")
        created = self.manager.records.create("sample-a", self.record_template["registration_id"],
                                              data={"name": "A", "measurement": {"value": 1.0, "unit": "m",
                                                                                   "evidence_refs": [evidence["evidence_id"]]}})
        revision_id = created["record_revision_id"]
        frozen = self.manager.records.show_revision(revision_id)
        relation = self.manager.store.row("SELECT * FROM record_material_relations WHERE record_revision_id=?", (revision_id,))
        self.assertTrue(relation["relation_id"])
        self.assertEqual({key: relation[key] for key in frozen["evidence_links"][0]}, frozen["evidence_links"][0])
        conclusion_id = self.publish("Record based conclusion")["conclusion_id"]
        package = self.manager.context_maintenance.prepare("sample-a")
        receipt_id = self.manager.store.row("SELECT receipt_id FROM basis_receipt_selections WHERE conclusion_id=?", (conclusion_id,))["receipt_id"]
        before = self.manager.context_maintenance.prepare("sample-a")["actual_input"]["materials"]
        self.assertIn(evidence["evidence_id"], before["discovery_ids"])
        operation = {"op": "record_relation", "action": "disable", "relation_id": relation["relation_id"],
                     "expected_version_id": f"record:{relation['relation_id']}:1", "expected_active": True, "reason": "Withdraw current contribution"}
        credential = self.manager.credentials.path_for("organizer-agent")
        verify = {"op": "context_change", "action": "verify", "reason": "Verify prepared materials",
                  "items": [{"conclusion_id": conclusion_id, "package_id": package["package_id"], "expected_receipt_id": receipt_id}]}
        self.manager.changesets.operation_engine.preflight([operation, verify])
        apply_reviewed_changeset(self.manager, credential, [operation])
        self.assertEqual(self.manager.context_maintenance.show(conclusion_id)["currentness"], "current")
        self.assertEqual(self.manager.records.show_revision(revision_id), frozen)
        after = self.manager.context_maintenance.prepare("sample-a")["actual_input"]["materials"]
        self.assertNotIn(evidence["evidence_id"], after["discovery_ids"])
        self.assertEqual(after["support_ids"], before["support_ids"])
        with self.assertRaisesRegex(ConflictError, "activation changed"):
            self.manager.changesets.operation_engine.preflight([operation])
        enable = {**operation, "action": "enable", "expected_active": False}
        apply_reviewed_changeset(self.manager, credential, [enable, verify, operation])
        self.assertEqual(self.manager.records.show_revision(revision_id), frozen)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "Immutable Record evidence snapshot"):
            with self.manager.store.transaction() as conn:
                conn.execute("UPDATE record_evidence_links SET field_path='changed' WHERE record_revision_id=?", (revision_id,))

    def test_record_relation_add_replace_validates_snapshots_and_preserves_history(self):
        evidence = self.manager.add_evidence(kind="external", locator="urn:record:add-material")
        other = self.manager.add_evidence(kind="external", locator="urn:record:other-material")
        created = self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "A"})
        frozen = self.manager.records.show_revision(created["record_revision_id"])
        add = {"op": "record_relation", "action": "add", "relation_id": "new-record-material", "reason": "Additional material",
               "replacement": {"record_revision_id": created["record_revision_id"], "field_path": "measurement",
                               "evidence_id": evidence["evidence_id"], "relation_role": "supports"}}
        credential = self.manager.credentials.path_for("organizer-agent")
        replace = {"op": "record_relation", "action": "replace", "relation_id": add["relation_id"],
                   "expected_version_id": "record:new-record-material:1", "expected_active": True, "reason": "Correct evidence",
                   "replacement": {"evidence_id": other["evidence_id"]}}
        conclusion_id = self.publish("Before added material")["conclusion_id"]
        package = self.manager.context_maintenance.prepare("sample-a")
        receipt_id = self.manager.store.row("SELECT receipt_id FROM basis_receipt_selections WHERE conclusion_id=?", (conclusion_id,))["receipt_id"]
        verify = {"op": "context_change", "action": "verify", "reason": "Verify prepared material",
                  "items": [{"conclusion_id": conclusion_id, "package_id": package["package_id"], "expected_receipt_id": receipt_id}]}
        self.manager.changesets.operation_engine.preflight([add, replace, verify])
        apply_reviewed_changeset(self.manager, credential, [add, replace])
        self.assertEqual(self.manager.records.show_revision(created["record_revision_id"]), frozen)
        row = self.manager.store.row("SELECT * FROM record_material_relations WHERE relation_id=?", (add["relation_id"],))
        self.assertEqual(row["evidence_id"], other["evidence_id"])
        self.assertEqual(self.manager.store.row("SELECT COUNT(*) AS n FROM managed_relation_versions WHERE domain='record'")["n"], 2)
        wrong_proof = self.manager.store.row("SELECT current_proof_id FROM evidence_refs WHERE evidence_id=?", (evidence["evidence_id"],))["current_proof_id"]
        for replacement in ({"field_path": "missing"}, {"proof_id": wrong_proof}, {"proof_hash": "fabricated"}):
            operation = {**replace, "expected_version_id": "record:new-record-material:2", "replacement": replacement}
            with self.subTest(replacement=replacement), self.assertRaises(ValidationError):
                self.manager.changesets.operation_engine.preflight([operation])
        # The normalizer must read preceding simulated lifecycle changes.
        with self.assertRaises(ValidationError):
            self.manager.changesets.operation_engine.preflight([
                {"op": "void_evidence", "evidence_id": other["evidence_id"], "reason": "Unavailable"},
                {**replace, "expected_version_id": "record:new-record-material:2", "replacement": {"relation_role": "context"}}])

    def test_report_query_and_conclusion_drift_gate(self) -> None:
        self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "A"}
        )
        self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "B"}
        )
        self.publish("basis one")
        prepared = self.manager.reports.prepare(
            "org.example.v81/report_template/summary@1.0.0",
            scope={"issue_id": "sample-a"},
            query={"name": {"eq": "A"}},
            output_format="json",
        )
        self.assertEqual(prepared["rows"], 1)
        self.assertTrue(self.manager.reports.explain_field(prepared["report_build_id"], 0, "name"))
        with self.assertRaises(ValidationError):
            self.manager.reports.prepare(
                "org.example.v81/report_template/summary@1.0.0",
                scope={"issue_id": "sample-a"},
                query={"unknown": {"eq": "A"}},
            )
        self.publish("basis two")
        with self.assertRaises(ConflictError):
            self.manager.reports.build(prepared["report_build_id"])
        self.assertEqual(self.manager.reports.show(prepared["report_build_id"])["state"], "stale")

    def test_report_prepare_reserves_snapshot_against_second_connection(self):
        self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "A"})
        self.publish("Report basis")
        candidate_records = self.manager.reports._candidate_records
        attempts = []

        def concurrent_attempt(issue_ids):
            with closing(sqlite3.connect(self.manager.store.db_path, timeout=0)) as other:
                with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                    other.execute("UPDATE issues SET title='Concurrent title' WHERE issue_id='sample-a'")
            attempts.append(True)
            return candidate_records(issue_ids)

        with patch.object(self.manager.reports, "_candidate_records", side_effect=concurrent_attempt):
            report = self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
        self.assertTrue(attempts)
        self.assertFalse(self.manager.store.conn.in_transaction)
        self.assertEqual(self.manager.reports.build(report["report_build_id"])["state"], "built")

    def test_report_prepare_failure_rolls_back_model_inputs_and_audit(self):
        self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "A"})
        self.publish("Report basis")
        tables = ("report_builds", "report_build_inputs", "audit_events")
        before = {table: self.manager.store.rows(f"SELECT * FROM {table}") for table in tables}
        with patch.object(self.manager.store, "audit", side_effect=RuntimeError("prepare audit failure")):
            with self.assertRaisesRegex(RuntimeError, "prepare audit failure"):
                self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
        self.assertFalse(self.manager.store.conn.in_transaction)
        self.assertEqual(before, {table: self.manager.store.rows(f"SELECT * FROM {table}") for table in tables})

    def test_report_build_keeps_input_reservation_through_render(self):
        self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "A"})
        self.publish("Report basis")
        report = self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
        render = self.manager.reports._render
        attempts = []

        def concurrent_attempt(model, output_format):
            with closing(sqlite3.connect(self.manager.store.db_path, timeout=0)) as other:
                with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                    other.execute("UPDATE issues SET title='Concurrent title' WHERE issue_id='sample-a'")
            attempts.append(True)
            return render(model, output_format)

        with patch.object(self.manager.reports, "_render", side_effect=concurrent_attempt):
            self.assertEqual(self.manager.reports.build(report["report_build_id"])["state"], "built")
        self.assertTrue(attempts)
        self.assertFalse(self.manager.store.conn.in_transaction)

    def test_report_render_failure_retains_prepared_state_without_database_artifact(self):
        self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "A"})
        self.publish("Report basis")
        report = self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
        before = self.manager.store.rows("SELECT * FROM artifacts")
        with patch.object(self.manager.reports, "_render", side_effect=RuntimeError("render failure")):
            with self.assertRaisesRegex(RuntimeError, "render failure"):
                self.manager.reports.build(report["report_build_id"])
        self.assertEqual(self.manager.reports.show(report["report_build_id"])["state"], "prepared")
        self.assertEqual(before, self.manager.store.rows("SELECT * FROM artifacts"))
        self.assertFalse(self.manager.store.conn.in_transaction)

    def test_report_rechecks_evidence_validation_for_included_and_filtered_records(self):
        evidence = self.manager.add_evidence(kind="external", locator="urn:report:validation")
        self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "A"},
                                    evidence_links=[{"field_path": "name", "evidence_id": evidence["evidence_id"], "relation_role": "supports"}])
        self.publish("Report basis")
        template = "org.example.v81/report_template/summary@1.0.0"
        historical = self.manager.reports.prepare(template, scope={"issue_id": "sample-a"})
        self.manager.reports.build(historical["report_build_id"])
        reports = [self.manager.reports.prepare(template, scope={"issue_id": "sample-a"}, query=query)
                   for query in ({}, {"name": {"eq": "B"}})]
        self.assertEqual([report["rows"] for report in reports], [1, 0])
        apply_reviewed_changeset(self.manager, self.organizer, [
            {"op": "void_evidence", "evidence_id": evidence["evidence_id"], "reason": "Invalid evidence"}])
        for report in reports:
            with self.subTest(rows=report["rows"]), self.assertRaises(ConflictError) as error:
                self.manager.reports.build(report["report_build_id"])
            self.assertIn("report_validation_changed", {item.get("code") for item in error.exception.details["changed_inputs"]})
        self.assertTrue(self.manager.reports.reproduce(historical["report_build_id"])["artifact_integrity"]["model_hash_valid"])

    def test_report_previously_ineligible_record_becomes_eligible(self):
        self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "A"})
        report = self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
        self.assertEqual(report["rows"], 0)
        self.publish("Now eligible")
        with self.assertRaises(ConflictError) as error:
            self.manager.reports.build(report["report_build_id"])
        self.assertIn("report_eligibility_changed", {item.get("code") for item in error.exception.details["changed_inputs"]})

    def test_report_quarantine_added_after_prepare_requires_reprepare(self):
        record = self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "A"})
        self.publish("Report basis")
        template = "org.example.v81/report_template/summary@1.0.0"
        historical = self.manager.reports.prepare(template, scope={"issue_id": "sample-a"})
        self.manager.reports.build(historical["report_build_id"])
        report = self.manager.reports.prepare(template, scope={"issue_id": "sample-a"})
        with self.manager.store.transaction() as conn:
            conn.execute("INSERT INTO migration_findings(finding_id,migration_version,object_type,object_id,classification,code,details_json,state) "
                         "VALUES ('report-quarantine',13,'record_revisions',?,'blocking_corruption','json_column_invalid',?, 'open')",
                         (record["record_revision_id"], '{"table":"record_revisions","column":"data_json"}'))
        self.manager.store.create_integrity_quarantine("report-quarantine", scopes=["exclude_new_reports"],
                                                      reason="Hold report use", actor="organizer-agent")
        with self.assertRaises(ConflictError) as error:
            self.manager.reports.build(report["report_build_id"])
        self.assertIn("report_eligibility_changed", {item.get("code") for item in error.exception.details["changed_inputs"]})
        fresh = self.manager.reports.prepare(template, scope={"issue_id": "sample-a"})
        self.assertEqual(fresh["rows"], 0)
        self.assertTrue(self.manager.reports.reproduce(historical["report_build_id"])["artifact_integrity"]["model_hash_valid"])

    def test_report_reuse_checks_content_and_preserves_corrupt_object(self):
        self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "A"})
        self.publish("Report basis")
        template = "org.example.v81/report_template/summary@1.0.0"
        content = b"Frozen report output\n"
        with patch.object(self.manager.reports, "_render", return_value=content):
            first = self.manager.reports.prepare(template, scope={"issue_id": "sample-a"})
            built = self.manager.reports.build(first["report_build_id"])
            artifact = self.manager.store.row("SELECT * FROM artifacts WHERE artifact_id=?", (built["output_artifact_id"],))
            object_path = self.manager.store.ledger_dir / artifact["storage_uri"]
            second = self.manager.reports.prepare(template, scope={"issue_id": "sample-a"})
            corrupt = b"X" * len(content)
            object_path.write_bytes(corrupt)
            with self.assertRaises(ConflictError) as error:
                self.manager.reports.build(second["report_build_id"])
            self.assertEqual(error.exception.details["code"], "report_object_content_mismatch")
            self.assertEqual(object_path.read_bytes(), corrupt)
            self.assertEqual(self.manager.reports.show(second["report_build_id"])["state"], "prepared")
            self.assertEqual(list((self.manager.store.ledger_dir / "reports").glob(f"{second['report_build_id']}.*")), [])
            object_path.write_bytes(content)
            recovered = self.manager.reports.build(second["report_build_id"])
        self.assertEqual(recovered["output_artifact_id"], built["output_artifact_id"])

    def test_report_expiring_during_render_does_not_publish_output(self):
        self.manager.records.create("sample-a", self.record_template["registration_id"], data={
            "name": "A", "measurement": {"value": 1, "unit": "m", "valid_until": "2090-01-02T00:00:00Z"}})
        self.publish("Report basis")
        render = self.manager.reports._render
        before = self.manager.store.rows("SELECT * FROM artifacts")
        with patch("issue_manager.report_service.datetime", wraps=datetime) as clock:
            clock.now.return_value = datetime(2090, 1, 1, tzinfo=timezone.utc)
            report = self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})

            def cross_boundary(model, output_format):
                content = render(model, output_format)
                clock.now.return_value = datetime(2090, 1, 3, tzinfo=timezone.utc)
                return content

            with patch.object(self.manager.reports, "_render", side_effect=cross_boundary):
                with self.assertRaises(ConflictError) as error:
                    self.manager.reports.build(report["report_build_id"])
        self.assertEqual(error.exception.details["changed_inputs"][0]["phase"], "after_render")
        shown = self.manager.reports.show(report["report_build_id"])
        self.assertEqual(shown["state"], "stale")
        self.assertIsNone(shown["output_artifact_id"])
        self.assertEqual(before, self.manager.store.rows("SELECT * FROM artifacts"))
        self.assertEqual(list((self.manager.store.ledger_dir / "reports").glob(f"{report['report_build_id']}.*")), [])

    def test_report_validity_boundary_requires_reprepare_without_database_writes(self):
        self.manager.records.create("sample-a", self.record_template["registration_id"], data={
            "name": "A", "measurement": {"value": 1, "unit": "m", "valid_until": "2090-01-02T00:00:00Z"}})
        self.publish("Report basis")
        with patch("issue_manager.report_service.datetime", wraps=datetime) as clock:
            clock.now.return_value = datetime(2090, 1, 1, tzinfo=timezone.utc)
            historical = self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
            pending = self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
            clock.now.return_value = datetime(2090, 1, 1, 12, tzinfo=timezone.utc)
            self.assertEqual(self.manager.reports.build(historical["report_build_id"])["state"], "built")
            clock.now.return_value = datetime(2090, 1, 3, tzinfo=timezone.utc)
            with self.assertRaises(ConflictError) as error:
                self.manager.reports.build(pending["report_build_id"])
            self.assertIn("report_time_condition_changed", {item.get("code") for item in error.exception.details["changed_inputs"]})
            fresh = self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
            self.assertEqual(self.manager.reports.build(fresh["report_build_id"])["state"], "built")
            reproduced = self.manager.reports.reproduce(historical["report_build_id"])
            self.assertTrue(reproduced["artifact_integrity"]["model_hash_valid"])

    def test_report_candidate_watch_detects_new_records_and_empty_ranges(self):
        template = "org.example.v81/report_template/summary@1.0.0"
        self.publish("Report basis")
        empty = self.manager.reports.prepare(template, scope={"issue_id": "sample-a"})
        self.assertEqual(empty["rows"], 0)
        self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "A"})
        with self.assertRaises(ConflictError) as error:
            self.manager.reports.build(empty["report_build_id"])
        self.assertIn("report_candidate_membership_changed", {item.get("code") for item in error.exception.details["changed_inputs"]})
        self.publish("Updated basis")
        populated = self.manager.reports.prepare(template, scope={"issue_id": "sample-a"})
        self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "B"})
        with self.assertRaises(ConflictError) as error:
            self.manager.reports.build(populated["report_build_id"])
        self.assertIn("report_candidate_membership_changed", {item.get("code") for item in error.exception.details["changed_inputs"]})

    def test_report_candidate_watch_ignores_records_outside_scope(self):
        self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "A"})
        self.publish("Report basis")
        report = self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
        self.manager.create_issue("sample-b", "specimen", issue_type_registration_id=self.specimen["registration_id"])
        self.manager.records.create("sample-b", self.record_template["registration_id"], data={"name": "B"})
        self.assertEqual(self.manager.reports.build(report["report_build_id"])["state"], "built")

    def test_report_candidate_watch_discovers_new_issues_in_type_scope(self):
        report = self.manager.reports.prepare(
            "org.example.v81/report_template/summary@1.0.0",
            scope={"issue_type_registration_ids": [self.specimen["registration_id"]]},
        )
        self.manager.create_issue("sample-b", "specimen", issue_type_registration_id=self.specimen["registration_id"])
        self.manager.records.create("sample-b", self.record_template["registration_id"], data={"name": "B"})
        with self.assertRaises(ConflictError) as error:
            self.manager.reports.build(report["report_build_id"])
        self.assertIn("report_candidate_membership_changed", {item.get("code") for item in error.exception.details["changed_inputs"]})

    def test_report_candidate_watch_tracks_previously_filtered_record(self):
        record = self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "B"})
        self.publish("Report basis")
        report = self.manager.reports.prepare(
            "org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"}, query={"name": {"eq": "A"}})
        self.assertEqual(report["rows"], 0)
        self.manager.records.revise(record["record_instance_id"], {"name": "A"}, expected_revision_id=record["record_revision_id"])
        with self.assertRaises(ConflictError) as error:
            self.manager.reports.build(report["report_build_id"])
        self.assertIn("report_candidate_membership_changed", {item.get("code") for item in error.exception.details["changed_inputs"]})

    def test_report_missing_candidate_watch_requires_reprepare_even_when_empty(self):
        report = self.manager.reports.prepare(
            "org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
        with self.manager.store.transaction() as conn:
            conn.execute("UPDATE report_builds SET report_model_json=json_remove(report_model_json,'$.provenance.candidate_watch') "
                         "WHERE report_build_id=?", (report["report_build_id"],))
        with self.assertRaises(ConflictError) as error:
            self.manager.reports.build(report["report_build_id"])
        self.assertIn("report_candidate_snapshot_missing", {item.get("code") for item in error.exception.details["changed_inputs"]})

    def test_report_current_material_basis_changes_without_rewriting_history(self):
        record = self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "A"})
        evidence = self.manager.add_evidence(kind="external", locator="urn:report:current-material")
        self.publish("Report basis")
        template = "org.example.v81/report_template/summary@1.0.0"
        historical = self.manager.reports.prepare(template, scope={"issue_id": "sample-a"})
        built = self.manager.reports.build(historical["report_build_id"])
        prepared = self.manager.reports.prepare(template, scope={"issue_id": "sample-a"})
        add = {"op": "record_relation", "action": "add", "relation_id": "report-material", "reason": "Additional source",
               "replacement": {"record_revision_id": record["record_revision_id"], "field_path": "name",
                               "evidence_id": evidence["evidence_id"], "relation_role": "supports"}}
        apply_reviewed_changeset(self.manager, self.organizer, [add])
        with self.assertRaises(ConflictError) as error:
            self.manager.reports.build(prepared["report_build_id"])
        self.assertIn("record_material_membership_changed", {item.get("code") for item in error.exception.details["changed_inputs"]})
        self.publish("Updated report basis")
        current = self.manager.reports.prepare(template, scope={"issue_id": "sample-a"})
        inputs = self.manager.reports.show(current["report_build_id"])["inputs"]
        snapshot = next(item["snapshot"] for item in inputs if item["object_type"] == "record_revision")
        self.assertEqual(snapshot["evidence_links"], [])
        self.assertEqual(snapshot["current_material_relations"][0]["relation_id"], "report-material")
        disable = {"op": "record_relation", "action": "disable", "relation_id": "report-material",
                   "expected_version_id": "record:report-material:1", "expected_active": True, "reason": "Withdraw source"}
        apply_reviewed_changeset(self.manager, self.organizer, [disable])
        with self.assertRaises(ConflictError):
            self.manager.reports.build(current["report_build_id"])
        reproduced = self.manager.reports.reproduce(built["report_build_id"])
        self.assertTrue(reproduced["artifact_integrity"]["artifact_hash_valid"])
        self.assertTrue(reproduced["artifact_integrity"]["model_hash_valid"])

    def test_report_missing_current_material_snapshot_requires_reprepare(self):
        self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "A"})
        self.publish("Report basis")
        report = self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
        # Emulate a prepared input from the earlier runtime, without inventing
        # a current-material receipt on its behalf.
        with self.manager.store.transaction() as conn:
            conn.execute("UPDATE report_build_inputs SET snapshot_json=json_remove(snapshot_json,'$.current_material_relations') "
                         "WHERE report_build_id=? AND object_type='record_revision'", (report["report_build_id"],))
        with self.assertRaises(ConflictError) as error:
            self.manager.reports.build(report["report_build_id"])
        self.assertIn("record_material_snapshot_missing", {item.get("code") for item in error.exception.details["changed_inputs"]})
        self.assertEqual(self.manager.reports.show(report["report_build_id"])["state"], "stale")

    def test_review_duty_blocks_report_without_invalidating_conclusion(self) -> None:
        self.manager.records.create("sample-a", self.record_template["registration_id"], data={"name": "A"})
        self.publish("Report basis")
        conclusion = self.manager.show_issue("sample-a")["current_conclusion"]["conclusion_id"]
        historical = self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
        built = self.manager.reports.build(historical["report_build_id"])
        prepared = self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
        apply_reviewed_changeset(self.manager, self.organizer, [{
            "op": "context_obligation", "action": "open", "obligation_id": "report-duty", "conclusion_id": conclusion,
            "details": {"request": "Sign off before reporting"}, "blocks_publication": True, "reason": "Review required"}])
        self.assertEqual(self.manager.context_maintenance.show(conclusion)["currentness"], "current")
        reproduced = self.manager.reports.reproduce(built["report_build_id"])
        self.assertTrue(reproduced["artifact_integrity"]["artifact_hash_valid"])
        self.assertTrue(reproduced["artifact_integrity"]["model_hash_valid"])
        with self.assertRaises(ConflictError):
            self.manager.reports.build(prepared["report_build_id"])
        excluded = self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
        self.assertEqual(excluded["rows"], 0)
        self.assertEqual(excluded["excluded"][0]["reason"], "independent_review_required")
        apply_reviewed_changeset(self.manager, self.organizer, [{
            "op": "context_obligation", "action": "complete", "obligation_id": "report-duty", "expected_revision": 0, "reason": "Signed off"}])
        ready = self.manager.reports.prepare("org.example.v81/report_template/summary@1.0.0", scope={"issue_id": "sample-a"})
        self.assertEqual(ready["rows"], 1)
        self.assertEqual(self.manager.reports.build(ready["report_build_id"])["state"], "built")

    def test_remote_field_bundle_blob_cas_route_apply_and_replay(self) -> None:
        blob = b"field attachment"
        digest = hashlib.sha256(blob).hexdigest()
        bundle = {
            "manifest": {
                "bundle_id": "field-v81",
                "bundle_version": FIELD_BUNDLE_VERSION,
                "created_by": "fixture",
                "created_at": now(),
                "source_namespace": "platform.fixture",
                "source_owner": "organizer-agent",
                "attachments": [
                    {"path": "a.bin", "sha256": digest, "size": len(blob)},
                    {"path": "copy.bin", "sha256": digest, "size": len(blob)},
                ],
            },
            "events": [
                {
                    "event_id": "observation-1",
                    "event_type": "observation",
                    "issue_id": "sample-a",
                    "body": "offline observation",
                }
            ],
        }
        begun = self.manager.field_bundles.upload(bundle)
        self.assertEqual(begun["state"], "received")
        self.assertEqual(len(begun["upload_tokens"]), 1)
        token = begun["upload_tokens"][0]["upload_token"]
        self.manager.field_bundles.upload_blob(
            "field-v81", digest, blob[:5], upload_token=token, final=False
        )
        completed = self.manager.field_bundles.upload_blob(
            "field-v81", digest, blob[5:], upload_token=token, offset=5, final=True
        )
        self.assertTrue(completed["complete"])
        shown = self.manager.field_bundles.show("field-v81")
        self.assertTrue(all(item["upload_state"] == "verified" for item in shown["attachments"]))
        artifact_id = shown["attachments"][0]["artifact_id"]
        self.assertEqual(shown["attachments"][1]["artifact_id"], artifact_id)
        self.assertTrue(self.manager.artifacts.verify(artifact_id)["ok"])
        routed = self.manager.field_bundles.route("field-v81")
        self.assertEqual(routed["state"], "ready")
        applied = self.manager.field_bundles.apply("field-v81")
        self.assertEqual(applied["state"], "applied")
        replay = self.manager.field_bundles.apply("field-v81")
        self.assertTrue(replay["idempotent_replay"])

    def test_import_levels_and_persistent_conflict_resume(self) -> None:
        mapping = "org.example.v81/mapping_profile/measurement-map@1.0.0"
        baseline_records = len(self.manager.store.rows("SELECT 1 FROM record_instances"))
        index_job = self.manager.imports.submit_bundle(
            self.import_bundle(owner="index-owner", external_id="index-1", name="Index")
        )["import_job_id"]
        self.manager.imports.stage(index_job, mapping_reference=mapping, migration_level="index")
        self.manager.imports.validate(index_job)
        index_result = self.manager.imports.apply(index_job)
        self.assertEqual(index_result["applied"][0]["created_objects"], ["external_mapping", "search_index"])
        self.assertEqual(len(self.manager.store.rows("SELECT 1 FROM record_instances")), baseline_records)

        for owner, level in (("structure-owner", "structure"), ("evidence-owner", "evidence_backfill")):
            job_id = self.manager.imports.submit_bundle(
                self.import_bundle(owner=owner, external_id="row-1", name=level)
            )["import_job_id"]
            self.manager.imports.stage(
                job_id,
                mapping_reference=mapping,
                target_issue_id="sample-a",
                migration_level=level,
            )
            self.manager.imports.validate(job_id)
            result = self.manager.imports.apply(job_id)
            created = result["applied"][0]["created_objects"]
            self.assertIn("record", created)
            self.assertEqual("evidence_candidate" in created, level == "evidence_backfill")
            if level == "evidence_backfill":
                self.assertTrue(result["applied"][0]["import_manifest_candidate_id"])
                shown = self.manager.imports.show(job_id)
                self.assertEqual(shown["manifest_candidates"][0]["state"], "pending_review")
                self.assertEqual(
                    shown["manifest_candidates"][0]["candidate"]["raw_fragment_hash"],
                    shown["items"][0]["raw_fragment_hash"],
                )

        first = self.manager.imports.submit_bundle(
            self.import_bundle(owner="conflict-owner", external_id="same", name="first")
        )["import_job_id"]
        self.manager.imports.stage(first, mapping_reference=mapping, target_issue_id="sample-a")
        self.manager.imports.validate(first)
        self.manager.imports.apply(first)
        second = self.manager.imports.submit_bundle(
            self.import_bundle(owner="conflict-owner", external_id="same", name="second")
        )["import_job_id"]
        self.manager.imports.stage(second, mapping_reference=mapping, target_issue_id="sample-a")
        validation = self.manager.imports.validate(second)
        self.assertEqual(validation["items"][0]["state"], "conflict")
        partial = self.manager.imports.apply(second)
        self.assertEqual(partial["state"], "partially_applied")
        conflict = self.manager.imports.conflicts(second)[0]
        self.manager.imports.resolve_conflict(
            second,
            conflict["integration_conflict_id"],
            "keep_internal_and_update_mapping",
            expected_revision=0,
        )
        resumed = self.manager.imports.resume(second)
        self.assertEqual(resumed["state"], "applied")

    def test_local_adapter_install_disable_and_hash_drift(self) -> None:
        executable = self.root / "adapter.exe"
        shutil.copy2(sys.executable, executable)
        descriptor = {
            "kind": "import",
            "name": "fixture-adapter",
            "version": "1.0.0",
            "protocol_version": ADAPTER_PROTOCOL,
            "timeout_seconds": 1,
            "maximum_output_bytes": 1024,
        }
        installed = self.manager.adapters.install(descriptor, executable)
        self.assertTrue(self.manager.adapters.verify("fixture-adapter@1.0.0", kind="import")["ok"])
        self.manager.adapters.set_enabled(
            "fixture-adapter@1.0.0", False, kind="import", reason="test disable"
        )
        with self.assertRaises(ConflictError):
            self.manager.adapters.execute(
                "fixture-adapter@1.0.0", kind="import", payload={}
            )
        self.manager.adapters.set_enabled("fixture-adapter@1.0.0", True, kind="import")
        executable.write_bytes(executable.read_bytes() + b"drift")
        self.assertFalse(self.manager.adapters.verify("fixture-adapter@1.0.0", kind="import")["ok"])
        with self.assertRaises(ConflictError):
            self.manager.adapters.execute(
                "fixture-adapter@1.0.0", kind="import", payload={}
            )
        self.assertTrue(installed["adapter_install_receipt_id"])


if __name__ == "__main__":
    unittest.main()
