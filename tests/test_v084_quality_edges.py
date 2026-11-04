from __future__ import annotations

import copy
import json
import math
import sqlite3
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from context_fixtures import corrupt_history
from test_v082 import V082Base

from issue_manager.default_policy import DEFAULT_POLICY
from issue_manager.errors import (
    ConflictError,
    NotFoundError,
    ValidationError,
)
from issue_manager.errors import PermissionError as ManagerPermissionError
from issue_manager.integrity import (
    _conclusion_findings,
    _conclusion_publication_profile_findings,
    _datetime_valid,
    _field_errors,
    _field_findings,
    _field_value,
    _receipt_finding_identity,
    _record_findings,
    _report_findings,
    _successor_supersedes,
    _template_fields,
    active_quarantines,
    assert_not_quarantined,
    digest,
    load_dependency,
    normalize_object_type,
    object_dependencies,
    object_hash,
    object_snapshot,
    validate_object_integrity,
    validate_quarantine_release_receipt,
    validator_for,
)
from issue_manager.migration_resolution import (
    _dependency_state_findings,
    _object_dependencies,
    _object_postvalidate,
    _object_prevalidate,
    _policy_postvalidate,
    _policy_prevalidate,
    dependency_snapshot_hash,
    handler_for,
    postcondition_hash,
    proof_payload,
    replay_receipt,
)
from issue_manager.policy_repair import (
    _auto_binding_map,
    _candidate_plan,
    _resolve_dependencies,
    _revalidate_candidate,
    apply_policy_repair_mutation,
    finding_fingerprint,
    load_candidate,
    load_policy_subject,
    policy_repair_dependency,
)
from issue_manager.registry_service import migrated_policy_bundle
from issue_manager.store import Store, canonical_json, now


class V084QualityBase(V082Base):
    def finding(
        self,
        finding_id: str,
        code: str,
        object_type: str,
        object_id: str,
        *,
        classification: str = "blocking_corruption",
        details: dict | None = None,
    ) -> None:
        with self.manager.store.transaction() as conn:
            conn.execute(
                "INSERT INTO migration_findings(finding_id,migration_version,object_type,"
                "object_id,classification,code,details_json,state) "
                "VALUES (?,?,?,?,?,?,?,'open')",
                (
                    finding_id,
                    13,
                    object_type,
                    object_id,
                    classification,
                    code,
                    canonical_json(details or {}),
                ),
            )

    def legacy_policy(self, finding_id: str = "policy-edge") -> tuple[dict, dict]:
        policy = {
            "version": 1,
            "issue_types": {},
            "publication": {"custom_rule": "legacy"},
            "publication_requirements": {},
            "conclusion_schemas": {},
        }
        bundle = self.manager.registry.install_bundle(migrated_policy_bundle(policy))
        self.manager.registry.activate_bundle(bundle["bundle_id"])
        self.finding(
            finding_id,
            "legacy_policy_semantics_not_declaratively_convertible",
            "extension_bundle",
            bundle["bundle_id"],
            classification="requires_policy_mapping",
            details={
                "bundle_id": bundle["bundle_id"],
                "semantic_code": "unknown_publication_logic",
                "json_pointer": "/publication/custom_rule",
            },
        )
        return bundle, policy


class V084IntegrityQualityEdges(V084QualityBase):
    def test_field_and_template_validator_matrix(self) -> None:
        self.assertEqual(normalize_object_type("field_action"), "field_bundle_action")
        self.assertEqual(normalize_object_type("custom"), "custom")
        self.assertEqual(_field_value({"a": {"b": 1}}, "a.b"), (True, 1))
        self.assertEqual(_field_value({"a": 1}, "a.b"), (False, None))
        self.assertEqual(_template_fields({"fields": {"a": {"type": "string"}}})["a"]["type"], "string")
        self.assertEqual(
            _template_fields({"fields": [{"path": "a", "type": "number"}, None]})["a"],
            {"type": "number"},
        )
        self.assertEqual(_template_fields({"fields": "bad"}), {})
        self.assertTrue(_datetime_valid("2026-08-10T12:00:00+08:00"))
        self.assertFalse(_datetime_valid("2026-08-10"))
        self.assertFalse(_datetime_valid(3))

        valid = (
            ("x", {"type": "string"}),
            (3, {"type": "integer"}),
            (3.5, {"type": "number"}),
            (True, {"type": "boolean"}),
            ("a", {"type": "enum", "values": ["a"]}),
            ("2026-08-10T12:00:00Z", {"type": "datetime"}),
            ("PT1S", {"type": "duration"}),
            (3, {"type": "duration"}),
            ({"value": 1.0, "unit": "m"}, {"type": "quantity", "units": ["m"]}),
            (
                {"value": 1.0, "unit": "m", "uncertainty": 0.1},
                {"type": "uncertain_quantity", "units": ["m"]},
            ),
            ({}, {"type": "object"}),
            ([], {"type": "array"}),
            ("evidence-1", {"type": "evidence_ref"}),
            (None, {"type": "string", "nullable": True}),
        )
        for value, spec in valid:
            with self.subTest(valid=spec["type"]):
                self.assertEqual(_field_errors(value, spec, "x"), [])
        invalid = (
            (None, {"type": "string"}),
            (1, {"type": "string"}),
            (True, {"type": "integer"}),
            (math.inf, {"type": "number"}),
            (1, {"type": "boolean"}),
            ("b", {"type": "enum", "enum": ["a"]}),
            ("bad", {"type": "datetime"}),
            (-1, {"type": "duration"}),
            ([], {"type": "quantity"}),
            (
                {
                    "value": math.inf,
                    "unit": "s",
                    "uncertainty": -1,
                    "observed_at": "bad",
                    "valid_from": "bad",
                    "valid_until": "bad",
                },
                {"type": "uncertain_quantity", "allowed_units": ["m"]},
            ),
            ([], {"type": "object"}),
            ({}, {"type": "array"}),
            ("", {"type": "artifact_ref"}),
            (1, {"type": "unknown"}),
        )
        for value, spec in invalid:
            with self.subTest(invalid=spec["type"]):
                self.assertTrue(_field_errors(value, spec, "x"))

    def test_object_snapshots_validators_and_dependencies(self) -> None:
        record = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "base"}
        )
        self.assertEqual(
            object_snapshot(self.manager.store.conn, "record_instances", record["record_instance_id"])[
                "current"
            ]["revision"]["record_revision_id"],
            record["record_revision_id"],
        )
        self.assertEqual(
            object_snapshot(self.manager.store.conn, "record_revision", "missing")["load_error"],
            "subject_missing",
        )
        self.assertEqual(
            object_snapshot(self.manager.store.conn, "record_instance", "missing")["load_error"],
            "subject_missing",
        )
        self.assertEqual(
            object_snapshot(self.manager.store.conn, "conclusion", "missing")["load_error"],
            "subject_missing",
        )
        self.assertEqual(
            object_snapshot(self.manager.store.conn, "unknown", "x")["load_error"],
            "object_integrity_validator_unknown",
        )
        self.assertEqual(object_hash(self.manager.store.conn, "record_revision", record["record_revision_id"]), digest(object_snapshot(self.manager.store.conn, "record_revision", record["record_revision_id"])))
        self.assertIsNotNone(validator_for("record_revision", "data_json"))
        self.assertIsNone(validator_for("record_revision", "unknown_json"))
        unknown = validate_object_integrity(self.manager.store.conn, "artifact", "missing")
        self.assertFalse(unknown["valid"])
        self.assertEqual(unknown["findings"][0]["code"], "object_integrity_validator_unknown")

        self.publish()
        conclusion_id = self.manager.show_issue("sample-a")["current_conclusion"]["conclusion_id"]
        conclusion = object_snapshot(self.manager.store.conn, "conclusion", conclusion_id)
        self.assertEqual(conclusion["conclusion"]["conclusion_id"], conclusion_id)
        self.manager.records.revise(
            record["record_instance_id"],
            {"name": "next"},
            expected_revision_id=record["record_revision_id"],
        )
        record_dependencies = object_dependencies(
            self.manager.store.conn, "record_revision", record["record_revision_id"]
        )
        conclusion_dependencies = object_dependencies(
            self.manager.store.conn, "conclusion_revision", conclusion_id
        )
        self.assertEqual(record_dependencies[0]["dependency_type"], "record_template_snapshot")
        self.assertEqual(
            conclusion_dependencies[0]["dependency_type"], "issue_type_semantic_snapshot"
        )
        for dependency in (*record_dependencies, *conclusion_dependencies):
            self.assertIsNotNone(
                load_dependency(
                    self.manager.store.conn,
                    dependency["dependency_type"],
                    dependency["dependency_id"],
                )
            )
        self.assertIsNotNone(
            load_dependency(
                self.manager.store.conn,
                "extension_bundle",
                self.issue_type["bundle_id"],
            )
        )

    def test_integrity_dependency_defensive_fallthroughs(self) -> None:
        with patch(
            "issue_manager.integrity.object_snapshot",
            return_value={
                "object_type": "field_bundle",
                "row": {},
                "events": [],
                "attachments": [],
            },
        ):
            validation = validate_object_integrity(
                self.manager.store.conn,
                "field_bundle",
                "synthetic",
                column="manifest_json",
            )
        self.assertFalse(validation["valid"])

        snapshots = (
            (
                "record_revision",
                {"revision": {"template_snapshot_json": "{"}},
            ),
            (
                "conclusion_revision",
                {"conclusion": {"issue_type_semantic_snapshot_json": "["}},
            ),
            (
                "report_build",
                {
                    "row": {"report_template_registration_id": "missing-registration"},
                    "artifact": None,
                },
            ),
        )
        for object_type, snapshot in snapshots:
            with (
                self.subTest(object_type=object_type),
                patch("issue_manager.integrity.object_snapshot", return_value=snapshot),
            ):
                self.assertEqual(
                    object_dependencies(
                        self.manager.store.conn, object_type, "synthetic"
                    ),
                    [],
                )
        self.assertIsNotNone(
            load_dependency(
                self.manager.store.conn,
                "registry_registration",
                self.issue_type["registration_id"],
            )
        )
        self.assertIsNone(load_dependency(self.manager.store.conn, "extension_bundle", "missing"))
        self.assertIsNone(load_dependency(self.manager.store.conn, "changeset_operation", "bad"))
        self.assertIsNone(load_dependency(self.manager.store.conn, "unknown", "bad"))

    def test_field_report_and_conclusion_validator_drift_matrix(self) -> None:
        bundle = self.manager.field_bundles.upload(
            self.bundle(
                "integrity-matrix",
                {
                    "event_id": "integrity-event",
                    "event_type": "observation",
                    "issue_id": "sample-a",
                    "body": "value",
                },
            )
        )
        self.manager.field_bundles.route(bundle["field_bundle_id"])
        event = self.manager.store.row(
            "SELECT field_bundle_event_id FROM field_bundle_events WHERE field_bundle_id=?",
            (bundle["field_bundle_id"],),
        )
        self.assertTrue(
            validate_object_integrity(
                self.manager.store.conn, "field_bundle", bundle["field_bundle_id"]
            )["valid"]
        )
        self.assertTrue(
            validate_object_integrity(
                self.manager.store.conn, "field_bundle_event", event["field_bundle_event_id"]
            )["valid"]
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE field_bundle_events SET event_hash='wrong' WHERE field_bundle_event_id=?",
                (event["field_bundle_event_id"],),
            )
        self.assertIn(
            "field_identity_hash_mismatch",
            {
                item["code"]
                for item in validate_object_integrity(
                    self.manager.store.conn,
                    "field_bundle_event",
                    event["field_bundle_event_id"],
                )["findings"]
            },
        )

        self.publish()
        self.manager.records.create(
            "sample-a",
            self.record_template["registration_id"],
            data={"name": "report", "measurement": {"value": 1.0, "unit": "m"}, "optional": "ok"},
        )
        prepared = self.manager.reports.prepare(
            self.report_template["registration_id"], scope={"issue_id": "sample-a"}
        )
        built = self.manager.reports.build(prepared["report_build_id"])
        report_validation = validate_object_integrity(
            self.manager.store.conn, "report_build", prepared["report_build_id"]
        )
        self.assertTrue(report_validation["valid"], report_validation)
        report_dependencies = object_dependencies(
            self.manager.store.conn, "report_build", prepared["report_build_id"]
        )
        self.assertEqual(
            {item["dependency_type"] for item in report_dependencies},
            {"artifact", "registry_registration"},
        )
        self.assertIsNotNone(
            load_dependency(self.manager.store.conn, "artifact", built["output_artifact_id"])
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE report_builds SET basis_hash='wrong',render_receipt_json='{}' "
                "WHERE report_build_id=?",
                (prepared["report_build_id"],),
            )
        codes = {
            item["code"]
            for item in validate_object_integrity(
                self.manager.store.conn, "report_build", prepared["report_build_id"]
            )["findings"]
        }
        self.assertIn("report_basis_hash_mismatch", codes)
        self.assertIn("report_render_receipt_missing", codes)

        conclusion_id = self.manager.show_issue("sample-a")["current_conclusion"]["conclusion_id"]
        with corrupt_history(self.manager, "conclusion_revisions") as conn:
            conn.execute(
                "UPDATE conclusion_revisions SET issue_type_semantic_hash='wrong' WHERE conclusion_id=?",
                (conclusion_id,),
            )
        conclusion_codes = {
            item["code"]
            for item in validate_object_integrity(
                self.manager.store.conn, "conclusion_revision", conclusion_id
            )["findings"]
        }
        self.assertIn("conclusion_semantic_hash_mismatch", conclusion_codes)

    def test_quarantine_successor_release_and_error_matrix(self) -> None:
        record = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "old"}
        )
        successor = self.manager.records.revise(
            record["record_instance_id"],
            {"name": "new"},
            expected_revision_id=record["record_revision_id"],
        )
        self.finding(
            "quarantine-release",
            "json_column_invalid",
            "record_revisions",
            record["record_revision_id"],
            details={"table": "record_revisions", "column": "data_json"},
        )
        with self.assertRaises(ValidationError):
            self.manager.store.create_integrity_quarantine(
                "quarantine-release", scopes=[], reason="", actor="organizer-agent"
            )
        with self.assertRaises(ValidationError):
            self.manager.store.create_integrity_quarantine(
                "quarantine-release",
                scopes=["unknown"],
                reason="bad scope",
                actor="organizer-agent",
            )
        with self.assertRaises(NotFoundError):
            self.manager.store.create_integrity_quarantine(
                "missing", scopes=[], reason="missing", actor="organizer-agent"
            )
        quarantine = self.manager.store.create_integrity_quarantine(
            "quarantine-release",
            scopes=["read_with_warning"],
            reason="historical subject",
            actor="organizer-agent",
        )
        replay = self.manager.store.create_integrity_quarantine(
            "quarantine-release",
            scopes=["read_with_warning"],
            reason="historical subject",
            actor="organizer-agent",
        )
        self.assertTrue(replay["idempotent_replay"])
        with self.assertRaises(ConflictError):
            self.manager.store.create_integrity_quarantine(
                "quarantine-release",
                scopes=["block_publication"],
                reason="different scope",
                actor="organizer-agent",
            )
        self.assertTrue(active_quarantines(self.manager.store.conn, "record_revision", record["record_revision_id"]))
        self.assertTrue(
            active_quarantines(
                self.manager.store.conn,
                "record_revision",
                record["record_revision_id"],
                scope="read_with_warning",
            )
        )
        with self.assertRaises(ConflictError):
            assert_not_quarantined(
                self.manager.store.conn,
                "record_revision",
                record["record_revision_id"],
                "read_with_warning",
            )
        self.assertTrue(
            self.manager.store.integrity_quarantine(quarantine["quarantine_id"])[
                "subject_hash_matches"
            ]
        )
        with self.assertRaises(NotFoundError):
            self.manager.store.integrity_quarantine("missing")

        self.finding(
            "successor-repair",
            "historical_json_invalid",
            "record_revisions",
            record["record_revision_id"],
            details={"table": "record_revisions", "column": "data_json"},
        )
        shown = self.manager.store.migration_finding("successor-repair")
        repaired = self.manager.store.resolve_migration_finding(
            "successor-repair",
            {
                "action": "repair_successor",
                "subject_hash": shown["subject_hash"],
                "successor_object_id": successor["record_revision_id"],
                "reason": "validated successor",
            },
            actor="organizer-agent",
        )
        self.assertTrue(repaired["accepted"], repaired)
        receipt = self.manager.store.migration_finding_receipt(repaired["receipt_id"])
        self.assertEqual(receipt["subject_before_hash"], quarantine["subject_hash"])
        with patch(
            "issue_manager.migration_resolution.replay_receipt",
            return_value={
                "valid": False,
                "mode": "full",
                "findings": [{"code": "forced_replay_failure"}],
            },
        ):
            with self.assertRaises(ValidationError) as replay_error:
                self.manager.store.release_integrity_quarantine(
                    quarantine["quarantine_id"],
                    repair_receipt_id=repaired["receipt_id"],
                    actor="organizer-agent",
                )
        self.assertEqual(
            replay_error.exception.details["code"], "quarantine_release_replay_failed"
        )
        released = self.manager.store.release_integrity_quarantine(
            quarantine["quarantine_id"],
            repair_receipt_id=repaired["receipt_id"],
            actor="organizer-agent",
        )
        self.assertEqual(released["state"], "released")
        self.assertTrue(
            self.manager.store.release_integrity_quarantine(
                quarantine["quarantine_id"],
                repair_receipt_id=repaired["receipt_id"],
                actor="organizer-agent",
            )["idempotent_replay"]
        )
        with self.assertRaises(ConflictError):
            self.manager.store.release_integrity_quarantine(
                quarantine["quarantine_id"],
                repair_receipt_id="different",
                actor="organizer-agent",
            )

    def test_validator_internal_negative_matrix(self) -> None:
        record = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "valid"}
        )
        record_subject = object_snapshot(
            self.manager.store.conn, "record_revision", record["record_revision_id"]
        )
        bad_record = copy.deepcopy(record_subject)
        bad_record["instance"] = None
        bad_record["revision"]["template_content_hash"] = "wrong"
        bad_record["revision"]["content_hash"] = "wrong"
        bad_record["revision"]["validation_profile"] = "accepted"
        template = {
            "content_hash": "also-wrong",
            "definition": {
                "fields": [
                    {"path": "required", "type": "string", "required": True},
                    {"path": "measured", "type": "number", "evidence_required": True},
                ],
                "profiles": {"accepted": "bad-profile"},
                "additional_fields": False,
            },
        }
        bad_record["revision"]["template_snapshot_json"] = canonical_json(template)
        bad_record["revision"]["data_json"] = canonical_json(
            {"name": "valid", "measured": 1, "extra": True}
        )
        bad_record["links"] = [
            {
                "field_path": "measured",
                "evidence_id": "missing",
                "proof_id": "missing-proof",
                "proof_hash": "wrong",
                "evidence_semantic_revision": 1,
            }
        ]
        record_codes = {
            item["code"] for item in _record_findings(self.manager.store.conn, bad_record)
        }
        self.assertTrue(
            {
                "record_instance_ownership_invalid",
                "record_template_hash_mismatch",
                "record_validation_profile_invalid",
                "record_required_field_missing",
                "record_additional_field_forbidden",
                "record_evidence_link_invalid",
                "record_revision_content_hash_mismatch",
            }.issubset(record_codes)
        )
        malformed_record = copy.deepcopy(record_subject)
        malformed_record["revision"]["data_json"] = "{"
        malformed_record["revision"]["template_snapshot_json"] = "[]"
        self.assertTrue(_record_findings(self.manager.store.conn, malformed_record))
        invalid_definition = copy.deepcopy(record_subject)
        invalid_definition["revision"]["template_snapshot_json"] = canonical_json(
            {"content_hash": invalid_definition["revision"]["template_content_hash"], "definition": []}
        )
        self.assertIn(
            "record_template_definition_invalid",
            {item["code"] for item in _record_findings(self.manager.store.conn, invalid_definition)},
        )

        self.publish()
        conclusion_id = self.manager.show_issue("sample-a")["current_conclusion"]["conclusion_id"]
        conclusion_subject = object_snapshot(
            self.manager.store.conn, "conclusion_revision", conclusion_id
        )
        bad_conclusion = copy.deepcopy(conclusion_subject)
        bad_conclusion["issue"] = None
        bad_conclusion["conclusion"]["structured_outputs_json"] = "[]"
        bad_conclusion["conclusion"]["limitations_json"] = "{}"
        semantics = {
            "definition": {
                "conclusion": {
                    "structured_outputs_schema": {
                        "type": "object",
                        "required": ["required"],
                    },
                    "publication_profiles": {
                        bad_conclusion["conclusion"]["status"]: {"min_active_evidence": 1}
                    },
                },
            }
        }
        bad_conclusion["conclusion"]["issue_type_semantic_snapshot_json"] = canonical_json(
            semantics
        )
        bad_conclusion["conclusion"]["issue_type_semantic_hash"] = "wrong"
        bad_conclusion["evidence"] = [
            {"proof_id": "missing", "proof_hash": "wrong"}
        ]
        conclusion_codes = {
            item["code"]
            for item in _conclusion_findings(self.manager.store.conn, bad_conclusion)
        }
        self.assertTrue(
            {
                "conclusion_structured_outputs_not_object",
                "conclusion_limitations_not_array",
                "conclusion_semantic_hash_mismatch",
                "conclusion_issue_ownership_invalid",
                "conclusion_evidence_proof_invalid",
            }.issubset(conclusion_codes)
        )

        action_subject = {
            "object_type": "field_bundle_action",
            "row": {
                "action_json": canonical_json(
                    {"record_instance_id": "one", "base_record_revision_id": "base"}
                ),
                "action_hash": "wrong",
                "target_record_instance_id": "two",
                "base_record_revision_id": "other",
            },
        }
        self.assertTrue(
            {
                "field_identity_hash_mismatch",
                "field_action_target_mismatch",
                "field_action_base_mismatch",
            }.issubset({item["code"] for item in _field_findings(action_subject)})
        )
        self.assertEqual(_field_findings({"load_error": "missing"}), [{"code": "missing"}])
        self.assertEqual(_report_findings({"load_error": "missing"}), [{"code": "missing"}])
        self.assertEqual(
            _conclusion_findings(self.manager.store.conn, {"load_error": "missing"}),
            [{"code": "missing"}],
        )
        exact_action = {
            "record_instance_id": "one",
            "base_record_revision_id": "base",
        }
        self.assertEqual(
            _field_findings(
                {
                    "object_type": "field_bundle_action",
                    "row": {
                        "action_json": canonical_json(exact_action),
                        "action_hash": digest(exact_action),
                        "target_record_instance_id": "one",
                        "base_record_revision_id": "base",
                    },
                }
            ),
            [],
        )
        prepared_report = {
            "object_type": "report_build",
            "row": {
                "state": "prepared",
                "scope_json": "{}",
                "normalized_scope_json": "{}",
                "query_json": "{}",
                "report_model_json": "{}",
                "report_template_snapshot_json": "{}",
                "renderer_snapshot_json": "{}",
                "renderer_config_json": "{}",
                "render_receipt_json": "{}",
            },
            "inputs": [],
            "artifact": None,
        }
        self.assertNotIn(
            "report_output_artifact_mismatch",
            {item["code"] for item in _report_findings(prepared_report)},
        )

    def test_integrity_branch_completion_matrix(self) -> None:
        record = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "evidence"}
        )
        evidence = self.manager.add_evidence(
            kind="external", locator="https://example.invalid/v084", issue_id="sample-a"
        )
        subject = object_snapshot(
            self.manager.store.conn, "record_revision", record["record_revision_id"]
        )
        template = {
            "content_hash": subject["revision"]["template_content_hash"],
            "definition": {
                "fields": {"measured": {"type": "number", "evidence_required": True}},
                "profiles": {"accepted": {"evidence_required": ["required-proof"]}},
            },
        }
        subject["revision"]["template_snapshot_json"] = canonical_json(template)
        subject["revision"]["validation_profile"] = "accepted"
        subject["revision"]["data_json"] = canonical_json({"measured": 1})
        subject["links"] = [
            {
                "field_path": "measured",
                "evidence_id": evidence["evidence_id"],
                "proof_id": None,
            },
            {
                "field_path": "other",
                "evidence_id": evidence["evidence_id"],
                "proof_id": "missing-proof",
                "proof_hash": "wrong",
                "evidence_semantic_revision": 1,
            },
        ]
        record_codes = {
            item["code"] for item in _record_findings(self.manager.store.conn, subject)
        }
        self.assertIn("record_evidence_required", record_codes)
        self.assertIn("record_evidence_proof_invalid", record_codes)
        current_drift = copy.deepcopy(subject)
        current_drift["revision"]["record_revision_id"] = "fake-current"
        current_drift["instance"]["current_revision_id"] = "fake-current"
        self.assertIn(
            "record_current_pointer_invalid",
            {
                item["code"]
                for item in _record_findings(self.manager.store.conn, current_drift)
            },
        )

        self.publish()
        conclusion_id = self.manager.show_issue("sample-a")["current_conclusion"]["conclusion_id"]
        conclusion = object_snapshot(
            self.manager.store.conn, "conclusion_revision", conclusion_id
        )
        malformed = copy.deepcopy(conclusion)
        malformed["conclusion"]["issue_type_semantic_snapshot_json"] = "[]"
        self.assertTrue(_conclusion_findings(self.manager.store.conn, malformed))
        quorum = copy.deepcopy(conclusion)
        semantics = {
            "definition": {
                "conclusion": {
                    "structured_outputs_schema": {
                        "type": "object",
                        "required": ["missing"],
                    },
                    "publication_profiles": {
                        quorum["conclusion"]["status"]: {"min_active_evidence": 2}
                    },
                },
            }
        }
        quorum["conclusion"]["issue_type_semantic_snapshot_json"] = canonical_json(semantics)
        quorum["conclusion"]["issue_type_semantic_hash"] = digest(semantics)
        quorum["evidence"] = []
        # Conclusions use their saved rule binding, not an unbound edited snapshot.
        schema = semantics["definition"]["conclusion"]["structured_outputs_schema"]
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        try:
            self.manager.store.conn.backup(conn)
            conn.execute("DROP TRIGGER conclusion_rule_bindings_no_update")
            conn.execute(
                "UPDATE conclusion_rule_bindings SET schema_json=?, schema_hash=? WHERE conclusion_id=?",
                (canonical_json(schema), digest(schema), conclusion_id),
            )
            quorum_codes = {item["code"] for item in _conclusion_findings(conn, quorum)}
        finally:
            conn.close()
        self.assertIn("conclusion_output_schema_invalid", quorum_codes)
        self.assertIn("conclusion_evidence_quorum_unsatisfied", quorum_codes)
        conclusion_drift = copy.deepcopy(conclusion)
        conclusion_drift["conclusion"]["conclusion_id"] = "fake-current"
        conclusion_drift["issue"]["current_conclusion_id"] = "fake-current"
        self.assertIn(
            "conclusion_current_pointer_invalid",
            {
                item["code"]
                for item in _conclusion_findings(self.manager.store.conn, conclusion_drift)
            },
        )

        invalid_bundle = {
            "object_type": "field_bundle",
            "row": {"manifest_json": "{", "content_hash": "wrong"},
            "events": [],
            "attachments": [],
        }
        self.assertIn(
            "field_json_invalid", {item["code"] for item in _field_findings(invalid_bundle)}
        )
        mismatched_bundle = {
            **invalid_bundle,
            "row": {"manifest_json": "{}", "content_hash": "wrong"},
        }
        self.assertIn(
            "field_identity_hash_mismatch",
            {item["code"] for item in _field_findings(mismatched_bundle)},
        )

    def test_p1_publication_profile_and_release_validation_matrix(self) -> None:
        self.publish()
        conclusion_id = self.manager.show_issue("sample-a")["current_conclusion"]["conclusion_id"]
        subject = object_snapshot(self.manager.store.conn, "conclusion_revision", conclusion_id)
        semantics = json.loads(subject["conclusion"]["issue_type_semantic_snapshot_json"])

        malformed_refs = copy.deepcopy(subject)
        malformed_refs["conclusion"]["evidence_refs_json"] = "{}"
        self.assertIn(
            "conclusion_evidence_refs_invalid",
            {
                item["code"]
                for item in _conclusion_findings(self.manager.store.conn, malformed_refs)
            },
        )
        malformed_refs["conclusion"]["evidence_refs_json"] = "[{}]"
        self.assertIn(
            "conclusion_evidence_refs_invalid",
            {
                item["code"]
                for item in _conclusion_findings(self.manager.store.conn, malformed_refs)
            },
        )
        malformed_definition = copy.deepcopy(subject)
        malformed_definition["conclusion"]["issue_type_semantic_snapshot_json"] = canonical_json(
            {"definition": []}
        )
        malformed_codes = {
            item["code"]
            for item in _conclusion_findings(self.manager.store.conn, malformed_definition)
        }
        self.assertIn("conclusion_semantic_snapshot_invalid", malformed_codes)
        malformed_schema = copy.deepcopy(subject)
        schema_snapshot = copy.deepcopy(semantics)
        schema_snapshot["definition"]["conclusion"]["structured_outputs_schema"] = []
        schema_snapshot["definition"]["conclusion"]["publication_profiles"] = []
        malformed_schema["conclusion"]["issue_type_semantic_snapshot_json"] = canonical_json(
            schema_snapshot
        )
        malformed_schema["conclusion"]["issue_type_semantic_hash"] = digest(schema_snapshot)
        # Exercise a malformed bound rule and malformed publication profiles.
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        try:
            self.manager.store.conn.backup(conn)
            conn.execute("DROP TRIGGER conclusion_rule_bindings_no_update")
            conn.execute(
                "UPDATE conclusion_rule_bindings SET schema_json=?, schema_hash=? WHERE conclusion_id=?",
                (canonical_json([]), digest([]), conclusion_id),
            )
            schema_codes = {item["code"] for item in _conclusion_findings(conn, malformed_schema)}
        finally:
            conn.close()
        self.assertIn("conclusion_semantic_snapshot_invalid", schema_codes)
        self.assertIn("conclusion_publication_profile_invalid", schema_codes)
        missing_profile = copy.deepcopy(subject)
        missing_snapshot = copy.deepcopy(semantics)
        missing_snapshot["definition"]["conclusion"]["publication_profiles"].pop("provisional")
        missing_profile["conclusion"]["issue_type_semantic_snapshot_json"] = canonical_json(
            missing_snapshot
        )
        missing_profile["conclusion"]["issue_type_semantic_hash"] = digest(missing_snapshot)
        self.assertIn(
            "conclusion_publication_profile_invalid",
            {
                item["code"]
                for item in _conclusion_findings(self.manager.store.conn, missing_profile)
            },
        )
        lifecycle_profile = copy.deepcopy(missing_profile)
        lifecycle_profile["conclusion"]["status"] = "disputed"
        self.assertNotIn(
            "conclusion_publication_profile_invalid",
            {
                item["code"]
                for item in _conclusion_findings(self.manager.store.conn, lifecycle_profile)
            },
        )

        invalid_profiles = (
            {"min_active_evidence": True},
            {"min_active_evidence": "1"},
            {"min_active_evidence": -1},
            {"review_quorum": True},
            {"review_quorum": "1"},
            {"review_quorum": -1},
            {"minimum_verification_level": []},
            {"minimum_verification_level": "unknown"},
        )
        for profile in invalid_profiles:
            with self.subTest(profile=profile):
                self.assertEqual(
                    _conclusion_publication_profile_findings(
                        self.manager.store.conn,
                        conclusion=subject["conclusion"],
                        outputs={},
                        evidence_refs=[],
                        valid_uses=[],
                        profile=profile,
                    ),
                    [{"code": "conclusion_publication_profile_invalid"}],
                )
        questionable = {
            "evidence_id": "questionable",
            "use_role": "support",
            "fitness": "fit_for_use",
            "quality_snapshot": "questionable",
            "verification_level_snapshot": "source_verified",
            "verification_state_snapshot": "active",
        }
        quality_findings = _conclusion_publication_profile_findings(
            self.manager.store.conn,
            conclusion=subject["conclusion"],
            outputs={"artifact_ids": "not-a-list", "derived_result": True},
            evidence_refs=[],
            valid_uses=[questionable],
            profile={
                "min_active_evidence": 1,
                "minimum_verification_level": "source_verified",
                "review_quorum": 1,
                "require_frozen_artifact": True,
                "require_analysis_run_or_waiver": True,
            },
        )
        quality_codes = {item["code"] for item in quality_findings}
        self.assertTrue(
            {
                "conclusion_evidence_quality_unsatisfied",
                "conclusion_review_quorum_unsatisfied",
                "conclusion_frozen_artifact_required",
                "conclusion_analysis_run_or_waiver_required",
                "conclusion_reproduced_support_required",
            }.issubset(quality_codes)
        )
        conflict_codes = {
            item["code"]
            for item in _conclusion_publication_profile_findings(
                self.manager.store.conn,
                conclusion={"proposal_id": "missing", "conclusion_id": "missing"},
                outputs={},
                evidence_refs=[],
                valid_uses=[
                    {
                        **questionable,
                        "quality_snapshot": "usable",
                        "verification_state_snapshot": "conflict",
                    }
                ],
                profile={
                    "min_active_evidence": 1,
                    "minimum_verification_level": "declared",
                    "review_quorum": 1,
                    "reject_conflict_as_only_support": True,
                },
            )
        }
        self.assertIn("conclusion_evidence_verification_unsatisfied", conflict_codes)

        with self.manager.store.transaction() as conn:
            conn.execute(
                "INSERT INTO artifacts(artifact_id,kind,role,mime_type,sha256,size,storage_uri,"
                "original_locator,created_at,created_by,frozen_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "profile-frozen-artifact",
                    "fixture",
                    "frozen",
                    "application/octet-stream",
                    "a" * 64,
                    1,
                    "objects/profile",
                    "fixture",
                    now(),
                    "organizer-agent",
                    now(),
                ),
            )
            conn.execute(
                "INSERT INTO analysis_methods(method_id,name,script_artifact_id,source_hash,"
                "created_at,created_by,scope) VALUES (?,?,?,?,?,?,?)",
                (
                    "profile-method",
                    "profile",
                    "profile-frozen-artifact",
                    "a" * 64,
                    now(),
                    "organizer-agent",
                    "shared-reviewed",
                ),
            )
            conn.execute(
                "INSERT INTO analysis_runs(analysis_run_id,method_id,config_json,environment_json,"
                "state,created_at,created_by,frozen_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    "profile-run",
                    "profile-method",
                    "{}",
                    "{}",
                    "frozen",
                    now(),
                    "organizer-agent",
                    now(),
                ),
            )
            conn.execute(
                "INSERT INTO analysis_outputs VALUES (?,?,?)",
                ("profile-run", "profile-frozen-artifact", "result"),
            )
        artifact_evidence = self.manager.add_evidence(
            kind="artifact", locator="profile-frozen-artifact", issue_id="sample-a"
        )
        reproduced = {
            **questionable,
            "evidence_id": artifact_evidence["evidence_id"],
            "quality_snapshot": "usable",
            "verification_level_snapshot": "reproduced",
        }
        self.assertEqual(
            _conclusion_publication_profile_findings(
                self.manager.store.conn,
                conclusion=subject["conclusion"],
                outputs={
                    "artifact_ids": ["profile-frozen-artifact"],
                    "derived_result": True,
                },
                evidence_refs=[artifact_evidence["evidence_id"]],
                valid_uses=[reproduced],
                profile={
                    "min_active_evidence": 1,
                    "minimum_verification_level": "reproduced",
                    "review_quorum": 0,
                    "require_frozen_artifact": True,
                    "require_analysis_run_or_waiver": True,
                },
            ),
            [],
        )

        self.assertEqual(
            _receipt_finding_identity(
                {
                    "finding_details_json": "{",
                    "finding_object_type": "record_revisions",
                    "finding_object_id": "record-a",
                }
            ),
            ("record_revision", "record-a"),
        )
        self.assertEqual(
            _receipt_finding_identity(
                {
                    "finding_details_json": "[]",
                    "finding_object_type": "field_bundle_event_actions",
                    "finding_object_id": "fallback",
                }
            ),
            ("field_bundle_action", "fallback"),
        )
        self.assertEqual(
            _receipt_finding_identity(
                {
                    "finding_details_json": canonical_json(
                        {
                            "table": "field_bundle_event_actions",
                            "field_bundle_event_action_id": "action-id",
                        }
                    )
                }
            ),
            ("field_bundle_action", "action-id"),
        )
        self.assertFalse(
            _successor_supersedes(
                self.manager.store.conn,
                "conclusion_revision",
                conclusion_id,
                "missing-conclusion",
            )
        )
        self.assertTrue(
            _successor_supersedes(
                self.manager.store.conn, "field_bundle", "old", "new"
            )
        )

        record = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "old"}
        )
        successor = self.manager.records.revise(
            record["record_instance_id"],
            {"name": "new"},
            expected_revision_id=record["record_revision_id"],
        )
        self.finding(
            "release-validation-matrix",
            "json_column_invalid",
            "record_revisions",
            record["record_revision_id"],
            details={"table": "record_revisions", "column": "data_json"},
        )
        quarantine = self.manager.store.create_integrity_quarantine(
            "release-validation-matrix",
            scopes=["read_with_warning"],
            reason="matrix",
            actor="organizer-agent",
        )
        shown = self.manager.store.migration_finding("release-validation-matrix")
        repaired = self.manager.store.resolve_migration_finding(
            "release-validation-matrix",
            {
                "action": "repair_successor",
                "subject_hash": shown["subject_hash"],
                "successor_object_id": successor["record_revision_id"],
                "reason": "matrix successor",
            },
            actor="organizer-agent",
        )
        self.assertEqual(
            validate_quarantine_release_receipt(
                self.manager.store,
                quarantine,
                "missing-receipt",
                full=False,
                actor="doctor",
            )["findings"][0]["code"],
            "quarantine_release_without_repair",
        )
        wrong_hash = {**quarantine, "subject_hash": "wrong"}
        self.assertEqual(
            validate_quarantine_release_receipt(
                self.manager.store,
                wrong_hash,
                repaired["receipt_id"],
                full=False,
                actor="doctor",
            )["findings"][0]["code"],
            "quarantine_release_subject_hash_mismatch",
        )
        with self.manager.store.transaction() as conn:
            original_resolution = conn.execute(
                "SELECT resolution_json FROM migration_finding_resolution_attempts "
                "WHERE attempt_id=?",
                (repaired["attempt_id"],),
            ).fetchone()[0]
            conn.execute(
                "UPDATE migration_finding_resolution_attempts SET resolution_json='[]' "
                "WHERE attempt_id=?",
                (repaired["attempt_id"],),
            )
        self.assertEqual(
            validate_quarantine_release_receipt(
                self.manager.store,
                quarantine,
                repaired["receipt_id"],
                full=False,
                actor="doctor",
            )["findings"][0]["code"],
            "quarantine_release_without_repair",
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_finding_resolution_attempts SET resolution_json='{' "
                "WHERE attempt_id=?",
                (repaired["attempt_id"],),
            )
        self.assertEqual(
            validate_quarantine_release_receipt(
                self.manager.store,
                quarantine,
                repaired["receipt_id"],
                full=False,
                actor="doctor",
            )["findings"][0]["code"],
            "quarantine_release_without_repair",
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_finding_resolution_attempts SET resolution_json=? "
                "WHERE attempt_id=?",
                (canonical_json({"action": "repair_successor"}), repaired["attempt_id"]),
            )
        self.assertEqual(
            validate_quarantine_release_receipt(
                self.manager.store,
                quarantine,
                repaired["receipt_id"],
                full=False,
                actor="doctor",
            )["findings"][0]["code"],
            "quarantine_release_successor_unbound",
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_finding_resolution_attempts SET resolution_json=? "
                "WHERE attempt_id=?",
                (original_resolution, repaired["attempt_id"]),
            )
            conn.execute(
                "UPDATE migration_finding_resolution_receipts SET subject_before_hash='wrong' "
                "WHERE receipt_id=?",
                (repaired["receipt_id"],),
            )
        drift_quarantine = {**quarantine, "subject_hash": "wrong"}
        self.assertEqual(
            validate_quarantine_release_receipt(
                self.manager.store,
                drift_quarantine,
                repaired["receipt_id"],
                full=False,
                actor="doctor",
            )["findings"][0]["code"],
            "quarantine_subject_drift",
        )
        invalid_action = {
            "object_type": "field_bundle_action",
            "row": {
                "action_json": "{",
                "action_hash": "wrong",
                "target_record_instance_id": None,
                "base_record_revision_id": None,
            },
        }
        self.assertIn(
            "field_json_invalid", {item["code"] for item in _field_findings(invalid_action)}
        )
        self.assertTrue(
            validate_object_integrity(
                self.manager.store.conn,
                "record_revision",
                record["record_revision_id"],
                column="validation_result_json",
            )["valid"]
        )
        self.assertIsNone(
            load_dependency(self.manager.store.conn, "record_template_snapshot", "missing")
        )
        self.assertIsNone(
            load_dependency(self.manager.store.conn, "issue_type_semantic_snapshot", "missing")
        )
        self.assertIsNone(
            load_dependency(self.manager.store.conn, "record_revision", "missing")
        )
        self.assertIsNone(load_dependency(self.manager.store.conn, "artifact", "missing"))
        self.assertIsNone(
            load_dependency(self.manager.store.conn, "integrity_quarantine", "missing")
        )


class V084PolicyAndProofQualityEdges(V084QualityBase):
    def test_policy_subject_fingerprint_and_candidate_plan_edges(self) -> None:
        bundle, _policy = self.legacy_policy()
        raw_finding = self.manager.store.row(
            "SELECT * FROM migration_findings WHERE finding_id='policy-edge'"
        )
        subject = load_policy_subject(self.manager.store.conn, raw_finding)
        fingerprint = finding_fingerprint(raw_finding, subject)
        self.assertEqual(fingerprint["source_bundle_id"], bundle["bundle_id"])
        malformed = {**raw_finding, "details_json": "{"}
        self.assertEqual(
            finding_fingerprint(malformed, subject)["semantic_code"],
            "unknown_policy_sections",
        )
        self.assertEqual(
            load_policy_subject(self.manager.store.conn, malformed)["bundle"]["bundle_id"],
            bundle["bundle_id"],
        )

        prepared = migrated_policy_bundle(copy.deepcopy(DEFAULT_POLICY))
        from issue_manager.registry_service import prepare_bundle

        prepared_bundle = prepare_bundle(prepared, trusted_local=True)
        binding = _auto_binding_map(subject, prepared_bundle)
        self.assertIsInstance(binding, dict)
        plan = _candidate_plan(
            mode="replacement_feature_bundle",
            fingerprint=fingerprint,
            prepared=prepared_bundle,
            dependency_locks=[],
            reference_locks=[],
            issue_binding_map={"old": "missing"},
            affected_issues=[{"issue_id": "x", "issue_type_registration_id": "old"}],
            replacement_policy_plan=None,
            registry_environment=[],
        )
        self.assertFalse(plan["safe_to_apply"])
        self.assertEqual(
            {item["code"] for item in plan["residual_findings"]},
            {"policy_repair_issue_binding_target_invalid"},
        )
        missing_plan = _candidate_plan(
            mode="replacement_feature_bundle",
            fingerprint=fingerprint,
            prepared=prepared_bundle,
            dependency_locks=[],
            reference_locks=[],
            issue_binding_map={},
            affected_issues=[{"issue_id": "x", "issue_type_registration_id": "old"}],
            replacement_policy_plan=None,
            registry_environment=[],
        )
        self.assertEqual(missing_plan["residual_findings"][0]["code"], "policy_repair_issue_binding_missing")

    def test_feature_bundle_candidate_and_stale_error_matrix(self) -> None:
        self.legacy_policy("feature-policy")
        with self.assertRaises(ValidationError):
            self.manager.store.create_migration_policy_repair(
                "feature-policy", actor="organizer-agent"
            )
        with self.assertRaises(ValidationError):
            self.manager.store.create_migration_policy_repair(
                "feature-policy",
                replacement_policy={},
                replacement_bundle={},
                actor="organizer-agent",
            )
        with self.assertRaises(NotFoundError):
            self.manager.store.create_migration_policy_repair(
                "missing", replacement_policy={}, actor="organizer-agent"
            )
        with self.assertRaises(NotFoundError):
            self.manager.store.migration_policy_repair("missing")
        with self.assertRaises(NotFoundError):
            load_candidate(self.manager.store.conn, "missing")
        self.assertEqual(policy_repair_dependency(self.manager.store.conn, "missing"), [])

        replacement = migrated_policy_bundle(copy.deepcopy(DEFAULT_POLICY))
        replacement["manifest"]["namespace"] = "org.example.v084.repair"
        replacement["manifest"]["name"] = "exact-replacement"
        candidate = self.manager.store.create_migration_policy_repair(
            "feature-policy",
            replacement_bundle=replacement,
            actor="organizer-agent",
        )
        validated = self.manager.store.validate_migration_policy_repair(candidate["repair_id"])
        self.assertEqual(validated["state"], "validated", validated["validation"])
        self.assertTrue(policy_repair_dependency(self.manager.store.conn, candidate["repair_id"]))
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_policy_repairs SET plan_hash='drift' WHERE repair_id=?",
                (candidate["repair_id"],),
            )
        stale = self.manager.store.validate_migration_policy_repair(candidate["repair_id"])
        self.assertEqual(stale["state"], "stale")
        self.assertIn("plan_hash", stale["validation"]["stale_fields"])
        with self.assertRaises(ConflictError):
            self.manager.store.apply_migration_policy_repair(
                candidate["repair_id"], actor="organizer-agent"
            )

        installed_bundle = self.manager.store.row(
            "SELECT namespace,name FROM extension_bundles WHERE bundle_id=?",
            (self.issue_type["bundle_id"],),
        )
        dependency_text = f"{installed_bundle['namespace']}/{installed_bundle['name']}@*"
        dependencies = _resolve_dependencies(
            self.manager.store.conn,
            [
                dependency_text,
                {
                    "namespace": installed_bundle["namespace"],
                    "name": installed_bundle["name"],
                    "version": "*",
                },
            ],
        )
        self.assertEqual(len(dependencies), 2)
        for invalid in ("bad", 3, "missing/nope@*"):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                _resolve_dependencies(self.manager.store.conn, [invalid])

    def test_proof_helpers_and_replay_drift_matrix(self) -> None:
        self.legacy_policy("proof-policy")
        candidate = self.manager.store.create_migration_policy_repair(
            "proof-policy",
            replacement_policy=copy.deepcopy(DEFAULT_POLICY),
            actor="organizer-agent",
        )
        self.manager.store.validate_migration_policy_repair(candidate["repair_id"])
        accepted = self.manager.store.apply_migration_policy_repair(
            candidate["repair_id"], actor="organizer-agent"
        )
        receipt = self.manager.store.migration_finding_receipt(accepted["receipt_id"])
        self.assertEqual(
            dependency_snapshot_hash(receipt["dependencies"]),
            receipt["dependency_snapshot_hash"],
        )
        postcondition = {"valid": True, "findings": [], "postcondition_hash": "ignored"}
        self.assertEqual(postcondition_hash(postcondition), digest({"valid": True, "findings": []}))
        payload = proof_payload(
            finding_id="f",
            finding_code="c",
            subject_before_hash="a",
            subject_after_hash="b",
            resolution_hash="r",
            invariant_id="i",
            invariant_version=2,
            invariant_parameters_hash="p",
            dependency_hash="d",
            postcondition_hash="q",
            result_objects=[
                {"object_type": "z", "object_id": "2", "content_hash": "h2"},
                {"object_type": "a", "object_id": "1", "content_hash": "h1"},
            ],
            actor="actor",
            event_id="event",
        )
        self.assertEqual(payload["result_object_hashes"][0]["object_type"], "a")
        self.assertTrue(replay_receipt(self.manager.store, accepted["receipt_id"], full=True)["valid"])
        with self.assertRaises(NotFoundError):
            replay_receipt(self.manager.store, "missing", full=False)
        attempt_id = receipt["accepted_attempt_id"]
        original_attempt = self.manager.store.row(
            "SELECT * FROM migration_finding_resolution_attempts WHERE attempt_id=?",
            (attempt_id,),
        )
        original_receipt = self.manager.store.row(
            "SELECT * FROM migration_finding_resolution_receipts WHERE receipt_id=?",
            (accepted["receipt_id"],),
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_finding_resolution_attempts SET resolution_json='{' "
                "WHERE attempt_id=?",
                (attempt_id,),
            )
        self.assertIn(
            "migration_resolution_proof_hash_mismatch",
            {
                item["code"]
                for item in replay_receipt(
                    self.manager.store, accepted["receipt_id"], full=False
                )["findings"]
            },
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_finding_resolution_attempts SET resolution_json=? WHERE attempt_id=?",
                (original_attempt["resolution_json"], attempt_id),
            )
            conn.execute(
                "UPDATE migration_finding_resolution_receipts SET invariant_id='unknown' "
                "WHERE receipt_id=?",
                (accepted["receipt_id"],),
            )
        self.assertIn(
            "migration_resolution_validator_unknown",
            {
                item["code"]
                for item in replay_receipt(
                    self.manager.store, accepted["receipt_id"], full=False
                )["findings"]
            },
        )
        dependency = receipt["dependencies"][0]
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_finding_resolution_receipts SET invariant_id=? WHERE receipt_id=?",
                (original_receipt["invariant_id"], accepted["receipt_id"]),
            )
            conn.execute(
                "UPDATE migration_resolution_dependencies SET dependency_id='missing' "
                "WHERE receipt_id=? AND ordinal=?",
                (accepted["receipt_id"], dependency["ordinal"]),
            )
        self.assertIn(
            "migration_resolution_dependency_missing",
            {
                item["code"]
                for item in replay_receipt(
                    self.manager.store, accepted["receipt_id"], full=False
                )["findings"]
            },
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_resolution_dependencies SET dependency_id=?,content_hash='wrong',"
                "required_states_json='[\"impossible\"]' WHERE receipt_id=? AND ordinal=?",
                (
                    dependency["dependency_id"],
                    accepted["receipt_id"],
                    dependency["ordinal"],
                ),
            )
        dependency_replay = replay_receipt(
            self.manager.store, accepted["receipt_id"], full=False
        )
        self.assertTrue(
            {
                "migration_resolution_dependency_hash_drift",
                "migration_resolution_dependency_state_drift",
            }.issubset({item["code"] for item in dependency_replay["findings"]})
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_finding_resolution_receipts SET invariant_parameters_json='{',"
                "postcondition_json='{}',invariant_parameters_hash='wrong',"
                "postcondition_hash='wrong',proof_format='v1' WHERE receipt_id=?",
                (accepted["receipt_id"],),
            )
        invalid_json_replay = replay_receipt(
            self.manager.store, accepted["receipt_id"], full=False, persist=True
        )
        self.assertFalse(invalid_json_replay["valid"])
        self.assertTrue(
            self.manager.store.rows(
                "SELECT * FROM migration_resolution_replays WHERE receipt_id=?",
                (accepted["receipt_id"],),
            )
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_finding_resolution_receipts SET proof_hash='drift' WHERE receipt_id=?",
                (accepted["receipt_id"],),
            )
        replay = replay_receipt(self.manager.store, accepted["receipt_id"], full=False)
        self.assertFalse(replay["valid"])
        self.assertIn("migration_resolution_proof_hash_mismatch", {item["code"] for item in replay["findings"]})
        self.assertIsNone(handler_for("unknown-code"))

    def test_policy_candidate_defensive_branch_matrix(self) -> None:
        bundle, _policy = self.legacy_policy("policy-defensive")
        candidate = self.manager.store.create_migration_policy_repair(
            "policy-defensive",
            replacement_policy=copy.deepcopy(DEFAULT_POLICY),
            actor="organizer-agent",
        )
        decoded = load_candidate(self.manager.store.conn, candidate["repair_id"])
        missing_finding = _revalidate_candidate(
            self.manager.store.conn, {**decoded, "finding_id": "missing"}
        )
        self.assertEqual(missing_finding["code"], "policy_repair_finding_missing")
        stale_candidate = {
            **decoded,
            "source_bundle_hash": "wrong",
            "source_policy_hash": "wrong",
            "finding_fingerprint_hash": "wrong",
            "plan_hash": "wrong",
        }
        stale = _revalidate_candidate(self.manager.store.conn, stale_candidate)
        self.assertTrue(
            {"source_bundle_hash", "source_policy_hash", "finding_fingerprint", "plan_hash"}.issubset(
                set(stale["stale_fields"])
            )
        )
        failed_prepare = _revalidate_candidate(
            self.manager.store.conn,
            {
                **decoded,
                "repair_mode": "replacement_feature_bundle",
                "replacement_bundle": {},
            },
        )
        self.assertEqual(failed_prepare["code"], "policy_repair_prepare_failed")

        self.finding(
            "policy-wrong-code",
            "json_column_invalid",
            "extension_bundle",
            bundle["bundle_id"],
        )
        with self.assertRaises(ValidationError):
            self.manager.store.create_migration_policy_repair(
                "policy-wrong-code",
                replacement_policy=copy.deepcopy(DEFAULT_POLICY),
                actor="organizer-agent",
            )
        self.finding(
            "policy-missing-source",
            "legacy_policy_snapshot_invalid",
            "extension_bundle",
            "missing",
            classification="requires_policy_mapping",
        )
        with self.assertRaises(ValidationError):
            self.manager.store.create_migration_policy_repair(
                "policy-missing-source",
                replacement_policy=copy.deepcopy(DEFAULT_POLICY),
                actor="organizer-agent",
            )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_findings SET state='resolved' WHERE finding_id='policy-defensive'"
            )
        self.assertIn(
            "finding_state",
            _revalidate_candidate(self.manager.store.conn, decoded)["stale_fields"],
        )
        with self.assertRaises(ConflictError):
            self.manager.store.create_migration_policy_repair(
                "policy-defensive",
                replacement_policy=copy.deepcopy(DEFAULT_POLICY),
                actor="organizer-agent",
            )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_findings SET state='open' WHERE finding_id='policy-defensive'"
            )
        self.manager.store.validate_migration_policy_repair(candidate["repair_id"])
        accepted = self.manager.store.apply_migration_policy_repair(
            candidate["repair_id"], actor="organizer-agent"
        )
        self.assertTrue(accepted["accepted"])
        with self.assertRaises(ConflictError):
            self.manager.store.validate_migration_policy_repair(candidate["repair_id"])
        with self.assertRaises(NotFoundError):
            self.manager.store.validate_migration_policy_repair("missing")

        legacy_finding = self.manager.store.row(
            "SELECT * FROM migration_findings WHERE finding_id='policy-defensive'"
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "INSERT INTO migration_findings(finding_id,migration_version,object_type,"
                "object_id,classification,code,details_json,state) "
                "VALUES ('policy-legacy-link',13,'extension_bundle',?,'requires_policy_mapping',"
                "'migration_policy_mapping_proof_insufficient',?,'open')",
                (
                    bundle["bundle_id"],
                    canonical_json({"legacy_finding_id": legacy_finding["finding_id"]}),
                ),
            )
        linked = self.manager.store.row(
            "SELECT * FROM migration_findings WHERE finding_id='policy-legacy-link'"
        )
        self.assertEqual(
            load_policy_subject(self.manager.store.conn, linked)["bundle"]["bundle_id"],
            bundle["bundle_id"],
        )
        missing_link = {
            **linked,
            "details_json": canonical_json({"legacy_finding_id": "missing"}),
        }
        self.assertEqual(
            load_policy_subject(self.manager.store.conn, missing_link)["bundle"]["bundle_id"],
            bundle["bundle_id"],
        )
        inferred = finding_fingerprint(
            {"classification": "x", "code": "unmatched", "details_json": "{}"},
            {"policy": None, "bundle": None, "policy_hash": None},
        )
        self.assertEqual(inferred["semantic_code"], "unspecified_policy_semantic")

        with self.assertRaises(ConflictError):
            with self.manager.store.transaction() as conn:
                apply_policy_repair_mutation(conn, decoded, actor="organizer-agent")

        self.finding(
            "policy-dependency",
            "legacy_policy_profile_invalid",
            "extension_bundle",
            bundle["bundle_id"],
            classification="requires_policy_mapping",
            details={"bundle_id": bundle["bundle_id"]},
        )
        installed_bundle = self.manager.store.row(
            "SELECT namespace,name FROM extension_bundles WHERE bundle_id=?",
            (self.issue_type["bundle_id"],),
        )
        dependency = f"{installed_bundle['namespace']}/{installed_bundle['name']}@*"
        replacement = migrated_policy_bundle(copy.deepcopy(DEFAULT_POLICY))
        replacement["manifest"].update(
            {
                "namespace": "org.example.v084.dependency-repair",
                "name": "dependency-repair",
                "dependencies": [dependency],
            }
        )
        dependency_candidate = self.manager.store.create_migration_policy_repair(
            "policy-dependency",
            replacement_bundle=replacement,
            actor="organizer-agent",
        )
        self.manager.store.validate_migration_policy_repair(
            dependency_candidate["repair_id"]
        )
        dependency_applied = self.manager.store.apply_migration_policy_repair(
            dependency_candidate["repair_id"], actor="organizer-agent"
        )
        self.assertTrue(dependency_applied["accepted"])

    def test_handler_pre_and_postcondition_negative_matrix(self) -> None:
        bundle, _policy = self.legacy_policy("handler-policy")
        candidate = self.manager.store.create_migration_policy_repair(
            "handler-policy",
            replacement_policy=copy.deepcopy(DEFAULT_POLICY),
            actor="organizer-agent",
        )
        finding = self.manager.store.row(
            "SELECT * FROM migration_findings WHERE finding_id='handler-policy'"
        )
        finding["details"] = {"bundle_id": bundle["bundle_id"]}
        subject = load_policy_subject(self.manager.store.conn, finding)
        self.assertFalse(
            _policy_prevalidate(
                self.manager.store.conn,
                finding,
                {"load_error": "missing"},
                {"repair_id": "missing"},
            )["valid"]
        )
        self.assertFalse(
            _policy_prevalidate(
                self.manager.store.conn,
                finding,
                subject,
                {"repair_id": "missing"},
            )["valid"]
        )
        negative = _policy_prevalidate(
            self.manager.store.conn,
            {**finding, "finding_id": "other"},
            {**subject, "bundle": {**subject["bundle"], "content_hash": "drift"}, "policy_hash": "drift"},
            {"repair_id": candidate["repair_id"], "repair_hash": "wrong"},
        )
        self.assertEqual(
            {item["code"] for item in negative["findings"]},
            {
                "policy_repair_finding_mismatch",
                "policy_repair_candidate_not_validated",
                "policy_repair_hash_mismatch",
                "policy_repair_source_bundle_drift",
                "policy_repair_source_policy_drift",
            },
        )
        post = _policy_postvalidate(
            self.manager.store.conn,
            finding,
            subject,
            {"repair_id": candidate["repair_id"]},
            [
                {
                    "dependency_type": "x",
                    "dependency_id": "x",
                    "content_hash": "h",
                    "state": "retired",
                    "required_states": ["active"],
                    "snapshot_hash": "s",
                }
            ],
            [],
        )
        self.assertIn("policy_repair_not_applied", {item["code"] for item in post["findings"]})
        self.assertIn(
            "migration_resolution_dependency_state_drift",
            {item["code"] for item in post["findings"]},
        )
        self.assertTrue(
            _dependency_state_findings(
                [
                    {
                        "dependency_type": "x",
                        "dependency_id": "x",
                        "state": "retired",
                        "required_states": ["active"],
                    }
                ]
            )
        )

        first = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "one"}
        )
        second = self.manager.records.revise(
            first["record_instance_id"],
            {"name": "two"},
            expected_revision_id=first["record_revision_id"],
        )
        third = self.manager.records.revise(
            first["record_instance_id"],
            {"name": "three"},
            expected_revision_id=second["record_revision_id"],
        )
        object_finding = {
            "finding_id": "direct",
            "object_type": "record_revisions",
            "object_id": first["record_revision_id"],
            "code": "json_column_invalid",
            "details": {"table": "record_revisions", "column": "data_json"},
        }
        object_subject = {
            "object_type": "record_revision",
            "object_id": first["record_revision_id"],
            "column": "data_json",
            "snapshot": object_snapshot(
                self.manager.store.conn, "record_revision", first["record_revision_id"]
            ),
        }
        invalid_successor = _object_prevalidate(
            self.manager.store.conn,
            object_finding,
            object_subject,
            {
                "action": "repair_successor",
                "successor_object_id": third["record_revision_id"],
            },
        )
        self.assertIn(
            "repair_successor_chain_mismatch",
            {item["code"] for item in invalid_successor["findings"]},
        )
        same = _object_prevalidate(
            self.manager.store.conn,
            object_finding,
            object_subject,
            {
                "action": "repair_successor",
                "successor_object_id": first["record_revision_id"],
            },
        )
        self.assertIn("repair_successor_identity_invalid", {item["code"] for item in same["findings"]})
        missing = _object_prevalidate(
            self.manager.store.conn,
            {**object_finding, "object_id": "missing"},
            {**object_subject, "snapshot": {"load_error": "subject_missing"}},
            {"action": "repair_from_source", "object_hash": "wrong"},
        )
        self.assertIn("subject_missing", {item["code"] for item in missing["findings"]})
        quarantine_post = _object_postvalidate(
            self.manager.store.conn,
            object_finding,
            object_subject,
            {"action": "quarantine_object", "quarantine_id": "missing"},
            [],
            [],
        )
        self.assertIn("quarantine_receipt_missing", {item["code"] for item in quarantine_post["findings"]})
        drifted_before = copy.deepcopy(object_subject)
        drifted_before["snapshot"]["revision"]["content_hash"] = "before-drift"
        drift_post = _object_postvalidate(
            self.manager.store.conn,
            object_finding,
            drifted_before,
            {"action": "repair_from_source", "object_hash": "irrelevant"},
            [],
            [],
        )
        self.assertIn(
            "migration_resolution_subject_drift",
            {item["code"] for item in drift_post["findings"]},
        )

        other = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "other"}
        )
        wrong_owner = _object_prevalidate(
            self.manager.store.conn,
            object_finding,
            object_subject,
            {
                "action": "repair_successor",
                "successor_object_id": other["record_revision_id"],
            },
        )
        self.assertIn(
            "repair_successor_owner_mismatch",
            {item["code"] for item in wrong_owner["findings"]},
        )

        self.finding(
            "quarantine-mismatch",
            "json_column_invalid",
            "record_revisions",
            first["record_revision_id"],
            details={"table": "record_revisions", "column": "data_json"},
        )
        quarantine = self.manager.store.create_integrity_quarantine(
            "quarantine-mismatch",
            scopes=["read_with_warning"],
            reason="mismatch matrix",
            actor="organizer-agent",
        )
        self.finding(
            "quarantine-other",
            "historical_json_invalid",
            "record_revisions",
            second["record_revision_id"],
            details={"table": "record_revisions", "column": "data_json"},
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE integrity_quarantines SET object_type='field_bundle',"
                "object_id='wrong',subject_hash='wrong',finding_id='quarantine-other' "
                "WHERE quarantine_id=?",
                (quarantine["quarantine_id"],),
            )
        mismatch = _object_prevalidate(
            self.manager.store.conn,
            {**object_finding, "finding_id": "quarantine-mismatch"},
            object_subject,
            {"action": "quarantine_object", "quarantine_id": quarantine["quarantine_id"]},
        )
        self.assertEqual(
            {item["code"] for item in mismatch["findings"]},
            {
                "quarantine_object_type_mismatch",
                "quarantine_object_id_mismatch",
                "quarantine_subject_hash_mismatch",
                "quarantine_finding_mismatch",
            },
        )
        self.assertEqual(
            _object_dependencies(
                self.manager.store.conn,
                object_finding,
                object_subject,
                {"action": "quarantine_object", "quarantine_id": "missing"},
            ),
            object_dependencies(
                self.manager.store.conn,
                "record_revision",
                first["record_revision_id"],
            ),
        )

        prepared_entry = next(
            item
            for item in candidate["prepared_bundle"]["entries"]
            if item["kind"] == "issue_type"
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_policy_repairs SET issue_binding_map_json=? WHERE repair_id=?",
                (
                    canonical_json(
                        {
                            self.issue_type["registration_id"]: prepared_entry[
                                "registration_id"
                            ],
                            "missing-source": "missing-target",
                        }
                    ),
                    candidate["repair_id"],
                ),
            )
        binding_post = _policy_postvalidate(
            self.manager.store.conn,
            finding,
            subject,
            {"repair_id": candidate["repair_id"]},
            [],
            [],
        )
        self.assertTrue(
            {
                "policy_repair_binding_target_missing",
                "policy_repair_binding_incomplete",
            }.issubset({item["code"] for item in binding_post["findings"]})
        )


class V084ChangesetCoverageEdges(V084QualityBase):
    def test_operation_ledger_expectation_and_review_edge_matrix(self) -> None:
        created = self.manager.changesets.create(
            {
                "changeset_version": 1,
                "intent": "coverage edge",
                "operations": [
                    {
                        "op": "create_issue",
                        "issue_id": "coverage-child",
                        "issue_type": "specimen",
                        "issue_type_registration_id": self.issue_type["registration_id"],
                    }
                ],
                "expected_revisions": {
                    "sample-a": {
                        "working_revision": 0,
                        "conclusion_revision": 0,
                    }
                },
            },
            credential=self.organizer,
        )
        self.assertEqual(self.manager.changesets.preview(created["changeset_id"])["operation_count"], 1)
        self.manager.changesets.validate(created["changeset_id"], credential=self.organizer)
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE issues SET working_revision=working_revision+1 WHERE issue_id='sample-a'"
            )
        with self.assertRaises(ConflictError):
            self.manager.changesets.apply(created["changeset_id"], credential=self.organizer)

        tampered = self.manager.changesets.create(
            {"changeset_version": 1, "intent": "tamper", "operations": [{"op": "create_issue", "issue_id": "tampered", "issue_type": "specimen", "issue_type_registration_id": self.issue_type["registration_id"]}]},
            credential=self.organizer,
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE changeset_operations SET operation_hash='wrong' WHERE changeset_id=?",
                (tampered["changeset_id"],),
            )
        with self.assertRaises(ConflictError):
            self.manager.changesets.validate(tampered["changeset_id"], credential=self.organizer)

        with self.assertRaises(NotFoundError):
            self.manager.changesets.claim_review("missing", credential=self.manager.credentials.path_for("review-agent-1"))
        simple = self.manager.changesets.create(
            {"changeset_version": 1, "intent": "no review", "operations": [{"op": "create_issue", "issue_id": "simple", "issue_type": "specimen", "issue_type_registration_id": self.issue_type["registration_id"]}]},
            credential=self.organizer,
        )
        with self.assertRaises(ConflictError):
            self.manager.changesets.claim_review(simple["changeset_id"], credential=self.manager.credentials.path_for("review-agent-1"))
        with self.assertRaises(ValidationError):
            self.manager.changesets.submit_review(
                simple["changeset_id"],
                decision="maybe",
                rationale="",
                credential=self.manager.credentials.path_for("review-agent-1"),
            )

    def test_changeset_review_claim_reclaim_and_ledger_branches(self) -> None:
        t3 = self.manager.changesets.create(
            {
                "changeset_version": 1,
                "intent": "independent review coverage",
                "operations": [
                    {
                        "op": "create_issue",
                        "issue_id": "report-scope-edge",
                        "issue_type": "report_scope",
                    }
                ],
            },
            credential=self.organizer,
        )
        self.assertIsNotNone(
            load_dependency(
                self.manager.store.conn,
                "changeset_operation",
                f"{t3['changeset_id']}:0",
            )
        )
        self.manager.changesets.validate(t3["changeset_id"], credential=self.organizer)
        with self.assertRaises(ManagerPermissionError):
            self.manager.changesets.claim_review(
                t3["changeset_id"], credential=self.organizer
            )
        reviewer1 = self.manager.credentials.path_for("review-agent-1")
        reviewer2 = self.manager.credentials.path_for("review-agent-2")
        first_claim = self.manager.changesets.claim_review(
            t3["changeset_id"], credential=reviewer1
        )
        replay_claim = self.manager.changesets.claim_review(
            t3["changeset_id"], credential=reviewer1
        )
        self.assertTrue(replay_claim["idempotent_replay"])
        self.manager.changesets.submit_review(
            t3["changeset_id"],
            decision="pass",
            rationale="first independent review",
            credential=reviewer1,
        )
        with self.assertRaises(ConflictError):
            self.manager.changesets.claim_review(
                t3["changeset_id"], credential=reviewer1
            )
        second_claim = self.manager.changesets.claim_review(
            t3["changeset_id"], credential=reviewer2
        )
        released = self.manager.changesets.release_review(
            t3["changeset_id"], credential=reviewer2
        )
        self.assertEqual(released["state"], "released")
        reclaimed = self.manager.changesets.claim_review(
            t3["changeset_id"], credential=reviewer2
        )
        self.assertGreater(reclaimed["lease_generation"], second_claim["lease_generation"])
        self.manager.changesets.submit_review(
            t3["changeset_id"],
            decision="pass",
            rationale="second independent review",
            credential=reviewer2,
        )
        applied = self.manager.changesets.apply(t3["changeset_id"], credential=self.organizer)
        self.assertEqual(applied["state"], "applied")
        self.assertTrue(
            self.manager.changesets.apply(
                t3["changeset_id"], credential=self.organizer
            )["idempotent_replay"]
        )
        self.assertTrue(first_claim["assignment_id"])

        with self.assertRaises(ConflictError):
            self.manager.changesets._validate_operation_rows(
                {"changeset": {"operations": [{}]}, "operations": []}
            )
        memory = sqlite3.connect(":memory:")
        memory.row_factory = sqlite3.Row
        try:
            memory.execute(
                "CREATE TABLE changeset_issue_expectations("
                "changeset_id TEXT,issue_id TEXT,expected_working_revision INTEGER,"
                "expected_conclusion_revision INTEGER)"
            )
            memory.execute(
                "CREATE TABLE issues(issue_id TEXT,working_revision INTEGER,conclusion_revision INTEGER)"
            )
            memory.execute(
                "INSERT INTO changeset_issue_expectations VALUES ('c','missing',0,0)"
            )
            with self.assertRaises(ConflictError):
                self.manager.changesets._validate_expectations(memory, "c")
        finally:
            memory.close()

    def test_changeset_apply_and_direct_operation_rejection_branches(self) -> None:
        maintenance = self.manager.credentials.path_for("maintenance-agent")
        self_reviewer = self.manager.credentials.issue_actor(
            actor_id="self-reviewer",
            actor_kind="organizer_agent",
            capabilities={"changeset.submit", "proposal.review", "issue.write"},
            maintenance_credential=maintenance,
        )
        self_credential = self_reviewer["credential_path"]
        self_change = self.manager.changesets.create(
            {
                "changeset_version": 1,
                "intent": "self review rejection",
                "operations": [
                    {
                        "op": "create_issue",
                        "issue_id": "self-review-report",
                        "issue_type": "report_scope",
                    }
                ],
            },
            credential=self_credential,
        )
        self.manager.changesets.validate(
            self_change["changeset_id"], credential=self_credential
        )
        with self.assertRaises(ManagerPermissionError):
            self.manager.changesets.claim_review(
                self_change["changeset_id"], credential=self_credential
            )

        state_edge = self.manager.changesets.create(
            {
                "changeset_version": 1,
                "intent": "state edge",
                "operations": [{"op": "add_tag", "issue_id": "sample-a", "tag": "x"}],
            },
            credential=self.organizer,
        )
        self.manager.changesets.validate(state_edge["changeset_id"], credential=self.organizer)
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE changesets SET state='applying' WHERE changeset_id=?",
                (state_edge["changeset_id"],),
            )
        with self.assertRaises(ConflictError):
            self.manager.changesets.apply(
                state_edge["changeset_id"], credential=self.organizer
            )

        replay_edge = self.manager.changesets.create(
            {
                "changeset_version": 1,
                "intent": "idempotency edge",
                "operations": [{"op": "add_tag", "issue_id": "sample-a", "tag": "y"}],
            },
            credential=self.organizer,
        )
        self.manager.changesets.validate(replay_edge["changeset_id"], credential=self.organizer)
        shown = self.manager.changesets.show(replay_edge["changeset_id"])
        request = {
            "changeset_id": replay_edge["changeset_id"],
            "changeset_hash": shown["changeset_hash"],
        }
        with self.manager.store.transaction() as conn:
            self.manager.store.idempotency_record(
                conn,
                "changeset.apply",
                "apply-replay-edge",
                request,
                {"changeset_id": replay_edge["changeset_id"], "state": "validated"},
            )
        self.assertTrue(
            self.manager.changesets.apply(
                replay_edge["changeset_id"],
                credential=self.organizer,
                idempotency_key="apply-replay-edge",
            )["idempotent_replay"]
        )

        auth = self.manager.changesets.credentials.resolve(
            self.organizer, "changeset.submit"
        )
        evidence = self.manager.add_evidence(
            kind="external", locator="https://example.invalid/changeset", issue_id="sample-a"
        )
        direct = self.manager.changesets._apply_operation
        attached = direct(
            "direct",
            {
                "op": "attach_evidence",
                "issue_id": "sample-a",
                "evidence_id": evidence["evidence_id"],
            },
            auth,
            self.organizer,
            [],
            None,  # type: ignore[arg-type]
            operation_ordinal=0,
            changeset_hash="hash",
        )
        self.assertEqual(attached["evidence_id"], evidence["evidence_id"])
        with self.assertRaises(ValidationError):
            direct(
                "direct",
                {"op": "attach_evidence", "issue_id": "sample-a", "evidence_id": "missing"},
                auth,
                self.organizer,
                [],
                None,  # type: ignore[arg-type]
                operation_ordinal=0,
                changeset_hash="hash",
            )
        with self.assertRaises(ConflictError):
            direct(
                "direct",
                {
                    "op": "resolve_import_conflict",
                    "conflict_id": "missing",
                    "resolution": "reject_candidate",
                    "expected_conflict_revision": 0,
                },
                auth,
                self.organizer,
                [],
                None,  # type: ignore[arg-type]
                operation_ordinal=0,
                changeset_hash="hash",
            )
        with self.assertRaises(AssertionError):
            direct(
                "direct",
                {"op": "unknown"},
                auth,
                self.organizer,
                [],
                None,  # type: ignore[arg-type]
                operation_ordinal=0,
                changeset_hash="hash",
            )

        completed_edge = self.manager.changesets.create(
            {
                "changeset_version": 1,
                "intent": "completed assignment edge",
                "operations": [
                    {
                        "op": "create_issue",
                        "issue_id": "completed-edge-report",
                        "issue_type": "report_scope",
                    }
                ],
            },
            credential=self.organizer,
        )
        self.manager.changesets.validate(
            completed_edge["changeset_id"], credential=self.organizer
        )
        reviewer = self.manager.credentials.path_for("review-agent-1")
        assignment = self.manager.changesets.claim_review(
            completed_edge["changeset_id"], credential=reviewer
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE changeset_review_assignments SET state='submitted' "
                "WHERE assignment_id=?",
                (assignment["assignment_id"],),
            )
        with self.assertRaises(ConflictError):
            self.manager.changesets.claim_review(
                completed_edge["changeset_id"], credential=reviewer
            )

        concurrent_edge = self.manager.changesets.create(
            {
                "changeset_version": 1,
                "intent": "claim race edge",
                "operations": [
                    {
                        "op": "create_issue",
                        "issue_id": "concurrent-edge-report",
                        "issue_type": "report_scope",
                    }
                ],
            },
            credential=self.organizer,
        )
        self.manager.changesets.validate(
            concurrent_edge["changeset_id"], credential=self.organizer
        )
        original_transaction = self.manager.store.transaction

        @contextmanager
        def concurrent_transaction():
            with original_transaction() as conn:
                conn.execute(
                    "UPDATE changesets SET state='validated' WHERE changeset_id=?",
                    (concurrent_edge["changeset_id"],),
                )
                yield conn

        with (
            patch.object(
                self.manager.store, "transaction", concurrent_transaction
            ),
            self.assertRaises(ConflictError),
        ):
            self.manager.changesets.claim_review(
                concurrent_edge["changeset_id"], credential=reviewer
            )


if __name__ == "__main__":
    unittest.main()


class V084StoreMigrationEdges(V084QualityBase):
    def test_store_defensive_helpers_and_report_quarantine_exclusion(self) -> None:
        with (
            patch.object(
                self.manager.store,
                "row",
                side_effect=[
                    {"receipt_id": "broken", "accepted_attempt_id": "missing"},
                    None,
                ],
            ),
            self.assertRaises(ConflictError),
        ):
            self.manager.store.migration_finding_receipt("broken")

        with (
            patch.object(
                self.manager.store,
                "row",
                side_effect=[
                    {"receipt_id": "legacy", "accepted_attempt_id": "attempt"},
                    {
                        "attempt_id": "attempt",
                        "resolution_json": "{}",
                        "validation_result_json": "{}",
                    },
                ],
            ),
            patch.object(self.manager.store, "rows", return_value=[]),
        ):
            legacy_receipt = self.manager.store.migration_finding_receipt("legacy")
        self.assertEqual(legacy_receipt["dependencies"], [])

        empty_store = object.__new__(Store)
        empty_store.conn = sqlite3.connect(":memory:")
        try:
            empty_store._ensure_audit_checkpoint()
        finally:
            empty_store.conn.close()

        capability = self.manager.store.row(
            "SELECT capability FROM actor_capabilities WHERE actor_id='organizer-agent' LIMIT 1"
        )
        self.assertIsNotNone(capability)
        with self.manager.store.transaction() as conn:
            conn.execute(
                "DELETE FROM actor_capabilities WHERE actor_id='organizer-agent' AND capability=?",
                (capability["capability"],),
            )
        self.manager.store._bootstrap_identities()

        self.legacy_policy("draft-policy-apply")
        draft_candidate = self.manager.store.create_migration_policy_repair(
            "draft-policy-apply",
            replacement_policy=copy.deepcopy(DEFAULT_POLICY),
            actor="organizer-agent",
        )
        self.assertTrue(
            self.manager.store.apply_migration_policy_repair(
                draft_candidate["repair_id"], actor="organizer-agent"
            )["accepted"]
        )

        self.publish()
        record = self.manager.records.create(
            "sample-a",
            self.record_template["registration_id"],
            data={
                "name": "quarantined",
                "measurement": {"value": 1.0, "unit": "m"},
                "optional": "ok",
            },
        )
        self.finding(
            "report-quarantine",
            "json_column_invalid",
            "record_revisions",
            record["record_revision_id"],
            details={"table": "record_revisions", "column": "data_json"},
        )
        quarantine = self.manager.store.create_integrity_quarantine(
            "report-quarantine",
            scopes=["exclude_new_reports"],
            reason="exclude damaged record from new reports",
            actor="organizer-agent",
        )
        prepared = self.manager.reports.prepare(
            self.report_template["registration_id"], scope={"issue_id": "sample-a"}
        )
        self.assertIn(
            quarantine["quarantine_id"],
            prepared["excluded"][0]["quarantine_ids"],
        )
