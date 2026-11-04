from __future__ import annotations

import copy
import json
import unittest

from context_fixtures import corrupt_history
from test_v082 import V082Base

from issue_manager.default_policy import DEFAULT_POLICY
from issue_manager.errors import ConflictError, MigrationResolutionError, ValidationError
from issue_manager.integrity import (
    _conclusion_findings,
    digest,
    object_snapshot,
    validate_object_integrity,
)
from issue_manager.registry_service import migrated_policy_bundle
from issue_manager.store import canonical_json


class V084ProofLifecycleTests(V082Base):
    def _finding(
        self,
        finding_id: str,
        *,
        object_type: str,
        object_id: str,
        code: str,
        classification: str,
        details: dict,
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
                    canonical_json(details),
                ),
            )

    def test_ordinary_mapping_cannot_close_policy_blocker(self) -> None:
        legacy = self.manager.registry.install_bundle(migrated_policy_bundle({
            "version": 1,
            "issue_types": {},
            "publication": {"custom_rule": "legacy"},
            "publication_requirements": {},
            "conclusion_schemas": {},
        }))
        self.manager.registry.activate_bundle(legacy["bundle_id"])
        self._finding(
            "v13-policy",
            object_type="extension_bundle",
            object_id=legacy["bundle_id"],
            code="legacy_policy_semantics_not_declaratively_convertible",
            classification="requires_policy_mapping",
            details={
                "bundle_id": legacy["bundle_id"],
                "semantic_code": "unknown_publication_logic",
                "json_pointer": "/publication/custom_rule",
            },
        )
        shown = self.manager.store.migration_finding("v13-policy")
        mapping = self.manager.registry.resolve(
            "org.example.v81/mapping_profile/measurement-map@1.0.0"
        )
        rejected = self.manager.store.validate_migration_finding_resolution(
            "v13-policy",
            {
                "action": "install_mapping_bundle",
                "subject_hash": shown["subject_hash"],
                "mapping_registration_id": mapping["registration_id"],
                "mapping_registration_hash": mapping["content_hash"],
                "reason": "unrelated mapping",
            },
        )
        self.assertFalse(rejected["valid"])
        self.assertEqual(rejected["code"], "migration_resolution_action_unsupported")

    def test_policy_candidate_produces_proof_v2_and_doctor_full_replays_postcondition(
        self,
    ) -> None:
        source_policy = {
            "version": 1,
            "issue_types": {},
            "publication": {"custom_rule": "legacy"},
            "publication_requirements": {},
            "conclusion_schemas": {},
        }
        legacy = self.manager.registry.install_bundle(migrated_policy_bundle(source_policy))
        self.manager.registry.activate_bundle(legacy["bundle_id"])
        self._finding(
            "v13-policy-apply",
            object_type="extension_bundle",
            object_id=legacy["bundle_id"],
            code="legacy_policy_semantics_not_declaratively_convertible",
            classification="requires_policy_mapping",
            details={
                "bundle_id": legacy["bundle_id"],
                "semantic_code": "unknown_publication_logic",
                "json_pointer": "/publication/custom_rule",
            },
        )
        replacement = copy.deepcopy(DEFAULT_POLICY)
        candidate = self.manager.store.create_migration_policy_repair(
            "v13-policy-apply",
            replacement_policy=replacement,
            actor="organizer-agent",
        )
        validated = self.manager.store.validate_migration_policy_repair(
            candidate["repair_id"]
        )
        self.assertEqual(validated["state"], "validated", validated["validation"])
        applied = self.manager.store.apply_migration_policy_repair(
            candidate["repair_id"], actor="organizer-agent"
        )
        self.assertTrue(applied["accepted"])
        self.assertEqual(applied["proof_format"], "migration-resolution-proof/v2")
        receipt = self.manager.store.migration_finding_receipt(applied["receipt_id"])
        self.assertTrue(receipt["proof_hash"])
        self.assertTrue(receipt["dependencies"])
        doctor = self.manager.doctor(full_resolution_replay=True)
        self.assertTrue(doctor["ok"], doctor["findings"])
        self.assertTrue(doctor["resolution_replays"][0]["mutation_executed"] is False)

    def test_strict_json_is_not_object_integrity(self) -> None:
        record = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "valid"}
        )
        with corrupt_history(self.manager, "record_revisions") as conn:
            conn.execute(
                "UPDATE record_revisions SET data_json='{}' WHERE record_revision_id=?",
                (record["record_revision_id"],),
            )
        self._finding(
            "v13-record-invalid",
            object_type="record_revisions",
            object_id=record["record_revision_id"],
            code="json_column_invalid",
            classification="blocking_corruption",
            details={"table": "record_revisions", "column": "data_json"},
        )
        shown = self.manager.store.migration_finding("v13-record-invalid")
        validation = validate_object_integrity(
            self.manager.store.conn,
            "record_revision",
            record["record_revision_id"],
            column="data_json",
        )
        self.assertFalse(validation["valid"])
        rejected = self.manager.store.validate_migration_finding_resolution(
            "v13-record-invalid",
            {
                "action": "repair_from_source",
                "subject_hash": shown["subject_hash"],
                "object_hash": validation["subject_after_hash"],
                "reason": "syntax alone must not pass",
            },
        )
        self.assertFalse(rejected["valid"])
        self.assertTrue(
            any(
                item["code"] == "record_required_field_missing"
                for item in rejected["precondition"]["findings"]
            )
        )

    def test_conclusion_repair_reads_frozen_definition_and_replays_evidence_profile(self) -> None:
        issue = self.manager.store.row("SELECT * FROM issues WHERE issue_id='sample-a'")
        assert issue is not None
        semantics = json.loads(issue["issue_type_snapshot_json"])
        semantics["definition"]["conclusion"]["structured_outputs_schema"] = {
            "type": "object",
            "required": ["result"],
            "properties": {"result": {"type": "string"}},
            "additionalProperties": False,
        }
        semantic_hash = digest(semantics)
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE issues SET issue_type_snapshot_json=?,issue_type_semantic_hash=? "
                "WHERE issue_id='sample-a'",
                (canonical_json(semantics), semantic_hash),
            )
        self.publish()
        conclusion_id = self.manager.show_issue("sample-a")["current_conclusion"]["conclusion_id"]
        with corrupt_history(self.manager, "conclusion_revisions") as conn:
            conn.execute(
                "UPDATE conclusion_revisions SET structured_outputs_json=? WHERE conclusion_id=?",
                (canonical_json({"unknown": "bad"}), conclusion_id),
            )
        self._finding(
            "v13-conclusion-frozen-semantics",
            object_type="conclusion_revisions",
            object_id=conclusion_id,
            code="json_column_invalid",
            classification="blocking_corruption",
            details={"table": "conclusion_revisions", "column": "structured_outputs_json"},
        )
        validation = validate_object_integrity(
            self.manager.store.conn,
            "conclusion_revision",
            conclusion_id,
            column="structured_outputs_json",
        )
        self.assertIn(
            "conclusion_output_schema_invalid",
            {item["code"] for item in validation["findings"]},
        )
        shown = self.manager.store.migration_finding("v13-conclusion-frozen-semantics")
        with self.assertRaises(MigrationResolutionError):
            self.manager.store.resolve_migration_finding(
                "v13-conclusion-frozen-semantics",
                {
                    "action": "repair_from_source",
                    "subject_hash": shown["subject_hash"],
                    "object_hash": validation["subject_after_hash"],
                    "reason": "invalid output must not be accepted",
                },
                actor="organizer-agent",
            )
        self.assertFalse(self.manager.doctor(full_resolution_replay=True)["ok"])

    def test_conclusion_profile_counts_only_active_evidence_with_valid_proof(self) -> None:
        evidence = self.manager.add_evidence(
            kind="external", locator="urn:v084:profile", issue_id="sample-a"
        )
        issue = self.manager.show_issue("sample-a")
        proposal = self.manager.proposals.create(
            {
                "issue_id": "sample-a",
                "expected_conclusion_revision": issue["conclusion_revision"],
                "status": "provisional",
                "statement": "evidence profile",
                "structured_outputs": {"result": "ok"},
                "limitations": [],
                "evidence_refs": [evidence["evidence_id"]],
                "evidence_uses": [
                    {
                        "evidence_id": evidence["evidence_id"],
                        "use_role": "support",
                        "fitness": "fit_for_use",
                    }
                ],
                "basis": [],
            },
            credential=self.organizer,
        )
        self.manager.proposals.validate(proposal["proposal_id"], credential=self.organizer)
        self.manager.proposals.apply(proposal["proposal_id"], credential=self.organizer)
        conclusion_id = self.manager.show_issue("sample-a")["current_conclusion"]["conclusion_id"]
        subject = object_snapshot(self.manager.store.conn, "conclusion_revision", conclusion_id)
        issue_row = self.manager.store.row("SELECT * FROM issues WHERE issue_id='sample-a'")
        assert issue_row is not None
        semantics = json.loads(issue_row["issue_type_snapshot_json"])
        semantics["definition"]["conclusion"]["publication_profiles"]["provisional"] = {
            "min_active_evidence": 1,
            "minimum_verification_level": "source_verified",
            "review_quorum": 0,
            "require_support_fit_for_use": True,
        }
        semantic_hash = digest(semantics)
        subject["conclusion"]["issue_type_semantic_snapshot_json"] = canonical_json(semantics)
        subject["conclusion"]["issue_type_semantic_hash"] = semantic_hash
        subject["issue"]["issue_type_semantic_hash"] = semantic_hash
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE evidence_refs SET lifecycle_status='void' WHERE evidence_id=?",
                (evidence["evidence_id"],),
            )
        codes = {
            item["code"]
            for item in validate_object_integrity(
                self.manager.store.conn, "conclusion_revision", conclusion_id
            )["findings"]
        }
        synthetic_codes = {
            item["code"]
            for item in _conclusion_findings(self.manager.store.conn, subject)
        }
        self.assertIn("conclusion_evidence_proof_invalid", codes)
        self.assertIn("conclusion_evidence_quorum_unsatisfied", synthetic_codes)
        self.assertIn("conclusion_evidence_verification_unsatisfied", synthetic_codes)

    def test_quarantine_release_rejects_other_objects_repair_receipt(self) -> None:
        quarantined = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "A"}
        )
        other = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "B"}
        )
        other_successor = self.manager.records.revise(
            other["record_instance_id"],
            {"name": "B repaired"},
            expected_revision_id=other["record_revision_id"],
        )
        self._finding(
            "v13-quarantined-a",
            object_type="record_revisions",
            object_id=quarantined["record_revision_id"],
            code="json_column_invalid",
            classification="blocking_corruption",
            details={"table": "record_revisions", "column": "data_json"},
        )
        quarantine = self.manager.store.create_integrity_quarantine(
            "v13-quarantined-a",
            scopes=["read_with_warning"],
            reason="isolate A",
            actor="organizer-agent",
        )
        self._finding(
            "v13-repaired-b",
            object_type="record_revisions",
            object_id=other["record_revision_id"],
            code="historical_json_invalid",
            classification="blocking_corruption",
            details={"table": "record_revisions", "column": "data_json"},
        )
        shown = self.manager.store.migration_finding("v13-repaired-b")
        repaired = self.manager.store.resolve_migration_finding(
            "v13-repaired-b",
            {
                "action": "repair_successor",
                "subject_hash": shown["subject_hash"],
                "successor_object_id": other_successor["record_revision_id"],
                "reason": "repair B only",
            },
            actor="organizer-agent",
        )
        receipt = self.manager.store.migration_finding_receipt(repaired["receipt_id"])
        self.assertNotEqual(receipt["subject_before_hash"], quarantine["subject_hash"])
        with self.assertRaises(ValidationError) as raised:
            self.manager.store.release_integrity_quarantine(
                quarantine["quarantine_id"],
                repair_receipt_id=repaired["receipt_id"],
                actor="organizer-agent",
            )
        self.assertEqual(raised.exception.details["code"], "quarantine_release_subject_mismatch")
        self.assertEqual(
            self.manager.store.integrity_quarantine(quarantine["quarantine_id"])["state"],
            "active",
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE integrity_quarantines SET state='released',released_at=?,released_by=?,"
                "release_receipt_id=? "
                "WHERE quarantine_id=?",
                (
                    "2026-08-10T00:00:00+00:00",
                    "organizer-agent",
                    repaired["receipt_id"],
                    quarantine["quarantine_id"],
                ),
            )
        doctor = self.manager.doctor(full_resolution_replay=True)
        self.assertFalse(doctor["ok"])
        self.assertIn(
            "quarantine_release_subject_mismatch",
            {item["code"] for item in doctor["findings"]},
        )

    def test_quarantine_overlay_blocks_new_use(self) -> None:
        record = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "valid"}
        )
        self._finding(
            "v13-quarantine",
            object_type="record_revisions",
            object_id=record["record_revision_id"],
            code="json_column_invalid",
            classification="blocking_corruption",
            details={"table": "record_revisions", "column": "data_json"},
        )
        shown = self.manager.store.migration_finding("v13-quarantine")
        fake = self.manager.store.validate_migration_finding_resolution(
            "v13-quarantine",
            {
                "action": "quarantine_object",
                "subject_hash": shown["subject_hash"],
                "quarantine_id": "fake-quarantine",
                "reason": "fake",
            },
        )
        self.assertFalse(fake["valid"])
        quarantine = self.manager.store.create_integrity_quarantine(
            "v13-quarantine",
            scopes=["read_with_warning"],
            reason="isolate historical revision",
            actor="organizer-agent",
        )
        accepted = self.manager.store.resolve_migration_finding(
            "v13-quarantine",
            {
                "action": "quarantine_object",
                "subject_hash": shown["subject_hash"],
                "quarantine_id": quarantine["quarantine_id"],
                "reason": "active overlay verified",
            },
            actor="organizer-agent",
        )
        self.assertTrue(accepted["accepted"])
        shown_record = self.manager.records.show_revision(record["record_revision_id"])
        self.assertTrue(shown_record["quarantined"])
        with self.assertRaises(ConflictError):
            self.manager.records.revise(
                record["record_instance_id"],
                {"name": "next"},
                expected_revision_id=record["record_revision_id"],
            )
        with self.assertRaises(ValidationError):
            self.manager.store.release_integrity_quarantine(
                quarantine["quarantine_id"],
                repair_receipt_id="missing",
                actor="organizer-agent",
            )


if __name__ == "__main__":
    unittest.main()
