from __future__ import annotations

import copy
import json
import math
import sqlite3
import unittest
from dataclasses import replace
from unittest.mock import patch

from test_v082 import V082Base

from issue_manager.conflict_governance import (
    build_resolution_operation,
    conflict_target,
    content_hash,
    current_revision,
    validate_resolution_binding,
)
from issue_manager.default_policy import DEFAULT_POLICY
from issue_manager.errors import (
    ConflictBindingError,
    ConflictError,
    MigrationResolutionStaleError,
    NotFoundError,
    ValidationError,
)
from issue_manager.field_bundle_service import FIELD_BUNDLE_VERSION
from issue_manager.integrity import validate_object_integrity
from issue_manager.migration_planner import (
    assert_policy_plan_current,
    plan_legacy_policy_migration,
)
from issue_manager.migration_resolution import _finding_details, apply_resolution, handler_for
from issue_manager.registry_service import (
    install_migrated_policy_bundle,
    migrated_policy_bundle,
)
from issue_manager.store import (
    canonical_json,
    now,
)


class V083PlannerQualityEdges(unittest.TestCase):
    def test_planner_rejection_matrix_and_plan_freshness(self) -> None:
        mutations = (
            ("issue-definition", ("issue_types", "sample"), []),
            ("publication", ("publication",), []),
            ("quorum-object", ("publication", "review_quorum"), []),
            (
                "report-minimum",
                ("publication", "report_facing_minimum_reviews"),
                True,
            ),
            ("requirements", ("publication_requirements",), []),
            ("profile", ("publication_requirements", "accepted"), []),
            (
                "profile-quorum",
                ("publication_requirements", "accepted", "review_quorum"),
                True,
            ),
            ("schemas", ("conclusion_schemas",), []),
            (
                "required-type",
                ("conclusion_schemas", "generic-capability-v1", "required"),
                "bad",
            ),
            (
                "required-item",
                ("conclusion_schemas", "generic-capability-v1", "required"),
                [1],
            ),
        )
        for name, path, value in mutations:
            policy = copy.deepcopy(DEFAULT_POLICY)
            target = policy
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(name=name):
                planned = plan_legacy_policy_migration(policy)
                self.assertFalse(planned["safe_to_apply"])
                self.assertTrue(planned["blocking_findings"])

        semantic = copy.deepcopy(DEFAULT_POLICY)
        semantic["custom_runtime_rule"] = {"python": "not declarative"}
        semantic_plan = plan_legacy_policy_migration(semantic)
        self.assertEqual(
            semantic_plan["blocking_findings"][0]["code"],
            "legacy_policy_semantics_not_declaratively_convertible",
        )
        local = plan_legacy_policy_migration(
            DEFAULT_POLICY, target_namespace="local.compat"
        )
        self.assertTrue(local["safe_to_apply"])
        self.assertFalse(local["prepared_bundle"]["manifest"]["name"].endswith("-v11"))

        with patch(
            "issue_manager.registry_service.migrated_policy_bundle",
            side_effect=ValueError("fixture"),
        ):
            failed_prepare = plan_legacy_policy_migration(DEFAULT_POLICY)
        self.assertEqual(
            failed_prepare["blocking_findings"][0]["code"],
            "legacy_policy_bundle_prepare_invalid",
        )

        plan = plan_legacy_policy_migration(DEFAULT_POLICY)
        self.assertEqual(
            assert_policy_plan_current(
                plan, DEFAULT_POLICY, existing_registry_entries=[]
            )["plan_hash"],
            plan["plan_hash"],
        )
        with self.assertRaises(ValidationError):
            assert_policy_plan_current(
                {**plan, "planner_version": 999},
                DEFAULT_POLICY,
                existing_registry_entries=[],
            )
        with self.assertRaises(ValidationError) as stale:
            assert_policy_plan_current(
                plan,
                DEFAULT_POLICY,
                existing_registry_entries=[
                    {
                        "registration_id": "new/reference@1",
                        "bundle_id": "bundle",
                        "kind": "mapping_profile",
                        "content_hash": "hash",
                        "state": "active",
                    }
                ],
            )
        self.assertEqual(stale.exception.details["code"], "migration_plan_stale")


class V083StoreInvariantQualityEdges(V082Base):
    pass


class V083ResolutionHandlerQualityEdges(V082Base):
    def add_finding(
        self,
        finding_id: str,
        code: str,
        object_type: str,
        object_id: str,
        *,
        details: dict | str | None = None,
        classification: str = "requires_triage",
    ) -> None:
        details_json = (
            details
            if isinstance(details, str)
            else canonical_json(details if details is not None else {})
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "INSERT INTO migration_findings(finding_id,migration_version,object_type,"
                "object_id,classification,code,details_json,state) "
                "VALUES (?,12,?,?,?,?,?,'open')",
                (
                    finding_id,
                    object_type,
                    object_id,
                    classification,
                    code,
                    details_json,
                ),
            )

    def json_subject(self, bundle_id: str = "resolution-json") -> dict:
        return self.manager.field_bundles.upload(
            {
                "manifest": {
                    "bundle_id": bundle_id,
                    "bundle_version": FIELD_BUNDLE_VERSION,
                    "created_by": "fixture",
                    "created_at": now(),
                    "source_namespace": "fixture",
                    "source_owner": "organizer-agent",
                    "attachments": [],
                },
                "events": [
                    {
                        "event_id": f"{bundle_id}-event",
                        "event_type": "observation",
                        "issue_id": "sample-a",
                        "body": "subject",
                    }
                ],
            }
        )

    def test_json_handler_schema_rejections_and_attempt_idempotency(self) -> None:
        self.assertEqual(_finding_details({"details": {"x": 1}}), {"x": 1})
        self.assertEqual(_finding_details({"details_json": "{"}), {})
        self.assertEqual(_finding_details({"details_json": "[]"}), {})

        uploaded = self.json_subject()
        details = {"table": "field_bundles", "column": "manifest_json"}
        self.add_finding(
            "json-main",
            "json_column_invalid",
            "field_bundles",
            uploaded["field_bundle_id"],
            details=details,
        )
        shown = self.manager.store.migration_finding("json-main")
        quarantine = self.manager.store.create_integrity_quarantine(
            "json-main",
            scopes=["block_integration_apply"],
            reason="verified quarantine",
            actor="organizer-agent",
        )
        with self.assertRaises(ValidationError):
            self.manager.store.validate_migration_finding_resolution(
                "json-main", []  # type: ignore[arg-type]
            )
        base = {
            "action": "quarantine_object",
            "subject_hash": shown["subject_hash"],
            "quarantine_id": quarantine["quarantine_id"],
            "reason": "verified",
        }
        cases = (
            ({**base, "action": "waive"}, "migration_resolution_action_unsupported"),
            (
                {key: value for key, value in base.items() if key != "quarantine_id"},
                "migration_resolution_payload_invalid",
            ),
            ({**base, "unknown": True}, "migration_resolution_payload_invalid"),
            ({**base, "quarantine_id": ""}, "migration_resolution_payload_invalid"),
            ({**base, "subject_hash": "stale"}, "migration_resolution_stale"),
            (
                {key: value for key, value in base.items() if key != "reason"},
                "migration_resolution_reason_required",
            ),
        )
        for resolution, code in cases:
            with self.subTest(code=code):
                self.assertEqual(
                    self.manager.store.validate_migration_finding_resolution(
                        "json-main", resolution
                    )["code"],
                    code,
                )
        bad = {**base, "quarantine_id": "wrong"}
        first = apply_resolution(
            self.manager.store, "json-main", bad, actor="organizer-agent"
        )
        second = apply_resolution(
            self.manager.store, "json-main", bad, actor="organizer-agent"
        )
        self.assertFalse(first["accepted"])
        self.assertTrue(second["idempotent_replay"])

        quarantine_subject = self.json_subject("json-quarantine-subject")
        self.add_finding(
            "json-quarantine",
            "historical_json_invalid",
            "field_bundles",
            quarantine_subject["field_bundle_id"],
            details=details,
        )
        quarantine_shown = self.manager.store.migration_finding("json-quarantine")
        exact_quarantine = self.manager.store.create_integrity_quarantine(
            "json-quarantine",
            scopes=["block_integration_apply"],
            reason="object isolated and exact snapshot verified",
            actor="organizer-agent",
        )
        quarantine = apply_resolution(
            self.manager.store,
            "json-quarantine",
            {
                "action": "quarantine_object",
                "subject_hash": quarantine_shown["subject_hash"],
                "quarantine_id": exact_quarantine["quarantine_id"],
                "reason": "object isolated and strict replacement verified",
            },
            actor="organizer-agent",
        )
        self.assertTrue(quarantine["accepted"])
        self.assertIsNotNone(
            self.manager.store.migration_finding("json-quarantine")["receipt"]
        )

        self.add_finding(
            "json-unsupported-subject",
            "legacy_policy_json_invalid",
            "unknown_table",
            "missing",
            details={"column": "value"},
        )
        unsupported = self.manager.store.migration_finding(
            "json-unsupported-subject"
        )
        self.assertEqual(
            unsupported["subject"]["load_error"], "policy_subject_missing"
        )
        self.assertFalse(
            self.manager.store.validate_migration_finding_resolution(
                "json-unsupported-subject",
                {
                    "action": "quarantine_object",
                    "subject_hash": unsupported["subject_hash"],
                    "quarantine_id": "receipt",
                    "reason": "missing subject cannot pass",
                },
            )["valid"]
        )

    def test_apply_rejection_branches_and_locked_subject_drift(self) -> None:
        details = {"table": "field_bundles", "column": "manifest_json"}
        original_handler = handler_for("json_column_invalid")
        assert original_handler is not None

        with self.assertRaises(ValidationError):
            apply_resolution(
                self.manager.store,
                "missing-finding",
                [],  # type: ignore[arg-type]
                actor="organizer-agent",
            )
        with self.assertRaises(NotFoundError):
            self.manager.store.migration_finding("missing-finding")

        cases = (
            ("apply-unsupported", {"action": "waive", "reason": "unsupported"}),
            (
                "apply-payload",
                {"action": "quarantine_object", "reason": "missing quarantine id"},
            ),
            (
                "apply-reason",
                {
                    "action": "quarantine_object",
                    "quarantine_id": "placeholder",
                },
            ),
        )
        for finding_id, partial in cases:
            case_uploaded = self.json_subject(f"{finding_id}-subject")
            self.add_finding(
                finding_id,
                "json_column_invalid",
                "field_bundles",
                case_uploaded["field_bundle_id"],
                details=details,
            )
            shown = self.manager.store.migration_finding(finding_id)
            resolution = {**partial, "subject_hash": shown["subject_hash"]}
            rejected = apply_resolution(
                self.manager.store,
                finding_id,
                resolution,
                actor="organizer-agent",
            )
            self.assertFalse(rejected["accepted"])

        drift_uploaded = self.json_subject("apply-drift-subject")
        self.add_finding(
            "apply-drift",
            "json_column_invalid",
            "field_bundles",
            drift_uploaded["field_bundle_id"],
            details=details,
        )
        drift_shown = self.manager.store.migration_finding("apply-drift")
        drift_quarantine = self.manager.store.create_integrity_quarantine(
            "apply-drift",
            scopes=["block_integration_apply"],
            reason="drift fixture",
            actor="organizer-agent",
        )
        with self.manager.store.transaction() as conn:
            manifest = json.loads(
                conn.execute(
                    "SELECT manifest_json FROM field_bundles WHERE field_bundle_id=?",
                    (drift_uploaded["field_bundle_id"],),
                ).fetchone()[0]
            )
            manifest["source_owner"] = "drifted-owner"
            conn.execute(
                "UPDATE field_bundles SET manifest_json=? WHERE field_bundle_id=?",
                (canonical_json(manifest), drift_uploaded["field_bundle_id"]),
            )
        drifted = apply_resolution(
            self.manager.store,
            "apply-drift",
            {
                "action": "quarantine_object",
                "subject_hash": drift_shown["subject_hash"],
                "quarantine_id": drift_quarantine["quarantine_id"],
                "reason": "subject drift must be rejected",
            },
            actor="organizer-agent",
        )
        self.assertFalse(drifted["accepted"])
        self.assertEqual(drifted["validation"]["code"], "migration_resolution_stale")

        concurrent_uploaded = self.json_subject("apply-concurrent-subject")
        self.add_finding(
            "apply-concurrent",
            "json_column_invalid",
            "field_bundles",
            concurrent_uploaded["field_bundle_id"],
            details=details,
        )
        concurrent_shown = self.manager.store.migration_finding("apply-concurrent")
        concurrent_quarantine = self.manager.store.create_integrity_quarantine(
            "apply-concurrent",
            scopes=["block_integration_apply"],
            reason="concurrent fixture",
            actor="organizer-agent",
        )

        def resolve_during_validation(conn, finding, _subject, _resolution):
            conn.execute(
                "UPDATE migration_findings SET state='resolved' WHERE finding_id=?",
                (finding["finding_id"],),
            )
            return {"valid": True, "findings": []}

        concurrent_handler = replace(
            original_handler,
            prevalidate=resolve_during_validation,
        )
        with (
            patch(
                "issue_manager.migration_resolution.handler_for",
                return_value=concurrent_handler,
            ),
            self.assertRaises(MigrationResolutionStaleError),
        ):
            apply_resolution(
                self.manager.store,
                "apply-concurrent",
                {
                    "action": "quarantine_object",
                    "subject_hash": concurrent_shown["subject_hash"],
                    "quarantine_id": concurrent_quarantine["quarantine_id"],
                    "reason": "concurrent state transition is rejected",
                },
                actor="organizer-agent",
            )

    def test_doctor_revalidates_resolution_receipt_and_subject(self) -> None:
        uploaded = self.json_subject("doctor-resolution")
        self.add_finding(
            "doctor-resolution",
            "json_column_invalid",
            "field_bundles",
            uploaded["field_bundle_id"],
            details={"table": "field_bundles", "column": "manifest_json"},
            classification="blocking_corruption",
        )
        shown = self.manager.store.migration_finding("doctor-resolution")
        quarantine = self.manager.store.create_integrity_quarantine(
            "doctor-resolution",
            scopes=["block_integration_apply"],
            reason="doctor quarantine fixture",
            actor="organizer-agent",
        )
        accepted = apply_resolution(
            self.manager.store,
            "doctor-resolution",
            {
                "action": "quarantine_object",
                "subject_hash": shown["subject_hash"],
                "quarantine_id": quarantine["quarantine_id"],
                "reason": "doctor receipt fixture",
            },
            actor="organizer-agent",
        )
        receipt_id = accepted["receipt_id"]
        with self.assertRaises(NotFoundError):
            self.manager.store.migration_finding_receipt("missing-receipt")

        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_finding_resolution_receipts SET invariant_id='unknown' "
                "WHERE receipt_id=?",
                (receipt_id,),
            )
        codes = {item["code"] for item in self.manager.doctor()["findings"]}
        self.assertIn("migration_resolution_validator_unknown", codes)

        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_finding_resolution_receipts SET invariant_id=? "
                "WHERE receipt_id=?",
                ("object-specific-integrity", receipt_id),
            )
            manifest = json.loads(
                conn.execute(
                    "SELECT manifest_json FROM field_bundles WHERE field_bundle_id=?",
                    (uploaded["field_bundle_id"],),
                ).fetchone()[0]
            )
            manifest["source_owner"] = "drifted-owner"
            conn.execute(
                "UPDATE field_bundles SET manifest_json=? WHERE field_bundle_id=?",
                (canonical_json(manifest), uploaded["field_bundle_id"]),
            )
        codes = {item["code"] for item in self.manager.doctor()["findings"]}
        self.assertIn("migration_resolution_subject_drift", codes)

        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE migration_findings SET resolution_receipt_id=NULL "
                "WHERE finding_id='doctor-resolution'"
            )
        codes = {item["code"] for item in self.manager.doctor()["findings"]}
        self.assertIn("blocking_finding_resolved_without_proof", codes)

    def test_json_and_field_subject_loader_failure_and_success_matrix(self) -> None:
        uploaded = self.json_subject("corrupt-json")
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE field_bundles SET last_error_json='{' WHERE field_bundle_id=?",
                (uploaded["field_bundle_id"],),
            )
        self.add_finding(
            "json-corrupt",
            "json_column_invalid",
            "field_bundles",
            uploaded["field_bundle_id"],
            details={"table": "field_bundles", "column": "last_error_json"},
        )
        corrupt = self.manager.store.migration_finding("json-corrupt")
        validation = validate_object_integrity(
            self.manager.store.conn,
            "field_bundle",
            uploaded["field_bundle_id"],
            column="last_error_json",
        )
        self.assertIn("invalid_json", {item["code"] for item in validation["findings"]})
        self.assertEqual(corrupt["subject"]["snapshot"]["object_type"], "field_bundle")
        self.add_finding(
            "json-missing",
            "historical_json_invalid",
            "field_bundles",
            "missing-bundle",
            details={"table": "field_bundles", "column": "manifest_json"},
        )
        self.assertEqual(
            self.manager.store.migration_finding("json-missing")["subject"]["snapshot"][
                "load_error"
            ],
            "subject_missing",
        )

        record = self.manager.records.create(
            "sample-a",
            self.record_template["registration_id"],
            data={"name": "base"},
        )
        bundle = self.manager.field_bundles.upload(
            self.bundle(
                "field-action-handler",
                {
                    "event_id": "field-action-event",
                    "event_type": "record_patch",
                    "record_instance_id": record["record_instance_id"],
                    "base_record_revision_id": record["record_revision_id"],
                    "data": {"name": "repair"},
                },
            )
        )
        self.manager.field_bundles.route(bundle["field_bundle_id"])
        action = self.manager.store.row(
            "SELECT * FROM field_bundle_event_actions ORDER BY created_at DESC LIMIT 1"
        )
        action_id = action["field_bundle_event_action_id"]
        self.add_finding(
            "field-repair",
            "field_action_identity_incoherent",
            "field_action",
            action_id,
        )
        repair_shown = self.manager.store.migration_finding("field-repair")
        action_validation = validate_object_integrity(
            self.manager.store.conn, "field_bundle_action", action_id
        )
        repaired = apply_resolution(
            self.manager.store,
            "field-repair",
            {
                "action": "repair_from_source",
                "subject_hash": repair_shown["subject_hash"],
                "object_hash": action_validation["subject_after_hash"],
                "reason": "action identity revalidated",
            },
            actor="organizer-agent",
        )
        self.assertTrue(repaired["accepted"], repaired)

        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE field_bundle_event_actions SET state='needs_triage' "
                "WHERE field_bundle_event_action_id=?",
                (action_id,),
            )
        self.add_finding(
            "field-quarantine",
            "record_base_revision_required",
            "field_action",
            action_id,
        )
        quarantine_shown = self.manager.store.migration_finding("field-quarantine")
        exact_quarantine = self.manager.store.create_integrity_quarantine(
            "field-quarantine",
            scopes=["block_integration_apply"],
            reason="action isolated",
            actor="organizer-agent",
        )
        quarantined = apply_resolution(
            self.manager.store,
            "field-quarantine",
            {
                "action": "quarantine_action",
                "subject_hash": quarantine_shown["subject_hash"],
                "quarantine_id": exact_quarantine["quarantine_id"],
                "reason": "action isolated",
            },
            actor="organizer-agent",
        )
        self.assertTrue(quarantined["accepted"])

        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE field_bundle_event_actions SET action_json='{' "
                "WHERE field_bundle_event_action_id=?",
                (action_id,),
            )
        self.add_finding(
            "field-corrupt",
            "record_base_revision_mismatch",
            "field_action",
            action_id,
        )
        corrupt_action = validate_object_integrity(
            self.manager.store.conn, "field_bundle_action", action_id, column="action_json"
        )
        self.assertIn(
            "invalid_json", {item["code"] for item in corrupt_action["findings"]}
        )
        self.add_finding(
            "field-missing",
            "field_action_identity_incoherent",
            "field_action",
            "missing-action",
        )
        self.assertEqual(
            self.manager.store.migration_finding("field-missing")["subject"]["snapshot"][
                "load_error"
            ],
            "subject_missing",
        )

    def test_policy_resolution_requires_exact_registration_and_subject(self) -> None:
        legacy = self.manager.registry.install_bundle(
            migrated_policy_bundle(DEFAULT_POLICY)
        )
        self.manager.registry.activate_bundle(legacy["bundle_id"])
        mapping = self.manager.registry.resolve(
            "org.example.v81/mapping_profile/measurement-map@1.0.0"
        )
        self.add_finding(
            "policy-mapping",
            "legacy_policy_semantics_not_declaratively_convertible",
            "extension_bundle",
            legacy["bundle_id"],
            details={"bundle_id": legacy["bundle_id"]},
            classification="requires_policy_mapping",
        )
        shown = self.manager.store.migration_finding("policy-mapping")
        mapped = apply_resolution(
            self.manager.store,
            "policy-mapping",
            {
                "action": "install_mapping_bundle",
                "subject_hash": shown["subject_hash"],
                "mapping_registration_id": mapping["registration_id"],
                "mapping_registration_hash": mapping["content_hash"],
                "reason": "exact active mapping registration installed",
            },
            actor="organizer-agent",
        )
        self.assertFalse(mapped["accepted"])
        self.assertEqual(
            mapped["validation"]["code"], "migration_resolution_action_unsupported"
        )

        candidate = self.manager.store.create_migration_policy_repair(
            "policy-mapping",
            replacement_policy=copy.deepcopy(DEFAULT_POLICY),
            actor="organizer-agent",
        )
        validated = self.manager.store.validate_migration_policy_repair(
            candidate["repair_id"]
        )
        self.assertEqual(validated["state"], "validated")
        repaired = self.manager.store.apply_migration_policy_repair(
            candidate["repair_id"],
            reason="exact Policy repair candidate",
            actor="organizer-agent",
        )
        self.assertTrue(repaired["accepted"])
        self.assertEqual(repaired["proof_format"], "migration-resolution-proof/v2")

        self.add_finding(
            "policy-missing",
            "legacy_policy_bundle_prepare_invalid",
            "extension_bundle",
            "missing-bundle",
            classification="requires_policy_mapping",
        )
        missing = self.manager.store.migration_finding("policy-missing")
        rejected = self.manager.store.validate_migration_finding_resolution(
            "policy-missing",
            {
                "action": "apply_policy_repair",
                "subject_hash": missing["subject_hash"],
                "repair_id": "missing-repair",
                "repair_hash": "wrong",
                "reason": "missing subject",
            },
        )
        self.assertFalse(rejected["valid"])
        self.assertIn(
            rejected["code"],
            {"migration_resolution_rejected", "migration_resolution_action_unsupported"},
        )


class V083ConflictBindingQualityEdges(V082Base):
    def apply_reviewed(self, changeset: dict) -> dict:
        organizer = self.manager.credentials.path_for("organizer-agent")
        created = self.manager.changesets.create(changeset, credential=organizer)
        self.manager.changesets.validate(created["changeset_id"], credential=organizer)
        for actor in ("review-agent-1", "review-agent-2"):
            reviewer = self.manager.credentials.path_for(actor)
            self.manager.changesets.claim_review(
                created["changeset_id"], credential=reviewer
            )
            self.manager.changesets.submit_review(
                created["changeset_id"],
                decision="pass",
                rationale="receipt integrity audit",
                credential=reviewer,
            )
        return self.manager.changesets.apply(
            created["changeset_id"], credential=organizer
        )

    def conflict_fixture(self, suffix="") -> tuple[dict, dict, dict]:
        record = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "base"}
        )
        bundle = self.manager.field_bundles.upload(
            self.bundle(
                "binding-matrix" + suffix,
                {
                    "event_id": "binding-action",
                    "event_type": "record_patch",
                    "record_instance_id": record["record_instance_id"],
                    "base_record_revision_id": record["record_revision_id"],
                    "data": {"name": "candidate"},
                },
            )
        )
        self.manager.field_bundles.route(bundle["field_bundle_id"])
        current = self.manager.records.revise(
            record["record_instance_id"],
            {"name": "current"},
            expected_revision_id=record["record_revision_id"],
        )
        self.manager.field_bundles.apply(bundle["field_bundle_id"])
        conflict = self.manager.field_bundles.conflicts(bundle["field_bundle_id"])[0]
        proposed = self.manager.field_bundles.propose_resolution(
            conflict["integration_conflict_id"], "reject_candidate"
        )
        return record, current, {
            "conflict": conflict,
            "operation": proposed["operation"],
            "changeset": proposed["changeset"],
        }

    def test_governed_conflict_preview_closes_only_virtual_state(self) -> None:
        from issue_manager.changeset_engine import simulate_operation
        from issue_manager.changeset_state import StateView

        _, _, fixture = self.conflict_fixture()
        operation = fixture["operation"]
        view = StateView(self.manager)
        simulate_operation(view, operation)
        self.assertEqual(view.integration_conflicts[operation["conflict_id"]]["state"], "resolved")
        self.assertEqual(view.integration_conflicts[operation["conflict_id"]]["state_revision"], operation["expected_conflict_revision"] + 1)
        with self.assertRaises(ConflictBindingError):
            validate_resolution_binding(self.manager.store.conn, "field_bundle", operation, state_view=view)
        self.assertEqual(validate_resolution_binding(self.manager.store.conn, "field_bundle", operation)["conflict"]["state"], "open")
        with self.assertRaises(ConflictError):
            self.manager.changesets.create({**fixture["changeset"], "operations": [operation, operation]},
                                           credential=self.manager.credentials.path_for("organizer-agent"))

    def test_field_source_preview_matches_resolution_execution(self) -> None:
        from issue_manager.changeset_engine import simulate_operation
        from issue_manager.changeset_state import StateView

        for decision in ("reject_candidate", "keep_internal", "needs_more_information"):
            with self.subTest(decision=decision):
                _, _, fixture = self.conflict_fixture(decision)
                operation = {**fixture["operation"], "resolution": decision}
                view = StateView(self.manager)
                simulate_operation(view, operation)
                self.manager.field_bundles.resolve_conflict(operation["conflict_id"], decision,
                                                           expected_revision=operation["expected_conflict_revision"])
                for table, key, staged in (
                    ("field_bundle_event_actions", "field_bundle_event_action_id", view.field_bundle_event_actions),
                    ("field_bundle_events", "field_bundle_event_id", view.field_bundle_events),
                    ("field_bundles", "field_bundle_id", view.field_bundles),
                ):
                    for identity, expected in staged.items():
                        self.assertEqual(expected, self.manager.store.row(f"SELECT * FROM {table} WHERE {key}=?", (identity,)))

    def test_field_record_resolution_preview_matches_dual_reviewer_execution(self) -> None:
        from issue_manager.changeset_engine import simulate_operation
        from issue_manager.changeset_state import StateView

        def normalize(value, id_map):
            if isinstance(value, dict):
                return {
                    key: (None if key == "event_id" else normalize(item, id_map))
                    for key, item in value.items()
                }
            if isinstance(value, list):
                return [normalize(item, id_map) for item in value]
            return id_map.get(value, value)

        for decision in ("accept_as_new_revision", "create_competing_record"):
            with self.subTest(decision=decision):
                _, _, fixture = self.conflict_fixture("-" + decision)
                proposed = self.manager.field_bundles.propose_resolution(
                    fixture["conflict"]["integration_conflict_id"], decision
                )
                operation = proposed["operation"]
                action_id = fixture["conflict"]["source_item_id"]
                event_id = self.manager.store.row(
                    "SELECT field_bundle_event_id FROM field_bundle_event_actions "
                    "WHERE field_bundle_event_action_id=?", (action_id,)
                )["field_bundle_event_id"]
                before_records = self.manager.store.row(
                    "SELECT COUNT(*) AS n FROM record_instances"
                )["n"]
                before_receipts = self.manager.store.row(
                    "SELECT COUNT(*) AS n FROM governed_conflict_resolution_receipts"
                )["n"]
                view = StateView(self.manager)
                simulate_operation(view, operation)
                self.assertEqual(
                    self.manager.store.row("SELECT COUNT(*) AS n FROM record_instances")["n"],
                    before_records,
                )
                self.assertEqual(
                    self.manager.store.row(
                        "SELECT COUNT(*) AS n FROM governed_conflict_resolution_receipts"
                    )["n"],
                    before_receipts,
                )
                preview_action = view.field_bundle_event_actions[action_id]
                preview_event = view.field_bundle_events[event_id]
                applied = self.apply_reviewed(proposed["changeset"])
                del applied
                actual_action = self.manager.store.row(
                    "SELECT result_json FROM field_bundle_event_actions "
                    "WHERE field_bundle_event_action_id=?", (action_id,)
                )
                actual_event = self.manager.store.row(
                    "SELECT result_json FROM field_bundle_events WHERE field_bundle_event_id=?",
                    (event_id,),
                )
                preview_result = json.loads(preview_action["result_json"])
                actual_result = json.loads(actual_action["result_json"])
                id_map = {}
                if str(preview_result.get("record_instance_id", "")).startswith("preflight-"):
                    id_map[preview_result["record_instance_id"]] = actual_result["record_instance_id"]
                if str(preview_result.get("record_revision_id", "")).startswith("preflight-"):
                    id_map[preview_result["record_revision_id"]] = actual_result["record_revision_id"]
                self.assertEqual(normalize(preview_result, id_map), normalize(actual_result, id_map))
                self.assertEqual(
                    normalize(json.loads(preview_event["result_json"]), id_map),
                    normalize(json.loads(actual_event["result_json"]), id_map),
                )
                for revision_id, planned in view.record_revisions.items():
                    actual_id = id_map.get(revision_id, revision_id)
                    actual = self.manager.store.row(
                        "SELECT * FROM record_revisions WHERE record_revision_id=?", (actual_id,)
                    )
                    self.assertIsNotNone(actual)
                    self.assertEqual(planned["content_hash"], actual["content_hash"])

    def test_field_batch_followup_reads_virtual_record_pointer(self) -> None:
        from issue_manager.changeset_engine import simulate_operation
        from issue_manager.changeset_state import StateView

        record = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "base"}
        )
        bundles = []
        for index, candidate in enumerate(("candidate-a", "candidate-b")):
            bundles.append(
                self.manager.field_bundles.upload(
                    self.bundle(
                        f"same-record-{index}",
                        {
                            "event_id": f"same-record-event-{index}",
                            "event_type": "record_patch",
                            "record_instance_id": record["record_instance_id"],
                            "base_record_revision_id": record["record_revision_id"],
                            "data": {"name": candidate},
                        },
                    )
                )
            )
            self.manager.field_bundles.route(bundles[-1]["field_bundle_id"])
        self.manager.records.revise(
            record["record_instance_id"], {"name": "online"},
            expected_revision_id=record["record_revision_id"],
        )
        for bundle in bundles:
            self.manager.field_bundles.apply(bundle["field_bundle_id"])
        conflicts = [
            self.manager.field_bundles.conflicts(bundle["field_bundle_id"])[0]
            for bundle in bundles
        ]
        operations = [
            self.manager.field_bundles.propose_resolution(
                conflict["integration_conflict_id"], "accept_as_new_revision"
            )["operation"]
            for conflict in conflicts
        ]
        view = StateView(self.manager)
        simulate_operation(view, operations[0])
        self.assertTrue(view.record_instances[record["record_instance_id"]]["current_revision_id"].startswith("preflight-"))
        with self.assertRaises(ConflictBindingError):
            simulate_operation(view, operations[1])

    def test_governed_payload_cannot_override_resolution(self) -> None:
        _, _, fixture = self.conflict_fixture()
        operation = fixture["operation"]
        payload = {"action": "accept_as_new_revision"}
        with self.assertRaises(ValidationError):
            build_resolution_operation(self.manager.store, "field_bundle", operation["conflict_id"],
                                       "reject_candidate", resolution_payload=payload)
        with self.assertRaises(ValidationError):
            validate_resolution_binding(self.manager.store.conn, "field_bundle",
                                        {**operation, "resolution_payload": payload, "resolution_payload_hash": content_hash(payload)})

    def test_operation_builder_and_binding_rejection_matrix(self) -> None:
        record, _, fixture = self.conflict_fixture()
        conflict = fixture["conflict"]
        operation = fixture["operation"]
        conflict_id = conflict["integration_conflict_id"]
        with self.assertRaises(ValidationError):
            build_resolution_operation(
                self.manager.store, "unknown", conflict_id, "reject_candidate"
            )
        with self.assertRaises(NotFoundError):
            build_resolution_operation(
                self.manager.store, "field_bundle", "missing", "reject_candidate"
            )
        with self.assertRaises(ValidationError):
            build_resolution_operation(
                self.manager.store, "field_bundle", conflict_id, "unknown"
            )
        with self.assertRaises(ValidationError):
            build_resolution_operation(
                self.manager.store,
                "field_bundle",
                conflict_id,
                "reject_candidate",
                resolution_payload={"bad": math.inf},
            )
        validated = validate_resolution_binding(
            self.manager.store.conn, "field_bundle", operation
        )
        self.assertEqual(validated["conflict"]["integration_conflict_id"], conflict_id)

        mutations = (
            ("op", "wrong"),
            ("resolution", "wrong"),
            ("conflict_id", "missing"),
            ("expected_conflict_revision", 99),
            ("candidate_action_hash", "wrong"),
            ("resolution_payload", []),
            ("resolution_payload_hash", "wrong"),
            ("record_instance_id", "wrong"),
            ("expected_current_revision_id", "wrong"),
            ("base_record_revision_id", "wrong"),
        )
        for field, value in mutations:
            candidate = copy.deepcopy(operation)
            candidate[field] = value
            with self.subTest(field=field), self.assertRaises(
                (ConflictError, ValidationError)
            ):
                validate_resolution_binding(
                    self.manager.store.conn, "field_bundle", candidate
                )

        domain_mismatch = {**operation, "op": "resolve_import_conflict"}
        with self.assertRaises(ConflictError):
            validate_resolution_binding(
                self.manager.store.conn, "import", domain_mismatch
            )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE integration_conflicts SET state='resolved' "
                "WHERE integration_conflict_id=?",
                (conflict_id,),
            )
            with self.assertRaises(ConflictError):
                validate_resolution_binding(conn, "field_bundle", operation)
            conn.execute(
                "UPDATE integration_conflicts SET state='open' "
                "WHERE integration_conflict_id=?",
                (conflict_id,),
            )

        other = self.manager.records.create(
            "sample-a", self.record_template["registration_id"], data={"name": "other"}
        )
        source_item_id = conflict["source_item_id"]
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE field_bundle_event_actions SET base_record_revision_id=? "
                "WHERE field_bundle_event_action_id=?",
                (other["record_revision_id"], source_item_id),
            )
            wrong_owner = {
                **operation,
                "base_record_revision_id": other["record_revision_id"],
            }
            with self.assertRaises(ConflictError):
                validate_resolution_binding(conn, "field_bundle", wrong_owner)

        self.assertEqual(current_revision(self.manager.store.conn, None), None)
        self.assertEqual(
            current_revision(self.manager.store.conn, "missing-record"), None
        )
        self.assertEqual(
            conflict_target(
                self.manager.store.conn,
                "import",
                {"existing_mapping_id": "missing-mapping"},
            ),
            (None, None),
        )

        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE field_bundle_event_actions SET state='needs_triage',"
                "target_record_instance_id=NULL,base_record_revision_id=NULL,action_json='{' "
                "WHERE field_bundle_event_action_id=?",
                (source_item_id,),
            )
            self.assertEqual(
                conflict_target(conn, "field_bundle", conflict), (None, None)
            )
            self.assertEqual(
                conflict_target(
                    conn,
                    "field_bundle",
                    {**conflict, "source_item_id": "missing-action"},
                ),
                (None, None),
            )
        self.assertEqual(record["record_instance_id"], operation["record_instance_id"])

    def test_doctor_detects_governance_receipt_and_review_tampering(self) -> None:
        _, _, fixture = self.conflict_fixture()
        applied = self.apply_reviewed(fixture["changeset"])
        conflict_id = fixture["conflict"]["integration_conflict_id"]
        receipt = self.manager.field_bundles.resolution_receipt(conflict_id)
        self.assertEqual(receipt["changeset_id"], applied["changeset_id"])

        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE governed_conflict_resolution_receipts SET operation_hash='tampered' "
                "WHERE receipt_id=?",
                (receipt["receipt_id"],),
            )
        codes = {item["code"] for item in self.manager.doctor()["findings"]}
        self.assertIn("conflict_changeset_binding_mismatch", codes)

        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE governed_conflict_resolution_receipts SET operation_hash=? "
                "WHERE receipt_id=?",
                (receipt["operation_hash"], receipt["receipt_id"]),
            )
            review_id = receipt["review_ids"][0]
            conn.execute(
                "UPDATE changeset_review_decisions SET changeset_hash='tampered' "
                "WHERE review_id=?",
                (review_id,),
            )
        codes = {item["code"] for item in self.manager.doctor()["findings"]}
        self.assertIn("conflict_review_hash_mismatch", codes)

        with self.manager.store.transaction() as conn:
            conn.execute(
                "DELETE FROM governed_conflict_resolution_receipts WHERE receipt_id=?",
                (receipt["receipt_id"],),
            )
        codes = {item["code"] for item in self.manager.doctor()["findings"]}
        self.assertIn("conflict_resolution_receipt_missing", codes)


class V083V12BackfillQualityEdges(unittest.TestCase):
    pass


if __name__ == "__main__":
    unittest.main()


class V083RegistryMigrationQualityEdges(V082Base):
    def test_migrated_policy_install_uses_verified_plan_and_exact_locks(self) -> None:
        custom = copy.deepcopy(DEFAULT_POLICY)
        custom["policy_version"] = int(custom["policy_version"]) + 1
        with self.manager.store.transaction() as conn:
            self.assertIsNone(install_migrated_policy_bundle(conn, DEFAULT_POLICY))
            installed = install_migrated_policy_bundle(conn, custom)
        assert installed is not None
        self.assertTrue(installed["migration_candidate"])
        self.assertTrue(
            self.manager.store.row(
                "SELECT registration_id FROM registry_entries "
                "WHERE bundle_id=? AND kind='routing_profile'",
                (installed["bundle_id"],),
            )
        )

        unsafe = {
            "safe_to_apply": False,
            "source_policy_hash": "wrong",
            "prepared_bundle": None,
            "prepared_bundle_hash": None,
            "blocking_findings": [{"code": "unsafe"}],
        }
        with self.assertRaises(ValidationError):
            with self.manager.store.transaction() as conn:
                install_migrated_policy_bundle(conn, custom, migration_plan=unsafe)

        empty = sqlite3.connect(":memory:")
        try:
            empty.execute("CREATE TABLE actors(actor_id TEXT)")
            self.assertIsNone(install_migrated_policy_bundle(empty, custom))
        finally:
            empty.close()
