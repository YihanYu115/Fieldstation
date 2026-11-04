from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from issue_manager import IssueManager
from issue_manager.changeset_engine import (
    ChangeSetOperationEngine,
    _simulate_attach_packet,
    _simulate_context_change,
    _simulate_issue_relation_lifecycle,
    _simulate_set_relation_impact,
    assert_operation_registry_complete,
)
from issue_manager.changeset_execution import ChangeSetExecutionMixin
from issue_manager.changeset_state import StateView
from issue_manager.errors import ValidationError
from issue_manager.evidence_service import EvidenceService
from issue_manager.risk import RiskPolicy
from issue_manager.scope_identity import SampleKey


class PreproductionStateAndEngineEdges(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.manager = IssueManager.initialize(Path(self.temp.name) / "ledger")
        self.manager.create_issue("edge-a", "investigation", scope={"sample": "A"})
        self.manager.create_issue("edge-b", "investigation", scope={"sample": "B"})

    def tearDown(self) -> None:
        self.manager.close()
        self.temp.cleanup()

    def test_state_view_overlay_and_cycle_error_edges(self) -> None:
        view = StateView(self.manager)
        with patch.object(self.manager.store, "rows", return_value=[{"issue_id": "edge-a"}]):
            self.assertTrue(view.has_current_evidence_use("evidence"))
        view.appended_work.append({"entry_id": "prepared", "source_packet_id": "packet-a"})
        self.assertEqual(view.context_rows("working_entries", "source_packet_id", "packet-a")[0]["entry_id"], "prepared")
        self.assertEqual(view.context_rows("working_entries", "entry_id", "prepared"), [])
        view.record_evidence_links[("revision", "field", "evidence", "supports")] = {
            "record_revision_id": "revision", "field_path": "field", "evidence_id": "evidence", "relation_role": "supports"
        }
        self.assertEqual(view.context_rows("record_evidence_links", "evidence_id", "evidence")[0]["field_path"], "field")
        view.external_mapping_targets[("mapping", "issue", "edge-a")] = {
            "source_object_mapping_id": "mapping", "internal_object_type": "issue", "internal_object_id": "edge-a"
        }
        self.assertTrue(view.context_rows("external_mapping_targets", "internal_object_id", "edge-a"))
        self.assertIsNone(view.issue_row("missing-issue"))
        with self.assertRaisesRegex(ValidationError, "Record not found"):
            view.record_instance("missing-record")
        with self.assertRaisesRegex(ValidationError, "Record revision not found"):
            view.record_revision("missing-revision")
        with self.assertRaisesRegex(ValidationError, "Missing relationship version"):
            view.stage_legacy_relation("issue", {"relation_id": "missing"})
        self.assertFalse(view.hard_issue_cycle("edge-a", "edge-b"))
        view.new_hard_issue_edges.add(("edge-b", "edge-a"))
        self.assertTrue(view.hard_issue_cycle("edge-a", "edge-b"))

    def test_simulator_rejects_cycles_and_models_context_select(self) -> None:
        view = StateView(self.manager)
        view.issue_relation_active["relation-1"] = True
        with unittest.mock.patch(
            "issue_manager.issue_relation_planner.plan_impact", return_value={"hard_cycle": True}
        ):
            with self.assertRaisesRegex(ValidationError, "would create a cycle"):
                _simulate_set_relation_impact(
                    view, {"relation_id": "relation-1", "impact_policy": "hard"}
                )
        with unittest.mock.patch(
            "issue_manager.issue_relation_planner.plan_lifecycle", return_value={"hard_cycle": True}
        ):
            with self.assertRaisesRegex(ValidationError, "would create a cycle"):
                _simulate_issue_relation_lifecycle(
                    view, {"op": "reactivate_relation", "relation_id": "relation-1"}
                )
        view.manager.context_maintenance = Mock()
        view.issue_relation = lambda _relation_id: None
        with patch(
            "issue_manager.issue_relation_planner.plan_impact", return_value={"hard_cycle": False}
        ):
            with self.assertRaisesRegex(ValidationError, "relationship does not exist"):
                _simulate_set_relation_impact(
                    view, {"relation_id": "relation-1", "impact_policy": "soft"}
                )
        with patch("issue_manager.intake_planner.plan_attach", return_value={
            "packet_id": "packet-a", "issue_id": "edge-a", "packet": {"packet_json": "{}"}
        }), patch("issue_manager.changeset_engine._simulate_attach_evidence"), patch(
            "issue_manager.changeset_engine._simulate_append_work",
            side_effect=lambda target_view, _operation: target_view.appended_work.append({}),
        ), patch.object(self.manager.store, "rows", return_value=[{"evidence_id": "e1"}]), patch.object(
            self.manager.store, "row", return_value={
                "packet_id": "packet-a", "issue_id": "edge-a", "disposition": "no_impact",
            }
        ):
            view.manager.intake._packet_work_body = Mock(return_value="packet work")
            view.manager.intake.active_link_types = Mock(return_value=[])
            with self.assertRaisesRegex(Exception, "append-only"):
                _simulate_attach_packet(view, {"packet_id": "packet-a", "issue_id": "edge-a"})
        view.manager.context_maintenance = Mock()
        view.manager.context_maintenance.validate_change.return_value = None
        _simulate_context_change(
            view,
            {
                "action": "select",
                "items": [{"conclusion_id": "c1", "receipt_id": "r1", "package_id": "pkg"}],
            },
        )
        self.assertEqual(view.selected_receipts["c1"], "r1")
        self.assertNotIn("c1", view.verified_packages)

    def test_runtime_contract_and_registry_mismatch_fail_closed(self) -> None:
        broken = SimpleNamespace(
            op="broken", validator="missing_validator", risk_model="missing_risk",
            simulator="missing_simulator", executor="missing_executor", base_tier="T1"
        )
        service = SimpleNamespace(manager=SimpleNamespace(), risk_policy=SimpleNamespace())
        engine = object.__new__(ChangeSetOperationEngine)
        engine.service = service
        with patch("issue_manager.changeset_engine.OPERATION_DEFINITIONS", {"broken": broken}), patch(
            "issue_manager.changeset_engine._SIMULATORS", {}
        ):
            with self.assertRaisesRegex(RuntimeError, "Incomplete ChangeSet operation runtime contracts"):
                engine._assert_runtime_contracts()
        with patch("issue_manager.changeset_engine.CHANGESET_OPERATION_SPECS", {"different": object()}):
            with self.assertRaisesRegex(RuntimeError, "registry mismatch"):
                assert_operation_registry_complete()


    def test_replace_relation_executor_requires_evidence_capability(self) -> None:
        executor = ChangeSetExecutionMixin()
        required = Mock()
        executor.manager = SimpleNamespace(relation_versions=Mock())
        executor.manager.relation_versions.replace.return_value = {"ok": True}
        context = SimpleNamespace(auth=SimpleNamespace(require=required, actor_id="actor"))
        result = executor._execute_replace_relation({"domain": "evidence"}, context=context)
        self.assertEqual(result, {"ok": True})
        required.assert_called_once_with("evidence.relation.write")

    def test_intake_claim_rejects_terminal_and_raced_terminal_task(self) -> None:
        credential = self.manager.credentials.path_for("organizer-agent")
        packet = self.manager.intake.submit(
            {
                "packet_version": 2,
                "request_id": "coverage-intake-claim",
                "routing_hints": {"topic": "coverage"},
                "observations": ["claim edge"],
                "evidence": [],
            },
            credential=credential,
        )
        packet_id = packet["packet_id"]
        with self.manager.store.transaction() as conn:
            conn.execute("UPDATE triage_tasks SET state='completed' WHERE packet_id=?", (packet_id,))
        with self.assertRaisesRegex(Exception, "not claimable"):
            self.manager.intake.claim(packet_id, credential=credential)

        class _Transaction:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def execute(self, _sql, _params=()):
                cursor = Mock()
                cursor.fetchone.return_value = {"state": "completed", "triage_task_id": "task"}
                return cursor

        with patch.object(self.manager.intake, "_task", return_value={"state": "pending"}), patch.object(
            self.manager.store, "transaction", return_value=_Transaction()
        ):
            with self.assertRaisesRegex(Exception, "not claimable"):
                self.manager.intake.claim(packet_id, credential=credential)


class PreproductionRiskEdges(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Mock()
        self.store.conn = SimpleNamespace(in_transaction=False)
        self.manager = SimpleNamespace(store=self.store)
        self.policy = RiskPolicy(self.manager)

    @staticmethod
    def _sample(value: str) -> SampleKey:
        return SampleKey.from_raw(value)  # type: ignore[return-value]

    def _state(self, issues: dict[str, dict]) -> Mock:
        state = Mock()
        state.issue.side_effect = lambda issue_id: issues[issue_id]
        state.sample_for_issue.side_effect = lambda issue_id: self._sample(issues[issue_id]["scope"]["sample"])
        state.question.side_effect = lambda question_id: {"issue_id": question_id.split("-")[-1]}
        state.context_rows.return_value = []
        state.material_version.return_value = None
        return state

    def test_question_context_and_material_consumers_escalate(self) -> None:
        issues = {
            "a": {"issue_type": "investigation", "scope": {"sample": "A"}},
            "b": {"issue_type": "investigation", "scope": {"sample": "B"}},
        }
        state = self._state(issues)
        self.store.row.side_effect = lambda _sql, args: {
            "canonical-conclusion": {"issue_id": "a", "status": "canonical"},
            "accepted-conclusion": {"issue_id": "b", "status": "accepted"},
        }.get(args[0])
        self.manager.issue_report_facing = lambda issue: issue is issues["b"]
        tier, reasons, samples = self.policy._risk_question(
            {"op": "answer_question", "question_id": "q-a", "conclusion_id": "canonical-conclusion"},
            state,
            "T0",
        )
        self.assertEqual(tier, "T3")
        self.assertIn("canonical-question-answer", reasons)
        self.assertEqual(samples, {self._sample("a")})

        self.store.rows.side_effect = lambda sql, args: (
            [{"conclusion_id": "accepted-conclusion"}, {"conclusion_id": "canonical-conclusion"}]
            if "conclusion_id FROM conclusion_revisions" in sql
            else []
        )
        tier, reasons, samples = self.policy._risk_material_consumers(
            {"a", "b"}, {"accepted-conclusion", "canonical-conclusion", "missing"}, state, "T0", "material"
        )
        self.assertEqual(tier, "T3")
        self.assertEqual(reasons, {"material"})
        self.assertEqual(samples, {self._sample("a"), self._sample("b")})

    def test_context_obligation_replacement_and_material_relation_edges(self) -> None:
        issues = {
            "a": {"issue_type": "investigation", "scope": {"sample": "A"}},
            "b": {"issue_type": "investigation", "scope": {"sample": "B"}},
        }
        state = self._state(issues)
        self.manager.issue_report_facing = lambda issue: issue is issues["b"]
        self.manager.context_obligations = Mock()
        self.manager.context_obligations.preview.return_value = {"after": {"conclusion_id": "accepted"}}
        self.store.row.side_effect = lambda _sql, args: {"issue_id": "a", "status": "accepted"} if args[0] == "accepted" else None
        tier, reasons, samples = self.policy._risk_context_obligation(
            {"action": "complete"}, state, "T0"
        )
        self.assertEqual(tier, "T2")
        self.assertEqual(reasons, {"independent-review-obligation"})
        self.assertEqual(samples, {self._sample("a")})

        self.manager.context_obligations.preview.return_value = {"after": {"conclusion_id": "missing"}}
        self.store.row.side_effect = lambda _sql, _args: None
        with self.assertRaisesRegex(ValidationError, "obligation conclusion"):
            self.policy._risk_context_obligation({"action": "complete"}, state, "T0")

        self.manager.context_obligations.preview.return_value = {"after": {"conclusion_id": "canonical"}}
        self.store.row.side_effect = lambda _sql, _args: {"issue_id": "b", "status": "canonical"}
        self.manager.issue_report_facing = lambda _issue: True
        tier, _reasons, _samples = self.policy._risk_context_obligation(
            {"action": "review"}, state, "T0"
        )
        self.assertEqual(tier, "T3")

        self.manager.relation_versions = Mock()
        self.manager.relation_versions.preview.return_value = {
            "domain": "issue",
            "before": {"impact_policy": "hard", "consumer_issue_id": "a", "provider_issue_id": "b"},
            "after": {"impact_policy": "hard", "consumer_issue_id": "b", "provider_issue_id": "a"},
        }
        tier, reasons, samples = self.policy._risk_replace_relation({}, state, "T0")
        self.assertEqual(tier, "T3")
        self.assertIn("hard-relation-replacement", reasons)
        self.assertIn("report-facing-relation", reasons)
        self.assertEqual(samples, {self._sample("a"), self._sample("b")})

    def test_context_relation_recurses_through_typed_material_endpoints(self) -> None:
        state = self._state({
            "a": {"issue_type": "investigation", "scope": {"sample": "A"}},
            "b": {"issue_type": "investigation", "scope": {"sample": "B"}},
        })
        self.manager.issue_report_facing = lambda _issue: False
        self.manager.context_relations = Mock()
        keys = {
            "record": json.dumps(["record_version", "record-v"]),
            "issue": json.dumps(["relation_version", "issue-v"]),
            "question": json.dumps(["relation_version", "question-v"]),
            "record_relation": json.dumps(["relation_version", "record-rel-v"]),
            "intake": json.dumps(["relation_version", "intake-v"]),
            "evidence": json.dumps(["relation_version", "evidence-v"]),
            "conclusion": json.dumps(["conclusion_version", "conclusion-a"]),
        }
        self.manager.context_relations.preview.return_value = {
            "before": {"source_key": keys["record"], "target_key": keys["issue"]},
            "after": {"source_key": keys["question"], "target_key": keys["record_relation"]},
        }
        material = {
            "record-v": {"domain": "record", "definition_json": json.dumps({"record_revision_id": "rr"})},
            "issue-v": {"domain": "issue", "definition_json": json.dumps({"consumer_issue_id": "a", "provider_issue_id": "b"})},
            "question-v": {"domain": "question", "definition_json": json.dumps({"question_id": "q-a"})},
            "record-rel-v": {"domain": "record", "definition_json": json.dumps({"record_revision_id": "rr"})},
            "intake-v": {"domain": "intake", "definition_json": json.dumps({"source_packet_id": "p1", "target_packet_id": "p2"})},
            "evidence-v": {"domain": "evidence", "definition_json": json.dumps({"consumer_evidence_id": "e1", "provider_evidence_id": "e2"})},
        }
        state.material_version.side_effect = lambda identity: material.get(identity)
        def row(sql: str, args: tuple[str, ...]):
            if "record_revisions" in sql:
                return {"issue_id": "a"}
            if "conclusion_revisions" in sql:
                return {"issue_id": "a", "status": "accepted"}
            if "intake_packets" in sql:
                return {"attached_issue_id": "b"}
            return None
        self.store.row.side_effect = row
        self.store.rows.side_effect = lambda sql, _args: (
            [{"issue_id": "b"}] if "issue_evidence" in sql else []
        )
        tier, reasons, samples = self.policy._risk_context_relation(
            {"op": "context_relation"}, state, "T0"
        )
        self.assertEqual(tier, "T3")
        self.assertIn("material-relation-change", reasons)
        self.assertEqual(samples, {self._sample("a"), self._sample("b")})

    def test_context_change_lifecycle_and_evidence_replacement_edges(self) -> None:
        issues = {
            "a": {"issue_type": "investigation", "scope": {"sample": "A"}},
            "b": {"issue_type": "investigation", "scope": {"sample": "B"}},
        }
        state = self._state(issues)
        self.manager.context_maintenance = Mock()
        self.manager.issue_report_facing = lambda _issue: False
        self.manager.context_maintenance.validate_change.return_value = None
        self.manager.context_maintenance.package.return_value = {"descriptor": {"kind": "test"}}
        self.manager.context_maintenance._resolver_for.return_value.resolve.return_value = SimpleNamespace(
            contributions=[("c2", None)]
        )

        def row(sql: str, args: tuple[str, ...]):
            if "basis_receipts" in sql:
                return {"package_id": "pkg"}
            if "conclusion_revisions" in sql:
                return {
                    "c1": {"issue_id": "a", "status": "canonical"},
                    "c2": {"issue_id": "b", "status": "accepted"},
                }.get(args[0])
            return None

        self.store.row.side_effect = row
        self.store.rows.side_effect = lambda sql, _args: (
            [{"consumer_conclusion_id": "c2"}]
            if "currentness_edge_contributions" in sql
            else []
        )
        tier, reasons, samples = self.policy._risk_context_change(
            {
                "action": "select",
                "items": [{"conclusion_id": "c1", "receipt_id": "r1"}],
            },
            state,
            "T0",
        )
        self.assertEqual(tier, "T3")
        self.assertIn("canonical-or-report-facing-context", reasons)
        self.assertIn("accepted-or-withdrawn-context", reasons)
        self.assertIn("cross-sample-context", reasons)
        self.assertEqual(samples, {self._sample("a"), self._sample("b")})

        state.issue_relation.return_value = None
        with self.assertRaisesRegex(ValidationError, "Relation not found"):
            self.policy._risk_issue_relation_lifecycle(
                {"op": "deactivate_relation", "relation_id": "missing"}, state, "T0"
            )

        self.manager.relation_versions = Mock()
        self.manager.relation_versions.preview.return_value = {
            "domain": "evidence",
            "before": {
                "impact_policy": "soft", "consumer_evidence_id": "e1",
                "provider_evidence_id": "e2", "relation_type": "supports",
            },
            "after": {
                "impact_policy": "hard", "consumer_evidence_id": "e2",
                "provider_evidence_id": "e1", "relation_type": "supports",
            },
        }
        self.manager.evidence_relations = Mock()
        self.manager.evidence_relations.assess_add.return_value = {
            "tier": "T2", "reasons": {"evidence-propagation"}
        }
        tier, reasons, _samples = self.policy._risk_replace_relation({}, state, "T0")
        self.assertEqual(tier, "T3")
        self.assertIn("hard-relation-replacement", reasons)
        self.assertIn("evidence-propagation", reasons)

    def test_context_relation_intake_evidence_and_conclusion_endpoints(self) -> None:
        issues = {
            "a": {"issue_type": "investigation", "scope": {"sample": "A"}},
            "b": {"issue_type": "investigation", "scope": {"sample": "B"}},
        }
        state = self._state(issues)
        self.manager.issue_report_facing = lambda _issue: False
        self.manager.context_relations = Mock()
        material = {
            "intake-v": {"domain": "intake", "definition_json": json.dumps({"source_packet_id": "p1", "target_packet_id": "p2"})},
            "evidence-v": {"domain": "evidence", "definition_json": json.dumps({"consumer_evidence_id": "e1", "provider_evidence_id": "e2"})},
        }
        state.material_version.side_effect = lambda identity: material.get(identity)
        self.store.row.side_effect = lambda sql, args: (
            {"attached_issue_id": "a"} if "intake_packets" in sql else
            {"issue_id": "a", "status": "canonical"} if "conclusion_revisions" in sql else
            None
        )
        self.store.rows.side_effect = lambda sql, _args: (
            [{"issue_id": "b"}] if "issue_evidence" in sql else []
        )
        for identity, domain in (("intake-v", "intake"), ("evidence-v", "evidence"), ("canonical", "conclusion")):
            if domain == "conclusion":
                source = json.dumps(["conclusion_version", "canonical"])
            else:
                source = json.dumps(["relation_version", identity])
            self.manager.context_relations.preview.return_value = {
                "before": {"source_key": source, "target_key": source}, "after": None
            }
            tier, reasons, _samples = self.policy._risk_context_relation(
                {"op": "context_relation"}, state, "T0"
            )
            self.assertEqual(tier, "T3" if domain == "conclusion" else "T1")
            self.assertIn("material-relation-change", reasons)

    def test_evidence_preview_rejection_boundaries_are_explicit(self) -> None:
        service = object.__new__(EvidenceService)
        service.store = Mock()
        service.manager = SimpleNamespace()

        with self.assertRaisesRegex(ValidationError, "requires a reason"):
            service.preview_source_migration("missing", "platform-a", reason=" ")
        service.store.row.side_effect = lambda sql, _args: (
            {"platform_id": "platform-a"} if "platform_sources" in sql else None
        )
        with self.assertRaisesRegex(Exception, "Evidence not found"):
            service.preview_source_migration("missing", "platform-a", reason="reviewed")

        state = Mock()
        state.context_rows.return_value = [{"ambiguity_id": "a", "state": "open", "evidence_id": "missing"}]
        state.evidence.return_value = None
        with self.assertRaisesRegex(Exception, "Evidence not found"):
            service.preview_identity_resolution(
                {"ambiguity_id": "a", "decision": "confirm_same_object", "rationale": "checked"},
                state_view=state,
            )
        state.evidence.return_value = {"evidence_id": "e", "kind": "external", "lifecycle_status": "active"}
        with self.assertRaisesRegex(ValidationError, "requires a rationale"):
            service.preview_identity_resolution(
                {"ambiguity_id": "a", "decision": "confirm_same_object", "rationale": " "},
                state_view=state,
            )
        state.has_current_evidence_use.return_value = True
        with self.assertRaisesRegex(ValidationError, "cannot be waived"):
            service.preview_identity_resolution(
                {"ambiguity_id": "a", "decision": "waive_migration_blocker", "rationale": "checked"},
                state_view=state,
            )
        state.has_current_evidence_use.return_value = False
        with self.assertRaisesRegex(ValidationError, "Unsupported identity ambiguity"):
            service.preview_identity_resolution(
                {"ambiguity_id": "a", "decision": "unsupported", "rationale": "checked"},
                state_view=state,
            )

        conflict_state = Mock()
        conflict_state.evidence.return_value = {"current_manifest_id": "manifest"}
        conflict_state.context_rows.side_effect = lambda table, _column, _value: (
            [{"source_platform_id": "platform-a"}] if table == "evidence_source_bindings" else []
        )
        service.store.row.side_effect = lambda _sql, _args: None
        with self.assertRaisesRegex(ValidationError, "current Manifest is missing"):
            service.preview_conflict_resolution(
                "e", accepted_attestation_ids=["att"], retained_attestation_ids=[],
                rejected_attestation_ids=[], rationale="checked", state_view=conflict_state,
            )
        service.store.row.side_effect = lambda _sql, _args: {"manifest_hash": "hash"}
        with self.assertRaisesRegex(ValidationError, "another Evidence"):
            conflict_state.context_rows.side_effect = lambda table, _column, _value: (
                [{"source_platform_id": "platform-a"}] if table == "evidence_source_bindings" else []
            )
            service.preview_conflict_resolution(
                "e", accepted_attestation_ids=["att"], retained_attestation_ids=[],
                rejected_attestation_ids=[], rationale="checked", state_view=conflict_state,
            )
        conflict_state.context_rows.side_effect = lambda table, _column, _value: (
            [{"source_platform_id": "platform-a"}] if table == "evidence_source_bindings" else
            [{"attestation_id": "att", "evidence_id": "e", "state": "accepted"}]
        )
        with self.assertRaisesRegex(ValidationError, "must include a conflict"):
            service.preview_conflict_resolution(
                "e", accepted_attestation_ids=["att"], retained_attestation_ids=[],
                rejected_attestation_ids=[], rationale="checked", state_view=conflict_state,
            )
        service.store.row.side_effect = None
        service.store.row.return_value = None
        with self.assertRaisesRegex(Exception, "Evidence not found"):
            service.recalculate(
                "missing", trigger_object_type="test", trigger_object_id="test",
                reason="coverage", auth=SimpleNamespace(actor_id="actor", run_id="run"),
            )


if __name__ == "__main__":
    unittest.main()
