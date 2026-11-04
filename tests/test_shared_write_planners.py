from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from issue_manager import IssueManager
from issue_manager.changeset_state import StateView
from issue_manager.errors import ConflictError, ValidationError
from issue_manager.evidence_planner import plan_create as plan_evidence_create
from issue_manager.evidence_planner import plan_maintenance
from issue_manager.intake_planner import plan_attach
from issue_manager.issue_relation_planner import plan_add, plan_impact, plan_lifecycle
from issue_manager.question_planner import plan_create as plan_question_create
from issue_manager.question_planner import plan_transition
from issue_manager.work_planner import plan_append


class SharedWritePlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.manager = IssueManager.initialize(Path(self.temporary.name) / "ledger")
        self.manager.create_issue("planner-a", "investigation", "A")
        self.manager.create_issue("planner-b", "investigation", "B")
        self.evidence = self.manager.add_evidence(
            kind="external", locator="urn:planner:active", issue_id="planner-a"
        )["evidence_id"]

    def tearDown(self) -> None:
        self.manager.close()
        self.temporary.cleanup()

    def test_relation_and_work_planners_cover_normalized_and_rejected_inputs(self) -> None:
        view = StateView(self.manager)
        relation = plan_add(
            view,
            {"consumer": "planner-a", "provider": "planner-b", "relation_type": "depends_on"},
        )
        self.assertEqual(relation["impact_policy"], "soft")
        with self.assertRaises(ValidationError):
            plan_add(view, {"consumer": "planner-a", "provider": "planner-a", "relation_type": "related_to"})
        with self.assertRaises(ValidationError):
            plan_add(view, {"consumer": "planner-a", "provider": "planner-b", "relation_type": "related_to", "impact_policy": "bad"})
        with self.assertRaises(ValidationError):
            plan_lifecycle(view, {"op": "deactivate_relation", "relation_id": "missing"})
        with self.assertRaises(ValidationError):
            plan_impact(view, {"relation_id": "missing", "impact_policy": "soft"})
        work = plan_append(view, {"issue_id": "planner-a", "body": "  note  ", "evidence_refs": [self.evidence, self.evidence]})
        self.assertEqual(work["evidence_refs"], [self.evidence])
        with self.assertRaises(ValidationError):
            plan_append(view, {"issue_id": "planner-a", "body": "x", "entry_type": "bad"})
        with self.assertRaises(ValidationError):
            plan_append(view, {"issue_id": "planner-a", "body": "", "entry_type": "note"})

    def test_evidence_question_and_intake_planners_share_boundaries(self) -> None:
        view = StateView(self.manager)
        evidence = plan_evidence_create(
            view, {"kind": "external", "locator": "urn:planner:new", "issue_id": "planner-a"}
        )
        self.assertEqual(evidence["identity_namespace"], "legacy")
        with self.assertRaises(ValidationError):
            plan_evidence_create(view, {"kind": "wrong", "locator": "urn:planner:bad"})
        with self.assertRaises(ValidationError):
            plan_evidence_create(view, {"kind": "external", "locator": "urn:planner:bad", "quality_status": "bad"})
        with self.assertRaises(ValidationError):
            plan_evidence_create(view, {"kind": "datavault_dataset", "locator": "missing-dataset"})
        maintenance = plan_maintenance(
            view, {"op": "reassess_evidence", "evidence_id": self.evidence, "quality_status": "usable"}
        )
        self.assertEqual(maintenance["stored_quality_status"], "usable")
        with self.assertRaises(ValidationError):
            plan_maintenance(view, {"op": "detach_evidence", "evidence_id": self.evidence, "issue_id": "planner-b"})
        question = plan_question_create(
            view, {"issue_id": "planner-a", "prompt": "What changed?", "question_key": "planner-q"}
        )
        self.assertEqual(question["question_kind"], "experiment")
        created_question = self.manager.questions.create("planner-a", "Existing", question_key="existing")
        with self.assertRaises(ConflictError):
            plan_question_create(view, {"issue_id": "planner-a", "prompt": "Duplicate", "question_key": "existing"})
        with self.assertRaises(ValidationError):
            plan_transition(view, {"question_id": created_question["question_id"], "action": "block"})
        with self.assertRaises(ValidationError):
            plan_attach(view, {"packet_id": "missing", "issue_id": "planner-a"})


if __name__ == "__main__":
    unittest.main()
