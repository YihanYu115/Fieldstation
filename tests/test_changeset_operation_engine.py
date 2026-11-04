from __future__ import annotations

import itertools
import tempfile
import unittest
from pathlib import Path
from typing import Any

from context_fixtures import append_status_version

from issue_manager.changeset_engine import OPERATION_DEFINITIONS, operation_definition
from issue_manager.changeset_operations import CHANGESET_OPERATION_SPECS
from issue_manager.changeset_state import StateView
from issue_manager.errors import ConflictError, ValidationError
from issue_manager.risk import TIER_VALUE, NormalizedMutation, RiskPolicy
from issue_manager.scope_identity import SampleKey, ScopeKey
from issue_manager.service import IssueManager


class ChangeSetOperationEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = Path(self.temp.name) / "ledger"
        self.manager = IssueManager.initialize(self.ledger)
        self.field = self.manager.credentials.path_for("experiment-agent")
        self.organizer = self.manager.credentials.path_for("organizer-agent")
        self.reviewers = [
            self.manager.credentials.path_for("review-agent-1"),
            self.manager.credentials.path_for("review-agent-2"),
        ]
        self.manager.create_issue("sample-a", "investigation", scope={"sample": "A"})
        self.manager.create_issue("sample-b", "investigation", scope={"sample": "B"})

    def tearDown(self) -> None:
        self.manager.close()
        self.temp.cleanup()

    @staticmethod
    def _payload(operations: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "changeset_version": 1,
            "intent": "operation engine invariant",
            "operations": operations,
        }

    def _review(self, changeset_id: str, required: int) -> None:
        for index in range(required):
            credential = self.reviewers[index]
            self.manager.changesets.claim_review(changeset_id, credential=credential)
            self.manager.changesets.submit_review(
                changeset_id,
                decision="pass",
                rationale=f"Invariant review {index + 1}",
                credential=credential,
            )

    def _publish(self, issue_id: str, statement: str) -> dict[str, Any]:
        issue = self.manager.show_issue(issue_id)
        proposal = {
            "issue_id": issue_id,
            "expected_conclusion_revision": issue["conclusion_revision"],
            "status": "provisional",
            "statement": statement,
            "structured_outputs": {},
            "limitations": [],
            "evidence_refs": [],
            "basis": [],
        }
        created = self.manager.proposals.create(proposal, credential=self.organizer)
        self.manager.proposals.validate(created["proposal_id"], credential=self.organizer)
        return self.manager.proposals.apply(
            created["proposal_id"], credential=self.organizer
        )

    @staticmethod
    def _mutation(operation: str, **target: Any) -> NormalizedMutation:
        return NormalizedMutation(
            operation=operation,
            target=target,
            requested_state={},
            actor_id="operation-engine-test",
            run_id="operation-engine-run",
            source="test",
            request_id="operation-engine-request",
        )

    def test_registry_has_one_complete_contract_per_schema_operation(self) -> None:
        manifest = self.manager.changesets.operation_engine.contract_manifest()
        expected = set(CHANGESET_OPERATION_SPECS)
        self.assertEqual(set(manifest), expected)
        self.assertEqual(set(RiskPolicy.OPERATIONS), expected)
        self.assertEqual(set(OPERATION_DEFINITIONS), expected)
        applicability = manifest["evidence_applicability_decision"]
        self.assertEqual(applicability["validator"], "evidence_applicability_decision")
        self.assertEqual(applicability["risk_model"], "evidence_applicability_decision")
        self.assertEqual(applicability["simulator"], "evidence_applicability_decision")
        self.assertEqual(applicability["executor"], "evidence_applicability_decision")
        for op, contract in manifest.items():
            with self.subTest(op=op):
                self.assertTrue(contract["validator"])
                self.assertTrue(contract["risk_model"])
                self.assertTrue(contract["simulator"])
                self.assertTrue(contract["executor"])
                self.assertIn(contract["base_tier"], TIER_VALUE)

    def test_sample_and_scope_keys_cannot_be_conflated(self) -> None:
        design = {"sample": "NB24-A01", "natural_target": "design"}
        qubits = {"sample": "NB24-A01", "natural_target": "qubits"}
        self.assertEqual(SampleKey.from_scope(design), SampleKey.from_scope(qubits))
        self.assertNotEqual(ScopeKey.from_scope(design), ScopeKey.from_scope(qubits))
        self.assertNotEqual(SampleKey.from_scope(design), ScopeKey.from_scope(design))

        self.assertIsNone(SampleKey.from_raw(None))
        self.assertIsNone(SampleKey.from_raw(True))
        self.assertIsNone(SampleKey.from_raw({"sample": "A"}))
        self.assertIsNone(SampleKey.from_raw("---"))
        self.assertEqual(str(SampleKey.from_raw(7)), "7")
        self.assertIsNone(ScopeKey.from_scope(None))
        self.assertIsNone(ScopeKey.from_scope({}))
        self.assertIsNone(ScopeKey.from_scope({"sample": ["A", "B"], "flag": True}))
        self.assertEqual(str(ScopeKey.from_scope({"sample": ["A"]})), "a")
        self.assertEqual(
            str(ScopeKey.from_scope({"sample": "A", "target": "---", "run": 2})),
            "a/2",
        )

    def test_state_view_overlays_are_the_only_simulated_read_model(self) -> None:
        attached = self.manager.add_evidence(
            kind="external", locator="urn:engine:state-attached", issue_id="sample-a"
        )["evidence_id"]
        additional = self.manager.add_evidence(
            kind="external", locator="urn:engine:state-additional"
        )["evidence_id"]
        issue_relation = self.manager.add_relation(
            "sample-a", "sample-b", "related_to", impact_policy="soft"
        )
        evidence_relation = self.manager.evidence_relations.add(
            attached, additional, "supports"
        )
        question = self.manager.questions.create("sample-a", "Overlay status?")

        view = StateView(self.manager)
        self.assertEqual(str(view.scope_for_issue("sample-a")), "a")
        view.evidence_lifecycle[attached] = "void"
        self.assertEqual(view.evidence(attached)["lifecycle_status"], "void")

        view.evidence_attachment_removals.add(("sample-a", attached))
        self.assertFalse(view.is_evidence_attached("sample-a", attached))
        self.assertEqual(view.evidence_samples(attached), set())
        view.evidence_attachment_additions.add(("sample-b", additional))
        self.assertTrue(view.is_evidence_attached("sample-b", additional))
        self.assertEqual(
            {sample.value for sample in view.evidence_samples(additional)}, {"b"}
        )
        view.publication_status_additions[additional] = {"canonical"}
        self.assertEqual(view.evidence_publication_statuses(additional), {"canonical"})

        view.question_status[question["question_id"]] = "blocked"
        self.assertEqual(view.question(question["question_id"])["status"], "blocked")
        view.issue_relation_active[issue_relation["relation_id"]] = False
        view.issue_relation_impact[issue_relation["relation_id"]] = "hard"
        self.assertEqual(
            view.issue_relation(issue_relation["relation_id"])["impact_policy"], "hard"
        )
        self.assertFalse(view.issue_relation(issue_relation["relation_id"])["active"])
        view.evidence_relation_active[evidence_relation["relation_id"]] = False
        self.assertFalse(view.evidence_relation(evidence_relation["relation_id"])["active"])

        view.new_hard_issue_edges.add(("sample-a", "sample-b"))
        self.assertTrue(view.hard_issue_cycle("sample-b", "sample-a"))
        view.new_hard_evidence_edges.add((attached, additional))
        self.assertTrue(view.hard_evidence_cycle(additional, attached))

    def test_state_view_staged_applicability_ranges_and_cycle_exclusion(self) -> None:
        target = self.manager.add_evidence(
            kind="external", locator="urn:engine:state-applicability-target"
        )["evidence_id"]
        version = {
            "decision_version_id": "applicability:staged:1",
            "decision_key": "staged",
            "scope_issue_id": "sample-a",
            "target_evidence_id": target,
        }
        head = {
            "decision_key": "staged",
            "decision_version_id": "applicability:staged:1",
            "active": True,
        }
        view = StateView(self.manager)
        view.applicability_versions[version["decision_version_id"]] = version
        view.applicability_heads[head["decision_key"]] = head

        self.assertEqual(
            view.context_rows(
                "evidence_applicability_decision_versions", "scope_issue_id", "sample-a"
            ),
            [version],
        )
        self.assertEqual(
            view.context_rows(
                "evidence_applicability_decision_versions", "scope_issue_id", "sample-b"
            ),
            [],
        )
        self.assertEqual(
            view.context_rows("evidence_applicability_decision_heads", "decision_key", "staged"),
            [head],
        )

        self.assertFalse(StateView._has_path({"a": {"b"}, "b": {"a"}}, "a", "absent"))
        other = self.manager.add_evidence(
            kind="external", locator="urn:engine:state-applicability-other"
        )["evidence_id"]
        relation = self.manager.evidence_relations.add(
            target, other, "supports", impact_policy="hard"
        )
        self.assertFalse(view.hard_evidence_cycle(other, target, excluding=relation["relation_id"]))

    def test_context_risk_walk_is_cycle_safe_and_fails_on_missing_receipt_or_conclusion(self) -> None:
        import json
        from unittest.mock import patch

        policy = self.manager.changesets.risk_policy
        view = StateView(self.manager)
        conclusion = self._publish("sample-a", "Risk propagation fixture")
        conclusion_id = conclusion["conclusion_id"]
        policy._risk_material_consumers(set(), set(), view, "T0", "fixture")

        with patch.object(self.manager.context_maintenance, "validate_change"):
            with self.assertRaisesRegex(ValidationError, "Selected basis receipt does not exist"):
                policy._risk_context_change(
                    {
                        "action": "select",
                        "items": [{"conclusion_id": conclusion_id, "receipt_id": "missing"}],
                    },
                    view,
                    "T0",
                )
            with self.assertRaisesRegex(ValidationError, "Conclusion not found"):
                policy._risk_context_change(
                    {"action": "other", "items": [{"conclusion_id": "missing"}]},
                    view,
                    "T0",
                )

        missing_relation_key = json.dumps(["relation_version", "missing-version"])
        with patch.object(
            self.manager.context_relations,
            "preview",
            return_value={
                "before": {"source_key": missing_relation_key, "target_key": missing_relation_key},
                "after": None,
            },
        ):
            with self.assertRaisesRegex(ValidationError, "Missing material relationship version"):
                policy._risk_context_relation({}, view, "T0")

    def test_risk_edges_fail_closed_and_preserve_escalations(self) -> None:
        policy = self.manager.changesets.risk_policy
        view = StateView(self.manager)

        with self.assertRaisesRegex(ValidationError, "Unsupported normalized mutation"):
            policy.assess_mutation(self._mutation("unknown"))
        with self.assertRaisesRegex(ValidationError, "Relation not found"):
            policy.assess_mutation(self._mutation("relation.deactivate", relation_id="missing"))
        with self.assertRaisesRegex(ValidationError, "non-empty list"):
            policy.assess({"operations": []})
        with self.assertRaisesRegex(ValidationError, "must be an object"):
            policy.assess({"operations": ["not-an-operation"]})
        with self.assertRaisesRegex(ValidationError, "Unsupported ChangeSet operation"):
            operation_definition("unknown")

        missing_issue = policy.assess(
            {
                "operations": [
                    {"op": "attach_packet", "issue_id": "missing", "packet_id": "missing"}
                ]
            }
        )
        self.assertEqual(missing_issue.tier, "T1")

        canonical_evidence = self.manager.add_evidence(
            kind="external", locator="urn:engine:canonical-evidence"
        )["evidence_id"]
        view.publication_status_additions[canonical_evidence] = {"canonical"}
        maintenance, _ = policy.assess_operation(
            {"op": "void_evidence", "evidence_id": canonical_evidence, "reason": "invalid"},
            view,
        )
        self.assertEqual(maintenance.tier, "T3")
        self.assertIn("published-evidence-maintenance", maintenance.reasons)

        publication, samples = policy.assess_operation(
            {
                "op": "propose_conclusion",
                "status": "canonical",
                "basis": [
                    None,
                    {"issue_id": "missing"},
                    {"issue_id": "sample-a"},
                    {"issue_id": "sample-b"},
                ],
            },
            view,
        )
        self.assertEqual(publication.tier, "T3")
        self.assertIn("canonical-publication", publication.reasons)
        self.assertEqual({sample.value for sample in samples}, {"a", "b"})

        provider_missing, _ = policy.assess_operation(
            {
                "op": "add_relation",
                "consumer": "sample-a",
                "provider": "missing",
                "relation_type": "depends_on",
            },
            view,
        )
        self.assertEqual(provider_missing.tier, "T1")
        hard_provider_missing, _ = policy.assess_operation(
            {
                "op": "add_relation",
                "consumer": "sample-a",
                "provider": "missing",
                "relation_type": "depends_on",
                "impact_policy": "hard",
            },
            view,
        )
        self.assertEqual(hard_provider_missing.tier, "T3")

    def test_changeset_parent_and_error_history_invariants(self) -> None:
        payload = self._payload(
            [{"op": "append_work", "issue_id": "sample-a", "body": "Applied parent"}]
        )
        parent = self.manager.changesets.create(payload, credential=self.field)
        self.manager.changesets.validate(parent["changeset_id"], credential=self.field)
        self.manager.changesets.apply(parent["changeset_id"], credential=self.field)

        with self.assertRaisesRegex(ValidationError, "Parent ChangeSet does not exist"):
            self.manager.changesets.create(
                payload, credential=self.field, parent_changeset_id="missing"
            )
        with self.assertRaisesRegex(ConflictError, "cannot be replaced"):
            self.manager.changesets.create(
                payload,
                credential=self.field,
                parent_changeset_id=parent["changeset_id"],
            )

        draft = self.manager.changesets.create(payload, credential=self.field)
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE changesets SET last_error=? WHERE changeset_id=?",
                ("not-json", draft["changeset_id"]),
            )
        shown = self.manager.changesets.show(draft["changeset_id"])
        self.assertEqual(shown["last_error_details"]["code"], "operation_failed")

        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE changesets SET last_error=? WHERE changeset_id=?",
                ('"scalar"', draft["changeset_id"]),
            )
            conn.execute(
                "DELETE FROM changeset_risk_assessments WHERE changeset_id=?",
                (draft["changeset_id"],),
            )
        shown = self.manager.changesets.show(draft["changeset_id"])
        self.assertIsNone(shown["last_error_details"])
        with self.assertRaisesRegex(ConflictError, "no persisted risk assessment history"):
            self.manager.changesets._stored_risk_snapshot(shown)

    def test_preflight_reads_prior_operations_and_rejects_invalid_domain_state(self) -> None:
        engine = self.manager.changesets.operation_engine
        modeled = engine.preflight(
            [
                {
                    "op": "create_issue",
                    "issue_id": "virtual-parent",
                    "issue_type": "investigation",
                    "scope": {"sample": "A"},
                },
                {
                    "op": "create_issue",
                    "issue_id": "virtual-child",
                    "issue_type": "episode",
                    "parent_issue_id": "virtual-parent",
                    "scope": {"sample": "A"},
                },
            ]
        )
        self.assertEqual(
            modeled["state_view"].issue("virtual-child")["parent_issue_id"],
            "virtual-parent",
        )
        with self.assertRaisesRegex(ConflictError, "already exists in this ChangeSet"):
            engine.preflight(
                [
                    {
                        "op": "create_issue",
                        "issue_id": "duplicate-virtual",
                        "issue_type": "investigation",
                    },
                    {
                        "op": "create_issue",
                        "issue_id": "duplicate-virtual",
                        "issue_type": "investigation",
                    },
                ]
            )

        voided = self.manager.add_evidence(
            kind="external", locator="urn:engine:void-preflight"
        )["evidence_id"]
        self.manager.void_evidence(voided, actor="operation-engine-test", reason="invalid")
        invalid_evidence_operations = [
            {"op": "attach_evidence", "issue_id": "sample-a", "evidence_id": voided},
            {
                "op": "append_work",
                "issue_id": "sample-a",
                "body": "Must not reference void evidence",
                "evidence_refs": [voided],
            },
        ]
        for operation in invalid_evidence_operations:
            with self.subTest(operation=operation["op"]), self.assertRaises(ValidationError):
                engine.preflight([operation])

        with self.assertRaisesRegex(ValidationError, "non-empty alias"):
            engine.preflight([{"op": "add_alias", "issue_id": "sample-a", "alias": " "}])
        with self.assertRaisesRegex(ValidationError, "non-empty tag"):
            engine.preflight([{"op": "add_tag", "issue_id": "sample-a", "tag": " "}])

        ambiguity_evidence = self.manager.add_evidence(
            kind="external", locator="urn:engine:ambiguity"
        )["evidence_id"]
        with self.manager.store.transaction() as conn:
            for ambiguity_id, state in (("ambiguity-open", "open"), ("ambiguity-closed", "resolved")):
                conn.execute(
                    "INSERT INTO evidence_identity_ambiguities("
                    "ambiguity_id,evidence_id,ambiguity_type,candidate_json,state,rationale,"
                    "created_at,created_by,resolved_at,resolved_by,reviewed_changeset_id,"
                    "review_ids_json) VALUES (?,?,?,'{}',?,'',datetime('now'),?,"
                    "NULL,NULL,NULL,'[]')",
                    (
                        ambiguity_id,
                        ambiguity_evidence,
                        "multiple_raw_locators",
                        state,
                        "organizer-agent",
                    ),
                )
        ambiguity_cases = [
            (
                "closed",
                {
                    "op": "resolve_evidence_identity_ambiguity",
                    "ambiguity_id": "ambiguity-closed",
                    "decision": "confirm_same_object",
                    "rationale": "reviewed",
                },
            ),
            (
                "decision",
                {
                    "op": "resolve_evidence_identity_ambiguity",
                    "ambiguity_id": "ambiguity-open",
                    "decision": "guess",
                    "rationale": "reviewed",
                },
            ),
            (
                "rationale",
                {
                    "op": "resolve_evidence_identity_ambiguity",
                    "ambiguity_id": "ambiguity-open",
                    "decision": "confirm_same_object",
                    "rationale": " ",
                },
            ),
        ]
        for label, operation in ambiguity_cases:
            with self.subTest(ambiguity=label), self.assertRaises(
                (ConflictError, ValidationError)
            ):
                engine.preflight([operation])

        question_for_answer = self.manager.questions.create("sample-a", "Answer scope?")
        same_issue_conclusion = self._publish("sample-a", "same issue")
        other_issue_conclusion = self._publish("sample-b", "other issue")
        with self.assertRaisesRegex(ValidationError, "same Issue"):
            engine.preflight(
                [
                    {
                        "op": "answer_question",
                        "question_id": question_for_answer["question_id"],
                        "conclusion_id": other_issue_conclusion["conclusion_id"],
                    }
                ]
            )
        disputed_version = append_status_version(self.manager, same_issue_conclusion["conclusion_id"], "disputed")
        with self.assertRaisesRegex(ValidationError, "Withdrawn Conclusion"):
            engine.preflight(
                [
                    {
                        "op": "answer_question",
                        "question_id": question_for_answer["question_id"],
                        "conclusion_id": disputed_version,
                    }
                ]
            )

        relation = self.manager.add_relation(
            "sample-a", "sample-b", "related_to", impact_policy="soft"
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE relations SET impact_policy='hard' WHERE relation_id=?",
                (relation["relation_id"],),
            )
        with self.assertRaisesRegex(ValidationError, "would create a cycle"):
            engine.preflight(
                [
                    {
                        "op": "add_relation",
                        "consumer": "sample-b",
                        "provider": "sample-a",
                        "relation_type": "depends_on",
                        "impact_policy": "hard",
                    }
                ]
            )

        reverse_relation = self.manager.add_relation(
            "sample-b", "sample-a", "related_to", impact_policy="soft"
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE relations SET active=0,impact_policy='hard' WHERE relation_id=?",
                (reverse_relation["relation_id"],),
            )
        with self.assertRaisesRegex(ValidationError, "Reactivated hard Issue relation"):
            engine.preflight(
                [
                    {
                        "op": "reactivate_relation",
                        "relation_id": reverse_relation["relation_id"],
                        "reason": "unsafe",
                    }
                ]
            )

        question = self.manager.questions.create("sample-a", "Existing question")
        with self.assertRaisesRegex(ConflictError, "Question already exists"):
            engine.preflight(
                [
                    {
                        "op": "create_question",
                        "issue_id": "sample-a",
                        "question_id": question["question_id"],
                        "prompt": "Duplicate question",
                    }
                ]
            )

        consumer = self.manager.add_evidence(
            kind="external", locator="urn:engine:duplicate-consumer"
        )["evidence_id"]
        provider = self.manager.add_evidence(
            kind="external", locator="urn:engine:duplicate-provider"
        )["evidence_id"]
        self.manager.evidence_relations.add(consumer, provider, "supports")
        engine.preflight(
            [{"op": "add_evidence_relation", "consumer_evidence_id": consumer,
              "provider_evidence_id": provider, "relation_type": "supports"}]
        )

        hard_evidence_relation = self.manager.evidence_relations.add(
            consumer, provider, "depends_on"
        )
        reverse_evidence_relation = self.manager.evidence_relations.add(
            provider, consumer, "supports"
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE evidence_relations SET active=0,impact_policy='hard' WHERE relation_id=?",
                (reverse_evidence_relation["relation_id"],),
            )
        self.assertEqual(hard_evidence_relation["impact_policy"], "hard")
        with self.assertRaisesRegex(ValidationError, "Reactivated hard Evidence relation"):
            engine.preflight(
                [
                    {
                        "op": "reactivate_evidence_relation",
                        "relation_id": reverse_evidence_relation["relation_id"],
                        "reason": "unsafe",
                    }
                ]
            )

    def test_state_view_supports_sequential_question_and_lifecycle_operations(self) -> None:
        relation = self.manager.add_relation(
            "sample-a", "sample-b", "related_to", impact_policy="soft"
        )
        created = self.manager.changesets.create(
            self._payload(
                [
                    {
                        "op": "create_question",
                        "issue_id": "sample-a",
                        "question_id": "engine-question",
                        "prompt": "Can sequential state be observed?",
                    },
                    {
                        "op": "transition_question",
                        "question_id": "engine-question",
                        "action": "start",
                    },
                    {
                        "op": "transition_question",
                        "question_id": "engine-question",
                        "action": "block",
                        "reason": "Waiting for evidence",
                    },
                    {
                        "op": "deactivate_relation",
                        "relation_id": relation["relation_id"],
                        "reason": "Sequential lifecycle test",
                    },
                    {
                        "op": "reactivate_relation",
                        "relation_id": relation["relation_id"],
                        "reason": "Sequential lifecycle test",
                    },
                ]
            ),
            credential=self.field,
        )
        validated = self.manager.changesets.validate(created["changeset_id"], credential=self.field)
        question_states = [
            item["pre_state"]["question_status"]
            for item in validated["risk_trace"]
            if item["op"] == "transition_question"
        ]
        relation_states = [
            item["pre_state"]["relation_active"]
            for item in validated["risk_trace"]
            if item["op"] in {"deactivate_relation", "reactivate_relation"}
        ]
        self.assertEqual(question_states, ["open", "in_progress"])
        self.assertEqual(relation_states, [True, False])
        self._review(created["changeset_id"], validated["risk"]["required_reviews"])
        applied = self.manager.changesets.apply(created["changeset_id"], credential=self.field)
        self.assertEqual(applied["state"], "applied")
        self.assertEqual(self.manager.questions.show("engine-question")["status"], "blocked")
        self.assertTrue(
            self.manager.store.row(
                "SELECT active FROM relations WHERE relation_id=?",
                (relation["relation_id"],),
            )["active"]
        )

    def test_operation_permutations_never_exceed_preflight_risk(self) -> None:
        for case, ordering in enumerate(itertools.permutations(("attach", "relation", "work"))):
            with self.subTest(ordering=ordering):
                provider = self.manager.add_evidence(
                    kind="external",
                    locator=f"urn:engine:provider:{case}",
                    issue_id="sample-b",
                )["evidence_id"]
                consumer = self.manager.add_evidence(
                    kind="external", locator=f"urn:engine:consumer:{case}"
                )["evidence_id"]
                by_name = {
                    "attach": {
                        "op": "attach_evidence",
                        "issue_id": "sample-a",
                        "evidence_id": consumer,
                    },
                    "relation": {
                        "op": "add_evidence_relation",
                        "consumer_evidence_id": consumer,
                        "provider_evidence_id": provider,
                        "relation_type": "depends_on",
                    },
                    "work": {
                        "op": "append_work",
                        "issue_id": "sample-a",
                        "body": f"Permutation {case}",
                    },
                }
                created = self.manager.changesets.create(
                    self._payload([by_name[name] for name in ordering]),
                    credential=self.field,
                )
                validated = self.manager.changesets.validate(
                    created["changeset_id"], credential=self.field
                )
                self._review(created["changeset_id"], validated["risk"]["required_reviews"])
                applied = self.manager.changesets.apply(
                    created["changeset_id"], credential=self.field
                )
                reviewed_tier = TIER_VALUE[validated["risk"]["tier"]]
                runtime_risks = [
                    result["risk"]
                    for result in applied["results"]
                    if isinstance(result, dict) and "risk" in result
                ]
                self.assertTrue(
                    all(TIER_VALUE[risk["tier"]] <= reviewed_tier for risk in runtime_risks)
                )

    def test_fault_after_each_operation_leaves_no_partial_domain_writes(self) -> None:
        for fail_index in range(3):
            with self.subTest(fail_index=fail_index):
                provider = self.manager.add_evidence(
                    kind="external",
                    locator=f"urn:engine:fault-provider:{fail_index}",
                    issue_id="sample-b",
                )["evidence_id"]
                consumer = self.manager.add_evidence(
                    kind="external", locator=f"urn:engine:fault-consumer:{fail_index}"
                )["evidence_id"]
                before_revision = self.manager._issue("sample-a")["working_revision"]
                operations = [
                    {
                        "op": "attach_evidence",
                        "issue_id": "sample-a",
                        "evidence_id": consumer,
                    },
                    {
                        "op": "add_evidence_relation",
                        "consumer_evidence_id": consumer,
                        "provider_evidence_id": provider,
                        "relation_type": "depends_on",
                    },
                    {
                        "op": "append_work",
                        "issue_id": "sample-a",
                        "body": f"Fault boundary {fail_index}",
                    },
                ]
                created = self.manager.changesets.create(
                    self._payload(operations), credential=self.field
                )
                validated = self.manager.changesets.validate(
                    created["changeset_id"], credential=self.field
                )
                self._review(created["changeset_id"], validated["risk"]["required_reviews"])

                def fail(point: str) -> None:
                    if point == f"changeset.after_operation.{fail_index}":
                        raise RuntimeError("operation boundary fault")

                self.manager.store.fault_injector = fail
                try:
                    with self.assertRaisesRegex(RuntimeError, "operation boundary fault"):
                        self.manager.changesets.apply(
                            created["changeset_id"], credential=self.field
                        )
                finally:
                    self.manager.store.fault_injector = None

                self.assertFalse(
                    self.manager.store.row(
                        "SELECT 1 FROM issue_evidence WHERE issue_id='sample-a' AND evidence_id=?",
                        (consumer,),
                    )
                )
                self.assertFalse(
                    self.manager.store.row(
                        "SELECT 1 FROM evidence_relations WHERE consumer_evidence_id=? "
                        "AND provider_evidence_id=?",
                        (consumer, provider),
                    )
                )
                self.assertEqual(
                    self.manager._issue("sample-a")["working_revision"], before_revision
                )
                states = self.manager.store.rows(
                    "SELECT state FROM changeset_operations WHERE changeset_id=? ORDER BY ordinal",
                    (created["changeset_id"],),
                )
                self.assertEqual([row["state"] for row in states], ["pending"] * 3)


if __name__ == "__main__":
    unittest.main()
