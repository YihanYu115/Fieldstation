from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from context_fixtures import append_status_version, apply_reviewed_changeset

from issue_manager import IssueManager
from issue_manager.errors import ConflictError, NotFoundError, PermissionError, ValidationError
from issue_manager.operation_registry import OperationRegistry, OperationSpec
from issue_manager.registry_service import _validate_v14_template
from issue_manager.rollup_service import RollupService
from issue_manager.security import AuthContext
from issue_manager.store import canonical_json


class V090QualityEdges(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = Path(self.temp.name)
        self.manager = IssueManager.initialize(self.ledger)
        self.organizer = self.manager.credentials.path_for("organizer-agent")
        self.manager.create_issue(
            "root", "sample", "Root", scope={"sample": "sample-a"}
        )

    def tearDown(self) -> None:
        self.manager.close()
        self.temp.cleanup()

    def evidence(self, name: str, issue_id: str = "root") -> str:
        return self.manager.add_evidence(
            kind="external",
            locator=f"urn:v090-quality:{name}",
            issue_id=issue_id,
        )["evidence_id"]

    def publish(self, issue_id: str, statement: str) -> dict:
        prepared = self.manager.prepare_refresh(issue_id)
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
            "basis_snapshot_token": prepared["proposal_template"]["basis_snapshot_token"],
        }
        created = self.manager.proposals.create(proposal, credential=self.organizer)
        self.manager.proposals.validate(created["proposal_id"], credential=self.organizer)
        return self.manager.proposals.apply(
            created["proposal_id"], credential=self.organizer
        )

    def set_rollup(self, issue_id: str, policy: dict) -> None:
        normalized = RollupService.normalize_policy(policy)
        encoded = canonical_json(normalized)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE issue_rollup_policies SET mode=?,policy_json=?,policy_hash=? "
                "WHERE issue_id=?",
                (normalized["mode"], encoded, digest, issue_id),
            )

    def test_rollup_preflight_tracks_new_and_removed_provider_members(self) -> None:
        self.manager.create_issue("provider", "investigation")
        self.set_rollup("root", {"mode": "explicit_providers", "accepted_conclusion_statuses": ["provisional"],
                                 "allow_stale_providers": True, "missing_provider_action": "block"})
        proposal = self.manager.prepare_refresh("root")["proposal_template"]
        proposal.pop("basis_snapshot_token")
        proposal.update(statement="Summary", evidence_refs=[])
        publication = {"op": "propose_conclusion", "proposal": proposal}
        add = {"op": "add_relation", "consumer": "root", "provider": "provider", "relation_type": "depends_on", "impact_policy": "soft"}
        created = self.manager.changesets.create({"changeset_version": 1, "intent": "Add incomplete provider",
                                                  "operations": [add, publication]}, credential=self.organizer)
        with self.assertRaises(ConflictError) as raised:
            self.manager.changesets.validate(created["changeset_id"], credential=self.organizer)
        self.assertIn("frozen Rollup Policy", str(raised.exception))
        relation = self.manager.add_relation("root", "provider", "depends_on", impact_policy="soft")
        apply_reviewed_changeset(self.manager, self.organizer, [
            {"op": "deactivate_relation", "relation_id": relation["relation_id"], "reason": "Remove incomplete provider"}, publication])
        self.assertEqual(self.manager.show_issue("root")["current_conclusion"]["statement"], "Summary")

    def test_question_completion_gate_observes_answer_and_reopen_preflight(self) -> None:
        answer = self.publish("root", "Answer")
        question = self.manager.questions.create("root", "Required question", question_key="required")
        self.set_rollup("root", {"mode": "local_only", "question_completion": "all"})
        proposal = self.manager.prepare_refresh("root")["proposal_template"]
        proposal.pop("basis_snapshot_token")
        proposal.update(statement="Summary after answer", evidence_refs=[])
        publication = {"op": "propose_conclusion", "proposal": proposal}
        apply_reviewed_changeset(self.manager, self.organizer, [
            {"op": "answer_question", "question_id": question["question_id"], "conclusion_id": answer["conclusion_id"]}, publication])
        proposal["expected_conclusion_revision"] = self.manager.show_issue("root")["conclusion_revision"]
        created = self.manager.changesets.create({"changeset_version": 1, "intent": "Reopen before publication",
                                                  "operations": [{"op": "transition_question", "question_id": question["question_id"],
                                                                  "action": "reopen", "reason": "More work"}, publication]}, credential=self.organizer)
        with self.assertRaisesRegex(ConflictError, "required_question_unanswered"):
            self.manager.changesets.validate(created["changeset_id"], credential=self.organizer)

    def test_child_rollup_gate_observes_prior_candidate_publication(self) -> None:
        self.manager.create_issue("child", "investigation", parent_issue_id="root")
        self.set_rollup("root", {"mode": "direct_children", "accepted_conclusion_statuses": ["provisional"],
                                 "allow_stale_providers": True, "missing_provider_action": "block"})
        root = self.manager.prepare_refresh("root")["proposal_template"]
        root.pop("basis_snapshot_token")
        root.update(statement="Child summary", evidence_refs=[])
        child = self.manager.prepare_refresh("child")["proposal_template"]
        child.update(statement="Child candidate", evidence_refs=[])
        created = self.manager.changesets.create({"changeset_version": 1, "intent": "Missing child",
                                                  "operations": [{"op": "propose_conclusion", "proposal": root}]}, credential=self.organizer)
        with self.assertRaises(ConflictError):
            self.manager.changesets.validate(created["changeset_id"], credential=self.organizer)
        apply_reviewed_changeset(self.manager, self.organizer, [
            {"op": "propose_conclusion", "proposal": child}, {"op": "propose_conclusion", "proposal": root}])
        self.assertEqual(self.manager.rollup.preview("root")["providers"][0]["conclusion_revision"], 1)

    def test_question_validation_edit_lifecycle_answer_and_links(self) -> None:
        for kwargs in (
            {"prompt": ""},
            {"prompt": "x", "question_kind": "unknown"},
            {"prompt": "x", "priority": True},
            {"prompt": "x", "priority": 101},
            {"prompt": "x", "expected_evidence": {}},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValidationError):
                self.manager.questions.create("root", **kwargs)  # type: ignore[arg-type]

        question = self.manager.questions.create(
            "root",
            " Original? ",
            question_key="q-key",
            question_kind="analysis",
            priority=70,
            expected_evidence=[{"kind": "external"}],
            idempotency_key="question-create",
        )
        replay = self.manager.questions.create(
            "root",
            " Original? ",
            question_key="q-key",
            question_kind="analysis",
            priority=70,
            expected_evidence=[{"kind": "external"}],
            idempotency_key="question-create",
        )
        self.assertTrue(replay["idempotent_replay"])
        with self.assertRaises(ConflictError):
            self.manager.questions.create("root", "duplicate", question_key="q-key")
        with self.assertRaises(NotFoundError):
            self.manager.questions.show("missing-question")
        with self.assertRaises(ValidationError):
            self.manager.questions.list("root", statuses=("bad",))
        with self.assertRaises(ValidationError):
            self.manager.questions.list("root", question_kind="bad")
        self.assertEqual(
            len(
                self.manager.questions.list(
                    "root",
                    statuses=("open",),
                    question_kind="analysis",
                    minimum_priority=50,
                )
            ),
            1,
        )

        edited = self.manager.questions.edit(
            question["question_id"],
            prompt=" Revised? ",
            motivation=" why ",
            priority=80,
            expected_evidence=[{"role": "support"}],
            reason="clarified",
        )
        self.assertEqual(edited["prompt"], "Revised?")
        for kwargs in ({"prompt": " "}, {"priority": -1}, {"expected_evidence": {}}):
            with self.subTest(edit=kwargs), self.assertRaises(ValidationError):
                self.manager.questions.edit(question["question_id"], **kwargs)  # type: ignore[arg-type]

        started = self.manager.questions.start(question["question_id"], actor="organizer-agent")
        self.assertTrue(
            self.manager.questions.start(
                question["question_id"], actor="organizer-agent"
            )["existing"]
        )
        self.assertEqual(started["status"], "in_progress")
        with self.assertRaises(ValidationError):
            self.manager.questions.block(question["question_id"], actor="organizer-agent", reason="")
        self.manager.questions.block(
            question["question_id"], actor="organizer-agent", reason="waiting"
        )
        self.manager.questions.defer(
            question["question_id"], actor="organizer-agent", reason="later"
        )
        self.manager.questions.cancel(
            question["question_id"], actor="organizer-agent", reason="obsolete"
        )
        with self.assertRaises(ConflictError):
            self.manager.questions.start(question["question_id"], actor="organizer-agent")
        with self.assertRaises(ValidationError):
            self.manager.questions.reopen(
                question["question_id"], actor="organizer-agent", reason=""
            )
        self.manager.questions.reopen(
            question["question_id"], actor="organizer-agent", reason="needed again"
        )
        with self.assertRaises(ValidationError):
            self.manager.questions._transition(
                question["question_id"],
                "bad",
                event_type="bad",
                actor="organizer-agent",
                reason="",
            )
        with self.assertRaises(ValidationError):
            self.manager.questions._transition(
                question["question_id"],
                "answered",
                event_type="answer",
                actor="organizer-agent",
                reason="",
            )

        evidence_id = self.evidence("question")
        with self.assertRaises(ValidationError):
            self.manager.questions.attach_evidence(
                question["question_id"], evidence_id, link_type="bad"
            )
        with self.assertRaises(NotFoundError):
            self.manager.questions.attach_evidence(question["question_id"], "missing")
        self.manager.questions.attach_evidence(
            question["question_id"], evidence_id, link_type="supports", rationale="useful"
        )
        duplicate = self.manager.questions.attach_evidence(
            question["question_id"], evidence_id, link_type="supports"
        )
        self.assertFalse(duplicate["existing"])
        self.assertTrue(duplicate["relation_id"])
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE issue_question_evidence_links SET active=0 WHERE question_id=?",
                (question["question_id"],),
            )
        self.manager.questions.attach_evidence(
            question["question_id"], evidence_id, link_type="supports", rationale="restore"
        )

        with self.assertRaises(NotFoundError):
            self.manager.questions.answer(
                question["question_id"], "missing", actor="organizer-agent"
            )
        self.manager.create_issue("other", "investigation")
        other_conclusion = self.publish("other", "other answer")
        with self.assertRaises(ValidationError):
            self.manager.questions.answer(
                question["question_id"],
                other_conclusion["conclusion_id"],
                actor="organizer-agent",
            )
        conclusion = self.publish("root", "first answer")
        answered = self.manager.questions.answer(
            question["question_id"], conclusion["conclusion_id"], actor="organizer-agent"
        )
        self.assertEqual(answered["answer_freshness"], "fresh")
        self.assertTrue(
            self.manager.questions.answer(
                question["question_id"], conclusion["conclusion_id"], actor="organizer-agent"
            )["existing"]
        )
        self.publish("root", "second answer")
        self.assertEqual(
            self.manager.questions.show(question["question_id"])["answer_freshness"],
            "stale",
        )
        self.assertEqual(
            self.manager.questions._answer_freshness(
                {"answer_conclusion_id": "missing-conclusion"}
            ),
            "missing",
        )
        disputed_version = append_status_version(self.manager, conclusion["conclusion_id"], "disputed")
        self.manager.questions.reopen(
            question["question_id"], actor="organizer-agent", reason="challenge"
        )
        with self.assertRaises(ValidationError):
            self.manager.questions.answer(
                question["question_id"], disputed_version, actor="organizer-agent"
            )

    def test_evidence_relation_validation_lifecycle_filters_and_propagation(self) -> None:
        self.manager.create_issue(
            "other", "investigation", scope={"sample": "sample-b"}
        )
        provider = self.evidence("provider")
        consumer = self.evidence("consumer")
        cross = self.evidence("cross", "other")
        for call in (
            lambda: self.manager.evidence_relations.assess_add(consumer, provider, "bad"),
            lambda: self.manager.evidence_relations.assess_add(
                consumer, provider, "supports", impact_policy="bad"
            ),
            lambda: self.manager.evidence_relations.assess_add(
                consumer, "missing", "supports"
            ),
            lambda: self.manager.evidence_relations.add(consumer, consumer, "supports"),
            lambda: self.manager.evidence_relations.add(consumer, provider, "bad"),
            lambda: self.manager.evidence_relations.add(
                consumer, provider, "supports", impact_policy="bad"
            ),
        ):
            with self.subTest(call=call), self.assertRaises((ValidationError, NotFoundError)):
                call()

        self.assertEqual(
            self.manager.evidence_relations.assess_add(cross, provider, "supports")["tier"],
            "T3",
        )
        relation = self.manager.evidence_relations.add(
            consumer,
            provider,
            "supports",
            impact_policy="informational",
            rationale="support",
            idempotency_key="support-relation",
        )
        self.assertEqual(relation["impact_policy"], "soft")
        self.assertTrue(
            self.manager.evidence_relations.add(
                consumer, provider, "supports", impact_policy="informational", rationale="support",
                idempotency_key="support-relation",
            )["idempotent_replay"]
        )
        with self.assertRaises(ConflictError):
            self.manager.evidence_relations.add(
                consumer, provider, "supports", impact_policy="hard", idempotency_key="support-relation"
            )
        self.assertEqual(
            self.manager.evidence_relations.validate_change(relation["relation_id"])["relation_id"],
            relation["relation_id"],
        )
        for kwargs in (
            {"evidence_id": provider},
            {"provider_evidence_id": provider},
            {"consumer_evidence_id": consumer},
            {"active_only": False},
        ):
            self.assertTrue(self.manager.evidence_relations.list(**kwargs))
        with self.assertRaises(ValidationError):
            self.manager.evidence_relations.deactivate(
                relation["relation_id"], actor="organizer-agent", reason=""
            )
        deactivated = self.manager.evidence_relations.deactivate(
            relation["relation_id"], actor="organizer-agent", reason="not independent"
        )
        self.assertFalse(deactivated["active"])
        self.assertTrue(
            self.manager.evidence_relations.deactivate(
                relation["relation_id"], actor="organizer-agent", reason="again"
            )["existing"]
        )
        independent = self.manager.evidence_relations.add(consumer, provider, "supports")
        self.assertNotEqual(independent["relation_id"], relation["relation_id"])
        self.manager.evidence_relations.deactivate(
            independent["relation_id"], actor="organizer-agent", reason="independent contribution withdrawn"
        )
        reactivated = self.manager.evidence_relations.reactivate(
            relation["relation_id"], actor="organizer-agent", reason="restored"
        )
        self.assertTrue(reactivated["active"])
        self.assertTrue(
            self.manager.evidence_relations.reactivate(
                relation["relation_id"], actor="organizer-agent", reason="again"
            )["existing"]
        )

        downstream = self.evidence("downstream")
        hard = self.manager.evidence_relations.add(downstream, consumer, "derived_from")
        impacts = self.manager.evidence_relations.propagate_change(
            consumer, source_event_type="quality", source_event_id="evt"
        )
        self.assertTrue(any(item["relation_id"] == hard["relation_id"] for item in impacts))
        self.assertTrue(self.manager.evidence_relations.impacts(evidence_id=provider))
        self.assertTrue(
            self.manager.evidence_relations.impacts(relation_id=relation["relation_id"])
        )
        with self.assertRaises(ValidationError):
            self.manager.evidence_relations.impacts(limit=0)
        with self.assertRaises(ValidationError):
            self.manager.evidence_relations.propagate_change(
                provider, source_event_type="quality", maximum_nodes=0
            )
        self.assertEqual(
            self.manager.evidence_relations._path({"a": ["b"]}, "a", "z"), None
        )

    def test_rollup_policy_validation_preview_and_publication_gates(self) -> None:
        invalid = [
            None,
            {"unknown": 1},
            {"mode": "manual_explicit"},
            {"relation_types": "bad"},
            {"relation_types": ["bad"]},
            {"accepted_conclusion_statuses": "bad"},
            {"accepted_conclusion_statuses": ["bad"]},
            {"maximum_depth": True},
            {"maximum_depth": 21},
            {"missing_provider_action": "bad"},
            {"question_completion": "bad"},
            {"required_providers": "bad"},
            {"optional_providers": [1]},
            {"required_question_keys": [1]},
        ]
        for policy in invalid:
            with self.subTest(policy=policy), self.assertRaises(ValidationError):
                RollupService.normalize_policy(policy)  # type: ignore[arg-type]

        self.manager.create_issue(
            "provider", "investigation", scope={"sample": "sample-b"}
        )
        self.manager.create_issue("child", "investigation", parent_issue_id="root")
        self.manager.create_issue("grandchild", "episode", parent_issue_id="child")
        self.manager.add_relation(
            "root", "provider", "depends_on", impact_policy="hard"
        )
        self.set_rollup(
            "root",
            {
                "mode": "explicit_providers",
                "accepted_conclusion_statuses": ["accepted", "canonical"],
                "allow_stale_providers": False,
                "missing_provider_action": "block",
                "cross_sample_allowed": False,
            },
        )
        preview = self.manager.rollup.preview("root")
        self.assertIn("missing_current_conclusion", preview["blockers"][0]["reasons"])
        provider_conclusion = self.publish("provider", "provider answer")
        preview = self.manager.rollup.preview("root")
        reasons = preview["blockers"][0]["reasons"]
        self.assertIn("conclusion_status_not_accepted", reasons)
        self.assertIn("cross_sample_provider_not_allowed", reasons)

        self.set_rollup(
            "root",
            {
                "mode": "explicit_providers",
                "required_providers": [],
                "optional_providers": ["provider"],
                "accepted_conclusion_statuses": ["provisional"],
                "allow_stale_providers": True,
                "missing_provider_action": "warn",
                "cross_sample_allowed": True,
            },
        )
        self.assertEqual(
            self.manager.rollup.preview("root")["basis"][0]["conclusion_id"],
            provider_conclusion["conclusion_id"],
        )
        self.set_rollup(
            "root",
            {
                "mode": "direct_children",
                "accepted_conclusion_statuses": ["provisional"],
                "missing_provider_action": "warn",
            },
        )
        self.assertEqual(self.manager.rollup.preview("root")["providers"][0]["issue_id"], "child")
        self.set_rollup(
            "root",
            {
                "mode": "subtree_conclusions",
                "maximum_depth": 2,
                "accepted_conclusion_statuses": ["provisional"],
                "missing_provider_action": "warn",
            },
        )
        subtree_ids = {item["issue_id"] for item in self.manager.rollup.preview("root")["providers"]}
        self.assertEqual(subtree_ids, {"child", "grandchild"})
        self.set_rollup("root", {"mode": "local_only"})
        self.assertEqual(self.manager.rollup.preview("root")["providers"], [])

        self.manager.questions.create("root", "Required?", question_key="required")
        self.set_rollup(
            "root",
            {
                "mode": "local_only",
                "required_question_keys": ["required"],
                "question_completion": "required_only",
            },
        )
        proposal = {
            "basis": [
                {
                    "issue_id": "provider",
                    "conclusion_id": provider_conclusion["conclusion_id"],
                    "conclusion_revision": 1,
                }
            ],
            "evidence_refs": [],
        }
        gate = self.manager.rollup.publication_gate("root", proposal)
        self.assertIn("required_question_unanswered", {item["code"] for item in gate["blockers"]})
        with self.assertRaises(ConflictError):
            self.manager.rollup.require_publication_allowed("root", proposal)
        missing_basis = self.manager.rollup.publication_gate(
            "root", {"basis": [], "evidence_refs": []}
        )
        self.assertIn(
            "hard_provider_missing_from_basis",
            {item["code"] for item in missing_basis["blockers"]},
        )
        with self.manager.store.transaction() as conn:
            conn.execute("UPDATE issues SET freshness='stale' WHERE issue_id='provider'")
        stale_gate = self.manager.rollup.publication_gate("root", proposal)
        self.assertIn("hard_provider_not_fresh", {item["code"] for item in stale_gate["blockers"]})
        with self.manager.store.transaction() as conn:
            conn.execute("UPDATE issues SET freshness='fresh' WHERE issue_id='provider'")

        evidence_provider = self.evidence("rollup-provider")
        evidence_consumer = self.evidence("rollup-consumer")
        self.manager.evidence_relations.add(
            evidence_consumer, evidence_provider, "depends_on"
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE evidence_refs SET lifecycle_status='void' WHERE evidence_id=?",
                (evidence_provider,),
            )
        proposal["evidence_refs"] = [evidence_consumer]
        blockers = self.manager.rollup.publication_gate("root", proposal)["blockers"]
        self.assertIn("unresolved_hard_evidence_dependency", {item["code"] for item in blockers})

        current = self.manager.issue_semantic_snapshot(self.manager.show_issue("root"))
        with self.manager.store.transaction() as conn:
            conn.execute("DELETE FROM issue_rollup_policies WHERE issue_id='root'")
        self.assertEqual(
            self.manager.rollup.ensure_snapshot("root", current, actor="organizer-agent")["issue_id"],
            "root",
        )
        self.assertEqual(
            self.manager.rollup.ensure_snapshot("root", current, actor="organizer-agent")["issue_id"],
            "root",
        )
        with self.assertRaises(ConflictError):
            self.manager.rollup.ensure_snapshot(
                "root",
                {"definition": {"rollup_policy": {"mode": "direct_children"}}},
                actor="organizer-agent",
            )
        with self.manager.store.transaction() as conn:
            conn.execute("DELETE FROM issue_rollup_policies WHERE issue_id='grandchild'")
        with self.assertRaises(NotFoundError):
            self.manager.rollup.show_policy("grandchild")

    def test_repositories_uow_operation_registry_guidance_and_service_boundaries(self) -> None:
        with self.manager.uow.transaction() as conn:
            self.assertEqual(
                self.manager.repositories["issues"].require("root", conn=conn)["issue_id"],
                "root",
            )
            self.assertIsNone(self.manager.repositories["issues"].get("missing", conn=conn))
        with self.assertRaises(NotFoundError):
            self.manager.repositories["issues"].require("missing")
        self.manager.issues.create("child", "investigation", parent_issue_id="root")
        self.assertEqual(self.manager.issues.show("child")["issue_id"], "child")
        self.assertTrue(self.manager.issues.tree("root"))
        self.assertIsInstance(self.manager.issues.history("root"), dict)

        relation = self.manager.relations.add(
            "root", "child", "related_to", impact_policy="soft"
        )
        self.assertTrue(self.manager.repositories["issues"].list_active_providers("root"))
        self.assertTrue(self.manager.repositories["relations"].list_for_issue("root"))
        self.assertIsInstance(self.manager.relations.trace("root"), dict)
        self.assertIsInstance(self.manager.relations.impact("child"), dict)
        self.manager.relations.deactivate(
            relation["relation_id"], actor="organizer-agent", reason="test"
        )
        self.manager.relations.reactivate(
            relation["relation_id"], actor="organizer-agent", reason="test"
        )
        self.manager.relations.set_impact(
            relation["relation_id"], "notify", actor="organizer-agent", reason="test"
        )

        conclusion = self.publish("child", "child answer")
        self.assertEqual(
            self.manager.repositories["conclusions"].get(conclusion["conclusion_id"])["issue_id"],
            "child",
        )
        self.assertEqual(
            self.manager.repositories["conclusions"].current_for_issue("child")["conclusion_id"],
            conclusion["conclusion_id"],
        )
        self.assertIsNone(self.manager.repositories["conclusions"].get("missing"))
        self.assertIsNone(self.manager.repositories["conclusions"].current_for_issue("root"))
        self.assertEqual(
            self.manager.conclusions.current("child")["conclusion_id"],
            conclusion["conclusion_id"],
        )
        self.assertEqual(self.manager.conclusions.rollup_preview("child")["issue_id"], "child")
        with self.assertRaises(PermissionError):
            self.manager.conclusions.publish({})
        with self.assertRaises(ValidationError):
            self.manager.conclusions.change_status(
                "root", "disputed", expected_revision=0, actor="organizer-agent", reason="test"
            )
        with self.assertRaises(ValidationError):
            self.manager.conclusions.validate({})

        question = self.manager.questions.create("root", "Repository question", priority=60)
        self.assertEqual(
            self.manager.repositories["questions"].require(question["question_id"])["question_id"],
            question["question_id"],
        )
        with self.manager.store.transaction() as conn:
            self.assertEqual(
                self.manager.repositories["questions"].get(question["question_id"], conn=conn)[
                    "question_id"
                ],
                question["question_id"],
            )
        with self.assertRaises(NotFoundError):
            self.manager.repositories["questions"].require("missing")

        evidence_a = self.evidence("repo-a")
        evidence_b = self.evidence("repo-b")
        evidence_relation = self.manager.evidence_relations.add(
            evidence_a, evidence_b, "duplicates"
        )
        self.assertEqual(
            self.manager.repositories["evidence_relations"].require(
                evidence_relation["relation_id"]
            )["relation_id"],
            evidence_relation["relation_id"],
        )
        with self.manager.store.transaction() as conn:
            self.assertIsNotNone(
                self.manager.repositories["evidence_relations"].get(
                    evidence_relation["relation_id"], conn=conn
                )
            )
        with self.assertRaises(NotFoundError):
            self.manager.repositories["evidence_relations"].require("missing")
        self.assertEqual(self.manager.repositories["context"].legacy_candidates("root"), [])
        self.assertIsInstance(self.manager.repositories["context"].relation_impacts("root"), list)

        self.assertIsInstance(self.manager.context_service.get("root", "investigate"), dict)
        self.assertIsInstance(self.manager.context_service.guidance("root"), dict)
        self.assertIsInstance(self.manager.freshness_service.recompute(), dict)
        self.assertIsInstance(self.manager.freshness_service.stale(), list)
        self.assertIsInstance(self.manager.freshness_service.why_stale("root"), dict)
        self.assertIsInstance(self.manager.freshness_service.plan("root"), dict)
        self.assertIsInstance(self.manager.freshness_service.prepare("root"), dict)

        auth = self.manager.credentials.resolve(self.organizer)
        guide = self.manager.operations.guide("issue.show/v1", auth=auth)
        self.assertTrue(guide["available"])
        unavailable = self.manager.operations.guide(
            "question.create/v1",
            auth=AuthContext("reader", "human", "run", frozenset(), frozenset()),
        )
        self.assertFalse(unavailable["available"])
        with self.assertRaises(NotFoundError):
            self.manager.operations.get("missing")
        with self.assertRaises(ValidationError):
            self.manager.operations.dispatch(
                "issue.show/v1", self.manager.operation_handler, {}, auth=auth
            )
        dispatched = self.manager.operations.dispatch(
            "issue.show/v1",
            self.manager.operation_handler,
            {"issue_id": "root"},
            auth=auth,
        )
        self.assertEqual(dispatched["issue_id"], "root")

        registry = OperationRegistry()
        base = dict(
            operation_id="x/v1",
            path_template="/x",
            required_capability="context.read",
            request_schema_version="x/v1",
            response_schema_version="x/v1",
            risk_classifier="T0",
            handler="show_issue",
            visibility_policy="issue",
        )
        for spec in (
            OperationSpec(method="TRACE", write=False, idempotency_required=False, **base),
            OperationSpec(method="GET", write=True, idempotency_required=True, **base),
            OperationSpec(method="POST", write=True, idempotency_required=False, **base),
        ):
            with self.subTest(spec=spec), self.assertRaises(ValidationError):
                registry.register(spec)
        valid = OperationSpec(method="GET", write=False, idempotency_required=False, **base)
        registry.register(valid)
        with self.assertRaises(ValidationError):
            registry.register(valid)

        template = self.manager.guidance.evidence_intake_template("root")
        self.assertTrue(template["registration_id"])
        invalid = self.manager.guidance.validate_evidence_intake(
            "root",
            {"related_evidence": [{"relation_type": "bad"}]},
        )
        self.assertFalse(invalid["valid"])
        self.assertTrue(self.manager.guidance._pointer_present({"x": 1}, "x"))
        self.assertFalse(self.manager.guidance._pointer_present({}, "/x"))
        self.assertTrue(
            self.manager.guidance._pointer_present({"a": {"b/c": 1}}, "/a/b~1c")
        )
        invalid_array = self.manager.guidance.validate_evidence_intake(
            "root", {"kind": "external", "locator": "urn:x", "related_evidence": {}}
        )
        self.assertFalse(invalid_array["valid"])
        with self.assertRaises(ValidationError):
            self.manager.guidance.get("root", intent="")
        self.assertIsNotNone(
            self.manager.guidance._template(
                "evidence_intake_template",
                {"evidence_intake_template": "missing/template@1.0.0"},
            )
        )
        with self.manager.store.transaction() as conn:
            conn.execute(
                "UPDATE registry_entries SET state='disabled' "
                "WHERE kind='evidence_intake_template'"
            )
        try:
            self.assertIsNone(
                self.manager.guidance._template("evidence_intake_template", {})
            )
            with self.assertRaises(ValidationError):
                self.manager.guidance.evidence_intake_template("root")
        finally:
            with self.manager.store.transaction() as conn:
                conn.execute(
                    "UPDATE registry_entries SET state='active' "
                    "WHERE kind='evidence_intake_template'"
                )

        self.manager.relations.deactivate(
            relation["relation_id"], actor="organizer-agent", reason="archive child"
        )
        self.manager.issues.archive("child", actor="organizer-agent", reason="done")

    def test_risk_policy_covers_question_and_evidence_relation_operations(self) -> None:
        question = self.manager.questions.create("root", "Risk question")
        conclusion = self.publish("root", "risk answer")
        provider = self.evidence("risk-provider")
        consumer = self.evidence("risk-consumer")
        relation = self.manager.evidence_relations.add(consumer, provider, "depends_on")

        cases = [
            ({"op": "create_question", "issue_id": "root", "prompt": "Risk assessment question"}, "T1"),
            (
                {
                    "op": "transition_question",
                    "question_id": question["question_id"],
                    "action": "start",
                },
                "T1",
            ),
            (
                {
                    "op": "answer_question",
                    "question_id": question["question_id"],
                    "conclusion_id": conclusion["conclusion_id"],
                },
                "T2",
            ),
            (
                {
                    "op": "add_evidence_relation",
                    "consumer_evidence_id": consumer,
                    "provider_evidence_id": provider,
                    "relation_type": "depends_on",
                },
                "T1",
            ),
            (
                {
                    "op": "deactivate_evidence_relation",
                    "relation_id": relation["relation_id"],
                },
                "T1",
            ),
            (
                {
                    "op": "reactivate_evidence_relation",
                    "relation_id": relation["relation_id"],
                },
                "T1",
            ),
        ]
        for operation, expected in cases:
            with self.subTest(operation=operation):
                result = self.manager.changesets.risk_policy.assess(
                    {"operations": [operation]}
                )
                self.assertEqual(result.tier, expected)

        with self.assertRaises(ValidationError):
            self.manager.changesets.risk_policy.assess(
                {
                    "operations": [
                        {
                            "op": "answer_question",
                            "question_id": question["question_id"],
                            "conclusion_id": "missing",
                        }
                    ]
                }
            )
        self.manager.create_issue("report", "report_scope")
        report_question = self.manager.questions.create("report", "Report risk")
        report_risk = self.manager.changesets.risk_policy.assess(
            {
                "operations": [
                    {
                        "op": "transition_question",
                        "question_id": report_question["question_id"],
                        "action": "start",
                    }
                ]
            }
        )
        self.assertEqual(report_risk.tier, "T3")

    def test_changeset_executes_new_operation_family(self) -> None:
        auth = self.manager.credentials.resolve(self.organizer)
        conclusion = self.publish("root", "ChangeSet answer")
        provider = self.evidence("changeset-provider")
        consumer = self.evidence("changeset-consumer")

        def apply(operation: dict) -> dict:
            return self.manager.changesets._apply_operation(
                "changeset-v14",
                operation,
                auth,
                self.organizer,
                [],
                None,  # type: ignore[arg-type]
                operation_ordinal=0,
                changeset_hash="hash",
            )

        question = apply(
            {
                "op": "create_question",
                "issue_id": "root",
                "prompt": "Reviewed question",
                "question_key": "reviewed",
                "motivation": "coverage",
                "question_kind": "analysis",
                "priority": 75,
                "expected_evidence": [],
            }
        )
        for action, reason in (
            ("start", ""),
            ("block", "waiting"),
            ("defer", "later"),
            ("cancel", "obsolete"),
            ("reopen", "needed"),
        ):
            apply(
                {
                    "op": "transition_question",
                    "question_id": question["question_id"],
                    "action": action,
                    "reason": reason,
                }
            )
        with self.assertRaises(ValidationError):
            apply(
                {
                    "op": "transition_question",
                    "question_id": question["question_id"],
                    "action": "invalid",
                }
            )
        answered = apply(
            {
                "op": "answer_question",
                "question_id": question["question_id"],
                "conclusion_id": conclusion["conclusion_id"],
            }
        )
        self.assertEqual(answered["status"], "answered")
        relation = apply(
            {
                "op": "add_evidence_relation",
                "consumer_evidence_id": consumer,
                "provider_evidence_id": provider,
                "relation_type": "supports",
                "rationale": "reviewed",
            }
        )
        self.assertFalse(
            apply(
                {
                    "op": "deactivate_evidence_relation",
                    "relation_id": relation["relation_id"],
                    "reason": "reviewed",
                }
            )["active"]
        )
        self.assertTrue(
            apply(
                {
                    "op": "reactivate_evidence_relation",
                    "relation_id": relation["relation_id"],
                    "reason": "reviewed",
                }
            )["active"]
        )

    def test_v14_template_validator_rejects_every_invalid_shape(self) -> None:
        cases = [
            ("evidence_intake_template", "bad/v1", {}),
            (
                "evidence_intake_template",
                "evidence-intake-template/v1",
                {"unknown": True},
            ),
            (
                "evidence_intake_template",
                "evidence-intake-template/v1",
                {"required_fields": "bad"},
            ),
            (
                "evidence_intake_template",
                "evidence-intake-template/v1",
                {"required_fields": ["/x"], "optional_fields": ["/x"]},
            ),
            (
                "evidence_intake_template",
                "evidence-intake-template/v1",
                {"allowed_relation_types": ["bad"]},
            ),
            ("question_template", "question-template/v1", {"unknown": True}),
            ("question_template", "question-template/v1", {"questions": {}}),
            ("question_template", "question-template/v1", {"questions": ["bad"]}),
            (
                "question_template",
                "question-template/v1",
                {"questions": [{"question_key": "q", "prompt": "x", "unknown": 1}]},
            ),
            (
                "question_template",
                "question-template/v1",
                {"questions": [{"question_key": "", "prompt": "x"}]},
            ),
            (
                "question_template",
                "question-template/v1",
                {"questions": [{"question_key": "q", "prompt": " "}]},
            ),
            (
                "question_template",
                "question-template/v1",
                {
                    "questions": [
                        {"question_key": "q", "prompt": "one"},
                        {"question_key": "q", "prompt": "two"},
                    ]
                },
            ),
            (
                "conclusion_summary_template",
                "conclusion-summary-template/v1",
                {"unknown": True},
            ),
            (
                "conclusion_summary_template",
                "conclusion-summary-template/v1",
                {"sections": "bad"},
            ),
        ]
        for kind, api_version, definition in cases:
            with self.subTest(kind=kind, definition=definition), self.assertRaises(
                ValidationError
            ):
                _validate_v14_template(kind, api_version, definition)


if __name__ == "__main__":
    unittest.main()
