from __future__ import annotations

import itertools
import unittest

from issue_manager.evidence_applicability import (
    APPLICABILITY_RULE_ID,
    EvidenceTargetSnapshot,
    basis_structure_errors,
    evaluate_applicability,
    qualification_structure_errors,
)


def snapshot(evidence_id="e-1", revision=4, proof="p-4", manifest="m-4", **extra):
    return {
        "evidence_id": evidence_id,
        "semantic_revision": revision,
        "proof_id": proof,
        "manifest_id": manifest,
        **extra,
    }


def basis(evidence_id="basis-1"):
    return [
        {
            "kind": "evidence_version",
            "evidence_id": evidence_id,
            "semantic_revision": 1,
            "proof_id": None,
            "manifest_id": None,
            "snapshot": {"semantic_revision": 1, "proof_id": None, "manifest_id": None},
        }
    ]


def qualification(changeset_id="cs-1"):
    return {
        "actor_id": "actor-1",
        "run_id": "run-1",
        "capability": "evidence.applicability.write",
        "changeset_id": changeset_id,
        "changeset_hash": "hash-1",
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


def head(key="k-1", version="applicability:k-1:1", effect="include", **overrides):
    row = {
        "decision_key": key,
        "decision_version_id": version,
        "active": True,
        "scope_kind": "issue_conclusion",
        "scope_issue_id": "issue-a",
        "target_binding": "fixed",
        "target_evidence_id": "e-1",
        "target_semantic_revision": 4,
        "target_proof_id": "p-4",
        "target_manifest_id": "m-4",
        "effect": effect,
        "basis_json": basis(),
        "rule_id": APPLICABILITY_RULE_ID,
        "qualification_json": qualification(),
        "changeset_id": "cs-1",
    }
    row.update(overrides)
    return row


def project(heads, candidates=None, *, scope="issue-a", accepted=None):
    return evaluate_applicability(
        scope_issue_id=scope,
        candidate_snapshots=candidates or {"e-1": snapshot()},
        current_heads=heads,
        accepted_rule_ids=accepted or {APPLICABILITY_RULE_ID},
    ).as_dict()


class EvidenceApplicabilityAlgebraTests(unittest.TestCase):
    def test_typed_basis_shape_rejects_invalid_and_conflicting_references(self):
        self.assertEqual(basis_structure_errors("{"), ("basis_json_invalid",))
        self.assertEqual(basis_structure_errors({"kind": "evidence_version"}), ("basis_empty_or_not_array",))
        errors = set(basis_structure_errors([
            None,
            {"kind": None},
            {"kind": "future_kind", "id": "x"},
            {"kind": "record_version"},
            {"kind": "conclusion_version", "conclusion_id": "  "},
            {
                "kind": "evidence_version",
                "evidence_id": "ev",
                "semantic_revision": True,
                "proof_id": 3,
                "manifest_id": [],
                "snapshot": {"semantic_revision": 2, "proof_id": "wrong", "manifest_id": "wrong"},
            },
            {
                "kind": "evidence_version",
                "evidence_id": "ev",
                "semantic_revision": True,
                "proof_id": 3,
                "manifest_id": [],
                "snapshot": {"semantic_revision": 2, "proof_id": "wrong", "manifest_id": "wrong"},
            },
        ]))
        self.assertTrue({
            "basis_item_not_object", "basis_kind_unknown", "basis_typed_reference_incomplete",
            "basis_identity_invalid", "basis_duplicate_reference", "basis_evidence_revision_invalid",
            "basis_evidence_proof_invalid", "basis_evidence_manifest_invalid",
            "basis_evidence_snapshot_revision_mismatch", "basis_evidence_snapshot_proof_mismatch",
            "basis_evidence_snapshot_manifest_mismatch",
        }.issubset(errors))
        self.assertIn("basis_evidence_snapshot_invalid", basis_structure_errors([
            {"kind": "evidence_version", "evidence_id": "ev", "semantic_revision": 1,
             "proof_id": None, "manifest_id": None, "snapshot": None}
        ]))

    def test_frozen_qualification_shape_checks_fields_quorum_and_normalization(self):
        self.assertEqual(qualification_structure_errors("not-json", rule_id=APPLICABILITY_RULE_ID),
                         ("qualification_json_invalid",))
        self.assertEqual(qualification_structure_errors([], rule_id=APPLICABILITY_RULE_ID),
                         ("qualification_not_object",))
        receipt = qualification()
        receipt["review_ids"] = ["review-b", "review-a"]
        receipt["validation_results"]["risk"] = False
        errors = set(qualification_structure_errors(
            {**receipt, "unexpected": True, "capability": "wrong", "risk_tier": "T9"},
            rule_id="wrong-rule",
            changeset_id="another-change",
        ))
        self.assertTrue({
            "qualification_fields_not_canonical", "qualification_capability_invalid",
            "qualification_rule_mismatch", "qualification_changeset_mismatch",
            "qualification_risk_tier_invalid", "qualification_review_ids_not_normalized",
            "qualification_validation_failed",
        }.issubset(errors))
        duplicate = qualification()
        duplicate["review_ids"] = ["same", "same"]
        self.assertIn("qualification_review_ids_duplicate", qualification_structure_errors(
            duplicate, rule_id=APPLICABILITY_RULE_ID
        ))
        malformed = qualification()
        malformed["review_ids"] = [None]
        malformed["validation_results"] = None
        self.assertIn("qualification_review_ids_invalid", qualification_structure_errors(
            malformed, rule_id=APPLICABILITY_RULE_ID
        ))
        self.assertIn("qualification_validation_results_incomplete", qualification_structure_errors(
            malformed, rule_id=APPLICABILITY_RULE_ID
        ))

    def test_candidate_and_decision_head_corruption_is_conservative(self):
        with self.assertRaisesRegex(ValueError, "scope_issue_id"):
            project([], scope=" ")
        candidates = [
            EvidenceTargetSnapshot("bad", True, None, None),
            EvidenceTargetSnapshot("bad", 2, None, None),
            {"evidence_id": "", "semantic_revision": 0},
        ]
        malformed_heads = [
            head("wrong-binding", "v-binding", "exclude", target_evidence_id="bad", target_binding="follow-current"),
            head("invalid-active", "v-active", "exclude", target_evidence_id="bad", active="yes"),
            head("missing-identity", "", "exclude", target_evidence_id="bad", decision_key=""),
            head("bad-effect", "v-effect", ["exclude"], target_evidence_id="bad"),
        ]
        result = evaluate_applicability(
            scope_issue_id="issue-a",
            candidate_snapshots=candidates,
            current_heads=malformed_heads,
            accepted_rule_ids={APPLICABILITY_RULE_ID},
        )
        item = result.by_evidence_id()["bad"]
        self.assertEqual(item.state, "unresolved")
        self.assertIn("candidate_snapshot_conflict", item.errors)
        self.assertIn("decision_target_binding_invalid", item.errors)
        self.assertIn("decision_active_flag_invalid", item.errors)
        self.assertEqual(item.as_dict()["state"], "unresolved")
    def test_table_driven_empty_single_and_same_effect_sets(self):
        cases = [
            ("no decisions", [], "included", [], []),
            (
                "one include",
                [head(effect="include")],
                "included",
                ["include"],
                ["applicability:k-1:1"],
            ),
            (
                "one exclude",
                [head(effect="exclude")],
                "excluded",
                ["exclude"],
                ["applicability:k-1:1"],
            ),
            (
                "independent same-effect excludes",
                [
                    head("k-1", "applicability:k-1:1", "exclude"),
                    head("k-2", "applicability:k-2:1", "exclude"),
                ],
                "excluded",
                ["exclude"],
                ["applicability:k-1:1", "applicability:k-2:1"],
            ),
            (
                "independent same-effect includes",
                [
                    head("k-1", "applicability:k-1:1", "include"),
                    head("k-2", "applicability:k-2:1", "include"),
                ],
                "included",
                ["include"],
                ["applicability:k-1:1", "applicability:k-2:1"],
            ),
        ]
        for label, heads, state, effects, versions in cases:
            with self.subTest(label=label):
                item = project(heads)["evidence"][0]
                self.assertEqual(item["state"], state)
                self.assertEqual(item["qualified_effects"], effects)
                self.assertEqual(item["decision_version_ids"], versions)

    def test_independent_include_and_exclude_are_unresolved_and_retained(self):
        result = project(
            [
                head("include-key", "applicability:include-key:1", "include"),
                head("exclude-key", "applicability:exclude-key:1", "exclude"),
            ]
        )
        self.assertEqual(result["unresolved"], ["e-1"])
        self.assertEqual(result["included"], [])
        self.assertEqual(result["excluded"], [])
        self.assertEqual(result["evidence"][0]["qualified_effects"], ["exclude", "include"])
        self.assertEqual(len(result["evidence"][0]["decision_version_ids"]), 2)

    def test_inactive_head_never_participates(self):
        item = project([head(effect="exclude", active=False)])["evidence"][0]
        self.assertEqual(item["state"], "included")
        self.assertEqual(item["decision_version_ids"], [])
        self.assertEqual(item["qualified_effects"], [])

    def test_only_matching_scope_participates(self):
        item = project(
            [head(effect="exclude", scope_issue_id="issue-b")],
            candidates={"e-1": snapshot()},
            scope="issue-a",
        )["evidence"][0]
        self.assertEqual(item["state"], "included")
        self.assertEqual(item["decision_version_ids"], [])
        self.assertEqual(
            item["nonmatching_heads"],
            [
                {
                    "decision_version_id": "applicability:k-1:1",
                    "reason": "scope_mismatch",
                }
            ],
        )

    def test_fixed_target_snapshot_change_makes_old_head_nonmatching(self):
        changed_snapshots = [
            snapshot(revision=5, proof="p-5", manifest="m-4"),
            snapshot(revision=4, proof="p-other", manifest="m-4"),
            snapshot(revision=4, proof="p-4", manifest="m-other"),
        ]
        for changed in changed_snapshots:
            with self.subTest(changed=changed):
                item = project([head(effect="exclude")], candidates={"e-1": changed})["evidence"][0]
                self.assertEqual(item["state"], "included")
                self.assertEqual(item["decision_version_ids"], [])
                self.assertEqual(item["nonmatching_decision_version_ids"], ["applicability:k-1:1"])
                self.assertEqual(
                    item["nonmatching_heads"][0]["reason"], "fixed_target_snapshot_mismatch"
                )

    def test_rule_basis_and_qualification_fail_closed_to_unresolved(self):
        invalid = [
            ("unaccepted rule", head(effect="exclude"), {"some-other-rule"}),
            ("empty basis", head(effect="exclude", basis_json=[]), {APPLICABILITY_RULE_ID}),
            (
                "unknown basis kind",
                head(effect="exclude", basis_json=[{"kind": "free_text", "id": "x"}]),
                {APPLICABILITY_RULE_ID},
            ),
            (
                "non-text basis kind",
                head(effect="exclude", basis_json=[{"kind": ["conclusion_version"]}]),
                {APPLICABILITY_RULE_ID},
            ),
            (
                "non-text effect",
                head(effect=["exclude"]),
                {APPLICABILITY_RULE_ID},
            ),
            (
                "non-text qualification risk tier",
                head(
                    effect="exclude",
                    qualification_json={**qualification(), "risk_tier": ["T1"]},
                ),
                {APPLICABILITY_RULE_ID},
            ),
            (
                "invalid qualification",
                head(effect="exclude", qualification_json={"authorized": True}),
                {APPLICABILITY_RULE_ID},
            ),
        ]
        for label, decision, accepted in invalid:
            with self.subTest(label=label):
                item = project([decision], accepted=accepted)["evidence"][0]
                self.assertEqual(item["state"], "unresolved")
                self.assertTrue(item["errors"])
                self.assertEqual(item["qualified_effects"], [])

    def test_same_key_multiple_current_heads_fail_closed(self):
        item = project(
            [
                head("same", "applicability:same:1", "exclude"),
                head("same", "applicability:same:2", "include"),
            ]
        )["evidence"][0]
        self.assertEqual(item["state"], "unresolved")
        self.assertIn("multiple_active_heads_for_decision_key", item["errors"])

    def test_permutations_and_nonsemantic_metadata_have_identical_normal_form(self):
        heads = [
            head(
                "k-a",
                "applicability:k-a:1",
                "include",
                created_at="later",
                rowid=90,
                ai_confidence=0.99,
            ),
            head(
                "k-b",
                "applicability:k-b:1",
                "exclude",
                created_at="earlier",
                rowid=2,
                ai_confidence=0.01,
            ),
        ]
        candidates = {"e-z": snapshot("e-z"), "e-1": snapshot()}
        baseline = evaluate_applicability(
            scope_issue_id="issue-a",
            candidate_snapshots=candidates,
            current_heads=heads,
            accepted_rule_ids={APPLICABILITY_RULE_ID},
        ).as_dict()
        for head_order in itertools.permutations(heads):
            for candidate_order in itertools.permutations(list(candidates.items())):
                permuted = evaluate_applicability(
                    scope_issue_id="issue-a",
                    candidate_snapshots=dict(candidate_order),
                    current_heads=head_order,
                    accepted_rule_ids={APPLICABILITY_RULE_ID},
                ).as_dict()
                self.assertEqual(permuted, baseline)

    def test_small_set_enumeration_uses_independent_set_expectations(self):
        # Each independent key can be absent, include, or exclude. The expected
        # state is table-driven from the mathematical effect-set definition.
        expected_by_effects = {
            frozenset(): "included",
            frozenset({"include"}): "included",
            frozenset({"exclude"}): "excluded",
            frozenset({"include", "exclude"}): "unresolved",
        }
        choices = (None, "include", "exclude")
        for left, right in itertools.product(choices, repeat=2):
            decisions = []
            effects = set()
            for index, effect in enumerate((left, right)):
                if effect is not None:
                    decisions.append(head(f"k-{index}", f"applicability:k-{index}:1", effect))
                    effects.add(effect)
            with self.subTest(left=left, right=right):
                item = project(decisions)["evidence"][0]
                self.assertEqual(item["state"], expected_by_effects[frozenset(effects)])


if __name__ == "__main__":
    unittest.main()
