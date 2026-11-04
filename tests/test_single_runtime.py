"""Release contracts for the sole scoped-v2 runtime, using synthetic stores."""
import hashlib
import sqlite3
from contextlib import closing

import pytest

from issue_manager import IssueManager
from issue_manager.changeset_state import StateView
from issue_manager.errors import ValidationError
from issue_manager.scoped_projection import project
from issue_manager.scoped_semantics import ScopedNode, ScopedRelation, ScopedSnapshot, solve


@pytest.mark.parametrize("rule", ["legacy-v1", "scoped-v1", "unknown"])
def test_unsupported_init_does_not_create_project(tmp_path, rule):
    target = tmp_path / "rejected"
    with pytest.raises(ValidationError):
        IssueManager.initialize(target, context_rule=rule)
    assert not target.exists()


def test_unsupported_stored_rule_is_rejected_without_mutation(tmp_path):
    target = tmp_path / "project"
    with closing(IssueManager.initialize(target)):
        pass
    database = target / "issue_ledger.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute("INSERT INTO context_rule_versions VALUES ('unknown','{}','test')")
        connection.execute("UPDATE context_rule_selections SET rule_id='unknown'")
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    with pytest.raises(ValidationError, match="Unsupported context rule"):
        IssueManager(target)
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before


def test_preflight_qualification_uses_overlay_without_changing_authority(tmp_path):
    with closing(IssueManager.initialize(tmp_path / "project")) as manager:
        manager.create_issue("scope", "investigation", "Scope")
        evidence = manager.add_evidence(kind="external", locator="urn:overlay", issue_id="scope")["evidence_id"]
        descriptor = manager.context_maintenance.default_descriptor("scope", evidence_ids=[evidence])
        resolver = manager.context_maintenance.scoped_v2_resolver
        original = resolver.resolve(descriptor)
        view = StateView(manager)
        assert resolver.resolve(descriptor, state_view=view).semantic == original.semantic
        view.evidence_quality[evidence] = "questionable"
        simulated = resolver.resolve(descriptor, state_view=view)
        assert simulated.model_materials["support_ids"] == []
        assert simulated.model_materials["gap"][0]["state"] == "?"
        assert resolver.resolve(descriptor).semantic == original.semantic


def test_u17_surviving_prerequisite_cannot_support_failed_root():
    nodes = tuple(ScopedNode(identity, "v1", "T") for identity in "ABCDE")
    edges = (
        ScopedRelation("BA", "r1", "B", "A", "v1", "v1", "depends_on"),
        ScopedRelation("BE", "r1", "B", "E", "v1", "v1", "depends_on"),
        ScopedRelation("CE", "r1", "C", "E", "v1", "v1", "refutes"),
    )
    graph = ScopedSnapshot("scope", nodes, edges, "context-currentness/scoped-v2")
    projection = project(graph, ["B", "D"], solve(graph))
    assert projection["states"]["A"] == "T"
    assert projection["support_ids"] == ["D"]
    assert [row["node_id"] for row in projection["gap"]] == ["B"]


def test_u15_same_snapshot_and_baseline_are_history_independent():
    nodes = tuple(ScopedNode(identity, "v1", "T") for identity in "ABC")
    dependency = ScopedRelation("BA", "r1", "B", "A", "v1", "v1", "depends_on")
    refutation = ScopedRelation("CA", "r2", "C", "A", "v1", "v1", "refutes")
    baseline = ScopedSnapshot("scope", nodes, (dependency,), "context-currentness/scoped-v2")
    frozen = project(baseline, ["B"], solve(baseline))["comparison"]
    current = ScopedSnapshot("scope", nodes, (dependency, refutation), baseline.rule_id)
    expected = project(current, ["B"], solve(current))
    # An earlier computation and reversed arrival order cannot act as hidden state.
    intervening = ScopedSnapshot("scope", nodes, (refutation,), baseline.rule_id)
    solve(intervening)
    reordered = ScopedSnapshot("scope", tuple(reversed(nodes)), (refutation, dependency), baseline.rule_id)
    actual = project(reordered, ["B"], solve(reordered))
    assert actual == expected
    assert (actual["comparison"] != frozen) == (expected["comparison"] != frozen)
