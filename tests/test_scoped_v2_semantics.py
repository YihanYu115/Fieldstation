from issue_manager.scoped_projection import project
from issue_manager.scoped_semantics import (
    ScopedNode,
    ScopedRelation,
    ScopedSnapshot,
    solve,
)


def relation(relation_id, source, target, kind, *, source_binding="v1", target_binding="v1"):
    return ScopedRelation(relation_id, "r1", source, target, source_binding, target_binding, kind)


def snapshot(nodes, relations):
    return ScopedSnapshot("issue-a", tuple(nodes), tuple(relations), "context-currentness/scoped-v2")


def test_mixed_refutation_and_dependency_chain_is_solved_together():
    graph = snapshot(
        [ScopedNode("A", "v1", "T"), ScopedNode("B", "v1", "T"), ScopedNode("C", "v1", "T")],
        [relation("b-depends-a", "B", "A", "depends_on"), relation("c-refutes-a", "C", "A", "refutes")],
    )
    result = solve(graph)
    assert dict(result.states) == {"A": "F", "B": "F", "C": "T"}
    assert {item.code for item in result.reasons["B"]} == {"necessary_basis_failed"}
    assert {item.code for item in result.reasons["A"]} == {"direct_refutation"}


def test_multiple_refuters_keep_every_valid_attacker_effective():
    graph = snapshot(
        [ScopedNode("A", "v1", "T"), ScopedNode("C1", "v1", "F"), ScopedNode("C2", "v1", "T")],
        [relation("c1-refutes-a", "C1", "A", "refutes"), relation("c2-refutes-a", "C2", "A", "refutes")],
    )
    result = solve(graph)
    assert dict(result.states) == {"A": "F", "C1": "F", "C2": "T"}
    assert {item.relation_id for item in result.reasons["A"]} == {"c2-refutes-a"}


def test_a_failed_refuter_does_not_exclude_a_new_independent_root():
    graph = snapshot(
        [ScopedNode("A", "v1", "T"), ScopedNode("B", "v1", "T"), ScopedNode("D", "v1", "T")],
        [relation("b-depends-a", "B", "A", "depends_on"), relation("b-refutes-d", "B", "D", "refutes")],
    )
    assert dict(solve(graph).states) == {"A": "T", "B": "T", "D": "F"}
    failed = snapshot(
        [ScopedNode("A", "v1", "F"), ScopedNode("B", "v1", "T"), ScopedNode("D", "v1", "T")],
        graph.relations,
    )
    assert dict(solve(failed).states) == {"A": "F", "B": "F", "D": "T"}


def test_refutation_of_refuter_restores_dependency_and_root_without_overwriting_selection():
    graph = snapshot(
        [ScopedNode("A", "v1", "T"), ScopedNode("B", "v1", "T"), ScopedNode("C", "v1", "T"), ScopedNode("E", "v1", "T")],
        [
            relation("b-depends-a", "B", "A", "depends_on"),
            relation("c-refutes-a", "C", "A", "refutes"),
            relation("e-refutes-c", "E", "C", "refutes"),
        ],
    )
    assert dict(solve(graph).states) == {"A": "T", "B": "T", "C": "F", "E": "T"}


def test_cycles_remain_undecided_but_external_information_can_break_them():
    graph = snapshot(
        [ScopedNode("A", "v1", "T"), ScopedNode("B", "v1", "T")],
        [relation("a-depends-b", "A", "B", "depends_on"), relation("b-depends-a", "B", "A", "depends_on")],
    )
    assert dict(solve(graph).states) == {"A": "?", "B": "?"}
    broken = snapshot(
        [ScopedNode("A", "v1", "T"), ScopedNode("B", "v1", "F")],
        graph.relations,
    )
    assert dict(solve(broken).states) == {"A": "F", "B": "F"}


def test_mismatched_dependency_is_an_unknown_obligation_not_a_deleted_edge():
    graph = snapshot(
        [ScopedNode("A", "new", "T"), ScopedNode("B", "v1", "T")],
        [relation("b-depends-old-a", "B", "A", "depends_on", target_binding="old")],
    )
    result = solve(graph)
    assert dict(result.states) == {"A": "T", "B": "?"}
    assert any(item.code == "necessary_binding_unknown" for item in result.reasons["B"])
    assert any(item.code == "dependency_binding_mismatch" for item in result.diagnostics)


def test_derived_from_does_not_make_a_consumer_depend_on_its_source():
    graph = snapshot(
        [ScopedNode("A", "v1", "F"), ScopedNode("B", "v1", "T")],
        [relation("b-derived-a", "B", "A", "derived_from")],
    )
    assert dict(solve(graph).states) == {"A": "F", "B": "T"}


def test_multiple_required_dependencies_are_and_not_or():
    graph = snapshot(
        [ScopedNode("A1", "v1", "F"), ScopedNode("A2", "v1", "T"), ScopedNode("B", "v1", "T")],
        [relation("b-depends-a1", "B", "A1", "depends_on"), relation("b-depends-a2", "B", "A2", "depends_on")],
    )
    assert dict(solve(graph).states) == {"A1": "F", "A2": "T", "B": "F"}


def test_projection_keeps_failed_root_out_of_support_but_retains_qualification_diagnostics():
    graph = snapshot(
        [
            ScopedNode("A", "v1", "T"), ScopedNode("B", "v1", "T"),
            ScopedNode("C", "v1", "T"), ScopedNode("D", "v1", "T"),
        ],
        [
            relation("b-depends-a", "B", "A", "depends_on"),
            relation("c-refutes-a", "C", "A", "refutes"),
        ],
    )
    result = solve(graph)
    view = project(graph, ["B"], result)
    assert view["basis_ids"] == ["A", "B"]
    assert view["support_ids"] == []
    assert view["gap"][0]["node_id"] == "B"
    assert "C" in view["qualification_ids"]
    assert view["discovery_ids"] == ["D"]


def test_projection_for_new_independent_root_isolated_from_old_chain():
    graph = snapshot(
        [
            ScopedNode("A", "v1", "F"), ScopedNode("B", "v1", "F"),
            ScopedNode("C", "v1", "T"), ScopedNode("D", "v1", "T"),
        ],
        [
            relation("b-depends-a", "B", "A", "depends_on"),
            relation("c-refutes-a", "C", "A", "refutes"),
        ],
    )
    view = project(graph, ["D"], solve(graph))
    assert view["support_ids"] == ["D"]
    assert view["qualification_ids"] == ["D"]
    assert set(view["discovery_ids"]) == {"A", "B", "C"}


def test_projection_is_independent_of_snapshot_input_order():
    nodes = [
        ScopedNode("A", "v1", "T"), ScopedNode("B", "v1", "T"),
        ScopedNode("C", "v1", "T"), ScopedNode("D", "v1", "T"),
    ]
    relations = [
        relation("b-depends-a", "B", "A", "depends_on"),
        relation("c-refutes-a", "C", "A", "refutes"),
        relation("d-challenges-b", "D", "B", "challenges"),
    ]
    first = project(snapshot(nodes, relations), ["B"], solve(snapshot(nodes, relations)))
    reversed_snapshot = snapshot(list(reversed(nodes)), list(reversed(relations)))
    second = project(reversed_snapshot, ["B"], solve(reversed_snapshot))
    assert first == second
