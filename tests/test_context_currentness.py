from __future__ import annotations

import random
import unittest
from itertools import product

from issue_manager.currentness import maintain_region


def reference(roots, edges):
    result = set()
    while True:
        revised = set(roots) | {consumer for provider, consumer in edges if provider in result}
        if revised == result:
            return result
        result = revised


def subsets(values):
    values = list(values)
    for mask in range(1 << len(values)):
        yield {value for i, value in enumerate(values) if mask & (1 << i)}


class CurrentnessAlgorithmTests(unittest.TestCase):
    def check_transition(self, roots, edges, new_roots, new_edges, new_nodes=()):
        previous = reference(roots, edges)
        forward, reverse = {}, {}
        for provider, consumer in new_edges:
            forward.setdefault(provider, set()).add(consumer)
            reverse.setdefault(consumer, set()).add(provider)
        update = maintain_region(
            changed_roots=roots ^ new_roots,
            added_edges=new_edges - edges,
            removed_edges=edges - new_edges,
            new_nodes=new_nodes,
            successors=lambda node: forward.get(node, ()),
            predecessors=lambda node: reverse.get(node, ()),
            is_local_root=new_roots.__contains__,
            was_dirty=previous.__contains__,
        )
        expected = reference(new_roots, new_edges)
        self.assertEqual((previous - update.region) | update.dirty, expected)
        self.assertLessEqual(previous ^ expected, update.region)
        return update

    def test_exhaustive_three_node_atomic_changes(self):
        nodes = {"a", "b", "c"}
        possible_edges = list(product(sorted(nodes), repeat=2))
        for edges in subsets(possible_edges):
            for roots in subsets(sorted(nodes)):
                for root in nodes:
                    self.check_transition(roots, edges, roots ^ {root}, edges)
                for edge in possible_edges:
                    self.check_transition(roots, edges, roots, edges ^ {edge})
                    for root in nodes:
                        self.check_transition(roots, edges, roots ^ {root}, edges ^ {edge})

    def test_seeded_sequences(self):
        rng = random.Random(20260906)
        roots, edges = set(), set()
        for _ in range(2000):
            revised_roots, revised_edges = set(roots), set(edges)
            for _ in range(rng.randrange(1, 7)):
                if rng.randrange(2):
                    revised_roots ^= {str(rng.randrange(8))}
                else:
                    revised_edges ^= {(str(rng.randrange(8)), str(rng.randrange(8)))}
            self.check_transition(roots, edges, revised_roots, revised_edges)
            roots, edges = revised_roots, revised_edges

    def test_last_root_removed_from_cycle(self):
        edges = {("a", "b"), ("b", "a")}
        update = self.check_transition({"a"}, edges, set(), edges)
        self.assertEqual(update.region, {"a", "b"})
        self.assertFalse(update.dirty)

    def test_new_nodes_and_external_boundary(self):
        update = self.check_transition({"a"}, {("a", "b")}, {"a"},
                                       {("a", "b"), ("b", "c")}, {"c"})
        self.assertEqual(update.region, {"c"})
        self.assertEqual(update.boundary, {"c"})

    def test_unrelated_components_are_not_read(self):
        visited = set()

        def successors(node):
            visited.add(node)
            return {"a": {"b"}, "b": {"a"}}.get(node, ())

        update = maintain_region(
            changed_roots={"a"}, added_edges=(), removed_edges=(),
            successors=successors, predecessors=lambda node: (),
            is_local_root=lambda node: False, was_dirty=lambda node: True,
        )
        self.assertEqual(visited, {"a", "b"})
        self.assertFalse(update.dirty)

    def test_replay_reads_no_graph(self):
        def unexpected(node):
            self.fail("No-change replay must not read the graph")
        update = maintain_region(
            changed_roots=(), added_edges=(), removed_edges=(),
            successors=unexpected, predecessors=unexpected,
            is_local_root=unexpected, was_dirty=unexpected,
        )
        self.assertFalse(update.region)


if __name__ == "__main__":
    unittest.main()
