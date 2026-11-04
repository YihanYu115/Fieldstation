"""Finite checks for the V1 abstract graph algorithm; not production code or proof.

Run from the repository root:
    python scripts/check_context_algebra.py

No project database, AI service, external dependency, or filesystem write is used.
"""

import json
import random
from collections import deque
from itertools import product


def full_reference(nodes, roots, edges):
    """Independent full reference: simultaneous iteration of the dirty equation."""
    dirty = set()
    while True:
        following = set(roots) | {v for u, v in edges if u in dirty}
        assert following <= nodes
        if following == dirty:
            return dirty
        dirty = following


def queue_reach(starts, edges, allowed):
    adjacency = {}
    for u, v in edges:
        if u in allowed and v in allowed:
            adjacency.setdefault(u, set()).add(v)
    reached = set(starts) & allowed
    pending = deque(reached)
    while pending:
        for following in adjacency.get(pending.popleft(), ()):
            if following not in reached:
                reached.add(following)
                pending.append(following)
    return reached


def local_maintain(nodes, old_roots, old_edges, old_dirty, roots, edges, new_nodes=()):
    seeds = (old_roots ^ roots) | {v for _, v in old_edges ^ edges} | set(new_nodes)
    region = queue_reach(seeds, old_edges | edges, nodes)
    boundary = (roots & region) | {
        v for u, v in edges if u not in region and u in old_dirty and v in region
    }
    revised = (old_dirty - region) | queue_reach(boundary, edges, region)
    return revised, region


def check_transition(nodes, old_roots, old_edges, roots, edges, new_nodes=()):
    old_dirty = full_reference(nodes, old_roots, old_edges)
    expected = full_reference(nodes, roots, edges)
    actual, region = local_maintain(
        nodes, old_roots, old_edges, old_dirty, roots, edges, new_nodes
    )
    assert actual == expected, (old_roots, old_edges, roots, edges, actual, expected)
    assert (old_dirty ^ expected) <= region
    repeated, _ = local_maintain(nodes, roots, edges, actual, roots, edges)
    assert repeated == actual


def subsets(items):
    items = list(items)
    for mask in range(1 << len(items)):
        yield {item for i, item in enumerate(items) if mask & (1 << i)}


def check_delta_algebra():
    # Set transformations act independently on each membership bit.
    changes = [(False, False), (True, False), (False, True)]

    def act(bit, change):
        insert, delete = change
        return (bit and not delete) or insert

    def compose(a, b):
        i1, d1 = a
        i2, d2 = b
        return ((i1 and not d2) or i2, (d1 or d2) and not i2)

    for a, b in product(changes, repeat=2):
        assert compose(a, b) in changes
        for bit in (False, True):
            assert act(act(bit, a), b) == act(bit, compose(a, b))
    for a, b, c in product(changes, repeat=3):
        assert compose(compose(a, b), c) == compose(a, compose(b, c))
    for a in changes:
        assert compose(a, changes[0]) == compose(changes[0], a) == a


def main():
    check_delta_algebra()
    nodes = set(range(3))
    possible_edges = list(product(sorted(nodes), repeat=2))
    exhaustive = 0
    # All 512 directed graphs (self-loops included), all 8 root sets.
    for edges in subsets(possible_edges):
        for roots in subsets(sorted(nodes)):
            for root in sorted(nodes):
                check_transition(nodes, roots, edges, roots ^ {root}, edges)
                exhaustive += 1
            for edge in possible_edges:
                check_transition(nodes, roots, edges, roots, edges ^ {edge})
                exhaustive += 1
            # Atomic combined changes exercise old/new boundary handling.
            for root, edge in product(sorted(nodes), possible_edges):
                check_transition(nodes, roots, edges, roots ^ {root}, edges ^ {edge})
                exhaustive += 1

    rng = random.Random(20260906)
    nodes = set(range(8))
    roots, edges, dirty = set(), set(), set()
    for _ in range(2000):
        new_roots, new_edges = set(roots), set(edges)
        for _ in range(rng.randrange(1, 7)):
            if rng.randrange(2):
                new_roots ^= {rng.randrange(8)}
            else:
                new_edges ^= {(rng.randrange(8), rng.randrange(8))}
        dirty, region = local_maintain(nodes, roots, edges, dirty, new_roots, new_edges)
        assert dirty == full_reference(nodes, new_roots, new_edges)
        roots, edges = new_roots, new_edges

    # Newly materialized node: compare over the common domain with no old edges.
    check_transition(set(range(4)), {0}, {(0, 1)}, {0}, {(0, 1), (1, 3)}, {3})
    check_transition(set(range(4)), set(), set(), {3}, set(), {3})

    print(json.dumps({
        "result": "pass",
        "delta_algebra": "membership-bit exhaustive checks passed",
        "three_node_graph_root_states": 4096,
        "exhaustive_transitions": exhaustive,
        "seeded_sequence_steps": 2000,
        "new_node_checks": 2,
        "random_seed": 20260906,
        "scope": "abstract L/G updates only; no selector, database, transaction or AI verification",
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

