"""V1 currentness maintenance over indexed, version-addressed dependencies.

This module implements CONTEXT_MAINTENANCE_V1 section 7. The caller owns
snapshot isolation, candidate discovery, edge contribution aggregation and
atomic publication. Neither workflow tasks nor old labels inside the affected
region are roots. Callbacks must all observe the same post-mutation snapshot.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class CurrentnessUpdate:
    region: frozenset[str]
    dirty: frozenset[str]
    boundary: frozenset[str]


def maintain_region(
    *,
    changed_roots: Iterable[str],
    added_edges: Iterable[tuple[str, str]],
    removed_edges: Iterable[tuple[str, str]],
    new_nodes: Iterable[str] = (),
    successors: Callable[[str], Iterable[str]],
    predecessors: Callable[[str], Iterable[str]],
    is_local_root: Callable[[str], bool],
    was_dirty: Callable[[str], bool],
) -> CurrentnessUpdate:
    """Return replacement labels for the affected region only.

    Edge deltas describe effective provider->consumer edges, after aggregating
    independent contributions. Removed edges are retained here to traverse the
    old/new union without loading either complete graph. Missing versions must
    already be represented by local roots by the context resolver.

    ``changed_roots`` is the symmetric difference of old/new root membership;
    explanation-only changes must separately be persisted by the caller even
    when this function returns an empty region.
    """
    added = set(added_edges)
    removed = set(removed_edges)
    if added & removed:
        raise ValueError("Effective edge insertion and removal must be disjoint")
    old_successors: dict[str, set[str]] = defaultdict(set)
    for provider, consumer in removed:
        old_successors[provider].add(consumer)
    region = set(changed_roots) | set(new_nodes)
    region.update(consumer for _, consumer in added | removed)
    pending = deque(sorted(region))
    while pending:
        provider = pending.popleft()
        for consumer in set(successors(provider)) | old_successors.get(provider, set()):
            if consumer not in region:
                region.add(consumer)
                pending.append(consumer)

    boundary = {
        node for node in region
        if is_local_root(node)
        or any(parent not in region and was_dirty(parent) for parent in predecessors(node))
    }
    dirty = set(boundary)
    pending = deque(sorted(boundary))
    while pending:
        for consumer in successors(pending.popleft()):
            if consumer in region and consumer not in dirty:
                dirty.add(consumer)
                pending.append(consumer)
    return CurrentnessUpdate(frozenset(region), frozenset(dirty), frozenset(boundary))
