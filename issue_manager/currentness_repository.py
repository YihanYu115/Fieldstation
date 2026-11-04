"""Transactional SQL refinement of the V1 local graph maintenance algorithm."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import Any

from .currentness import CurrentnessUpdate, maintain_region
from .errors import ConflictError
from .store import canonical_json


class CurrentnessRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def apply(
        self,
        *,
        revision: int,
        local_reasons: Mapping[str, list[dict[str, Any]]],
        contributions: Mapping[str, set[tuple[str, str]]],
    ) -> CurrentnessUpdate:
        """Replace candidate roots and incoming contributions in one transaction.

        ``contributions[consumer]`` contains (provider, contribution_id) pairs.
        Candidates must include every consumer with a changed context/read set.
        This method deliberately does not discover candidates by scanning cached
        results. The resolver's subscriptions provide them, including empty sets.
        The caller commits inputs, this cache update and audit together.
        """
        if not self.conn.in_transaction:
            raise RuntimeError("Currentness maintenance requires an input transaction")
        current_revision = self.conn.execute(
            "SELECT revision FROM context_input_clock WHERE singleton=1"
        ).fetchone()[0]
        if revision != current_revision:
            raise ConflictError("Currentness computation uses an obsolete input revision")
        changed_roots, new_nodes = set(), set()
        added_edges: set[tuple[str, str]] = set()
        removed_edges: set[tuple[str, str]] = set()
        for consumer, entries in contributions.items():
            old = {
                (row[0], row[1]) for row in self.conn.execute(
                    "SELECT provider_conclusion_id,contribution_id FROM currentness_edge_contributions "
                    "WHERE consumer_conclusion_id=?", (consumer,)
                )
            }
            for provider, identity in old - entries:
                self.conn.execute(
                    "DELETE FROM currentness_edge_contributions WHERE provider_conclusion_id=? "
                    "AND consumer_conclusion_id=? AND contribution_id=?", (provider, consumer, identity)
                )
            for provider, identity in entries - old:
                self.conn.execute(
                    "INSERT INTO currentness_edge_contributions VALUES (?,?,?)",
                    (provider, consumer, identity)
                )
            old_providers = {provider for provider, _ in old}
            new_providers = {provider for provider, _ in entries}
            removed_edges.update((provider, consumer) for provider in old_providers - new_providers)
            added_edges.update((provider, consumer) for provider in new_providers - old_providers)

        for node, reasons in local_reasons.items():
            old = self.conn.execute(
                "SELECT local_mismatch,maintenance_state FROM conclusion_currentness WHERE conclusion_id=?", (node,)
            ).fetchone()
            local = bool(reasons)
            if old is None or old[1] != "ready":
                new_nodes.add(node)
            if old is None or bool(old[0]) != local:
                changed_roots.add(node)
            self.conn.execute(
                "INSERT INTO conclusion_currentness VALUES (?,?,1,'pending',?,?) "
                "ON CONFLICT(conclusion_id) DO UPDATE SET local_mismatch=excluded.local_mismatch,"
                "reason_json=excluded.reason_json",
                (node, int(local), revision, canonical_json(reasons))
            )

        def successors(node):
            return [row[0] for row in self.conn.execute(
                "SELECT DISTINCT consumer_conclusion_id FROM currentness_edge_contributions "
                "WHERE provider_conclusion_id=?", (node,)
            )]

        def predecessors(node):
            return [row[0] for row in self.conn.execute(
                "SELECT DISTINCT provider_conclusion_id FROM currentness_edge_contributions "
                "WHERE consumer_conclusion_id=?", (node,)
            )]

        def flag(node, column):
            row = self.conn.execute(
                f"SELECT {column},maintenance_state FROM conclusion_currentness WHERE conclusion_id=?",
                (node,)
            ).fetchone()
            if row is None:
                raise ConflictError(f"Missing currentness node: {node}")
            # Pending external boundaries cannot be consumed as current results.
            if column == "needs_update" and row[1] != "ready":
                raise ConflictError(f"Currentness boundary is not maintained: {node}")
            return bool(row[0])

        update = maintain_region(
            changed_roots=changed_roots, added_edges=added_edges, removed_edges=removed_edges,
            new_nodes=new_nodes, successors=successors, predecessors=predecessors,
            is_local_root=lambda node: flag(node, "local_mismatch"),
            was_dirty=lambda node: flag(node, "needs_update"),
        )
        for node in update.region:
            self.conn.execute(
                "UPDATE conclusion_currentness SET needs_update=?,maintenance_state='ready',"
                "computed_revision=? WHERE conclusion_id=?",
                (int(node in update.dirty), revision, node)
            )
        # A matching/changed explanation must be published even if L and G did
        # not change. Do not stamp unrelated nodes with this revision.
        for node in set(local_reasons) - update.region:
            self.conn.execute(
                "UPDATE conclusion_currentness SET computed_revision=? WHERE conclusion_id=?",
                (revision, node)
            )
        return update
