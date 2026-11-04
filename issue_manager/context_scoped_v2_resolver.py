"""Database adapter for the pure scoped-v2 graph solver and projections."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import asdict, dataclass, field
from typing import Any

from .context_resolver import subscription_key
from .context_scoped_rule import SCOPED_V2_RULE_ID, scoped_v2_rule_id
from .errors import ValidationError
from .scoped_projection import project
from .scoped_semantics import ScopedNode, ScopedRelation, ScopedSnapshot, Truth, solve
from .store import canonical_json


@dataclass
class ScopedV2ResolvedContext:
    semantic: dict[str, Any] = field(default_factory=dict)
    comparison_context: dict[str, Any] = field(default_factory=dict)
    model_materials: dict[str, Any] = field(default_factory=dict)
    selection_trace: dict[str, Any] = field(default_factory=dict)
    actual_reads: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    subscriptions: dict[str, dict[str, Any]] = field(default_factory=dict)
    contributions: set[tuple[str, str]] = field(default_factory=set)
    errors: list[dict[str, Any]] = field(default_factory=list)
    complete: bool = True


def _binding(row: dict[str, Any]) -> str:
    value = {
        "kind": "evidence_version", "evidence_id": row["evidence_id"],
        "semantic_revision": row.get("semantic_revision"),
        "proof_id": row.get("current_proof_id"),
        "manifest_id": row.get("current_manifest_id"),
        "content_hash": row.get("content_hash"),
        "lifecycle_status": row.get("lifecycle_status"),
        "quality_status": row.get("quality_status"),
    }
    return "evidence-binding/v1:" + hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


def _base_state(row: dict[str, Any]) -> Truth:
    if row.get("lifecycle_status") == "void" or row.get("quality_status") == "unusable_for_purpose":
        return "F"
    if row.get("quality_status") == "questionable":
        return "?"
    return "T"


class ContextScopedV2Resolver:
    """Read one bounded SQL snapshot and delegate all semantics to pure code."""

    MAX_NODES = 1000
    MAX_RELATIONS = 5000

    def __init__(self, conn: sqlite3.Connection, *, manager=None):
        self.conn = conn
        self.manager = manager

    def resolve(self, descriptor: dict[str, Any], *, tolerate_errors=False, state_view=None,
                maximum_nodes: int | None = None, maximum_relations: int | None = None):
        result = ScopedV2ResolvedContext()
        try:
            if state_view is not None:
                # A pristine preflight view is the same authoritative snapshot.
                # Never ignore modeled graph changes: unsupported overlays fail closed.
                from .changeset_state import StateView

                if not isinstance(state_view, StateView):
                    raise ValidationError("scoped-v2 resolver does not support unknown staged state views")
                if state_view.context_rule is not None or state_view.new_issue_relations:
                    raise ValidationError("scoped-v2 staged state views cannot switch rules or add unbound issue relations")
            node_limit = self._limit(maximum_nodes, self.MAX_NODES, "maximum_nodes")
            relation_limit = self._limit(maximum_relations, self.MAX_RELATIONS, "maximum_relations")
            return self._resolve(descriptor, result, node_limit, relation_limit, state_view)
        except (ValidationError, ValueError, TypeError, KeyError) as exc:
            if not tolerate_errors:
                if isinstance(exc, ValidationError):
                    raise
                raise ValidationError(f"Invalid scoped-v2 context input: {exc}") from exc
            result.complete = False
            result.errors.append({"code": "context_resolution_failed", "error_type": type(exc).__name__, "message": str(exc)})
            return result

    @staticmethod
    def _limit(value, maximum, field):
        if value is None:
            return maximum
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > maximum:
            raise ValidationError(f"{field} must be between 1 and {maximum}")
        return value

    def _resolve(self, descriptor, result, node_limit, relation_limit, state_view):
        allowed = {"version", "rule_version_id", "issue_id", "seed_evidence_ids", "prior_conclusion_id", "provider_bindings"}
        if not isinstance(descriptor, dict) or set(descriptor) - allowed:
            raise ValidationError("Unknown scoped-v2 context selector fields")
        if descriptor.get("version") != SCOPED_V2_RULE_ID:
            raise ValidationError("Unsupported scoped-v2 context descriptor version")
        if descriptor.get("rule_version_id") != scoped_v2_rule_id():
            raise ValidationError("Explicit scoped-v2 rule identity does not match the frozen definition")
        issue_id = descriptor.get("issue_id")
        if not isinstance(issue_id, str) or not issue_id:
            raise ValidationError("Scoped-v2 context descriptor needs an issue ID")
        seeds = descriptor.get("seed_evidence_ids", [])
        if not isinstance(seeds, list) or any(not isinstance(item, str) or not item for item in seeds):
            raise ValidationError("Scoped-v2 seed_evidence_ids must be an array of nonempty strings")
        providers = descriptor.get("provider_bindings", [])
        if not isinstance(providers, list):
            raise ValidationError("Scoped-v2 provider_bindings must be an array")
        if len(set(seeds)) != len(seeds) or len(seeds) > node_limit:
            raise ValidationError("Scoped-v2 seed_evidence_ids must be unique and within budget")
        if len(providers) > node_limit:
            raise ValidationError("Scoped-v2 provider_bindings exceeds its permitted budget")

        def read(sql, params=()):
            return [dict(row) for row in self.conn.execute(sql, params).fetchall()]

        def bounded(rows, label, maximum):
            if len(rows) > maximum:
                raise ValidationError(f"Scoped-v2 {label} snapshot exceeds its permitted budget")
            return rows

        def rows(table, column, value):
            key = subscription_key(table, column, value)
            result.subscriptions[key] = {"table": table, "column": column, "value": value}
            values = (state_view.context_rows(table, column, value) if state_view is not None
                      else read(f'SELECT * FROM "{table}" WHERE "{column}" IS ? LIMIT ?',
                                (value, max(node_limit, relation_limit) + 1)))
            result.actual_reads[key] = values
            return values

        issue = bounded(rows("issues", "issue_id", issue_id), "issue", 1)
        if not issue:
            raise ValidationError("Scoped-v2 context issue not found")
        attached = rows("issue_evidence", "issue_id", issue_id)
        questions: list[dict[str, Any]] = []
        for question in bounded(rows("issue_questions", "issue_id", issue_id), "question", node_limit):
            questions.extend(item for item in rows("issue_question_evidence_links", "question_id", question["question_id"])
                             if item["active"])
        records: list[dict[str, Any]] = []
        for record in bounded(rows("record_instances", "issue_id", issue_id), "record", node_limit):
            if record["lifecycle_status"] == "active" and record.get("current_revision_id"):
                records.extend(item for item in rows("record_material_relations", "record_revision_id", record["current_revision_id"])
                               if item["active"])
        attached = bounded(attached, "issue evidence", node_limit)
        questions = bounded(questions, "question evidence", node_limit)
        records = bounded(records, "record material", node_limit)
        discovered_seed_ids = sorted(set(seeds) | {row["evidence_id"] for row in attached + questions + records})

        evidence_ids = set(discovered_seed_ids)
        heads_by_id: dict[str, dict[str, Any]] = {}
        expanded: set[str] = set()
        while pending := sorted(evidence_ids - expanded):
            if len(evidence_ids) > node_limit:
                raise ValidationError("Scoped-v2 evidence graph exceeds its permitted node budget")
            expanded.update(pending)
            for evidence_id in pending:
                for column in ("source_evidence_id", "target_evidence_id"):
                    key = subscription_key("scoped_evidence_relation_heads", column, evidence_id)
                    result.subscriptions[key] = {"table": "scoped_evidence_relation_heads",
                                                 "column": column, "value": evidence_id}
            # Fetch only edges that can affect qualification or explain a related
            # challenge. scope_issue_id records declaration location; it does not
            # partition this ledger's evidence graph.
            placeholders = ",".join("?" for _ in pending)
            rows_for_frontier = read(
                "SELECT v.* FROM scoped_evidence_relation_heads h JOIN "
                "scoped_evidence_relation_versions v ON v.relation_id=h.relation_id "
                "AND v.version_id=h.current_version_id WHERE v.active=1 AND ("
                f"(v.source_evidence_id IN ({placeholders}) AND v.relation_type='depends_on') "
                "OR (v.target_evidence_id IN (" + placeholders + ") "
                "AND v.relation_type IN ('refutes','challenges')) ) ORDER BY v.relation_id",
                tuple(pending) + tuple(pending),
            )
            for relation in rows_for_frontier:
                heads_by_id[relation["relation_id"]] = relation
                evidence_ids.update((relation["source_evidence_id"], relation["target_evidence_id"]))
                if len(heads_by_id) > relation_limit:
                    raise ValidationError("Scoped-v2 relation graph exceeds its permitted budget")
        heads = [heads_by_id[key] for key in sorted(heads_by_id)]
        for column in ("source_evidence_id", "target_evidence_id"):
            # This endpoint-range watch also catches relationships that do not
            # exist yet, including newly added cross-Issue attackers.
            result.actual_reads.update({
                subscription_key("scoped_evidence_relation_heads", column, item):
                    [relation for relation in heads if relation[column] == item]
                for item in expanded
            })
        if len(evidence_ids) > node_limit:
            raise ValidationError("Scoped-v2 evidence graph exceeds its permitted node budget")
        evidence_rows: dict[str, dict[str, Any]] = {}
        errors = []
        for evidence_id in sorted(evidence_ids):
            evidence_values = rows("evidence_refs", "evidence_id", evidence_id)
            if not evidence_values:
                errors.append({"code": "evidence_not_found", "evidence_id": evidence_id})
                continue
            evidence_rows[evidence_id] = evidence_values[0]
            key = subscription_key("evidence_refs", "evidence_id", evidence_id)
            result.subscriptions[key] = {"table": "evidence_refs", "column": "evidence_id", "value": evidence_id}
            result.actual_reads[key] = evidence_values
        if errors:
            result.errors.extend(errors)
            result.complete = False
            return result

        provider_comparison: list[dict[str, Any]] = []

        def read_provider(binding: dict[str, Any], *, relation: dict[str, Any] | None = None):
            allowed_binding = {"issue_id", "mode", "conclusion_id", "require_currentness"}
            if set(binding) - allowed_binding:
                raise ValidationError("Invalid scoped-v2 provider binding fields")
            provider_issue = binding.get("issue_id")
            mode = binding.get("mode")
            if not isinstance(provider_issue, str) or not provider_issue or mode not in {"fixed", "follow-current"}:
                raise ValidationError("Scoped-v2 provider binding needs issue_id and mode")
            require_currentness = binding.get("require_currentness", mode == "follow-current")
            if not isinstance(require_currentness, bool):
                raise ValidationError("Scoped-v2 provider require_currentness must be boolean")
            provider_rows = rows("issues", "issue_id", provider_issue)
            provider_key = subscription_key("issues", "issue_id", provider_issue)
            result.subscriptions[provider_key] = {"table": "issues", "column": "issue_id", "value": provider_issue}
            result.actual_reads[provider_key] = provider_rows
            if not provider_rows:
                result.errors.append({"code": "provider_issue_missing", "issue_id": provider_issue})
                return
            provider = provider_rows[0]
            conclusion_id = binding.get("conclusion_id") if mode == "fixed" else provider.get("current_conclusion_id")
            if mode == "fixed" and (not isinstance(conclusion_id, str) or not conclusion_id):
                raise ValidationError("Fixed scoped-v2 provider binding needs conclusion_id")
            conclusion = None
            if conclusion_id:
                values = rows("conclusion_revisions", "conclusion_id", conclusion_id)
                columns = ("conclusion_id", "issue_id", "revision_number", "status", "statement",
                           "structured_outputs_json", "limitations_json", "evidence_refs_json")
                conclusion = {key: values[0].get(key) for key in columns} if values else None
            if conclusion is None:
                result.errors.append({"code": "provider_conclusion_missing", "issue_id": provider_issue,
                                      "conclusion_id": conclusion_id})
                return
            if conclusion["issue_id"] != provider_issue:
                raise ValidationError("Scoped-v2 provider conclusion belongs to another issue")
            provider_comparison.append({
                "issue_id": provider_issue,
                "mode": mode,
                "conclusion_id": conclusion["conclusion_id"],
                "require_currentness": require_currentness,
                "relation_id": relation.get("relation_id") if relation else None,
                "conclusion": conclusion,
            })
            if require_currentness:
                contribution_id = (
                    f"scoped-provider:{issue_id}:{relation['relation_id']}"
                    if relation else f"scoped-provider:{issue_id}:{provider_issue}"
                )
                result.contributions.add((conclusion["conclusion_id"], contribution_id))

        for binding in providers:
            if not isinstance(binding, dict):
                raise ValidationError("Scoped-v2 provider bindings must be objects")
            read_provider(binding)

        issue_relations = bounded(sorted(
            (item for item in rows("relations", "consumer_issue_id", issue_id)
             if item["active"] and item["relation_type"] != "related_to"),
            key=lambda item: (item["relation_type"], item["provider_issue_id"])),
            "issue provider relation", relation_limit)
        explicit_bindings = {item.get("issue_id"): item for item in providers if isinstance(item, dict)}
        for relation in issue_relations:
            binding = explicit_bindings.get(relation["provider_issue_id"], {"issue_id": relation["provider_issue_id"],
                                                                                "mode": "follow-current"})
            read_provider(binding, relation=relation)

        issue_provider_comparison = [
            {key: row[key] for key in ("relation_id", "consumer_issue_id", "provider_issue_id", "relation_type", "impact_policy")}
            for row in issue_relations
        ]

        nodes = tuple(ScopedNode(item, _binding(evidence_rows[item]), _base_state(evidence_rows[item])) for item in sorted(evidence_rows))
        relations = tuple(ScopedRelation(
            row["relation_id"], row["version_id"], row["source_evidence_id"], row["target_evidence_id"],
            row["source_binding_token"], row["target_binding_token"], row["relation_type"], bool(row["active"]),
        ) for row in heads)
        graph = ScopedSnapshot(issue_id, nodes, relations, SCOPED_V2_RULE_ID)
        solution = solve(graph)
        # Root selection is a preparation concern.  This adapter only consumes
        # the already-frozen descriptor; it never rehydrates roots from a
        # prior conclusion or from the Issue's discovery set.
        roots = [item for item in seeds if item in evidence_rows]
        view = project(graph, roots, solution)
        evidence_json = {item: evidence_rows[item] for item in view["support_ids"]}
        excluded_ids = sorted(set(view["qualification_ids"]) - set(view["support_ids"]))
        excluded_json = {item: evidence_rows[item] for item in excluded_ids if item in evidence_rows}
        result.comparison_context = {
            **view["comparison"],
            "provider_bindings": provider_comparison,
            "issue_relations": issue_provider_comparison,
        }
        result.semantic = result.comparison_context
        result.model_materials = {
            "evidence": evidence_json,
            "excluded_evidence": excluded_json,
            "roots": view["roots"],
            "basis_ids": view["basis_ids"],
            "support_ids": view["support_ids"],
            "candidate_states": [
                {"candidate_id": item, "status": solution.states[item],
                 "reasons": [asdict(reason) for reason in solution.reasons[item]]}
                for item in sorted(evidence_rows)
            ],
            "gap": view["gap"],
            "related_challenges": view["related_challenges"],
            "discovery_ids": view["discovery_ids"],
            "relations": view["qualification_edges"],
            "providers": provider_comparison,
            "issue_relations": issue_provider_comparison,
        }
        result.selection_trace = {
            "heads": heads,
            "rule_id": SCOPED_V2_RULE_ID,
            "states": dict(solution.states),
            "reasons": {key: [asdict(reason) for reason in value] for key, value in solution.reasons.items()},
            "diagnostics": [asdict(reason) for reason in solution.diagnostics],
            "projection": view,
        }
        result.complete = not result.errors
        return result
