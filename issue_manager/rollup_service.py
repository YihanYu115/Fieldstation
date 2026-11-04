from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import deque
from contextlib import nullcontext
from typing import TYPE_CHECKING, Any

from .errors import ConflictError, NotFoundError, ValidationError
from .repositories import IssueRepository
from .store import canonical_json, now
from .strict_json import require_strict_json

if TYPE_CHECKING:
    from .service import IssueManager


ROLLUP_MODES = {
    "local_only",
    "explicit_providers",
    "direct_children",
    "subtree_conclusions",
    "manual_explicit",
}
_ACTIVE_STATUSES = {"draft", "provisional", "accepted", "canonical"}


def compatibility_rollup_policy() -> dict[str, Any]:
    return {
        "policy_version": "rollup-policy/v1",
        "mode": "manual_explicit",
        "required_providers": [],
        "optional_providers": [],
        "accepted_conclusion_statuses": sorted(
            _ACTIVE_STATUSES | {"disputed", "superseded", "retracted"}
        ),
        "allow_stale_providers": True,
        "missing_provider_action": "compatibility",
        "maximum_depth": 0,
        "relation_types": ["depends_on", "rolls_up_from"],
        "cross_sample_allowed": True,
        "required_question_keys": [],
        "question_completion": "compatibility",
    }


class RollupService:
    """Executes frozen Issue rollup policies without treating tree edges as dependencies."""

    def __init__(self, manager: IssueManager):
        self.manager = manager
        self.store = manager.store
        self.issues = IssueRepository(self.store)

    @staticmethod
    def normalize_policy(raw: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise ValidationError("rollup_policy must be an object")
        allowed = {
            "policy_version",
            "mode",
            "required_providers",
            "optional_providers",
            "accepted_conclusion_statuses",
            "allow_stale_providers",
            "missing_provider_action",
            "maximum_depth",
            "relation_types",
            "cross_sample_allowed",
            "required_question_keys",
            "question_completion",
        }
        unknown = sorted(set(raw) - allowed)
        if unknown:
            raise ValidationError(f"Unknown Rollup Policy fields: {unknown}")
        mode = raw.get("mode", "local_only")
        if mode not in ROLLUP_MODES - {"manual_explicit"}:
            raise ValidationError(f"Unsupported Rollup Policy mode: {mode!r}")
        relation_types = raw.get("relation_types", ["depends_on", "rolls_up_from"])
        if not isinstance(relation_types, list) or any(
            item not in {"depends_on", "rolls_up_from", "related_to"}
            for item in relation_types
        ):
            raise ValidationError("Rollup relation_types contains an unsupported value")
        statuses = raw.get("accepted_conclusion_statuses", ["accepted", "canonical"])
        if not isinstance(statuses, list) or any(
            item not in {
                "draft",
                "provisional",
                "accepted",
                "canonical",
                "disputed",
                "superseded",
                "retracted",
            }
            for item in statuses
        ):
            raise ValidationError("Rollup accepted_conclusion_statuses is invalid")
        maximum_depth = raw.get("maximum_depth", 1)
        if (
            isinstance(maximum_depth, bool)
            or not isinstance(maximum_depth, int)
            or maximum_depth < 0
            or maximum_depth > 20
        ):
            raise ValidationError("Rollup maximum_depth must be between 0 and 20")
        missing_action = raw.get("missing_provider_action", "block")
        if missing_action not in {"block", "warn", "ignore"}:
            raise ValidationError("Rollup missing_provider_action must be block, warn, or ignore")
        completion = raw.get("question_completion", "required_only")
        if completion not in {"none", "required_only", "all"}:
            raise ValidationError("Rollup question_completion is invalid")
        required = raw.get("required_providers", [])
        optional = raw.get("optional_providers", [])
        question_keys = raw.get("required_question_keys", [])
        for name, value in (
            ("required_providers", required),
            ("optional_providers", optional),
            ("required_question_keys", question_keys),
        ):
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise ValidationError(f"Rollup {name} must be a string array")
        policy = {
            "policy_version": "rollup-policy/v1",
            "mode": mode,
            "required_providers": list(required),
            "optional_providers": list(optional),
            "accepted_conclusion_statuses": list(statuses),
            "allow_stale_providers": bool(raw.get("allow_stale_providers", False)),
            "missing_provider_action": missing_action,
            "maximum_depth": maximum_depth,
            "relation_types": list(relation_types),
            "cross_sample_allowed": bool(raw.get("cross_sample_allowed", False)),
            "required_question_keys": list(question_keys),
            "question_completion": completion,
        }
        require_strict_json(policy, path="$.rollup_policy")
        return policy

    def snapshot_row(self, issue_id: str, semantic_snapshot: dict[str, Any]) -> dict[str, Any]:
        raw = semantic_snapshot.get("definition", {}).get("rollup_policy")
        policy = self.normalize_policy(raw) if isinstance(raw, dict) else compatibility_rollup_policy()
        encoded = canonical_json(policy)
        return {"issue_id": issue_id, "policy_version": policy["policy_version"], "mode": policy["mode"],
                "policy_json": encoded, "policy_hash": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
                "source_registration_id": semantic_snapshot.get("registration_id"),
                "source_content_hash": semantic_snapshot.get("registration_content_hash"),
                "created_at": None, "created_by": None}

    def ensure_snapshot(
        self,
        issue_id: str,
        semantic_snapshot: dict[str, Any],
        *,
        actor: str,
        conn: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        snapshot_row = self.snapshot_row(issue_id, semantic_snapshot)
        policy_json, policy_hash = snapshot_row["policy_json"], snapshot_row["policy_hash"]
        policy = json.loads(policy_json)
        transaction = self.store.transaction() if conn is None else nullcontext(conn)
        with transaction as active:
            existing = active.execute(
                "SELECT * FROM issue_rollup_policies WHERE issue_id=?", (issue_id,)
            ).fetchone()
            if existing:
                if existing["policy_hash"] != policy_hash:
                    raise ConflictError(
                        "Issue already has a different frozen Rollup Policy",
                        details={"issue_id": issue_id, "policy_hash": existing["policy_hash"]},
                    )
                return self.show_policy(issue_id)
            active.execute(
                "INSERT INTO issue_rollup_policies VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    issue_id,
                    policy["policy_version"],
                    policy["mode"],
                    policy_json,
                    policy_hash,
                    semantic_snapshot.get("registration_id"),
                    semantic_snapshot.get("registration_content_hash"),
                    now(),
                    actor,
                ),
            )
        return {
            "issue_id": issue_id,
            "policy": policy,
            "policy_hash": policy_hash,
            "mode": policy["mode"],
        }

    def show_policy(self, issue_id: str, *, state_view=None) -> dict[str, Any]:
        row = (dict(state_view.rollup_policies[issue_id]) if state_view is not None and issue_id in state_view.rollup_policies else self.store.row(
            "SELECT * FROM issue_rollup_policies WHERE issue_id=?", (issue_id,)
        ))
        if not row:
            raise NotFoundError(f"Frozen Rollup Policy not found for Issue {issue_id}")
        row["policy"] = json.loads(row.pop("policy_json"))
        return row

    def _candidate_provider_ids(
        self, issue_id: str, policy: dict[str, Any], *, state_view=None
    ) -> list[str]:
        mode = policy["mode"]
        if mode in {"local_only", "manual_explicit"}:
            return []
        if mode == "explicit_providers":
            relation_types = policy["relation_types"]
            if state_view is not None:
                return sorted({row["provider_issue_id"] for row in state_view.context_rows("relations", "consumer_issue_id", issue_id)
                               if row["active"] and row["relation_type"] in relation_types})
            placeholders = ",".join("?" for _ in relation_types)
            return [
                row["provider_issue_id"]
                for row in self.store.rows(
                    f"SELECT DISTINCT provider_issue_id FROM relations WHERE consumer_issue_id=? "
                    f"AND active=1 AND relation_type IN ({placeholders}) ORDER BY provider_issue_id",
                    (issue_id, *relation_types),
                )
            ]
        def children(parent):
            rows = (state_view.context_rows("issues", "parent_issue_id", parent) if state_view is not None
                    else self.store.rows("SELECT * FROM issues WHERE parent_issue_id=?", (parent,)))
            return sorted((row for row in rows if row["work_status"] not in {"void", "archived"}), key=lambda row: row["issue_id"])

        if mode == "direct_children":
            return [row["issue_id"] for row in children(issue_id)]
        maximum = int(policy["maximum_depth"])
        queue: deque[tuple[str, int]] = deque([(issue_id, 0)])
        seen = {issue_id}
        result: list[str] = []
        while queue:
            current, depth = queue.popleft()
            if depth >= maximum:
                continue
            for row in children(current):
                child = row["issue_id"]
                if child in seen:
                    continue
                seen.add(child)
                result.append(child)
                queue.append((child, depth + 1))
        return result

    def preview(self, issue_id: str, *, state_view=None) -> dict[str, Any]:
        consumer = state_view.issue(issue_id) if state_view is not None else self.issues.require(issue_id)
        frozen = self.show_policy(issue_id, state_view=state_view)
        policy = frozen["policy"]
        provider_ids = self._candidate_provider_ids(issue_id, policy, state_view=state_view)
        required_ids = set(policy["required_providers"])
        optional_ids = set(policy["optional_providers"])
        if policy["mode"] == "explicit_providers" and not required_ids:
            required_ids = {
                row["provider_issue_id"]
                for row in self.store.rows(
                    "SELECT provider_issue_id FROM relations WHERE consumer_issue_id=? "
                    "AND active=1 AND impact_policy='hard'",
                    (issue_id,),
                )
            }
            if state_view is not None:
                required_ids = {row["provider_issue_id"] for row in state_view.context_rows("relations", "consumer_issue_id", issue_id)
                                if row["active"] and row["impact_policy"] == "hard"}
        provider_ids = sorted(set(provider_ids) | required_ids | optional_ids)
        providers: list[dict[str, Any]] = []
        blockers: list[dict[str, Any]] = []
        warnings: list[dict[str, Any]] = []
        for provider_id in provider_ids:
            provider = state_view.issue(provider_id) if state_view is not None else self.issues.require(provider_id)
            required = provider_id in required_ids or provider_id not in optional_ids
            card = {
                "issue_id": provider_id,
                "required": required,
                "current_conclusion_id": provider.get("current_conclusion_id"),
                "conclusion_revision": provider["conclusion_revision"],
                "conclusion_status": provider["conclusion_status"],
                "freshness": provider["freshness"],
            }
            provider_scope = provider.get("normalized_scope_key")
            consumer_scope = consumer.get("normalized_scope_key")
            cross_sample = bool(
                provider_scope and consumer_scope and provider_scope != consumer_scope
            )
            card["cross_sample"] = cross_sample
            reasons: list[str] = []
            if not provider.get("current_conclusion_id"):
                reasons.append("missing_current_conclusion")
            elif provider["conclusion_status"] not in policy["accepted_conclusion_statuses"]:
                reasons.append("conclusion_status_not_accepted")
            if not policy["allow_stale_providers"] and provider["freshness"] != "fresh":
                reasons.append("provider_not_fresh")
            if cross_sample and not policy["cross_sample_allowed"]:
                reasons.append("cross_sample_provider_not_allowed")
            card["blockers"] = reasons
            providers.append(card)
            if reasons:
                target = blockers if required and policy["missing_provider_action"] == "block" else warnings
                target.append({"provider_issue_id": provider_id, "reasons": reasons})
        return {
            "rollup_preview_version": "conclusion-rollup-preview/v1",
            "issue_id": issue_id,
            "policy_hash": frozen["policy_hash"],
            "mode": policy["mode"],
            "providers": providers,
            "blockers": blockers,
            "warnings": warnings,
            "basis": [
                {
                    "issue_id": item["issue_id"],
                    "conclusion_id": item["current_conclusion_id"],
                    "conclusion_revision": item["conclusion_revision"],
                }
                for item in providers
                if item["current_conclusion_id"] and not item["blockers"]
            ],
        }

    def publication_gate(
        self, issue_id: str, proposal: dict[str, Any], *, state_view=None
    ) -> dict[str, Any]:
        if state_view is None:
            self.issues.require(issue_id)
        else:
            state_view.issue(issue_id)
        frozen = self.show_policy(issue_id, state_view=state_view)
        policy = frozen["policy"]
        blockers: list[dict[str, Any]] = []
        warnings: list[dict[str, Any]] = []

        hard_relations = self.store.rows(
            "SELECT r.provider_issue_id,p.current_conclusion_id,p.freshness,p.conclusion_status "
            "FROM relations r JOIN issues p ON p.issue_id=r.provider_issue_id "
            "WHERE r.consumer_issue_id=? AND r.active=1 AND r.impact_policy='hard' "
            "ORDER BY r.provider_issue_id",
            (issue_id,),
        )
        if state_view is not None:
            provider_ids = {row["provider_issue_id"] for row in state_view.context_rows("relations", "consumer_issue_id", issue_id)
                            if row["active"] and row["impact_policy"] == "hard"}
            hard_relations = [{**state_view.issue(provider_id), "provider_issue_id": provider_id}
                              for provider_id in sorted(provider_ids)]
        basis_ids = {
            item.get("issue_id")
            for item in proposal.get("basis", [])
            if isinstance(item, dict)
        }
        for relation in hard_relations:
            provider_id = relation["provider_issue_id"]
            if not relation["current_conclusion_id"]:
                blockers.append(
                    {"code": "hard_provider_missing_conclusion", "provider_issue_id": provider_id}
                )
            elif provider_id not in basis_ids:
                blockers.append(
                    {"code": "hard_provider_missing_from_basis", "provider_issue_id": provider_id}
                )
            elif relation["freshness"] != "fresh":
                blockers.append(
                    {
                        "code": "hard_provider_not_fresh",
                        "provider_issue_id": provider_id,
                        "freshness": relation["freshness"],
                    }
                )

        if policy["mode"] not in {"manual_explicit", "local_only"}:
            preview = self.preview(issue_id, state_view=state_view)
            blockers.extend(preview["blockers"])
            warnings.extend(preview["warnings"])

        required_keys = set(policy.get("required_question_keys", []))
        completion = policy.get("question_completion", "none")
        if completion != "none":
            questions = self.store.rows(
                "SELECT question_id,question_key,status FROM issue_questions WHERE issue_id=? "
                "ORDER BY priority DESC,question_id",
                (issue_id,),
            )
            if state_view is not None:
                identities = {row["question_id"] for row in questions}
                identities.update(identity for identity, row in state_view.virtual_questions.items() if row["issue_id"] == issue_id)
                questions = [state_view.question(identity) for identity in sorted(identities)]
            for question in questions:
                required = completion == "all" or question["question_key"] in required_keys
                if required and question["status"] != "answered":
                    blockers.append(
                        {
                            "code": "required_question_unanswered",
                            "question_id": question["question_id"],
                            "question_key": question["question_key"],
                        }
                    )

        evidence_ids = {
            str(item)
            for item in proposal.get("evidence_refs", [])
            if isinstance(item, str)
        }
        for use in proposal.get("evidence_uses", []) or []:
            if isinstance(use, dict) and isinstance(use.get("evidence_id"), str):
                evidence_ids.add(use["evidence_id"])
        if evidence_ids:
            placeholders = ",".join("?" for _ in evidence_ids)
            unresolved = self.store.rows(
                "SELECT r.consumer_evidence_id,r.provider_evidence_id,p.lifecycle_status,"
                "p.quality_status FROM evidence_relations r JOIN evidence_refs p "
                "ON p.evidence_id=r.provider_evidence_id "
                f"WHERE r.active=1 AND r.impact_policy='hard' AND r.consumer_evidence_id IN ({placeholders}) "
                "AND (p.lifecycle_status<>'active' OR p.quality_status='unusable_for_purpose')",
                tuple(sorted(evidence_ids)),
            )
            if state_view is not None:
                unresolved = []
                for evidence_id in sorted(evidence_ids):
                    for relation in state_view.context_rows("evidence_relations", "consumer_evidence_id", evidence_id):
                        if not relation["active"] or relation["impact_policy"] != "hard":
                            continue
                        provider = state_view.evidence(relation["provider_evidence_id"])
                        if provider["lifecycle_status"] != "active" or provider["quality_status"] == "unusable_for_purpose":
                            unresolved.append({"consumer_evidence_id": evidence_id,
                                               "provider_evidence_id": provider["evidence_id"],
                                               "lifecycle_status": provider["lifecycle_status"],
                                               "quality_status": provider["quality_status"]})
            blockers.extend(
                {"code": "unresolved_hard_evidence_dependency", **row}
                for row in unresolved
            )
        return {
            "publication_gate_version": "conclusion-publication-gate/v1",
            "issue_id": issue_id,
            "policy_hash": frozen["policy_hash"],
            "allowed": not blockers,
            "blockers": blockers,
            "warnings": warnings,
        }

    def require_publication_allowed(
        self, issue_id: str, proposal: dict[str, Any], *, state_view=None
    ) -> dict[str, Any]:
        result = self.publication_gate(issue_id, proposal, state_view=state_view)
        if not result["allowed"]:
            summary = ", ".join(
                f"{item.get('code', 'rollup_blocker')}"
                + (
                    f"({item['provider_issue_id']})"
                    if item.get("provider_issue_id")
                    else ""
                )
                for item in result["blockers"]
            )
            raise ConflictError(
                f"Conclusion publication is blocked by frozen Rollup Policy: {summary}",
                details=result,
            )
        return result
