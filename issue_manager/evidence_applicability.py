"""Pure, deterministic algebra for scoped Evidence applicability.

This module deliberately has no database, model, clock, or currentness
dependencies.  It consumes snapshots and already-selected decision heads and
returns a rebuildable projection.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

APPLICABILITY_RULE_ID = "evidence-applicability/v1"
SCOPE_KIND = "issue_conclusion"
EFFECTS = frozenset({"include", "exclude"})


@dataclass(frozen=True)
class EvidenceTargetSnapshot:
    evidence_id: str
    semantic_revision: int
    proof_id: str | None
    manifest_id: str | None


@dataclass(frozen=True)
class DecisionHead:
    decision_key: str
    decision_version_id: str
    active: bool
    scope_kind: str
    scope_issue_id: str
    target_binding: str
    target_evidence_id: str
    target_semantic_revision: int
    target_proof_id: str | None
    target_manifest_id: str | None
    effect: str
    basis_json: Any
    rule_id: str
    qualification_json: Any
    changeset_id: str | None = None


@dataclass(frozen=True)
class ApplicabilityResult:
    evidence_id: str
    state: str
    qualified_effects: tuple[str, ...]
    decision_version_ids: tuple[str, ...]
    nonmatching_decision_version_ids: tuple[str, ...]
    nonmatching_heads: tuple[dict[str, str], ...]
    errors: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "state": self.state,
            "qualified_effects": list(self.qualified_effects),
            "decision_version_ids": list(self.decision_version_ids),
            "nonmatching_decision_version_ids": list(self.nonmatching_decision_version_ids),
            "nonmatching_heads": [dict(item) for item in self.nonmatching_heads],
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class ApplicabilityProjection:
    scope_issue_id: str
    results: tuple[ApplicabilityResult, ...]

    def by_evidence_id(self) -> dict[str, ApplicabilityResult]:
        return {item.evidence_id: item for item in self.results}

    def as_dict(self) -> dict[str, Any]:
        states: dict[str, list[str]] = {"included": [], "excluded": [], "unresolved": []}
        for item in self.results:
            states[item.state].append(item.evidence_id)
        return {
            "scope": {"kind": SCOPE_KIND, "issue_id": self.scope_issue_id},
            "included": sorted(states["included"]),
            "excluded": sorted(states["excluded"]),
            "unresolved": sorted(states["unresolved"]),
            "evidence": [item.as_dict() for item in self.results],
        }


_BASIS_REQUIRED_FIELDS = {
    "evidence_version": frozenset(
        {"kind", "evidence_id", "semantic_revision", "proof_id", "manifest_id", "snapshot"}
    ),
    "conclusion_version": frozenset({"kind", "conclusion_id"}),
    "record_version": frozenset({"kind", "record_revision_id"}),
    "relation_version": frozenset({"kind", "version_id"}),
    "applicability_decision_version": frozenset({"kind", "decision_version_id"}),
}


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    if hasattr(value, "__dataclass_fields__"):
        return {name: getattr(value, name) for name in value.__dataclass_fields__}
    return {}


def _parse_json(value: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value


def basis_structure_errors(value: Any) -> tuple[str, ...]:
    """Check the portable fixed-typed shape; existence is checked by the service."""
    try:
        basis = _parse_json(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return ("basis_json_invalid",)
    if not isinstance(basis, list) or not basis:
        return ("basis_empty_or_not_array",)
    errors: set[str] = set()
    identities: set[tuple[str, str]] = set()
    for item in basis:
        if not isinstance(item, Mapping):
            errors.add("basis_item_not_object")
            continue
        kind = item.get("kind")
        if not isinstance(kind, str):
            errors.add("basis_kind_unknown")
            continue
        required = _BASIS_REQUIRED_FIELDS.get(kind)
        if required is None:
            errors.add("basis_kind_unknown")
            continue
        if not required.issubset(item):
            errors.add("basis_typed_reference_incomplete")
            continue
        identity_field = {
            "evidence_version": "evidence_id",
            "conclusion_version": "conclusion_id",
            "record_version": "record_revision_id",
            "relation_version": "version_id",
            "applicability_decision_version": "decision_version_id",
        }[kind]
        identity = item.get(identity_field)
        if not isinstance(identity, str) or not identity.strip():
            errors.add("basis_identity_invalid")
            continue
        if (kind, identity) in identities:
            errors.add("basis_duplicate_reference")
        identities.add((kind, identity))
        if kind == "evidence_version":
            revision = item.get("semantic_revision")
            snapshot = item.get("snapshot")
            if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
                errors.add("basis_evidence_revision_invalid")
            if item.get("proof_id") is not None and not isinstance(item.get("proof_id"), str):
                errors.add("basis_evidence_proof_invalid")
            if item.get("manifest_id") is not None and not isinstance(item.get("manifest_id"), str):
                errors.add("basis_evidence_manifest_invalid")
            if not isinstance(snapshot, Mapping):
                errors.add("basis_evidence_snapshot_invalid")
            else:
                if snapshot.get("semantic_revision") != revision:
                    errors.add("basis_evidence_snapshot_revision_mismatch")
                if snapshot.get("proof_id") != item.get("proof_id"):
                    errors.add("basis_evidence_snapshot_proof_mismatch")
                if snapshot.get("manifest_id") != item.get("manifest_id"):
                    errors.add("basis_evidence_snapshot_manifest_mismatch")
    return tuple(sorted(errors))


def qualification_structure_errors(
    value: Any, *, rule_id: str, changeset_id: str | None = None
) -> tuple[str, ...]:
    """Validate the frozen qualification receipt envelope, not live authority.

    Live actor capabilities are intentionally not consulted: the plan freezes
    qualification when applied, so later capability changes cannot rewrite Q.
    """
    try:
        receipt = _parse_json(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return ("qualification_json_invalid",)
    if not isinstance(receipt, Mapping):
        return ("qualification_not_object",)
    errors: set[str] = set()
    allowed_fields = {
        "actor_id", "run_id", "capability", "changeset_id", "changeset_hash",
        "risk_tier", "review_ids", "rule_id", "validation_results",
    }
    if set(receipt) != allowed_fields:
        errors.add("qualification_fields_not_canonical")
    for field in ("actor_id", "run_id", "changeset_id", "changeset_hash"):
        if not isinstance(receipt.get(field), str) or not receipt[field].strip():
            errors.add(f"qualification_{field}_missing")
    if receipt.get("capability") != "evidence.applicability.write":
        errors.add("qualification_capability_invalid")
    if receipt.get("rule_id") != rule_id or rule_id != APPLICABILITY_RULE_ID:
        errors.add("qualification_rule_mismatch")
    if changeset_id is not None and receipt.get("changeset_id") != changeset_id:
        errors.add("qualification_changeset_mismatch")
    risk_tier = receipt.get("risk_tier")
    if not isinstance(risk_tier, str) or risk_tier not in {"T0", "T1", "T2", "T3"}:
        errors.add("qualification_risk_tier_invalid")
    reviews = receipt.get("review_ids")
    if not isinstance(reviews, list) or any(
        not isinstance(item, str) or not item.strip() for item in reviews
    ):
        errors.add("qualification_review_ids_invalid")
    elif len(reviews) != len(set(reviews)):
        errors.add("qualification_review_ids_duplicate")
    elif reviews != sorted(reviews):
        errors.add("qualification_review_ids_not_normalized")
    checks = receipt.get("validation_results")
    expected_checks = {"scope", "target", "basis", "capability", "risk", "reviews"}
    if not isinstance(checks, Mapping) or set(checks) != expected_checks:
        errors.add("qualification_validation_results_incomplete")
    elif any(checks.get(name) is not True for name in expected_checks):
        errors.add("qualification_validation_failed")
    return tuple(sorted(errors))


def _candidate_snapshot(value: Any, evidence_id: str) -> dict[str, Any]:
    snapshot = _mapping(value)
    if not snapshot and isinstance(value, Mapping):
        snapshot = value
    candidate_id = snapshot.get("evidence_id", evidence_id)
    revision = snapshot.get("semantic_revision")
    proof_id = snapshot.get("proof_id", snapshot.get("current_proof_id"))
    manifest_id = snapshot.get("manifest_id", snapshot.get("current_manifest_id"))
    return {
        "evidence_id": candidate_id,
        "semantic_revision": revision,
        "proof_id": proof_id,
        "manifest_id": manifest_id,
    }


def _head_mapping(value: Any) -> dict[str, Any]:
    return dict(_mapping(value))


def evaluate_applicability(
    *,
    scope_issue_id: str,
    candidate_snapshots: Mapping[str, Any] | Iterable[Any],
    current_heads: Iterable[Any],
    accepted_rule_ids: Iterable[str],
) -> ApplicabilityProjection:
    """Reduce current decision heads over candidate Evidence snapshots.

    Invalid or unexplainable matching decisions conservatively produce
    ``unresolved``.  Only a consistent set containing ``exclude`` excludes.
    Inputs are normalized by stable identities; timing, row order, rowid and
    confidence fields are never read.
    """
    if not isinstance(scope_issue_id, str) or not scope_issue_id.strip():
        raise ValueError("scope_issue_id must be a non-empty stable Issue identity")
    if isinstance(candidate_snapshots, Mapping):
        raw_candidates = [
            (_candidate_snapshot(value, str(key))) for key, value in candidate_snapshots.items()
        ]
    else:
        raw_candidates = []
        for value in candidate_snapshots:
            raw = _mapping(value)
            candidate_id = raw.get("evidence_id")
            raw_candidates.append(_candidate_snapshot(value, str(candidate_id or "")))
    candidate_alternatives: dict[str, set[str]] = {}
    duplicate_candidate_ids: set[str] = set()
    for snapshot in raw_candidates:
        evidence_id = snapshot["evidence_id"]
        if not isinstance(evidence_id, str) or not evidence_id.strip():
            continue
        encoded = json.dumps(
            snapshot, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":")
        )
        candidate_alternatives.setdefault(evidence_id, set()).add(encoded)
        if len(candidate_alternatives[evidence_id]) > 1:
            duplicate_candidate_ids.add(evidence_id)
    candidates = {
        evidence_id: json.loads(sorted(alternatives)[0])
        for evidence_id, alternatives in candidate_alternatives.items()
    }

    normalized_heads = [_head_mapping(value) for value in current_heads]
    # Deduplicate exact repeated records without considering non-semantic SQL columns.
    semantic_head_fields = (
        "decision_key",
        "decision_version_id",
        "active",
        "scope_kind",
        "scope_issue_id",
        "target_binding",
        "target_evidence_id",
        "target_semantic_revision",
        "target_proof_id",
        "target_manifest_id",
        "effect",
        "basis_json",
        "rule_id",
        "qualification_json",
        "changeset_id",
    )
    unique_heads: dict[str, dict[str, Any]] = {}
    for head in normalized_heads:
        semantic = {key: head.get(key) for key in semantic_head_fields if key in head}
        identity = json.dumps(
            semantic, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":")
        )
        unique_heads[identity] = semantic
    normalized_heads = list(unique_heads.values())
    normalized_heads.sort(
        key=lambda head: (
            str(head.get("decision_key", "")),
            str(head.get("decision_version_id", "")),
        )
    )
    accepted = frozenset(accepted_rule_ids)

    results: list[ApplicabilityResult] = []
    for evidence_id in sorted(candidates):
        candidate = candidates[evidence_id]
        errors: set[str] = set()
        effects: set[str] = set()
        participating: set[str] = set()
        nonmatching: dict[tuple[str, str], dict[str, str]] = {}
        if evidence_id in duplicate_candidate_ids:
            errors.add("candidate_snapshot_conflict")
        revision = candidate["semantic_revision"]
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            errors.add("candidate_snapshot_invalid")

        matching_by_key: dict[str, set[str]] = {}
        for head in normalized_heads:
            target_id = head.get("target_evidence_id")
            if target_id != evidence_id:
                continue
            decision_id = head.get("decision_version_id")
            if head.get("active") not in (True, 1):
                if head.get("active") not in (False, 0):
                    errors.add("decision_active_flag_invalid")
                continue
            reason = None
            if head.get("scope_kind") != SCOPE_KIND or head.get("scope_issue_id") != scope_issue_id:
                reason = "scope_mismatch"
            elif head.get("target_binding") != "fixed":
                # A follow-current/unknown binding is malformed, not a match.
                errors.add("decision_target_binding_invalid")
                reason = "target_binding_invalid"
            elif (
                head.get("target_semantic_revision") != candidate["semantic_revision"]
                or head.get("target_proof_id") != candidate["proof_id"]
                or head.get("target_manifest_id") != candidate["manifest_id"]
            ):
                reason = "fixed_target_snapshot_mismatch"
            if reason:
                item = {"decision_version_id": str(decision_id or ""), "reason": reason}
                nonmatching[(item["decision_version_id"], reason)] = item
                continue

            version_id = decision_id if isinstance(decision_id, str) and decision_id else ""
            if (
                not version_id
                or not isinstance(head.get("decision_key"), str)
                or not head.get("decision_key")
            ):
                errors.add("decision_identity_invalid")
            if version_id:
                participating.add(version_id)
            key = str(head.get("decision_key", ""))
            matching_by_key.setdefault(key, set()).add(version_id)
            rule_id = head.get("rule_id")
            if not isinstance(rule_id, str) or rule_id not in accepted:
                errors.add("decision_rule_unaccepted")
            effect = head.get("effect")
            if not isinstance(effect, str) or effect not in EFFECTS:
                errors.add("decision_effect_invalid")
            else:
                head_errors = basis_structure_errors(head.get("basis_json"))
                errors.update(head_errors)
                qualification_errors = qualification_structure_errors(
                    head.get("qualification_json"),
                    rule_id=str(rule_id or ""),
                    changeset_id=head.get("changeset_id"),
                )
                errors.update(qualification_errors)
                if (
                    not head_errors
                    and not qualification_errors
                    and isinstance(rule_id, str)
                    and rule_id in accepted
                ):
                    effects.add(str(head["effect"]))

        for versions in matching_by_key.values():
            if len(versions) > 1:
                errors.add("multiple_active_heads_for_decision_key")
        if errors:
            state = "unresolved"
        elif effects == {"exclude"}:
            state = "excluded"
        elif effects in (set(), {"include"}):
            state = "included"
        else:
            state = "unresolved"
        results.append(
            ApplicabilityResult(
                evidence_id=evidence_id,
                state=state,
                qualified_effects=tuple(sorted(effects)),
                decision_version_ids=tuple(sorted(participating)),
                nonmatching_decision_version_ids=tuple(
                    sorted(
                        {
                            item["decision_version_id"]
                            for item in nonmatching.values()
                            if item["decision_version_id"]
                        }
                    )
                ),
                nonmatching_heads=tuple(nonmatching[key] for key in sorted(nonmatching)),
                errors=tuple(sorted(errors)),
            )
        )
    return ApplicabilityProjection(scope_issue_id=scope_issue_id, results=tuple(results))
