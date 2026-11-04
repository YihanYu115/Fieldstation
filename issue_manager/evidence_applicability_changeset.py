"""Shared planner and transactional writer for Q ChangeSet operations.

All action, CAS, fixed-target and typed-basis semantics live here.  The
operation preflight, StateView simulation and transactional executor call the
same planner so their interpretation cannot drift.
"""

from __future__ import annotations

import json
from typing import Any

from .errors import ConflictError, ValidationError
from .evidence_applicability import APPLICABILITY_RULE_ID, SCOPE_KIND, basis_structure_errors
from .store import canonical_json, now

_ACTIONS = {"add", "replace", "disable", "enable"}
_DEFINITION_KEYS = {"scope", "target", "effect", "basis"}
_BASIS_IDENTITY_FIELDS = {
    "evidence_version": "evidence_id",
    "conclusion_version": "conclusion_id",
    "record_version": "record_revision_id",
    "relation_version": "version_id",
    "applicability_decision_version": "decision_version_id",
}


class EvidenceApplicabilityChangeSetPlanner:
    """Single semantic planner plus the narrow Q persistence boundary."""

    def __init__(self, manager: Any):
        self.manager = manager
        self.store = manager.store

    @staticmethod
    def _nonempty(value: Any, label: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{label} must be a non-empty string")
        return value

    def _definition(self, state_view, value: Any, *, own_version_id: str) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != _DEFINITION_KEYS:
            raise ValidationError("definition must contain exactly scope, target, effect and basis")
        scope = value["scope"]
        if not isinstance(scope, dict) or set(scope) != {"kind", "issue_id"}:
            raise ValidationError("definition.scope must contain exactly kind and issue_id")
        if scope.get("kind") != SCOPE_KIND:
            raise ValidationError("Applicability Scope kind must be issue_conclusion")
        issue_id = self._nonempty(scope.get("issue_id"), "scope.issue_id")
        state_view.issue(issue_id)

        target = value["target"]
        target_fields = {
            "kind", "evidence_id", "binding", "semantic_revision", "proof_id", "manifest_id"
        }
        if not isinstance(target, dict) or set(target) != target_fields:
            raise ValidationError("definition.target is incomplete or contains unsupported fields")
        if target.get("kind") != "evidence_version" or target.get("binding") != "fixed":
            raise ValidationError("Applicability target must use a fixed Evidence version")
        evidence_id = self._nonempty(target.get("evidence_id"), "target.evidence_id")
        evidence = state_view.evidence(evidence_id)
        revision = target.get("semantic_revision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise ValidationError("target.semantic_revision must be a non-negative integer")
        proof_id, manifest_id = target.get("proof_id"), target.get("manifest_id")
        if proof_id is not None:
            self._nonempty(proof_id, "target.proof_id")
        if manifest_id is not None:
            self._nonempty(manifest_id, "target.manifest_id")
        current = {
            "semantic_revision": int(evidence["semantic_revision"]),
            "proof_id": evidence.get("current_proof_id"),
            "manifest_id": evidence.get("current_manifest_id"),
        }
        if {
            "semantic_revision": revision,
            "proof_id": proof_id,
            "manifest_id": manifest_id,
        } != current:
            raise ConflictError(
                "Applicability target snapshot is stale",
                details={"evidence_id": evidence_id, "expected": {
                    "semantic_revision": revision, "proof_id": proof_id, "manifest_id": manifest_id
                }, "current": current},
            )

        effect = value["effect"]
        if not isinstance(effect, str) or effect not in {"include", "exclude"}:
            raise ValidationError("definition.effect must be include or exclude")
        basis = value["basis"]
        basis_errors = basis_structure_errors(basis)
        if basis_errors:
            raise ValidationError("Applicability basis is invalid", details={"basis_errors": list(basis_errors)})
        normalized_basis = []
        for item in basis:
            kind = item["kind"]
            expected_fields = (
                {"kind", "evidence_id", "semantic_revision", "proof_id", "manifest_id", "snapshot"}
                if kind == "evidence_version"
                else {"kind", _BASIS_IDENTITY_FIELDS[kind]}
            )
            if set(item) != expected_fields:
                raise ValidationError(f"{kind} basis item is incomplete or contains unsupported fields")
            if kind == "evidence_version":
                snapshot = item["snapshot"]
                if not isinstance(snapshot, dict) or set(snapshot) != {
                    "semantic_revision", "proof_id", "manifest_id"
                }:
                    raise ValidationError("Evidence basis snapshot has unsupported fields")
            basis_item = json.loads(canonical_json(item))
            errors = self.manager.evidence_applicability._validate_basis_reference(
                basis_item, own_version_id=own_version_id, state_view=state_view
            )
            if errors:
                stale = any("revision" in error or "snapshot_mismatch" in error for error in errors)
                error_type = ConflictError if stale else ValidationError
                raise error_type(
                    "Applicability basis no longer resolves to the submitted fixed material",
                    details={"basis_errors": errors},
                )
            normalized_basis.append(basis_item)
        normalized_basis.sort(
            key=lambda item: (item["kind"], item[_BASIS_IDENTITY_FIELDS[item["kind"]]])
        )
        return {
            "scope_kind": SCOPE_KIND,
            "scope_issue_id": issue_id,
            "target_binding": "fixed",
            "target_evidence_id": evidence_id,
            "target_semantic_revision": revision,
            "target_proof_id": proof_id,
            "target_manifest_id": manifest_id,
            "effect": effect,
            "basis": normalized_basis,
            "rule_id": APPLICABILITY_RULE_ID,
        }

    def plan(self, operation: dict[str, Any], *, state_view) -> dict[str, Any]:
        """Validate one operation and return its deterministic before/after plan."""
        if operation.get("op") != "evidence_applicability_decision":
            raise ValidationError("Applicability planner received a different operation")
        action = operation.get("action")
        if not isinstance(action, str) or action not in _ACTIONS:
            raise ValidationError("Unsupported evidence applicability action")
        key = self._nonempty(operation.get("decision_key"), "decision_key")
        reason = self._nonempty(operation.get("reason"), "reason")
        expected_version = operation.get("expected_version_id")
        expected_active = operation.get("expected_active")
        if not isinstance(expected_version, str) or not isinstance(expected_active, bool):
            raise ValidationError("expected_version_id and expected_active are required")

        current = state_view.applicability_head(key)
        history = state_view.applicability_versions_for_key(key)
        if action == "add":
            if expected_version != "" or expected_active is not False:
                raise ValidationError("add requires expected_version_id='' and expected_active=false")
            if "definition" not in operation:
                raise ValidationError("add requires a complete definition")
            if current is not None or history:
                raise ConflictError("Applicability decision key already exists")
            version_number = 1
            previous_version_id = None
            active = True
        elif action == "replace":
            if "definition" not in operation:
                raise ValidationError("replace requires a complete definition")
            if current is None:
                raise ConflictError("Applicability decision head does not exist")
            if expected_version != current["decision_version_id"] or expected_active is not bool(current["active"]):
                raise ConflictError("Applicability decision head changed; expected version/active CAS failed")
            version_number = int(current["version_number"]) + 1
            previous_version_id = current["decision_version_id"]
            active = bool(current["active"])
        else:
            if "definition" in operation:
                raise ValidationError(f"{action} does not accept a definition")
            if current is None:
                raise ConflictError("Applicability decision head does not exist")
            if expected_version != current["decision_version_id"] or expected_active is not bool(current["active"]):
                raise ConflictError("Applicability decision head changed; expected version/active CAS failed")
            desired_active = action == "enable"
            if bool(current["active"]) == desired_active:
                raise ConflictError(f"Applicability decision is already {'active' if desired_active else 'inactive'}")
            version_number = int(current["version_number"])
            previous_version_id = current.get("previous_version_id")
            active = desired_active

        version = None
        if action in {"add", "replace"}:
            version_id = f"applicability:{key}:{version_number}"
            definition = self._definition(state_view, operation.get("definition"), own_version_id=version_id)
            persisted_definition = {key_name: value for key_name, value in definition.items()
                                    if key_name != "basis"}
            version = {
                "decision_version_id": version_id,
                "decision_key": key,
                "version_number": version_number,
                "previous_version_id": previous_version_id,
                **persisted_definition,
                "basis_json": canonical_json(definition["basis"]),
                "qualification_json": None,
                "reason": reason,
            }
        else:
            version = {key_name: current.get(key_name) for key_name in (
                "decision_version_id", "decision_key", "version_number", "previous_version_id",
                "scope_kind", "scope_issue_id", "target_binding", "target_evidence_id",
                "target_semantic_revision", "target_proof_id", "target_manifest_id", "effect",
                "basis_json", "rule_id", "qualification_json", "reason", "changeset_id",
            )}
            version["basis"] = json.loads(version["basis_json"])
            version["reason"] = reason

        after_head = {
            "decision_key": key,
            "decision_version_id": version["decision_version_id"],
            "active": active,
            "head_revision": int(current["head_revision"]) + 1 if current else 1,
        }
        return {
            "action": action,
            "decision_key": key,
            "reason": reason,
            "before_head": current,
            "before_version": current,
            "version": version if action in {"add", "replace"} else None,
            "after_version": version,
            "after_head": after_head,
        }

    def simulate(self, operation: dict[str, Any], *, state_view) -> dict[str, Any]:
        plan = self.plan(operation, state_view=state_view)
        state_view.stage_applicability_plan(plan)
        return plan

    @staticmethod
    def _qualification(operation_context, plan: dict[str, Any]) -> dict[str, Any]:
        auth = operation_context.auth
        auth.require("evidence.applicability.write")
        assessment = operation_context.grant.assessment
        review_ids = sorted(
            review["review_id"] for review in operation_context.reviews
            if review.get("decision") == "pass"
        )
        if len(review_ids) < assessment.required_reviews:
            raise ConflictError("Applicability qualification is missing required ChangeSet reviews")
        return {
            "actor_id": auth.actor_id,
            "run_id": auth.run_id,
            "capability": "evidence.applicability.write",
            "changeset_id": operation_context.changeset_id,
            "changeset_hash": operation_context.changeset_hash,
            "risk_tier": assessment.tier,
            "review_ids": review_ids,
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

    def execute(self, operation: dict[str, Any], *, context) -> dict[str, Any]:
        """Replan under the ChangeSet transaction, CAS and write Q plus audit."""
        context.auth.require("evidence.applicability.write")
        from .changeset_state import StateView

        state_view = StateView(self.manager)
        plan = self.plan(operation, state_view=state_view)
        qualification = self._qualification(context, plan)
        qualification_json = canonical_json(qualification)
        version = plan["version"]
        before_head = plan["before_head"]
        timestamp = now()
        if version is not None:
            version_payload = {
                **{key: value for key, value in version.items() if key != "basis"},
                "qualification_json": qualification_json,
                "changeset_id": context.changeset_id,
                "created_at": timestamp,
                "created_by": context.auth.actor_id,
                "run_id": context.auth.run_id,
            }
            columns = ",".join(version_payload)
            marks = ",".join("?" for _ in version_payload)
            self.store.fault("evidence_applicability.before_version_insert")
            try:
                self.store.conn.execute(
                    f"INSERT INTO evidence_applicability_decision_versions({columns}) VALUES ({marks})",
                    tuple(version_payload.values()),
                )
            except Exception as exc:
                if "IntegrityError" in type(exc).__name__:
                    raise ConflictError("Applicability decision version conflicted with a concurrent change") from exc
                raise
            self.store.fault("evidence_applicability.after_version_insert")

        self.store.fault("evidence_applicability.before_head_write")
        if before_head is None:
            try:
                self.store.conn.execute(
                    "INSERT INTO evidence_applicability_decision_heads(decision_key,decision_version_id,active,"
                    "head_revision,updated_at,updated_by) VALUES (?,?,?,?,?,?)",
                    (plan["decision_key"], plan["after_head"]["decision_version_id"],
                     int(plan["after_head"]["active"]), plan["after_head"]["head_revision"],
                     timestamp, context.auth.actor_id),
                )
            except Exception as exc:
                if "IntegrityError" in type(exc).__name__:
                    raise ConflictError("Applicability decision head conflicted with a concurrent change") from exc
                raise
        else:
            cursor = self.store.conn.execute(
                "UPDATE evidence_applicability_decision_heads SET decision_version_id=?,active=?,"
                "head_revision=head_revision+1,updated_at=?,updated_by=? WHERE decision_key=? "
                "AND decision_version_id=? AND active=? AND head_revision=?",
                (plan["after_head"]["decision_version_id"], int(plan["after_head"]["active"]),
                 timestamp, context.auth.actor_id, plan["decision_key"],
                 before_head["decision_version_id"], int(bool(before_head["active"])),
                 int(before_head["head_revision"])),
            )
            if cursor.rowcount != 1:
                raise ConflictError("Applicability decision head changed during commit")
        self.store.fault("evidence_applicability.after_head_write")
        audit_payload = {
            "action": plan["action"],
            "decision_key": plan["decision_key"],
            "before": ({"decision_version_id": before_head["decision_version_id"],
                        "active": bool(before_head["active"]),
                        "head_revision": int(before_head["head_revision"])} if before_head else None),
            "after": {"decision_version_id": plan["after_head"]["decision_version_id"],
                      "active": plan["after_head"]["active"],
                      "head_revision": plan["after_head"]["head_revision"]},
            "qualification": qualification,
            "changeset_id": context.changeset_id,
            "changeset_hash": context.changeset_hash,
        }
        self.store.fault("evidence_applicability.before_audit")
        self.store.audit(
            self.store.conn,
            actor=context.auth.actor_id,
            action=f"evidence_applicability_decision.{plan['action']}",
            object_type="evidence_applicability_decision",
            object_id=plan["decision_key"],
            before_revision=(int(before_head["head_revision"]) if before_head else None),
            after_revision=int(plan["after_head"]["head_revision"]),
            reason=plan["reason"],
            payload=audit_payload,
        )
        self.store.fault("evidence_applicability.after_audit")
        return {
            "decision_key": plan["decision_key"],
            "decision_version_id": plan["after_head"]["decision_version_id"],
            "active": plan["after_head"]["active"],
            "head_revision": plan["after_head"]["head_revision"],
            "qualification": qualification,
        }
