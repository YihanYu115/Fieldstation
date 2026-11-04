"""Read-only repository/query service for scoped Evidence applicability.

This service intentionally exposes no mutation methods. It validates the
stored fixed snapshots, typed basis references, and frozen qualification
receipt before passing active heads to the pure evaluator.
"""

from __future__ import annotations

import json
from typing import Any, Iterable, Sequence

from .errors import NotFoundError, ValidationError
from .evidence_applicability import (
    APPLICABILITY_RULE_ID,
    SCOPE_KIND,
    EvidenceTargetSnapshot,
    basis_structure_errors,
    evaluate_applicability,
    qualification_structure_errors,
)


class EvidenceApplicabilityService:
    """Read-only access to applicability versions, heads, projections and why."""

    def __init__(self, manager):
        self.manager = manager
        self.store = manager.store
        from .evidence_applicability_changeset import EvidenceApplicabilityChangeSetPlanner

        self.changeset_planner = EvidenceApplicabilityChangeSetPlanner(manager)

    @staticmethod
    def _decode(value: Any, fallback: Any) -> Any:
        try:
            return json.loads(value) if isinstance(value, str) else value
        except (TypeError, ValueError, json.JSONDecodeError):
            return fallback

    @staticmethod
    def _parse_id_list(values: Iterable[str] | None) -> list[str] | None:
        if values is None:
            return None
        result = list(values)
        if any(not isinstance(item, str) or not item.strip() for item in result):
            raise ValidationError("Evidence IDs must be non-empty strings")
        return sorted(set(result))

    def _require_scope(self, scope_issue_id: str) -> None:
        if not isinstance(scope_issue_id, str) or not scope_issue_id.strip():
            raise ValidationError("scope_issue_id must be a non-empty Issue identity")
        if not self.store.row("SELECT issue_id FROM issues WHERE issue_id=?", (scope_issue_id,)):
            raise NotFoundError("Applicability Issue Scope not found")

    def _validate_basis_reference(
        self, item: dict[str, Any], *, own_version_id: str, state_view=None
    ) -> list[str]:
        kind = item.get("kind")
        identity_field = (
            {
                "evidence_version": "evidence_id",
                "conclusion_version": "conclusion_id",
                "record_version": "record_revision_id",
                "relation_version": "version_id",
                "applicability_decision_version": "decision_version_id",
            }.get(kind)
            if isinstance(kind, str)
            else None
        )
        if identity_field is None:
            return ["basis_kind_unknown"]
        identity = item.get(identity_field)
        if not isinstance(identity, str) or not identity:
            return ["basis_identity_invalid"]
        if kind == "evidence_version":
            evidence = (
                state_view.evidence(identity)
                if state_view is not None and identity in state_view.new_evidence
                else self.store.row(
                    "SELECT evidence_id,semantic_revision,current_proof_id,current_manifest_id "
                    "FROM evidence_refs WHERE evidence_id=?", (identity,),
                )
            )
            if evidence is None:
                return ["basis_evidence_missing"]
            revision = item.get("semantic_revision")
            proof_id = item.get("proof_id")
            manifest_id = item.get("manifest_id")
            if proof_id is not None:
                proof = self.store.row(
                    "SELECT evidence_id,semantic_revision,manifest_id FROM evidence_proofs WHERE proof_id=?",
                    (proof_id,),
                )
                if (
                    not proof
                    or proof["evidence_id"] != identity
                    or int(proof["semantic_revision"]) != revision
                ):
                    return ["basis_evidence_proof_unresolvable"]
                if manifest_id != proof["manifest_id"]:
                    return ["basis_evidence_proof_manifest_mismatch"]
            elif (
                int(evidence["semantic_revision"]) != revision
                or evidence["current_proof_id"] is not None
            ):
                return ["basis_evidence_unproved_revision_unresolvable"]
            if manifest_id is not None:
                manifest = self.store.row(
                    "SELECT evidence_id FROM evidence_manifests WHERE manifest_id=?", (manifest_id,)
                )
                if not manifest or manifest["evidence_id"] != identity:
                    return ["basis_evidence_manifest_unresolvable"]
            elif (
                int(evidence["semantic_revision"]) == revision
                and evidence["current_manifest_id"] is not None
            ):
                return ["basis_evidence_manifest_snapshot_mismatch"]
            return []
        if kind == "conclusion_version":
            exists = self.store.row(
                "SELECT 1 FROM conclusion_revisions WHERE conclusion_id=?", (identity,)
            )
        elif kind == "record_version":
            exists = self.store.row(
                "SELECT 1 FROM record_revisions WHERE record_revision_id=?", (identity,)
            )
        elif kind == "relation_version":
            exists = self.store.row(
                "SELECT 1 FROM managed_relation_versions WHERE version_id=?", (identity,)
            )
        else:
            if identity == own_version_id:
                return ["basis_applicability_self_reference"]
            exists = (
                state_view.applicability_version(identity)
                if state_view is not None
                else self.store.row(
                    "SELECT 1 FROM evidence_applicability_decision_versions WHERE decision_version_id=?",
                    (identity,),
                )
            )
        return [] if exists else [f"basis_{kind}_missing"]

    def _validate_qualification(self, version: dict[str, Any]) -> list[str]:
        errors = list(
            qualification_structure_errors(
                version.get("qualification_json"),
                rule_id=str(version.get("rule_id") or ""),
                changeset_id=version.get("changeset_id"),
            )
        )
        if errors:
            return errors
        receipt = self._decode(version.get("qualification_json"), {})
        actor = self.store.row(
            "SELECT actor_id FROM actors WHERE actor_id=?", (receipt["actor_id"],)
        )
        run = self.store.row("SELECT actor_id FROM agent_runs WHERE run_id=?", (receipt["run_id"],))
        if not actor or not run or run["actor_id"] != receipt["actor_id"]:
            errors.append("qualification_actor_run_unresolvable")
        changeset = self.store.row(
            "SELECT changeset_hash,risk_tier,risk_reasons_json FROM changesets WHERE changeset_id=?",
            (version.get("changeset_id"),),
        )
        reviewed_actor_ids: set[str] = set()
        if not changeset:
            errors.append("qualification_changeset_missing")
        else:
            if changeset["changeset_hash"] != receipt["changeset_hash"]:
                errors.append("qualification_changeset_hash_mismatch")
            if changeset["risk_tier"] != receipt["risk_tier"]:
                errors.append("qualification_risk_tier_mismatch")
            required_reviews = {"T0": 0, "T1": 0, "T2": 1, "T3": 2}.get(
                str(changeset["risk_tier"]), 3
            )
            if len(receipt.get("review_ids", [])) < required_reviews:
                errors.append("qualification_review_quorum_missing")
        for review_id in receipt.get("review_ids", []):
            review = self.store.row(
                "SELECT changeset_id,decision,changeset_hash,reviewer_actor_id,risk_snapshot_json "
                "FROM changeset_review_decisions WHERE review_id=?",
                (review_id,),
            )
            if not review or review["changeset_id"] != version.get("changeset_id"):
                errors.append("qualification_review_unresolvable")
            elif (
                review["decision"] != "pass"
                or review["changeset_hash"] != receipt["changeset_hash"]
            ):
                errors.append("qualification_review_not_matching_pass")
            else:
                reviewed_actor_ids.add(str(review["reviewer_actor_id"]))
                risk_snapshot = self._decode(review.get("risk_snapshot_json"), {})
                if (
                    not changeset
                    or risk_snapshot.get("risk_tier") != changeset["risk_tier"]
                    or risk_snapshot.get("risk_reasons") != self._decode(changeset["risk_reasons_json"], None)
                ):
                    errors.append("qualification_review_risk_snapshot_mismatch")
        if len(reviewed_actor_ids) != len(receipt.get("review_ids", [])):
            errors.append("qualification_reviews_not_independent")
        return sorted(set(errors))

    def _validate_version(self, version: dict[str, Any], *, state_view=None) -> list[str]:
        if version.get("__simulated_validated__"):
            return []
        errors: set[str] = set()
        scope_exists = (
            state_view.issue_row(str(version.get("scope_issue_id"))) is not None
            if state_view is not None
            else bool(self.store.row("SELECT 1 FROM issues WHERE issue_id=?", (version.get("scope_issue_id"),)))
        )
        if version.get("scope_kind") != SCOPE_KIND or not scope_exists:
            errors.add("decision_scope_unresolvable")
        if version.get("target_binding") != "fixed":
            errors.add("decision_target_binding_invalid")
        target = self.store.row(
            "SELECT evidence_id FROM evidence_refs WHERE evidence_id=?",
            (version.get("target_evidence_id"),),
        )
        if not target:
            errors.add("decision_target_missing")
        if version.get("target_proof_id") is not None:
            proof = self.store.row(
                "SELECT evidence_id,semantic_revision FROM evidence_proofs WHERE proof_id=?",
                (version.get("target_proof_id"),),
            )
            if (
                not proof
                or proof["evidence_id"] != version.get("target_evidence_id")
                or int(proof["semantic_revision"])
                != int(version.get("target_semantic_revision", -1))
            ):
                errors.add("decision_target_proof_unresolvable")
        if version.get("target_manifest_id") is not None:
            manifest = self.store.row(
                "SELECT evidence_id FROM evidence_manifests WHERE manifest_id=?",
                (version.get("target_manifest_id"),),
            )
            if not manifest or manifest["evidence_id"] != version.get("target_evidence_id"):
                errors.add("decision_target_manifest_unresolvable")
        basis = self._decode(version.get("basis_json"), None)
        errors.update(basis_structure_errors(basis))
        if isinstance(basis, list):
            for item in basis:
                if isinstance(item, dict):
                    errors.update(
                        self._validate_basis_reference(
                            item,
                            own_version_id=str(version.get("decision_version_id") or ""),
                            state_view=state_view,
                        )
                    )
        errors.update(self._validate_qualification(version))
        return sorted(errors)

    @staticmethod
    def _public_version(
        row: dict[str, Any], *, validation_errors: list[str] | None = None
    ) -> dict[str, Any]:
        result = dict(row)
        result["basis"] = EvidenceApplicabilityService._decode(result.pop("basis_json", None), None)
        result["qualification"] = EvidenceApplicabilityService._decode(
            result.pop("qualification_json", None), None
        )
        head_active = result.pop("head_active", None)
        result["active"] = bool(head_active) if head_active is not None else None
        result["head_revision"] = result.pop("head_revision", None)
        result["updated_at"] = result.pop("head_updated_at", None)
        result["updated_by"] = result.pop("head_updated_by", None)
        result["validation_errors"] = list(validation_errors or [])
        return result

    def _head_rows(
        self, *, evidence_ids: list[str] | None = None,
        scope_issue_id: str | None = None, state_view=None
    ) -> list[dict[str, Any]]:
        if state_view is not None:
            rows = state_view.applicability_head_rows(scope_issue_id=scope_issue_id)
            if evidence_ids is not None:
                allowed = set(evidence_ids)
                rows = [row for row in rows if row.get("target_evidence_id") in allowed]
            return rows
        sql = (
            "SELECT v.*,h.active AS head_active,h.head_revision,h.updated_at AS head_updated_at,"
            "h.updated_by AS head_updated_by FROM evidence_applicability_decision_heads h "
            "JOIN evidence_applicability_decision_versions v "
            "ON v.decision_key=h.decision_key AND v.decision_version_id=h.decision_version_id"
        )
        clauses: list[str] = []
        params: list[Any] = []
        if evidence_ids is not None:
            if not evidence_ids:
                return []
            placeholders = ",".join("?" for _ in evidence_ids)
            clauses.append(f"v.target_evidence_id IN ({placeholders})")
            params.extend(evidence_ids)
        if scope_issue_id is not None:
            clauses.append("v.scope_issue_id=?")
            params.append(scope_issue_id)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY v.decision_key,v.decision_version_id"
        return self.store.rows(sql, tuple(params))

    def list(
        self,
        *,
        scope_issue_id: str | None = None,
        evidence_id: str | None = None,
        include_inactive: bool = True,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if scope_issue_id is not None:
            self._require_scope(scope_issue_id)
            clauses.append("v.scope_issue_id=?")
            params.append(scope_issue_id)
        if evidence_id is not None:
            if not isinstance(evidence_id, str) or not evidence_id.strip():
                raise ValidationError("evidence_id must be a non-empty Evidence identity")
            if not self.store.row("SELECT 1 FROM evidence_refs WHERE evidence_id=?", (evidence_id,)):
                raise NotFoundError("Evidence not found")
            clauses.append("v.target_evidence_id=?")
            params.append(evidence_id)
        if not include_inactive:
            clauses.append("h.active=1")
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        rows = self.store.rows(
            "SELECT v.*,h.active AS head_active,h.head_revision,h.updated_at AS head_updated_at,"
            "h.updated_by AS head_updated_by FROM evidence_applicability_decision_heads h "
            "JOIN evidence_applicability_decision_versions v "
            "ON v.decision_key=h.decision_key AND v.decision_version_id=h.decision_version_id"
            + where
            + " ORDER BY v.scope_issue_id,v.target_evidence_id,v.decision_key",
            tuple(params),
        )
        return [
            self._public_version(row, validation_errors=self._validate_version(row)) for row in rows
        ]

    def show(self, identity: str) -> dict[str, Any]:
        if not isinstance(identity, str) or not identity.strip():
            raise ValidationError("decision key or version identity must be non-empty")
        rows = self.store.rows(
            "SELECT v.*,h.active AS head_active,h.head_revision,h.updated_at AS head_updated_at,"
            "h.updated_by AS head_updated_by FROM evidence_applicability_decision_versions v "
            "LEFT JOIN evidence_applicability_decision_heads h "
            "ON h.decision_key=v.decision_key AND h.decision_version_id=v.decision_version_id "
            "WHERE v.decision_key=? OR v.decision_version_id=? "
            "ORDER BY v.version_number",
            (identity, identity),
        )
        if not rows:
            raise NotFoundError("Applicability decision not found")
        versions = [
            self._public_version(row, validation_errors=self._validate_version(row)) for row in rows
        ]
        current = next((item for item in versions if item["head_revision"] is not None), None)
        return {
            "decision_key": versions[0]["decision_key"],
            "current_head": ({
                "decision_version_id": current["decision_version_id"],
                "active": current["active"],
                "head_revision": current["head_revision"],
            } if current else None),
            "versions": versions,
        }

    def _current_snapshots(self, evidence_ids: Sequence[str]) -> dict[str, EvidenceTargetSnapshot]:
        if not evidence_ids:
            return {}
        placeholders = ",".join("?" for _ in evidence_ids)
        rows = self.store.rows(
            "SELECT evidence_id,semantic_revision,current_proof_id,current_manifest_id "
            f"FROM evidence_refs WHERE evidence_id IN ({placeholders}) ORDER BY evidence_id",
            tuple(evidence_ids),
        )
        return {
            row["evidence_id"]: EvidenceTargetSnapshot(
                evidence_id=row["evidence_id"],
                semantic_revision=int(row["semantic_revision"]),
                proof_id=row["current_proof_id"],
                manifest_id=row["current_manifest_id"],
            )
            for row in rows
        }

    def projection(
        self,
        *,
        scope_issue_id: str,
        evidence_ids: Iterable[str] | None = None,
        accepted_rule_ids: Iterable[str] = (APPLICABILITY_RULE_ID,),
        state_view=None,
    ) -> dict[str, Any]:
        """Project explicit candidate IDs, or Issue-attached IDs plus head targets.

        The default candidate list is a convenience. Callers with
        a resolver-discovered candidate set must pass it explicitly.
        """
        if state_view is None:
            self._require_scope(scope_issue_id)
        else:
            # issue() derives freshness by resolving its current conclusion;
            # v2 resolution calls this projection again. Read the overlay row
            # directly to avoid recursive currentness derivation during writes.
            if state_view.issue_row(scope_issue_id) is None:
                raise NotFoundError("Applicability Issue Scope not found")
        explicit_ids = self._parse_id_list(evidence_ids)
        if explicit_ids is None:
            attached = (
                state_view.context_rows("issue_evidence", "issue_id", scope_issue_id)
                if state_view is not None
                else self.store.rows(
                    "SELECT evidence_id FROM issue_evidence WHERE issue_id=? ORDER BY evidence_id",
                    (scope_issue_id,),
                )
            )
            scoped_targets = [
                row for row in self._head_rows(state_view=state_view)
                if row.get("scope_issue_id") == scope_issue_id
            ]
            explicit_ids = sorted(
                {row["evidence_id"] for row in attached}
                | {row["target_evidence_id"] for row in scoped_targets}
            )
        if state_view is None:
            snapshots = self._current_snapshots(explicit_ids)
        else:
            snapshots = {}
            for evidence_id in explicit_ids:
                try:
                    row = state_view.evidence(evidence_id)
                except ValidationError:
                    continue
                snapshots[evidence_id] = EvidenceTargetSnapshot(
                    evidence_id=evidence_id,
                    semantic_revision=int(row["semantic_revision"]),
                    proof_id=row.get("current_proof_id"),
                    manifest_id=row.get("current_manifest_id"),
                )
        missing = sorted(set(explicit_ids) - set(snapshots))
        if missing:
            raise NotFoundError("Candidate Evidence not found", details={"evidence_ids": missing})
        heads = self._head_rows(
            evidence_ids=explicit_ids, scope_issue_id=scope_issue_id, state_view=state_view
        )
        current_snapshots = snapshots
        evaluatable_heads = []
        unexplainable: dict[str, dict[str, set[str]]] = {}
        for row in heads:
            head = dict(row)
            head["active"] = int(row["head_active"])
            target_id = row["target_evidence_id"]
            candidate = current_snapshots.get(target_id)
            if (
                candidate is not None
                and int(row["head_active"]) == 1
                and row["scope_kind"] == SCOPE_KIND
                and row["scope_issue_id"] == scope_issue_id
                and row["target_binding"] == "fixed"
                and row["target_semantic_revision"] == candidate.semantic_revision
                and row["target_proof_id"] == candidate.proof_id
                and row["target_manifest_id"] == candidate.manifest_id
            ):
                validation_errors = self._validate_version(row, state_view=state_view)
                if validation_errors:
                    problem_record = unexplainable.setdefault(
                        target_id, {"versions": set(), "errors": set()}
                    )
                    problem_record["versions"].add(str(row["decision_version_id"]))
                    problem_record["errors"].update(validation_errors)
                    continue
            evaluatable_heads.append(head)
        projection = evaluate_applicability(
            scope_issue_id=scope_issue_id,
            candidate_snapshots=snapshots,
            current_heads=evaluatable_heads,
            accepted_rule_ids=frozenset(accepted_rule_ids),
        )
        public_projection: dict[str, Any] = projection.as_dict()
        for item in public_projection["evidence"]:
            quarantined = unexplainable.get(item["evidence_id"])
            if quarantined:
                item["state"] = "unresolved"
                item["decision_version_ids"] = sorted(
                    set(item["decision_version_ids"]) | quarantined["versions"]
                )
                item["errors"] = sorted(set(item["errors"]) | quarantined["errors"])
        public_projection["included"] = [
            item["evidence_id"] for item in public_projection["evidence"] if item["state"] == "included"
        ]
        public_projection["excluded"] = [
            item["evidence_id"] for item in public_projection["evidence"] if item["state"] == "excluded"
        ]
        public_projection["unresolved"] = [
            item["evidence_id"] for item in public_projection["evidence"] if item["state"] == "unresolved"
        ]
        return public_projection

    def why(
        self,
        *,
        scope_issue_id: str,
        evidence_id: str,
        accepted_rule_ids: Iterable[str] = (APPLICABILITY_RULE_ID,),
    ) -> dict[str, Any]:
        if not isinstance(evidence_id, str) or not evidence_id.strip():
            raise ValidationError("evidence_id must be a non-empty Evidence identity")
        projection = self.projection(
            scope_issue_id=scope_issue_id,
            evidence_ids=[evidence_id],
            accepted_rule_ids=accepted_rule_ids,
        )
        result = next(item for item in projection["evidence"] if item["evidence_id"] == evidence_id)
        heads = self._head_rows(evidence_ids=[evidence_id])
        inactive = []
        for row in heads:
            if (
                row["scope_kind"] == SCOPE_KIND
                and row["scope_issue_id"] == scope_issue_id
                and not row["head_active"]
            ):
                inactive.append(
                    {
                        "decision_key": row["decision_key"],
                        "decision_version_id": row["decision_version_id"],
                        "effect": row["effect"],
                        "reason": row["reason"],
                    }
                )
        result["inactive_heads"] = sorted(
            inactive, key=lambda item: (item["decision_key"], item["decision_version_id"])
        )
        result["selected"] = result["state"] in {"included", "unresolved"}
        return result


    def scope_projection(self, scope_issue_id: str) -> dict[str, Any]:
        """Expose the same current qualification projection as the generic API."""
        return self.manager.context_maintenance.current_scoped_projection(scope_issue_id)

    def _evidence_snapshot(self, evidence_id: str) -> dict[str, Any]:
        row = self.store.row(
            "SELECT evidence_id,lifecycle_status,quality_status,semantic_revision,"
            "current_proof_id,current_manifest_id FROM evidence_refs WHERE evidence_id=?",
            (evidence_id,),
        )
        if not row:
            raise NotFoundError("Evidence not found")
        return {
            "evidence_id": row["evidence_id"],
            "lifecycle_status": row["lifecycle_status"],
            "quality_status": row["quality_status"],
            "semantic_revision": int(row["semantic_revision"]),
            "proof_id": row["current_proof_id"],
            "manifest_id": row["current_manifest_id"],
        }

    def _expand_basis_ref(self, ref: dict[str, Any]) -> dict[str, Any]:
        """Resolve one typed reference to a bounded, non-recursive summary."""
        kind = ref.get("kind")
        summary: dict[str, Any] = {"kind": kind, "reference": dict(ref)}
        if kind == "evidence_version":
            summary["object"] = self._evidence_snapshot(str(ref.get("evidence_id", "")))
        elif kind == "conclusion_version":
            row = self.store.row(
                "SELECT conclusion_id,issue_id,revision_number,status,statement,change_summary "
                "FROM conclusion_revisions WHERE conclusion_id=?", (ref.get("conclusion_id"),),
            )
            summary["object"] = row
        elif kind == "record_version":
            row = self.store.row(
                "SELECT record_revision_id,record_instance_id,revision_number,content_json "
                "FROM record_revisions WHERE record_revision_id=?", (ref.get("record_revision_id"),),
            )
            if row and isinstance(row.get("content_json"), str):
                raw = row["content_json"]
                row["content_json"] = raw[:512]
                row["content_truncated"] = len(raw) > 512
            summary["object"] = row
        elif kind == "relation_version":
            row = self.store.row(
                "SELECT version_id,domain,relation_id,version_number,definition_json "
                "FROM managed_relation_versions WHERE version_id=?", (ref.get("version_id"),),
            )
            if row and isinstance(row.get("definition_json"), str):
                raw = row["definition_json"]
                row["definition_json"] = raw[:512]
                row["definition_truncated"] = len(raw) > 512
            summary["object"] = row
        elif kind == "applicability_decision_version":
            # Deliberately omit that decision's basis: expansion is one level.
            summary["object"] = self.store.row(
                "SELECT decision_version_id,decision_key,version_number,scope_issue_id,"
                "target_evidence_id,effect,reason FROM evidence_applicability_decision_versions "
                "WHERE decision_version_id=?", (ref.get("decision_version_id"),),
            )
        else:
            summary["object"] = None
        obj = summary.get("object")
        if isinstance(obj, dict):
            truncated_fields = []
            for key, value in list(obj.items()):
                if isinstance(value, str) and len(value) > 512:
                    obj[key] = value[:512]
                    truncated_fields.append(key)
            if truncated_fields:
                summary["object_truncated_fields"] = sorted(truncated_fields)
        return summary

    def scope_why(self, scope_issue_id: str, evidence_id: str, *, expand_basis: bool = False) -> dict[str, Any]:
        projection = self.manager.context_maintenance.current_scoped_projection(scope_issue_id)
        item = next((item for item in projection["candidate_states"]
                     if item["candidate_id"] == evidence_id), None)
        if item is None:
            raise NotFoundError("Evidence is outside this scope")
        return {"issue_id": scope_issue_id, "evidence_id": evidence_id,
                "qualification": item, "adopted": evidence_id in projection["roots"]}


__all__ = ["EvidenceApplicabilityService"]
