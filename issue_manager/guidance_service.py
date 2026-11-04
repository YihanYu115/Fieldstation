from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .errors import ValidationError
from .security import ALL_WRITE_CAPABILITIES, AuthContext
from .strict_json import require_strict_json

if TYPE_CHECKING:
    from .service import IssueManager


class GuidanceService:
    """Builds deterministic, capability-aware action guidance from current state."""

    def __init__(self, manager: IssueManager):
        self.manager = manager
        self.store = manager.store

    @staticmethod
    def _capabilities(auth: AuthContext | None) -> set[str]:
        return set(auth.capabilities) if auth else set(ALL_WRITE_CAPABILITIES)

    def _template(
        self, kind: str, semantic_definition: dict[str, Any]
    ) -> dict[str, Any] | None:
        reference_key = {
            "evidence_intake_template": "evidence_intake_template",
            "question_template": "question_template",
            "conclusion_summary_template": "conclusion_summary_template",
        }[kind]
        reference = semantic_definition.get(reference_key)
        row = None
        if isinstance(reference, str):
            try:
                entry = self.manager.registry.resolve(reference, kind=kind, for_creation=False)
            except Exception:
                entry = None
            if entry:
                return {
                    "registration_id": entry["registration_id"],
                    "content_hash": entry["content_hash"],
                    "api_version": entry["api_version"],
                    "definition": entry["definition"],
                }
        row = self.store.row(
            "SELECT registration_id,content_hash,api_version,definition_json "
            "FROM registry_entries WHERE kind=? AND state='active' "
            "ORDER BY created_at DESC,registration_id LIMIT 1",
            (kind,),
        )
        if not row:
            return None
        return {
            "registration_id": row["registration_id"],
            "content_hash": row["content_hash"],
            "api_version": row["api_version"],
            "definition": json.loads(row["definition_json"]),
        }

    @staticmethod
    def _form_fields(template: dict[str, Any] | None) -> tuple[list[Any], list[Any]]:
        if not template:
            return (
                [
                    "/kind",
                    "/locator",
                    "/issue_id",
                    "/description",
                    "/addresses_question_ids",
                ],
                [
                    "/target_scope",
                    "/quality_status",
                    "/content_hash",
                    "/related_evidence",
                ],
            )
        definition = template["definition"]
        required = definition.get("required_fields", [])
        optional = definition.get("optional_fields", [])
        return list(required), list(optional)

    def evidence_intake_template(
        self, issue_id: str, *, auth: AuthContext | None = None
    ) -> dict[str, Any]:
        """Return the exact intake template frozen by the Issue semantics."""

        if auth:
            auth.require("context.read")
        issue = self.manager.show_issue(issue_id)
        definition = self.manager.issue_semantic_snapshot(issue).get("definition", {})
        template = self._template("evidence_intake_template", definition)
        if not template:
            raise ValidationError("No active Evidence Intake Template is available")
        required, optional = self._form_fields(template)
        return {
            "template_version": "evidence-intake-template-view/v1",
            "issue_id": issue_id,
            **template,
            "required_fields": required,
            "optional_fields": optional,
        }

    @staticmethod
    def _pointer_present(payload: dict[str, Any], pointer: str) -> bool:
        if not pointer.startswith("/"):
            return pointer in payload and payload[pointer] is not None
        current: Any = payload
        for raw_part in pointer[1:].split("/"):
            part = raw_part.replace("~1", "/").replace("~0", "~")
            if not isinstance(current, dict) or part not in current:
                return False
            current = current[part]
        return current is not None

    def validate_evidence_intake(
        self,
        issue_id: str,
        payload: dict[str, Any],
        *,
        auth: AuthContext | None = None,
    ) -> dict[str, Any]:
        """Validate a prospective Evidence submit payload without mutating the ledger."""

        template = self.evidence_intake_template(issue_id, auth=auth)
        require_strict_json(payload, path="$.evidence_intake")
        missing = [
            pointer
            for pointer in template["required_fields"]
            if not self._pointer_present(payload, pointer)
        ]
        allowed_relations = set(template["definition"].get("allowed_relation_types", []))
        invalid_relations: list[dict[str, Any]] = []
        related = payload.get("related_evidence", [])
        if not isinstance(related, list):
            invalid_relations.append(
                {"path": "/related_evidence", "code": "expected_array"}
            )
        else:
            for index, relation in enumerate(related):
                relation_type = relation.get("relation_type") if isinstance(relation, dict) else None
                if not isinstance(relation, dict) or relation_type not in allowed_relations:
                    invalid_relations.append(
                        {
                            "path": f"/related_evidence/{index}/relation_type",
                            "code": "relation_type_not_allowed",
                            "value": relation_type,
                        }
                    )
        errors = [
            {"path": pointer, "code": "required_field_missing"}
            for pointer in missing
        ] + invalid_relations
        return {
            "validation_version": "evidence-intake-validation/v1",
            "issue_id": issue_id,
            "registration_id": template["registration_id"],
            "content_hash": template["content_hash"],
            "valid": not errors,
            "errors": errors,
        }

    def get(
        self,
        issue_id: str,
        *,
        auth: AuthContext | None = None,
        intent: str = "design-experiment",
    ) -> dict[str, Any]:
        if auth:
            auth.require("context.read")
        if not intent.strip():
            raise ValidationError("Guidance intent cannot be empty")
        issue = self.manager.show_issue(issue_id)
        semantic_snapshot = self.manager.issue_semantic_snapshot(issue)
        definition = semantic_snapshot.get("definition", {})
        capabilities = self._capabilities(auth)
        questions = self.manager.questions.list(issue_id)
        open_questions = [
            item for item in questions if item["status"] in {"open", "in_progress"}
        ]
        blocked_questions = [item for item in questions if item["status"] == "blocked"]
        answered_but_stale = [
            item
            for item in questions
            if item["status"] == "answered" and item["answer_freshness"] != "fresh"
        ]
        intake_template = self._template("evidence_intake_template", definition)
        question_template = self._template("question_template", definition)
        summary_template = self._template("conclusion_summary_template", definition)
        required_fields, optional_fields = self._form_fields(intake_template)
        actions: list[dict[str, Any]] = []
        unavailable: list[dict[str, Any]] = []

        def offer(
            operation_id: str,
            reason: str,
            *,
            risk_tier: str,
            template: dict[str, Any] | None = None,
            blocked_by: list[dict[str, Any]] | None = None,
            fields: tuple[list[Any], list[Any]] | None = None,
            allowed_relation_types: list[str] | None = None,
        ) -> None:
            spec = self.manager.operations.get(operation_id)
            blockers = blocked_by or []
            action = {
                "operation_id": operation_id,
                "reason": reason,
                "risk_tier": risk_tier,
                "required_capability": spec.required_capability,
                "method": spec.method,
                "path": spec.path_template.replace("{issue_id}", issue_id),
                "template": (
                    {
                        "registration_id": template["registration_id"],
                        "content_hash": template["content_hash"],
                        "api_version": template["api_version"],
                    }
                    if template
                    else None
                ),
                "required_fields": (fields or (list(spec.required_fields), []))[0],
                "optional_fields": (fields or ([], list(spec.optional_fields)))[1],
                "allowed_relation_types": allowed_relation_types or [],
                "preflight": {
                    "state_revision": issue["working_revision"],
                    "conclusion_revision": issue["conclusion_revision"],
                    "freshness": issue["freshness"],
                },
                "blocked_by": blockers,
            }
            if spec.required_capability in capabilities and not blockers:
                actions.append(action)
            else:
                unavailable.append(
                    {
                        "operation_id": operation_id,
                        "reason": reason,
                        "required_role": (
                            "reviewer"
                            if risk_tier in {"T2", "T3"}
                            else "data_manager"
                        ),
                        "blocked_by": blockers
                        or [
                            {
                                "code": "missing_capability",
                                "capability": spec.required_capability,
                            }
                        ],
                    }
                )

        if open_questions or answered_but_stale:
            target = (open_questions or answered_but_stale)[0]
            offer(
                "evidence.submit/v2",
                f"Question {target['question_id']} still needs usable Evidence",
                risk_tier="T1",
                template=intake_template,
                fields=(required_fields, optional_fields),
                allowed_relation_types=[
                    "depends_on",
                    "derived_from",
                    "reproduces",
                    "supports",
                    "challenges",
                    "amends",
                    "duplicates",
                    "context_for",
                ],
            )
        else:
            offer(
                "question.create/v1",
                "No active Question remains; record the next explicit knowledge gap",
                risk_tier="T1",
                template=question_template,
            )
        if issue["freshness"] != "fresh":
            offer(
                "context.get/v2",
                "Inspect refresh blockers and Evidence lineage impacts",
                risk_tier="T0",
            )
        if questions and all(
            item["status"] in {"answered", "deferred", "cancelled"}
            for item in questions
        ):
            rollup = self.manager.rollup.preview(issue_id)
            offer(
                "conclusion.rollup_preview/v1",
                "Questions are dispositioned; prepare an explicit Conclusion basis",
                risk_tier="T0",
                blocked_by=rollup["blockers"],
            )

        goal = (
            f"Answer the highest-priority Question: {open_questions[0]['prompt']}"
            if open_questions
            else (
                "Revalidate the stale answer and its Evidence dependencies"
                if answered_but_stale
                else "Define the next explicit experimental or analysis Question"
            )
        )
        return {
            "guidance_version": "issue-guidance/v1",
            "issue_id": issue_id,
            "intent": intent,
            "current_goal": goal,
            "open_questions": open_questions,
            "blocked_questions": blocked_questions,
            "answered_but_stale_questions": answered_but_stale,
            "recommended_actions": actions,
            "unavailable_actions": unavailable,
            "structured_outputs_schema": definition.get("conclusion", {}).get(
                "structured_outputs_schema", {}
            ),
            "conclusion_summary_template": summary_template,
            "question_template": question_template,
            "evidence_intake_template": intake_template,
            "issue_type_registration": {
                "registration_id": semantic_snapshot.get("registration_id"),
                "content_hash": semantic_snapshot.get("registration_content_hash"),
            },
            "state_token": {
                "working_revision": issue["working_revision"],
                "conclusion_revision": issue["conclusion_revision"],
                "freshness": issue["freshness"],
            },
        }
