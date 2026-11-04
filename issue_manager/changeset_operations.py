from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .errors import ValidationError
from .registry_service import validate_json_instance
from .strict_json import require_strict_json

_STRING = {"type": "string"}
_INTEGER = {"type": "integer"}
_OBJECT = {"type": "object", "additionalProperties": True, "properties": {}}
_STRING_ARRAY = {"type": "array", "items": _STRING}


@dataclass(frozen=True)
class ChangeSetOperationSpec:
    op: str
    description: str
    required_capability: str
    required_fields: tuple[str, ...]
    optional_fields: tuple[str, ...]
    properties: dict[str, dict[str, Any]]
    example: dict[str, Any]
    static_risk: str

    @property
    def schema(self) -> dict[str, Any]:
        properties = {"op": {"type": "string", "enum": [self.op]}, **self.properties}
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"issue-manager://changesets/operations/{self.op}/v1",
            "type": "object",
            "required": ["op", *self.required_fields],
            "properties": properties,
            # Operation extensions remain forward-compatible. The authoritative
            # validator still checks every declared field and all domain semantics.
            "additionalProperties": self.op != "evidence_applicability_decision",
        }

    def guide(self, *, available: bool) -> dict[str, Any]:
        return {
            "changeset_operation_guide_version": "changeset-operation-guide/v1",
            "op": self.op,
            "description": self.description,
            "required_capability": self.required_capability,
            "required_fields": list(self.required_fields),
            "optional_fields": list(self.optional_fields),
            "schema": self.schema,
            "example": self.example,
            "static_risk_hint": self.static_risk,
            "available": available,
            "blocked_by": []
            if available
            else [
                {
                    "code": "missing_capability",
                    "capability": self.required_capability,
                }
            ],
        }


def _spec(
    op: str,
    description: str,
    capability: str,
    required: tuple[str, ...],
    optional: tuple[str, ...],
    properties: dict[str, dict[str, Any]],
    example: dict[str, Any],
    risk: str,
) -> ChangeSetOperationSpec:
    return ChangeSetOperationSpec(
        op,
        description,
        capability,
        required,
        optional,
        properties,
        {"op": op, **example},
        risk,
    )


CHANGESET_OPERATION_SPECS: dict[str, ChangeSetOperationSpec] = {
    item.op: item
    for item in (
        _spec(
            "record_relation", "Change current Record material membership without rewriting its historical evidence snapshot.",
            "record.create", ("action", "relation_id", "reason"), ("expected_version_id", "expected_active", "replacement"),
            {"action": {"type": "string", "enum": ["add", "replace", "enable", "disable"]}, "relation_id": _STRING, "replacement": _OBJECT,
             "expected_version_id": _STRING, "expected_active": {"type": "boolean"}, "reason": _STRING},
            {"action": "disable", "relation_id": "record_origin_...", "expected_version_id": "record:record_origin_...:1",
             "expected_active": True, "reason": "Withdraw this material contribution"}, "T1; published and cross-sample context may escalate",
        ),
        _spec(
            "intake_relation", "Change a named Packet link while retaining its history.",
            "triage.manage", ("action", "link_id", "reason"), ("expected_version_id", "expected_active", "replacement", "provenance"),
            {"action": {"type": "string", "enum": ["add", "enable", "disable", "replace"]}, "link_id": _STRING, "provenance": _OBJECT,
             "expected_version_id": _STRING, "expected_active": {"type": "boolean"}, "reason": _STRING, "replacement": _OBJECT},
            {"action": "disable", "link_id": "packet_link_...", "expected_version_id": "intake:packet_link_...:1",
             "expected_active": True, "reason": "Withdraw this contribution"}, "T1; published context and cross-sample changes escalate",
        ),
        _spec(
            "question_relation", "Change a named Question material relationship with version and activation checks.",
            "question.write", ("action", "relation_id", "reason"), ("expected_version_id", "expected_active", "replacement"),
            {"action": {"type": "string", "enum": ["add", "enable", "disable", "replace"]}, "relation_id": _STRING,
             "expected_version_id": _STRING, "expected_active": {"type": "boolean"}, "reason": _STRING, "replacement": _OBJECT},
            {"action": "disable", "relation_id": "question_relation_...", "expected_version_id": "question:question_relation_...:1",
             "expected_active": True, "reason": "Withdraw this contribution"}, "T1; published and cross-sample context may escalate",
        ),
        _spec(
            "context_obligation", "Record or transition an independent review duty without changing currentness.",
            "conclusion.propose", ("action", "obligation_id", "reason"), ("conclusion_id", "details", "blocks_publication", "expected_revision"),
            {"action": {"type": "string", "enum": ["open", "complete", "cancel", "reopen"]}, "obligation_id": _STRING,
             "reason": _STRING, "conclusion_id": _STRING, "details": _OBJECT, "blocks_publication": {"type": "boolean"}, "expected_revision": _INTEGER},
            {"action": "open", "obligation_id": "review-duty-1", "conclusion_id": "conclusion_...", "reason": "Independent sign-off required",
             "details": {"request": "Review the calibration"}, "blocks_publication": True},
            "T1 to open; at least T2 to complete/cancel; T3 for canonical or report-facing judgments",
        ),
        _spec(
            "context_rule_upgrade", "Activate an immutable rule supported by this runtime and invalidate old-rule receipts.",
            "maintenance", ("expected_rule_id", "target_rule_id", "reason"), (),
            {"expected_rule_id": _STRING, "target_rule_id": _STRING, "reason": _STRING},
            {"expected_rule_id": "currentness-rule-old", "target_rule_id": "currentness-rule-supported", "reason": "Reviewed rule upgrade"},
            "T3; global context rule activation requires independent reviews",
        ),
        _spec(
            "context_relation", "Add, replace, disable or enable a typed material relationship between retained versions.",
            "relation.write", ("action", "relation_id", "reason"), ("definition", "expected_version_id"),
            {"action": {"type": "string", "enum": ["add", "replace", "disable", "enable"]},
             "relation_id": _STRING, "reason": _STRING, "definition": _OBJECT, "expected_version_id": _STRING},
            {"action": "add", "relation_id": "material-challenge-1", "reason": "New challenge",
             "definition": {"source": {"kind": "conclusion_version", "version_id": "conclusion_..."},
                            "target": {"kind": "relation_version", "version_id": "issue:rel_...:1"},
                            "relation_type": "challenges", "require_currentness": False}},
            "T1; T2 for accepted versions; T3 for canonical/report-facing or cross-sample effects",
        ),
        _spec(
            "evidence_applicability_decision",
            "Add, replace, disable or enable a fixed, Issue-scoped Evidence applicability decision.",
            "evidence.applicability.write",
            ("action", "decision_key", "expected_version_id", "expected_active", "reason"),
            ("definition",),
            {
                "action": {"type": "string", "enum": ["add", "replace", "disable", "enable"]},
                "decision_key": _STRING,
                "expected_version_id": _STRING,
                "expected_active": {"type": "boolean"},
                "reason": _STRING,
                "definition": {
                    "type": "object",
                    "required": ["scope", "target", "effect", "basis"],
                    "properties": {
                        "scope": {
                            "type": "object", "required": ["kind", "issue_id"],
                            "properties": {"kind": {"type": "string", "enum": ["issue_conclusion"]},
                                           "issue_id": _STRING},
                            "additionalProperties": False,
                        },
                        "target": {
                            "type": "object",
                            "required": ["kind", "evidence_id", "binding", "semantic_revision", "proof_id", "manifest_id"],
                            "properties": {"kind": {"type": "string", "enum": ["evidence_version"]},
                                           "evidence_id": _STRING,
                                           "binding": {"type": "string", "enum": ["fixed"]},
                                           "semantic_revision": {"type": "integer", "minimum": 0},
                                           "proof_id": {"type": ["string", "null"]},
                                           "manifest_id": {"type": ["string", "null"]}},
                            "additionalProperties": False,
                        },
                        "effect": {"type": "string", "enum": ["include", "exclude"]},
                        "basis": {
                            "type": "array", "minItems": 1,
                            "items": {
                                "type": "object", "required": ["kind"],
                                "properties": {
                                    "kind": {"type": "string", "enum": [
                                        "evidence_version", "conclusion_version", "record_version",
                                        "relation_version", "applicability_decision_version"]},
                                    "evidence_id": _STRING,
                                    "semantic_revision": {"type": "integer", "minimum": 0},
                                    "proof_id": {"type": ["string", "null"]},
                                    "manifest_id": {"type": ["string", "null"]},
                                    "snapshot": {
                                        "type": "object",
                                        "required": ["semantic_revision", "proof_id", "manifest_id"],
                                        "properties": {
                                            "semantic_revision": {"type": "integer", "minimum": 0},
                                            "proof_id": {"type": ["string", "null"]},
                                            "manifest_id": {"type": ["string", "null"]},
                                        },
                                        "additionalProperties": False,
                                    },
                                    "conclusion_id": _STRING,
                                    "record_revision_id": _STRING,
                                    "version_id": _STRING,
                                    "decision_version_id": _STRING,
                                },
                                "additionalProperties": False,
                            },
                        },
                    },
                    "additionalProperties": False,
                },
            },
            {
                "action": "add", "decision_key": "old-fit-outside-scope",
                "expected_version_id": "", "expected_active": False,
                "definition": {
                    "scope": {"kind": "issue_conclusion", "issue_id": "issue-a"},
                    "target": {"kind": "evidence_version", "evidence_id": "evidence-old-fit",
                               "binding": "fixed", "semantic_revision": 1,
                               "proof_id": None, "manifest_id": None},
                    "effect": "exclude",
                    "basis": [{"kind": "evidence_version", "evidence_id": "evidence-drift-test",
                               "semantic_revision": 1, "proof_id": None, "manifest_id": None,
                               "snapshot": {"semantic_revision": 1, "proof_id": None, "manifest_id": None}}],
                },
                "reason": "A newer drift test limits the old fit to its original interval",
            },
            "T1 draft; at least T2 for accepted/disputed/retracted/superseded consumers; T3 for canonical, report-facing or cross-sample effects",
        ),
        _spec(
            "replace_relation", "Atomically replace relation contents while retaining its immutable versions.",
            "relation.write", ("domain", "relation_id", "expected_version_id", "replacement", "reason"), (),
            {"domain": {"type": "string", "enum": ["issue", "evidence"]}, "relation_id": _STRING,
             "expected_version_id": _STRING, "replacement": _OBJECT, "reason": _STRING},
            {"domain": "issue", "relation_id": "rel_...", "expected_version_id": "issue:rel_...:1",
             "replacement": {"provider_issue_id": "new-provider"}, "reason": "Revised dependency"},
            "T1; T3 when either side is hard or the replacement crosses samples",
        ),
        _spec(
            "context_change",
            "Verify saved conclusion versions or change their selected receipt/qualification atomically.",
            "conclusion.propose",
            ("action", "items", "reason"),
            ("allow_historical",),
            {
                "action": {"type": "string", "enum": ["verify", "select", "revoke", "restore"]},
                "items": {"type": "array", "minItems": 1, "items": _OBJECT},
                "reason": _STRING,
                "allow_historical": {"type": "boolean"},
            },
            {"action": "verify", "items": [{"conclusion_id": "conclusion_...",
              "package_id": "context_input_...", "expected_receipt_id": ""}],
             "reason": "Verified against the prepared materials"},
            "T1; T2 for accepted judgments; T3 for canonical/report-facing or cross-sample effects",
        ),
        _spec(
            "create_issue",
            "Create an Issue from a registered or compatibility Issue Type.",
            "issue.write",
            ("issue_id", "issue_type"),
            (
                "title",
                "parent_issue_id",
                "scope",
                "topic",
                "canonical_alias",
                "issue_type_registration_id",
            ),
            {
                "issue_id": _STRING,
                "issue_type": _STRING,
                "title": _STRING,
                "parent_issue_id": _STRING,
                "scope": _OBJECT,
                "topic": _STRING,
                "canonical_alias": _STRING,
                "issue_type_registration_id": _STRING,
            },
            {"issue_id": "new-issue", "issue_type": "investigation", "title": "New issue"},
            "T1 (T3 for report-facing or cross-sample changes)",
        ),
        _spec(
            "attach_packet",
            "Attach and disposition a claimed Intake packet.",
            "triage.manage",
            ("packet_id", "issue_id"),
            (
                "disposition",
                "disposition_reason",
                "proposal_id",
                "evidence_request_id",
            ),
            {
                "packet_id": _STRING,
                "issue_id": _STRING,
                "disposition": _STRING,
                "disposition_reason": _STRING,
                "proposal_id": _STRING,
                "evidence_request_id": _STRING,
            },
            {"packet_id": "packet_...", "issue_id": "issue-a"},
            "T1",
        ),
        _spec(
            "attach_evidence",
            "Attach existing Evidence or create and attach a new Evidence reference.",
            "evidence.write",
            ("issue_id",),
            ("evidence_id", "evidence", "kind", "locator", "description", "quality_status"),
            {
                "issue_id": _STRING,
                "evidence_id": _STRING,
                "evidence": _OBJECT,
                "kind": _STRING,
                "locator": _STRING,
                "description": _STRING,
                "quality_status": _STRING,
            },
            {"issue_id": "issue-a", "evidence_id": "evidence_..."},
            "T1",
        ),
        _spec(
            "append_work",
            "Append an immutable working-history entry.",
            "work.write",
            ("issue_id", "body"),
            ("entry_type", "evidence_refs"),
            {
                "issue_id": _STRING,
                "body": _STRING,
                "entry_type": {
                    "type": "string",
                    "enum": [
                        "observation",
                        "run_link",
                        "analysis",
                        "note",
                        "question",
                        "decision_candidate",
                        "amendment",
                    ],
                },
                "evidence_refs": _STRING_ARRAY,
            },
            {"issue_id": "issue-a", "entry_type": "note", "body": "Checked result."},
            "T0 unless combined with higher-risk operations",
        ),
        _spec(
            "add_alias",
            "Add a normalized Issue alias.",
            "issue.write",
            ("issue_id", "alias"),
            (),
            {"issue_id": _STRING, "alias": _STRING},
            {"issue_id": "issue-a", "alias": "sample-a-result"},
            "T1",
        ),
        _spec(
            "add_tag",
            "Add a normalized Issue tag.",
            "issue.write",
            ("issue_id", "tag"),
            (),
            {"issue_id": _STRING, "tag": _STRING},
            {"issue_id": "issue-a", "tag": "pilot"},
            "T1",
        ),
        _spec(
            "add_relation",
            "Add an Issue dependency or semantic relation.",
            "relation.write",
            ("consumer", "provider", "relation_type"),
            ("impact_policy", "reason"),
            {
                "consumer": _STRING,
                "provider": _STRING,
                "relation_type": _STRING,
                "impact_policy": {
                    "type": "string",
                    "enum": ["hard", "soft", "notify", "none"],
                },
                "reason": _STRING,
            },
            {
                "consumer": "issue-a",
                "provider": "issue-b",
                "relation_type": "depends_on",
                "impact_policy": "hard",
            },
            "T1; hard dependencies are T3",
        ),
        _spec(
            "set_relation_impact",
            "Change an Issue relation impact policy.",
            "relation.write",
            ("relation_id", "impact_policy"),
            ("reason",),
            {
                "relation_id": _STRING,
                "impact_policy": {
                    "type": "string",
                    "enum": ["hard", "soft", "notify", "none"],
                },
                "reason": _STRING,
            },
            {"relation_id": "rel_...", "impact_policy": "soft", "reason": "Reassessed"},
            "T1; any before/after hard dependency is T3",
        ),
        *(
            _spec(
                op,
                f"{verb} an Issue relation.",
                "relation.write",
                ("relation_id",),
                ("reason",),
                {"relation_id": _STRING, "reason": _STRING},
                {"relation_id": "rel_...", "reason": "Reviewed lifecycle change"},
                "T1; changing a hard dependency is T3",
            )
            for op, verb in (
                ("deactivate_relation", "Deactivate"),
                ("reactivate_relation", "Reactivate"),
            )
        ),
        *(
            _spec(
                op,
                "Validate and publish a Conclusion proposal through the ChangeSet review boundary.",
                "conclusion.propose",
                (),
                (
                    "proposal",
                    "issue_id",
                    "expected_conclusion_revision",
                    "status",
                    "statement",
                    "structured_outputs",
                    "limitations",
                    "evidence_refs",
                    "evidence_uses",
                    "basis",
                    "basis_snapshot_token",
                ),
                {
                    "proposal": _OBJECT,
                    "issue_id": _STRING,
                    "expected_conclusion_revision": _INTEGER,
                    "status": {
                        "type": "string",
                        "enum": [
                            "draft",
                            "provisional",
                            "accepted",
                            "canonical",
                            "disputed",
                            "superseded",
                            "retracted",
                        ],
                    },
                    "statement": _STRING,
                    "structured_outputs": _OBJECT,
                    "limitations": _STRING_ARRAY,
                    "evidence_refs": _STRING_ARRAY,
                    "evidence_uses": {"type": "array", "items": _OBJECT},
                    "basis": {"type": "array", "items": _OBJECT},
                    "basis_snapshot_token": _STRING,
                },
                {
                    "issue_id": "issue-a",
                    "expected_conclusion_revision": 0,
                    "status": "provisional",
                    "statement": "Candidate conclusion",
                    "structured_outputs": {},
                    "limitations": [],
                    "basis": [],
                    "basis_snapshot_token": "<Manager-signed token from prepare/context>",
                },
                "T1 provisional; published/canonical and report-facing changes require review",
            )
            for op in ("propose_conclusion", "refresh_issue")
        ),
        _spec(
            "mark_needs_review",
            "Enqueue an Issue refresh/review task.",
            "refresh.manage",
            ("issue_id",),
            ("priority",),
            {"issue_id": _STRING, "priority": {"type": "integer", "minimum": 0, "maximum": 100}},
            {"issue_id": "issue-a", "priority": 50},
            "T1",
        ),
        _spec(
            "reassess_evidence",
            "Record a new Evidence quality assessment.",
            "evidence.write",
            ("evidence_id", "quality_status"),
            ("reason",),
            {
                "evidence_id": _STRING,
                "quality_status": {
                    "type": "string",
                    "enum": [
                        "unknown",
                        "usable",
                        "questionable",
                        "invalid",
                        "unusable_for_purpose",
                    ],
                },
                "reason": _STRING,
            },
            {"evidence_id": "evidence_...", "quality_status": "questionable", "reason": "Drift"},
            "T1; published impact promotes risk",
        ),
        *(
            _spec(
                op,
                description,
                "evidence.write",
                required,
                ("reason",),
                {**{field: _STRING for field in required}, "reason": _STRING},
                {
                    **{field: value for field, value in example.items()},
                    "reason": "Reviewed maintenance",
                },
                "T1; published impact promotes risk",
            )
            for op, description, required, example in (
                (
                    "void_evidence",
                    "Void an Evidence reference while preserving its history.",
                    ("evidence_id",),
                    {"evidence_id": "evidence_..."},
                ),
                (
                    "detach_evidence",
                    "Detach Evidence from an Issue.",
                    ("evidence_id", "issue_id"),
                    {"evidence_id": "evidence_...", "issue_id": "issue-a"},
                ),
            )
        ),
        _spec(
            "migrate_evidence_source",
            "Move Evidence ownership to another registered platform.",
            "evidence.resolve",
            ("evidence_id", "new_platform_id"),
            ("reason",),
            {"evidence_id": _STRING, "new_platform_id": _STRING, "reason": _STRING},
            {"evidence_id": "evidence_...", "new_platform_id": "platform-b"},
            "T3",
        ),
        _spec(
            "resolve_evidence_conflict",
            "Resolve Evidence attestations through reviewed governance.",
            "evidence.resolve",
            ("evidence_id",),
            (
                "accepted_attestation_ids",
                "retained_attestation_ids",
                "rejected_attestation_ids",
                "rationale",
            ),
            {
                "evidence_id": _STRING,
                "accepted_attestation_ids": _STRING_ARRAY,
                "retained_attestation_ids": _STRING_ARRAY,
                "rejected_attestation_ids": _STRING_ARRAY,
                "rationale": _STRING,
            },
            {"evidence_id": "evidence_...", "accepted_attestation_ids": ["attestation_..."]},
            "T3",
        ),
        _spec(
            "resolve_evidence_identity_ambiguity",
            "Resolve or waive a persisted Evidence identity ambiguity.",
            "evidence.resolve",
            ("ambiguity_id", "decision"),
            ("rationale", "platform_id", "locator"),
            {
                "ambiguity_id": _STRING,
                "decision": _STRING,
                "rationale": _STRING,
                "platform_id": _STRING,
                "locator": _STRING,
            },
            {"ambiguity_id": "ambiguity_...", "decision": "bind", "rationale": "Verified"},
            "T3",
        ),
        *(
            _spec(
                op,
                description,
                "changeset.submit",
                ("conflict_id", "expected_conflict_revision", "resolution"),
                ("resolution_payload", "reason"),
                {
                    "conflict_id": _STRING,
                    "expected_conflict_revision": _INTEGER,
                    "resolution": _STRING,
                    "resolution_payload": _OBJECT,
                    "reason": _STRING,
                },
                {
                    "conflict_id": "conflict_...",
                    "expected_conflict_revision": 1,
                    "resolution": "accept_candidate",
                    "resolution_payload": {},
                },
                "T3",
            )
            for op, description in (
                ("resolve_field_conflict", "Resolve a governed Field Bundle conflict."),
                ("resolve_import_conflict", "Resolve a governed Import conflict."),
            )
        ),
        _spec(
            "create_question",
            "Create a first-class Issue Question.",
            "question.write",
            ("issue_id", "prompt"),
            (
                "question_id",
                "question_key",
                "motivation",
                "question_kind",
                "priority",
                "expected_evidence",
                "reason",
            ),
            {
                "issue_id": _STRING,
                "prompt": _STRING,
                "question_id": _STRING,
                "question_key": _STRING,
                "motivation": _STRING,
                "question_kind": {
                    "type": "string",
                    "enum": [
                        "experiment",
                        "analysis",
                        "data_gap",
                        "conflict",
                        "verification",
                        "decision",
                    ],
                },
                "priority": {"type": "integer", "minimum": 0, "maximum": 100},
                "expected_evidence": {"type": "array", "items": {}},
                "reason": _STRING,
            },
            {"issue_id": "issue-a", "prompt": "What measurement resolves this?", "priority": 50},
            "T1; report-facing Questions can be T3",
        ),
        _spec(
            "transition_question",
            "Move a Question through its controlled lifecycle.",
            "question.write",
            ("question_id", "action"),
            ("reason",),
            {
                "question_id": _STRING,
                "action": {
                    "type": "string",
                    "enum": ["start", "block", "defer", "cancel", "reopen"],
                },
                "reason": _STRING,
            },
            {"question_id": "question_...", "action": "start", "reason": "Work began"},
            "T1; report-facing Questions can be T3",
        ),
        _spec(
            "answer_question",
            "Answer a Question with an existing Conclusion.",
            "question.answer",
            ("question_id", "conclusion_id"),
            ("reason",),
            {"question_id": _STRING, "conclusion_id": _STRING, "reason": _STRING},
            {"question_id": "question_...", "conclusion_id": "issue-a@r1"},
            "T2 for published answers; canonical answers are T3",
        ),
        _spec(
            "add_evidence_relation",
            "Add a typed relation between Evidence references.",
            "evidence.relation.write",
            ("consumer_evidence_id", "provider_evidence_id", "relation_type"),
            ("impact_policy", "rationale", "relation_id"),
            {
                "relation_id": _STRING,
                "consumer_evidence_id": _STRING,
                "provider_evidence_id": _STRING,
                "relation_type": {
                    "type": "string",
                    "enum": [
                        "depends_on",
                        "derived_from",
                        "reproduces",
                        "supports",
                        "challenges",
                        "amends",
                        "duplicates",
                        "context_for",
                    ],
                },
                "impact_policy": {"type": "string", "enum": ["hard", "soft", "informational"]},
                "rationale": _STRING,
            },
            {
                "consumer_evidence_id": "evidence_consumer",
                "provider_evidence_id": "evidence_provider",
                "relation_type": "depends_on",
            },
            "T1 direct reversible relation; propagation is recorded separately",
        ),
        *(
            _spec(
                op,
                f"{verb} an Evidence relation.",
                "evidence.relation.write",
                ("relation_id",),
                ("reason",),
                {"relation_id": _STRING, "reason": _STRING},
                {"relation_id": "evidence_relation_...", "reason": "Reviewed lifecycle change"},
                "T1 direct reversible relation; propagation is recorded separately",
            )
            for op, verb in (
                ("deactivate_evidence_relation", "Deactivate"),
                ("reactivate_evidence_relation", "Reactivate"),
            )
        ),
    )
}


def operation_spec(op: str) -> ChangeSetOperationSpec:
    try:
        return CHANGESET_OPERATION_SPECS[op]
    except KeyError as exc:
        raise ValidationError(f"Unsupported ChangeSet operation: {op!r}") from exc


def validate_operation_shape(operation: dict[str, Any], *, ordinal: int) -> None:
    require_strict_json(operation, path=f"$.operations[{ordinal}]")
    if not isinstance(operation, dict):
        raise ValidationError(f"ChangeSet operation {ordinal} must be an object")
    op = operation.get("op")
    if not isinstance(op, str):
        raise ValidationError(f"ChangeSet operation {ordinal} requires a string op")
    spec = operation_spec(op)
    schema = spec.schema
    if op == "evidence_applicability_decision":
        # The shared registry validator intentionally retains its v1 type
        # contract. Resolve the two advertised string|null fields locally so
        # the Q schema can faithfully preserve explicit null snapshots.
        operation, schema = _prepare_nullable_snapshot_fields(operation, schema)
    errors = validate_json_instance(operation, schema, path=f"$.operations[{ordinal}]")
    if errors:
        raise ValidationError(
            f"ChangeSet operation {ordinal} ({op}) failed its authoritative schema",
            details={"operation_ordinal": ordinal, "op": op, "field_errors": errors},
        )
    for field in spec.required_fields:
        value = operation[field]
        if (
            op == "evidence_applicability_decision"
            and operation.get("action") == "add"
            and field == "expected_version_id"
            and value == ""
        ):
            continue
        if isinstance(value, str) and not value.strip():
            raise ValidationError(
                f"ChangeSet operation {ordinal} ({op}) requires non-empty {field}"
            )


def _prepare_nullable_snapshot_fields(value: Any, schema: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    """Adapt Q's nullable proof/manifest fields for the legacy schema walker."""
    result = dict(schema)
    if schema.get("type") == ["string", "null"]:
        result["type"] = "string"
        return ("" if value is None else value), result
    if isinstance(value, dict):
        normalized = dict(value)
        children = {}
        for name, child in schema.get("properties", {}).items():
            if name in value:
                normalized[name], children[name] = _prepare_nullable_snapshot_fields(value[name], child)
            else:
                children[name] = child
        result["properties"] = children
        value = normalized
    elif isinstance(value, list) and isinstance(schema.get("items"), dict):
        normalized_items: list[Any] = []
        item_schema = schema["items"]
        for item in value:
            item_value, item_schema = _prepare_nullable_snapshot_fields(item, schema["items"])
            normalized_items.append(item_value)
        result["items"] = item_schema
        value = normalized_items
    return value, result


def operation_catalog(*, capabilities: frozenset[str] | set[str]) -> dict[str, Any]:
    return {
        "changeset_operation_catalog_version": "changeset-operation-catalog/v1",
        "changeset_envelope_schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "issue-manager://changesets/envelope/v1",
            "type": "object",
            "required": ["changeset_version", "intent", "operations"],
            "properties": {
                "changeset_version": {"type": "integer", "enum": [1]},
                "intent": {"type": "string"},
                "source_packet_ids": _STRING_ARRAY,
                "expected_revisions": _OBJECT,
                "operations": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "object", "additionalProperties": True, "properties": {}},
                },
            },
            "additionalProperties": True,
        },
        "replacement": {
            "create_field": "parent_changeset_id",
            "supersede_action": "POST /v1/changesets/{changeset_id}/supersede",
            "abandon_action": "POST /v1/changesets/{changeset_id}/abandon",
        },
        "operations": [
            spec.guide(available=spec.required_capability in capabilities)
            for spec in CHANGESET_OPERATION_SPECS.values()
        ],
    }
