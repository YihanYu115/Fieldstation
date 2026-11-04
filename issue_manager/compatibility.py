from __future__ import annotations

from copy import deepcopy
from typing import Any

from .policy import LEGACY_EVIDENCE_RELATION_DEFAULTS

COMPAT_NAMESPACE = "org.issue-manager.compat"
COMPAT_BUNDLE_NAME = "experimental-core"
COMPAT_BUNDLE_VERSION = "1.2.0"
COMPAT_TEMPLATE_REF = (
    f"{COMPAT_NAMESPACE}/issue_template/superconducting-qubit-project@{COMPAT_BUNDLE_VERSION}"
)
LEGACY_SCAFFOLD_ALIAS = "superconducting-qubit-project-v1"
LEGACY_COMPONENT_PARAMETER = "qubit"
LEGACY_COMPONENTS_PARAMETER = "qubits"


_ISSUE_TYPES: dict[str, dict[str, Any]] = {
    "sample": {
        "allowed_children": ["qubit", "interaction", "investigation", "report_scope"],
        "rollup_mode": "mixed",
    },
    "qubit": {
        "allowed_children": ["capability", "episode", "investigation"],
        "default_child_templates": [
            "readout",
            "excitation",
            "coherence",
            "operating-points",
        ],
        "rollup_mode": "mixed",
    },
    "capability": {
        "allowed_children": ["episode", "investigation"],
        "conclusion_schema": "generic-capability-v1",
        "rollup_mode": "semantic",
    },
    "interaction": {
        "allowed_children": ["episode", "investigation"],
        "conclusion_schema": "generic-interaction-v1",
        "rollup_mode": "semantic",
    },
    "episode": {
        "allowed_children": [],
        "conclusion_schema": "generic-episode-v1",
        "rollup_mode": "semantic",
    },
    "investigation": {
        "allowed_children": ["episode"],
        "conclusion_schema": "generic-investigation-v1",
        "rollup_mode": "semantic",
    },
    "report_scope": {
        "allowed_children": [],
        "conclusion_schema": "report-basis-v1",
        "rollup_mode": "mechanical",
    },
}


COMPAT_POLICY: dict[str, Any] = {
    "policy_version": 7,
    "issue_types": deepcopy(_ISSUE_TYPES),
    "publication": {
        "proposer_capability": "conclusion.propose",
        "apply_capability": "proposal.apply",
        "review_capability": "proposal.review",
        "review_quorum": {
            "draft": 0,
            "provisional": 0,
            "accepted": 1,
            "canonical": 2,
            "disputed": 0,
            "superseded": 1,
            "retracted": 1,
        },
        "report_facing_minimum_reviews": 2,
        "historical_basis_allowed": ["draft", "disputed", "retracted", "superseded"],
    },
    "publication_requirements": {
        "provisional": {"min_active_evidence": 0},
        "accepted": {
            "min_active_evidence": 1,
            "review_quorum": 1,
            "minimum_verification_level": "source_verified",
            "require_support_fit_for_use": True,
        },
        "canonical": {
            "min_active_evidence": 1,
            "review_quorum": 2,
            "minimum_verification_level": "snapshot_verified",
            "require_support_fit_for_use": True,
            "reject_conflict_as_only_support": True,
            "derived_result_requires_frozen_analysis": True,
        },
        "report_scope": {
            "review_quorum": 2,
            "minimum_verification_level": "snapshot_verified",
            "require_support_fit_for_use": True,
            "require_frozen_artifact": True,
            "require_analysis_run_or_waiver": True,
        },
    },
    "evidence": {
        "manifest_max_bytes": 262144,
        "verification_levels": [
            "declared",
            "source_verified",
            "snapshot_verified",
            "reproduced",
        ],
    },
    "resolver": {
        "minimum_score": 90,
        "minimum_lead": 15,
        "required_reasons": ["exact_scope", "topic_identity"],
    },
    "risk_policy": {"version": 1, "tiers": ["T0", "T1", "T2", "T3"]},
    "relation_defaults": {
        "rolls_up_from": "hard",
        "depends_on": "soft",
        "related_to": "none",
    },
    "evidence_relation_defaults": dict(LEGACY_EVIDENCE_RELATION_DEFAULTS),
    "conclusion_schemas": {
        "generic-capability-v1": {"required": []},
        "generic-interaction-v1": {"required": []},
        "generic-episode-v1": {"required": []},
        "generic-investigation-v1": {"required": []},
        "report-basis-v1": {"required": ["report_locator"]},
    },
}


def compatibility_bundle() -> dict[str, Any]:
    registrations: list[dict[str, Any]] = []
    for name, definition in _ISSUE_TYPES.items():
        schema_name = definition.get("conclusion_schema")
        schema_definition = COMPAT_POLICY["conclusion_schemas"].get(schema_name, {})
        required = list(schema_definition.get("required", []))
        profiles: dict[str, dict[str, Any]] = {}
        for status, quorum in COMPAT_POLICY["publication"]["review_quorum"].items():
            profile = dict(COMPAT_POLICY["publication_requirements"].get(status, {}))
            profile.setdefault("min_active_evidence", 0)
            profile.setdefault("minimum_verification_level", "declared")
            profile["review_quorum"] = int(profile.get("review_quorum", quorum))
            if name == "report_scope":
                profile.update(COMPAT_POLICY["publication_requirements"]["report_scope"])
                profile["review_quorum"] = max(
                    int(profile.get("review_quorum", 0)),
                    int(COMPAT_POLICY["publication"]["report_facing_minimum_reviews"]),
                )
            profiles[status] = profile
        allowed_children = [
            f"{COMPAT_NAMESPACE}/issue_type/{child}@{COMPAT_BUNDLE_VERSION}"
            for child in definition.get("allowed_children", [])
        ]
        registrations.append(
            {
                "kind": "issue_type",
                "name": name,
                "version": COMPAT_BUNDLE_VERSION,
                "api_version": "issue-type/v2",
                "definition": {
                    "allowed_children": allowed_children,
                    "rollup_mode": definition.get("rollup_mode", "semantic"),
                    "conclusion": {
                        "structured_outputs_schema": {
                            "type": "object",
                            "required": required,
                            "properties": {field: {} for field in required},
                            "additionalProperties": True,
                        },
                        "publication_profiles": profiles,
                        "report_facing": name == "report_scope",
                    },
                },
            }
        )
    registrations.extend(
        [
            {
                "kind": "issue_template",
                "name": "superconducting-qubit-project",
                "version": COMPAT_BUNDLE_VERSION,
                "api_version": "issue-template/v1",
                "definition": {
                    "parent_relation": {
                        "relation_type": "rolls_up_from",
                        "impact_policy": "hard",
                    },
                    "parameters": {
                        "sample": {"type": "string", "required": True},
                        "qubits": {"type": "array", "items": "string", "required": True},
                    },
                    "nodes": [
                        {
                            "id": "{sample}",
                            "issue_type": "sample",
                            "title": "{sample} sample",
                            "scope": {"sample": "{sample}"},
                            "topic": "sample",
                        },
                        {
                            "repeat": "qubits",
                            "as": "qubit_name",
                            "id": "{sample}-{qubit_name}",
                            "issue_type": "qubit",
                            "title": "{sample}/{qubit_name}",
                            "parent": "{sample}",
                            "scope": {"sample": "{sample}", "qubit": "{qubit_name}"},
                            "topic": "qubit",
                            "children_for_each": [
                                "readout",
                                "excitation",
                                "coherence",
                                "operating-points",
                            ],
                            "child": {
                                "id": "{sample}-{qubit_name}-{child_name}",
                                "issue_type": "capability",
                                "title": "{sample}/{qubit_name} {child_name}",
                                "parent": "{sample}-{qubit_name}",
                                "scope": {
                                    "sample": "{sample}",
                                    "qubit": "{qubit_name}",
                                },
                                "topic": "{child_name}",
                            },
                        },
                    ],
                    "compatibility_aliases": [LEGACY_SCAFFOLD_ALIAS],
                },
            },
            {
                "kind": "routing_profile",
                "name": "legacy-scope-topic",
                "version": COMPAT_BUNDLE_VERSION,
                "api_version": "routing-profile/v1",
                "definition": {
                    "rules": [
                        {"field": "scope", "operation": "exact", "weight": 70},
                        {"field": "topic", "operation": "normalized_exact", "weight": 30},
                    ]
                },
            },
            {
                "kind": "evidence_intake_template",
                "name": "generic-experiment-evidence",
                "version": COMPAT_BUNDLE_VERSION,
                "api_version": "evidence-intake-template/v1",
                "definition": {
                    "question_kinds": [
                        "experiment", "analysis", "data_gap", "conflict",
                        "verification", "decision",
                    ],
                    "required_fields": [
                        "/kind", "/locator", "/issue_id", "/description",
                        "/addresses_question_ids",
                    ],
                    "optional_fields": [
                        "/target_scope", "/quality_status", "/content_hash",
                        "/related_evidence",
                    ],
                    "allowed_relation_types": [
                        "depends_on", "derived_from", "reproduces", "supports",
                        "challenges", "amends", "duplicates", "context_for",
                    ],
                    "default_evidence_role": "support",
                    "artifact_requirements": {"content_addressed_when_uploaded": True},
                    "locator_requirements": {"exact_identity": True},
                    "manifest_requirements": {"required_for_platform_sources": True},
                    "analysis_summary_requirements": {"description_is_required": True},
                    "quality_requirements": {"default": "unknown"},
                    "proof_requirements": {"manager_recalculates": True},
                    "field_help": {
                        "/addresses_question_ids": "Exact Question IDs motivating the result",
                        "/related_evidence": "Explicit Evidence lineage declarations",
                    },
                    "examples": [],
                    "clarification_questions": [
                        "Which exact Issue and Question motivated this result?",
                        "Where is the immutable data or Artifact located?",
                        "Does this result depend on, amend, or challenge existing Evidence?",
                    ],
                    "deprecated": False,
                },
            },
            {
                "kind": "question_template",
                "name": "generic-experiment-questions",
                "version": COMPAT_BUNDLE_VERSION,
                "api_version": "question-template/v1",
                "definition": {
                    "questions": [
                        {
                            "question_key": "primary-result",
                            "prompt": "What result would resolve the current knowledge gap?",
                            "motivation": "Tie experimental work to an explicit question.",
                            "question_kind": "experiment",
                            "priority": 80,
                            "expected_evidence": [],
                            "required": True,
                            "output_fields": [],
                        }
                    ],
                    "deprecated": False,
                },
            },
            {
                "kind": "conclusion_summary_template",
                "name": "generic-issue-summary",
                "version": COMPAT_BUNDLE_VERSION,
                "api_version": "conclusion-summary-template/v1",
                "definition": {
                    "sections": ["answer", "basis", "limitations", "open_questions"],
                    "field_labels": {},
                    "question_mappings": {},
                    "limitation_display": {
                        "show_stale_answers": True,
                        "show_optional_provider_gaps": True,
                    },
                    "deprecated": False,
                },
            },
        ]
    )
    return {
        "manifest": {
            "bundle_format": "issue-manager-feature-bundle/v1",
            "namespace": COMPAT_NAMESPACE,
            "name": COMPAT_BUNDLE_NAME,
            "version": COMPAT_BUNDLE_VERSION,
            "core_api": ">=0.8,<1.0",
            "description": "Schema v14 compatibility semantics for legacy ledgers",
            "registrations": [],
            "dependencies": [],
        },
        "registrations": registrations,
    }
