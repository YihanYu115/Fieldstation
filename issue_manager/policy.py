from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import ValidationError

EVIDENCE_RELATION_TYPES = frozenset(
    {
        "depends_on",
        "derived_from",
        "reproduces",
        "supports",
        "challenges",
        "amends",
        "duplicates",
        "context_for",
    }
)
EVIDENCE_IMPACT_POLICIES = frozenset({"hard", "soft", "informational"})
EVIDENCE_IMPACT_ORDER = {"informational": 0, "soft": 1, "hard": 2}

# Compatibility fallback for policy files created before
# evidence_relation_defaults existed. Keep this in the policy boundary so
# domain services do not carry a second, hidden mapping.
LEGACY_EVIDENCE_RELATION_DEFAULTS = {
    "depends_on": "hard",
    "derived_from": "hard",
    "reproduces": "soft",
    "supports": "soft",
    "challenges": "soft",
    "amends": "hard",
    "duplicates": "informational",
    "context_for": "informational",
}


class Policy:
    def __init__(self, data: dict[str, Any], path: Path):
        self.data = data
        self.path = path
        if not isinstance(data.get("policy_version"), int):
            raise ValidationError("policy.yaml must contain an integer policy_version")
        self._validate_evidence_relation_defaults()

    def _validate_evidence_relation_defaults(self) -> None:
        if "evidence_relation_defaults" not in self.data:
            return
        configured = self.data["evidence_relation_defaults"]
        if not isinstance(configured, dict):
            raise ValidationError("evidence_relation_defaults must be an object")
        expected = set(EVIDENCE_RELATION_TYPES)
        actual = set(configured)
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        if missing or unknown:
            details = []
            if missing:
                details.append(f"missing={missing}")
            if unknown:
                details.append(f"unknown={unknown}")
            raise ValidationError(
                "evidence_relation_defaults must contain exactly the supported relation types ("
                + ", ".join(details)
                + ")"
            )
        invalid = {
            key: value
            for key, value in configured.items()
            if not isinstance(value, str) or value not in EVIDENCE_IMPACT_POLICIES
        }
        if invalid:
            raise ValidationError(
                "evidence_relation_defaults values must be one of hard, soft, informational; "
                f"invalid={invalid}"
            )

    @classmethod
    def load(cls, path: Path) -> "Policy":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ValidationError(f"Policy file not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise ValidationError(
                f"policy.yaml must use the MVP's JSON-compatible YAML syntax: {exc}"
            ) from exc
        return cls(data, path)

    @property
    def version(self) -> int:
        return int(self.data["policy_version"])

    def issue_type(self, name: str) -> dict[str, Any]:
        try:
            return self.data["issue_types"][name]
        except KeyError as exc:
            allowed = ", ".join(sorted(self.data.get("issue_types", {})))
            raise ValidationError(f"Unknown issue type {name!r}; allowed: {allowed}") from exc

    def validate_child(self, parent_type: str, child_type: str) -> None:
        allowed = self.issue_type(parent_type).get("allowed_children", [])
        if child_type not in allowed:
            raise ValidationError(
                f"Policy does not allow {child_type!r} below {parent_type!r}; allowed: {allowed}"
            )

    def default_impact(self, relation_type: str) -> str:
        try:
            return self.data["relation_defaults"][relation_type]
        except KeyError as exc:
            allowed = ", ".join(sorted(self.data.get("relation_defaults", {})))
            raise ValidationError(
                f"Unknown relation type {relation_type!r}; allowed: {allowed}"
            ) from exc

    def evidence_relation_defaults(self) -> dict[str, str]:
        if "evidence_relation_defaults" not in self.data:
            return dict(LEGACY_EVIDENCE_RELATION_DEFAULTS)
        configured = self.data["evidence_relation_defaults"]
        return {key: str(configured[key]) for key in EVIDENCE_RELATION_TYPES}

    def evidence_relation_default(self, relation_type: str) -> str:
        defaults = self.evidence_relation_defaults()
        try:
            return defaults[relation_type]
        except KeyError as exc:
            allowed = ", ".join(sorted(defaults))
            raise ValidationError(
                f"Unknown Evidence relation type {relation_type!r}; allowed: {allowed}"
            ) from exc

    def resolve_evidence_relation_impact(
        self, relation_type: str, requested: str | None = None
    ) -> dict[str, str]:
        default = self.evidence_relation_default(relation_type)
        value = default if requested is None else requested
        if value not in EVIDENCE_IMPACT_POLICIES:
            raise ValidationError(f"Unknown Evidence impact policy: {value!r}")
        effective = (
            default
            if EVIDENCE_IMPACT_ORDER[default] >= EVIDENCE_IMPACT_ORDER[value]
            else value
        )
        return {"default": default, "requested": value, "effective": effective}

    def review_quorum(self, status: str, *, report_facing: bool = False) -> int:
        publication = self.data.get("publication", {})
        quorum = int(publication.get("review_quorum", {}).get(status, 0))
        if report_facing:
            quorum = max(quorum, int(publication.get("report_facing_minimum_reviews", 2)))
        return quorum

    def publication_requirements(
        self, status: str, *, report_facing: bool = False
    ) -> dict[str, Any]:
        requirements = dict(self.data.get("publication_requirements", {}).get(status, {}))
        if report_facing:
            requirements.update(
                self.data.get("publication_requirements", {}).get("report_scope", {})
            )
        return requirements

    def validate_structured_outputs(self, issue_type: str, outputs: dict[str, Any]) -> None:
        type_policy = self.issue_type(issue_type)
        schema_name = type_policy.get("conclusion_schema")
        if not schema_name:
            return
        schema = self.data.get("conclusion_schemas", {}).get(schema_name)
        if schema is None:
            raise ValidationError(f"Policy refers to missing conclusion schema {schema_name!r}")
        missing = [field for field in schema.get("required", []) if field not in outputs]
        if missing:
            raise ValidationError(
                f"Conclusion schema {schema_name!r} is missing structured outputs: {missing}"
            )
