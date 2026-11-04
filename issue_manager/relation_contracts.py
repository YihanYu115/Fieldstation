"""Closed, versioned relationship contracts used by the V1 resolver.

Business labels select a declared contract; they never select truth rules or
special recovery algorithms. Snapshots are copied into the frozen context rule.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from .context_journal import NON_SEMANTIC
from .errors import ValidationError

VERSION_ENDPOINTS_V1 = {
    "conclusion_version": ("conclusion_revisions", "conclusion_id"),
    "record_version": ("record_revisions", "record_revision_id"),
    "relation_version": ("managed_relation_versions", "version_id"),
}

# Runtime endpoint support can grow without rewriting the frozen v1 rule
# snapshot. The v2 rule snapshot opts in to this complete endpoint registry.
VERSION_ENDPOINTS = {
    **VERSION_ENDPOINTS_V1,
    "applicability_decision_version": (
        "evidence_applicability_decision_versions",
        "decision_version_id",
    ),
}


@dataclass(frozen=True)
class Domain:
    table: str
    role_column: str
    identity: tuple[str, ...]
    source: str
    target: str
    source_kind: str
    target_kind: str
    selector: str
    scopes: tuple[str, ...]
    active: str | None
    binding: str
    capability: str
    lifecycle: tuple[str, ...]


DOMAINS = {
    "issue": Domain("relations", "relation_type", ("relation_id",), "provider_issue_id", "consumer_issue_id",
                    "issue", "issue", "issue-provider", ("consumer_issue_id",), "active", "follow-current",
                    "relation.write", ("add", "disable", "enable", "replace", "head-change")),
    "evidence": Domain("evidence_relations", "relation_type", ("relation_id",), "provider_evidence_id", "consumer_evidence_id",
                       "evidence", "evidence", "evidence-component", ("consumer_evidence_id", "provider_evidence_id"), "active",
                       "current-proof-and-manifest", "evidence.relation.write", ("add", "disable", "enable", "replace", "head-change")),
    "question": Domain("issue_question_evidence_links", "link_type", ("relation_id",),
                       "evidence_id", "question_id", "evidence", "question", "question-material", ("question_id",), "active",
                       "current-proof-and-manifest", "question.write", ("add", "disable", "enable", "replace")),
    "record": Domain("record_material_relations", "relation_role", ("relation_id",),
                     "evidence_id", "record_revision_id", "evidence", "record-version-field", "record-field-material", ("record_revision_id",),
                     "active", "fixed-proof-plus-current-evidence", "record.create", ("add", "disable", "enable", "replace", "record-head-change")),
    "intake": Domain("intake_packet_links", "link_type", ("link_id",), "source_packet_id", "target_packet_id",
                     "packet-version", "packet-version", "packet-component", ("source_packet_id", "target_packet_id"), "active",
                     "fixed", "triage.manage", ("add", "disable", "enable", "replace")),
    "context": Domain("context_relations", "relation_type", ("relation_id",), "source_key", "target_key",
                      "typed-version", "typed-version", "typed-material-component", ("source_key", "target_key"), "active",
                      "fixed", "relation.write", ("add", "disable", "enable", "replace")),
    "triage": Domain("triage_dispositions", "disposition", ("packet_id",), "packet_id", "issue_id",
                     "packet-version", "issue-or-conclusion-version", "triage-material", ("issue_id",), None,
                     "fixed-packet-and-optional-conclusion", "triage.disposition", ("add",)),
}

MEANINGS = {
    "issue": {"rolls_up_from": "Consumer summarizes the provider judgment", "depends_on": "Consumer uses the provider judgment",
              "related_to": "Navigation to a related Issue"},
    "evidence": {"depends_on": "Consumer relies on provider material", "derived_from": "Provider is the generation source of consumer",
                 "supports": "Provider supports consumer", "challenges": "Provider challenges consumer", "reproduces": "Provider reports reproduction of consumer",
                 "amends": "Provider amends consumer", "duplicates": "Provider and consumer are claimed to duplicate", "context_for": "Provider supplies context for consumer"},
    "question": {"addresses": "Evidence addresses the question", "supports": "Evidence supports material considered for the question",
                 "challenges": "Evidence challenges material considered for the question", "context": "Evidence supplies question context"},
    "record": {"produced_by": "Evidence is the production source of the field", "calibration": "Evidence supplies field calibration",
               "supports": "Evidence supports the field", "contradicts": "Evidence contradicts the field", "context": "Evidence supplies field context"},
    "intake": {"followup_of": "Source follows up target", "tests_hypothesis_of": "Source tests a hypothesis in target",
               "challenges": "Source challenges target", "amends": "Source amends target", "duplicates": "Source is claimed to duplicate target",
               "grouped_with": "Source is grouped with target", "split_from": "Source was split from target"},
    "context": {"supports": "Source supports target", "challenges": "Source challenges target", "reproduces": "Source reports reproduction of target",
                "amends": "Source amends target", "context_for": "Source supplies target context", "derived_from": "Source is a derivation from target",
                "depends_on": "Source states dependence on target", "duplicates": "Source is claimed to duplicate target"},
    "triage": {"supports_current": "Packet supports a target judgment", "challenges_current": "Packet challenges a target judgment",
               "amends_previous": "Packet amends a target judgment", "no_impact": "Packet is classified as outside the target context",
               "proposal_created": "A proposal was created", "duplicate": "Packet was classified as duplicate",
               "rejected": "Packet was rejected", "needs_input": "Triage needs input", "evidence_requested": "Evidence was requested"},
}


@dataclass(frozen=True)
class RelationContract:
    type_key: str
    contract_version: str
    domain: str
    role: str
    meaning: str
    participation: str
    source_currentness_default: bool

    def snapshot(self, *, version="v1"):
        spec = DOMAINS[self.domain]
        snapshot = {
            **asdict(self),
            "endpoints": {"source": {"field": spec.source, "kind": spec.source_kind},
                          "target": {"field": spec.target, "kind": spec.target_kind},
                          "allowed_version_kinds": list(
                              VERSION_ENDPOINTS if version == "v2" else VERSION_ENDPOINTS_V1
                          ) if self.domain == "context" else [],
                          "relation_targets": self.domain == "context"},
            "orientation": {"storage": "explicit-source-and-target-fields", "currentness_edge": "source-conclusion-to-consuming-conclusion"},
            "context_selection": {"selector": spec.selector, "scope_columns": list(spec.scopes),
                                  "active_column": spec.active, "empty_ranges": True,
                                  "participation": self.participation, "closure": "finite-node-set" if "component" in spec.selector else "declared-direct-range"},
            "binding_defaults": {"content": spec.binding, "source_currentness": self.source_currentness_default,
                                 "fixed_currentness_override": self.domain in {"issue", "context"}},
            "maintenance": {"ContentBinding": True, "CollectionWatch": True,
                            "FreshnessDependency": "explicit-source-conclusion" if self.domain in {"issue", "context"} else "none"},
            "triggers": {"operations": list(spec.lifecycle), "candidate_fields": list(spec.scopes), "old_and_new_ranges": True},
            "snapshot_projection": {"table": spec.table, "role_column": spec.role_column,
                                    "excluded_runtime_fields": sorted(NON_SEMANTIC), "json_fields": "parse-structurally",
                                    "immutable_relation_head": self.domain in {"issue", "evidence", "context"}},
            "aggregation": {"identity_columns": list(spec.identity), "calculation_edges": "set-of-independent-contributions",
                            "independent_named_identity": self.domain in {"issue", "evidence", "context"}},
            "constraints": {"typed_existing_endpoints": True, "no_truth_inference": True,
                            "legacy_membership_key": self.domain in {"question", "record"},
                            "legacy_endpoint_uniqueness": self.domain in {"question", "record", "intake"},
                            "source_currentness_requires_conclusion": True},
            "workflow_policy": {"capability": spec.capability, "dirty_is_not_workflow": True,
                                "publication": "existing-reviewed-business-policy"},
            "migration": {"source_table": spec.table, "identity_mapping": list(spec.identity),
                          "missing_historical_receipt": "needs-verification", "unknown_roles": "retain-input-and-fail-closed"},
            "truth_effect": "none",
        }
        if version == "v2":
            snapshot["applicability_effect"] = "none"
        return snapshot


class RelationContractRegistry:
    def __init__(self):
        self._contracts = {}
        for domain, meanings in MEANINGS.items():
            for role, meaning in meanings.items():
                participation = "context"
                if (domain, role) == ("issue", "related_to"):
                    participation = "navigation"
                elif domain == "triage" and role not in {"supports_current", "challenges_current", "amends_previous"}:
                    participation = "workflow"
                self._contracts[(domain, role)] = RelationContract(
                    f"{domain}.{role}", "1", domain, role, meaning, participation,
                    domain == "issue" and participation == "context")
        self.by_table = {spec.table: domain for domain, spec in DOMAINS.items()}

    def roles(self, domain, *, participation=None):
        return tuple(role for (group, role), contract in self._contracts.items()
                     if group == domain and (participation is None or contract.participation == participation))

    def require(self, domain, role):
        contract = self._contracts.get((domain, role))
        if contract is None:
            raise ValidationError(f"Unclassified relationship contract: {domain}.{role}")
        return contract

    def row_contract(self, table, row):
        domain = self.by_table.get(table)
        return self.require(domain, row[DOMAINS[domain].role_column]) if domain else None

    def snapshot(self, *, version="v1"):
        return [self._contracts[key].snapshot(version=version) for key in sorted(self._contracts)]

    def validate_schema(self, conn):
        """Fail at startup if a migration and its declared adapters diverge."""
        for domain, spec in DOMAINS.items():
            metadata = list(conn.execute(f'PRAGMA table_info("{spec.table}")'))
            columns = {row[1] for row in metadata}
            identity = tuple(row[1] for row in sorted(metadata, key=lambda row: row[5]) if row[5])
            if identity != spec.identity:
                raise ValidationError(f"Relationship identity and SQL primary key differ: {domain}")
            required = {spec.source, spec.target, spec.role_column, *spec.identity, *spec.scopes}
            if spec.active:
                required.add(spec.active)
            if not required <= columns:
                raise ValidationError(f"Relationship contract columns missing: {domain}: {sorted(required - columns)}")
            sql = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (spec.table,)).fetchone()[0]
            check = re.search(rf"CHECK\s*\(\s*{spec.role_column}\s+IN\s*\((.*?)\)", sql, re.I | re.S)
            if not check or set(re.findall(r"'([^']+)'", check[1])) != set(self.roles(domain)):
                raise ValidationError(f"Relationship contract roles and SQL schema differ: {domain}")


REGISTRY = RelationContractRegistry()
RELATION_ROLES = {domain: REGISTRY.roles(domain) for domain in DOMAINS}
