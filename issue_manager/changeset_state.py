from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .errors import ValidationError
from .scope_identity import SampleKey, ScopeKey

if TYPE_CHECKING:
    from .service import IssueManager


@dataclass
class StateView:
    """Explicit ledger pre-state plus rollback-free ChangeSet overlays.

    Risk and semantic simulation read through this object instead of reaching
    into whatever database state happens to be current. Each operation advances
    the view, so operation N observes the modeled effects of operations 0..N-1.
    """

    manager: IssueManager
    virtual_issues: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence_attachment_additions: set[tuple[str, str]] = field(default_factory=set)
    evidence_attachment_removals: set[tuple[str, str]] = field(default_factory=set)
    evidence_lifecycle: dict[str, str] = field(default_factory=dict)
    evidence_quality: dict[str, str] = field(default_factory=dict)
    publication_status_additions: dict[str, set[str]] = field(default_factory=dict)
    virtual_questions: dict[str, dict[str, Any]] = field(default_factory=dict)
    question_status: dict[str, str] = field(default_factory=dict)
    issue_relation_active: dict[str, bool] = field(default_factory=dict)
    issue_relation_impact: dict[str, str] = field(default_factory=dict)
    evidence_relation_active: dict[str, bool] = field(default_factory=dict)
    new_issue_relations: set[tuple[str, str, str]] = field(default_factory=set)
    new_hard_issue_edges: set[tuple[str, str]] = field(default_factory=set)
    new_evidence_relations: set[tuple[str, str, str]] = field(default_factory=set)
    new_hard_evidence_edges: set[tuple[str, str]] = field(default_factory=set)
    trace: list[dict[str, Any]] = field(default_factory=list)
    context_relation_rows: dict[str, dict[str, Any]] = field(default_factory=dict)
    question_relation_rows: dict[str, dict[str, Any]] = field(default_factory=dict)
    intake_relation_rows: dict[str, dict[str, Any]] = field(default_factory=dict)
    record_relation_rows: dict[str, dict[str, Any]] = field(default_factory=dict)
    issue_relation_rows: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence_relation_rows: dict[str, dict[str, Any]] = field(default_factory=dict)
    material_versions: dict[str, dict[str, Any]] = field(default_factory=dict)
    material_heads: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    applicability_versions: dict[str, dict[str, Any]] = field(default_factory=dict)
    applicability_heads: dict[str, dict[str, Any]] = field(default_factory=dict)
    selected_receipts: dict[str, str | None] = field(default_factory=dict)
    receipt_eligibility: dict[str, bool] = field(default_factory=dict)
    context_rule: dict[str, Any] | None = None
    obligations: dict[str, dict[str, Any]] = field(default_factory=dict)
    appended_work: list[dict[str, Any]] = field(default_factory=list)
    published_issue_rows: dict[str, dict[str, Any]] = field(default_factory=dict)
    published_evidence_uses: dict[str, set[str]] = field(default_factory=dict)
    published_conclusions: dict[str, dict[str, Any]] = field(default_factory=dict)
    rollup_policies: dict[str, dict[str, Any]] = field(default_factory=dict)
    new_evidence: dict[str, dict[str, Any]] = field(default_factory=dict)
    new_proofs: dict[str, dict[str, Any]] = field(default_factory=dict)
    source_bindings: dict[str, dict[str, Any]] = field(default_factory=dict)
    attestations: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence_requests: dict[str, dict[str, Any]] = field(default_factory=dict)
    field_bundle_event_actions: dict[str, dict[str, Any]] = field(default_factory=dict)
    field_bundle_events: dict[str, dict[str, Any]] = field(default_factory=dict)
    field_bundles: dict[str, dict[str, Any]] = field(default_factory=dict)
    import_items: dict[str, dict[str, Any]] = field(default_factory=dict)
    import_jobs: dict[str, dict[str, Any]] = field(default_factory=dict)
    external_object_mappings: dict[str, dict[str, Any]] = field(default_factory=dict)
    external_mapping_targets: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)
    record_instances: dict[str, dict[str, Any]] = field(default_factory=dict)
    record_revisions: dict[str, dict[str, Any]] = field(default_factory=dict)
    record_evidence_links: dict[tuple[str, str, str, str], dict[str, Any]] = field(default_factory=dict)
    governed_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    integration_conflicts: dict[str, dict[str, Any]] = field(default_factory=dict)
    identity_ambiguities: dict[str, dict[str, Any]] = field(default_factory=dict)
    verified_packages: dict[str, str] = field(default_factory=dict)
    triage_dispositions: dict[str, dict[str, Any]] = field(default_factory=dict)

    def has_current_evidence_use(self, evidence_id: str) -> bool:
        for row in self.manager.store.rows(
            "SELECT DISTINCT i.issue_id FROM issues i JOIN conclusion_evidence_uses u "
            "ON u.conclusion_id=i.current_conclusion_id WHERE u.evidence_id=?", (evidence_id,)
        ):
            if row["issue_id"] not in self.published_evidence_uses:
                return True
        return any(evidence_id in uses for uses in self.published_evidence_uses.values())

    def context_rows(self, table: str, column: str, value: Any):
        """Overlay only modeled rows; range moves remove old matches as well."""
        base = self.manager.store.rows(f'SELECT * FROM "{table}" WHERE "{column}" IS ?', (value,))
        if table == "working_entries":
            # New entry IDs are allocated at execution, so they cannot be
            # addressed by a previously prepared fixed-ID selector. Other
            # ranges observe the exact body/type/references of staged writes.
            return base + ([] if column == "entry_id" else [
                row for row in self.appended_work if row[column] == value])
        if table == "evidence_applicability_decision_versions":
            merged = {row["decision_version_id"]: row for row in base}
            for identity, row in self.applicability_versions.items():
                merged.pop(identity, None)
                if row.get(column) == value:
                    merged[identity] = row
            return list(merged.values())
        if table == "evidence_applicability_decision_heads":
            merged = {row["decision_key"]: row for row in base}
            for key, row in self.applicability_heads.items():
                merged.pop(key, None)
                if row.get(column) == value:
                    merged[key] = row
            return list(merged.values())
        if table == "issue_evidence":
            merged = {(row["issue_id"], row["evidence_id"]): row for row in base}
            for attachment_key in self.evidence_attachment_removals:
                merged.pop(attachment_key, None)
            for issue_id, evidence_id in self.evidence_attachment_additions:
                row = {"issue_id": issue_id, "evidence_id": evidence_id,
                       "attached_at": None, "attached_by": None}
                if row[column] == value:
                    merged.setdefault((issue_id, evidence_id), row)
            return list(merged.values())
        if table == "record_evidence_links":
            merged_links: dict[tuple[str, str, str, str], dict[str, Any]] = {
                (row["record_revision_id"], row["field_path"], row["evidence_id"], row["relation_role"]): row
                for row in base
            }
            for link_key, link_row in self.record_evidence_links.items():
                merged_links[link_key] = link_row
            return [row for row in merged_links.values() if row[column] == value]
        if table == "external_mapping_targets":
            merged_targets: dict[tuple[str, str, str], dict[str, Any]] = {
                (row["source_object_mapping_id"], row["internal_object_type"], row["internal_object_id"]): row
                for row in base
            }
            merged_targets.update(self.external_mapping_targets)
            return [row for row in merged_targets.values() if row[column] == value]
        definitions: dict[str, tuple[str, Mapping[str, Any], Callable[[str], dict[str, Any] | None]]] = {
            "field_bundle_event_actions": ("field_bundle_event_action_id", self.field_bundle_event_actions, self.field_bundle_event_actions.get),
            "field_bundle_events": ("field_bundle_event_id", self.field_bundle_events, self.field_bundle_events.get),
            "field_bundles": ("field_bundle_id", self.field_bundles, self.field_bundles.get),
            "import_items": ("import_item_id", self.import_items, self.import_items.get),
            "import_jobs": ("import_job_id", self.import_jobs, self.import_jobs.get),
            "external_object_mappings": ("source_object_mapping_id", self.external_object_mappings, self.external_object_mappings.get),
            "record_instances": ("record_instance_id", self.record_instances, self.record_instances.get),
            "record_revisions": ("record_revision_id", self.record_revisions, self.record_revisions.get),
            "integration_conflicts": ("integration_conflict_id", self.integration_conflicts, self.integration_conflicts.get),
            "evidence_identity_ambiguities": ("ambiguity_id", self.identity_ambiguities, self.identity_ambiguities.get),
            "evidence_source_bindings": ("evidence_id", self.source_bindings, self.source_bindings.get),
            "evidence_attestations": ("attestation_id", self.attestations, self.attestations.get),
            "evidence_requests": ("evidence_request_id", self.evidence_requests, self.evidence_requests.get),
            "record_material_relations": ("relation_id", self.record_relation_rows, self.record_relation),
            "intake_packet_links": ("link_id", self.intake_relation_rows, self.intake_relation),
            "issue_question_evidence_links": ("relation_id", self.question_relation_rows, self.question_relation),
            "triage_dispositions": ("packet_id", self.triage_dispositions, self.triage_dispositions.get),
            "issue_rollup_policies": ("issue_id", self.rollup_policies, self.rollup_policies.get),
            "issue_questions": ("question_id", self.virtual_questions, self.question_row),
            "issues": ("issue_id", {**self.virtual_issues, **self.published_issue_rows}, self.issue_row),
            "conclusion_revisions": ("conclusion_id", self.published_conclusions, self.published_conclusions.get),
            "evidence_refs": ("evidence_id", {**self.new_evidence, **self.evidence_lifecycle, **self.evidence_quality}, self.evidence),
            "evidence_proofs": ("proof_id", self.new_proofs, self.new_proofs.get),
            "relations": ("relation_id", self.issue_relation_rows, self.issue_relation),
            "evidence_relations": ("relation_id", self.evidence_relation_rows, self.evidence_relation),
            "context_relations": ("relation_id", self.context_relation_rows, self.context_relation),
            "managed_relation_versions": ("version_id", self.material_versions, self.material_version),
        }
        if table not in definitions:
            return base
        identity, overlay, lookup = definitions[table]
        keys = set(overlay)
        if table == "issue_questions":
            keys.update(self.question_status)
        if table == "relations":
            keys.update(self.issue_relation_active)
            keys.update(self.issue_relation_impact)
        elif table == "evidence_relations":
            keys.update(self.evidence_relation_active)
        merged_rows = {row[identity]: row for row in base}
        for overlay_key in keys:
            overlay_row = lookup(overlay_key)
            merged_rows.pop(overlay_key, None)
            if overlay_row and overlay_row[column] == value:
                merged_rows[overlay_key] = overlay_row
        return list(merged_rows.values())

    def record_instance(self, record_instance_id: str) -> dict[str, Any]:
        row = self.record_instances.get(record_instance_id) or self.manager.store.row(
            "SELECT * FROM record_instances WHERE record_instance_id=?", (record_instance_id,)
        )
        if not row:
            raise ValidationError(f"Record not found: {record_instance_id}")
        return dict(row)

    def record_revision(self, record_revision_id: str) -> dict[str, Any]:
        row = self.record_revisions.get(record_revision_id) or self.manager.store.row(
            "SELECT * FROM record_revisions WHERE record_revision_id=?", (record_revision_id,)
        )
        if not row:
            raise ValidationError(f"Record revision not found: {record_revision_id}")
        return dict(row)

    def material_version(self, version_id: str):
        return self.material_versions.get(version_id) or self.manager.store.row(
            "SELECT * FROM managed_relation_versions WHERE version_id=?", (version_id,))

    def material_head(self, domain: str, relation_id: str):
        return self.material_heads.get((domain, relation_id)) or self.manager.store.row(
            "SELECT v.* FROM managed_relation_heads h JOIN managed_relation_versions v USING(version_id) "
            "WHERE h.domain=? AND h.relation_id=?", (domain, relation_id))

    def applicability_version(self, version_id: str) -> dict[str, Any] | None:
        return self.applicability_versions.get(version_id) or self.manager.store.row(
            "SELECT * FROM evidence_applicability_decision_versions WHERE decision_version_id=?",
            (version_id,),
        )

    def applicability_versions_for_key(self, decision_key: str) -> list[dict[str, Any]]:
        rows = self.manager.store.rows(
            "SELECT * FROM evidence_applicability_decision_versions WHERE decision_key=? "
            "ORDER BY version_number", (decision_key,),
        )
        merged = {row["decision_version_id"]: row for row in rows}
        for identity, row in self.applicability_versions.items():
            if row["decision_key"] == decision_key:
                merged[identity] = row
        return sorted(merged.values(), key=lambda row: int(row["version_number"]))

    def applicability_head(self, decision_key: str) -> dict[str, Any] | None:
        staged = self.applicability_heads.get(decision_key)
        if staged is not None:
            version = self.applicability_version(staged["decision_version_id"])
            return {**(version or {}), **staged}
        return self.manager.store.row(
            "SELECT v.*,h.active,h.head_revision,h.updated_at AS head_updated_at,"
            "h.updated_by AS head_updated_by FROM evidence_applicability_decision_heads h "
            "JOIN evidence_applicability_decision_versions v "
            "ON v.decision_key=h.decision_key AND v.decision_version_id=h.decision_version_id "
            "WHERE h.decision_key=?", (decision_key,),
        )

    def applicability_head_rows(self, *, scope_issue_id: str | None = None) -> list[dict[str, Any]]:
        rows = self.manager.store.rows(
            "SELECT v.*,h.active AS head_active,h.head_revision,"
            "h.updated_at AS head_updated_at,h.updated_by AS head_updated_by "
            "FROM evidence_applicability_decision_heads h JOIN "
            "evidence_applicability_decision_versions v ON v.decision_key=h.decision_key "
            "AND v.decision_version_id=h.decision_version_id"
        )
        merged = {row["decision_key"]: dict(row) for row in rows}
        for key, head in self.applicability_heads.items():
            version = self.applicability_version(head["decision_version_id"])
            merged[key] = {
                **(version or {}),
                **head,
                "head_active": int(bool(head["active"])),
                "head_updated_at": head.get("updated_at"),
                "head_updated_by": head.get("updated_by"),
            }
        result = [row for row in merged.values()
                  if scope_issue_id is None or row.get("scope_issue_id") == scope_issue_id]
        return sorted(result, key=lambda row: (str(row.get("decision_key", "")),
                                                str(row.get("decision_version_id", ""))))

    def stage_applicability_plan(self, plan: dict[str, Any]) -> None:
        """Advance the applicability overlay after shared planner validation."""
        from .store import canonical_json

        version = plan.get("version")
        if version is not None:
            staged = dict(version)
            staged["qualification_json"] = canonical_json({
                "actor_id": "simulation-actor",
                "run_id": "simulation-run",
                "capability": "evidence.applicability.write",
                "changeset_id": "simulation-changeset",
                "changeset_hash": "simulation-hash",
                "risk_tier": "T1",
                "review_ids": [],
                "rule_id": "evidence-applicability/v1",
                "validation_results": {key: True for key in
                                        ("scope", "target", "basis", "capability", "risk", "reviews")},
            })
            staged["changeset_id"] = "simulation-changeset"
            staged["__simulated_validated__"] = True
            self.applicability_versions[staged["decision_version_id"]] = staged
        after = dict(plan["after_head"])
        after["updated_at"] = None
        after["updated_by"] = None
        self.applicability_heads[plan["decision_key"]] = after

    def applicability_projection(self, scope_issue_id: str, evidence_ids=None) -> dict[str, Any]:
        return self.manager.evidence_applicability.projection(
            scope_issue_id=scope_issue_id, evidence_ids=evidence_ids, state_view=self,
        )

    def context_relation(self, relation_id: str):
        return self.context_relation_rows.get(relation_id) or self.manager.store.row(
            "SELECT * FROM context_relations WHERE relation_id=?", (relation_id,))

    def question_relation(self, relation_id: str):
        return self.question_relation_rows.get(relation_id) or self.manager.store.row(
            "SELECT * FROM issue_question_evidence_links WHERE relation_id=?", (relation_id,))

    def intake_relation(self, link_id: str):
        return self.intake_relation_rows.get(link_id) or self.manager.store.row(
            "SELECT * FROM intake_packet_links WHERE link_id=?", (link_id,))

    def record_relation(self, relation_id: str):
        return self.record_relation_rows.get(relation_id) or self.manager.store.row(
            "SELECT * FROM record_material_relations WHERE relation_id=?", (relation_id,))

    def stage_legacy_relation(self, domain: str, row: dict[str, Any]) -> None:
        from .store import canonical_json

        identity = row["relation_id"]
        head = self.material_head(domain, identity)
        if not head:
            raise ValidationError("Missing relationship version in simulated state")
        old_content = json.loads(head["definition_json"])
        content = {key: row[key] for key in old_content}
        number = head["version_number"] + int(content != old_content)
        version = {**head, "version_id": f"{domain}:{identity}:{number}", "version_number": number,
                   "definition_json": canonical_json(content)}
        (self.issue_relation_rows if domain == "issue" else self.evidence_relation_rows)[identity] = dict(row)
        self.material_versions[version["version_id"]] = version
        self.material_heads[(domain, identity)] = version

    def stage_new_relation(self, domain: str, row: dict[str, Any]) -> None:
        from .relation_versions import RELATION_RUNTIME_FIELDS
        from .store import canonical_json

        identity = row["relation_id"]
        version = {"version_id": f"{domain}:{identity}:1", "domain": domain, "relation_id": identity,
                   "version_number": 1, "contract_version": "context-currentness/v1",
                   "definition_json": canonical_json({key: value for key, value in row.items()
                                                      if key not in RELATION_RUNTIME_FIELDS})}
        (self.issue_relation_rows if domain == "issue" else self.evidence_relation_rows)[identity] = row
        self.material_versions[version["version_id"]] = version
        self.material_heads[(domain, identity)] = version

    def issue(self, issue_id: str) -> dict[str, Any]:
        virtual = self.virtual_issues.get(issue_id)
        row = dict(virtual) if virtual is not None else {
            **self.manager._issue(issue_id, active=False), **self.published_issue_rows.get(issue_id, {})}
        if row.get("current_conclusion_id"):
            from .context_currentness_preview import is_current

            row["freshness"] = "fresh" if is_current(self, row["current_conclusion_id"]) else "stale"
        return row

    def issue_row(self, issue_id: str):
        row = self.published_issue_rows.get(issue_id) or self.virtual_issues.get(issue_id) or self.manager.store.row(
            "SELECT * FROM issues WHERE issue_id=?", (issue_id,))
        if row is None:
            return None
        columns = {column[1] for column in self.manager.store.conn.execute("PRAGMA table_info(issues)")}
        return {key: value for key, value in row.items() if key in columns}

    def sample_for_issue(self, issue_id: str) -> SampleKey | None:
        return SampleKey.from_scope(self.issue(issue_id).get("scope", {}))

    def scope_for_issue(self, issue_id: str) -> ScopeKey | None:
        return ScopeKey.from_scope(self.issue(issue_id).get("scope", {}))

    def evidence(self, evidence_id: str) -> dict[str, Any]:
        row = self.new_evidence.get(evidence_id) or self.manager.store.row(
            "SELECT * FROM evidence_refs WHERE evidence_id=?", (evidence_id,)
        )
        if not row:
            raise ValidationError(f"Evidence not found: {evidence_id}")
        row = dict(row)
        if evidence_id in self.evidence_lifecycle:
            row["lifecycle_status"] = self.evidence_lifecycle[evidence_id]
        if evidence_id in self.evidence_quality:
            row["quality_status"] = self.evidence_quality[evidence_id]
        return row

    def evidence_samples(self, evidence_id: str) -> set[SampleKey]:
        samples: set[SampleKey] = set()
        for row in self.manager.store.rows(
            "SELECT ie.issue_id,i.scope_json FROM issue_evidence ie "
            "JOIN issues i ON i.issue_id=ie.issue_id WHERE ie.evidence_id=?",
            (evidence_id,),
        ):
            if (str(row["issue_id"]), evidence_id) in self.evidence_attachment_removals:
                continue
            scope = json.loads(row["scope_json"])
            sample = SampleKey.from_scope(scope if isinstance(scope, dict) else {})
            if sample:
                samples.add(sample)
        for issue_id, attached_evidence_id in self.evidence_attachment_additions:
            key = (issue_id, attached_evidence_id)
            if attached_evidence_id != evidence_id or key in self.evidence_attachment_removals:
                continue
            sample = self.sample_for_issue(issue_id)
            if sample:
                samples.add(sample)
        return samples

    def evidence_publication_statuses(self, evidence_id: str) -> set[str]:
        statuses = set(self.publication_status_additions.get(evidence_id, set()))
        statuses.update(
            str(row["status"])
            for row in self.manager.store.rows(
                "SELECT DISTINCT c.status FROM conclusion_evidence_uses u "
                "JOIN conclusion_revisions c ON c.conclusion_id=u.conclusion_id "
                "WHERE u.evidence_id=?",
                (evidence_id,),
            )
            if row.get("status")
        )
        return statuses

    def is_evidence_attached(self, issue_id: str, evidence_id: str) -> bool:
        key = (issue_id, evidence_id)
        if key in self.evidence_attachment_removals:
            return False
        if key in self.evidence_attachment_additions:
            return True
        return bool(
            self.manager.store.row(
                "SELECT 1 FROM issue_evidence WHERE issue_id=? AND evidence_id=?",
                key,
            )
        )

    def question(self, question_id: str) -> dict[str, Any]:
        question = self.virtual_questions.get(question_id)
        if question is None:
            question = self.manager.questions.show(question_id)
        result = dict(question)
        if question_id in self.question_status:
            result["status"] = self.question_status[question_id]
        return result

    def question_row(self, question_id: str) -> dict[str, Any] | None:
        row = self.virtual_questions.get(question_id) or self.manager.store.row(
            "SELECT * FROM issue_questions WHERE question_id=?", (question_id,))
        if row is None:
            return None
        columns = {column[1] for column in self.manager.store.conn.execute("PRAGMA table_info(issue_questions)")}
        result = {key: value for key, value in row.items() if key in columns}
        if question_id in self.question_status:
            result["status"] = self.question_status[question_id]
        return result

    def issue_relation(self, relation_id: str) -> dict[str, Any] | None:
        relation = self.issue_relation_rows.get(relation_id) or self.manager.store.row(
            "SELECT * FROM relations WHERE relation_id=?", (relation_id,)
        )
        if relation:
            relation = dict(relation)
            if relation_id in self.issue_relation_active:
                relation["active"] = self.issue_relation_active[relation_id]
            if relation_id in self.issue_relation_impact:
                relation["impact_policy"] = self.issue_relation_impact[relation_id]
        return relation

    def evidence_relation(self, relation_id: str) -> dict[str, Any] | None:
        relation = self.evidence_relation_rows.get(relation_id) or self.manager.store.row(
            "SELECT * FROM evidence_relations WHERE relation_id=?", (relation_id,)
        )
        if relation:
            relation = dict(relation)
            if relation_id in self.evidence_relation_active:
                relation["active"] = self.evidence_relation_active[relation_id]
        return relation

    @staticmethod
    def _has_path(graph: dict[str, set[str]], start: str, target: str) -> bool:
        pending = [start]
        seen: set[str] = set()
        while pending:
            current = pending.pop()
            if current == target:
                return True
            if current in seen:
                continue
            seen.add(current)
            pending.extend(graph.get(current, set()) - seen)
        return False

    def hard_issue_cycle(self, consumer: str, provider: str, *, excluding: str | None = None) -> bool:
        graph: dict[str, set[str]] = {}
        for row in self.manager.store.rows(
            "SELECT relation_id,consumer_issue_id,provider_issue_id,impact_policy,active "
            "FROM relations"
        ):
            relation_id = str(row["relation_id"])
            if relation_id == excluding:
                continue
            row = self.issue_relation_rows.get(relation_id, row)
            active = self.issue_relation_active.get(relation_id, bool(row["active"]))
            impact = self.issue_relation_impact.get(relation_id, str(row["impact_policy"]))
            if active and impact == "hard":
                graph.setdefault(str(row["consumer_issue_id"]), set()).add(
                    str(row["provider_issue_id"])
                )
        for left, right in self.new_hard_issue_edges:
            graph.setdefault(left, set()).add(right)
        graph.setdefault(consumer, set()).add(provider)
        return self._has_path(graph, provider, consumer)

    def hard_evidence_cycle(self, consumer: str, provider: str, *, excluding: str | None = None) -> bool:
        graph: dict[str, set[str]] = {}
        for row in self.manager.store.rows(
            "SELECT relation_id,consumer_evidence_id,provider_evidence_id,impact_policy,active "
            "FROM evidence_relations"
        ):
            relation_id = str(row["relation_id"])
            if relation_id == excluding:
                continue
            row = self.evidence_relation_rows.get(relation_id, row)
            active = self.evidence_relation_active.get(relation_id, bool(row["active"]))
            if active and row["impact_policy"] == "hard":
                graph.setdefault(str(row["consumer_evidence_id"]), set()).add(
                    str(row["provider_evidence_id"])
                )
        for left, right in self.new_hard_evidence_edges:
            graph.setdefault(left, set()).add(right)
        graph.setdefault(consumer, set()).add(provider)
        return self._has_path(graph, provider, consumer)

    def record(self, *, ordinal: int, operation: dict[str, Any], risk: dict[str, Any]) -> None:
        self.trace.append(
            {
                "operation_ordinal": ordinal,
                "op": operation["op"],
                "risk": risk,
                "pre_state": self.pre_state(operation),
            }
        )

    def pre_state(self, operation: dict[str, Any]) -> dict[str, Any]:
        name = str(operation["op"])
        result: dict[str, Any] = {"op": name}
        if name == "context_obligation":
            duty = self.manager.context_obligations.get(operation["obligation_id"], state_view=self)
            result["obligation"] = ({key: duty[key] for key in
                                     ("obligation_id", "conclusion_id", "state", "revision", "blocks_publication")}
                                    if duty else None)
        if name == "intake_relation":
            head = self.material_head("intake", operation["link_id"])
            row = self.intake_relation(operation["link_id"])
            result["relation_version_id"] = head["version_id"] if head else None
            result["relation_active"] = bool(row["active"]) if row else None
        if name in {"context_relation", "replace_relation", "question_relation", "record_relation"}:
            domain = {"context_relation": "context", "question_relation": "question", "record_relation": "record"}.get(name, operation.get("domain"))
            if not isinstance(domain, str):
                raise ValidationError("Relationship domain must be specified")
            head = self.material_head(domain, operation["relation_id"])
            result["relation_version_id"] = head["version_id"] if head else None
            if name == "record_relation":
                row = self.record_relation(operation["relation_id"])
                result["relation_active"] = bool(row["active"]) if row else None
            if name == "question_relation":
                row = self.question_relation(operation["relation_id"])
                result["relation_active"] = bool(row["active"]) if row else None
        elif name == "context_change":
            result["selected_receipts"] = []
            for item in operation["items"]:
                row = self.manager.store.row("SELECT receipt_id FROM basis_receipt_selections WHERE conclusion_id=?", (item["conclusion_id"],))
                selected = self.selected_receipts.get(item["conclusion_id"], row["receipt_id"] if row else "")
                result["selected_receipts"].append({"conclusion_id": item["conclusion_id"], "receipt_id": selected})
        if name == "attach_evidence":
            result["issue_sample"] = (
                sample.value
                if (sample := self.sample_for_issue(str(operation["issue_id"])))
                else None
            )
        if name == "add_evidence_relation":
            consumer = str(operation["consumer_evidence_id"])
            provider = str(operation["provider_evidence_id"])
            result.update(
                {
                    "consumer_samples": sorted(
                        sample.value for sample in self.evidence_samples(consumer)
                    ),
                    "provider_samples": sorted(
                        sample.value for sample in self.evidence_samples(provider)
                    ),
                    "consumer_publication_statuses": sorted(
                        self.evidence_publication_statuses(consumer)
                    ),
                    "provider_publication_statuses": sorted(
                        self.evidence_publication_statuses(provider)
                    ),
                }
            )
        elif name in {"transition_question", "answer_question"}:
            question = self.question(str(operation["question_id"]))
            result.update(
                {
                    "question_id": question["question_id"],
                    "question_status": question["status"],
                }
            )
        elif name in {
            "set_relation_impact",
            "deactivate_relation",
            "reactivate_relation",
        }:
            relation = self.issue_relation(str(operation["relation_id"]))
            if relation:
                result["relation_active"] = bool(relation["active"])
                result["relation_impact_policy"] = relation["impact_policy"]
        elif name in {
            "deactivate_evidence_relation",
            "reactivate_evidence_relation",
        }:
            relation = self.evidence_relation(str(operation["relation_id"]))
            if relation:
                result["relation_active"] = bool(relation["active"])
        return result
