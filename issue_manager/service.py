from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import defaultdict, deque
from contextlib import nullcontext
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

from .compatibility import (
    COMPAT_TEMPLATE_REF,
    LEGACY_COMPONENT_PARAMETER,
    LEGACY_COMPONENTS_PARAMETER,
    LEGACY_SCAFFOLD_ALIAS,
)
from .context_rule_service import rule_capabilities
from .errors import (
    ConflictError,
    CycleError,
    NotFoundError,
    OverviewTooLargeError,
    PermissionError,
    ValidationError,
)
from .evidence_identity import (
    IDENTITY_ALGORITHM,
    LOCATOR_IDENTITY_VERSION,
    conflict_identity_key,
    identity_locator,
    legacy_identity_key,
    platform_identity_key,
    search_normalize_locator,
)
from .registry_service import (
    build_issue_type_semantics,
    validate_json_instance,
)
from .risk import ExecutionGrant, NormalizedMutation, RiskAssessment
from .schema import LATEST_SCHEMA_VERSION
from .scope_identity import ScopeKey, normalize_identity_term
from .security import AuthContext
from .store import Store, canonical_json, new_id, now
from .strict_json import json_value_errors, require_strict_json
from .transitions import validate_transition

OPEN_TASK_STATES = ("pending", "blocked", "ready", "proposed", "awaiting_approval")
PUBLISH_STATUSES = {
    "draft",
    "provisional",
    "accepted",
    "canonical",
    "disputed",
    "superseded",
    "retracted",
}
ENTRY_TYPES = {
    "observation",
    "run_link",
    "analysis",
    "note",
    "question",
    "decision_candidate",
    "amendment",
}


def _loads(value: str | None, fallback: Any) -> Any:
    if value is None:
        return fallback
    return json.loads(value)


def _clean_row(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    result = dict(row)
    conversions: tuple[tuple[str, str, Any], ...] = (
        ("scope_json", "scope", {}),
        ("structured_outputs_json", "structured_outputs", {}),
        ("limitations_json", "limitations", []),
        ("evidence_refs_json", "evidence_refs", []),
        ("payload_json", "payload", {}),
        ("issue_type_snapshot_json", "issue_type_snapshot", {}),
        ("issue_type_semantic_snapshot_json", "issue_type_semantic_snapshot", {}),
    )
    for source, target, fallback in conversions:
        if source in result:
            result[target] = _loads(result.pop(source), fallback)
    if "active" in result:
        result["active"] = bool(result["active"])
    return result


class IssueManager:
    """Transactional domain service used by both the CLI and agent gateway."""

    def __init__(self, ledger_dir: str | Path = "issue_ledger"):
        self.store = Store(ledger_dir)
        self.policy = self.store.policy
        self._wire_services()

    @classmethod
    def initialize(cls, ledger_dir: str | Path = "issue_ledger", *, context_rule: str = "scoped-v2") -> "IssueManager":
        store = Store.initialize(ledger_dir, context_rule=context_rule)
        manager = cls.__new__(cls)
        manager.store = store
        manager.policy = store.policy
        manager._wire_services()
        return manager

    def _wire_services(self) -> None:
        from .adapter_service import AdapterService
        from .agent_workflow_service import WorkflowService
        from .artifact_service import ArtifactService
        from .changeset_service import ChangeSetService
        from .conclusion_service import ConclusionService
        from .context_service import ContextService
        from .evidence_relation_service import EvidenceRelationService
        from .evidence_request_service import EvidenceRequestService
        from .evidence_service import EvidenceService
        from .field_bundle_service import FieldBundleService
        from .freshness_service import FreshnessService
        from .guidance_service import GuidanceService
        from .import_service import ImportService
        from .intake_service import IntakeService
        from .issue_service import IssueService
        from .operation_registry import build_operation_registry
        from .proposal_service import ProposalService
        from .question_service import QuestionService
        from .record_service import RecordService
        from .registry_service import RegistryService
        from .relation_service import RelationService
        from .report_service import ReportService
        from .repositories import (
            ConclusionRepository,
            ContextQueries,
            EvidenceRelationRepository,
            IssueRepository,
            QuestionRepository,
            RelationRepository,
            UnitOfWork,
        )
        from .rollup_service import RollupService
        from .security import CredentialResolver
        from .session_service import SessionService

        self._grant_authority = object()
        self.credentials = CredentialResolver(self.store)
        self.uow = UnitOfWork(self.store)
        self.repositories = {
            "issues": IssueRepository(self.store),
            "relations": RelationRepository(self.store),
            "conclusions": ConclusionRepository(self.store),
            "questions": QuestionRepository(self.store),
            "evidence_relations": EvidenceRelationRepository(self.store),
            "context": ContextQueries(self.store),
        }
        self.context_queries = ContextQueries(self.store)
        self.operations = build_operation_registry()
        self.registry = RegistryService(self)
        self.adapters = AdapterService(self)
        self.records = RecordService(self)
        self.imports = ImportService(self)
        self.field_bundles = FieldBundleService(self)
        self.reports = ReportService(self)
        self.evidence = EvidenceService(self)
        self.evidence_requests = EvidenceRequestService(self)
        self.proposals = ProposalService(self)
        self.intake = IntakeService(self)
        self.artifacts = ArtifactService(self)
        self.workflow = WorkflowService(self)
        self.changesets = ChangeSetService(self)
        self.sessions = SessionService(self)
        self.questions = QuestionService(self)
        self.evidence_relations = EvidenceRelationService(self)
        from .scoped_evidence_relation_service import ScopedEvidenceRelationService

        self.scoped_evidence_relations = ScopedEvidenceRelationService(self)
        from .direct_split_service import DirectSplitService

        self.direct_splits = DirectSplitService(self)
        self.rollup = RollupService(self)
        self.guidance = GuidanceService(self)
        self.issues = IssueService(self)
        self.relations = RelationService(self)
        self.conclusions = ConclusionService(self)
        self.freshness_service = FreshnessService(self)
        self.context_service = ContextService(self)
        from .evidence_applicability_service import EvidenceApplicabilityService

        self.evidence_applicability = EvidenceApplicabilityService(self)
        from .context_maintenance_service import ContextMaintenanceService
        from .context_obligation_service import ContextObligationService
        from .context_relations import ContextRelationService
        from .context_rule_service import ContextRuleService
        from .relation_contracts import REGISTRY
        from .relation_version_service import RelationVersionService

        REGISTRY.validate_schema(self.store.conn)
        self.relation_contracts = REGISTRY
        self.context_maintenance = ContextMaintenanceService(self)
        self.context_rules = ContextRuleService(self)
        self.context_obligations = ContextObligationService(self)
        self.relation_versions = RelationVersionService(self)
        self.context_relations = ContextRelationService(self)
        from .original_access_binding import OriginalAccessBindings

        self.original_access_bindings = OriginalAccessBindings(self)
        from .question_relation_service import QuestionRelationService

        self.question_relations = QuestionRelationService(self)
        from .intake_relation_service import IntakeRelationService

        self.intake_relations = IntakeRelationService(self)
        from .record_relation_service import RecordRelationService

        self.record_relations = RecordRelationService(self)
        self.store.before_commit = self.context_maintenance.flush
        with self.store.transaction():
            self.context_rules.initialize()

    def _issue_execution_grant(
        self,
        mutation: NormalizedMutation,
        assessment: RiskAssessment,
        *,
        changeset_id: str | None = None,
        changeset_hash: str | None = None,
    ) -> ExecutionGrant:
        return ExecutionGrant(
            mutation=mutation,
            assessment=assessment,
            changeset_id=changeset_id,
            changeset_hash=changeset_hash,
            authority=self._grant_authority,
        )

    def _verify_relation_grant(
        self,
        grant: ExecutionGrant | None,
        *,
        before_hard: bool,
        after_hard: bool,
    ) -> None:
        # Direct library/--ledger calls are the documented trusted-process compatibility path.
        if grant is None:
            return
        if grant.authority is not self._grant_authority:
            raise PermissionError("ExecutionGrant was not issued by this Manager")
        if before_hard or after_hard:
            if grant.assessment.tier != "T3" or not grant.changeset_id:
                raise PermissionError(
                    "Hard dependency lifecycle changes require a reviewed T3 ExecutionGrant"
                )

    def close(self) -> None:
        self.store.close()

    def operation_handler(self, handler_path: str) -> Any:
        """Resolve a registered public use-case handler without exposing private attributes."""
        target: Any = self
        for part in handler_path.split("."):
            if not part or part.startswith("_"):
                raise ValidationError(f"Invalid registered handler path: {handler_path!r}")
            target = getattr(target, part, None)
            if target is None:
                raise ValidationError(f"Registered handler is unavailable: {handler_path!r}")
        if not callable(target):
            raise ValidationError(f"Registered handler is not callable: {handler_path!r}")
        return target

    # ------------------------------------------------------------------
    # Basic lookups
    # ------------------------------------------------------------------
    def _issue(self, issue_id: str, *, active: bool = True) -> dict[str, Any]:
        row = self.store.row("SELECT * FROM issues WHERE issue_id = ?", (issue_id,))
        if not row or (active and row["work_status"] in {"void", "archived"}):
            raise NotFoundError(f"Issue not found or inactive: {issue_id}")
        return _clean_row(row) or {}

    def _issue_semantic_snapshot(self, issue: dict[str, Any]) -> dict[str, Any]:
        snapshot = issue.get("issue_type_snapshot")
        if snapshot is None and issue.get("issue_type_snapshot_json"):
            snapshot = json.loads(issue["issue_type_snapshot_json"])
        if isinstance(snapshot, dict) and snapshot.get("definition"):
            expected = issue.get("issue_type_semantic_hash")
            actual = hashlib.sha256(canonical_json(snapshot).encode("utf-8")).hexdigest()
            if expected and expected != actual:
                raise ConflictError(
                    "Issue Type semantic snapshot hash is incoherent",
                    details={
                        "issue_id": issue.get("issue_id"),
                        "expected": expected,
                        "actual": actual,
                    },
                )
            return snapshot
        registration_id = issue.get("issue_type_registration_id")
        if not registration_id:
            raise ConflictError("Registered Issue has no pinned Issue Type semantics")
        entry = self.registry.resolve(registration_id, kind="issue_type", for_creation=False)
        semantics = build_issue_type_semantics(
            entry["name"], entry["api_version"], entry["definition"]
        )
        return {
            "registration_id": entry["registration_id"],
            "registration_content_hash": entry["content_hash"],
            "api_version": entry["api_version"],
            "definition": semantics,
        }

    def issue_semantic_snapshot(self, issue: dict[str, Any] | str) -> dict[str, Any]:
        """Return the pinned, replayable Issue Type semantics through a public boundary."""
        value = self._issue(issue, active=False) if isinstance(issue, str) else issue
        return self._issue_semantic_snapshot(value)

    def issue_publication_profile(self, issue: dict[str, Any] | str, status: str) -> dict[str, Any]:
        value = self._issue(issue) if isinstance(issue, str) else issue
        semantics = self._issue_semantic_snapshot(value)["definition"]
        profiles = semantics["conclusion"]["publication_profiles"]
        profile = profiles.get(status)
        if profile is None and status in {"disputed", "superseded", "retracted"}:
            profile = {
                "min_active_evidence": 0,
                "minimum_verification_level": "declared",
                "review_quorum": 0,
            }
        if not isinstance(profile, dict):
            raise ValidationError(
                f"Issue Type does not define a publication profile for {status!r}"
            )
        return dict(profile)

    def issue_report_facing(self, issue: dict[str, Any] | str) -> bool:
        value = self._issue(issue) if isinstance(issue, str) else issue
        return bool(
            self._issue_semantic_snapshot(value)["definition"]["conclusion"].get(
                "report_facing", False
            )
        )

    def show_issue(self, issue_id: str) -> dict[str, Any]:
        issue = self._issue(issue_id, active=False)
        issue["current_conclusion"] = self.get_current_conclusion(issue_id)
        if hasattr(self, "context_maintenance") and issue.get("current_conclusion_id"):
            issue["currentness"] = self.context_maintenance.show(issue["current_conclusion_id"])
        issue["relations_as_consumer"] = [
            _clean_row(row)
            for row in self.store.rows(
                "SELECT * FROM relations WHERE consumer_issue_id = ? AND active = 1 ORDER BY relation_type, provider_issue_id",
                (issue_id,),
            )
        ]
        issue["relations_as_provider"] = [
            _clean_row(row)
            for row in self.store.rows(
                "SELECT * FROM relations WHERE provider_issue_id = ? AND active = 1 ORDER BY relation_type, consumer_issue_id",
                (issue_id,),
            )
        ]
        return issue

    def inspect_issue(self, issue_id: str, *, auth: AuthContext) -> dict[str, Any]:
        """Return the bounded handoff surface used by orchestration.

        This deliberately avoids the former all-purpose context envelope.  The
        authoritative Issue head, its current conclusion/currentness and the
        scoped-v2 projection are sufficient for a new participant to continue.
        """
        with self.store.read_transaction():
            return self._inspect_issue_snapshot(issue_id, auth=auth)

    def _inspect_issue_snapshot(self, issue_id: str, *, auth: AuthContext) -> dict[str, Any]:
        auth.require("context.read")
        issue = self._issue(issue_id, active=False)
        current = self.get_current_conclusion(issue_id)
        from .conclusion_rule_service import ConclusionRuleService
        from .original_access_service import OriginalAccessService

        rule = ConclusionRuleService(self).current(issue_id, issue=issue)
        if current is not None:
            binding = self.store.row("SELECT revision,schema_hash FROM conclusion_rule_bindings WHERE conclusion_id=?",
                                     (current["conclusion_id"],))
            current["applied_rule"] = binding
            errors = validate_json_instance(current["structured_outputs"], rule["schema"],
                                            path="$.structured_outputs")
            from .conclusion_rule_schema import bounded_rule_errors
            current["current_rule_comparison"] = {"rule_revision": rule["revision"],
                                                  "valid": not errors, **bounded_rule_errors(errors)}

        return {
            "protocol_version": 1,
            "issue": issue,
            "current_conclusion": current,
            "conclusion_rule": rule,
            "original_access": OriginalAccessService(self).entry(issue_id, auth),
            "scoped_context": self.context_maintenance.current_scoped_projection(
                issue_id, auth=auth
            ),
        }

    def issue_overview(self, root_issue_id: str, *, auth: AuthContext) -> dict[str, Any]:
        """Return a bounded, read-only project subtree from one SQLite snapshot."""
        import hashlib

        auth.require("context.read")
        if auth.platform_id is not None:
            raise PermissionError("Platform-scoped principals cannot read a whole Issue subtree")
        if not isinstance(root_issue_id, str) or not root_issue_id.strip():
            raise ValidationError("root must be a non-empty issue id")
        root_issue_id = root_issue_id.strip()

        with self.store.read_transaction():
            root = self.store.row("SELECT issue_id FROM issues WHERE issue_id=?", (root_issue_id,))
            if root is None:
                raise NotFoundError(f"Issue {root_issue_id!r} not found")
            nodes = self.store.rows(
                "WITH RECURSIVE subtree(issue_id) AS ("
                " SELECT issue_id FROM issues WHERE issue_id=?"
                " UNION ALL"
                " SELECT child.issue_id FROM issues child JOIN subtree parent"
                " ON child.parent_issue_id=parent.issue_id"
                ") SELECT i.issue_id,i.parent_issue_id,i.issue_type,i.title,i.work_status,"
                "i.current_conclusion_id,i.conclusion_revision,i.freshness "
                "FROM subtree s JOIN issues i ON i.issue_id=s.issue_id "
                "ORDER BY i.issue_id LIMIT 129",
                (root_issue_id,),
            )
            if len(nodes) > 128:
                raise OverviewTooLargeError(
                    "Issue overview exceeds 128 nodes; read a smaller root",
                    details={"code": "overview_too_large", "max_nodes": 128},
                )
            revision_row = self.store.row(
                "SELECT revision FROM context_input_clock WHERE singleton=1"
            )
            context_revision = int(revision_row["revision"]) if revision_row else 0
            projected: list[dict[str, Any]] = []
            for issue in nodes:
                conclusion_id = issue["current_conclusion_id"]
                currentness = None
                gap_count = None
                diagnostic = None
                if conclusion_id:
                    status = self.context_maintenance.show(conclusion_id)
                    currentness = status.get("currentness")
                    try:
                        projection = self.context_maintenance.current_scoped_projection(
                            issue["issue_id"], auth=auth
                        )
                        if projection.get("complete") and not projection.get("errors"):
                            gap_count = len(projection.get("gap", []))
                        else:
                            diagnostic = {
                                "code": "scoped_projection_incomplete",
                                "errors": projection.get("errors", [])[:8],
                            }
                    except ConflictError as exc:
                        diagnostic = {"code": "scoped_projection_unavailable", "message": str(exc)}
                    except PermissionError as exc:
                        diagnostic = {"code": "scoped_projection_forbidden", "message": str(exc)}
                    except ValidationError as exc:
                        diagnostic = {"code": "scoped_projection_invalid", "message": str(exc)}
                projected_node = {
                    "issue_id": issue["issue_id"],
                    "parent_issue_id": issue["parent_issue_id"],
                    "issue_type": issue["issue_type"],
                    "title": issue["title"],
                    "work_status": issue["work_status"],
                    "current_conclusion_id": conclusion_id,
                    "conclusion_revision": int(issue["conclusion_revision"]),
                    "freshness": issue["freshness"],
                    "currentness": currentness,
                    "gap_count": gap_count,
                    "detail_ref": "/v1/context?issue=" + quote(issue["issue_id"], safe=""),
                }
                if diagnostic is not None:
                    projected_node["diagnostic"] = diagnostic
                elif not conclusion_id:
                    projected_node["diagnostic"] = {"code": "no_current_conclusion"}
                projected.append(projected_node)
            payload: dict[str, Any] = {
                "protocol_version": 1,
                "root_issue_id": root_issue_id,
                "complete": True,
                "snapshot": {"context_revision": context_revision},
                "nodes": projected,
            }
            from .original_access_service import OriginalAccessService

            payload["original_access"] = OriginalAccessService(self).entry(root_issue_id, auth)
            payload["snapshot"]["content_sha256"] = hashlib.sha256(
                canonical_json(payload).encode("utf-8")
            ).hexdigest()
            if len(canonical_json(payload).encode("utf-8")) > 256 * 1024:
                raise OverviewTooLargeError(
                    "Issue overview exceeds 256 KiB; read a smaller root",
                    details={"code": "overview_too_large", "max_bytes": 256 * 1024},
                )
            return payload

    def get_current_conclusion(self, issue_id: str) -> dict[str, Any] | None:
        row = self.store.row(
            "SELECT c.* FROM issues i LEFT JOIN conclusion_revisions c "
            "ON c.conclusion_id = i.current_conclusion_id WHERE i.issue_id = ?",
            (issue_id,),
        )
        if not row or row.get("conclusion_id") is None:
            return None
        result = _clean_row(row) or {}
        result["basis"] = self._basis_for(result["conclusion_id"])
        evidence_uses = []
        for raw_use in self.store.rows(
            "SELECT * FROM conclusion_evidence_uses WHERE conclusion_id=? "
            "ORDER BY evidence_id,use_role",
            (result["conclusion_id"],),
        ):
            use = dict(raw_use)
            use["limitations"] = _loads(use.pop("limitations_json", None), [])
            use["source_packet_ids"] = _loads(use.pop("source_packet_ids_json", None), [])
            evidence_uses.append(use)
        result["evidence_uses"] = evidence_uses
        if hasattr(self, "context_maintenance"):
            result["currentness"] = self.context_maintenance.show(result["conclusion_id"])
        return result

    def _basis_for(self, conclusion_id: str) -> list[dict[str, Any]]:
        return self.store.rows(
            "SELECT provider_issue_id AS issue_id, provider_revision AS conclusion_revision, "
            "provider_conclusion_id AS conclusion_id,basis_mode,historical_reason FROM conclusion_basis "
            "WHERE conclusion_id = ? ORDER BY provider_issue_id",
            (conclusion_id,),
        )

    # ------------------------------------------------------------------
    # Issue and scaffold operations
    # ------------------------------------------------------------------
    def create_issue(
        self,
        issue_id: str,
        issue_type: str,
        title: str | None = None,
        *,
        parent_issue_id: str | None = None,
        scope: dict[str, Any] | None = None,
        topic: str | None = None,
        canonical_alias: str | None = None,
        actor: str = "organizer-agent",
        reason: str = "",
        dry_run: bool = False,
        idempotency_key: str | None = None,
        issue_type_registration_id: str | None = None,
        _state_view=None,
    ) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", issue_id):
            raise ValidationError("issue_id may contain only letters, digits, '.', '_' and '-'")
        type_entry: dict[str, Any] | None = None
        if issue_type_registration_id:
            type_entry = self.registry.resolve(
                issue_type_registration_id, kind="issue_type", for_creation=True
            )
            if type_entry["name"] != issue_type:
                raise ValidationError(
                    "issue_type does not match the pinned issue_type registration"
                )
        else:
            try:
                self.policy.issue_type(issue_type)
            except ValidationError as policy_error:
                try:
                    type_entry = self.registry.resolve(issue_type, kind="issue_type")
                except NotFoundError as exc:
                    raise ValidationError(str(policy_error)) from exc
            else:
                from .compatibility import COMPAT_BUNDLE_VERSION, COMPAT_NAMESPACE

                type_entry = self.registry.resolve(
                    f"{COMPAT_NAMESPACE}/issue_type/{issue_type}@{COMPAT_BUNDLE_VERSION}",
                    for_creation=True,
                )
        assert type_entry is not None
        semantic_definition = build_issue_type_semantics(
            type_entry["name"], type_entry["api_version"], type_entry["definition"]
        )
        semantic_snapshot = {
            "registration_id": type_entry["registration_id"],
            "registration_content_hash": type_entry["content_hash"],
            "api_version": type_entry["api_version"],
            "definition": semantic_definition,
        }
        semantic_snapshot_json = canonical_json(semantic_snapshot)
        semantic_hash = hashlib.sha256(semantic_snapshot_json.encode("utf-8")).hexdigest()
        if scope is not None and not isinstance(scope, dict):
            raise ValidationError("scope must be a JSON object")
        idempotency_payload = {
            "operation": "create_issue",
            "issue_id": issue_id,
            "issue_type": issue_type,
            "title": title,
            "parent_issue_id": parent_issue_id,
            "scope": scope or {},
            "topic": topic,
            "canonical_alias": canonical_alias,
            "issue_type_registration_id": type_entry["registration_id"],
        }
        replay = self.store.idempotency_lookup("issue.create", idempotency_key, idempotency_payload)
        if replay:
            return {**replay, "idempotent_replay": True}
        if self.store.row("SELECT issue_id FROM issues WHERE issue_id = ?", (issue_id,)):
            raise ConflictError(f"Issue already exists: {issue_id}")
        if parent_issue_id:
            parent = _state_view.issue(parent_issue_id) if _state_view is not None else self._issue(parent_issue_id)
            parent_registration = parent.get("issue_type_registration_id")
            if parent_registration:
                allowed_ids = {
                    item["target_registration_id"]
                    for item in self.store.rows(
                        "SELECT target_registration_id FROM registry_reference_locks "
                        "WHERE owner_registration_id=? AND target_kind='issue_type' "
                        "AND json_pointer LIKE '/allowed_children/%'",
                        (parent_registration,),
                    )
                }
                if type_entry["registration_id"] not in allowed_ids:
                    raise ValidationError(
                        f"Issue type {issue_type!r} is not allowed under {parent['issue_type']!r}"
                    )
            else:
                self.policy.validate_child(parent["issue_type"], issue_type)
        preview = {
            "operation": "create_issue",
            "issue_id": issue_id,
            "issue_type": issue_type,
            "parent_issue_id": parent_issue_id,
            "would_write": not dry_run,
        }
        if dry_run:
            row = {column[1]: (self.store.conn.execute("SELECT " + column[4]).fetchone()[0]
                               if column[4] is not None else None)
                   for column in self.store.conn.execute("PRAGMA table_info(issues)")}
            row.update({"issue_id": issue_id, "title": title or issue_id, "issue_type": issue_type,
                        "scope_json": canonical_json(scope or {}), "parent_issue_id": parent_issue_id,
                        "policy_version": self.policy.version, "normalized_scope_key": self._normalized_scope_key(scope or {}),
                        "topic": self._normalize_term(topic) if topic else None, "canonical_alias": canonical_alias or issue_id,
                        "issue_type_registration_id": type_entry["registration_id"], "issue_type_content_hash": type_entry["content_hash"],
                        "issue_type_snapshot_json": semantic_snapshot_json, "issue_type_semantic_hash": semantic_hash})
            return {**preview, "issue_row": row}
        timestamp = now()
        scope_value = scope or {}
        normalized_scope_key = self._normalized_scope_key(scope_value)
        topic_value = self._normalize_term(topic) if topic else None
        canonical_alias_value = canonical_alias or issue_id
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO issues(issue_id,title,issue_type,scope_json,parent_issue_id,created_at,"
                "created_by,updated_at,policy_version,normalized_scope_key,topic,canonical_alias,"
                "issue_type_registration_id,issue_type_content_hash,"
                "issue_type_snapshot_json,issue_type_semantic_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    issue_id,
                    title or issue_id,
                    issue_type,
                    canonical_json(scope_value),
                    parent_issue_id,
                    timestamp,
                    actor,
                    timestamp,
                    self.policy.version,
                    normalized_scope_key,
                    topic_value,
                    canonical_alias_value,
                    type_entry["registration_id"],
                    type_entry["content_hash"],
                    semantic_snapshot_json,
                    semantic_hash,
                ),
            )
            conn.execute(
                "INSERT OR IGNORE INTO issue_aliases(issue_id,alias,normalized_alias,created_at,created_by) "
                "VALUES (?,?,?,?,?)",
                (
                    issue_id,
                    canonical_alias_value,
                    self._normalize_term(canonical_alias_value),
                    timestamp,
                    actor,
                ),
            )
            self.rollup.ensure_snapshot(
                issue_id,
                semantic_snapshot,
                actor=actor,
                conn=conn,
            )
            self.questions.instantiate_template(
                issue_id,
                semantic_snapshot,
                actor=actor,
                conn=conn,
            )
            event = self.store.audit(
                conn,
                actor=actor,
                action="issue.create",
                object_type="issue",
                object_id=issue_id,
                before_revision=None,
                after_revision=0,
                reason=reason,
                payload=preview,
            )
            response = {**preview, "event_id": event, "would_write": True}
            self.store.idempotency_record(
                conn, "issue.create", idempotency_key, idempotency_payload, response
            )
        return response

    @staticmethod
    def _normalize_term(value: str) -> str:
        return normalize_identity_term(value)

    @classmethod
    def _normalized_scope_key(cls, scope: dict[str, Any]) -> str | None:
        key = ScopeKey.from_scope(scope)
        return key.value if key else None

    def archive_issue(
        self,
        issue_id: str,
        *,
        actor: str = "organizer-agent",
        reason: str,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        issue = self._issue(issue_id)
        children = self.store.rows(
            "SELECT issue_id FROM issues WHERE parent_issue_id = ? AND work_status NOT IN ('archived','void')",
            (issue_id,),
        )
        active_relations = self.store.rows(
            "SELECT relation_id FROM relations WHERE active = 1 AND (consumer_issue_id = ? OR provider_issue_id = ?)",
            (issue_id, issue_id),
        )
        if children or active_relations:
            raise ValidationError(
                f"Cannot archive {issue_id}: it has {len(children)} active children and {len(active_relations)} active relations"
            )
        result = {"issue_id": issue_id, "from": issue["work_status"], "to": "archived"}
        if dry_run:
            return {**result, "would_write": False}
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE issues SET work_status='archived', updated_at=? WHERE issue_id=?",
                (now(), issue_id),
            )
            event = self.store.audit(
                conn,
                actor=actor,
                action="issue.archive",
                object_type="issue",
                object_id=issue_id,
                before_revision=issue["conclusion_revision"],
                after_revision=issue["conclusion_revision"],
                reason=reason,
                payload=result,
            )
        return {**result, "event_id": event, "would_write": True}

    def scaffold(
        self,
        *,
        sample: str,
        components: Iterable[str] | None = None,
        template: str = LEGACY_SCAFFOLD_ALIAS,
        actor: str = "organizer-agent",
        reason: str = "initialize project skeleton",
        dry_run: bool = False,
        **legacy_parameters: Any,
    ) -> dict[str, Any]:
        legacy_components = legacy_parameters.pop(LEGACY_COMPONENTS_PARAMETER, None)
        if legacy_parameters:
            raise ValidationError(f"Unknown scaffold parameters: {sorted(legacy_parameters)}")
        if components is not None and legacy_components is not None:
            raise ValidationError("Scaffold components were supplied more than once")
        selected_components = components if components is not None else legacy_components or []
        reference = COMPAT_TEMPLATE_REF if template == LEGACY_SCAFFOLD_ALIAS else template
        try:
            result = self.registry.instantiate_issue_template(
                reference,
                {
                    "sample": sample,
                    LEGACY_COMPONENTS_PARAMETER: [
                        item.strip() for item in selected_components if item.strip()
                    ],
                },
                actor=actor,
                reason=reason,
                dry_run=dry_run,
            )
        except NotFoundError as exc:
            raise ValidationError(f"Unknown scaffold template: {template}") from exc
        operations = [
            {**operation, "issue_id": operation["id"]} for operation in result["operations"]
        ]
        return {
            **result,
            "template": template,
            "resolved_registration": result["template_registration_id"],
            "deprecation_warning": (
                "legacy scaffold alias is deprecated; use the exact registered template reference"
                if template == LEGACY_SCAFFOLD_ALIAS
                else None
            ),
            "sample": sample,
            "operations": operations,
        }

    # ------------------------------------------------------------------
    # Relations and graph analysis
    # ------------------------------------------------------------------
    def _hard_edges(self, *, include: tuple[str, str] | None = None) -> dict[str, list[str]]:
        edges: dict[str, list[str]] = defaultdict(list)
        for row in self.store.rows(
            "SELECT consumer_issue_id, provider_issue_id FROM relations WHERE active=1 AND impact_policy='hard'"
        ):
            edges[row["consumer_issue_id"]].append(row["provider_issue_id"])
        if include:
            edges[include[0]].append(include[1])
        return edges

    @staticmethod
    def _find_path(edges: dict[str, list[str]], start: str, target: str) -> list[str] | None:
        queue: deque[tuple[str, list[str]]] = deque([(start, [start])])
        seen = {start}
        while queue:
            node, path = queue.popleft()
            if node == target:
                return path
            for nxt in edges.get(node, []):
                if nxt not in seen:
                    seen.add(nxt)
                    queue.append((nxt, [*path, nxt]))
        return None

    def _validate_hard_relation(self, consumer: str, provider: str) -> None:
        edges = self._hard_edges()
        path = self._find_path(edges, provider, consumer)
        if path:
            cycle = [consumer, *path]
            raise CycleError("Hard relation would create a dependency cycle", cycle)

    def _insert_relation(
        self,
        conn: sqlite3.Connection,
        *,
        consumer: str,
        provider: str,
        relation_type: str,
        impact_policy: str,
        actor: str,
        reason: str,
    ) -> str:
        relation_id = new_id("rel")
        conn.execute(
            "INSERT INTO relations("
            "relation_id,consumer_issue_id,provider_issue_id,relation_type,impact_policy,active,"
            "created_at,created_by,reason,policy_version"
            ") VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)",
            (
                relation_id,
                consumer,
                provider,
                relation_type,
                impact_policy,
                now(),
                actor,
                reason,
                self.policy.version,
            ),
        )
        conn.execute(
            "INSERT INTO relation_events VALUES (?,?,'created','{}',?,?,?,?)",
            (
                new_id("relation_event"),
                relation_id,
                canonical_json({"active": True, "impact_policy": impact_policy}),
                reason,
                now(),
                actor,
            ),
        )
        return relation_id

    def add_relation(
        self,
        consumer: str,
        provider: str,
        relation_type: str,
        *,
        impact_policy: str | None = None,
        actor: str = "organizer-agent",
        reason: str = "",
        dry_run: bool = False,
        idempotency_key: str | None = None,
        _execution_grant: ExecutionGrant | None = None,
    ) -> dict[str, Any]:
        from .changeset_state import StateView
        from .issue_relation_planner import plan_add

        decision = plan_add(
            StateView(self),
            {
                "consumer": consumer,
                "provider": provider,
                "relation_type": relation_type,
                "impact_policy": impact_policy,
                "reason": reason,
            },
        )
        consumer = decision["consumer"]
        provider = decision["provider"]
        relation_type = decision["relation_type"]
        impact_policy = decision["impact_policy"]
        self._verify_relation_grant(
            _execution_grant, before_hard=False, after_hard=impact_policy == "hard"
        )
        idempotency_payload = {
            "consumer": consumer,
            "provider": provider,
            "relation_type": relation_type,
            "impact_policy": impact_policy,
            "reason": reason,
        }
        replay = self.store.idempotency_lookup("relation.add", idempotency_key, idempotency_payload)
        if replay:
            return {**replay, "idempotent_replay": True}
        cycle_path = None
        if decision["hard_cycle"]:
            try:
                self._validate_hard_relation(consumer, provider)
            except CycleError as exc:
                cycle_path = exc.path
                if not dry_run:
                    raise
        downstream = self.impact(provider)["affected"]
        prospective = list(downstream)
        if impact_policy in {"hard", "soft", "notify"} and not any(
            item["issue_id"] == consumer for item in prospective
        ):
            prospective.append(
                {
                    "issue_id": consumer,
                    "via": relation_type,
                    "impact_policy": impact_policy,
                    "path": [provider, consumer],
                }
            )
        if impact_policy in {"hard", "soft", "notify"}:
            for item in self.impact(consumer)["affected"]:
                if not any(existing["issue_id"] == item["issue_id"] for existing in prospective):
                    prospective.append({**item, "path": [provider, *item["path"]]})
        provider_issue = self._issue(provider)
        creates_task = bool(
            provider_issue["current_conclusion_id"] and impact_policy in {"hard", "soft"}
        )
        preview = {
            "consumer": consumer,
            "provider": provider,
            "relation_type": relation_type,
            "impact_policy": impact_policy,
            "cycle_path": cycle_path,
            "currently_affected_if_provider_changes": downstream,
            "affected_if_provider_changes_after_add": prospective,
            "refresh_tasks_created_now": 1 if creates_task else 0,
        }
        if dry_run:
            return {**preview, "valid": cycle_path is None, "would_write": False}
        with self.store.transaction() as conn:
            relation_id = self._insert_relation(
                conn,
                consumer=consumer,
                provider=provider,
                relation_type=relation_type,
                impact_policy=impact_policy,
                actor=actor,
                reason=reason,
            )
            refresh_task_id = None
            if creates_task:
                refresh_task_id = self._enqueue_refresh(
                    conn,
                    issue_id=consumer,
                    trigger_issue_id=provider,
                    from_revision=0,
                    to_revision=provider_issue["conclusion_revision"],
                    reason_type="child_changed"
                    if impact_policy == "hard"
                    else "dependency_changed",
                    priority=50,
                )
            event = self.store.audit(
                conn,
                actor=actor,
                action="relation.add",
                object_type="relation",
                object_id=relation_id,
                before_revision=None,
                after_revision=1,
                reason=reason,
                payload=preview,
            )
            response = {
                **preview,
                "relation_id": relation_id,
                "refresh_task_id": refresh_task_id,
                "event_id": event,
                "would_write": True,
            }
            self.store.idempotency_record(
                conn, "relation.add", idempotency_key, idempotency_payload, response
            )
        if creates_task:
            self.recompute_freshness()
        return response

    def impact(self, provider_issue_id: str) -> dict[str, Any]:
        self._issue(provider_issue_id, active=False)
        reverse: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for relation in self.store.rows(
            "SELECT consumer_issue_id,provider_issue_id,relation_type,impact_policy FROM relations WHERE active=1"
        ):
            reverse[relation["provider_issue_id"]].append(relation)
        queue: deque[tuple[str, list[str]]] = deque([(provider_issue_id, [provider_issue_id])])
        best: dict[str, dict[str, Any]] = {}
        while queue:
            provider, path = queue.popleft()
            for relation in reverse.get(provider, []):
                consumer = relation["consumer_issue_id"]
                candidate = {
                    "issue_id": consumer,
                    "via": relation["relation_type"],
                    "impact_policy": relation["impact_policy"],
                    "path": [*path, consumer],
                }
                if consumer not in best or len(candidate["path"]) < len(best[consumer]["path"]):
                    best[consumer] = candidate
                if relation["impact_policy"] in {"hard", "soft", "notify"} and consumer not in path:
                    queue.append((consumer, candidate["path"]))
        return {"provider_issue_id": provider_issue_id, "affected": list(best.values())}

    def deactivate_relation(
        self,
        relation_id: str,
        *,
        actor: str,
        reason: str,
        _execution_grant: ExecutionGrant | None = None,
    ) -> dict[str, Any]:
        from .changeset_state import StateView
        from .issue_relation_planner import plan_lifecycle

        decision = plan_lifecycle(
            StateView(self), {"op": "deactivate_relation", "relation_id": relation_id, "_direct": True}
        )
        relation = decision["relation"]
        if not relation["active"]:
            return {"relation_id": relation_id, "active": False, "existing": True}
        self._verify_relation_grant(
            _execution_grant,
            before_hard=relation["impact_policy"] == "hard",
            after_hard=False,
        )
        before = {"active": True, "impact_policy": relation["impact_policy"]}
        after = {"active": False, "impact_policy": relation["impact_policy"]}
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE relations SET active=0,deactivated_at=?,deactivated_by=? WHERE relation_id=?",
                (now(), actor, relation_id),
            )
            conn.execute(
                "INSERT INTO relation_events VALUES (?,?,'deactivated',?,?,?,?,?)",
                (
                    new_id("relation_event"),
                    relation_id,
                    canonical_json(before),
                    canonical_json(after),
                    reason,
                    now(),
                    actor,
                ),
            )
            event = self.store.audit(
                conn,
                actor=actor,
                action="relation.deactivate",
                object_type="relation",
                object_id=relation_id,
                before_revision=1,
                after_revision=2,
                reason=reason,
                payload=after,
            )
        self.recompute_freshness()
        return {"relation_id": relation_id, "active": False, "event_id": event}

    def set_relation_impact(
        self,
        relation_id: str,
        impact_policy: str,
        *,
        actor: str,
        reason: str,
        _execution_grant: ExecutionGrant | None = None,
    ) -> dict[str, Any]:
        from .changeset_state import StateView
        from .issue_relation_planner import plan_impact

        decision = plan_impact(
            StateView(self),
            {"relation_id": relation_id, "impact_policy": impact_policy, "_direct": True},
        )
        relation = decision["relation"]
        impact_policy = decision["impact_policy"]
        self._verify_relation_grant(
            _execution_grant,
            before_hard=bool(relation["active"]) and relation["impact_policy"] == "hard",
            after_hard=bool(relation["active"]) and impact_policy == "hard",
        )
        if decision["hard_cycle"]:
            self._validate_hard_relation(
                relation["consumer_issue_id"], relation["provider_issue_id"]
            )
        before = {"active": bool(relation["active"]), "impact_policy": relation["impact_policy"]}
        after = {"active": bool(relation["active"]), "impact_policy": impact_policy}
        if before == after:
            return {"relation_id": relation_id, **after, "existing": True}
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE relations SET impact_policy=? WHERE relation_id=?",
                (impact_policy, relation_id),
            )
            conn.execute(
                "INSERT INTO relation_events VALUES (?,?,'impact_changed',?,?,?,?,?)",
                (
                    new_id("relation_event"),
                    relation_id,
                    canonical_json(before),
                    canonical_json(after),
                    reason,
                    now(),
                    actor,
                ),
            )
            event = self.store.audit(
                conn,
                actor=actor,
                action="relation.set_impact",
                object_type="relation",
                object_id=relation_id,
                before_revision=None,
                after_revision=None,
                reason=reason,
                payload={"before": before, "after": after},
            )
        self.recompute_freshness()
        return {"relation_id": relation_id, **after, "event_id": event}

    def reactivate_relation(
        self,
        relation_id: str,
        *,
        actor: str,
        reason: str,
        _execution_grant: ExecutionGrant | None = None,
    ) -> dict[str, Any]:
        from .changeset_state import StateView
        from .issue_relation_planner import plan_lifecycle

        decision = plan_lifecycle(
            StateView(self), {"op": "reactivate_relation", "relation_id": relation_id, "_direct": True}
        )
        relation = decision["relation"]
        if relation["active"]:
            return {"relation_id": relation_id, "active": True, "existing": True}
        self._verify_relation_grant(
            _execution_grant,
            before_hard=False,
            after_hard=relation["impact_policy"] == "hard",
        )
        if decision["hard_cycle"]:
            self._validate_hard_relation(
                relation["consumer_issue_id"], relation["provider_issue_id"]
            )
        before = {"active": False, "impact_policy": relation["impact_policy"]}
        after = {"active": True, "impact_policy": relation["impact_policy"]}
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE relations SET active=1,deactivated_at=NULL,deactivated_by=NULL "
                "WHERE relation_id=?",
                (relation_id,),
            )
            conn.execute(
                "INSERT INTO relation_events VALUES (?,?,'reactivated',?,?,?,?,?)",
                (
                    new_id("relation_event"),
                    relation_id,
                    canonical_json(before),
                    canonical_json(after),
                    reason,
                    now(),
                    actor,
                ),
            )
            event = self.store.audit(
                conn,
                actor=actor,
                action="relation.reactivate",
                object_type="relation",
                object_id=relation_id,
                before_revision=None,
                after_revision=None,
                reason=reason,
                payload={"before": before, "after": after},
            )
        self.recompute_freshness()
        return {"relation_id": relation_id, **after, "event_id": event}

    def dependency_trace(self, issue_id: str) -> dict[str, Any]:
        self._issue(issue_id, active=False)
        relations = self.store.rows(
            "SELECT * FROM relations WHERE active=1 AND (consumer_issue_id=? OR provider_issue_id=?) "
            "ORDER BY consumer_issue_id, provider_issue_id",
            (issue_id, issue_id),
        )
        return {
            "issue_id": issue_id,
            "providers": [_clean_row(r) for r in relations if r["consumer_issue_id"] == issue_id],
            "consumers": [_clean_row(r) for r in relations if r["provider_issue_id"] == issue_id],
        }

    # ------------------------------------------------------------------
    # Evidence and append-only workspace
    # ------------------------------------------------------------------
    def add_evidence(
        self,
        *,
        kind: str,
        locator: str,
        issue_id: str | None = None,
        target_scope: str | None = None,
        description: str = "",
        quality_status: str = "unknown",
        content_hash: str | None = None,
        actor: str = "agent",
        reason: str = "",
        dry_run: bool = False,
        idempotency_key: str | None = None,
        addresses_question_ids: Iterable[str] = (),
        related_evidence: Iterable[dict[str, Any]] = (),
        _declared_source_locator: str | None = None,
        _source_packet_id: str | None = None,
        _allocated_evidence_id: str | None = None,
        _conn: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        from .changeset_state import StateView
        from .evidence_planner import plan_create

        decision = plan_create(
            StateView(self),
            {"kind": kind, "locator": locator, "issue_id": issue_id, "quality_status": quality_status,
             "addresses_question_ids": addresses_question_ids, "related_evidence": related_evidence,
             "_direct": True},
        )
        kind = decision["kind"]
        locator = decision["locator"]
        exact_locator = decision["exact_locator"]
        normalized_locator = decision["normalized_locator"]
        stored_quality = decision["stored_quality_status"]
        question_ids = decision["question_ids"]
        relation_declarations = decision["relation_declarations"]
        idempotency_payload = {
            "kind": kind,
            "locator": locator,
            "issue_id": issue_id,
            "target_scope": target_scope,
            "description": description,
            "quality_status": quality_status,
            "content_hash": content_hash,
            "addresses_question_ids": question_ids,
            "related_evidence": relation_declarations,
        }
        replay = self.store.idempotency_lookup("evidence.add", idempotency_key, idempotency_payload)
        if replay:
            return {**replay, "idempotent_replay": True}
        existing = decision["existing"]
        identity_key = decision["identity_key"]
        if existing:
            evidence_id = existing["evidence_id"]
            if decision["attached"]:
                return {"evidence_id": evidence_id, "existing": True, "attached_to": issue_id,
                        "original_access": self.original_access_bindings.evidence(issue_id, evidence_id)
                        if issue_id else []}
        else:
            evidence_id = _allocated_evidence_id or new_id("ev")
        preview = {
            "evidence_id": evidence_id,
            "kind": kind,
            "locator": locator,
            "normalized_locator": normalized_locator,
            "identity_locator": exact_locator,
            "search_locator": normalized_locator,
            "locator_identity_version": LOCATOR_IDENTITY_VERSION,
            "identity_algorithm": IDENTITY_ALGORITHM,
            "identity_namespace": "legacy",
            "identity_key": identity_key,
            "attached_to": issue_id,
        }
        if _declared_source_locator is not None:
            preview["locator_role"] = "internal_identity"
            preview["declared_source_locator"] = _declared_source_locator
        if dry_run:
            return {**preview, "would_write": False}
        transaction = self.store.transaction() if _conn is None else nullcontext(_conn)
        with transaction as conn:
            locked_existing = conn.execute(
                "SELECT evidence_id FROM evidence_refs WHERE identity_key=?", (identity_key,)
            ).fetchone()
            if locked_existing and _allocated_evidence_id:
                raise ConflictError("Allocated Evidence locator already exists")
            if locked_existing:
                existing = locked_existing
                evidence_id = locked_existing["evidence_id"]
                preview["evidence_id"] = evidence_id
            if not existing:
                conn.execute(
                    "INSERT INTO evidence_refs("
                    "evidence_id,kind,locator,normalized_locator,identity_locator,search_locator,"
                    "locator_identity_version,identity_key,identity_namespace,"
                    "target_scope,short_description,quality_status,content_hash,declared_source_locator,lifecycle_status,"
                    "created_at,created_by"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'legacy', ?, ?, ?, ?, ?, 'active', ?, ?)",
                    (
                        evidence_id,
                        kind,
                        locator,
                        normalized_locator,
                        exact_locator,
                        normalized_locator,
                        LOCATOR_IDENTITY_VERSION,
                        identity_key,
                        target_scope,
                        description,
                        stored_quality,
                        content_hash,
                        _declared_source_locator,
                        now(),
                        actor,
                    ),
                )
                binding_actor = actor
                if not conn.execute(
                    "SELECT 1 FROM actors WHERE actor_id=?", (binding_actor,)
                ).fetchone():
                    binding_actor = "organizer-agent"
                conn.execute(
                    "INSERT INTO evidence_source_bindings("
                    "evidence_id,source_platform_id,binding_state,source_key,binding_revision,"
                    "created_at,created_by,reviewed_at,reviewed_by,reason) "
                    "VALUES (?,NULL,'legacy_unbound',NULL,1,?,?,NULL,NULL,?)",
                    (
                        evidence_id,
                        now(),
                        binding_actor,
                        "Evidence created without an authenticated source Manifest",
                    ),
                )
                self.evidence.recalculate(
                    evidence_id,
                    trigger_object_type="evidence_ref",
                    trigger_object_id=evidence_id,
                    reason="initial declared Evidence proof",
                    auth=AuthContext(
                        actor_id=binding_actor,
                        actor_kind="organizer_agent",
                        run_id="trusted-process",
                        capabilities=frozenset(),
                        lineage=frozenset({binding_actor}),
                    ),
                    conn=conn,
                    semantic_change_class="initial",
                    _allocated_proof_id=("split-proof:" + evidence_id) if _allocated_evidence_id else None,
                )
            if issue_id:
                conn.execute(
                    "INSERT OR IGNORE INTO issue_evidence VALUES (?, ?, ?, ?)",
                    (issue_id, evidence_id, now(), actor),
                )
                preview["original_access"] = self.original_access_bindings.admit_evidence(
                    issue_id, evidence_id, inherit_packet=_source_packet_id)
            question_links = []
            for question_id in question_ids:
                question = self.questions.questions.require(question_id, conn=conn)
                if issue_id and question["issue_id"] != issue_id:
                    raise ValidationError(
                        f"Question {question_id} does not belong to Evidence Issue {issue_id}"
                    )
                question_links.append(
                    self.questions.attach_evidence(
                        question_id,
                        evidence_id,
                        link_type="addresses",
                        rationale="Evidence submission declared this Question as motivation",
                        actor=actor,
                        conn=conn,
                    )
                )
            evidence_relations = []
            for declaration in relation_declarations:
                provider_id = declaration.get("provider_evidence_id") or declaration.get(
                    "evidence_id"
                )
                relation_type = declaration.get("relation_type")
                if not isinstance(provider_id, str) or not isinstance(relation_type, str):
                    raise ValidationError(
                        "Each related_evidence item needs provider_evidence_id and relation_type"
                    )
                evidence_relations.append(
                    self.evidence_relations.add(
                        evidence_id,
                        provider_id,
                        relation_type,
                        impact_policy=declaration.get("impact_policy"),
                        rationale=str(declaration.get("rationale", "")),
                        actor=actor,
                        conn=conn,
                    )
                )
            event = self.store.audit(
                conn,
                actor=actor,
                action="evidence.add" if not existing else "evidence.attach",
                object_type="evidence",
                object_id=evidence_id,
                before_revision=None,
                after_revision=1,
                reason=reason,
                payload=preview,
            )
            response = {
                **preview,
                "event_id": event,
                "would_write": True,
                "question_links": question_links,
                "evidence_relations": evidence_relations,
                "impact": [],
            }
            self.store.idempotency_record(
                conn, "evidence.add", idempotency_key, idempotency_payload, response
            )
        return response

    def add_scoped_evidence_contribution(
        self,
        *,
        issue_id: str,
        kind: str,
        locator: str,
        description: str,
        related_evidence: Iterable[dict[str, Any]],
        actor: str,
        auth: AuthContext,
        reason: str,
        idempotency_key: str,
        _source_packet_id: str | None = None,
    ) -> dict[str, Any]:
        """Atomically save one Evidence contribution and its scoped relations."""
        auth.require("evidence.write")
        if kind not in {"observation", "interpretation"}:
            raise ValidationError("Contribution kind must be observation or interpretation")
        try:
            declared_source_locator = identity_locator(locator)
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"source is invalid: {exc}") from exc
        declarations = list(related_evidence)
        if declarations:
            auth.require("evidence.relation.write")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValidationError("Scoped contributions require an idempotency key")
        if len(declarations) > 8:
            raise ValidationError("A scoped contribution may declare at most 8 relations")
        normalized: list[dict[str, Any]] = []
        for declaration in declarations:
            if not isinstance(declaration, dict) or set(declaration) - {
                "provider_evidence_id", "relation_type", "rationale", "impact_policy"
            }:
                raise ValidationError("Scoped relation declarations contain unsupported fields")
            provider = declaration.get("provider_evidence_id")
            relation_type = declaration.get("relation_type")
            rationale = declaration.get("rationale")
            if not all(isinstance(value, str) and value.strip() for value in (provider, relation_type, rationale)):
                raise ValidationError("Each scoped relation needs provider, type, and rationale")
            item = {"provider_evidence_id": provider, "relation_type": relation_type,
                    "rationale": rationale}
            if declaration.get("impact_policy") is not None:
                if not isinstance(declaration["impact_policy"], str) or not declaration["impact_policy"].strip():
                    raise ValidationError("impact_policy must be a non-empty string")
                item["impact_policy"] = declaration["impact_policy"]
            normalized.append(item)
        payload = {
            "issue_id": issue_id, "kind": kind,
            "declared_source_locator": declared_source_locator,
            "description": description, "related_evidence": normalized, "reason": reason,
        }
        operation = f"scoped_contribution:{auth.actor_id}:{auth.run_id}"
        if _source_packet_id is not None:
            payload["source_packet_id"] = _source_packet_id
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, idempotency_key, payload)
            if replay is not None:
                return {**replay, "idempotent_replay": True}
            # Each contribution gets a server-owned identity locator. The
            # submitted locator remains a declared source and may be shared.
            evidence = None
            for _ in range(8):
                internal_locator = "im-internal:scoped-contribution:" + new_id("src")
                if conn.execute(
                    "SELECT 1 FROM evidence_refs WHERE identity_key=?",
                    (legacy_identity_key("report", internal_locator),),
                ).fetchone():
                    continue
                evidence = self.add_evidence(
                    kind="report", locator=internal_locator, issue_id=issue_id,
                    description=description, actor=actor, reason=reason,
                    idempotency_key=None,
                    _declared_source_locator=declared_source_locator,
                    _source_packet_id=_source_packet_id,
                    _conn=conn,
                )
                break
            if evidence is None:
                raise ConflictError("Could not allocate a unique internal contribution identity")
            if evidence.get("existing"):
                raise ConflictError("Internal contribution identity collided with existing Evidence")
            evidence_id = evidence["evidence_id"]
            self.store.fault("scoped_contribution.after_evidence")
            relations = []
            for index, declaration in enumerate(normalized):
                provider = declaration["provider_evidence_id"]
                source_row = self.scoped_evidence_relations._evidence(conn, evidence_id)
                target_row = self.scoped_evidence_relations._evidence(conn, provider)
                _, source_token = self.scoped_evidence_relations._binding(source_row)
                _, target_token = self.scoped_evidence_relations._binding(target_row)
                relation = self.scoped_evidence_relations.create(
                    scope_issue_id=issue_id, source_evidence_id=evidence_id,
                    target_evidence_id=provider, relation_type=declaration["relation_type"],
                    rationale=declaration["rationale"], impact_policy=declaration.get("impact_policy"),
                    auth=auth, expected_source_token=source_token,
                    expected_target_token=target_token,
                    idempotency_key=f"{idempotency_key}:relation:{index}", conn=conn,
                )
                relations.append(relation)
                self.store.fault("scoped_contribution.after_relation")
            result = {"evidence": evidence, "contribution_kind": kind, "scoped_relations": relations,
                      "issue_id": issue_id, "atomic": True}
            self.store.idempotency_record(conn, operation, idempotency_key, payload, result)
            return result

    def curate_field_item(
        self, *, packet_id: str, issue_id: str, expected_curation_version: int,
        description: str, kind: str, origin: dict[str, Any], source_locator: str,
        reason: str, related_evidence: Iterable[dict[str, Any]], auth: AuthContext,
        idempotency_key: str, request_id: str,
    ) -> dict[str, Any]:
        """Atomically create one curated fact, Evidence, mapping and selected relations."""
        auth.require("evidence.write")
        declarations = list(related_evidence)
        if declarations:
            auth.require("evidence.relation.write")
        if kind not in {"observation", "interpretation"}:
            raise ValidationError("kind must be observation or interpretation")
        from .field_origin import validate_handoff

        validate_handoff(origin)
        payload = {"packet_id": packet_id, "issue_id": issue_id,
                   "expected_curation_version": expected_curation_version,
                   "description": description, "kind": kind, "origin": origin,
                   "source_locator": source_locator, "reason": reason,
                   "related_evidence": declarations}
        operation = f"field_packet.curate:{auth.actor_id}:{auth.run_id}"
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, idempotency_key, payload)
            if replay is not None:
                return {**replay, "idempotent_replay": True}
            packet = conn.execute(
                "SELECT issue_id,content,sources_json,attachment_refs_json FROM field_packets WHERE packet_id=?",
                (packet_id,),
            ).fetchone()
            if packet is None:
                raise NotFoundError("Field packet was not found")
            if packet["issue_id"] != issue_id:
                raise ValidationError("Field packet belongs to another Issue")
            from .field_origin import revalidate_origin

            verified_origin, verified_locator = revalidate_origin({
                "packet_id": packet_id, "content": packet["content"],
                "sources": json.loads(packet["sources_json"]),
                "attachment_refs": json.loads(packet["attachment_refs_json"]),
            }, origin)
            if verified_locator != source_locator:
                raise ValidationError("Curated item source locator does not match its packet origin")
            origin = verified_origin
            self._issue(issue_id)
            head = conn.execute("SELECT version FROM field_packet_curation_heads WHERE packet_id=?", (packet_id,)).fetchone()
            if head is None:
                raise NotFoundError("Field packet curation head was not found")
            if head["version"] != expected_curation_version:
                raise ConflictError("Packet curation version changed; read current items and retry with a new intent",
                                    details={"expected": expected_curation_version, "actual": head["version"]})
            resolved = []
            for item in declarations:
                if item.get("target_kind") == "fact_ref":
                    target = conn.execute(
                        "SELECT f.issue_id,m.evidence_id FROM field_facts f "
                        "LEFT JOIN field_fact_mapping_heads h USING(fact_ref) "
                        "LEFT JOIN field_fact_mapping_versions m ON m.mapping_id=h.mapping_id "
                        "WHERE f.fact_ref=?", (item.get("target_ref"),),
                    ).fetchone()
                    if target is None:
                        raise NotFoundError("related_evidence fact_ref was not found")
                    if target["evidence_id"] is None:
                        raise ConflictError("related_evidence fact_ref has no Evidence mapping yet",
                                            details={"needs_attention": True, "fact_ref": item["target_ref"]})
                    provider_id = target["evidence_id"]
                    self.evidence.require_read_access(provider_id, auth)
                elif item.get("target_kind") == "evidence_id":
                    target = conn.execute("SELECT 1 FROM evidence_refs WHERE evidence_id=?",
                                          (item.get("target_ref"),)).fetchone()
                    if target is None:
                        raise NotFoundError("related_evidence Evidence ID was not found")
                    provider_id = item["target_ref"]
                    self.evidence.require_read_access(provider_id, auth)
                else:
                    raise ValidationError("related_evidence target_kind must be fact_ref or evidence_id")
                resolved.append({"provider_evidence_id": provider_id,
                                 "relation_type": item["relation_type"], "rationale": item["rationale"]})
            fact_ref = new_id("fact")
            timestamp = now()
            conn.execute(
                "INSERT INTO field_facts(fact_ref,packet_id,issue_id,description,kind,origin_json,source_locator,created_at,created_by) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (fact_ref, packet_id, issue_id, description, kind, canonical_json(origin), source_locator,
                 timestamp, auth.actor_id),
            )
            self.store.fault("field_curate.after_fact")
            contribution = self.add_scoped_evidence_contribution(
                issue_id=issue_id, kind=kind, locator=source_locator, description=description,
                related_evidence=resolved, actor=auth.actor_id, auth=auth, reason=reason,
                idempotency_key=f"{idempotency_key}:contribution",
                _source_packet_id=packet_id,
            )
            evidence = contribution["evidence"]
            self.store.fault("field_curate.after_evidence")
            relation_ids = [item["relation_id"] for item in contribution["scoped_relations"]]
            self.store.fault("field_curate.after_relations")
            mapping_id = new_id("ffmap")
            conn.execute(
                "INSERT INTO field_fact_mapping_versions(mapping_id,fact_ref,version,evidence_id,created_at,created_by,request_id) "
                "VALUES (?,?,1,?,?,?,?)",
                (mapping_id, fact_ref, evidence["evidence_id"], timestamp, auth.actor_id, request_id),
            )
            conn.execute("INSERT INTO field_fact_mapping_heads(fact_ref,mapping_id,version,updated_at) VALUES (?,?,1,?)",
                         (fact_ref, mapping_id, timestamp))
            self.store.fault("field_curate.after_mapping")
            new_version = expected_curation_version + 1
            updated = conn.execute(
                "UPDATE field_packet_curation_heads SET version=?,updated_at=? WHERE packet_id=? AND version=?",
                (new_version, timestamp, packet_id, expected_curation_version),
            )
            if updated.rowcount != 1:
                raise ConflictError("Packet curation version changed during commit")
            self.store.fault("field_curate.after_head")
            self.store.audit(conn, actor=auth.actor_id, action="field_packet.curate",
                             object_type="field_packet", object_id=packet_id,
                             before_revision=expected_curation_version, after_revision=new_version,
                             reason=reason, payload={"fact_ref": fact_ref, "evidence_id": evidence["evidence_id"],
                                                    "mapping_id": mapping_id, "relation_ids": relation_ids})
            result = {"status": "curated", "packet_id": packet_id, "fact_ref": fact_ref,
                      "evidence": evidence, "evidence_id": evidence["evidence_id"],
                      "mapping_id": mapping_id, "mapping_version": 1, "relation_ids": relation_ids,
                      "origin": origin, "source_locator": source_locator,
                      "curation_version": new_version, "atomic": True, "idempotent_replay": False}
            self.store.idempotency_record(conn, operation, idempotency_key, payload, result)
            return result

    def record_field_review(
        self, *, packet_id: str, issue_id: str, expected_curation_version: int,
        handled_fact_refs: list[str], unresolved: list[dict[str, Any]], reason: str,
        auth: AuthContext, idempotency_key: str, request_id: str,
    ) -> dict[str, Any]:
        auth.require("evidence.write")
        from .field_origin import validate_handoff

        for index, item in enumerate(unresolved):
            if isinstance(item, dict):
                validate_handoff(item.get("origin"), path=f"/unresolved/{index}/origin")
        payload = {"packet_id": packet_id, "issue_id": issue_id,
                   "expected_curation_version": expected_curation_version,
                   "handled_fact_refs": handled_fact_refs, "unresolved": unresolved, "reason": reason}
        operation = f"field_packet.review:{auth.actor_id}:{auth.run_id}"
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, idempotency_key, payload)
            if replay is not None:
                return {**replay, "idempotent_replay": True}
            packet = conn.execute(
                "SELECT issue_id,content,sources_json,attachment_refs_json FROM field_packets WHERE packet_id=?",
                (packet_id,),
            ).fetchone()
            if packet is None:
                raise NotFoundError("Field packet was not found")
            if packet["issue_id"] != issue_id:
                raise ValidationError("Field packet belongs to another Issue")
            from .field_origin import revalidate_origin

            packet_origin = {"packet_id": packet_id, "content": packet["content"],
                             "sources": json.loads(packet["sources_json"]),
                             "attachment_refs": json.loads(packet["attachment_refs_json"])}
            normalized_unresolved = []
            for item in unresolved:
                if not isinstance(item, dict) or set(item) != {"origin", "reason"}:
                    raise ValidationError("Each unresolved entry needs origin and reason")
                verified_origin, _ = revalidate_origin(packet_origin, item["origin"])
                normalized_unresolved.append({"origin": verified_origin,
                                              "reason": item["reason"]})
            unresolved = normalized_unresolved
            head = conn.execute("SELECT version FROM field_packet_curation_heads WHERE packet_id=?", (packet_id,)).fetchone()
            if head is None:
                raise NotFoundError("Field packet curation head was not found")
            if head["version"] != expected_curation_version:
                raise ConflictError("Packet curation version changed; read current state before reviewing",
                                    details={"expected": expected_curation_version, "actual": head["version"]})
            known = {row[0] for row in conn.execute("SELECT fact_ref FROM field_facts WHERE packet_id=?", (packet_id,))}
            if any(ref not in known for ref in handled_fact_refs):
                raise ValidationError("handled_fact_refs must belong to this packet")
            timestamp = now()
            version = expected_curation_version + 1
            review_id = new_id("fprev")
            conn.execute("INSERT INTO field_packet_reviews(review_id,packet_id,version,handled_fact_refs_json,unresolved_json,reason,created_at,created_by,request_id) VALUES (?,?,?,?,?,?,?,?,?)",
                         (review_id, packet_id, version, canonical_json(handled_fact_refs), canonical_json(unresolved),
                          reason, timestamp, auth.actor_id, request_id))
            self.store.fault("field_review.after_receipt")
            updated = conn.execute("UPDATE field_packet_curation_heads SET version=?,updated_at=? WHERE packet_id=? AND version=?",
                                   (version, timestamp, packet_id, expected_curation_version))
            if updated.rowcount != 1:
                raise ConflictError("Packet curation version changed during review")
            self.store.fault("field_review.after_head")
            self.store.audit(conn, actor=auth.actor_id, action="field_packet.review",
                             object_type="field_packet", object_id=packet_id,
                             before_revision=expected_curation_version, after_revision=version,
                             reason=reason, payload={"review_id": review_id, "unresolved_count": len(unresolved)})
            result = {"status": "review_recorded", "packet_id": packet_id, "review_id": review_id,
                      "curation_version": version, "atomic": True, "idempotent_replay": False}
            self.store.idempotency_record(conn, operation, idempotency_key, payload, result)
            return result

    def append_work(
        self,
        issue_id: str,
        body: str,
        *,
        entry_type: str = "note",
        evidence_refs: Iterable[str] = (),
        actor: str = "agent",
        reason: str = "",
        dry_run: bool = False,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        from .changeset_state import StateView
        from .work_planner import plan_append

        decision = plan_append(
            StateView(self),
            {"issue_id": issue_id, "body": body, "entry_type": entry_type, "evidence_refs": evidence_refs},
        )
        issue_id = decision["issue_id"]
        body = decision["body"]
        entry_type = decision["entry_type"]
        refs = decision["evidence_refs"]
        new_revision = decision["working_revision"]
        preview = {key: decision[key] for key in (
            "issue_id", "entry_type", "working_revision", "conclusion_revision", "propagates"
        )}
        if dry_run:
            return {**preview, "would_write": False}
        idempotency_payload = {
            "issue_id": issue_id,
            "body": body,
            "entry_type": entry_type,
            "evidence_refs": refs,
        }
        replay = self.store.idempotency_lookup("work.append", idempotency_key, idempotency_payload)
        if replay:
            return {**replay, "idempotent_replay": True}
        entry_id = new_id("work")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO working_entries("
                "entry_id,issue_id,entry_type,body,evidence_refs_json,created_at,created_by,policy_version"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry_id,
                    issue_id,
                    entry_type,
                    body,
                    canonical_json(refs),
                    now(),
                    actor,
                    self.policy.version,
                ),
            )
            conn.execute(
                "UPDATE issues SET working_revision=?, updated_at=? WHERE issue_id=?",
                (new_revision, now(), issue_id),
            )
            event = self.store.audit(
                conn,
                actor=actor,
                action="work.append",
                object_type="issue",
                object_id=issue_id,
                before_revision=decision["before_working_revision"],
                after_revision=new_revision,
                reason=reason,
                payload={**preview, "entry_id": entry_id},
            )
            response = {
                **preview,
                "entry_id": entry_id,
                "event_id": event,
                "would_write": True,
            }
            self.store.idempotency_record(
                conn, "work.append", idempotency_key, idempotency_payload, response
            )
        return response

    def reassess_evidence(
        self,
        evidence_id: str,
        quality_status: str,
        *,
        actor: str,
        reason: str,
        _reviewed_changeset: bool = False,
    ) -> dict[str, Any]:
        from .changeset_state import StateView
        from .evidence_planner import plan_maintenance

        decision = plan_maintenance(
            StateView(self),
            {"op": "reassess_evidence", "evidence_id": evidence_id, "quality_status": quality_status,
             "_enforce_review": True, "_reviewed_changeset": _reviewed_changeset, "_direct": True},
        )
        stored_quality = decision["stored_quality_status"]
        impact = decision.get("impact")
        assessment_id = new_id("assessment")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO evidence_assessments VALUES (?,?,?,?,?,?)",
                (assessment_id, evidence_id, stored_quality, reason, now(), actor),
            )
            conn.execute(
                "UPDATE evidence_refs SET quality_status=? WHERE evidence_id=?",
                (stored_quality, evidence_id),
            )
            conn.execute(
                "INSERT INTO evidence_events VALUES (?,? ,NULL,'reassessed',?,?,?)",
                (new_id("evidence_event"), evidence_id, reason, now(), actor),
            )
            if impact and stored_quality in {"questionable", "unusable_for_purpose"}:
                self._mark_evidence_impact(conn, impact, evidence_id)
            lineage_impacts = self.evidence_relations.propagate_change(
                evidence_id,
                source_event_type="evidence_reassessed",
                source_event_id=assessment_id,
                conn=conn,
            )
        return {
            "evidence_id": evidence_id,
            "assessment_id": assessment_id,
            "quality_status": quality_status,
            "lineage_impacts": lineage_impacts,
        }

    def void_evidence(
        self,
        evidence_id: str,
        *,
        actor: str,
        reason: str,
        _reviewed_changeset: bool = False,
    ) -> dict[str, Any]:
        from .changeset_state import StateView
        from .evidence_planner import plan_maintenance

        decision = plan_maintenance(
            StateView(self),
            {"op": "void_evidence", "evidence_id": evidence_id,
             "_enforce_review": True, "_reviewed_changeset": _reviewed_changeset, "_direct": True},
        )
        if decision["existing"]:
            return {"evidence_id": evidence_id, "status": "void", "existing": True}
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE evidence_refs SET lifecycle_status='void',identity_namespace='conflict',"
                "identity_key=? WHERE evidence_id=?",
                (conflict_identity_key(evidence_id), evidence_id),
            )
            conn.execute(
                "UPDATE evidence_source_bindings SET binding_state='retired',source_key=NULL,"
                "binding_revision=binding_revision+1,reason=? WHERE evidence_id=?",
                (f"Evidence voided: {reason}", evidence_id),
            )
            conn.execute(
                "INSERT INTO evidence_events VALUES (?,? ,NULL,'voided',?,?,?)",
                (new_id("evidence_event"), evidence_id, reason, now(), actor),
            )
            proof_actor = actor
            if not conn.execute("SELECT 1 FROM actors WHERE actor_id=?", (proof_actor,)).fetchone():
                proof_actor = "organizer-agent"
            proof_run = conn.execute(
                "SELECT run_id FROM agent_runs WHERE actor_id=? ORDER BY started_at LIMIT 1",
                (proof_actor,),
            ).fetchone()
            if not proof_run:
                raise ValidationError(
                    f"Evidence void proof recalculation has no run for actor {proof_actor}"
                )
            self.evidence.recalculate(
                evidence_id,
                trigger_object_type="evidence_ref",
                trigger_object_id=evidence_id,
                reason=reason or "Evidence voided",
                auth=AuthContext(
                    actor_id=proof_actor,
                    actor_kind="organizer_agent",
                    run_id=proof_run["run_id"],
                    capabilities=frozenset(),
                    lineage=frozenset({proof_actor}),
                ),
                conn=conn,
            )
            lineage_impacts = self.evidence_relations.propagate_change(
                evidence_id,
                source_event_type="evidence_voided",
                source_event_id=evidence_id,
                conn=conn,
            )
        return {
            "evidence_id": evidence_id,
            "status": "void",
            "lineage_impacts": lineage_impacts,
        }

    def detach_evidence(
        self,
        evidence_id: str,
        issue_id: str,
        *,
        actor: str,
        reason: str,
        _reviewed_changeset: bool = False,
    ) -> dict[str, Any]:
        from .changeset_state import StateView
        from .evidence_planner import plan_maintenance

        decision = plan_maintenance(
            StateView(self),
            {"op": "detach_evidence", "evidence_id": evidence_id, "issue_id": issue_id,
             "_enforce_review": True, "_reviewed_changeset": _reviewed_changeset, "_direct": True},
        )
        impact = decision.get("impact")
        with self.store.transaction() as conn:
            conn.execute(
                "DELETE FROM issue_evidence WHERE issue_id=? AND evidence_id=?",
                (issue_id, evidence_id),
            )
            conn.execute(
                "INSERT INTO evidence_events VALUES (?, ?, ?,'detached',?,?,?)",
                (new_id("evidence_event"), evidence_id, issue_id, reason, now(), actor),
            )
            if impact:
                self._mark_evidence_impact(conn, impact, evidence_id)
        return {"evidence_id": evidence_id, "issue_id": issue_id, "attached": False}

    def _evidence_publication_impact(
        self,
        evidence_id: str,
        *,
        issue_id: str | None = None,
        include_working: bool = False,
        manifest_change_class: str | None = None,
        before_proof: dict[str, str] | None = None,
        after_proof: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        severity = {"none": 0, "notify": 1, "impact_review": 2, "stale": 3, "blocked": 4}
        affected: list[dict[str, Any]] = []
        tier = "T1"
        for row in self.store.rows(
            "SELECT DISTINCT i.issue_id,i.issue_type,c.conclusion_id,c.status,u.use_role,"
            "u.proof_id AS stored_proof_id,u.proof_hash AS stored_proof_hash,"
            "e.current_proof_id,p.proof_hash AS current_proof_hash FROM issues i "
            "JOIN conclusion_revisions c ON c.conclusion_id=i.current_conclusion_id "
            "JOIN conclusion_evidence_uses u ON u.conclusion_id=c.conclusion_id "
            "JOIN evidence_refs e ON e.evidence_id=u.evidence_id "
            "LEFT JOIN evidence_proofs p ON p.proof_id=e.current_proof_id "
            "WHERE u.evidence_id=?",
            (evidence_id,),
        ):
            if issue_id and row["issue_id"] != issue_id:
                continue
            if row["status"] in {"accepted", "disputed", "superseded", "retracted"}:
                tier = "T2"
            if row["status"] == "canonical" or row["issue_type"] == "report_scope":
                tier = "T3"
            if include_working or row["status"] not in {"draft", "provisional"}:
                selected = "stale"
                reasons: list[str] = ["evidence_mutation"]
                if manifest_change_class is not None or before_proof is not None:
                    selected = "none"
                    reasons = []
                    working = row["status"] in {"draft", "provisional"}
                    report_or_canonical = (
                        row["status"] == "canonical" or row["issue_type"] == "report_scope"
                    )
                    if manifest_change_class == "summary_only":
                        selected = "notify" if working else "impact_review"
                        reasons.append("manifest_summary_changed")
                    elif manifest_change_class in {"metadata_changed", "provenance_changed"}:
                        selected = (
                            "notify"
                            if working
                            else ("stale" if report_or_canonical else "impact_review")
                        )
                        reasons.append(f"manifest_{manifest_change_class}")
                    elif manifest_change_class in {"content_changed", "initial"}:
                        selected = "impact_review" if working else "stale"
                        reasons.append(f"manifest_{manifest_change_class}")

                    before_value = before_proof or {}
                    after_value = after_proof or {}
                    level_rank = {
                        "declared": 0,
                        "source_verified": 1,
                        "snapshot_verified": 2,
                        "reproduced": 3,
                    }
                    before_level = before_value.get("level", "declared")
                    after_level = after_value.get("level", before_level)
                    after_state = after_value.get("state", before_value.get("state", "active"))
                    proof_impact = "none"
                    if after_state in {"conflict", "unavailable", "superseded"}:
                        proof_impact = "impact_review" if working else "stale"
                        reasons.append(f"verification_state_{after_state}")
                    elif level_rank.get(after_level, 0) < level_rank.get(before_level, 0):
                        proof_impact = "impact_review" if working else "stale"
                        reasons.append("verification_downgrade")
                    elif level_rank.get(after_level, 0) > level_rank.get(before_level, 0):
                        proof_impact = "notify"
                        reasons.append("verification_upgrade")
                    if severity[proof_impact] > severity[selected]:
                        selected = proof_impact

                refresh_reason = (
                    "dependency_changed"
                    if selected == "impact_review"
                    else ("retracted" if selected in {"stale", "blocked"} else None)
                )
                priority = (
                    90
                    if row["issue_type"] == "report_scope"
                    else (70 if selected in {"stale", "blocked"} else 60)
                )
                affected.append(
                    {
                        "issue_id": row["issue_id"],
                        "issue_type": row["issue_type"],
                        "status": row["status"],
                        "conclusion_id": row["conclusion_id"],
                        "conclusion_status": row["status"],
                        "use_role": row["use_role"],
                        "stored_proof_id": row["stored_proof_id"],
                        "stored_proof_hash": row["stored_proof_hash"],
                        "current_proof_id": row["current_proof_id"],
                        "current_proof_hash": row["current_proof_hash"],
                        "selected_freshness": selected,
                        "refresh_reason": refresh_reason,
                        "priority": priority,
                        "reason_codes": sorted(set(reasons)),
                    }
                )
        return (
            {
                "tier": tier,
                "issues": affected,
                "max_impact": max(
                    (item["selected_freshness"] for item in affected),
                    key=lambda value: severity[value],
                ),
            }
            if affected
            else None
        )

    def _mark_evidence_impact(
        self,
        conn: sqlite3.Connection,
        impact: dict[str, Any],
        evidence_id: str,
        *,
        impact_class: str = "stale",
    ) -> list[dict[str, Any]]:
        applied: list[dict[str, Any]] = []
        severity = {
            "none": 0,
            "notify": 1,
            "impact_review": 2,
            "stale": 3,
            "blocked": 4,
            "migration_unresolved": 2,
        }
        grouped: dict[str, dict[str, Any]] = {}
        for item in impact["issues"]:
            candidate = (
                item.get("selected_freshness", "none")
                if impact_class == "per_conclusion"
                else impact_class
            )
            current = grouped.get(item["issue_id"])
            current_value = (
                current.get("selected_freshness", "none")
                if current and impact_class == "per_conclusion"
                else (impact_class if current else "none")
            )
            if current is None or severity[candidate] > severity[current_value]:
                grouped[item["issue_id"]] = item
        for affected in grouped.values():
            selected = (
                affected.get("selected_freshness", "none")
                if impact_class == "per_conclusion"
                else impact_class
            )
            if selected in {"none", "notify"}:
                applied.append({**affected, "refresh_task_id": None})
                continue
            issue = conn.execute(
                "SELECT conclusion_revision,issue_type,conclusion_status FROM issues "
                "WHERE issue_id=?",
                (affected["issue_id"],),
            ).fetchone()
            if not issue:
                continue
            report_or_canonical = (
                issue["issue_type"] == "report_scope" or issue["conclusion_status"] == "canonical"
            )
            working = issue["conclusion_status"] in {"draft", "provisional"}
            if selected == "blocked":
                reason_type = "retracted"
            elif selected == "migration_unresolved":
                reason_type = "dependency_changed"
            elif selected == "impact_review" and not report_or_canonical:
                reason_type = "dependency_changed"
            elif selected == "stale" and working:
                reason_type = "dependency_changed"
            else:
                reason_type = "retracted"
            task_id = self._enqueue_refresh(
                conn,
                issue_id=affected["issue_id"],
                trigger_issue_id=affected["issue_id"],
                from_revision=issue["conclusion_revision"],
                to_revision=issue["conclusion_revision"],
                reason_type=reason_type,
                priority=(
                    90
                    if issue["issue_type"] == "report_scope"
                    else (60 if selected in {"impact_review", "migration_unresolved"} else 70)
                ),
            )
            affected["refresh_task_id"] = task_id
            affected["refresh_reason"] = reason_type
            applied.append(dict(affected))
            self._propagate(
                conn,
                provider_issue_id=affected["issue_id"],
                from_revision=issue["conclusion_revision"],
                to_revision=issue["conclusion_revision"],
                reason_type=None,
            )
        self._recompute_freshness_in_conn(conn)
        return applied

    # ------------------------------------------------------------------
    # Conclusion publication, optimistic locking, and propagation
    # ------------------------------------------------------------------
    def _validate_basis(
        self,
        issue_id: str,
        basis: list[dict[str, Any]],
        *,
        require_current_hard: bool,
        allow_withdrawn: bool = False,
        state_view=None,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        relations = (state_view.context_rows("relations", "consumer_issue_id", issue_id)
                     if state_view is not None else self.store.rows(
                         "SELECT * FROM relations WHERE consumer_issue_id=?", (issue_id,)))
        impact_order = {"none": 0, "notify": 1, "soft": 2, "hard": 3}
        relation_policies = {
            row["provider_issue_id"]: row["impact_policy"]
            for row in sorted(relations, key=lambda row: impact_order[row["impact_policy"]]) if row["active"]
        }
        consumer = state_view.issue(issue_id) if state_view is not None else self._issue(issue_id)
        for item in basis:
            provider_id = item.get("issue_id")
            revision = item.get("conclusion_revision")
            if not provider_id or not isinstance(revision, int):
                raise ValidationError(
                    "Each basis item needs issue_id and integer conclusion_revision"
                )
            if provider_id in seen:
                raise ValidationError(f"Duplicate provider in basis: {provider_id}")
            seen.add(provider_id)
            provider = state_view.issue(provider_id) if state_view is not None else self._issue(provider_id)
            if provider_id not in relation_policies:
                raise ValidationError(
                    f"Basis provider {provider_id} requires an active relation from consumer {issue_id}"
                )
            conclusion = self.store.row(
                "SELECT conclusion_id,status FROM conclusion_revisions WHERE issue_id=? AND revision_number=?",
                (provider_id, revision),
            )
            if state_view is not None:
                conclusion = next((row for row in state_view.context_rows("conclusion_revisions", "issue_id", provider_id)
                                   if row["revision_number"] == revision), None)
            if not conclusion:
                raise ValidationError(
                    f"Basis references missing revision: {provider_id}@{revision}"
                )
            basis_mode = item.get("basis_mode", "current")
            historical_reason = item.get("historical_reason")
            if basis_mode not in {"current", "historical"}:
                raise ValidationError(f"Unknown basis_mode for {provider_id}: {basis_mode!r}")
            if basis_mode == "historical":
                if not isinstance(historical_reason, str) or not historical_reason.strip():
                    raise ValidationError(
                        f"Historical basis {provider_id}@{revision} requires historical_reason"
                    )
                if relation_policies.get(provider_id) == "hard" and not allow_withdrawn:
                    raise ValidationError(
                        f"Hard provider {provider_id} cannot use historical basis"
                    )
                if consumer["issue_type"] == "report_scope" and not allow_withdrawn:
                    raise ValidationError(
                        "Report scopes cannot silently use historical provider basis"
                    )
            elif (
                revision != provider["conclusion_revision"]
                or conclusion["conclusion_id"] != provider["current_conclusion_id"]
            ):
                raise ConflictError(
                    f"Current basis provider {provider_id} changed; use basis_mode=historical with a reason "
                    "when policy permits, or prepare again"
                )
            superseded = self.store.row(
                "SELECT new_conclusion_id FROM conclusion_supersessions WHERE old_conclusion_id=?",
                (conclusion["conclusion_id"],),
            )
            if not allow_withdrawn and (conclusion["status"] == "retracted" or superseded):
                raise ValidationError(
                    f"New conclusions cannot silently use retracted/superseded basis {provider_id}@{revision}"
                )
            if (
                not allow_withdrawn
                and provider["conclusion_status"] == "retracted"
                and provider["conclusion_revision"] != revision
            ):
                raise ValidationError(
                    f"Provider {provider_id} is currently retracted; choose an explicit replacement"
                )
            normalized.append(
                {
                    "issue_id": provider_id,
                    "conclusion_revision": revision,
                    "conclusion_id": conclusion["conclusion_id"],
                    "basis_mode": basis_mode,
                    "historical_reason": historical_reason,
                }
            )

        if require_current_hard:
            by_id = {item["issue_id"]: item for item in normalized}
            for provider_id, impact_policy in relation_policies.items():
                if impact_policy != "hard":
                    continue
                provider = state_view.issue(provider_id) if state_view is not None else self._issue(provider_id)
                if not provider["current_conclusion_id"]:
                    raise ValidationError(
                        f"Hard provider {provider_id} has no current Conclusion; publication is blocked"
                    )
                basis_item = by_id.get(provider_id)
                if not basis_item:
                    raise ValidationError(f"Refresh basis must include hard provider {provider_id}")
                if (
                    basis_item["conclusion_revision"] != provider["conclusion_revision"]
                    or not provider["current_conclusion_id"]
                ):
                    raise ConflictError(
                        f"Hard provider {provider_id} changed or has no current conclusion; prepare again"
                    )
                if provider["freshness"] != "fresh":
                    raise ConflictError(
                        f"Hard provider {provider_id} is {provider['freshness']}; refresh it first"
                    )
        return normalized

    def validate_proposal(
        self, proposal: dict[str, Any], *, refresh: bool = True, state_view=None
    ) -> dict[str, Any]:
        if hasattr(self, "context_maintenance") and self.store.conn.in_transaction:
            self.context_maintenance.flush()
        issue_id = proposal.get("issue_id")
        if not issue_id:
            raise ValidationError("Proposal is missing issue_id")
        issue = state_view.issue(issue_id) if state_view is not None else self._issue(issue_id)
        expected = proposal.get("expected_conclusion_revision")
        if not isinstance(expected, int):
            raise ValidationError("Proposal needs integer expected_conclusion_revision")
        if expected != issue["conclusion_revision"]:
            raise ConflictError(
                f"Optimistic lock failed for {issue_id}: expected {expected}, current {issue['conclusion_revision']}"
            )
        if not isinstance(proposal.get("statement"), str) or not proposal["statement"].strip():
            raise ValidationError("Proposal needs a non-empty statement")
        outputs = proposal.get("structured_outputs", {})
        if not isinstance(outputs, dict):
            raise ValidationError("structured_outputs must be an object")
        require_strict_json(outputs, path="$.structured_outputs")
        semantic_snapshot = self._issue_semantic_snapshot(issue)
        from .conclusion_rule_service import ConclusionRuleService
        rule = ConclusionRuleService(self).current(issue_id, issue=issue)
        output_schema = rule["schema"]
        output_errors = validate_json_instance(outputs, output_schema, path="$.structured_outputs")
        if output_errors:
            from .conclusion_rule_schema import bounded_rule_errors
            raise ValidationError(
                "structured_outputs failed the current conclusion rule",
                details={**bounded_rule_errors(output_errors), "rule_revision": rule["revision"]},
            )
        limitations = proposal.get("limitations", [])
        if not isinstance(limitations, list) or any(
            not isinstance(item, str) for item in limitations
        ):
            raise ValidationError("limitations must be a list of strings")
        status = proposal.get("status", "provisional")
        if status not in PUBLISH_STATUSES:
            raise ValidationError(f"Unknown conclusion status: {status}")
        if status in {"accepted", "canonical"} and hasattr(self, "context_obligations"):
            self.context_obligations.require_publication(issue_id, state_view=state_view)
        transition_type = validate_transition(issue["conclusion_status"], status)
        evidence_refs = proposal.get("evidence_refs", [])
        if not isinstance(evidence_refs, list) or any(
            not isinstance(item, str) for item in evidence_refs
        ):
            raise ValidationError("evidence_refs must be a list of evidence IDs")
        for evidence_id in evidence_refs:
            evidence = self.store.row(
                "SELECT lifecycle_status FROM evidence_refs WHERE evidence_id=?", (evidence_id,)
            )
            if not evidence or evidence["lifecycle_status"] != "active":
                raise ValidationError(
                    f"Conclusion references missing or void evidence: {evidence_id}"
                )
        evidence_uses = proposal.get("evidence_uses")
        if evidence_uses is None:
            evidence_uses = [
                {
                    "evidence_id": evidence_id,
                    "use_role": "context",
                    "fitness": "unknown_for_use",
                    "limitations": [],
                    "source_packet_ids": [],
                }
                for evidence_id in evidence_refs
            ]
        if not isinstance(evidence_uses, list) or any(
            not isinstance(item, dict) for item in evidence_uses
        ):
            raise ValidationError("evidence_uses must be a list of objects")
        roles = {"support", "challenge", "context", "calibration", "alternative"}
        fitness_values = {
            "fit_for_use",
            "limited_for_use",
            "unusable_for_use",
            "unknown_for_use",
        }
        normalized_uses: list[dict[str, Any]] = []
        seen_uses: set[tuple[str, str]] = set()
        for item in evidence_uses:
            evidence_id = item.get("evidence_id")
            role = item.get("use_role")
            fitness = item.get("fitness")
            if evidence_id not in evidence_refs:
                raise ValidationError("Every evidence use must reference proposal evidence_refs")
            if role not in roles or fitness not in fitness_values:
                raise ValidationError("Evidence use has an unknown role or fitness")
            key = (str(evidence_id), str(role))
            if key in seen_uses:
                raise ValidationError(f"Duplicate evidence use: {evidence_id}/{role}")
            seen_uses.add(key)
            limitations_value = item.get("limitations", [])
            source_packets = item.get("source_packet_ids", [])
            if not isinstance(limitations_value, list) or not isinstance(source_packets, list):
                raise ValidationError(
                    "Evidence use limitations and source_packet_ids must be lists"
                )
            evidence = self.store.row(
                "SELECT * FROM evidence_refs WHERE evidence_id=? AND lifecycle_status='active'",
                (evidence_id,),
            )
            if not evidence:
                raise ValidationError(f"Evidence use references inactive evidence: {evidence_id}")
            proof = (
                self.store.row(
                    "SELECT proof_id,proof_hash,semantic_revision,manifest_id,manifest_hash,"
                    "verification_level,verification_state FROM evidence_proofs WHERE proof_id=?",
                    (evidence.get("current_proof_id"),),
                )
                if evidence.get("current_proof_id")
                else None
            )
            if not proof:
                raise ConflictError(
                    f"Evidence {evidence_id} has no current proof bundle; run migration/doctor"
                )
            if (
                proof["verification_level"] != evidence.get("verification_level")
                or proof["verification_state"] != evidence.get("verification_state")
                or int(proof["semantic_revision"]) != int(evidence.get("semantic_revision", 0))
            ):
                raise ConflictError(f"Evidence {evidence_id} current proof pointer is incoherent")
            quality = (
                "invalid"
                if evidence["quality_status"] == "unusable_for_purpose"
                else evidence["quality_status"]
            )
            normalized_uses.append(
                {
                    "evidence_id": str(evidence_id),
                    "use_role": str(role),
                    "fitness": str(fitness),
                    "verification_level_snapshot": evidence.get("verification_level", "declared"),
                    "verification_state_snapshot": evidence.get("verification_state", "active"),
                    "quality_snapshot": quality,
                    "applicability": item.get("applicability"),
                    "limitations": limitations_value,
                    "source_packet_ids": source_packets,
                    "proof_id": proof["proof_id"],
                    "proof_hash": proof["proof_hash"],
                    "evidence_semantic_revision": int(proof["semantic_revision"]),
                    "manifest_id": proof.get("manifest_id"),
                    "manifest_hash": proof.get("manifest_hash"),
                }
            )
        requirements = self.issue_publication_profile(issue, status)
        minimum_evidence = int(requirements.get("min_active_evidence", 0))
        if len(set(evidence_refs)) < minimum_evidence:
            raise ValidationError(
                f"Policy requires at least {minimum_evidence} active evidence reference(s) "
                f"for {status}; received {len(set(evidence_refs))}"
            )
        minimum_level = requirements.get("minimum_verification_level")
        if minimum_level and (
            minimum_evidence > 0 or requirements.get("require_support_fit_for_use")
        ):
            level_rank = {
                "declared": 0,
                "source_verified": 1,
                "snapshot_verified": 2,
                "reproduced": 3,
            }
            eligible_support = [
                item
                for item in normalized_uses
                if item["use_role"] == "support"
                and item["fitness"] == "fit_for_use"
                and item["quality_snapshot"] != "invalid"
                and level_rank.get(item["verification_level_snapshot"], -1)
                >= level_rank[str(minimum_level)]
            ]
            if requirements.get("reject_conflict_as_only_support"):
                eligible_support = [
                    item
                    for item in eligible_support
                    if item["verification_state_snapshot"] != "conflict"
                ]
            if not eligible_support:
                raise ValidationError(
                    f"Policy requires support + fit_for_use evidence at {minimum_level} or higher "
                    f"for {status}"
                )
            if all(item["quality_snapshot"] == "questionable" for item in eligible_support):
                raise ValidationError(
                    f"All qualifying support evidence is questionable for {status}"
                )
        referenced_artifacts: set[str] = set()
        for evidence_id in evidence_refs:
            evidence = self.store.row(
                "SELECT kind,locator FROM evidence_refs WHERE evidence_id=?", (evidence_id,)
            )
            if evidence and evidence["kind"] == "artifact":
                artifact = self.store.row(
                    "SELECT artifact_id FROM artifacts WHERE artifact_id=? OR storage_uri=?",
                    (evidence["locator"], evidence["locator"]),
                )
                if artifact:
                    referenced_artifacts.add(artifact["artifact_id"])
        artifact_outputs = outputs.get("artifact_ids", [])
        if isinstance(artifact_outputs, list):
            referenced_artifacts.update(str(item) for item in artifact_outputs)
        frozen_artifacts = []
        for artifact_id in referenced_artifacts:
            artifact = self.store.row(
                "SELECT artifact_id,role FROM artifacts WHERE artifact_id=?", (artifact_id,)
            )
            if (
                artifact
                and artifact["role"] == "frozen"
                and self.artifacts.verify(artifact_id)["ok"]
            ):
                frozen_artifacts.append(artifact_id)
        waiver_id = outputs.get("waiver_id")
        waiver = (
            self.store.row(
                "SELECT * FROM publication_waivers WHERE waiver_id=? AND issue_id=?",
                (waiver_id, issue_id),
            )
            if waiver_id
            else None
        )
        if requirements.get("require_frozen_artifact") and not frozen_artifacts:
            raise ValidationError("Report-facing publication requires a verified frozen Artifact")
        requires_analysis = bool(
            requirements.get("derived_result_requires_frozen_analysis")
        ) and bool(outputs.get("derived_result") or referenced_artifacts)
        if requirements.get("require_analysis_run_or_waiver"):
            requires_analysis = True
        if requires_analysis:
            placeholders = ",".join("?" for _ in frozen_artifacts)
            frozen_run = None
            if frozen_artifacts:
                frozen_run = self.store.row(
                    f"SELECT ar.analysis_run_id FROM analysis_runs ar JOIN analysis_outputs ao "
                    f"ON ao.analysis_run_id=ar.analysis_run_id WHERE ar.state='frozen' "
                    f"AND ao.artifact_id IN ({placeholders}) LIMIT 1",
                    tuple(frozen_artifacts),
                )
            if not frozen_run and not waiver:
                raise ValidationError(
                    "Publication requires a frozen AnalysisRun for derived outputs or a reviewed waiver"
                )
            if (
                outputs.get("derived_result")
                and not waiver
                and not any(
                    item["use_role"] == "support"
                    and item["fitness"] == "fit_for_use"
                    and item["verification_level_snapshot"] == "reproduced"
                    for item in normalized_uses
                )
            ):
                raise ValidationError(
                    "Report-facing or derived publication requires reproduced support evidence "
                    "or a reviewed waiver"
                )
        lifecycle_only = status in {"disputed", "retracted", "superseded"}
        rollup_gate = (
            {"allowed": True, "blockers": [], "warnings": []}
            if lifecycle_only
            else self.rollup.require_publication_allowed(issue_id, proposal, state_view=state_view)
        )
        normalized_basis = self._validate_basis(
            issue_id,
            proposal.get("basis", []),
            # A hard provider with a published conclusion is mandatory even for
            # an ordinary publication. This prevents bypassing refresh rules by
            # using the non-refresh CLI path.
            require_current_hard=not lifecycle_only,
            allow_withdrawn=lifecycle_only,
            state_view=state_view,
        )
        historical_allowed = set(
            self.policy.data.get("publication", {}).get("historical_basis_allowed", [])
        )
        if any(item["basis_mode"] == "historical" for item in normalized_basis):
            if status not in historical_allowed:
                raise ValidationError(
                    f"Policy does not allow historical basis for target status {status!r}"
                )
        return {
            "valid": True,
            "issue_id": issue_id,
            "expected_conclusion_revision": expected,
            "next_conclusion_revision": expected + 1,
            "normalized_basis": normalized_basis,
            "normalized_evidence_uses": normalized_uses,
            "status": status,
            "transition_type": transition_type,
            "policy_version": self.policy.version,
            "issue_type_registration_id": semantic_snapshot["registration_id"],
            "issue_type_semantic_hash": issue["issue_type_semantic_hash"],
            "issue_type_semantic_snapshot": semantic_snapshot,
            "conclusion_rule": rule,
            "rollup_gate": rollup_gate,
        }

    def record_working_conclusion(self, request: dict[str, Any], *, auth: AuthContext,
                                  idempotency_key: str) -> dict[str, Any]:
        """Record a scoped provisional conclusion in one authoritative transaction."""
        from .context_rule_service import rule_capabilities
        auth.require("conclusion.record")
        actor = auth.actor_id
        payload = dict(request)
        operation_key = f"conclusion.record:{auth.actor_id}:{auth.run_id}"
        replay = self.store.idempotency_lookup(operation_key, idempotency_key, payload)
        if replay is not None:
            return replay
        if not rule_capabilities(self.context_rules.active()["rule_id"])["direct_working_conclusion"]:
            raise PermissionError("Direct working conclusions require an active scoped rule")
        issue_id = request.get("issue_id")
        statement = request.get("statement")
        reason = request.get("reason")
        refs = request.get("evidence_refs", [])
        if not isinstance(issue_id, str) or not issue_id:
            raise ValidationError("Working conclusion needs issue_id")
        if not isinstance(statement, str) or not statement.strip():
            raise ValidationError("Working conclusion statement is required")
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationError("Working conclusion reason is required")
        if not isinstance(refs, list) or any(not isinstance(item, str) or not item for item in refs):
            raise ValidationError("evidence_refs must be an array of nonempty strings")
        if len(set(refs)) != len(refs):
            raise ValidationError("evidence_refs must be unique")
        expected_revision = request.get("expected_conclusion_revision")
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool):
            raise ValidationError("expected_conclusion_revision must be an integer")
        package_id, view_id = request.get("package_id"), request.get("view_id")
        if not isinstance(package_id, str) or not isinstance(view_id, str):
            raise ValidationError("package_id and view_id are required")
        package = self.context_maintenance.package(package_id)
        self.context_maintenance.view(view_id, auth=auth)
        evidence = package["actual_input"].get("materials", {}).get("evidence", {})
        if any(item not in evidence for item in refs):
            raise ValidationError("Every evidence_ref must be included in the frozen package")
        if package["descriptor"].get("version") == "context-currentness/scoped-v2":
            declared_roots = package["descriptor"].get("seed_evidence_ids")
            if not isinstance(declared_roots, list) or not declared_roots:
                raise ValidationError("scoped-v2 working conclusions require explicit non-empty basis roots")
            if sorted(refs) != sorted(declared_roots):
                raise ValidationError("evidence_refs must exactly match the frozen scoped-v2 basis roots")
        for evidence_id in refs:
            self.evidence.require_read_access(evidence_id, auth)
        from .conclusion_rule_service import ConclusionRuleService
        expected_rule = request.get("expected_rule_revision", 0)
        if type(expected_rule) is not int or expected_rule < 0:
            raise ValidationError("expected_rule_revision must be a nonnegative integer")
        if ConclusionRuleService(self).current(issue_id)["revision"] != expected_rule:
            raise ConflictError("Conclusion rule changed; inspect the current rule")
        validation = self.validate_proposal(
            {"issue_id": issue_id, "expected_conclusion_revision": expected_revision,
             "statement": statement, "structured_outputs": request.get("structured_outputs", {}),
             "limitations": request.get("limitations", []), "evidence_refs": refs,
             "status": "provisional"}, refresh=False,
        )
        evidence_use_by_id = {
            use["evidence_id"]: use for use in validation["normalized_evidence_uses"]
        }
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation_key, idempotency_key, payload)
            if replay is not None:
                return replay
            issue = conn.execute("SELECT * FROM issues WHERE issue_id=?", (issue_id,)).fetchone()
            if not issue:
                raise NotFoundError("Issue not found")
            if issue["conclusion_revision"] != expected_revision or issue["current_conclusion_id"] != request.get("expected_current_conclusion_id"):
                raise ConflictError("Issue conclusion head changed; rebase working conclusion")
            from .conclusion_rule_service import ConclusionRuleService
            rules = ConclusionRuleService(self)
            if rules.current(issue_id)["revision"] != validation["conclusion_rule"]["revision"]:
                raise ConflictError("Conclusion rule changed; prepare the conclusion again")
            if expected_rule != validation["conclusion_rule"]["revision"]:
                raise ConflictError("Conclusion rule changed; inspect the current rule")
            view = conn.execute("SELECT 1 FROM context_package_views WHERE view_id=? AND package_id=? AND issue_id=?", (view_id, package_id, issue_id)).fetchone()
            if not view:
                raise ConflictError("Package view does not belong to this issue and package")
            # Verify the frozen package before any conclusion write can advance
            # the same authoritative context clock.
            self.context_maintenance.verify_package(package_id, issue_id)
            new_revision = int(issue["conclusion_revision"]) + 1
            conclusion_id = f"{issue_id}@r{new_revision}"
            issue_type_snapshot = json.loads(issue["issue_type_snapshot_json"])
            conn.execute(
                "INSERT INTO conclusion_revisions(conclusion_id,issue_id,revision_number,status,statement,structured_outputs_json,confidence,applicability,limitations_json,evidence_refs_json,change_summary,created_at,created_by,approved_by,previous_conclusion_id,policy_version,transition_type,proposal_id,issue_type_registration_id,issue_type_semantic_hash,issue_type_semantic_snapshot_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (conclusion_id, issue_id, new_revision, "provisional", statement.strip(), canonical_json(request.get("structured_outputs", {})),
                 request.get("confidence"), request.get("applicability"), canonical_json(request.get("limitations", [])), canonical_json(refs),
                 reason.strip(), now(), actor, None, issue["current_conclusion_id"], self.policy.version, "working-conclusion", None,
                 issue["issue_type_registration_id"], issue["issue_type_semantic_hash"], canonical_json(issue_type_snapshot)),
            )
            rules.bind(conn, conclusion_id, validation["conclusion_rule"])
            self.store.fault("conclusion.record.after_conclusion_insert")
            for evidence_id in refs:
                use = evidence_use_by_id[evidence_id]
                current = conn.execute(
                    "SELECT current_proof_id,semantic_revision FROM evidence_refs WHERE evidence_id=?",
                    (evidence_id,),
                ).fetchone()
                if not current:
                    raise ValidationError("Referenced Evidence not found")
                if (
                    current["current_proof_id"] != use["proof_id"]
                    or int(current["semantic_revision"]) != use["evidence_semantic_revision"]
                ):
                    raise ConflictError(
                        f"Evidence {evidence_id} proof changed while applying; prepare again"
                    )
                conn.execute(
                    "INSERT INTO conclusion_evidence_uses("
                    "conclusion_id,evidence_id,use_role,fitness,verification_level_snapshot,"
                    "verification_state_snapshot,quality_snapshot,applicability,limitations_json,"
                    "source_packet_ids_json,proof_id,proof_hash,evidence_semantic_revision,"
                    "manifest_id,manifest_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        conclusion_id, evidence_id, "support", "unknown_for_use",
                        use["verification_level_snapshot"], use["verification_state_snapshot"],
                        use["quality_snapshot"], request.get("applicability"), "[]", "[]",
                        use["proof_id"], use["proof_hash"], use["evidence_semantic_revision"],
                        use["manifest_id"], use["manifest_hash"],
                    ),
                )
            conn.execute("INSERT INTO conclusion_currentness(conclusion_id,local_mismatch,needs_update,maintenance_state,computed_revision,reason_json) VALUES (?,?,?,?,?,?)",
                         (conclusion_id, 1, 1, "pending", 0, "[]"))
            receipt = self.context_maintenance.attach_receipt(conclusion_id, package_id, actor=actor,
                                                               identity={"working_conclusion": True, "view_id": view_id})
            self.store.fault("conclusion.record.after_receipt")
            conn.execute("UPDATE issues SET conclusion_status='provisional',conclusion_revision=?,working_revision=working_revision+1,current_conclusion_id=?,updated_at=? WHERE issue_id=? AND conclusion_revision=?",
                         (new_revision, conclusion_id, now(), issue_id, expected_revision))
            if conn.execute("SELECT changes()").fetchone()[0] != 1:
                raise ConflictError("Issue conclusion head changed; rebase working conclusion")
            self.store.fault("conclusion.record.after_issue_head")
            result = {"issue_id": issue_id, "conclusion_id": conclusion_id, "status": "provisional",
                      "revision_number": new_revision, "receipt": receipt, "view_id": view_id}
            self.store.audit(conn, actor=actor, action="conclusion.record", object_type="conclusion", object_id=conclusion_id,
                             before_revision=expected_revision, after_revision=new_revision, reason=reason, payload=result)
            self.store.idempotency_record(conn, operation_key, idempotency_key, payload, result)
            self.store.fault("conclusion.record.before_commit")
            return result

    def publish_conclusion(
        self,
        proposal: dict[str, Any],
        *,
        actor: str = "organizer-agent",
        approved_by: str | None = None,
        reason: str = "",
        refresh: bool = False,
        dry_run: bool = False,
        proposal_id: str | None = None,
        _auth_context: AuthContext | None = None,
        _conn: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        if not proposal_id:
            raise PermissionError(
                "Direct conclusion publication is disabled; create, validate, and apply a persisted proposal"
            )
        validation = self.validate_proposal(proposal, refresh=refresh)
        issue_id = validation["issue_id"]
        issue = self._issue(issue_id)
        status = validation["status"]
        required_reviews = int(
            self.issue_publication_profile(issue, status).get("review_quorum", 0)
        )
        persisted = self.store.row("SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,))
        if not persisted:
            raise PermissionError(f"Persisted proposal not found: {proposal_id}")
        required_reviews = max(required_reviews, int(persisted["required_reviews"]))
        permitted_state = "validated" if required_reviews == 0 else "review_passed"
        if persisted["state"] != permitted_state:
            raise PermissionError(
                f"Proposal {proposal_id} must be {permitted_state!r} before publication; "
                f"current state is {persisted['state']!r}"
            )
        proposal_hash = hashlib.sha256(canonical_json(proposal).encode("utf-8")).hexdigest()
        if persisted["proposal_hash"] != proposal_hash:
            raise ConflictError("Apply payload does not match the persisted proposal hash")
        review_count_row = self.store.row(
            "SELECT COUNT(DISTINCT reviewer_actor_id) AS n FROM review_decisions "
            "WHERE proposal_id=? AND decision='pass'",
            (proposal_id,),
        )
        review_count = int((review_count_row or {"n": 0})["n"])
        if review_count < required_reviews:
            raise PermissionError(
                f"Proposal has {review_count} independent passing review(s); {required_reviews} required"
            )
        if _auth_context:
            _auth_context.require("proposal.apply")
        if proposal_id:
            reviews = self.store.rows(
                "SELECT reviewer_actor_id FROM review_decisions "
                "WHERE proposal_id=? AND decision='pass' ORDER BY created_at",
                (proposal_id,),
            )
            approved_by = canonical_json([row["reviewer_actor_id"] for row in reviews])
        new_revision = issue["conclusion_revision"] + 1
        conclusion_id = f"{issue_id}@r{new_revision}"
        result = {
            "issue_id": issue_id,
            "conclusion_id": conclusion_id,
            "revision_number": new_revision,
            "status": status,
            "previous_revision": issue["conclusion_revision"],
            "basis": validation["normalized_basis"],
            "refresh": refresh,
            "proposal_id": proposal_id,
            "transition_type": validation["transition_type"],
            "issue_type_registration_id": validation["issue_type_registration_id"],
            "issue_type_semantic_hash": validation["issue_type_semantic_hash"],
        }
        if dry_run:
            return {**result, "would_write": False, "propagation_preview": self.impact(issue_id)}

        transaction_context = self.store.transaction() if _conn is None else nullcontext(_conn)
        with transaction_context as conn:
            # Re-check under the write lock so a prepared proposal cannot overwrite a newer revision.
            locked = conn.execute(
                "SELECT conclusion_revision,current_conclusion_id FROM issues WHERE issue_id=?",
                (issue_id,),
            ).fetchone()
            expected = proposal["expected_conclusion_revision"]
            if locked["conclusion_revision"] != expected:
                raise ConflictError(
                    f"Optimistic lock failed for {issue_id}: expected {expected}, current {locked['conclusion_revision']}"
                )
            from .conclusion_rule_service import ConclusionRuleService
            rules = ConclusionRuleService(self)
            if rules.current(issue_id)["revision"] != validation["conclusion_rule"]["revision"]:
                raise ConflictError("Conclusion rule changed; prepare the proposal again")
            locked_basis = self._validate_basis(
                issue_id,
                proposal.get("basis", []),
                require_current_hard=status not in {"disputed", "retracted", "superseded"},
                allow_withdrawn=status in {"disputed", "retracted", "superseded"},
            )
            if locked_basis != validation["normalized_basis"]:
                raise ConflictError("Provider basis changed while applying proposal; prepare again")
            conn.execute(
                "INSERT INTO conclusion_revisions("
                "conclusion_id,issue_id,revision_number,status,statement,structured_outputs_json,"
                "confidence,applicability,limitations_json,evidence_refs_json,change_summary,created_at,"
                "created_by,approved_by,previous_conclusion_id,policy_version,transition_type,proposal_id"
                ",issue_type_registration_id,issue_type_semantic_hash,"
                "issue_type_semantic_snapshot_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    conclusion_id,
                    issue_id,
                    new_revision,
                    status,
                    proposal["statement"].strip(),
                    canonical_json(proposal.get("structured_outputs", {})),
                    proposal.get("confidence"),
                    proposal.get("applicability"),
                    canonical_json(proposal.get("limitations", [])),
                    canonical_json(proposal.get("evidence_refs", [])),
                    proposal.get("change_summary", ""),
                    now(),
                    actor,
                    approved_by,
                    locked["current_conclusion_id"],
                    self.policy.version,
                    validation["transition_type"],
                    proposal_id,
                    validation["issue_type_registration_id"],
                    validation["issue_type_semantic_hash"],
                    canonical_json(validation["issue_type_semantic_snapshot"]),
                ),
            )
            rules.bind(conn, conclusion_id, validation["conclusion_rule"])
            self.store.fault("proposal.after_conclusion_insert")
            for basis in validation["normalized_basis"]:
                conn.execute(
                    "INSERT INTO conclusion_basis("
                    "conclusion_id,provider_issue_id,provider_revision,provider_conclusion_id,"
                    "basis_mode,historical_reason) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        conclusion_id,
                        basis["issue_id"],
                        basis["conclusion_revision"],
                        basis["conclusion_id"],
                        basis["basis_mode"],
                        basis.get("historical_reason"),
                    ),
                )
            for use in validation["normalized_evidence_uses"]:
                locked_proof = conn.execute(
                    "SELECT current_proof_id,semantic_revision FROM evidence_refs "
                    "WHERE evidence_id=?",
                    (use["evidence_id"],),
                ).fetchone()
                if (
                    not locked_proof
                    or locked_proof["current_proof_id"] != use["proof_id"]
                    or int(locked_proof["semantic_revision"])
                    != int(use["evidence_semantic_revision"])
                ):
                    raise ConflictError(
                        f"Evidence {use['evidence_id']} proof changed while applying; prepare again"
                    )
                conn.execute(
                    "INSERT INTO conclusion_evidence_uses("
                    "conclusion_id,evidence_id,use_role,fitness,verification_level_snapshot,"
                    "verification_state_snapshot,quality_snapshot,applicability,limitations_json,"
                    "source_packet_ids_json,proof_id,proof_hash,evidence_semantic_revision,"
                    "manifest_id,manifest_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        conclusion_id,
                        use["evidence_id"],
                        use["use_role"],
                        use["fitness"],
                        use["verification_level_snapshot"],
                        use["verification_state_snapshot"],
                        use["quality_snapshot"],
                        use.get("applicability"),
                        canonical_json(use.get("limitations", [])),
                        canonical_json(use.get("source_packet_ids", [])),
                        use["proof_id"],
                        use["proof_hash"],
                        use["evidence_semantic_revision"],
                        use.get("manifest_id"),
                        use.get("manifest_hash"),
                    ),
                )
            self.store.fault("proposal.after_basis_insert")
            if hasattr(self, "context_maintenance"):
                snapshot = self.proposals._decode_snapshot(persisted["basis_snapshot_token"])
                if snapshot.get("context_package_id"):
                    self.context_maintenance.attach_receipt(
                        conclusion_id, snapshot["context_package_id"], actor=actor,
                        identity={"proposal_id": proposal_id},
                    )
            conn.execute(
                "UPDATE issues SET conclusion_revision=?, current_conclusion_id=?, conclusion_status=?, "
                + ("" if hasattr(self, "context_maintenance") else "freshness='fresh', ")
                + "updated_at=? WHERE issue_id=?",
                (new_revision, conclusion_id, status, now(), issue_id),
            )
            self.store.fault("proposal.after_issue_pointer")
            conn.execute(
                "UPDATE refresh_tasks SET state='applied', updated_at=? WHERE issue_id=? "
                "AND state IN ('pending','blocked','ready','proposed','awaiting_approval')",
                (now(), issue_id),
            )
            propagation = self._propagate(
                conn,
                provider_issue_id=issue_id,
                from_revision=issue["conclusion_revision"],
                to_revision=new_revision,
                reason_type="retracted"
                if status in {"retracted", "disputed", "superseded"}
                else None,
            )
            self.store.fault("proposal.after_freshness_propagation")
            event = self.store.audit(
                conn,
                actor=actor,
                action="conclusion.publish",
                object_type="issue",
                object_id=issue_id,
                before_revision=issue["conclusion_revision"],
                after_revision=new_revision,
                reason=reason,
                payload={**result, "propagation": propagation},
            )
            self._recompute_freshness_in_conn(conn)
        return {**result, "event_id": event, "propagation": propagation, "would_write": True}

    def change_conclusion_status(
        self,
        issue_id: str,
        status: str,
        *,
        expected_revision: int,
        actor: str,
        approved_by: str | None = None,
        reason: str,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        current = self.get_current_conclusion(issue_id)
        if not current:
            raise ValidationError(f"Issue {issue_id} has no conclusion to mark {status}")
        proposal = {
            "issue_id": issue_id,
            "expected_conclusion_revision": expected_revision,
            "status": status,
            "statement": current["statement"],
            "structured_outputs": current["structured_outputs"],
            "confidence": current.get("confidence"),
            "applicability": current.get("applicability"),
            "limitations": current["limitations"],
            "evidence_refs": current["evidence_refs"],
            "change_summary": f"Status changed from {current['status']} to {status}: {reason}",
            "basis": [
                {
                    **basis,
                    **(
                        {
                            "basis_mode": "historical",
                            "historical_reason": reason,
                        }
                        if (
                            self._issue(basis["issue_id"], active=False)["conclusion_revision"]
                            != basis["conclusion_revision"]
                            or status in {"retracted", "superseded"}
                        )
                        else {}
                    ),
                }
                for basis in current["basis"]
            ],
        }
        return self.publish_conclusion(
            proposal,
            actor=actor,
            approved_by=approved_by,
            reason=reason,
            refresh=False,
            dry_run=dry_run,
        )

    def supersede(
        self,
        old_conclusion_id: str,
        new_conclusion_id: str,
        *,
        actor: str,
        reason: str,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        raise PermissionError(
            "Direct supersession is disabled; publish a persisted superseded proposal and satisfy its review quorum"
        )

    def _propagate(
        self,
        conn: sqlite3.Connection,
        *,
        provider_issue_id: str,
        from_revision: int,
        to_revision: int,
        reason_type: str | None,
    ) -> list[dict[str, Any]]:
        relations = [
            dict(row)
            for row in conn.execute(
                "SELECT r.*, i.issue_type FROM relations r JOIN issues i ON i.issue_id=r.consumer_issue_id "
                "WHERE r.provider_issue_id=? AND r.active=1 AND r.impact_policy IN ('hard','soft','notify')",
                (provider_issue_id,),
            ).fetchall()
        ]
        affected: list[dict[str, Any]] = []
        affected_ids: set[str] = set()
        for relation in relations:
            policy = relation["impact_policy"]
            consumer = relation["consumer_issue_id"]
            if policy == "hard":
                freshness = "stale"
                task_reason = reason_type or "child_changed"
            elif policy == "soft":
                freshness = "impact_review"
                task_reason = reason_type or "dependency_changed"
            else:
                freshness = None
                task_reason = reason_type or "dependency_changed"
            priority = (
                90 if relation["issue_type"] == "report_scope" else (70 if reason_type else 50)
            )
            task_id = None
            if policy != "notify":
                task_id = self._enqueue_refresh(
                    conn,
                    issue_id=consumer,
                    trigger_issue_id=provider_issue_id,
                    from_revision=from_revision,
                    to_revision=to_revision,
                    reason_type=task_reason,
                    priority=priority,
                )
            if freshness and not hasattr(self, "context_maintenance"):
                current = conn.execute(
                    "SELECT freshness FROM issues WHERE issue_id=?", (consumer,)
                ).fetchone()[0]
                if freshness == "stale" or current == "fresh":
                    conn.execute(
                        "UPDATE issues SET freshness=?, updated_at=? WHERE issue_id=?",
                        (freshness, now(), consumer),
                    )
            affected.append(
                {
                    "issue_id": consumer,
                    "impact_policy": policy,
                    "freshness": freshness or "unchanged",
                    "refresh_task_id": task_id,
                }
            )
            affected_ids.add(consumer)
        basis_consumers = conn.execute(
            "SELECT DISTINCT c.issue_id,i.issue_type FROM conclusion_basis b "
            "JOIN conclusion_revisions c ON c.conclusion_id=b.conclusion_id "
            "JOIN issues i ON i.current_conclusion_id=c.conclusion_id "
            "WHERE b.provider_issue_id=?",
            (provider_issue_id,),
        ).fetchall()
        for basis_consumer in basis_consumers:
            consumer = basis_consumer["issue_id"]
            if consumer in affected_ids:
                continue
            task_id = self._enqueue_refresh(
                conn,
                issue_id=consumer,
                trigger_issue_id=provider_issue_id,
                from_revision=from_revision,
                to_revision=to_revision,
                reason_type=reason_type or "dependency_changed",
                priority=90 if basis_consumer["issue_type"] == "report_scope" else 70,
            )
            if not hasattr(self, "context_maintenance"):
                conn.execute(
                    "UPDATE issues SET freshness='impact_review',updated_at=? WHERE issue_id=? "
                    "AND freshness='fresh'", (now(), consumer),
                )
            affected.append(
                {
                    "issue_id": consumer,
                    "impact_policy": "basis_index",
                    "freshness": "impact_review",
                    "refresh_task_id": task_id,
                }
            )
        return affected

    def _enqueue_refresh(
        self,
        conn: sqlite3.Connection,
        *,
        issue_id: str,
        trigger_issue_id: str,
        from_revision: int,
        to_revision: int,
        reason_type: str,
        priority: int,
    ) -> str:
        placeholders = ",".join("?" for _ in OPEN_TASK_STATES)
        existing = conn.execute(
            f"SELECT * FROM refresh_tasks WHERE issue_id=? AND state IN ({placeholders})",
            (issue_id, *OPEN_TASK_STATES),
        ).fetchone()
        timestamp = now()
        if existing:
            task_id = existing["refresh_task_id"]
            conn.execute(
                "UPDATE refresh_tasks SET trigger_issue_id=?, to_revision=?, priority=MAX(priority,?), "
                "reason_type=CASE WHEN ?='retracted' THEN 'retracted' ELSE reason_type END, "
                "state='pending', coalesced_events=coalesced_events+1, updated_at=? WHERE refresh_task_id=?",
                (trigger_issue_id, to_revision, priority, reason_type, timestamp, task_id),
            )
        else:
            task_id = new_id("refresh")
            conn.execute(
                "INSERT INTO refresh_tasks("
                "refresh_task_id,issue_id,reason_type,trigger_issue_id,from_revision,to_revision,"
                "priority,state,coalesced_events,created_at,updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', 1, ?, ?)",
                (
                    task_id,
                    issue_id,
                    reason_type,
                    trigger_issue_id,
                    from_revision,
                    to_revision,
                    priority,
                    timestamp,
                    timestamp,
                ),
            )
        conn.execute(
            "INSERT INTO refresh_task_events VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                new_id("rte"),
                task_id,
                trigger_issue_id,
                from_revision,
                to_revision,
                reason_type,
                timestamp,
            ),
        )
        return task_id

    # ------------------------------------------------------------------
    # Freshness, refresh queue, context package
    # ------------------------------------------------------------------
    def _open_tasks(self) -> list[dict[str, Any]]:
        placeholders = ",".join("?" for _ in OPEN_TASK_STATES)
        return self.store.rows(
            f"SELECT * FROM refresh_tasks WHERE state IN ({placeholders}) ORDER BY priority DESC, created_at",
            OPEN_TASK_STATES,
        )

    def _derive_freshness(
        self,
        *,
        legacy: bool = False,
    ) -> tuple[dict[str, str], dict[str, list[str]], dict[str, list[dict[str, Any]]]]:
        if hasattr(self, "context_maintenance") and not legacy:
            states = {
                row["issue_id"]: ("fresh" if row["current_conclusion_id"] is None or (
                    row["maintenance_state"] == "ready" and row["needs_update"] == 0
                ) else "stale")
                for row in self.store.rows(
                    "SELECT i.issue_id,i.current_conclusion_id,c.needs_update,c.maintenance_state "
                    "FROM issues i LEFT JOIN conclusion_currentness c ON c.conclusion_id=i.current_conclusion_id "
                    "WHERE i.work_status NOT IN ('archived','void')"
                )
            }
            providers = defaultdict(list)
            for row in self.store.rows(
                "SELECT consumer_issue_id,provider_issue_id FROM relations WHERE active=1 AND impact_policy='hard'"
            ):
                providers[row["consumer_issue_id"]].append(row["provider_issue_id"])
            tasks = defaultdict(list)
            for task in self._open_tasks():
                tasks[task["issue_id"]].append(task)
            return states, providers, tasks
        issues = {
            row["issue_id"]: row
            for row in self.store.rows(
                "SELECT issue_id,freshness FROM issues WHERE work_status NOT IN ('archived','void')"
            )
        }
        hard_providers: dict[str, list[str]] = defaultdict(list)
        for row in self.store.rows(
            "SELECT consumer_issue_id,provider_issue_id FROM relations WHERE active=1 AND impact_policy='hard'"
        ):
            hard_providers[row["consumer_issue_id"]].append(row["provider_issue_id"])
        tasks_by_issue: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for task in self._open_tasks():
            tasks_by_issue[task["issue_id"]].append(task)

        current_basis: dict[str, dict[str, int]] = defaultdict(dict)
        for row in self.store.rows(
            "SELECT i.issue_id,cb.provider_issue_id,cb.provider_revision FROM issues i "
            "JOIN conclusion_basis cb ON cb.conclusion_id=i.current_conclusion_id"
        ):
            current_basis[row["issue_id"]][row["provider_issue_id"]] = row["provider_revision"]
        hard_mismatch: set[str] = set()
        soft_mismatch: set[str] = set()
        for relation in self.store.rows(
            "SELECT r.consumer_issue_id,r.provider_issue_id,r.impact_policy,i.conclusion_revision,i.current_conclusion_id "
            "FROM relations r JOIN issues i ON i.issue_id=r.provider_issue_id "
            "WHERE r.active=1 AND r.impact_policy IN ('hard','soft')"
        ):
            if not relation["current_conclusion_id"]:
                continue
            used = current_basis.get(relation["consumer_issue_id"], {}).get(
                relation["provider_issue_id"]
            )
            if used != relation["conclusion_revision"]:
                target = hard_mismatch if relation["impact_policy"] == "hard" else soft_mismatch
                target.add(relation["consumer_issue_id"])

        state = {issue_id: "fresh" for issue_id in issues}
        for _ in range(max(2, len(issues) + 1)):
            changed = False
            for issue_id in sorted(issues):
                providers_fresh = all(
                    state.get(provider) == "fresh" for provider in hard_providers.get(issue_id, [])
                )
                issue_tasks = tasks_by_issue.get(issue_id, [])
                has_hard_task = issue_id in hard_mismatch or any(
                    task["reason_type"] in {"child_changed", "retracted", "report_build"}
                    for task in issue_tasks
                )
                has_soft_task = issue_id in soft_mismatch or any(
                    task["reason_type"] in {"dependency_changed", "manual"} for task in issue_tasks
                )
                if has_hard_task:
                    desired = "stale" if providers_fresh else "blocked"
                elif not providers_fresh:
                    desired = "blocked"
                elif has_soft_task:
                    desired = "impact_review"
                else:
                    desired = "fresh"
                if state[issue_id] != desired:
                    state[issue_id] = desired
                    changed = True
            if not changed:
                break
        return state, hard_providers, tasks_by_issue

    def recompute_freshness(self) -> dict[str, Any]:
        with self.store.transaction() as conn:
            return self._recompute_freshness_in_conn(conn)

    def _recompute_freshness_in_conn(self, conn: sqlite3.Connection) -> dict[str, Any]:
        if hasattr(self, "context_maintenance"):
            return self.context_maintenance.flush()
        issues = {
            row["issue_id"]: row
            for row in self.store.rows(
                "SELECT issue_id,freshness FROM issues WHERE work_status NOT IN ('archived','void')"
            )
        }
        state, hard_providers, _ = self._derive_freshness()

        changed_rows: list[dict[str, str]] = []
        for issue_id, desired in state.items():
            old = issues[issue_id]["freshness"]
            if old != desired:
                conn.execute(
                    "UPDATE issues SET freshness=?, updated_at=? WHERE issue_id=?",
                    (desired, now(), issue_id),
                )
                changed_rows.append({"issue_id": issue_id, "from": old, "to": desired})
        for task in self._open_tasks():
            providers = hard_providers.get(task["issue_id"], [])
            ready = all(state.get(provider) == "fresh" for provider in providers)
            target_state = "ready" if ready else "blocked"
            if task["state"] in {"pending", "ready", "blocked"} and task["state"] != target_state:
                conn.execute(
                    "UPDATE refresh_tasks SET state=?, updated_at=? WHERE refresh_task_id=?",
                    (target_state, now(), task["refresh_task_id"]),
                )
        return {"changed": changed_rows, "count": len(changed_rows)}

    def stale(self) -> list[dict[str, Any]]:
        self.recompute_freshness()
        return self.store.rows(
            "SELECT issue_id,title,issue_type,freshness,conclusion_revision FROM issues "
            "WHERE freshness <> 'fresh' AND work_status NOT IN ('archived','void') ORDER BY freshness, issue_id"
        )

    def why_stale(self, issue_id: str) -> dict[str, Any]:
        issue = self._issue(issue_id, active=False)
        if hasattr(self, "context_maintenance") and issue.get("current_conclusion_id"):
            explanation = self.context_maintenance.why(issue["current_conclusion_id"])
            return {"issue_id": issue_id, "freshness": issue["freshness"], **explanation,
                    "tasks": self.store.rows("SELECT * FROM refresh_tasks WHERE issue_id=?", (issue_id,))}
        tasks = self.store.rows(
            "SELECT * FROM refresh_tasks WHERE issue_id=? ORDER BY created_at DESC", (issue_id,)
        )
        providers = self.store.rows(
            "SELECT r.provider_issue_id,r.relation_type,r.impact_policy,i.freshness,i.conclusion_revision "
            "FROM relations r JOIN issues i ON i.issue_id=r.provider_issue_id "
            "WHERE r.consumer_issue_id=? AND r.active=1 ORDER BY r.provider_issue_id",
            (issue_id,),
        )
        basis = self.get_current_conclusion(issue_id)
        basis_by_id = {
            item["issue_id"]: item["conclusion_revision"] for item in (basis or {}).get("basis", [])
        }
        reasons = []
        for provider in providers:
            used = basis_by_id.get(provider["provider_issue_id"])
            if used != provider["conclusion_revision"] or provider["freshness"] != "fresh":
                reasons.append({**provider, "basis_revision": used})
        return {
            "issue_id": issue_id,
            "freshness": issue["freshness"],
            "reasons": reasons,
            "tasks": tasks,
        }

    def refresh_plan(self, root: str | None = None) -> dict[str, Any]:
        self.recompute_freshness()
        tasks = self._open_tasks()
        if root:
            self._issue(root, active=False)
            allowed = set(self._subtree_ids(root))
            tasks = [task for task in tasks if task["issue_id"] in allowed]
        # Provider depth makes lower-level tasks appear first; ready tasks are always actionable.
        edges = self._hard_edges()

        def depth(issue_id: str, trail: set[str] | None = None) -> int:
            trail = set() if trail is None else trail
            if issue_id in trail:
                return 0
            return 1 + max(
                (depth(p, trail | {issue_id}) for p in edges.get(issue_id, [])), default=0
            )

        tasks.sort(
            key=lambda task: (
                0 if task["state"] == "ready" else 1,
                depth(task["issue_id"]),
                -task["priority"],
                task["created_at"],
            )
        )
        return {
            "root": root,
            "ready": [task for task in tasks if task["state"] == "ready"],
            "blocked": [task for task in tasks if task["state"] != "ready"],
            "order": [task["issue_id"] for task in tasks],
        }

    def claim_refresh_task(
        self,
        refresh_task_id: str,
        *,
        actor: str,
        lease_until: str,
    ) -> dict[str, Any]:
        task = self.store.row(
            "SELECT * FROM refresh_tasks WHERE refresh_task_id=?", (refresh_task_id,)
        )
        if not task:
            raise NotFoundError(f"Refresh task not found: {refresh_task_id}")
        if task["state"] not in {"pending", "ready", "blocked"}:
            raise ConflictError(f"Refresh task is not claimable from state {task['state']!r}")
        if task["claimed_by"] and task["lease_until"] and task["lease_until"] > now():
            raise ConflictError(
                f"Refresh task is leased by {task['claimed_by']} until {task['lease_until']}"
            )
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE refresh_tasks SET claimed_by=?,lease_until=?,attempt_count=attempt_count+1,"
                "updated_at=? WHERE refresh_task_id=?",
                (actor, lease_until, now(), refresh_task_id),
            )
        return {"refresh_task_id": refresh_task_id, "claimed_by": actor, "lease_until": lease_until}

    def update_refresh_task(
        self,
        refresh_task_id: str,
        state: str,
        *,
        actor: str,
        error: str | None = None,
    ) -> dict[str, Any]:
        if state not in {"failed", "cancelled", "pending"}:
            raise ValidationError("Refresh task update state must be failed, cancelled, or pending")
        task = self.store.row(
            "SELECT * FROM refresh_tasks WHERE refresh_task_id=?", (refresh_task_id,)
        )
        if not task:
            raise NotFoundError(f"Refresh task not found: {refresh_task_id}")
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE refresh_tasks SET state=?,claimed_by=NULL,lease_until=NULL,last_error=?,updated_at=? "
                "WHERE refresh_task_id=?",
                (state, error, now(), refresh_task_id),
            )
            event = self.store.audit(
                conn,
                actor=actor,
                action=f"refresh.{state}",
                object_type="refresh_task",
                object_id=refresh_task_id,
                before_revision=None,
                after_revision=None,
                reason=error or "",
                payload={"state": state},
            )
        self.recompute_freshness()
        return {"refresh_task_id": refresh_task_id, "state": state, "event_id": event}

    def _provider_card(self, issue_id: str) -> dict[str, Any]:
        issue = self._issue(issue_id, active=False)
        conclusion = self.get_current_conclusion(issue_id)
        if not conclusion:
            return {
                "issue_id": issue_id,
                "title": issue["title"],
                "conclusion_revision": 0,
                "status": "none",
                "freshness": issue["freshness"],
            }
        return {
            "issue_id": issue_id,
            "title": issue["title"],
            "conclusion_revision": conclusion["revision_number"],
            "status": conclusion["status"],
            "freshness": issue["freshness"],
            "statement": conclusion["statement"],
            "structured_outputs": conclusion["structured_outputs"],
            "confidence": conclusion.get("confidence"),
            "applicability": conclusion.get("applicability"),
            "limitations": conclusion["limitations"],
            "change_summary": conclusion["change_summary"],
            "key_evidence_refs": conclusion["evidence_refs"],
        }

    def prepare_refresh(self, issue_id: str, *, actor: str = "organizer-agent") -> dict[str, Any]:
        issue = self._issue(issue_id)
        relations = self.store.rows(
            "SELECT provider_issue_id,relation_type,impact_policy FROM relations "
            "WHERE consumer_issue_id=? AND active=1 AND impact_policy IN ('hard','soft') "
            "ORDER BY impact_policy,provider_issue_id",
            (issue_id,),
        )
        cards = []
        for relation in relations:
            cards.append({**relation, "card": self._provider_card(relation["provider_issue_id"])})
        hard_blockers = [
            item["provider_issue_id"]
            for item in cards
            if item["impact_policy"] == "hard" and item["card"]["freshness"] != "fresh"
        ]
        proposal_template = {
            "issue_id": issue_id,
            "expected_conclusion_revision": issue["conclusion_revision"],
            "status": "provisional",
            "statement": "",
            "structured_outputs": {},
            "confidence": "medium",
            "applicability": "",
            "limitations": [],
            "change_summary": "",
            "basis": [
                {
                    "issue_id": item["provider_issue_id"],
                    "conclusion_revision": item["card"]["conclusion_revision"],
                    "basis_mode": "current",
                }
                for item in {card["provider_issue_id"]: card for card in cards}.values()
                if item["impact_policy"] in {"hard", "soft"}
                and item["card"]["conclusion_revision"] > 0
            ],
        }
        context_package = self.context_maintenance.prepare(
            issue_id, basis=proposal_template["basis"], actor=actor
        ) if hasattr(self, "context_maintenance") else None
        proposal_template["basis_snapshot_token"] = self.proposals.make_snapshot_token(
            issue_id,
            issue["conclusion_revision"],
            proposal_template["basis"],
            context_package_id=context_package["package_id"] if context_package else None,
        )
        package = {
            "protocol_version": 1,
            "intent": "refresh",
            "issue": issue,
            "current_conclusion": self.get_current_conclusion(issue_id),
            "provider_cards": cards,
            "context_input_package": context_package,
            "hard_blockers": hard_blockers,
            "proposal_template": proposal_template,
            "can_apply": not hard_blockers,
            "review_quorum": self.policy.data.get("publication", {}).get("review_quorum", {}),
            "policy_version": self.policy.version,
        }
        return package

    def add_alias(
        self, issue_id: str, alias: str, *, actor: str = "organizer-agent"
    ) -> dict[str, Any]:
        self._issue(issue_id, active=False)
        normalized = self._normalize_term(alias)
        if not normalized:
            raise ValidationError("Alias cannot be empty")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO issue_aliases VALUES (?,?,?,?,?)",
                (issue_id, alias, normalized, now(), actor),
            )
        return {"issue_id": issue_id, "alias": alias, "normalized_alias": normalized}

    def add_tag(self, issue_id: str, tag: str, *, actor: str = "organizer-agent") -> dict[str, Any]:
        self._issue(issue_id, active=False)
        normalized = self._normalize_term(tag)
        if not normalized:
            raise ValidationError("Tag cannot be empty")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO issue_tags VALUES (?,?,?,?,?)",
                (issue_id, tag, normalized, now(), actor),
            )
        return {"issue_id": issue_id, "tag": tag, "normalized_tag": normalized}

    def resolve(
        self,
        *,
        sample: str,
        component: str | None = None,
        topic: str,
        **legacy_parameters: Any,
    ) -> dict[str, Any]:
        legacy_component = legacy_parameters.pop(LEGACY_COMPONENT_PARAMETER, None)
        if legacy_parameters:
            raise ValidationError(f"Unknown resolver parameters: {sorted(legacy_parameters)}")
        if component is not None and legacy_component is not None:
            raise ValidationError("Resolver component was supplied more than once")
        component = component if component is not None else legacy_component
        scope_key = "/".join(
            item
            for item in (self._normalize_term(sample), self._normalize_term(component or ""))
            if item
        )
        normalized_topic = self._normalize_term(topic)
        rows = self.store.rows(
            "SELECT issue_id,title,issue_type,scope_json,normalized_scope_key,topic,canonical_alias,"
            "work_status,freshness FROM issues WHERE work_status NOT IN ('archived','void')"
        )
        alias_by_issue: dict[str, list[str]] = defaultdict(list)
        for alias in self.store.rows("SELECT issue_id,normalized_alias FROM issue_aliases"):
            alias_by_issue[alias["issue_id"]].append(alias["normalized_alias"])
        tag_by_issue: dict[str, list[str]] = defaultdict(list)
        for tag in self.store.rows("SELECT issue_id,normalized_tag FROM issue_tags"):
            tag_by_issue[tag["issue_id"]].append(tag["normalized_tag"])
        candidates: list[dict[str, Any]] = []
        for row in rows:
            score = 0
            reasons: list[str] = []
            row_scope = row.get("normalized_scope_key") or self._normalized_scope_key(
                _loads(row.get("scope_json"), {})
            )
            if row_scope == scope_key:
                score += 60
                reasons.append("exact_scope")
            elif scope_key and row_scope and row_scope.startswith(scope_key.split("/")[0]):
                score += 10
                reasons.append("sample_scope")
            row_topic = self._normalize_term(row.get("topic") or "")
            if row_topic == normalized_topic:
                score += 50
                reasons.append("exact_topic")
            aliases = alias_by_issue[row["issue_id"]]
            tags = tag_by_issue[row["issue_id"]]
            if normalized_topic in aliases or normalized_topic in tags:
                score += 35
                reasons.append("alias_or_tag")
            normalized_id = self._normalize_term(row["issue_id"])
            if normalized_topic and normalized_topic in normalized_id:
                score += 15
                reasons.append("id_contains_topic")
            if self._normalize_term(sample) in normalized_id:
                score += 5
            if component and self._normalize_term(component) in normalized_id:
                score += 5
            if score >= 50:
                candidates.append(
                    {
                        "issue_id": row["issue_id"],
                        "title": row["title"],
                        "issue_type": row["issue_type"],
                        "scope_key": row_scope,
                        "topic": row_topic,
                        "score": score,
                        "reasons": reasons,
                        "freshness": row["freshness"],
                    }
                )
        candidates.sort(key=lambda item: (-item["score"], item["issue_id"]))
        resolver_policy = self.policy.data.get("resolver", {})
        minimum_score = int(resolver_policy.get("minimum_score", 90))
        minimum_lead = int(resolver_policy.get("minimum_lead", 15))
        eligible = [
            item
            for item in candidates
            if item["score"] >= minimum_score
            and "exact_scope" in item["reasons"]
            and ({"exact_topic", "alias_or_tag"} & set(item["reasons"]))
        ]
        if not eligible:
            status = "not_found"
            match = None
        elif len(eligible) == 1 or eligible[0]["score"] - eligible[1]["score"] >= minimum_lead:
            status = "unique"
            match = eligible[0]
        else:
            status = "multiple"
            match = None
        return {
            "status": status,
            "query": {
                "sample": sample,
                LEGACY_COMPONENT_PARAMETER: component,
                "topic": topic,
            },
            "match": match,
            "candidates": candidates,
            "routing_policy": {
                "policy_version": self.policy.version,
                "minimum_score": minimum_score,
                "minimum_lead": minimum_lead,
                "required_reasons": ["exact_scope", "topic_identity"],
            },
        }

    def context(
        self,
        issue_id: str,
        intent: str,
        *,
        max_nodes: int = 20,
        max_evidence: int = 20,
        max_work_entries: int = 10,
        relation_types: Iterable[str] = ("rolls_up_from", "depends_on"),
        include_disputed: bool = True,
        cursor: str | None = None,
        max_pending_signals: int = 20,
        pending_token_budget: int = 4000,
        since_activity: int | None = None,
        auth: AuthContext | None = None,
    ) -> dict[str, Any]:
        issue = self._issue(issue_id, active=False)
        if max_nodes < 1 or max_nodes > 200:
            raise ValidationError("max_nodes must be between 1 and 200")
        if since_activity is not None and int(since_activity) < 0:
            raise ValidationError("since activity cursor must be a non-negative integer")
        allowed_relation_types = set(relation_types)
        unknown_relations = allowed_relation_types - {"rolls_up_from", "depends_on", "related_to"}
        if unknown_relations:
            raise ValidationError(f"Unknown relation types: {sorted(unknown_relations)}")
        offset = int(cursor or 0)
        adjacency: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for relation in self.store.rows(
            "SELECT consumer_issue_id,provider_issue_id,relation_type,impact_policy FROM relations WHERE active=1"
        ):
            if relation["relation_type"] not in allowed_relation_types:
                continue
            adjacency[relation["consumer_issue_id"]].append(relation)
        ordered_ids: list[str] = []
        queue: deque[str] = deque([issue_id])
        seen: set[str] = set()
        while queue and len(ordered_ids) < offset + max_nodes + 1:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            ordered_ids.append(current)
            for relation in sorted(
                adjacency.get(current, []), key=lambda item: item["provider_issue_id"]
            ):
                queue.append(relation["provider_issue_id"])
        page_ids = ordered_ids[offset : offset + max_nodes]
        has_more = len(ordered_ids) > offset + max_nodes
        nodes: list[dict[str, Any]] = []
        quarantine_warnings: list[str] = []
        from .integrity import active_quarantines

        for node_id in page_ids:
            node_issue = self._issue(node_id, active=False)
            conclusion = self.get_current_conclusion(node_id)
            if conclusion and conclusion["status"] == "disputed" and not include_disputed:
                conclusion = None
            if conclusion:
                quarantines = active_quarantines(
                    self.store.conn,
                    "conclusion_revision",
                    str(conclusion["conclusion_id"]),
                )
                if quarantines:
                    quarantine_warnings.append(
                        f"Conclusion {conclusion['conclusion_id']} is quarantined; follow "
                        f"{quarantines[0]['quarantine_id']}"
                    )
                    conclusion = None
            nodes.append(
                {
                    "issue_id": node_id,
                    "title": node_issue["title"],
                    "issue_type": node_issue["issue_type"],
                    "freshness": node_issue["freshness"],
                    "work_status": node_issue["work_status"],
                    "current_conclusion": conclusion,
                }
            )
        placeholders = ",".join("?" for _ in page_ids)
        evidence: list[dict[str, Any]] = []
        work_entries: list[dict[str, Any]] = []
        if page_ids:
            evidence = self.store.rows(
                f"SELECT ie.issue_id,e.evidence_id,e.kind,e.locator,e.quality_status,"
                f"e.verification_level,e.verification_state,"
                f"(SELECT m.platform_id FROM evidence_manifests m "
                f"WHERE m.evidence_id=e.evidence_id ORDER BY m.manifest_revision DESC LIMIT 1) "
                f"AS platform_id "
                f"FROM issue_evidence ie JOIN evidence_refs e ON e.evidence_id=ie.evidence_id "
                f"WHERE ie.issue_id IN ({placeholders}) AND e.lifecycle_status='active' "
                "ORDER BY ie.attached_at LIMIT ?",
                (*page_ids, max_evidence),
            )
            work_entries = [
                _clean_row(row) or {}
                for row in self.store.rows(
                    f"SELECT * FROM working_entries WHERE issue_id IN ({placeholders}) "
                    "ORDER BY created_at DESC LIMIT ?",
                    (*page_ids, max_work_entries),
                )
            ]
        child_episodes = self.store.rows(
            "SELECT issue_id,title,work_status,conclusion_status,freshness FROM issues "
            "WHERE parent_issue_id=? AND issue_type='episode' "
            "AND (work_status='open' OR conclusion_status='disputed') ORDER BY updated_at DESC",
            (issue_id,),
        )
        pending_signals, pending_summary = self._pending_signals(
            issue,
            max_items=max_pending_signals,
            character_budget=max(256, pending_token_budget),
        )
        warnings: list[str] = []
        warnings.extend(quarantine_warnings)
        if pending_summary["count"]:
            warnings.append(
                f"There are {pending_summary['count']} untriaged packet(s) relevant to this target"
            )
        allowed = ["show", "append-work", "append-evidence"]
        if issue["work_status"] not in {"archived", "void"}:
            allowed.extend(["publish-draft", "publish-provisional"])
        if issue["freshness"] != "fresh":
            allowed.append("refresh")
        primary_conclusion = self.get_current_conclusion(issue_id)
        if primary_conclusion and active_quarantines(
            self.store.conn,
            "conclusion_revision",
            str(primary_conclusion["conclusion_id"]),
        ):
            primary_conclusion = None
        payload: dict[str, Any] = {
            "protocol_version": 2,
            "intent": intent,
            "issue": issue,
            "current_conclusion": primary_conclusion,
            "freshness_detail": self.why_stale(issue_id),
            "dependency_closure": {
                "nodes": nodes,
                "evidence": evidence,
                "work_entries": work_entries,
                "open_or_disputed_child_episodes": child_episodes,
                "next_cursor": str(offset + max_nodes) if has_more else None,
                "limits": {
                    "max_nodes": max_nodes,
                    "max_evidence": max_evidence,
                    "max_work_entries": max_work_entries,
                },
            },
            "preflight": {
                "registry": "Query the Registry for current state before designing or running experiments",
                "protocol": "Follow the experiment gateway's current protocol; this ledger is read-only toward hardware",
            },
            "allowed_next_actions": allowed,
            "required_fields": {
                "append-work": ["entry_type", "body"],
                "publish": ["issue_id", "expected_conclusion_revision", "statement", "basis"],
            },
            "policy_version": self.policy.version,
            "published_context": {
                "issue": issue,
                "current_conclusion": primary_conclusion,
                "dependency_closure": {"nodes": nodes},
            },
            "pending_signals": pending_signals if intent != "report" else [],
            "pending_signal_summary": pending_summary,
            "warnings": warnings,
        }
        activity_head_row = self.store.row(
            "SELECT COALESCE(MAX(activity_sequence),0) AS cursor FROM activity_events"
        )
        activity_head = int((activity_head_row or {"cursor": 0})["cursor"])
        changes: list[dict[str, Any]] = []
        scanned_activity: list[dict[str, Any]] = []
        if since_activity is not None:
            scanned_activity = self.store.rows(
                "SELECT * FROM activity_events WHERE activity_sequence>? "
                "ORDER BY activity_sequence LIMIT 500",
                (int(since_activity),),
            )
            for event in scanned_activity:
                event_issue_ids = _loads(event.pop("issue_ids_json"), [])
                if event_issue_ids and not set(event_issue_ids) & set(page_ids):
                    continue
                event["issue_ids"] = event_issue_ids
                event["summary"] = _loads(event.pop("summary_json"), {})
                changes.append(event)
        next_activity_cursor = (
            int(scanned_activity[-1]["activity_sequence"]) if scanned_activity else activity_head
        )
        evidence_requests = self.store.rows(
            "SELECT DISTINCT r.evidence_request_id,r.evidence_id,r.platform_id,r.request_type,"
            "r.question,r.priority,r.state,r.deadline_at FROM evidence_requests r "
            "LEFT JOIN issue_evidence ie ON ie.evidence_id=r.evidence_id "
            "WHERE (r.issue_id=? OR ie.issue_id=?) AND r.state IN ('pending','claimed','running') "
            "ORDER BY r.priority DESC,r.created_at",
            (issue_id, issue_id),
        )
        needs_input = self.store.rows(
            "SELECT p.packet_id,q.question_id,q.question,q.created_at FROM intake_packets p "
            "JOIN intake_questions q ON q.packet_id=p.packet_id "
            "WHERE p.attached_issue_id=? AND p.status='needs_input' AND q.state='open' "
            "ORDER BY q.created_at",
            (issue_id,),
        )
        refresh_tasks = self.store.rows(
            "SELECT * FROM refresh_tasks WHERE issue_id=? AND state IN "
            "('pending','blocked','ready','proposed','awaiting_approval') "
            "ORDER BY priority DESC,created_at",
            (issue_id,),
        )
        record_revision_tokens: list[dict[str, Any]] = []
        if page_ids:
            record_revision_tokens = self.store.rows(
                "SELECT i.issue_id,i.record_instance_id,i.current_revision_id,"
                "i.record_template_registration_id,r.template_content_hash AS "
                "record_template_content_hash FROM record_instances i "
                "JOIN record_revisions r ON r.record_revision_id=i.current_revision_id "
                f"WHERE i.lifecycle_status='active' AND i.issue_id IN ({placeholders}) "
                "ORDER BY i.issue_id,i.record_instance_id",
                tuple(page_ids),
            )
        evidence_ids = sorted({item["evidence_id"] for item in evidence})
        evidence_semantic_changes: list[dict[str, Any]] = []
        proof_changes: list[dict[str, Any]] = []
        verification_blockers: list[dict[str, Any]] = []
        binding_conflicts: list[dict[str, Any]] = []
        if evidence_ids:
            evidence_placeholders = ",".join("?" for _ in evidence_ids)
            evidence_semantic_changes = self.store.rows(
                f"SELECT semantic_event_id,evidence_id,from_semantic_revision,"
                f"to_semantic_revision,event_type,trigger_object_type,trigger_object_id,"
                f"before_proof_id,after_proof_id,impact_class,reason,created_at "
                f"FROM evidence_semantic_events WHERE evidence_id IN ({evidence_placeholders}) "
                "ORDER BY created_at DESC LIMIT 100",
                tuple(evidence_ids),
            )
            proof_changes = [
                {
                    "evidence_id": item["evidence_id"],
                    "before_proof_id": item["before_proof_id"],
                    "after_proof_id": item["after_proof_id"],
                    "impact_class": item["impact_class"],
                    "reason": item["reason"],
                }
                for item in evidence_semantic_changes
                if item.get("before_proof_id") != item.get("after_proof_id")
            ]
            for evidence_id_value in evidence_ids:
                proof = self.store.row(
                    "SELECT reason_codes_json FROM evidence_proofs WHERE proof_id=("
                    "SELECT current_proof_id FROM evidence_refs WHERE evidence_id=?)",
                    (evidence_id_value,),
                )
                reasons = _loads(proof["reason_codes_json"], []) if proof else []
                if reasons:
                    verification_blockers.append(
                        {"evidence_id": evidence_id_value, "reason_codes": reasons}
                    )
            binding_conflicts = self.store.rows(
                f"SELECT evidence_id,binding_state,binding_revision,reason FROM "
                f"evidence_source_bindings WHERE evidence_id IN ({evidence_placeholders}) "
                "AND binding_state='binding_conflict' ORDER BY evidence_id",
                tuple(evidence_ids),
            )
        for token in record_revision_tokens:
            token["context_cursor"] = next_activity_cursor
        payload.update(
            {
                "snapshot": payload["published_context"],
                "changes_since_cursor": changes,
                "evidence_requests": evidence_requests,
                "needs_input": needs_input,
                "refresh_tasks": refresh_tasks,
                "evidence_semantic_changes": evidence_semantic_changes,
                "proof_changes": proof_changes,
                "verification_blockers": verification_blockers,
                "binding_conflicts": binding_conflicts,
                "refresh_reason": [
                    {
                        "issue_id": item["issue_id"],
                        "reason_type": item["reason_type"],
                        "trigger_issue_id": item["trigger_issue_id"],
                    }
                    for item in refresh_tasks
                ],
                "next_activity_cursor": next_activity_cursor,
                "next_cursor": next_activity_cursor,
                "activity_has_more": next_activity_cursor < activity_head,
                "record_revision_tokens": record_revision_tokens,
            }
        )
        guidance = self.guidance.get(issue_id, auth=auth, intent=intent)
        payload.update(
            {
                "guidance": guidance,
                "open_questions": guidance["open_questions"],
                "blocked_questions": guidance["blocked_questions"],
                "answered_but_stale_questions": guidance["answered_but_stale_questions"],
                "legacy_relation_candidates": self.context_queries.legacy_candidates(issue_id),
                "evidence_relation_impacts": self.context_queries.relation_impacts(issue_id),
                "changeset_replacement_chains": self.changesets.replacement_chains_for_issue(
                    issue_id
                ),
            }
        )
        active_rule = self.context_rules.active()["rule_id"]
        if rule_capabilities(active_rule)["resolver"] == "scoped-v2":
            payload["scoped_context"] = self.context_maintenance.current_scoped_projection(
                issue_id, auth=auth
            )
            # The scoped-v2 projection is the default handoff surface.  Do not
            # let the generic context envelope reintroduce the old ABC evidence
            # body; historical material remains available through its explicit
            # package/view/history APIs.
            payload["dependency_closure"] = {
                "nodes": [],
                "evidence": [],
                "work_entries": [],
                "open_or_disputed_child_episodes": [],
                "next_cursor": None,
                "limits": payload["dependency_closure"]["limits"],
            }
            for envelope in ("published_context", "snapshot"):
                published = dict(payload[envelope])
                published["dependency_closure"] = {"nodes": []}
                payload[envelope] = published
        if intent == "refresh":
            payload["refresh_package"] = self.prepare_refresh(issue_id)
        return payload

    def _pending_signals(
        self,
        issue: dict[str, Any],
        *,
        max_items: int,
        character_budget: int,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if max_items < 0 or max_items > 200:
            raise ValidationError("max_pending_signals must be between 0 and 200")
        issue_scope = issue.get("normalized_scope_key") or self._normalized_scope_key(
            issue.get("scope", {})
        )
        issue_topic = self._normalize_term(str(issue.get("topic") or ""))
        vocabulary = {
            self._normalize_term(row["value"])
            for row in self.store.rows(
                "SELECT alias AS value FROM issue_aliases WHERE issue_id=? "
                "UNION SELECT tag AS value FROM issue_tags WHERE issue_id=?",
                (issue["issue_id"], issue["issue_id"]),
            )
        }
        ranked: list[dict[str, Any]] = []
        for row in self.store.rows(
            "SELECT p.packet_id,p.packet_json,p.created_at,p.status,t.state AS triage_state "
            "FROM intake_packets p JOIN triage_tasks t ON t.packet_id=p.packet_id "
            "WHERE p.status IN ('pending','claimed','needs_input') "
            "ORDER BY p.created_at,p.packet_id LIMIT 500"
        ):
            packet = self.intake._v2_view(json.loads(row["packet_json"]))
            hints = packet.get("routing_hints", {})
            sample = str(hints.get("sample") or "")
            components = hints.get("components", [])
            if not isinstance(components, list):
                components = [components]
            packet_scope = "/".join(
                part
                for part in (
                    self._normalize_term(sample),
                    self._normalize_term(str(components[0])) if len(components) == 1 else "",
                )
                if part
            )
            packet_topic = self._normalize_term(str(hints.get("topic") or ""))
            score = 0
            if issue_scope and packet_scope == issue_scope:
                score += 100
            elif (
                issue_scope
                and packet_scope
                and (
                    issue_scope.startswith(packet_scope + "/")
                    or packet_scope.startswith(issue_scope + "/")
                )
            ):
                score += 65
            if issue_topic and packet_topic == issue_topic:
                score += 25
            text_terms = {
                self._normalize_term(str(value))
                for field in ("actions", "observations", "interpretation")
                for value in packet.get(field, [])
            }
            if vocabulary & text_terms:
                score += 10
            if score < 50:
                continue
            ranked.append(
                {
                    "packet_id": row["packet_id"],
                    "created_at": row["created_at"],
                    "routing_score": score,
                    "observations": [str(item) for item in packet.get("observations", [])[:5]],
                    "evidence_count": len(packet.get("evidence", [])),
                    "triage_state": row["triage_state"],
                }
            )
        ranked.sort(
            key=lambda item: (-item["routing_score"], item["created_at"], item["packet_id"])
        )
        selected: list[dict[str, Any]] = []
        used = 0
        for item in ranked:
            size = len(canonical_json(item))
            if len(selected) >= max_items or used + size > character_budget:
                break
            selected.append(item)
            used += size
        oldest_wait_seconds = None
        if ranked:
            try:
                oldest = min(datetime.fromisoformat(item["created_at"]) for item in ranked)
                oldest_wait_seconds = max(
                    0, int((datetime.now().astimezone() - oldest).total_seconds())
                )
            except ValueError:
                oldest_wait_seconds = None
        return selected, {
            "count": len(ranked),
            "returned": len(selected),
            "oldest_wait_seconds": oldest_wait_seconds,
            "cursor": selected[-1]["packet_id"]
            if len(selected) < len(ranked) and selected
            else None,
            "character_budget": character_budget,
            "characters_used": used,
        }

    # ------------------------------------------------------------------
    # Queries, doctor, audit, projections
    # ------------------------------------------------------------------
    def _subtree_ids(self, root: str) -> list[str]:
        rows = self.store.rows(
            "WITH RECURSIVE tree(issue_id) AS (SELECT issue_id FROM issues WHERE issue_id=? "
            "UNION ALL SELECT i.issue_id FROM issues i JOIN tree t ON i.parent_issue_id=t.issue_id) "
            "SELECT issue_id FROM tree",
            (root,),
        )
        return [row["issue_id"] for row in rows]

    def tree(self, root: str | None = None) -> dict[str, Any]:
        if root:
            self._issue(root, active=False)
            ids = set(self._subtree_ids(root))
            rows = [
                row
                for row in self.store.rows(
                    "SELECT issue_id,title,issue_type,parent_issue_id,work_status,conclusion_revision,freshness "
                    "FROM issues ORDER BY issue_id"
                )
                if row["issue_id"] in ids
            ]
        else:
            rows = self.store.rows(
                "SELECT issue_id,title,issue_type,parent_issue_id,work_status,conclusion_revision,freshness "
                "FROM issues ORDER BY issue_id"
            )
        children: dict[str | None, list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            children[row["parent_issue_id"]].append(row)

        def node(row: dict[str, Any]) -> dict[str, Any]:
            return {**row, "children": [node(child) for child in children.get(row["issue_id"], [])]}

        roots = [
            node(row)
            for row in rows
            if (row["issue_id"] == root if root else row["parent_issue_id"] is None)
        ]
        return {"root": root, "trees": roots}

    def history(self, issue_id: str) -> dict[str, Any]:
        self._issue(issue_id, active=False)
        conclusions = [
            _clean_row(row) or {}
            for row in self.store.rows(
                "SELECT * FROM conclusion_revisions WHERE issue_id=? ORDER BY revision_number",
                (issue_id,),
            )
        ]
        for conclusion in conclusions:
            conclusion["basis"] = self._basis_for(conclusion["conclusion_id"])
            conclusion["applied_rule"] = self.store.row(
                "SELECT revision,schema_hash,schema_json FROM conclusion_rule_bindings WHERE conclusion_id=?",
                (conclusion["conclusion_id"],))
            if conclusion["applied_rule"]:
                conclusion["applied_rule"]["schema"] = json.loads(conclusion["applied_rule"].pop("schema_json"))
        working = [
            _clean_row(row) or {}
            for row in self.store.rows(
                "SELECT * FROM working_entries WHERE issue_id=? ORDER BY created_at", (issue_id,)
            )
        ]
        events = [
            _clean_row(row) or {}
            for row in self.store.rows(
                "SELECT * FROM audit_events WHERE object_id=? ORDER BY timestamp,event_id",
                (issue_id,),
            )
        ]
        return {
            "issue_id": issue_id,
            "conclusions": conclusions,
            "working_entries": working,
            "audit_events": events,
        }

    def report_basis(self, report_issue_id: str) -> dict[str, Any]:
        issue = self._issue(report_issue_id, active=False)
        if issue["issue_type"] != "report_scope":
            raise ValidationError(f"Issue {report_issue_id} is not a report_scope")
        conclusion = self.get_current_conclusion(report_issue_id)
        if not conclusion:
            return {
                "report_issue_id": report_issue_id,
                "report_locator": None,
                "conclusion_revision": 0,
                "basis": [],
                "analysis_provenance": [],
                "needs_review": True,
                "reason": "report_scope has no published conclusion",
            }
        items: list[dict[str, Any]] = []
        needs_review = issue["freshness"] != "fresh"
        for basis in conclusion["basis"]:
            provider = self._issue(basis["issue_id"], active=False)
            superseded = self.store.row(
                "SELECT new_conclusion_id FROM conclusion_supersessions WHERE old_conclusion_id=?",
                (basis["conclusion_id"],),
            )
            changed = (
                provider["conclusion_revision"] != basis["conclusion_revision"]
                or bool(superseded)
                or provider["freshness"] != "fresh"
            )
            needs_review = needs_review or changed
            items.append(
                {
                    **basis,
                    "current_conclusion_revision": provider["conclusion_revision"],
                    "provider_freshness": provider["freshness"],
                    "superseded_by": superseded["new_conclusion_id"] if superseded else None,
                    "changed": changed,
                }
            )
        analysis_provenance: list[dict[str, Any]] = []
        artifact_ids = conclusion["structured_outputs"].get("artifact_ids", [])
        if not isinstance(artifact_ids, list):
            artifact_ids = []
        for artifact_id in artifact_ids:
            artifact = self.store.row(
                "SELECT artifact_id,sha256,role,storage_uri FROM artifacts WHERE artifact_id=?",
                (artifact_id,),
            )
            run = self.store.row(
                "SELECT ar.*,m.name AS method_name,m.script_artifact_id,m.source_hash "
                "FROM analysis_outputs ao JOIN analysis_runs ar "
                "ON ar.analysis_run_id=ao.analysis_run_id JOIN analysis_methods m "
                "ON m.method_id=ar.method_id WHERE ao.artifact_id=? AND ar.state='frozen' "
                "ORDER BY ar.frozen_at DESC LIMIT 1",
                (artifact_id,),
            )
            traceable = bool(artifact and artifact["role"] == "frozen" and run)
            if not traceable:
                needs_review = True
            analysis_provenance.append(
                {
                    "artifact": artifact,
                    "analysis_run_id": run["analysis_run_id"] if run else None,
                    "method_id": run["method_id"] if run else None,
                    "method_name": run["method_name"] if run else None,
                    "script_artifact_id": run["script_artifact_id"] if run else None,
                    "source_hash": run["source_hash"] if run else None,
                    "config": json.loads(run["config_json"]) if run else None,
                    "environment": json.loads(run["environment_json"]) if run else None,
                    "inputs": self.store.rows(
                        "SELECT input_type,input_id,validated_at,validation_snapshot "
                        "FROM analysis_inputs WHERE analysis_run_id=? ORDER BY input_type,input_id",
                        (run["analysis_run_id"],),
                    )
                    if run
                    else [],
                    "traceable": traceable,
                }
            )
        return {
            "report_issue_id": report_issue_id,
            "report_locator": conclusion["structured_outputs"].get("report_locator"),
            "conclusion_revision": conclusion["revision_number"],
            "basis": items,
            "analysis_provenance": analysis_provenance,
            "needs_review": needs_review,
        }

    def audit_events(self, limit: int = 200) -> list[dict[str, Any]]:
        return [
            _clean_row(row) or {}
            for row in self.store.rows(
                "SELECT * FROM audit_events ORDER BY timestamp DESC,event_id DESC LIMIT ?", (limit,)
            )
        ]

    def doctor(
        self,
        *,
        fix: bool = False,
        actor: str = "doctor",
        full_resolution_replay: bool = False,
        receipt_id: str | None = None,
    ) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        resolution_replays: list[dict[str, Any]] = []
        schema_version = self.store._schema_version(self.store.conn)
        if schema_version != LATEST_SCHEMA_VERSION:
            findings.append(
                {
                    "code": "schema_version",
                    "stored": schema_version,
                    "expected": LATEST_SCHEMA_VERSION,
                    "repairable": False,
                }
            )
        foreign_keys = self.store.rows("PRAGMA foreign_key_check")
        for row in foreign_keys:
            findings.append({"code": "foreign_key", "detail": row, "repairable": False})

        actual_evidence_columns = {
            row["name"] for row in self.store.rows("PRAGMA table_info(evidence_refs)")
        }
        required_v8_columns = {
            "normalized_locator",
            "identity_locator",
            "search_locator",
            "locator_identity_version",
            "identity_key",
            "identity_namespace",
        }
        if schema_version >= 8 and not required_v8_columns.issubset(actual_evidence_columns):
            findings.append(
                {
                    "code": "schema_shape_mismatch",
                    "detail": {
                        "missing_evidence_columns": sorted(
                            required_v8_columns - actual_evidence_columns
                        )
                    },
                    "repairable": False,
                }
            )
        if schema_version >= 2 and "declared_source_locator" not in actual_evidence_columns:
            findings.append(
                {
                    "code": "schema_shape_mismatch",
                    "detail": {"missing_evidence_columns": ["declared_source_locator"]},
                    "repairable": False,
                }
            )

        # Detect any existing hard cycle independently of relation-add validation.
        edges = self._hard_edges()
        for start in sorted(edges):
            for provider in edges[start]:
                path = self._find_path(edges, provider, start)
                if path:
                    findings.append(
                        {"code": "hard_cycle", "path": [start, *path], "repairable": False}
                    )
                    break

        pointers = self.store.rows(
            "SELECT i.issue_id,i.current_conclusion_id,i.conclusion_revision,c.issue_id AS conclusion_issue,c.revision_number "
            "FROM issues i LEFT JOIN conclusion_revisions c ON c.conclusion_id=i.current_conclusion_id "
            "WHERE (i.current_conclusion_id IS NOT NULL AND c.conclusion_id IS NULL) "
            "OR (c.issue_id IS NOT NULL AND (c.issue_id<>i.issue_id OR c.revision_number<>i.conclusion_revision))"
        )
        for row in pointers:
            findings.append({"code": "current_pointer", "detail": row, "repairable": False})

        for proposal in self.store.rows(
            "SELECT proposal_id,state,required_reviews,applied_conclusion_id FROM proposals"
        ):
            passes_row = self.store.row(
                "SELECT COUNT(*) AS n FROM review_decisions WHERE proposal_id=? AND decision='pass'",
                (proposal["proposal_id"],),
            )
            passes = int((passes_row or {"n": 0})["n"])
            if (
                proposal["state"] in {"review_passed", "applied"}
                and passes < proposal["required_reviews"]
            ):
                findings.append(
                    {
                        "code": "proposal_review_quorum",
                        "detail": {**proposal, "pass_count": passes},
                        "repairable": False,
                    }
                )
            if proposal["state"] == "applied" and not proposal["applied_conclusion_id"]:
                findings.append(
                    {"code": "proposal_apply_pointer", "detail": proposal, "repairable": False}
                )
            linked = self.store.row(
                "SELECT conclusion_id FROM conclusion_revisions WHERE proposal_id=?",
                (proposal["proposal_id"],),
            )
            if linked and (
                proposal["state"] != "applied"
                or proposal["applied_conclusion_id"] != linked["conclusion_id"]
            ):
                findings.append(
                    {"code": "proposal_reconcile_needed", "detail": proposal, "repairable": False}
                )
            if proposal["state"] == "applied" and not linked:
                findings.append(
                    {"code": "proposal_missing_conclusion", "detail": proposal, "repairable": False}
                )

        for task in self.store.rows(
            "SELECT triage_task_id,packet_id,claimed_by,lease_until FROM triage_tasks "
            "WHERE state='claimed' AND lease_until IS NOT NULL AND lease_until<?",
            (now(),),
        ):
            findings.append({"code": "expired_triage_lease", "detail": task, "repairable": False})

        for task in self.store.rows(
            "SELECT evidence_request_id,platform_id,claimed_by,lease_generation,lease_until "
            "FROM evidence_requests WHERE state IN ('claimed','running') "
            "AND lease_until IS NOT NULL AND lease_until<?",
            (now(),),
        ):
            findings.append(
                {"code": "expired_evidence_request_lease", "detail": task, "repairable": False}
            )

        for manifest in self.store.rows(
            "SELECT manifest_id,evidence_id,manifest_hash,manifest_json FROM evidence_manifests"
        ):
            actual = hashlib.sha256(
                canonical_json(json.loads(manifest["manifest_json"])).encode("utf-8")
            ).hexdigest()
            if actual != manifest["manifest_hash"]:
                findings.append(
                    {
                        "code": "evidence_manifest_hash",
                        "detail": {
                            "manifest_id": manifest["manifest_id"],
                            "evidence_id": manifest["evidence_id"],
                            "stored": manifest["manifest_hash"],
                            "actual": actual,
                        },
                        "repairable": False,
                    }
                )

        platform_l0_legacy = self.store.rows(
            "SELECT DISTINCT e.evidence_id,a.platform_id,ie.packet_id,ie.locator "
            "FROM evidence_refs e JOIN intake_evidence ie ON ie.evidence_id=e.evidence_id "
            "JOIN intake_packets p ON p.packet_id=ie.packet_id "
            "JOIN actors a ON a.actor_id=p.submitted_by "
            "WHERE a.platform_id IS NOT NULL AND e.current_manifest_id IS NULL "
            "AND e.identity_namespace='legacy' ORDER BY e.evidence_id,ie.packet_id"
        )
        if platform_l0_legacy:
            findings.append(
                {
                    "code": "platform_l0_legacy_identity",
                    "detail": platform_l0_legacy,
                    "repairable": False,
                }
            )
        multi_platform_l0 = self.store.rows(
            "SELECT e.evidence_id,COUNT(DISTINCT a.platform_id) AS platform_count "
            "FROM evidence_refs e JOIN intake_evidence ie ON ie.evidence_id=e.evidence_id "
            "JOIN intake_packets p ON p.packet_id=ie.packet_id "
            "JOIN actors a ON a.actor_id=p.submitted_by "
            "WHERE a.platform_id IS NOT NULL AND e.current_manifest_id IS NULL "
            "GROUP BY e.evidence_id HAVING COUNT(DISTINCT a.platform_id)>1"
        )
        unresolved_multi = [
            item
            for item in multi_platform_l0
            if not self.store.row(
                "SELECT 1 FROM evidence_identity_ambiguities WHERE evidence_id=? "
                "AND ambiguity_type='multi_platform_l0' AND state IN ('resolved','waived')",
                (item["evidence_id"],),
            )
        ]
        if unresolved_multi:
            findings.append(
                {
                    "code": "multi_platform_l0_identity_merge",
                    "detail": unresolved_multi,
                    "repairable": False,
                }
            )
        raw_locators: dict[str, set[str]] = defaultdict(set)
        for item in self.store.rows(
            "SELECT e.evidence_id,e.locator AS evidence_locator,ie.locator AS packet_locator "
            "FROM evidence_refs e LEFT JOIN intake_evidence ie ON ie.evidence_id=e.evidence_id"
        ):
            raw_locators[item["evidence_id"]].add(item["evidence_locator"])
            if item.get("packet_locator") is not None:
                raw_locators[item["evidence_id"]].add(item["packet_locator"])
        unresolved_raw = [
            {"evidence_id": evidence_id, "raw_locators": sorted(locators)}
            for evidence_id, locators in sorted(raw_locators.items())
            if len(locators) > 1
            and not self.store.row(
                "SELECT 1 FROM evidence_identity_ambiguities WHERE evidence_id=? "
                "AND ambiguity_type='multiple_raw_locators' AND state IN ('resolved','waived')",
                (evidence_id,),
            )
        ]
        if unresolved_raw:
            findings.append(
                {
                    "code": "multiple_raw_locator_identity_merge",
                    "detail": unresolved_raw,
                    "repairable": False,
                }
            )
        published_ambiguities = self.store.rows(
            "SELECT DISTINCT a.ambiguity_id,a.evidence_id,a.ambiguity_type,c.conclusion_id,"
            "c.status,i.issue_id,i.issue_type FROM evidence_identity_ambiguities a "
            "JOIN conclusion_evidence_uses u ON u.evidence_id=a.evidence_id "
            "JOIN conclusion_revisions c ON c.conclusion_id=u.conclusion_id "
            "JOIN issues i ON i.current_conclusion_id=c.conclusion_id "
            "WHERE a.state='open' AND (c.status IN ('accepted','canonical') "
            "OR i.issue_type='report_scope') ORDER BY a.ambiguity_id,i.issue_id"
        )
        if published_ambiguities:
            findings.append(
                {
                    "code": "published_identity_ambiguity",
                    "detail": published_ambiguities,
                    "repairable": False,
                }
            )

        binding_findings: list[dict[str, Any]] = []
        identity_v2_findings: list[dict[str, Any]] = []
        for evidence in self.store.rows(
            "SELECT evidence_id,kind,locator,normalized_locator,identity_locator,search_locator,"
            "locator_identity_version,identity_key,identity_namespace,"
            "lifecycle_status,current_manifest_id,current_proof_id,semantic_revision,"
            "verification_level,verification_state FROM evidence_refs"
        ):
            binding = self.store.row(
                "SELECT * FROM evidence_source_bindings WHERE evidence_id=?",
                (evidence["evidence_id"],),
            )
            current_manifest: dict[str, Any] | None = (
                self.store.row(
                    "SELECT evidence_id,platform_id FROM evidence_manifests WHERE manifest_id=?",
                    (evidence.get("current_manifest_id"),),
                )
                if evidence.get("current_manifest_id")
                else None
            )
            if not binding:
                binding_findings.append(
                    {"evidence_id": evidence["evidence_id"], "error": "binding_missing"}
                )
            try:
                exact = identity_locator(evidence["locator"])
                search = search_normalize_locator(evidence["locator"])
            except (TypeError, ValueError) as exc:
                identity_v2_findings.append(
                    {
                        "evidence_id": evidence["evidence_id"],
                        "error": "locator_identity_invalid",
                        "detail": str(exc),
                    }
                )
                continue
            if (
                evidence["identity_locator"] != exact
                or evidence["search_locator"] != search
                or evidence["normalized_locator"] != search
                or int(evidence["locator_identity_version"]) != LOCATOR_IDENTITY_VERSION
            ):
                identity_v2_findings.append(
                    {
                        "evidence_id": evidence["evidence_id"],
                        "error": "locator_v2_fields_drift",
                        "stored_identity_locator": evidence["identity_locator"],
                        "expected_identity_locator": exact,
                        "stored_search_locator": evidence["search_locator"],
                        "expected_search_locator": search,
                        "stored_version": evidence["locator_identity_version"],
                    }
                )
            expected_namespace = "legacy"
            expected_identity = legacy_identity_key(evidence["kind"], exact)
            if evidence["lifecycle_status"] != "active" or (
                binding and binding["binding_state"] in {"binding_conflict", "retired"}
            ):
                expected_namespace = "conflict"
                expected_identity = conflict_identity_key(evidence["evidence_id"])
            elif binding and binding["binding_state"] in {"bound", "inferred"}:
                expected_namespace = "platform"
                if binding.get("source_platform_id"):
                    expected_identity = platform_identity_key(
                        binding["source_platform_id"], evidence["kind"], exact
                    )
                if binding.get("source_key") != expected_identity:
                    binding_findings.append(
                        {
                            "evidence_id": evidence["evidence_id"],
                            "error": "source_key_drift",
                            "stored": binding.get("source_key"),
                            "expected": expected_identity,
                        }
                    )
            if (
                evidence["identity_namespace"] != expected_namespace
                or evidence["identity_key"] != expected_identity
            ):
                identity_v2_findings.append(
                    {
                        "evidence_id": evidence["evidence_id"],
                        "error": "evidence_identity_drift",
                        "stored_namespace": evidence["identity_namespace"],
                        "expected_namespace": expected_namespace,
                        "stored_key": evidence["identity_key"],
                        "expected_key": expected_identity,
                    }
                )
            if (
                binding
                and binding["binding_state"] in {"bound", "inferred"}
                and current_manifest
                and current_manifest["platform_id"] != binding["source_platform_id"]
            ):
                binding_findings.append(
                    {
                        "evidence_id": evidence["evidence_id"],
                        "error": "current_manifest_platform_mismatch",
                        "expected_platform": binding["source_platform_id"],
                        "actual_platform": current_manifest["platform_id"],
                    }
                )
            proof = (
                self.store.row(
                    "SELECT * FROM evidence_proofs WHERE proof_id=?",
                    (evidence.get("current_proof_id"),),
                )
                if evidence.get("current_proof_id")
                else None
            )
            if not proof:
                binding_findings.append(
                    {"evidence_id": evidence["evidence_id"], "error": "current_proof_missing"}
                )
            elif (
                proof["evidence_id"] != evidence["evidence_id"]
                or int(proof["semantic_revision"]) != int(evidence["semantic_revision"])
                or proof["verification_level"] != evidence["verification_level"]
                or proof["verification_state"] != evidence["verification_state"]
                or hashlib.sha256(proof["proof_json"].encode("utf-8")).hexdigest()
                != proof["proof_hash"]
            ):
                binding_findings.append(
                    {"evidence_id": evidence["evidence_id"], "error": "current_proof_incoherent"}
                )
            elif (
                hashlib.sha256(
                    canonical_json(self.evidence._proof_snapshot(evidence["evidence_id"])).encode(
                        "utf-8"
                    )
                ).hexdigest()
                != proof["proof_hash"]
            ):
                binding_findings.append(
                    {"evidence_id": evidence["evidence_id"], "error": "proof_pointer_drift"}
                )
        if binding_findings:
            findings.append(
                {
                    "code": "evidence_proof_binding_drift",
                    "detail": binding_findings,
                    "repairable": False,
                }
            )
        if identity_v2_findings:
            findings.append(
                {
                    "code": "identity_v2_drift",
                    "detail": identity_v2_findings,
                    "repairable": False,
                }
            )

        conclusion_proof_drifts: list[dict[str, Any]] = []
        for use in self.store.rows(
            "SELECT conclusion_id,evidence_id,use_role,proof_id,proof_hash,"
            "evidence_semantic_revision,manifest_id,manifest_hash FROM conclusion_evidence_uses"
        ):
            proof = (
                self.store.row(
                    "SELECT proof_hash,semantic_revision,manifest_id,manifest_hash,evidence_id "
                    "FROM evidence_proofs WHERE proof_id=?",
                    (use.get("proof_id"),),
                )
                if use.get("proof_id")
                else None
            )
            if not proof or any(
                (
                    proof["evidence_id"] != use["evidence_id"],
                    proof["proof_hash"] != use.get("proof_hash"),
                    int(proof["semantic_revision"])
                    != int(
                        use["evidence_semantic_revision"]
                        if use.get("evidence_semantic_revision") is not None
                        else -1
                    ),
                    proof.get("manifest_id") != use.get("manifest_id"),
                    proof.get("manifest_hash") != use.get("manifest_hash"),
                )
            ):
                conclusion_proof_drifts.append(
                    {
                        "conclusion_id": use["conclusion_id"],
                        "evidence_id": use["evidence_id"],
                        "use_role": use["use_role"],
                    }
                )
        if conclusion_proof_drifts:
            findings.append(
                {
                    "code": "conclusion_proof_snapshot_drift",
                    "detail": conclusion_proof_drifts,
                    "repairable": False,
                }
            )

        level_rank = {
            "declared": 0,
            "source_verified": 1,
            "snapshot_verified": 2,
            "reproduced": 3,
        }
        stale_proof_uses: list[dict[str, Any]] = []
        for use in self.store.rows(
            "SELECT i.issue_id,i.freshness,c.conclusion_id,c.status,u.evidence_id,"
            "stored.verification_level AS stored_level,current.verification_level AS current_level,"
            "current.verification_state AS current_state FROM issues i "
            "JOIN conclusion_revisions c ON c.conclusion_id=i.current_conclusion_id "
            "JOIN conclusion_evidence_uses u ON u.conclusion_id=c.conclusion_id "
            "LEFT JOIN evidence_proofs stored ON stored.proof_id=u.proof_id "
            "JOIN evidence_refs e ON e.evidence_id=u.evidence_id "
            "LEFT JOIN evidence_proofs current ON current.proof_id=e.current_proof_id "
            "WHERE i.freshness='fresh'"
        ):
            if use.get("current_state") in {
                "conflict",
                "unavailable",
                "superseded",
            } or level_rank.get(str(use.get("current_level") or "declared"), 0) < level_rank.get(
                str(use.get("stored_level") or "declared"), 0
            ):
                stale_proof_uses.append(use)
        if stale_proof_uses:
            findings.append(
                {
                    "code": "fresh_conclusion_uses_degraded_proof",
                    "detail": stale_proof_uses,
                    "repairable": False,
                }
            )

        semantic_impact_drifts: list[dict[str, Any]] = []
        severity = {"none": 0, "notify": 1, "impact_review": 2, "stale": 3, "blocked": 4}
        for event in self.store.rows(
            "SELECT semantic_event_id,impact_class,cause_json FROM evidence_semantic_events"
        ):
            try:
                cause = json.loads(event["cause_json"] or "{}")
            except json.JSONDecodeError:
                cause = {}
            before = {
                "level": str(cause.get("before_level", "declared")),
                "state": str(cause.get("before_state", "active")),
            }
            after = {
                "level": str(cause.get("after_level", before["level"])),
                "state": str(cause.get("after_state", before["state"])),
            }
            _, required_impact, _ = self.evidence._classify_proof_transition(before, after)
            if severity.get(event["impact_class"], -1) < severity[required_impact]:
                semantic_impact_drifts.append(
                    {
                        "semantic_event_id": event["semantic_event_id"],
                        "stored": event["impact_class"],
                        "required": required_impact,
                    }
                )
        if semantic_impact_drifts:
            findings.append(
                {
                    "code": "semantic_impact_below_proof_transition",
                    "detail": semantic_impact_drifts,
                    "repairable": False,
                }
            )

        legacy_published = self.store.rows(
            "SELECT DISTINCT u.evidence_id,c.conclusion_id,c.status,i.issue_id,i.issue_type "
            "FROM issues i JOIN conclusion_revisions c "
            "ON c.conclusion_id=i.current_conclusion_id "
            "JOIN conclusion_evidence_uses u ON u.conclusion_id=c.conclusion_id "
            "LEFT JOIN evidence_source_bindings b ON b.evidence_id=u.evidence_id "
            "WHERE (c.status IN ('accepted','canonical') OR i.issue_type='report_scope') "
            "AND COALESCE(b.binding_state,'legacy_unbound')='legacy_unbound'"
        )
        if legacy_published:
            findings.append(
                {
                    "code": "legacy_published_binding_review_required",
                    "detail": legacy_published,
                    "repairable": False,
                }
            )

        verification_drifts: list[dict[str, Any]] = []
        for evidence in self.store.rows(
            "SELECT evidence_id,verification_level,verification_state FROM evidence_refs"
        ):
            expected_verification = self.evidence.expected(evidence["evidence_id"])
            stored_verification = {
                "level": evidence["verification_level"],
                "state": evidence["verification_state"],
            }
            if stored_verification != expected_verification:
                verification_drifts.append(
                    {
                        "evidence_id": evidence["evidence_id"],
                        "stored": stored_verification,
                        "expected": expected_verification,
                    }
                )
        if verification_drifts:
            findings.append(
                {
                    "code": "evidence_verification_drift",
                    "detail": verification_drifts,
                    "repairable": True,
                    "fixed": fix,
                }
            )
            if fix:
                with self.store.transaction() as conn:
                    for drift in verification_drifts:
                        conn.execute(
                            "UPDATE evidence_refs SET verification_level=?,verification_state=? "
                            "WHERE evidence_id=?",
                            (
                                drift["expected"]["level"],
                                drift["expected"]["state"],
                                drift["evidence_id"],
                            ),
                        )

        for packet in self.store.rows(
            "SELECT p.packet_id FROM intake_packets p LEFT JOIN triage_dispositions d "
            "ON d.packet_id=p.packet_id WHERE p.status='completed' AND d.packet_id IS NULL"
        ):
            findings.append(
                {
                    "code": "completed_triage_without_disposition",
                    "detail": packet,
                    "repairable": False,
                }
            )

        for basis in self.store.rows(
            "SELECT c.issue_id AS consumer_issue_id,b.provider_issue_id,c.conclusion_id "
            "FROM conclusion_basis b JOIN conclusion_revisions c ON c.conclusion_id=b.conclusion_id "
            "JOIN issues i ON i.current_conclusion_id=c.conclusion_id "
            "LEFT JOIN relations r ON r.consumer_issue_id=c.issue_id "
            "AND r.provider_issue_id=b.provider_issue_id AND r.active=1 "
            "WHERE r.relation_id IS NULL"
        ):
            findings.append(
                {"code": "basis_without_active_relation", "detail": basis, "repairable": False}
            )

        for conclusion in self.store.rows(
            "SELECT c.conclusion_id,c.issue_id,c.status FROM conclusion_revisions c "
            "WHERE c.status IN ('accepted','canonical') AND EXISTS ("
            "SELECT 1 FROM conclusion_evidence_uses u WHERE u.conclusion_id=c.conclusion_id "
            "AND (u.verification_level_snapshot='declared' OR u.fitness='unknown_for_use'))"
        ):
            findings.append(
                {"code": "legacy_verification_gap", "detail": conclusion, "repairable": False}
            )

        for artifact in self.store.rows("SELECT artifact_id FROM artifacts"):
            verification = self.artifacts.verify(artifact["artifact_id"])
            if not verification["ok"]:
                findings.append(
                    {"code": "artifact_integrity", "detail": verification, "repairable": False}
                )

        publishable_artifacts = self.store.rows(
            "SELECT DISTINCT a.artifact_id FROM artifacts a "
            "WHERE a.role='frozen' OR a.artifact_id IN (SELECT artifact_id FROM artifact_links) "
            "OR a.artifact_id IN (SELECT artifact_id FROM analysis_outputs) "
            "OR a.artifact_id IN (SELECT locator FROM evidence_refs WHERE kind='artifact')"
        )
        for artifact in publishable_artifacts:
            verification = self.artifacts.verify_manifest(artifact["artifact_id"])
            if not verification["ok"]:
                if fix:
                    self.artifacts._write_manifest(artifact["artifact_id"])
                findings.append(
                    {
                        "code": "artifact_manifest_integrity",
                        "detail": verification,
                        "repairable": True,
                        "fixed": fix,
                    }
                )

        for run in self.store.rows(
            "SELECT analysis_run_id,method_id FROM analysis_runs WHERE state='frozen'"
        ):
            try:
                method = self.store.row(
                    "SELECT script_artifact_id FROM analysis_methods WHERE method_id=?",
                    (run["method_id"],),
                )
                if not method or not self.artifacts.verify(method["script_artifact_id"])["ok"]:
                    raise ValidationError("method script is missing or corrupt")
                for input_row in self.store.rows(
                    "SELECT input_type,input_id FROM analysis_inputs WHERE analysis_run_id=?",
                    (run["analysis_run_id"],),
                ):
                    self.artifacts._validate_input(input_row["input_type"], input_row["input_id"])
                for output in self.store.rows(
                    "SELECT artifact_id FROM analysis_outputs WHERE analysis_run_id=?",
                    (run["analysis_run_id"],),
                ):
                    if not self.artifacts.verify(output["artifact_id"])["ok"]:
                        raise ValidationError(
                            f"output {output['artifact_id']} is missing or corrupt"
                        )
            except (NotFoundError, ValidationError) as exc:
                findings.append(
                    {
                        "code": "analysis_run_integrity",
                        "detail": {"analysis_run_id": run["analysis_run_id"], "error": str(exc)},
                        "repairable": False,
                    }
                )

        for issue in self.store.rows(
            "SELECT issue_id,issue_type_registration_id,issue_type_content_hash,"
            "issue_type_snapshot_json,issue_type_semantic_hash FROM issues "
            "WHERE issue_type_registration_id IS NOT NULL"
        ):
            try:
                snapshot = json.loads(issue["issue_type_snapshot_json"])
                actual_semantic_hash = hashlib.sha256(
                    canonical_json(snapshot).encode("utf-8")
                ).hexdigest()
                entry = self.store.row(
                    "SELECT kind,content_hash FROM registry_entries WHERE registration_id=?",
                    (issue["issue_type_registration_id"],),
                )
                if (
                    not entry
                    or entry["kind"] != "issue_type"
                    or entry["content_hash"] != issue["issue_type_content_hash"]
                    or snapshot.get("registration_id") != issue["issue_type_registration_id"]
                    or actual_semantic_hash != issue["issue_type_semantic_hash"]
                ):
                    raise ValueError("registration or semantic hash mismatch")
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                findings.append(
                    {
                        "code": "issue_type_semantic_snapshot_incoherent",
                        "detail": {"issue_id": issue["issue_id"], "error": str(exc)},
                        "repairable": False,
                    }
                )
        for conclusion in self.store.rows(
            "SELECT c.conclusion_id,c.issue_id,c.issue_type_registration_id,"
            "c.issue_type_semantic_hash,c.issue_type_semantic_snapshot_json,"
            "i.issue_type_registration_id AS current_registration_id,"
            "i.issue_type_semantic_hash AS current_semantic_hash "
            "FROM conclusion_revisions c JOIN issues i ON i.issue_id=c.issue_id"
        ):
            try:
                snapshot = json.loads(conclusion["issue_type_semantic_snapshot_json"])
                actual = hashlib.sha256(canonical_json(snapshot).encode("utf-8")).hexdigest()
                coherent = (
                    conclusion["issue_type_semantic_hash"] == actual
                    and snapshot.get("registration_id") == conclusion["issue_type_registration_id"]
                )
            except (json.JSONDecodeError, TypeError):
                coherent = False
            if not coherent:
                findings.append(
                    {
                        "code": "conclusion_issue_type_semantics_incoherent",
                        "detail": {"conclusion_id": conclusion["conclusion_id"]},
                        "repairable": False,
                    }
                )
        from .integrity import validate_object_integrity
        for conclusion in self.store.rows("SELECT conclusion_id FROM conclusion_revisions ORDER BY conclusion_id"):
            checked = validate_object_integrity(self.store.conn, "conclusion_revision", conclusion["conclusion_id"])
            rule_findings = [item for item in checked["findings"] if item.get("code") in {
                "conclusion_rule_binding_missing", "conclusion_rule_binding_incoherent",
                "conclusion_output_schema_invalid"}]
            if rule_findings:
                findings.append({"code": "conclusion_rule_integrity", "repairable": False,
                                 "detail": {"conclusion_id": conclusion["conclusion_id"],
                                            "findings": rule_findings}})
        for rule in self.store.rows("SELECT issue_id,revision,schema_json,schema_hash FROM issue_conclusion_rule_versions"):
            try:
                from .conclusion_rule_schema import validate_conclusion_rule_schema
                schema = validate_conclusion_rule_schema(json.loads(rule["schema_json"]))
                if hashlib.sha256(canonical_json(schema).encode("utf-8")).hexdigest() != rule["schema_hash"]:
                    raise ValueError("schema hash mismatch")
            except (ValueError, TypeError, ValidationError) as exc:
                findings.append({"code": "conclusion_rule_version_incoherent", "repairable": False,
                                 "detail": {"issue_id": rule["issue_id"], "revision": rule["revision"],
                                            "error": str(exc)}})
        incomplete_links = self.store.rows(
            "SELECT l.record_revision_id,l.field_path,l.evidence_id,l.proof_id "
            "FROM record_evidence_links l JOIN record_revisions r "
            "ON r.record_revision_id=l.record_revision_id WHERE r.validation_profile IN "
            "('accepted','canonical','report') AND (l.proof_id IS NULL OR l.proof_hash IS NULL "
            "OR l.verification_level_snapshot IS NULL OR l.verification_state_snapshot IS NULL)"
        )
        findings.extend(
            {
                "code": "formal_record_proof_snapshot_incomplete",
                "detail": item,
                "repairable": False,
            }
            for item in incomplete_links
        )
        for build in self.store.rows(
            "SELECT report_build_id,report_template_snapshot_json,report_model_json,"
            "report_model_hash,renderer_hash,output_format,state,normalized_scope_json,"
            "normalized_scope_hash,renderer_snapshot_json,renderer_kind,"
            "renderer_registration_id,adapter_name,adapter_version,adapter_executable_hash,"
            "adapter_descriptor_hash,adapter_protocol_version,adapter_state_revision "
            "FROM report_builds"
        ):
            try:
                template = json.loads(build["report_template_snapshot_json"])
                model = json.loads(build["report_model_json"])
                minimum = template.get("definition", {}).get("eligibility", {}).get(
                    "minimum_conclusion_status"
                ) or template.get("definition", {}).get("minimum_conclusion_status")
                conclusion_inputs = int(
                    (
                        self.store.row(
                            "SELECT COUNT(*) AS n FROM report_build_inputs WHERE report_build_id=? "
                            "AND object_type='conclusion'",
                            (build["report_build_id"],),
                        )
                        or {"n": 0}
                    )["n"]
                )
                normalized_scope = json.loads(build["normalized_scope_json"])
                renderer_snapshot = json.loads(build["renderer_snapshot_json"])
                renderer_payload = {
                    key: value for key, value in renderer_snapshot.items() if key != "renderer_hash"
                }
                healthy = (
                    hashlib.sha256(canonical_json(model).encode("utf-8")).hexdigest()
                    == build["report_model_hash"]
                    and hashlib.sha256(canonical_json(normalized_scope).encode("utf-8")).hexdigest()
                    == build["normalized_scope_hash"]
                    and hashlib.sha256(canonical_json(renderer_payload).encode("utf-8")).hexdigest()
                    == build["renderer_hash"]
                    and (
                        not minimum
                        or conclusion_inputs > 0
                        or build["state"] in {"stale", "stale_requires_reprepare"}
                    )
                )
                if healthy and build["renderer_kind"] == "adapter":
                    renderer_identity = self.reports.renderer_identity(build["report_build_id"])
                    healthy = renderer_identity["status"] == "matched"
                    for identity_finding in renderer_identity["findings"]:
                        code = str(identity_finding["code"])
                        if code in {
                            "renderer_adapter_snapshot_unresolvable",
                            "renderer_registration_unavailable",
                        }:
                            doctor_code = "renderer_adapter_snapshot_unresolvable"
                        elif code == "adapter_limit_snapshot_invalid":
                            doctor_code = "adapter_limit_snapshot_invalid"
                        else:
                            doctor_code = "renderer_frozen_identity_incomplete"
                        findings.append(
                            {
                                "code": doctor_code,
                                "detail": {
                                    "report_build_id": build["report_build_id"],
                                    "identity_finding": identity_finding,
                                },
                                "repairable": False,
                            }
                        )
            except (json.JSONDecodeError, TypeError, NotFoundError, ValidationError):
                healthy = False
            if not healthy:
                findings.append(
                    {
                        "code": "report_basis_incoherent",
                        "detail": {"report_build_id": build["report_build_id"]},
                        "repairable": False,
                    }
                )
        for attachment in self.store.rows(
            "SELECT field_bundle_id,attachment_path,expected_sha256,artifact_id,upload_state "
            "FROM field_bundle_attachments WHERE upload_state='verified'"
        ):
            attachment_artifact = self.store.row(
                "SELECT sha256 FROM artifacts WHERE artifact_id=?", (attachment["artifact_id"],)
            )
            if (
                not attachment_artifact
                or attachment_artifact["sha256"] != attachment["expected_sha256"]
                or not self.artifacts.verify(attachment["artifact_id"])["ok"]
            ):
                findings.append(
                    {
                        "code": "field_bundle_attachment_incoherent",
                        "detail": attachment,
                        "repairable": False,
                    }
                )
        recoverable_states = {
            "pending",
            "staged",
            "ready",
            "applied",
            "needs_triage",
            "rejected",
            "failed",
            "replayed",
        }
        for event in self.store.rows(
            "SELECT field_bundle_event_id,processing_state,result_json FROM field_bundle_events"
        ):
            if event["processing_state"] not in recoverable_states:
                findings.append(
                    {
                        "code": "field_bundle_event_state_unrecoverable",
                        "detail": event,
                        "repairable": False,
                    }
                )
        for action in self.store.rows(
            "SELECT field_bundle_event_action_id,action_type,action_json,action_hash,state,"
            "target_record_instance_id,base_record_revision_id,conflict_policy,validation_state "
            "FROM field_bundle_event_actions WHERE action_type='record_revise'"
        ):
            try:
                normalized = self.field_bundles._normalize_action(json.loads(action["action_json"]))
                coherent = (
                    action["target_record_instance_id"] == normalized["record_instance_id"]
                    and action["base_record_revision_id"] == normalized["base_record_revision_id"]
                    and action["conflict_policy"] == "create_conflict"
                    and action["validation_state"] == "valid"
                    and hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
                    == action["action_hash"]
                )
            except (json.JSONDecodeError, ValidationError):
                coherent = action["state"] == "needs_triage"
            if not coherent:
                findings.append(
                    {
                        "code": "field_action_identity_incoherent",
                        "detail": action,
                        "repairable": action["state"] == "ready",
                        "fixed": False,
                    }
                )
        for finding in self.store.rows(
            "SELECT finding_id,migration_version,classification,code,object_type,object_id,"
            "details_json FROM migration_findings WHERE state='open' "
            "AND classification<>'safe_auto_migration'"
        ):
            finding["details"] = json.loads(finding.pop("details_json"))
            findings.append(
                {
                    "code": "migration_operator_finding",
                    "detail": finding,
                    "repairable": False,
                    "operator_action_required": True,
                }
            )
        from .integrity import object_hash, validate_quarantine_release_receipt

        for quarantine in self.store.rows(
            "SELECT * FROM integrity_quarantines ORDER BY created_at,quarantine_id"
        ):
            if quarantine["state"] == "active":
                current_hash = object_hash(
                    self.store.conn,
                    str(quarantine["object_type"]),
                    str(quarantine["object_id"]),
                )
                if current_hash != quarantine["subject_hash"]:
                    findings.append(
                        {
                            "code": "quarantine_subject_drift",
                            "detail": {
                                "quarantine_id": quarantine["quarantine_id"],
                                "recorded": quarantine["subject_hash"],
                                "current": current_hash,
                            },
                            "repairable": False,
                        }
                    )
            else:
                receipt_id = quarantine.get("release_receipt_id")
                quarantine_validation: dict[str, Any] = (
                    validate_quarantine_release_receipt(
                        self.store,
                        quarantine,
                        str(receipt_id),
                        full=full_resolution_replay,
                        actor="doctor",
                    )
                    if receipt_id
                    else {
                        "valid": False,
                        "findings": [{"code": "quarantine_release_without_repair"}],
                    }
                )
                if not quarantine_validation["valid"]:
                    for item in quarantine_validation["findings"]:
                        findings.append(
                            {
                                "code": item["code"],
                                "detail": {
                                    "quarantine_id": quarantine["quarantine_id"],
                                    **item,
                                },
                                "repairable": False,
                            }
                        )
        for finding in self.store.rows(
            "SELECT * FROM migration_findings WHERE state='resolved' AND classification IN "
            "('requires_policy_mapping','blocking_corruption','requires_triage')"
        ):
            receipt_id = finding.get("resolution_receipt_id")
            if not receipt_id:
                findings.append(
                    {
                        "code": "blocking_finding_resolved_without_proof",
                        "detail": {"finding_id": finding["finding_id"]},
                        "repairable": False,
                    }
                )
                continue
            receipt = self.store.row(
                "SELECT * FROM migration_finding_resolution_receipts WHERE receipt_id=?",
                (receipt_id,),
            )
            attempt = (
                self.store.row(
                    "SELECT * FROM migration_finding_resolution_attempts WHERE attempt_id=?",
                    (receipt["accepted_attempt_id"],),
                )
                if receipt
                else None
            )
            if (
                not receipt
                or receipt["finding_id"] != finding["finding_id"]
                or not attempt
                or not attempt["accepted"]
                or attempt["finding_id"] != finding["finding_id"]
            ):
                findings.append(
                    {
                        "code": "migration_resolution_receipt_missing",
                        "detail": {
                            "finding_id": finding["finding_id"],
                            "receipt_id": receipt_id,
                        },
                        "repairable": False,
                    }
                )
                continue
            if receipt_id and receipt_id != receipt["receipt_id"]:
                continue
            if receipt.get("proof_format") != "migration-resolution-proof/v2":
                findings.append(
                    {
                        "code": "migration_resolution_proof_format_legacy",
                        "detail": {
                            "finding_id": finding["finding_id"],
                            "receipt_id": receipt["receipt_id"],
                            "proof_format": receipt.get("proof_format"),
                        },
                        "repairable": False,
                    }
                )
                continue
            replay = self.store.replay_migration_finding_receipt(
                receipt["receipt_id"],
                full=full_resolution_replay,
                persist=full_resolution_replay,
                actor=actor,
            )
            resolution_replays.append(replay)
            for replay_finding in replay["findings"]:
                findings.append(
                    {
                        "code": replay_finding["code"],
                        "detail": {
                            "finding_id": finding["finding_id"],
                            "receipt_id": receipt["receipt_id"],
                            **{
                                key: value for key, value in replay_finding.items() if key != "code"
                            },
                        },
                        "repairable": False,
                    }
                )
        for receipt in self.store.rows("SELECT * FROM governed_conflict_resolution_receipts"):
            operation = self.store.row(
                "SELECT operation_json,operation_hash,state FROM changeset_operations "
                "WHERE changeset_id=? AND ordinal=?",
                (receipt["changeset_id"], receipt["operation_ordinal"]),
            )
            changeset = self.store.row(
                "SELECT changeset_hash,state FROM changesets WHERE changeset_id=?",
                (receipt["changeset_id"],),
            )
            coherent = bool(operation and changeset)
            if operation and changeset:
                actual_operation_hash = hashlib.sha256(
                    canonical_json(json.loads(operation["operation_json"])).encode("utf-8")
                ).hexdigest()
                coherent = bool(
                    operation["state"] == "applied"
                    and changeset["state"] == "applied"
                    and operation["operation_hash"] == actual_operation_hash
                    and receipt["operation_hash"] == actual_operation_hash
                    and receipt["changeset_hash"] == changeset["changeset_hash"]
                )
                review_ids = json.loads(receipt["review_ids_json"])
                bound_reviews = self.store.rows(
                    "SELECT review_id,changeset_hash FROM changeset_review_decisions "
                    "WHERE changeset_id=? AND decision='pass'",
                    (receipt["changeset_id"],),
                )
                review_map = {row["review_id"]: row["changeset_hash"] for row in bound_reviews}
                if any(
                    review_map.get(review_id) != receipt["changeset_hash"]
                    for review_id in review_ids
                ):
                    findings.append(
                        {
                            "code": "conflict_review_hash_mismatch",
                            "detail": {"receipt_id": receipt["receipt_id"]},
                            "repairable": False,
                        }
                    )
            if not coherent:
                findings.append(
                    {
                        "code": "conflict_changeset_binding_mismatch",
                        "detail": {"receipt_id": receipt["receipt_id"]},
                        "repairable": False,
                    }
                )
        for conflict in self.store.rows(
            "SELECT integration_conflict_id,source_kind FROM integration_conflicts "
            "WHERE state='resolved' AND EXISTS (SELECT 1 FROM integration_conflict_resolutions r "
            "WHERE r.integration_conflict_id=integration_conflicts.integration_conflict_id "
            "AND r.reviewed_changeset_id IS NOT NULL)"
        ):
            if not self.store.row(
                "SELECT receipt_id FROM governed_conflict_resolution_receipts "
                "WHERE conflict_domain=? AND conflict_id=?",
                (conflict["source_kind"], conflict["integration_conflict_id"]),
            ):
                findings.append(
                    {
                        "code": "conflict_resolution_receipt_missing",
                        "detail": conflict,
                        "repairable": False,
                    }
                )
        json_columns = {
            "conclusion_revisions": ["structured_outputs_json", "limitations_json"],
            "record_revisions": ["data_json", "validation_result_json"],
            "field_bundles": ["manifest_json", "last_error_json"],
            "field_bundle_events": ["event_json", "result_json"],
            "report_builds": [
                "scope_json",
                "normalized_scope_json",
                "query_json",
                "report_model_json",
                "renderer_config_json",
            ],
            "issue_questions": ["expected_evidence_json", "template_snapshot_json"],
            "issue_question_events": ["payload_json"],
            "evidence_relation_events": ["before_json", "after_json"],
            "evidence_relation_impacts": ["details_json"],
            "issue_rollup_policies": ["policy_json"],
            "legacy_v14_candidates": ["candidate_json"],
        }
        for table, columns in json_columns.items():
            primary_key = self.store.rows(f"PRAGMA table_info({table})")[0]["name"]
            for column in columns:
                for item in self.store.rows(f"SELECT {primary_key},{column} FROM {table}"):
                    try:
                        value = json.loads(item[column])
                        errors = json_value_errors(value, path=f"$.{table}.{column}")
                    except (json.JSONDecodeError, TypeError) as exc:
                        errors = [
                            {
                                "path": f"$.{table}.{column}",
                                "code": "invalid_json",
                                "message": str(exc),
                            }
                        ]
                    if errors:
                        findings.append(
                            {
                                "code": "strict_json_violation",
                                "detail": {
                                    "table": table,
                                    "object_id": item[primary_key],
                                    "column": column,
                                    "errors": errors,
                                },
                                "repairable": False,
                            }
                        )
        for job in self.store.rows(
            "SELECT import_job_id FROM import_jobs WHERE state='partially_applied'"
        ):
            if not self.store.row(
                "SELECT 1 AS present FROM integration_conflicts WHERE source_kind='import' "
                "AND source_job_id=? AND state IN ('open','needs_more_information') LIMIT 1",
                (job["import_job_id"],),
            ):
                findings.append(
                    {
                        "code": "import_partial_without_conflict_path",
                        "detail": job,
                        "repairable": False,
                    }
                )

        missing_rollup = self.store.rows(
            "SELECT i.issue_id FROM issues i LEFT JOIN issue_rollup_policies p "
            "ON p.issue_id=i.issue_id WHERE p.issue_id IS NULL ORDER BY i.issue_id"
        )
        if missing_rollup:
            findings.append(
                {
                    "code": "v14_rollup_snapshot_missing",
                    "detail": missing_rollup,
                    "repairable": False,
                }
            )
        question_drifts = self.store.rows(
            "SELECT q.question_id,q.current_revision,MAX(r.revision_number) AS latest_revision "
            "FROM issue_questions q LEFT JOIN issue_question_revisions r "
            "ON r.question_id=q.question_id GROUP BY q.question_id,q.current_revision "
            "HAVING latest_revision IS NULL OR latest_revision<>q.current_revision"
        )
        if question_drifts:
            findings.append(
                {
                    "code": "question_revision_drift",
                    "detail": question_drifts,
                    "repairable": False,
                }
            )
        invalid_answers = self.store.rows(
            "SELECT q.question_id,q.issue_id,c.issue_id AS conclusion_issue_id "
            "FROM issue_questions q JOIN conclusion_revisions c "
            "ON c.conclusion_id=q.answer_conclusion_id "
            "WHERE q.status='answered' AND q.issue_id<>c.issue_id"
        )
        if invalid_answers:
            findings.append(
                {
                    "code": "question_answer_scope_invalid",
                    "detail": invalid_answers,
                    "repairable": False,
                }
            )
        hard_provider_gaps = self.store.rows(
            "SELECT r.relation_id,r.consumer_issue_id,r.provider_issue_id "
            "FROM relations r JOIN issues p ON p.issue_id=r.provider_issue_id "
            "WHERE r.active=1 AND r.impact_policy='hard' "
            "AND p.current_conclusion_id IS NULL ORDER BY r.relation_id"
        )
        if hard_provider_gaps:
            findings.append(
                {
                    "code": "hard_provider_missing_conclusion",
                    "detail": hard_provider_gaps,
                    "repairable": False,
                    # This is an operational publication blocker, not ledger
                    # corruption. Keep it visible without making backup/restore
                    # verification fail for a valid work-in-progress ledger.
                    "blocking": False,
                }
            )
        evidence_graph: dict[str, list[str]] = defaultdict(list)
        for relation in self.store.rows(
            "SELECT consumer_evidence_id,provider_evidence_id FROM evidence_relations "
            "WHERE active=1 AND impact_policy='hard'"
        ):
            evidence_graph[relation["consumer_evidence_id"]].append(
                relation["provider_evidence_id"]
            )
        for start in sorted(evidence_graph):
            queue: deque[tuple[str, list[str]]] = deque([(start, [start])])
            visited: set[str] = set()
            while queue:
                current, path = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                for provider in sorted(evidence_graph.get(current, [])):
                    if provider == start:
                        findings.append(
                            {
                                "code": "hard_evidence_relation_cycle",
                                "detail": {"path": [*path, provider]},
                                "repairable": False,
                            }
                        )
                        queue.clear()
                        break
                    if provider not in path:
                        queue.append((provider, [*path, provider]))
                if findings and findings[-1].get("code") == "hard_evidence_relation_cycle":
                    break
        from .project_component import installation

        portable_installation = installation(self.store)
        for adapter in self.adapters.list():
            if portable_installation:
                findings.append({'code': 'imported_adapter_unbound', 'adapter_name': adapter['adapter_name'],
                                 'repairable': False, 'blocking': False})
                continue
            full_adapter = self.store.row(
                "SELECT * FROM adapter_allowlist WHERE adapter_kind=? AND adapter_name=? "
                "AND adapter_version=? AND executable_hash=?",
                (
                    adapter["adapter_kind"],
                    adapter["adapter_name"],
                    adapter["adapter_version"],
                    adapter["executable_hash"],
                ),
            )
            verification = (
                self.adapters._verify_row(full_adapter)
                if full_adapter
                else {"ok": False, "adapter_name": adapter["adapter_name"]}
            )
            if adapter["enabled"] and not verification["ok"]:
                findings.append(
                    {
                        "code": "enabled_adapter_verification_failed",
                        "detail": verification,
                        "repairable": False,
                    }
                )

        findings.extend(self.store.verify_audit_chain())
        registry_health = self.registry.doctor()
        findings.extend({**finding, "repairable": False} for finding in registry_health["findings"])

        for assignment in self.store.rows(
            "SELECT assignment_id,proposal_id,reviewer_actor_id,lease_until "
            "FROM review_assignments WHERE state='assigned' AND lease_until IS NOT NULL "
            "AND lease_until<?",
            (now(),),
        ):
            findings.append(
                {
                    "code": "expired_review_lease",
                    "detail": assignment,
                    "repairable": False,
                }
            )
        before = {
            row["issue_id"]: row["freshness"]
            for row in self.store.rows("SELECT issue_id,freshness FROM issues")
        }
        expected, _, _ = self._derive_freshness()
        drifts = [
            {"issue_id": issue_id, "stored": before[issue_id], "expected": expected[issue_id]}
            for issue_id in expected
            if before[issue_id] != expected[issue_id]
        ]
        if drifts:
            findings.append(
                {"code": "freshness_drift", "detail": drifts, "repairable": True, "fixed": fix}
            )
            if fix:
                with self.store.transaction() as conn:
                    for issue_id, freshness in expected.items():
                        conn.execute(
                            "UPDATE issues SET freshness=?, updated_at=? WHERE issue_id=?",
                            (freshness, now(), issue_id),
                        )
                    self.store.audit(
                        conn,
                        actor=actor,
                        action="doctor.fix_freshness",
                        object_type="ledger",
                        object_id=str(self.store.ledger_dir),
                        before_revision=None,
                        after_revision=None,
                        reason="repair derived freshness cache",
                        payload={"drifts": drifts},
                    )
        unresolved = [
            item
            for item in findings
            if item.get("blocking", True) and not (fix and item.get("repairable"))
        ]
        return {
            "ok": not unresolved,
            "fixed": fix,
            "full_resolution_replay": full_resolution_replay,
            "resolution_replays": resolution_replays,
            "findings": findings,
        }

    def export(self) -> dict[str, Any]:
        from .projection import export_all

        return export_all(self)
