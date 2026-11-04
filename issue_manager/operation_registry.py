from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable

from .errors import NotFoundError, ValidationError
from .security import AuthContext


@dataclass(frozen=True)
class OperationSpec:
    operation_id: str
    method: str
    path_template: str
    write: bool
    required_capability: str
    request_schema_version: str
    response_schema_version: str
    idempotency_required: bool
    risk_classifier: str
    handler: str
    visibility_policy: str
    required_fields: tuple[str, ...] = ()
    optional_fields: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["read_write"] = "write" if self.write else "read"
        value["required_fields"] = list(self.required_fields)
        value["optional_fields"] = list(self.optional_fields)
        return value


class OperationRegistry:
    """Single metadata contract shared by HTTP, CLI, SDK, and Guidance."""

    def __init__(self) -> None:
        self._specs: dict[str, OperationSpec] = {}

    def register(self, spec: OperationSpec) -> None:
        if spec.operation_id in self._specs:
            raise ValidationError(f"Duplicate operation_id: {spec.operation_id}")
        if spec.method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValidationError(f"Unsupported Operation HTTP method: {spec.method}")
        if spec.write != (spec.method != "GET"):
            raise ValidationError(
                f"Operation {spec.operation_id} read/write classification disagrees with HTTP method"
            )
        if spec.write and not spec.idempotency_required:
            raise ValidationError(
                f"Write operation {spec.operation_id} must require idempotency"
            )
        self._specs[spec.operation_id] = spec

    def get(self, operation_id: str) -> OperationSpec:
        try:
            return self._specs[operation_id]
        except KeyError as exc:
            raise NotFoundError(f"Operation not registered: {operation_id}") from exc

    def list(self) -> list[dict[str, Any]]:
        return [self._specs[key].as_dict() for key in sorted(self._specs)]

    def guide(
        self,
        operation_id: str,
        *,
        auth: AuthContext | None = None,
    ) -> dict[str, Any]:
        spec = self.get(operation_id)
        available = auth is None or spec.required_capability in auth.capabilities
        supplement: dict[str, Any] = {}
        return {
            "operation_guide_version": "operation-guide/v1",
            **spec.as_dict(),
            "available": available,
            "blocked_by": []
            if available
            else [{"code": "missing_capability", "capability": spec.required_capability}],
            **supplement,
        }

    def dispatch(
        self,
        operation_id: str,
        resolver: Callable[[str], Callable[..., Any]],
        arguments: dict[str, Any],
        *,
        auth: AuthContext,
    ) -> Any:
        spec = self.get(operation_id)
        auth.require(spec.required_capability)
        missing = [field for field in spec.required_fields if field not in arguments]
        if missing:
            raise ValidationError(
                f"Operation {operation_id} is missing required fields: {missing}",
                details={"missing_fields": missing},
            )
        handler = resolver(spec.handler)
        return handler(**arguments)


def build_operation_registry() -> OperationRegistry:
    registry = OperationRegistry()

    def add(
        operation_id: str,
        method: str,
        path: str,
        capability: str,
        request_version: str,
        response_version: str,
        handler: str,
        required: tuple[str, ...] = (),
        optional: tuple[str, ...] = (),
        risk: str = "risk-policy/v1",
        visibility: str = "issue-visibility/v1",
    ) -> None:
        registry.register(
            OperationSpec(
                operation_id=operation_id,
                method=method,
                path_template=path,
                write=method != "GET",
                required_capability=capability,
                request_schema_version=request_version,
                response_schema_version=response_version,
                idempotency_required=method != "GET",
                risk_classifier=risk,
                handler=handler,
                visibility_policy=visibility,
                required_fields=required,
                optional_fields=optional,
            )
        )

    for operation, method, path, capability, handler, required in [
        ("issue.create/v1", "POST", "/v1/issues", "issue.write", "create_issue", ("issue_id", "issue_type", "title")),
        ("intake.submit/v2", "POST", "/v1/intake", "intake.submit", "intake.submit", ("packet",)),
        ("intake.list/v1", "GET", "/v1/intake", "context.read", "desktop_queries.dispatch", ()),
        ("intake.show/v1", "GET", "/v1/intake/{packet_id}", "context.read", "intake.show", ("packet_id",)),
        ("evidence.list/v1", "GET", "/v1/evidence", "context.read", "desktop_queries.dispatch", ()),
        ("project.editor/v1", "GET", "/v1/project/editor", "context.read", "desktop_queries.dispatch", ()),
    ]:
        optional: tuple[str, ...] = ()
        if operation == "issue.create/v1":
            optional = ("parent_issue_id", "scope", "reason", "issue_type_registration_id")
        elif operation in {"intake.list/v1", "evidence.list/v1"}:
            optional = ("limit", "offset", "q")
        name, version = operation.rsplit("/", 1)
        add(
            operation, method, path, capability, f"{name}-request/{version}",
            f"{name}-response/{version}", handler, required, optional,
            risk="T1" if method == "POST" else "T0", visibility="unscoped-project-principal/v1",
        )

    add(
        "context.get/v2",
        "GET",
        "/v1/context",
        "context.read",
        "context-request/v2",
        "context/v3",
        "context",
        ("issue_id", "intent"),
    )
    add(
        "issue.show/v1",
        "GET",
        "/v1/issues/{issue_id}",
        "context.read",
        "issue-show-request/v1",
        "issue/v1",
        "show_issue",
        ("issue_id",),
    )
    add(
        "issue.guidance/v1",
        "GET",
        "/v1/issues/{issue_id}/guidance",
        "context.read",
        "issue-guidance-request/v1",
        "issue-guidance/v1",
        "guidance.get",
        ("issue_id",),
        ("intent",),
        risk="T0",
    )
    add(
        "question.list/v1",
        "GET",
        "/v1/issues/{issue_id}/questions",
        "context.read",
        "question-list-request/v1",
        "issue-question-list/v1",
        "questions.list",
        ("issue_id",),
        ("statuses", "question_kind", "minimum_priority"),
        risk="T0",
    )
    add(
        "question.show/v1",
        "GET",
        "/v1/questions/{question_id}",
        "context.read",
        "question-show-request/v1",
        "issue-question/v1",
        "questions.show",
        ("question_id",),
        risk="T0",
    )
    add(
        "question.create/v1",
        "POST",
        "/v1/issues/{issue_id}/questions",
        "question.write",
        "issue-question-create/v1",
        "issue-question/v1",
        "questions.create",
        ("issue_id", "prompt"),
        (
            "question_key",
            "motivation",
            "question_kind",
            "priority",
            "expected_evidence",
            "reason",
        ),
        risk="question-risk/v1",
    )
    for action in ("start", "block", "defer", "cancel", "reopen"):
        add(
            f"question.{action}/v1",
            "POST",
            f"/v1/questions/{{question_id}}/{action}",
            "question.write",
            f"issue-question-{action}/v1",
            "issue-question/v1",
            f"questions.{action}",
            ("question_id",),
            ("reason",),
            risk="question-risk/v1",
        )
    add(
        "question.answer/v1",
        "POST",
        "/v1/questions/{question_id}/answer",
        "question.answer",
        "issue-question-answer/v1",
        "issue-question/v1",
        "questions.answer",
        ("question_id", "conclusion_id"),
        ("reason",),
        risk="question-answer-risk/v1",
    )
    add(
        "question.attach_evidence/v1",
        "POST",
        "/v1/questions/{question_id}/evidence",
        "question.write",
        "issue-question-evidence-link/v1",
        "issue-question-evidence-link/v1",
        "questions.attach_evidence",
        ("question_id", "evidence_id"),
        ("link_type", "rationale"),
        risk="question-risk/v1",
    )
    add(
        "evidence.relation.list/v1",
        "GET",
        "/v1/evidence-relations",
        "context.read",
        "evidence-relation-list-request/v1",
        "evidence-relation-list/v1",
        "evidence_relations.list",
        (),
        (
            "evidence_id",
            "provider_evidence_id",
            "consumer_evidence_id",
            "active_only",
        ),
        risk="T0",
    )
    add(
        "evidence.relation.add/v1",
        "POST",
        "/v1/evidence-relations",
        "evidence.relation.write",
        "evidence-relation-create/v1",
        "evidence-relation/v1",
        "evidence_relations.add",
        ("consumer_evidence_id", "provider_evidence_id", "relation_type"),
        ("impact_policy", "rationale"),
        risk="evidence-relation-risk/v1",
    )
    for action in ("deactivate", "reactivate"):
        add(
            f"evidence.relation.{action}/v1",
            "POST",
            f"/v1/evidence-relations/{{relation_id}}/{action}",
            "evidence.relation.write",
            f"evidence-relation-{action}/v1",
            "evidence-relation/v1",
            f"evidence_relations.{action}",
            ("relation_id", "reason"),
            risk="evidence-relation-risk/v1",
        )
    add(
        "evidence.relation.impact/v1",
        "GET",
        "/v1/evidence-relations/impacts",
        "context.read",
        "evidence-relation-impact-request/v1",
        "evidence-relation-impact-list/v1",
        "evidence_relations.impacts",
        (),
        ("evidence_id", "relation_id", "limit"),
        risk="T0",
    )
    add(
        "conclusion.rollup_preview/v1",
        "GET",
        "/v1/issues/{issue_id}/conclusion/rollup-preview",
        "context.read",
        "conclusion-rollup-preview-request/v1",
        "conclusion-rollup-preview/v1",
        "rollup.preview",
        ("issue_id",),
        risk="T0",
    )
    add(
        "evidence.submit/v2",
        "POST",
        "/v1/evidence",
        "evidence.write",
        "evidence-submit/v2",
        "evidence-receipt/v2",
        "add_evidence",
        ("kind", "locator"),
        (
            "issue_id",
            "target_scope",
            "description",
            "quality_status",
            "content_hash",
            "addresses_question_ids",
            "related_evidence",
        ),
        risk="evidence-submit-risk/v2",
    )
    for operation, method, path, handler, capability, required, optional in (
        ("currentness.obligation/v1", "GET", "/v1/currentness/obligations/{obligation_id}", "context_obligations.show",
         "context.read", ("obligation_id",), ()),
        ("currentness.contracts/v1", "GET", "/v1/currentness/contracts", "relation_contracts.snapshot", "context.read", (), ()),
        ("currentness.rules/v1", "GET", "/v1/currentness/rules", "context_rules.describe", "context.read", (), ()),
        ("currentness.prepare/v1", "POST", "/v1/currentness/prepare", "context_maintenance.prepare",
         "conclusion.propose", ("issue_id",), ("basis", "evidence_ids", "descriptor")),
        ("currentness.show/v1", "GET", "/v1/currentness/conclusions/{conclusion_id}", "context_maintenance.why",
         "context.read", ("conclusion_id",), ()),
        ("currentness.package/v1", "GET", "/v1/currentness/packages/{package_id}", "context_maintenance.package",
         "conclusion.propose", ("package_id",), ()),
        ("currentness.audit/v1", "GET", "/v1/currentness/audit", "context_maintenance.audit",
         "maintenance", (), ()),
    ):
        add(operation, method, path, capability, "currentness-request/v1", "currentness-response/v1",
            handler, required, optional, risk="T1" if method == "POST" else "T0",
            visibility="unscoped-ledger-principal/v1")
    for operation, path, handler, required, optional in (
        ("applicability.decision.list/v1", "/v1/currentness/applicability/decisions",
         "evidence_applicability.list", (), ("issue_id", "evidence_id", "active")),
        ("applicability.decision.show/v1", "/v1/currentness/applicability/decisions/{decision_key}",
         "evidence_applicability.show", ("decision_key",), ()),
        ("applicability.projection/v1", "/v1/currentness/applicability/scopes/{issue_id}/projection",
         "evidence_applicability.scope_projection", ("issue_id",), ()),
        ("applicability.why/v1", "/v1/currentness/applicability/scopes/{issue_id}/evidence/{evidence_id}/why",
         "evidence_applicability.scope_why", ("issue_id", "evidence_id"), ("expand_basis",)),
    ):
        add(
            operation, "GET", path, "context.read", "applicability-query/v1",
            "applicability-query-result/v1", handler, required, optional,
            risk="T0", visibility="unscoped-ledger-principal/v1",
        )
    return registry
