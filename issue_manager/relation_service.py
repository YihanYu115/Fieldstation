from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .service import IssueManager


class RelationService:
    """Public Issue-relation graph boundary."""

    def __init__(self, manager: IssueManager):
        self.manager = manager

    def add(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.manager.add_relation(*args, **kwargs)

    def deactivate(self, relation_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.manager.deactivate_relation(relation_id, **kwargs)

    def reactivate(self, relation_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.manager.reactivate_relation(relation_id, **kwargs)

    def set_impact(self, relation_id: str, impact: str, **kwargs: Any) -> dict[str, Any]:
        return self.manager.set_relation_impact(relation_id, impact, **kwargs)

    def trace(self, issue_id: str) -> dict[str, Any]:
        return self.manager.dependency_trace(issue_id)

    def impact(self, provider_issue_id: str) -> dict[str, Any]:
        return self.manager.impact(provider_issue_id)
