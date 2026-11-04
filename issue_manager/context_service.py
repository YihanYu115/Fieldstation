from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .security import AuthContext

if TYPE_CHECKING:
    from .service import IssueManager


class ContextService:
    """Public Context and capability-aware Guidance read boundary."""

    def __init__(self, manager: IssueManager):
        self.manager = manager

    def get(self, issue_id: str, intent: str, **kwargs: Any) -> dict[str, Any]:
        return self.manager.context(issue_id, intent, **kwargs)

    def guidance(
        self,
        issue_id: str,
        *,
        auth: AuthContext | None = None,
        intent: str = "design-experiment",
    ) -> dict[str, Any]:
        return self.manager.guidance.get(issue_id, auth=auth, intent=intent)
