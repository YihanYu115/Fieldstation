from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .service import IssueManager


class IssueService:
    """Public Issue lifecycle boundary retained behind the compatibility facade."""

    def __init__(self, manager: IssueManager):
        self.manager = manager

    def create(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        return self.manager.create_issue(*args, **kwargs)

    def show(self, issue_id: str) -> dict[str, Any]:
        return self.manager.show_issue(issue_id)

    def archive(self, issue_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.manager.archive_issue(issue_id, **kwargs)

    def tree(self, root: str | None = None) -> dict[str, Any]:
        return self.manager.tree(root)

    def history(self, issue_id: str) -> dict[str, Any]:
        return self.manager.history(issue_id)


class IssueFacadeProtocol:
    """Marker used by contract tests to keep the legacy facade explicit."""
