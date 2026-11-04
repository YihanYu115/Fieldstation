from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .service import IssueManager


class FreshnessService:
    """Public derived-freshness and refresh-task boundary."""

    def __init__(self, manager: IssueManager):
        self.manager = manager

    def recompute(self) -> dict[str, Any]:
        return self.manager.recompute_freshness()

    def stale(self) -> list[dict[str, Any]]:
        return self.manager.stale()

    def why_stale(self, issue_id: str) -> dict[str, Any]:
        return self.manager.why_stale(issue_id)

    def plan(self, root: str | None = None) -> dict[str, Any]:
        return self.manager.refresh_plan(root)

    def prepare(self, issue_id: str) -> dict[str, Any]:
        return self.manager.prepare_refresh(issue_id)
