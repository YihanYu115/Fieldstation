from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .service import IssueManager


class ConclusionService:
    """Public Conclusion validation, publication, and status boundary."""

    def __init__(self, manager: IssueManager):
        self.manager = manager

    def current(self, issue_id: str) -> dict[str, Any] | None:
        return self.manager.get_current_conclusion(issue_id)

    def validate(self, proposal: dict[str, Any], *, refresh: bool = True) -> dict[str, Any]:
        return self.manager.validate_proposal(proposal, refresh=refresh)

    def publish(self, proposal: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        return self.manager.publish_conclusion(proposal, **kwargs)

    def change_status(self, conclusion_id: str, status: str, **kwargs: Any) -> dict[str, Any]:
        return self.manager.change_conclusion_status(conclusion_id, status, **kwargs)

    def rollup_preview(self, issue_id: str) -> dict[str, Any]:
        return self.manager.rollup.preview(issue_id)
