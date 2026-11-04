from __future__ import annotations

import pytest

from issue_manager import IssueManager, context_api
from issue_manager.errors import NotFoundError, ValidationError


def test_currentness_parser_is_strict():
    assert context_api.handles("POST", ["v1", "currentness", "prepare"])
    assert not context_api.handles("POST", ["v1", "issues"])
    assert context_api._decode("issue%2Da") == "issue-a"
    with pytest.raises(ValidationError):
        context_api._decode("bad%2")
    with pytest.raises(ValidationError):
        context_api._query("cursor=1&cursor=2")


def test_context_api_exposes_only_scoped_package_workflow(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    try:
        manager.create_issue("scope", "investigation", "Scope")
        evidence = manager.add_evidence(
            kind="external", locator="urn:context-api", issue_id="scope"
        )["evidence_id"]
        auth = manager.credentials.resolve(
            manager.credentials.path_for("organizer-agent"), "conclusion.propose"
        )
        package = context_api.dispatch(
            manager,
            "POST",
            ["v1", "currentness", "prepare"],
            {"issue_id": "scope", "evidence_ids": [evidence]},
            auth,
        )
        assert package["actual_input"]["summary"]["roots"] == [evidence]
        with pytest.raises(NotFoundError):
            context_api.dispatch(
                manager,
                "GET",
                ["v1", "currentness", "applicability", "decisions"],
                {},
                auth,
            )
    finally:
        manager.close()
