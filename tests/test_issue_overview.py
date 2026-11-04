from __future__ import annotations

import hashlib
import json

import pytest
from workflow_orchestrator.client import WorkflowAPIError, WorkflowClient

from issue_manager import IssueManager
from issue_manager.errors import ConflictError, NotFoundError, PermissionError, ValidationError
from issue_manager.issue_overview_api import dispatch
from issue_manager.manager_api import ManagerService
from issue_manager.security import AuthContext


def _read_auth(manager):
    return manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "context.read")


def _publish_empty_conclusion(manager, issue_id):
    issue = manager.show_issue(issue_id)
    package = manager.context_maintenance.prepare(issue_id, basis=[])
    proposal = {
        "issue_id": issue_id, "expected_conclusion_revision": issue["conclusion_revision"],
        "status": "provisional", "statement": "Current conclusion", "structured_outputs": {},
        "confidence": "medium", "applicability": "pilot", "limitations": [],
        "change_summary": "Current conclusion", "basis": [],
        "basis_snapshot_token": manager.proposals.make_snapshot_token(
            issue_id, issue["conclusion_revision"], [], context_package_id=package["package_id"]
        ),
    }
    created = manager.proposals.create(proposal, credential=manager.credentials.path_for("organizer-agent"))
    manager.proposals.validate(created["proposal_id"], credential=manager.credentials.path_for("organizer-agent"))
    return manager.proposals.apply(created["proposal_id"], credential=manager.credentials.path_for("organizer-agent"))


def test_issue_overview_is_complete_stable_hashed_and_http_client_validates(tmp_path):
    ledger = tmp_path / "ledger"
    manager = IssueManager.initialize(ledger)
    manager.create_issue("ROOT", "sample", "Root")
    manager.create_issue("CHILD", "qubit", "Child", parent_issue_id="ROOT")
    manager.create_issue("LEAF", "capability", "Leaf", parent_issue_id="CHILD")
    child = manager.show_issue("CHILD")
    package = manager.context_maintenance.prepare("CHILD", basis=[])
    proposal = {
        "issue_id": "CHILD", "expected_conclusion_revision": child["conclusion_revision"],
        "status": "provisional", "statement": "Child conclusion", "structured_outputs": {},
        "confidence": "medium", "applicability": "pilot", "limitations": [],
        "change_summary": "Child conclusion", "basis": [],
        "basis_snapshot_token": manager.proposals.make_snapshot_token(
            "CHILD", child["conclusion_revision"], [], context_package_id=package["package_id"]
        ),
    }
    created = manager.proposals.create(proposal, credential=manager.credentials.path_for("organizer-agent"))
    manager.proposals.validate(created["proposal_id"], credential=manager.credentials.path_for("organizer-agent"))
    manager.proposals.apply(created["proposal_id"], credential=manager.credentials.path_for("organizer-agent"))
    auth = _read_auth(manager)
    one = manager.issue_overview("ROOT", auth=auth)
    two = manager.issue_overview("ROOT", auth=auth)
    assert one == two
    assert [item["issue_id"] for item in one["nodes"]] == ["CHILD", "LEAF", "ROOT"]
    assert one["nodes"][0]["parent_issue_id"] == "ROOT"
    assert one["nodes"][1]["parent_issue_id"] == "CHILD"
    leaf_node = next(item for item in one["nodes"] if item["issue_id"] == "LEAF")
    assert leaf_node["current_conclusion_id"] is None
    assert leaf_node["currentness"] is None
    assert leaf_node["gap_count"] is None
    child_node = next(item for item in one["nodes"] if item["issue_id"] == "CHILD")
    single = manager.inspect_issue("CHILD", auth=auth)
    assert child_node["current_conclusion_id"] == single["issue"]["current_conclusion_id"]
    assert child_node["currentness"] == single["current_conclusion"]["currentness"]["currentness"]
    assert child_node["gap_count"] == len(single["scoped_context"]["gap"])
    hash_input = dict(one)
    hash_snapshot = dict(hash_input["snapshot"])
    digest = hash_snapshot.pop("content_sha256")
    hash_input["snapshot"] = hash_snapshot
    canonical = json.dumps(hash_input, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(canonical.encode("utf-8")).hexdigest() == digest
    assert one["complete"] is True
    credential_path = manager.credentials.path_for("organizer-agent")
    credential = json.loads(credential_path.read_text(encoding="utf-8"))["token"]
    manager.close()

    service = ManagerService(ledger, port=0)
    base_url = "http://%s:%s" % service.start()
    client = WorkflowClient(base_url, credential)
    try:
        assert client.get_issue_overview("ROOT") == one
    finally:
        service.close()


def test_issue_overview_projection_shares_one_read_snapshot_with_concurrent_writer(tmp_path, monkeypatch):
    ledger = tmp_path / "ledger"
    manager = IssueManager.initialize(ledger)
    writer = None
    try:
        manager.create_issue("ROOT", "sample", "Root")
        manager.create_issue("CHILD", "qubit", "Child", parent_issue_id="ROOT")
        published = _publish_empty_conclusion(manager, "CHILD")
        conclusion_id = published["conclusion_id"]
        writer = IssueManager(ledger)
        observed = []
        original = manager.context_maintenance.current_scoped_projection

        def update_during_projection(issue_id, *, auth=None):
            assert manager.store.conn.in_transaction
            with writer.store.transaction() as conn:
                conn.execute("UPDATE issues SET current_conclusion_id=NULL WHERE issue_id='CHILD'")
            result = original(issue_id, auth=auth)
            observed.append(result["conclusion_id"])
            return result

        monkeypatch.setattr(manager.context_maintenance, "current_scoped_projection", update_during_projection)
        overview = manager.issue_overview("ROOT", auth=_read_auth(manager))
        child = next(item for item in overview["nodes"] if item["issue_id"] == "CHILD")
        assert child["current_conclusion_id"] == conclusion_id
        assert observed == [conclusion_id]
        assert writer.show_issue("CHILD")["current_conclusion_id"] is None
    finally:
        if writer is not None:
            writer.close()
        manager.close()


def test_issue_overview_rejects_bad_root_and_platform_scope(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    try:
        manager.create_issue("ROOT", "sample", "Root")
        auth = _read_auth(manager)
        with pytest.raises(NotFoundError):
            manager.issue_overview("missing", auth=auth)
        for query in ("", "root=", "root=ROOT&root=ROOT", "root=ROOT&extra=1", "root=bad%2"):
            with pytest.raises(ValidationError):
                dispatch(manager, query, auth)
        platform = AuthContext(
            actor_id="platform", actor_kind="service", run_id="run",
            capabilities=frozenset({"context.read"}), lineage=frozenset(),
            principal_kind="service", platform_id="source-a",
        )
        with pytest.raises(PermissionError):
            manager.issue_overview("ROOT", auth=platform)
    finally:
        manager.close()


def test_issue_overview_over_limit_rejects_whole_projection(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    try:
        manager.create_issue("ROOT", "sample", "Root")
        for index in range(128):
            manager.create_issue(f"C{index:03d}", "qubit", "Child", parent_issue_id="ROOT")
        with pytest.raises(ConflictError) as caught:
            manager.issue_overview("ROOT", auth=_read_auth(manager))
        assert caught.value.code == "overview_too_large"
        assert caught.value.details["code"] == "overview_too_large"
    finally:
        manager.close()


def test_issue_overview_rejects_byte_limit_without_partial_result(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    try:
        manager.create_issue("ROOT", "sample", "X" * (256 * 1024))
        with pytest.raises(ConflictError) as caught:
            manager.issue_overview("ROOT", auth=_read_auth(manager))
        assert caught.value.code == "overview_too_large"
        assert caught.value.details["code"] == "overview_too_large"
        assert caught.value.details["max_bytes"] == 256 * 1024
    finally:
        manager.close()


def test_client_rejects_incomplete_or_corrupt_overview(monkeypatch):
    client = WorkflowClient("http://example.invalid", "token")
    monkeypatch.setattr(client, "_request", lambda *args, **kwargs: {
        "protocol_version": 1, "complete": False, "nodes": [],
        "snapshot": {"content_sha256": "0" * 64},
    })
    with pytest.raises(WorkflowAPIError, match="incomplete"):
        client.get_issue_overview("ROOT")
    monkeypatch.setattr(client, "_request", lambda *args, **kwargs: {
        "protocol_version": 1, "complete": True, "nodes": [],
        "snapshot": {"context_revision": 0, "content_sha256": "0" * 64},
    })
    with pytest.raises(WorkflowAPIError, match="hash does not match"):
        client.get_issue_overview("ROOT")
