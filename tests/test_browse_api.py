from __future__ import annotations

import json

import pytest
from workflow_orchestrator.client import WorkflowAPIError, WorkflowClient

from issue_manager import IssueManager
from issue_manager.browse_service import BrowseService
from issue_manager.errors import ConflictError, PermissionError, ValidationError
from issue_manager.manager_api import ManagerService
from issue_manager.security import AuthContext


@pytest.fixture
def browsing(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    manager.create_issue("ROOT", "sample", "合成项目")
    manager.create_issue("CHILD", "qubit", "子问题", parent_issue_id="ROOT")
    manager.create_issue("LEAF", "investigation", "无结论材料", parent_issue_id="CHILD")
    manager.create_issue("OUTSIDE", "sample", "另一项目")
    auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"))
    evidence = [manager.add_evidence(kind="external", locator=f"urn:browse:{i}",
                                     description=f"中文完整观察 {i}", issue_id="LEAF")["evidence_id"]
                for i in range(4)]
    manager.add_evidence(kind="external", locator="urn:browse:0", issue_id="CHILD")
    yield manager, auth, evidence
    manager.close()


def test_browse_complete_registration_large_tree_and_read_only(browsing):
    manager, auth, refs = browsing
    for i in range(130):
        manager.create_issue(f"C{i:03}", "qubit", "分页子节点", parent_issue_id="ROOT")
    browse = BrowseService(manager)
    before = manager.store.conn.total_changes
    page = browse.read("children", "ROOT", auth=auth, limit=50)
    found = page["items"][:]
    while page["has_more"]:
        page = browse.read("children", "ROOT", auth=auth, limit=50,
                           cursor=page["next_cursor"])
        found += page["items"]
    assert len(found) == 131
    registered = browse.read("evidence", "LEAF", auth=auth)
    assert {item["evidence_id"] for item in registered["items"]} == set(refs)
    detail = browse.read("detail", refs[0], auth=auth)
    assert detail["evidence"]["issue_ids"] == ["CHILD", "LEAF"]
    assert browse.read("issue", "LEAF", auth=auth)["current_conclusion"] is None
    assert manager.store.conn.total_changes == before


def test_browse_pages_fail_on_collection_mutation_and_bad_cursor(browsing):
    manager, auth, refs = browsing
    browse = BrowseService(manager)
    page = browse.read("evidence", "LEAF", auth=auth, limit=1)
    other_actor = AuthContext(actor_id="other", actor_kind="service", run_id="other-run",
                              capabilities=frozenset({"context.read"}), lineage=frozenset(),
                              principal_kind="service")
    with pytest.raises(ConflictError):
        browse.read("evidence", "LEAF", auth=other_actor, cursor=page["next_cursor"])
    with pytest.raises(ConflictError):
        browse.read("evidence", "CHILD", auth=auth, cursor=page["next_cursor"])
    manager.add_evidence(kind="external", locator="urn:late", issue_id="LEAF")
    with pytest.raises(ConflictError, match="changed"):
        browse.read("evidence", "LEAF", auth=auth, cursor=page["next_cursor"])
    with pytest.raises(ValidationError):
        browse.read("evidence", "LEAF", auth=auth, cursor="!")
    assert browse.read("issue", "OUTSIDE", auth=auth)["issue"]["parent_issue_id"] is None
    platform = AuthContext(actor_id="platform", actor_kind="service", run_id="run",
                           capabilities=frozenset({"context.read"}), lineage=frozenset(),
                           principal_kind="service", platform_id="private")
    assert all(row["restricted"] for row in browse.read("evidence", "LEAF",
                                                       auth=platform)["items"])
    with pytest.raises(PermissionError):
        browse.read("detail", refs[0], auth=platform)


def test_browse_bidirectional_layered_relations_and_http(browsing):
    manager, auth, refs = browsing
    for source, target, kind in ((refs[0], refs[1], "depends_on"),
                                 (refs[2], refs[0], "refutes")):
        manager.scoped_evidence_relations.create(
            scope_issue_id="LEAF", source_evidence_id=source, target_evidence_id=target,
            relation_type=kind, rationale="必要关系", auth=auth,
            expected_source_token=manager.scoped_evidence_relations.binding(source, auth=auth)["token"],
            expected_target_token=manager.scoped_evidence_relations.binding(target, auth=auth)["token"],
            idempotency_key=kind)
    manager.scoped_evidence_relations.create(
        scope_issue_id="OUTSIDE", source_evidence_id=refs[3], target_evidence_id=refs[0],
        relation_type="depends_on", rationale="声明位置位于项目树外",
        auth=auth,
        expected_source_token=manager.scoped_evidence_relations.binding(refs[3], auth=auth)["token"],
        expected_target_token=manager.scoped_evidence_relations.binding(refs[0], auth=auth)["token"],
        idempotency_key="outside-declaration")
    token = json.loads(manager.credentials.path_for("organizer-agent").read_text(encoding="utf-8"))["token"]
    before = list(manager.store.conn.iterdump())
    service = ManagerService(manager.store.ledger_dir, port=0)
    endpoint = "http://%s:%s" % service.start()
    client = WorkflowClient(endpoint, token)
    try:
        assert client.browse_issue("LEAF")["issue"]["parent_issue_id"] == "CHILD"
        assert client.browse_issue("ROOT")["issue"]["parent_issue_id"] is None
        assert client.browse_issue("OUTSIDE")["issue"]["issue_id"] == "OUTSIDE"
        page = client.browse_neighbors(refs[0], limit=1)
        assert page["has_more"] and page["items"][0]["layer"] == "scoped-v2"
        following = client.browse_neighbors(refs[0], cursor=page["next_cursor"])
        all_relations = page["items"] + following["items"]
        assert {row["relation_type"] for row in all_relations} == {"depends_on", "refutes"}
        assert any(row["scope_issue_id"] == "OUTSIDE" for row in all_relations)
        assert all(row["binding_current"] for row in following["items"])
        assert client.browse_evidence_detail(refs[0])["evidence"]["short_description"].startswith("中文")
        with pytest.raises(WorkflowAPIError):
            WorkflowClient(endpoint, "invalid").browse_children("ROOT")
        with pytest.raises(WorkflowAPIError):
            client.browse_children("ROOT", actor="forged")
        assert list(manager.store.conn.iterdump()) == before
    finally:
        service.close()
