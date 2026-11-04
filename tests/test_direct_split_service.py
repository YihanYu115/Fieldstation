from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from issue_manager import IssueManager
from issue_manager.errors import ConflictError, IdempotencyConflictError, PermissionError


@pytest.fixture
def setup_split(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    manager.create_issue("scope", "investigation", "Scope")
    auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"))
    source = manager.add_evidence(kind="external", locator="urn:split:source", issue_id="scope")["evidence_id"]
    correction = manager.add_evidence(kind="external", locator="urn:split:correction", issue_id="scope")["evidence_id"]
    service = manager.scoped_evidence_relations
    relation = service.create(
        scope_issue_id="scope", source_evidence_id=correction, target_evidence_id=source,
        relation_type="refutes", rationale="count", auth=auth,
        expected_source_token=service.binding(correction, auth=auth)["token"],
        expected_target_token=service.binding(source, auth=auth)["token"], idempotency_key="correction",
    )
    request = {"source_evidence_id": source,
               "expected_snapshot": manager.direct_splits.boundary(source, auth=auth)["snapshot"],
               "parts": [{"issue_id": "scope", "kind": "observation", "text": "count"},
                         {"issue_id": "scope", "kind": "interpretation", "text": "method and result"}],
               "relation_decisions": [{"relation_id": relation["relation_id"], "action": "replace",
                                       "part_index": 0, "reason": "correction concerns count"}],
               "new_relations": []}
    yield manager, auth, request, relation
    manager.close()


def test_direct_split_replaces_only_chosen_relation_and_replays(setup_split):
    manager, auth, request, relation = setup_split
    result = manager.direct_splits.split(request, auth=auth, idempotency_key="split")
    assert len(result["parts"]) == 2
    assert not manager.scoped_evidence_relations.show(relation["relation_id"], auth=auth)["active"]
    replacement = result["relations_created"][0]
    assert replacement["source_evidence_id"] == relation["source_evidence_id"]
    assert replacement["target_evidence_id"] == result["parts"][0]["evidence_id"]
    assert manager.store.row("SELECT COUNT(*) AS n FROM direct_split_origins")["n"] == 2
    for part in result["parts"]:
        child = manager.evidence.show(part["evidence_id"], auth=auth)
        assert child["quality_status"] == "unknown"
        assert child["current_proof"]["verification_level"] == "declared"
        assert child["source_binding"]["binding_state"] == "legacy_unbound"
        assert child["current_manifest_id"] is None
    assert manager.direct_splits.split(request, auth=auth, idempotency_key="split")["split_id"] == result["split_id"]
    with pytest.raises(IdempotencyConflictError):
        manager.direct_splits.split({**request, "new_relations": [{"different": True}]}, auth=auth, idempotency_key="split")
    from issue_manager.direct_split_api import dispatch
    child_id = result["parts"][0]["evidence_id"]
    origin = dispatch(manager, "GET", ["v1", "direct-evidence-splits", "origins", child_id],
                      {}, "", auth, idempotency_key=None)["items"][0]
    assert origin["source_binding_current"] is True
    assert origin["source_binding"]["evidence_id"] == request["source_evidence_id"]
    with manager.store.transaction() as conn:
        conn.execute("UPDATE evidence_refs SET content_hash='later-version' WHERE evidence_id=?",
                     (request["source_evidence_id"],))
    after = dispatch(manager, "GET", ["v1", "direct-evidence-splits", "origins", child_id],
                     {}, "", auth, idempotency_key=None)["items"][0]
    assert after["source_binding_current"] is False
    assert after["source_binding_token"] == origin["source_binding_token"]
    assert after["source_binding"] == origin["source_binding"]


@pytest.mark.parametrize("fault", ["direct_split.after_child", "direct_split.after_origin",
                                   "direct_split.after_relation", "direct_split.after_currentness",
                                   "direct_split.after_receipt"])
def test_direct_split_failure_rolls_back_all_writes(setup_split, fault):
    manager, auth, request, relation = setup_split
    original = manager.store.fault
    def fail(point):
        if point == fault:
            raise RuntimeError(point)
        original(point)
    manager.store.fault = fail
    with pytest.raises(RuntimeError, match=fault):
        manager.direct_splits.split(request, auth=auth, idempotency_key="split")
    manager.store.fault = original
    assert manager.store.row("SELECT COUNT(*) AS n FROM direct_split_origins")["n"] == 0
    assert manager.store.row("SELECT COUNT(*) AS n FROM evidence_refs")["n"] == 2
    assert manager.scoped_evidence_relations.show(relation["relation_id"], auth=auth)["active"]
    assert len(manager.direct_splits.split(request, auth=auth, idempotency_key="split")["parts"]) == 2


def test_new_boundary_relation_rejects_stale_split(setup_split):
    manager, auth, request, _ = setup_split
    extra = manager.add_evidence(kind="external", locator="urn:split:extra")["evidence_id"]
    service = manager.scoped_evidence_relations
    service.create(scope_issue_id="scope", source_evidence_id=extra,
                   target_evidence_id=request["source_evidence_id"], relation_type="supports",
                   rationale="new", auth=auth, expected_source_token=service.binding(extra, auth=auth)["token"],
                   expected_target_token=service.binding(request["source_evidence_id"], auth=auth)["token"],
                   idempotency_key="new")
    with pytest.raises(ConflictError, match="boundary changed"):
        manager.direct_splits.split(request, auth=auth, idempotency_key="split")
    assert manager.store.row("SELECT COUNT(*) AS n FROM direct_split_origins")["n"] == 0


def test_browse_only_suppresses_split_boundary_limit(setup_split, monkeypatch):
    from issue_manager import direct_split_boundary
    from issue_manager.browse_api import dispatch

    manager, auth, request, _ = setup_split
    source = request['source_evidence_id']
    def unavailable(*args, **kwargs):
        raise ConflictError('Different conflict', details={'code': 'another_conflict'})
    monkeypatch.setattr(direct_split_boundary, 'snapshot', unavailable)
    result = dispatch(manager, ['v1', 'browse', 'detail'], 'id=' + source, auth)
    assert result['evidence']['evidence_id'] == source
    with pytest.raises(ConflictError, match='Different conflict'):
        dispatch(manager, ['v1', 'browse', 'detail'], 'id=' + source + '&split_observation=1', auth)


def test_relevant_indirect_dependency_change_rejects_stale_split(setup_split):
    manager, auth, request, _ = setup_split
    middle = manager.add_evidence(kind="external", locator="urn:split:middle")["evidence_id"]
    end = manager.add_evidence(kind="external", locator="urn:split:end")["evidence_id"]
    service = manager.scoped_evidence_relations
    for start, target, key in ((request["source_evidence_id"], middle, "first-dependency"),
                               (middle, end, "second-dependency")):
        service.create(scope_issue_id="scope", source_evidence_id=start, target_evidence_id=target,
            relation_type="depends_on", rationale="Required", auth=auth,
            expected_source_token=service.binding(start, auth=auth)["token"],
            expected_target_token=service.binding(target, auth=auth)["token"], idempotency_key=key)
        if key == "first-dependency":
            request["expected_snapshot"] = manager.direct_splits.boundary(request["source_evidence_id"], auth=auth)["snapshot"]
    with pytest.raises(ConflictError, match="boundary changed"):
        manager.direct_splits.split(request, auth=auth, idempotency_key="indirect-stale")


def test_extra_endpoint_relation_competition_rejects_stale_split(setup_split):
    manager, auth, request, _ = setup_split
    external = manager.add_evidence(kind="external", locator="urn:split:external")["evidence_id"]
    other = manager.add_evidence(kind="external", locator="urn:split:external-other")["evidence_id"]
    external_snapshot = manager.direct_splits.boundary(external, auth=auth)["snapshot"]
    service = manager.scoped_evidence_relations
    service.create(scope_issue_id="scope", source_evidence_id=external, target_evidence_id=other,
        relation_type="depends_on", rationale="Concurrent external relation", auth=auth,
        expected_source_token=service.binding(external, auth=auth)["token"],
        expected_target_token=service.binding(other, auth=auth)["token"], idempotency_key="external-new")
    request["extra_snapshots"] = {external: external_snapshot}
    request["new_relations"] = [{"issue_id": "scope", "source": {"part_index": 1},
        "target": {"evidence_id": external}, "relation_type": "depends_on", "rationale": "External input"}]
    with pytest.raises(ConflictError, match="selected Evidence boundary changed"):
        manager.direct_splits.split(request, auth=auth, idempotency_key="external-stale")
    assert manager.store.row("SELECT COUNT(*) AS n FROM direct_split_origins")["n"] == 0


@pytest.mark.parametrize("change", ["source", "relation"])
def test_changed_source_or_relation_rejects_stale_split(setup_split, change):
    manager, auth, request, relation = setup_split
    if change == "source":
        with manager.store.transaction() as conn:
            conn.execute("UPDATE evidence_refs SET content_hash='changed' WHERE evidence_id=?",
                         (request["source_evidence_id"],))
    else:
        manager.scoped_evidence_relations.revise(relation["relation_id"],
            expected_version_id=relation["version_id"], rationale="Changed relation",
            auth=auth, idempotency_key="revise-before-split")
    with pytest.raises(ConflictError, match="boundary changed"):
        manager.direct_splits.split(request, auth=auth, idempotency_key="stale-split")
    assert manager.store.row("SELECT COUNT(*) AS n FROM direct_split_origins")["n"] == 0


def test_authorization_rejections_leave_no_children(setup_split):
    manager, auth, request, _ = setup_split
    for capabilities in ({"context.read"}, {"context.read", "evidence.write"}):
        with pytest.raises(PermissionError):
            manager.direct_splits.split(request, auth=replace(auth, capabilities=frozenset(capabilities)),
                                        idempotency_key="unauthorized")
    assert manager.store.row("SELECT COUNT(*) AS n FROM direct_split_origins")["n"] == 0


def test_independent_and_concurrent_original_actions(setup_split):
    manager, auth, request, _ = setup_split
    ledger = manager.store.ledger_dir
    def split_once():
        instance = IssueManager(ledger)
        try:
            principal = instance.credentials.resolve(instance.credentials.path_for("organizer-agent"))
            return instance.direct_splits.split(request, auth=principal, idempotency_key="concurrent")
        finally:
            instance.close()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: split_once(), range(2)))
    assert results[0]["split_id"] == results[1]["split_id"]
    assert manager.store.row("SELECT COUNT(*) AS n FROM direct_split_origins")["n"] == 2
    fresh = {**request, "expected_snapshot": manager.direct_splits.boundary(
        request["source_evidence_id"], auth=auth)["snapshot"], "relation_decisions": []}
    first = manager.direct_splits.split(fresh, auth=auth, idempotency_key="new-1")
    second = manager.direct_splits.split(fresh, auth=auth, idempotency_key="new-2")
    assert first["split_id"] != second["split_id"]


def test_actual_depends_on_differs_from_derived_from(setup_split):
    manager, auth, request, _ = setup_split
    request["parts"].append({"issue_id": "scope", "kind": "interpretation", "text": "derived only"})
    request["new_relations"] = [
        {"issue_id": "scope", "source": {"part_index": 1}, "target": {"part_index": 0},
         "relation_type": "depends_on", "rationale": "The result needs the count"},
        {"issue_id": "scope", "source": {"part_index": 2}, "target": {"part_index": 0},
         "relation_type": "derived_from", "rationale": "The source is the count"},
    ]
    result = manager.direct_splits.split(request, auth=auth, idempotency_key="qualification")
    preview = manager.scoped_evidence_relations.preview_selection(
        scope_issue_id="scope", seed_evidence_ids=[part["evidence_id"] for part in result["parts"]],
        maximum_nodes=30, maximum_relations=30, auth=auth)
    status = {item["candidate_id"]: item["status"] for item in preview["selection"]["candidates"]}
    assert status[result["parts"][0]["evidence_id"]] != "included"
    assert status[result["parts"][1]["evidence_id"]] != "included"
    assert status[result["parts"][2]["evidence_id"]] == "included"


def test_legacy_split_operations_are_not_registered(setup_split):
    from issue_manager.changeset_engine import operation_definition
    from issue_manager.errors import ValidationError
    manager, _, _, _ = setup_split
    assert not any(item["operation_id"].startswith("evidence.split.") for item in manager.operations.list())
    for operation in ("split_guard", "create_evidence", "split_finalize"):
        with pytest.raises(ValidationError):
            operation_definition(operation)


def test_platform_subject_can_trace_own_children_only_while_source_readable(setup_split):
    manager, _, _, _ = setup_split
    maintenance = manager.credentials.path_for("maintenance-agent")
    manager.evidence.register_platform("external", display_name="External", capabilities=["manifest"],
                                       credential=maintenance)
    manager.credentials.issue_actor(actor_id="external-agent", actor_kind="experiment_agent",
        platform_id="external", capabilities={"context.read", "evidence.write", "evidence.relation.write",
                                              "evidence.manifest.submit"}, maintenance_credential=maintenance)
    auth = manager.credentials.resolve(manager.credentials.path_for("external-agent"))
    source = manager.add_evidence(kind="external", locator="urn:external-source", issue_id="scope")["evidence_id"]
    with manager.store.transaction() as conn:
        conn.execute("UPDATE evidence_source_bindings SET source_platform_id='external',binding_state='inferred' "
                     "WHERE evidence_id=?", (source,))
    request = {"source_evidence_id": source,
        "expected_snapshot": manager.direct_splits.boundary(source, auth=auth)["snapshot"],
        "parts": [{"issue_id": "scope", "kind": "observation", "text": "One"},
                  {"issue_id": "scope", "kind": "interpretation", "text": "Two"}],
        "relation_decisions": [], "new_relations": []}
    first = manager.direct_splits.split(request, auth=auth, idempotency_key="external-first")
    # A different principal may split the same source without making the
    # first principal's own provenance and source unreadable.
    organizer = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"))
    other = manager.direct_splits.split({**request, "expected_snapshot": manager.direct_splits.boundary(
        source, auth=organizer)["snapshot"]}, auth=organizer, idempotency_key="other-split")
    from issue_manager.direct_split_api import dispatch
    page = dispatch(manager, "GET", ["v1", "direct-evidence-splits", "origins", source],
                    {}, "", auth, idempotency_key=None)
    assert {x.get("evidence_id") for x in page["items"] if not x.get("restricted")} == {
        part["evidence_id"] for part in first["parts"]}
    assert any(x.get("restricted") for x in page["items"])
    assert all(part["evidence_id"] not in str(page) for part in other["parts"])
    child = first["parts"][0]["evidence_id"]
    manager.evidence.require_read_access(child, auth)
    second = manager.direct_splits.split({**request, "source_evidence_id": child,
        "expected_snapshot": manager.direct_splits.boundary(child, auth=auth)["snapshot"]},
        auth=auth, idempotency_key="external-second")
    grandchild = second["parts"][0]["evidence_id"]
    manager.evidence.require_read_access(grandchild, auth)
    with manager.store.transaction() as conn:
        conn.execute("UPDATE evidence_source_bindings SET source_platform_id=NULL,binding_state='legacy_unbound' "
                     "WHERE evidence_id=?", (source,))
    with pytest.raises(PermissionError):
        manager.evidence.require_read_access(grandchild, auth)


def test_unresolvable_conclusion_impact_rolls_back_split(setup_split, monkeypatch):
    from issue_manager.context_scoped_v2_resolver import ScopedV2ResolvedContext

    manager, auth, _, _ = setup_split
    source = manager.add_evidence(kind="external", locator="urn:impact-source", issue_id="scope")["evidence_id"]
    package = manager.context_maintenance.prepare("scope", evidence_ids=[source])
    view = manager.context_maintenance.create_view(package["package_id"], auth=auth, idempotency_key="impact-view")
    manager.record_working_conclusion({"issue_id": "scope", "expected_current_conclusion_id": None,
        "expected_conclusion_revision": 0, "package_id": package["package_id"], "view_id": view["view_id"],
        "statement": "Conclusion", "evidence_refs": [source], "reason": "Synthetic"},
        auth=auth, idempotency_key="impact-conclusion")
    request = {"source_evidence_id": source,
        "expected_snapshot": manager.direct_splits.boundary(source, auth=auth)["snapshot"],
        "parts": [{"issue_id": "scope", "kind": "observation", "text": "One"},
                  {"issue_id": "scope", "kind": "interpretation", "text": "Two"}],
        "relation_decisions": [], "new_relations": []}
    with monkeypatch.context() as isolated:
        isolated.setattr(manager.context_maintenance.scoped_v2_resolver, "resolve",
            lambda *args, **kwargs: ScopedV2ResolvedContext(
                complete=False, errors=[{"code": "context_resolution_failed"}]))
        with pytest.raises(ConflictError, match="impact could not be resolved"):
            manager.direct_splits.split(request, auth=auth, idempotency_key="incomplete-impact")
    assert manager.store.row("SELECT COUNT(*) AS n FROM direct_split_origins")["n"] == 0
