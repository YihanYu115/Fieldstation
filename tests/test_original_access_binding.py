"""Admission-time automatic pins through real HTTP; no model or original backend."""
from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from workflow_orchestrator.client import WorkflowAPIError, WorkflowClient

from issue_manager.store import Store
from tests.test_original_access import document, write
from tests.test_original_access import live as _live


@pytest.fixture
def live(tmp_path):
    yield from _live.__wrapped__(tmp_path)


def contribution(client, ref="archive:item/a", key=None, issue="CHILD"):
    return client.scoped_contribution({"issue_id": issue, "kind": "observation", "source": ref,
        "description": "合成观察，无需填写契约版本。", "reason": "自动绑定验收", "related_evidence": []},
        idempotency_key=key or str(uuid4()))


def test_automatic_pin_old_new_replay_and_frozen_pointer(live):
    manager, client, reader = live
    write(client, doc=document(parameters="p" * 1500))
    first = contribution(client, key="first")
    evidence = first["evidence"]["evidence_id"]
    pin = first["evidence"]["original_access"][0]
    assert pin["status"] == "bound" and pin["revision"] == 1
    package = client.prepare_materials("CHILD", [evidence], idempotency_key="frozen")
    view = client.create_view(package["package_id"], idempotency_key="view")
    frozen_before = manager.context_maintenance.package(package["package_id"])
    page_before = client.material(view["view_id"], evidence)
    write(client, expected=1, doc=document(change_impact="interpretation", semantics="新版读取语义。"))
    assert contribution(client, key="first")["evidence"]["original_access"] == [pin]
    assert reader.read_original_access("CHILD", evidence_id=evidence)["revision"] == 1
    second = contribution(client)["evidence"]
    assert second["original_access"][0]["revision"] == 2
    assert reader.read_original_access("CHILD", evidence_id=second["evidence_id"])["revision"] == 2
    read_pin = reader.browse_evidence_detail(evidence)["evidence"]["original_access"][0]
    assert read_pin["binding_id"] == pin["binding_id"] and read_pin["revision"] == 1
    assert reader.read_original_access(**read_pin["read"]["arguments"])["revision"] == 1
    assert manager.context_maintenance.package(package["package_id"]) == frozen_before
    assert client.material(view["view_id"], evidence) == page_before
    pointer = page_before["source"]["original_access"]["read"]["arguments"]
    assert reader.read_original_access(**pointer)["revision"] == 1
    for query in ("&contract_id=archive&revision=1", "&reference=other"):
        if "contract_id" in query:
            with pytest.raises(WorkflowAPIError):
                reader._request("GET", f"/v1/original-access/read?issue_id=CHILD&evidence_id={evidence}" + query)
    full = reader.read_original_access("CHILD", evidence_id=evidence)
    from issue_manager.store import canonical_json
    size = len(canonical_json(full).encode("utf-8"))
    with pytest.raises(WorkflowAPIError) as budget:
        reader.read_original_access("CHILD", evidence_id=evidence, max_bytes=max(1024, size-1))
    assert budget.value.details["required_bytes"] == size


def test_packet_admission_inherited_after_delayed_curation(live):
    manager, client, reader = live
    write(client)
    manager.credentials.issue_actor(actor_id="capture-only", actor_kind="experiment_agent", capabilities={"intake.submit"},
        maintenance_credential=manager.credentials.path_for("maintenance-agent"))
    token = json.loads(manager.credentials.path_for("capture-only").read_text(encoding="utf-8"))["token"]
    capture = WorkflowClient(client.base_url, token)
    body = {"issue_id": "CHILD", "content": "正文观察。", "sources": [{"locator": "archive:item/text", "provided_text": "给定来源。"}],
            "attachment_refs": ["archive:item/a", "archive:item/b"]}
    receipt = capture.submit_field_packet(body, request_id="receive", idempotency_key="receive")
    packet_id = receipt["packet_id"]
    old_pins = reader.field_packet(packet_id)["original_access"]
    assert len(old_pins) == 3 and all(b["revision"] == 1 for b in old_pins)
    write(client, expected=1, doc=document(change_impact="editorial", impact_note="说明措辞更新。"))
    replay = capture.submit_field_packet(body, request_id="receive", idempotency_key="receive")
    assert replay == {**receipt, "idempotent_replay": True}
    assert reader.field_packet_summary(packet_id)["original_access"] == old_pins
    origins = [{"type": "attachment", "attachment_ref": "archive:item/a", "part_locator": "lines:2-2"},
               {"type": "source_text", "source_index": 0, "quoted_text": "给定来源。"},
               {"type": "packet_text", "quoted_text": "正文观察。"}]
    for index, origin in enumerate(origins):
        saved = client.curate_field_item(packet_id, {"issue_id": "CHILD", "expected_curation_version": index,
            "description": "局部观察", "kind": "observation", "origin": origin, "reason": "延迟整理",
            "related_evidence": []}, request_id=f"curate-{index}", idempotency_key=f"curate-{index}")
        fact = reader.field_packet_fact(packet_id, saved["fact_ref"])
        binding = fact["original_access"][0]
        if index < 2:
            assert binding["revision"] == 1 and binding["inherited_from"] in {p["binding_id"] for p in old_pins}
            assert reader.read_original_access("CHILD", evidence_id=fact["mapping"]["evidence_id"])["revision"] == 1
        else:
            assert binding["status"] == "internal"


def test_missing_ambiguous_internal_and_no_retroactive_rebinding(live):
    _, client, reader = live
    missing = contribution(client)["evidence"]
    assert missing["original_access"][0]["status"] == "missing"
    write(client)
    assert reader.read_original_access("CHILD", evidence_id=missing["evidence_id"])["binding_status"] == "missing"
    assert contribution(client)["evidence"]["original_access"][0]["status"] == "bound"
    write(client, "overlap", doc=document("archive:"))
    ambiguous = contribution(client)["evidence"]
    assert ambiguous["original_access"][0]["status"] == "ambiguous"
    assert ambiguous["original_access"][0]["candidate_count"] == 2
    internal = contribution(client, ref="im-field-packet:internal#content")["evidence"]
    assert internal["original_access"][0]["status"] == "internal"
    # New references consider active heads only, not older matching prefixes.
    write(client, "overlap", expected=1, doc=document("new-prefix:", change_impact="interpretation"))
    write(client, expected=1, doc=document("new-archive:", change_impact="interpretation"))
    assert contribution(client)["evidence"]["original_access"][0]["status"] == "missing"


@pytest.mark.parametrize("packet", [False, True])
def test_admission_failure_rolls_back_pin_and_domain_and_original_retry(live, monkeypatch, packet):
    manager, client, reader = live
    write(client)
    tables = ["evidence_refs", "issue_evidence", "field_packets", "project_original_access_bindings", "audit_events"]
    before = {t: manager.store.rows(f"SELECT * FROM {t}") for t in tables}
    original = Store.fault
    def fault(self, name):
        original(self, name)
        if name == "original_access.after_binding":
            raise RuntimeError("Synthetic admission fault")
    def perform():
        if packet:
            return client.submit_field_packet({"issue_id": "CHILD", "content": "合成观察", "attachment_refs": ["archive:item/a"]},
                                              request_id="retry", idempotency_key="retry")
        return client._request("POST", "/v1/scoped-evidence-contributions", {"issue_id": "CHILD", "kind": "observation",
            "source": "archive:item/a", "description": "合成观察", "reason": "故障恢复", "related_evidence": []},
            request_id="retry", idempotency_key="retry")
    with monkeypatch.context() as patch:
        patch.setattr(Store, "fault", fault)
        with pytest.raises(WorkflowAPIError) as error:
            perform()
        assert error.value.status == 500
    assert {t: manager.store.rows(f"SELECT * FROM {t}") for t in tables} == before
    saved = perform()
    pins = reader.field_packet(saved["packet_id"])["original_access"] if packet else saved["evidence"]["original_access"]
    assert pins[0]["revision"] == 1
    assert perform() == ({**saved, "idempotent_replay": True} if packet else saved)


def test_shared_evidence_project_pins_and_bound_read_authorization(live):
    manager, client, reader = live
    write(client)
    write(client, root="OTHER", doc=document(semantics="独立项目契约。"))
    first = manager.add_evidence(kind="external", locator="archive:item/a", issue_id="CHILD")
    evidence = first["evidence_id"]
    write(client, expected=1, doc=document(change_impact="editorial"))
    assert manager.add_evidence(kind="external", locator="archive:item/a", issue_id="CHILD")["original_access"][0]["revision"] == 1
    manager.add_evidence(kind="external", locator="archive:item/a", issue_id="OTHER")
    pins = reader.browse_evidence_detail(evidence)["evidence"]["original_access"]
    assert {(p["root_issue_id"], p["issue_id"], p["revision"]) for p in pins} == {
        ("ROOT", "CHILD", 1), ("OTHER", "OTHER", 1)}
    assert reader.read_original_access("CHILD", evidence_id=evidence)["revision"] == 1
    assert reader.read_original_access("OTHER", evidence_id=evidence)["document"]["semantics"].startswith("独立")
    other = contribution(client, issue="OTHER")["evidence"]["evidence_id"]
    with pytest.raises(WorkflowAPIError) as denied:
        reader.read_original_access("CHILD", evidence_id=other)
    assert denied.value.status == 403
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        manager.store.conn.execute("DELETE FROM project_original_access_bindings")


def test_concurrent_contract_update_and_admission_have_one_transaction_order(live):
    _, client, reader = live
    write(client)
    def admit():
        return contribution(client)["evidence"]
    with ThreadPoolExecutor(2) as pool:
        a = pool.submit(admit)
        b = pool.submit(write, client, expected=1, doc=document(change_impact="editorial"))
        evidence = a.result()
        assert b.result()["revision"] == 2
    pin = evidence["original_access"][0]
    assert pin["revision"] in {1, 2}
    assert reader.read_original_access("CHILD", evidence_id=evidence["evidence_id"])["revision"] == pin["revision"]
