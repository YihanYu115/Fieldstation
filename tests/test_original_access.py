"""Synthetic HTTP/MCP acceptance; no real models or research originals."""
from __future__ import annotations

import hashlib
import importlib.resources
import json
import sqlite3
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from unittest.mock import patch
from uuid import uuid4

import pytest
from jsonschema import Draft202012Validator
from workflow_orchestrator.client import WorkflowAPIError, WorkflowClient

from issue_manager import IssueManager
from issue_manager.errors import PermissionError, ValidationError
from issue_manager.manager_api import ManagerService
from issue_manager.original_access_service import OriginalAccessService
from issue_manager.project_component import export_component, prepare_component
from issue_manager.security import AuthContext
from issue_manager.store import Store, canonical_json
from project_package.host import ProjectHost


def document(prefix="archive:item/", **changes):
    return {"reference_prefix": prefix, "summary": "合成原件读取说明",
            "capability": "synthetic.read_lines", "parameters": "reference, lines (1-based inclusive)",
            "example": "reference=archive:item/a; lines=2-2",
            "semantics": "按行读取，无摘要保证。complete=true表示请求区间完整，不代表整个文档。",
            "failures": "missing_binding:宿主未绑定；forbidden:无读取权限；missing:原件缺失。",
            "change_impact": "initial", "impact_note": "合成契约，无科学解释变化。", **changes}


def write(client, contract="archive", expected=0, doc=None, root="ROOT", key=None):
    identity = key or str(uuid4())
    return client.register_original_access({"root_issue_id": root, "contract_id": contract,
        "expected_revision": expected, "document": doc or document(), "reason": "合成验收"},
        request_id=identity, idempotency_key=identity)


@pytest.fixture
def live(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    manager.create_issue("ROOT", "sample", "合成项目")
    manager.create_issue("CHILD", "qubit", "局部工作", parent_issue_id="ROOT")
    manager.create_issue("OTHER", "investigation", "另一项目")
    tokens = {name: json.loads(manager.credentials.path_for(name).read_text(encoding="utf-8"))["token"]
              for name in ("organizer-agent", "review-agent-1")}
    with ManagerService(manager.store.ledger_dir, port=0, project_runtime=tmp_path / "components") as service:
        endpoint = "http://%s:%s" % service.address
        yield manager, WorkflowClient(endpoint, tokens["organizer-agent"]), WorkflowClient(
            endpoint, tokens["review-agent-1"])
    manager.close()


def test_synthetic_two_contract_handoff_and_scientific_independence(live):
    manager, client, reader = live
    assert reader.discover_original_access("CHILD")["total"] == 0
    write(client)
    write(client, "remote", doc=document("remote-record:", capability="synthetic.get_cell",
        parameters="record_id, cell", example="record_id=42; cell=voltage",
        semantics="返回一个数值字段，不提供行号或摘要。"))
    # External backends are synthetic, separate capabilities; IM never parses these references.
    backends = {"synthetic.read_lines": lambda ref: "第二行观察" if ref == "archive:item/a" else None,
                "synthetic.get_cell": lambda ref: 3.5 if ref == "remote-record:42" else None}
    refs = ["archive:item/a", "remote-record:42"]
    for index, ref in enumerate(refs):
        match = reader.discover_original_access("CHILD", reference=ref)
        assert match["match_status"] == "matched"
        pointer = match["items"][0]["read"]["arguments"]
        instructions = reader.read_original_access(**pointer)
        assert instructions["complete"] and instructions["external_binding"] == "host_required"
        observed = backends[instructions["document"]["capability"]](ref)
        access_version = (instructions["root_issue_id"], instructions["contract_id"], instructions["revision"])
        saved = client.scoped_contribution({"issue_id": "CHILD", "kind": "observation",
            "source": ref, "description": f"合成局部结果：{observed}；访问说明 {access_version}",
            "related_evidence": [], "reason": "保留准确来源和说明版本"}, idempotency_key=f"e-{index}")
        assert saved["evidence"]["declared_source_locator"] == ref
    ids = [r["evidence_id"] for r in client.browse_evidence("CHILD")["items"]]
    package = client.prepare_materials("CHILD", ids, idempotency_key="freeze")
    view = client.create_view(package["package_id"], idempotency_key="view")
    client.record_working_conclusion({"issue_id": "CHILD", "expected_current_conclusion_id": None,
        "expected_conclusion_revision": 0, "package_id": package["package_id"],
        "view_id": view["view_id"], "evidence_refs": ids, "statement": "合成结果，待真实核验。",
        "reason": "合成状态独立性测试", "confidence": "low"}, idempotency_key="conclusion")
    tables = ["evidence_refs", "context_input_packages", "context_input_clock", "context_input_events",
              "conclusion_revisions", "conclusion_currentness", "scoped_evidence_relation_versions"]
    before = {table: manager.store.rows(f"SELECT * FROM {table}") for table in tables}
    old = reader.read_original_access("CHILD", "archive", 1)
    write(client, expected=1, doc=document(change_impact="interpretation", impact_note="第二版调整读取语义，需作者复核。"))
    assert reader.read_original_access("CHILD", "archive", 1) == old
    assert reader.discover_original_access("CHILD", reference=refs[0])["match_status"] == "version_required"
    assert {table: manager.store.rows(f"SELECT * FROM {table}") for table in tables} == before
    assert reader.browse_issue("CHILD")["original_access"]["contract_count"] == 2
    assert reader.get_issue_overview("CHILD")["original_access"]["root_issue_id"] == "ROOT"


def test_http_replay_cas_conflicts_fault_rollback_and_restart(live):
    manager, client, reader = live
    receipt = write(client, key="initial")
    assert write(client, key="initial") == receipt
    with pytest.raises(WorkflowAPIError) as conflict:
        write(client, key="initial", doc=document(summary="异内容"))
    assert conflict.value.status == 409
    doc = document(change_impact="editorial", impact_note="文字更新")
    def race(_):
        try:
            return write(client, expected=1, doc=doc)["revision"]
        except WorkflowAPIError as exc:
            return exc.status
    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(race, range(2))) == [2, 409]
    original_audit = Store.audit
    def injected(self, *args, **kwargs):
        original_audit(self, *args, **kwargs)
        if kwargs.get("action") == "project.original_access.revise":
            raise RuntimeError("synthetic fault after head and audit write")
    with patch.object(Store, "audit", injected), pytest.raises(WorkflowAPIError) as failure:
        write(client, expected=2, doc=doc, key="retry")
    assert failure.value.status == 500
    assert reader.discover_original_access("CHILD", contract_id="archive")["total"] == 2
    # Same durable intent and request identity recover after transient server fault.
    assert write(client, expected=2, doc=doc, key="retry")["revision"] == 3
    with closing(IssueManager(manager.store.ledger_dir)) as restarted:
        assert restarted.store.row("SELECT revision FROM project_original_access_heads")["revision"] == 3
        assert not restarted.store.verify_audit_chain()
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            restarted.store.conn.execute("DELETE FROM project_original_access_versions")


def test_scope_permissions_diagnostics_and_page_snapshots(live):
    manager, client, reader = live
    write(client)
    write(client, "overlap", doc=document("archive:"))
    assert reader.discover_original_access("CHILD", reference="archive:item/a")["match_status"] == "ambiguous"
    assert reader.discover_original_access("CHILD", reference="unknown:")["match_status"] == "missing"
    assert reader.discover_original_access("OTHER")["total"] == 0
    write(client, root="OTHER", doc=document(semantics="另一个项目的独立读取解释。"))
    assert reader.read_original_access("OTHER", "archive", 1)["document"]["semantics"].startswith("另一个")
    assert reader.read_original_access("CHILD", "archive", 1)["document"]["semantics"].startswith("按行")
    assert reader.discover_original_access("OTHER")["total"] == 1
    for ro in (reader, WorkflowClient(client.base_url, "invalid")):
        with pytest.raises(WorkflowAPIError) as denied:
            write(ro)
        assert denied.value.status == 403
    manager.credentials.issue_actor(actor_id="no-context-reader", actor_kind="experiment_agent",
        capabilities={"intake.submit"},
        maintenance_credential=manager.credentials.path_for("maintenance-agent"))
    token = json.loads(manager.credentials.path_for("no-context-reader").read_text(encoding="utf-8"))["token"]
    with pytest.raises(WorkflowAPIError) as denied:
        WorkflowClient(client.base_url, token).discover_original_access("CHILD")
    assert denied.value.status == 403
    with pytest.raises(WorkflowAPIError) as invalid:
        write(client, root="CHILD")
    assert invalid.value.status == 400
    auth = AuthContext(actor_id="platform", actor_kind="service", run_id="p", lineage=frozenset(),
        capabilities=frozenset({"context.read", "issue.write"}), platform_id="p")
    with pytest.raises(PermissionError):
        OriginalAccessService(manager).discover("ROOT", auth=auth)
    page = reader.discover_original_access("CHILD", limit=1)
    next_page = reader.discover_original_access("CHILD", cursor=page["next_cursor"], limit=1)
    assert page["has_more"] and next_page["complete"] and page["snapshot"] == next_page["snapshot"]
    write(client, "third", doc=document("third:"))
    with pytest.raises(WorkflowAPIError) as changed:
        reader.discover_original_access("CHILD", cursor=page["next_cursor"])
    assert changed.value.status == 409
    for query in ("issue_id=ROOT&issue_id=OTHER", "issue_id=ROOT&limit=0", "issue_id=%ZZ", "issue_id=ROOT&actor=x"):
        with pytest.raises(WorkflowAPIError) as invalid:
            reader._request("GET", "/v1/original-access/discover?" + query)
        assert invalid.value.status == 400


def test_utf8_budgets_inert_instructions_and_validation(live, tmp_path):
    manager, client, reader = live
    sentinel = tmp_path / "must-not-exist"
    doc = document(semantics="中🙂" * 900, example=f"Never execute: create {sentinel}")
    write(client, doc=doc)
    value = reader.read_original_access("CHILD", "archive", 1)
    assert value["document"] == doc and not sentinel.exists()
    with pytest.raises(WorkflowAPIError) as budget:
        reader.read_original_access("CHILD", "archive", 1, max_bytes=1024)
    required = budget.value.details["required_bytes"]
    exact = reader.read_original_access("CHILD", "archive", 1, max_bytes=required)
    assert len(canonical_json(exact).encode("utf-8")) == required
    with pytest.raises(WorkflowAPIError):
        reader.read_original_access("CHILD", "archive", 1, max_bytes=required-1)
    for bad in (document(summary="中"*171), document(capability="https://example.invalid"),
                document(parameters="a"*8192, example="b"*8192, semantics="c"*8192, failures="d"*8192),
                {**document(), "api_key": "synthetic-forbidden-field"}):
        with pytest.raises(WorkflowAPIError) as invalid:
            write(client, "bad", doc=bad)
        assert invalid.value.status == 400
    assert reader.discover_original_access("CHILD")["total"] == 1
    assert manager.store.row("SELECT COUNT(*) AS n FROM project_original_access_versions")["n"] == 1


def test_project_component_preserves_versions_and_isolation(live, tmp_path):
    manager, client, _ = live
    write(client)
    write(client, expected=1, doc=document(change_impact="editorial", impact_note="说明修订"))
    export_component(manager, tmp_path / "snapshot.im.component")
    result = prepare_component(tmp_path / "snapshot.im.component", tmp_path / "restored")
    assert result["metadata"]["table_counts"]["project_original_access_versions"] == 2
    with closing(IssueManager(tmp_path / "restored")) as restored:
        for table in ("project_original_access_heads", "project_original_access_versions", "project_original_access_bindings"):
            assert restored.store.rows(f"SELECT * FROM {table}") == manager.store.rows(f"SELECT * FROM {table}")
        with pytest.raises(sqlite3.DatabaseError):
            restored.store.conn.execute("DELETE FROM project_original_access_heads")


@pytest.mark.parametrize("old_version", [4, 5])
def test_old_schema_refused_without_mutating_bytes(tmp_path, old_version):
    with closing(IssueManager.initialize(tmp_path / "old")) as manager:
        path = manager.store.db_path
    with closing(sqlite3.connect(path)) as db:
        db.execute("PRAGMA ignore_check_constraints=ON")
        db.execute("UPDATE schema_identity SET version=?", (old_version,))
        db.commit()
    before = hashlib.sha256(path.read_bytes()).digest()
    with pytest.raises(ValidationError, match=f"schema identity {old_version}"):
        IssueManager(tmp_path / "old")
    assert hashlib.sha256(path.read_bytes()).digest() == before


def test_full_project_package_over_http_carries_instruction_history(live, tmp_path):
    manager, client, _ = live
    write(client)
    packet = client.submit_field_packet({"issue_id": "CHILD", "content": "待整理的合成观察",
        "attachment_refs": ["archive:item/a"]}, request_id="package-packet", idempotency_key="package-packet")
    client.curate_field_item(packet["packet_id"], {"issue_id": "CHILD", "expected_curation_version": 0,
        "kind": "observation", "description": "合成观察", "reason": "封装绑定及继承链",
        "origin": {"type": "attachment", "attachment_ref": "archive:item/a", "part_locator": "lines:1-1"},
        "related_evidence": []}, request_id="package-curate", idempotency_key="package-curate")
    write(client, expected=1, doc=document(change_impact="interpretation", impact_note="历史保留测试"))
    token = json.loads(manager.credentials.path_for("maintenance-agent").read_text(encoding="utf-8"))["token"]
    host = ProjectHost(client.base_url, token, "ROOT", tmp_path / "host", tmp_path / "projects")
    try:
        export = host.export("instructions", False)
        with zipfile.ZipFile(host.runtime / "exports" / (export["job_id"] + ".improjectpkg")) as archive:
            manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        schema = json.loads(importlib.resources.files("project_package").joinpath("contracts.json").read_text(encoding="utf-8"))
        Draft202012Validator({**schema, "$ref": "#/$defs/projectManifest"}).validate(manifest)
        Draft202012Validator({**schema, "$ref": "#/$defs/imComponentManifest"}).validate(manifest["components"]["im"])
        # The host receives exported bytes through its normal upload/preflight/install workflow.
        upload_path = host.runtime / "uploads" / "instructions.receiving"
        upload_path.write_bytes((host.runtime / "exports" / (export["job_id"] + ".improjectpkg")).read_bytes())
        uploaded = host.register_upload(upload_path)
        inspected = host.preflight(uploaded["upload_id"])
        assert inspected["components"]["im"]["table_counts"]["project_original_access_versions"] == 2
        assert inspected["components"]["im"]["table_counts"]["project_original_access_bindings"] == 2
        with zipfile.ZipFile(host.runtime / "inspections" / uploaded["upload_id"] / "im.component") as component:
            references = json.loads(component.read("external-references.json").decode("utf-8"))
        assert any(r["table"] == "project_original_access_bindings" and r["reference"] == "archive:item/a"
                   for r in references)
        assert any(r["field"] == "declared_source_locator" and r["reference"] == "archive:item/a"
                   for r in references)
        host.install(inspected["upload_id"], inspected["preflight_hash"], "restored", "install-access")
        with closing(IssueManager(tmp_path / "projects/restored/im")) as restored:
            for table in ("project_original_access_heads", "project_original_access_versions", "project_original_access_bindings"):
                assert restored.store.rows(f"SELECT * FROM {table}") == manager.store.rows(f"SELECT * FROM {table}")
    finally:
        host.close()
