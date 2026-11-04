import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import replace
from pathlib import Path

import pytest

from issue_manager import IssueManager
from issue_manager.errors import ConflictError, PermissionError
from issue_manager.manager_api import ManagerService
from tests.scoped_test_support import prepare_explicit as _prepare


def _working(manager, issue_id, key):
    propose = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.propose")
    record = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.record")
    package = _prepare(manager, issue_id)
    view = manager.context_maintenance.create_view(package["package_id"], auth=propose, idempotency_key=f"{key}-view")
    issue = manager.store.row("SELECT current_conclusion_id,conclusion_revision FROM issues WHERE issue_id=?", (issue_id,))
    return manager.record_working_conclusion(
        {"issue_id": issue_id, "expected_current_conclusion_id": issue["current_conclusion_id"],
         "expected_conclusion_revision": issue["conclusion_revision"],
         "package_id": package["package_id"], "view_id": view["view_id"],
         "statement": key, "evidence_refs": package["descriptor"]["seed_evidence_ids"], "reason": key},
        auth=record, idempotency_key=f"{key}-conclusion",
    )


def test_scoped_provider_relation_and_fixed_binding_keep_independent_dirty_edges(tmp_path):
    manager = IssueManager.initialize(tmp_path / "provider", context_rule="scoped-v2")
    try:
        manager.create_issue("consumer", "investigation", "Consumer")
        manager.create_issue("provider", "investigation", "Provider")
        first_relation = manager.add_relation("consumer", "provider", "depends_on", impact_policy="notify", reason="basis")
        second_relation = manager.add_relation("consumer", "provider", "rolls_up_from", impact_policy="notify", reason="rollup basis")
        first = _working(manager, "provider", "provider-first")
        descriptor = manager.context_maintenance.default_descriptor(
            "consumer", basis=[{"issue_id": "provider", "basis_mode": "current"}]
        )
        resolved = manager.context_maintenance.scoped_v2_resolver.resolve(descriptor)
        assert {item[0] for item in resolved.contributions} == {first["conclusion_id"]}
        assert len(resolved.contributions) == 3
        assert all(item[1].startswith("scoped-provider:consumer:") for item in resolved.contributions)
        assert {item[1].rsplit(":", 1)[-1] for item in resolved.contributions
                if item[1] != "scoped-provider:consumer:provider"} == {
                    first_relation["relation_id"], second_relation["relation_id"]
                }
        assert resolved.comparison_context["issue_relations"][0]["provider_issue_id"] == "provider"

        fixed = {**descriptor, "provider_bindings": [{
            "issue_id": "provider", "mode": "fixed", "conclusion_id": first["conclusion_id"],
            "require_currentness": False,
        }]}
        fixed_resolved = manager.context_maintenance.scoped_v2_resolver.resolve(fixed)
        assert fixed_resolved.contributions == set()
        fixed_currentness = {**fixed, "provider_bindings": [{
            "issue_id": "provider", "mode": "fixed", "conclusion_id": first["conclusion_id"],
            "require_currentness": True,
        }]}
        assert not manager.context_maintenance.scoped_v2_resolver.resolve(fixed_currentness).errors
        second = _working(manager, "provider", "provider-second")
        assert manager.context_maintenance.scoped_v2_resolver.resolve(fixed).comparison_context["provider_bindings"][0]["conclusion"]["conclusion_id"] == first["conclusion_id"]
        assert second["conclusion_id"] != first["conclusion_id"]
    finally:
        manager.close()


def test_new_issue_provider_relation_invalidates_existing_downstream(tmp_path):
    manager = IssueManager.initialize(tmp_path / "provider-subscription", context_rule="scoped-v2")
    try:
        manager.create_issue("down", "investigation", "Down")
        manager.create_issue("up", "investigation", "Up")
        down = _working(manager, "down", "down-before-provider")
        assert manager.context_maintenance.show(down["conclusion_id"])["currentness"] == "current"
        _working(manager, "up", "upstream")
        manager.add_relation("down", "up", "depends_on", impact_policy="notify", reason="new provider")
        with manager.store.transaction():
            manager.context_maintenance.flush()
        state = manager.context_maintenance.show(down["conclusion_id"])
        assert state["currentness"] == "needs_update"
        assert any(item["code"] == "context_mismatch" for item in state["reasons"])
        assert manager.context_maintenance.audit()["ok"] is True
    finally:
        manager.close()


def test_excluded_material_requires_explicit_mode_and_never_becomes_reference(tmp_path):
    manager = IssueManager.initialize(tmp_path / "excluded", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scope")
        included = manager.add_evidence(kind="external", locator="urn:included", issue_id="scope")["evidence_id"]
        excluded = manager.add_evidence(kind="external", locator="urn:excluded")["evidence_id"]
        read = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "context.read")
        write = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "evidence.relation.write")
        source = manager.scoped_evidence_relations.binding(excluded, auth=read)["token"]
        target = manager.scoped_evidence_relations.binding(included, auth=read)["token"]
        manager.scoped_evidence_relations.create(scope_issue_id="scope", source_evidence_id=excluded,
            target_evidence_id=included, relation_type="refutes", rationale="exclude", auth=write,
            expected_source_token=source, expected_target_token=target, idempotency_key="exclude-edge")
        package = _prepare(manager, "scope")
        propose = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.propose")
        view = manager.context_maintenance.create_view(package["package_id"], auth=propose, idempotency_key="excluded-view")
        with pytest.raises(Exception):
            manager.context_maintenance.material_page(view["view_id"], included, auth=read)
        excluded_page = manager.context_maintenance.material_page(view["view_id"], included, auth=read, mode="excluded")
        assert excluded_page["complete"] is True
        assert excluded not in package["actual_input"]["materials"]["evidence"]
        assert included not in package["actual_input"]["materials"]["evidence"]
    finally:
        manager.close()


def test_frozen_candidate_entry_exposes_status_reason_without_current_reread(tmp_path):
    manager = IssueManager.initialize(tmp_path / "entry", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scope")
        included = manager.add_evidence(kind="external", locator="urn:entry-included", issue_id="scope")["evidence_id"]
        excluded = manager.add_evidence(kind="external", locator="urn:entry-excluded")["evidence_id"]
        read = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "context.read")
        write = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "evidence.relation.write")
        source = manager.scoped_evidence_relations.binding(excluded, auth=read)["token"]
        target = manager.scoped_evidence_relations.binding(included, auth=read)["token"]
        manager.scoped_evidence_relations.create(scope_issue_id="scope", source_evidence_id=excluded,
            target_evidence_id=included, relation_type="refutes", rationale="entry", auth=write,
            expected_source_token=source, expected_target_token=target, idempotency_key="entry-edge")
        package = _prepare(manager, "scope")
        propose = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.propose")
        view = manager.context_maintenance.create_view(package["package_id"], auth=propose, idempotency_key="entry-view")
        entry = manager.context_maintenance.entry(view["view_id"], "candidate", included, auth=read)
        assert entry["status"] == "excluded"
        assert entry["diagnostics"]
        assert entry["diagnostics"][0]["relation_id"]
    finally:
        manager.close()


def test_oversized_frozen_relation_entry_is_replayable_by_cursor(tmp_path):
    manager = IssueManager.initialize(tmp_path / "entry-pages", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scope")
        source_id = manager.add_evidence(kind="external", locator="urn:entry-source", issue_id="scope")["evidence_id"]
        target_id = manager.add_evidence(kind="external", locator="urn:entry-target", issue_id="scope")["evidence_id"]
        read = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "context.read")
        write = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "evidence.relation.write")
        source = manager.scoped_evidence_relations.binding(source_id, auth=read)["token"]
        target = manager.scoped_evidence_relations.binding(target_id, auth=read)["token"]
        relation = manager.scoped_evidence_relations.create(
            scope_issue_id="scope", source_evidence_id=source_id, target_evidence_id=target_id,
            relation_type="depends_on", rationale="长理由🙂" * 700, auth=write,
            expected_source_token=source, expected_target_token=target, idempotency_key="entry-long",
        )
        package = _prepare(manager, "scope")
        propose = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.propose")
        view = manager.context_maintenance.create_view(package["package_id"], auth=propose,
                                                        budget_bytes=2048, idempotency_key="entry-long-view")
        page = manager.context_maintenance.entry(view["view_id"], "relation", relation["relation_id"], auth=read)
        assert page["complete"] is False
        fragments = [page["content_utf8"]]
        cursor = page["next_cursor"]
        while cursor is not None:
            page = manager.context_maintenance.entry(view["view_id"], "relation", relation["relation_id"],
                                                     auth=read, cursor=cursor)
            fragments.append(page["content_utf8"])
            assert len(json.dumps(page, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) <= 2048
            cursor = page["next_cursor"]
        decoded = json.loads("".join(fragments))
        assert decoded["id"] == relation["relation_id"]
        assert decoded["relation"]["rationale"] == "长理由🙂" * 700
        token = json.loads(manager.credentials.path_for("organizer-agent").read_text(encoding="utf-8"))["token"]
        with ManagerService(manager.store.ledger_dir, port=0) as server:
            base = f"http://{server.address[0]}:{server.address[1]}"
            cursor = None
            http_fragments = []
            while True:
                path = f"/v1/currentness/views/{view['view_id']}/entries/relation/{relation['relation_id']}"
                if cursor is not None:
                    path += "?cursor=" + urllib.parse.quote(cursor, safe="")
                request = urllib.request.Request(base + path, headers={"Authorization": f"Bearer {token}"})
                with urllib.request.urlopen(request) as response:
                    raw = response.read()
                    assert len(raw) <= 2048
                    payload = json.loads(raw)["result"]
                http_fragments.append(payload["content_utf8"])
                if payload["complete"]:
                    break
                cursor = payload["next_cursor"]
            assert json.loads("".join(http_fragments)) == decoded
    finally:
        manager.close()


def test_http_permission_matrix_rejects_missing_capability_without_side_effects(tmp_path):
    manager = IssueManager.initialize(tmp_path / "http-permissions", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scope")
        manager.add_evidence(kind="external", locator="urn:http-permission", issue_id="scope")
        reader = manager.credentials.issue_actor(
            actor_id="reader-only", capabilities={"context.read"},
            maintenance_credential=manager.credentials.path_for("maintenance-agent"),
        )
        organizer_token = json.loads(manager.credentials.path_for("organizer-agent").read_text(encoding="utf-8"))["token"]
        reader_token = json.loads(Path(reader["credential_path"]).read_text(encoding="utf-8"))["token"]

        def call(base, token, method, path, body=None, key=None):
            data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers = {"Authorization": f"Bearer {token}", "X-Request-ID": key or "http-permission"}
            if data is not None:
                headers["Content-Type"] = "application/json"
            if key:
                headers["Idempotency-Key"] = key
            request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())["result"]

        def denied(base, token, method, path, body, key):
            with pytest.raises(urllib.error.HTTPError) as error:
                call(base, token, method, path, body, key)
            assert error.value.code == 403

        with ManagerService(manager.store.ledger_dir, port=0) as server:
            base = f"http://{server.address[0]}:{server.address[1]}"
            package = call(base, organizer_token, "POST", "/v1/currentness/prepare",
                           {"issue_id": "scope", "evidence_ids": []}, "http-permission-prepare")[1]
            view = call(base, organizer_token, "POST", f"/v1/currentness/packages/{package['package_id']}/views",
                        {"budget_bytes": 8192}, "http-permission-view")[1]
            call(base, reader_token, "GET", f"/v1/currentness/views/{view['view_id']}")
            denied(base, reader_token, "POST", "/v1/currentness/prepare",
                   {"issue_id": "scope", "evidence_ids": []}, "http-permission-denied-prepare")
            denied(base, reader_token, "POST", f"/v1/currentness/packages/{package['package_id']}/views",
                   {"budget_bytes": 8192}, "http-permission-denied-view")
            denied(base, reader_token, "POST", "/v1/issues/scope/working-conclusion",
                   {"issue_id": "scope", "expected_current_conclusion_id": None,
                    "expected_conclusion_revision": 0, "package_id": package["package_id"],
                    "view_id": view["view_id"], "statement": "denied", "evidence_refs": package["descriptor"]["seed_evidence_ids"],
                    "reason": "permission"}, "http-permission-denied-conclusion")
        assert manager.store.row("SELECT current_conclusion_id FROM issues WHERE issue_id='scope'")["current_conclusion_id"] is None
        assert manager.store.row("SELECT COUNT(*) AS n FROM context_package_views")["n"] == 1
    finally:
        manager.close()


@pytest.mark.parametrize("fault_point", [
    "conclusion.record.after_conclusion_insert", "conclusion.record.after_issue_head",
    "conclusion.record.after_receipt", "conclusion.record.before_commit",
])
def test_working_conclusion_fault_rolls_back_content_and_maintenance_rows(tmp_path, fault_point):
    manager = IssueManager.initialize(tmp_path / fault_point.replace(".", "-"), context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scope")
        propose = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.propose")
        record = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.record")
        package = _prepare(manager, "scope")
        view = manager.context_maintenance.create_view(package["package_id"], auth=propose, idempotency_key="snapshot-view")
        request = {"issue_id": "scope", "expected_current_conclusion_id": None,
                   "expected_conclusion_revision": 0, "package_id": package["package_id"],
                   "view_id": view["view_id"], "statement": "rollback", "evidence_refs": package["descriptor"]["seed_evidence_ids"], "reason": "fault"}
        tables = ("issues", "conclusion_revisions", "conclusion_evidence_uses", "basis_receipts",
                  "basis_receipt_selections", "basis_receipt_eligibility", "conclusion_context_selections",
                  "context_subscriptions", "currentness_edge_contributions", "conclusion_currentness",
                  "audit_events", "context_input_events", "context_input_clock",
                  "context_maintenance_checkpoint", "request_idempotency")

        def snapshot():
            return {table: [tuple(row) for row in manager.store.conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]
                    for table in tables}

        before = snapshot()
        manager.store.fault_injector = lambda current: (_ for _ in ()).throw(RuntimeError(current)) if current == fault_point else None
        with pytest.raises(RuntimeError, match=fault_point):
            manager.record_working_conclusion(request, auth=record, idempotency_key="snapshot-conclusion")
        manager.store.fault_injector = None
        assert snapshot() == before
        replay = manager.record_working_conclusion(request, auth=record, idempotency_key="snapshot-conclusion")
        assert replay["status"] == "provisional"
    finally:
        manager.close()


def test_direct_conclusion_rejects_missing_capability_before_any_write(tmp_path):
    manager = IssueManager.initialize(tmp_path / "permission", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scope")
        package = _prepare(manager, "scope")
        propose = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.propose")
        view = manager.context_maintenance.create_view(package["package_id"], auth=propose, idempotency_key="permission-view")
        no_record = replace(
            manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "context.read"),
            capabilities=frozenset({"context.read", "conclusion.propose"}),
        )
        request = {"issue_id": "scope", "expected_current_conclusion_id": None, "expected_conclusion_revision": 0,
                   "package_id": package["package_id"], "view_id": view["view_id"],
                   "statement": "denied", "evidence_refs": package["descriptor"]["seed_evidence_ids"], "reason": "permission"}
        with pytest.raises(PermissionError):
            manager.record_working_conclusion(request, auth=no_record, idempotency_key="permission-conclusion")
        assert manager.store.row("SELECT current_conclusion_id FROM issues WHERE issue_id='scope'")["current_conclusion_id"] is None
        assert manager.store.row("SELECT COUNT(*) AS n FROM request_idempotency WHERE operation LIKE 'conclusion.record:%'")["n"] == 0
    finally:
        manager.close()


def test_working_conclusion_two_connections_obey_head_cas(tmp_path):
    path = tmp_path / "two-connections"
    manager = IssueManager.initialize(path, context_rule="scoped-v2")
    manager.create_issue("scope", "investigation", "Scope")
    propose = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.propose")
    package = _prepare(manager, "scope")
    view = manager.context_maintenance.create_view(package["package_id"], auth=propose, idempotency_key="cas-view")
    request = {"issue_id": "scope", "expected_current_conclusion_id": None, "expected_conclusion_revision": 0,
               "package_id": package["package_id"], "view_id": view["view_id"],
               "statement": "one wins", "evidence_refs": package["descriptor"]["seed_evidence_ids"], "reason": "cas"}
    barrier = threading.Barrier(2)
    results = []

    def submit(key):
        target = IssueManager(path)
        try:
            auth = target.credentials.resolve(target.credentials.path_for("organizer-agent"), "conclusion.record")
            barrier.wait(timeout=5)
            results.append(target.record_working_conclusion(request, auth=auth, idempotency_key=key))
        except Exception as exc:  # the losing connection is expected to conflict
            results.append(exc)
        finally:
            target.close()

    manager.close()
    first = threading.Thread(target=submit, args=("cas-one",))
    second = threading.Thread(target=submit, args=("cas-two",))
    first.start()
    second.start()
    first.join(10)
    second.join(10)
    assert len(results) == 2
    assert sum(isinstance(item, dict) for item in results) == 1, repr(results)
    assert sum(isinstance(item, ConflictError) for item in results) == 1
    checker = IssueManager(path)
    assert checker.store.row("SELECT conclusion_revision FROM issues WHERE issue_id='scope'")["conclusion_revision"] == 1
    checker.close()


def test_working_conclusion_same_key_concurrent_replay_returns_one_receipt(tmp_path):
    path = tmp_path / "same-key"
    manager = IssueManager.initialize(path, context_rule="scoped-v2")
    manager.create_issue("scope", "investigation", "Scope")
    propose = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.propose")
    package = _prepare(manager, "scope")
    view = manager.context_maintenance.create_view(package["package_id"], auth=propose, idempotency_key="same-key-view")
    request = {"issue_id": "scope", "expected_current_conclusion_id": None, "expected_conclusion_revision": 0,
               "package_id": package["package_id"], "view_id": view["view_id"],
               "statement": "same request", "evidence_refs": package["descriptor"]["seed_evidence_ids"], "reason": "same key"}
    path_reader = manager.credentials.path_for("organizer-agent")
    barrier = threading.Barrier(2)
    results = []

    def submit():
        target = IssueManager(path)
        try:
            auth = target.credentials.resolve(path_reader, "conclusion.record")
            barrier.wait(timeout=5)
            results.append(target.record_working_conclusion(request, auth=auth, idempotency_key="same-key-conclusion"))
        finally:
            target.close()

    manager.close()
    threads = [threading.Thread(target=submit) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert len(results) == 2
    assert all(isinstance(item, dict) for item in results)
    assert {item["conclusion_id"] for item in results} == {"scope@r1"}
    checker = IssueManager(path)
    assert checker.store.row("SELECT COUNT(*) AS n FROM conclusion_revisions WHERE issue_id='scope'")["n"] == 1
    checker.close()


def test_working_conclusion_same_key_isolated_by_actor_run_namespace(tmp_path):
    manager = IssueManager.initialize(tmp_path / "actor-run", context_rule="scoped-v2")
    try:
        manager.create_issue("one", "investigation", "One")
        manager.create_issue("two", "investigation", "Two")
        issued = manager.credentials.issue_actor(
            actor_id="second-organizer", capabilities={"context.read", "conclusion.propose", "conclusion.record"},
            maintenance_credential=manager.credentials.path_for("maintenance-agent"),
        )
        propose = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.propose")
        first_package = _prepare(manager, "one")
        first_view = manager.context_maintenance.create_view(first_package["package_id"], auth=propose, idempotency_key="namespace-one-view")
        second_package = _prepare(manager, "two")
        second_view = manager.context_maintenance.create_view(second_package["package_id"], auth=propose, idempotency_key="namespace-two-view")
        first = manager.record_working_conclusion(
            {"issue_id": "one", "expected_current_conclusion_id": None, "expected_conclusion_revision": 0,
             "package_id": first_package["package_id"], "view_id": first_view["view_id"],
             "statement": "one", "evidence_refs": first_package["descriptor"]["seed_evidence_ids"], "reason": "namespace"},
            auth=manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.record"),
            idempotency_key="shared-key",
        )
        second = manager.record_working_conclusion(
            {"issue_id": "two", "expected_current_conclusion_id": None, "expected_conclusion_revision": 0,
             "package_id": second_package["package_id"], "view_id": second_view["view_id"],
             "statement": "two", "evidence_refs": second_package["descriptor"]["seed_evidence_ids"], "reason": "namespace"},
            auth=manager.credentials.resolve(Path(issued["credential_path"]), "conclusion.record"),
            idempotency_key="shared-key",
        )
        assert first["conclusion_id"] == "one@r1"
        assert second["conclusion_id"] == "two@r1"
    finally:
        manager.close()
