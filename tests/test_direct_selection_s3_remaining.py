import errno
import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from issue_manager import IssueManager
from issue_manager.errors import ConflictError
from issue_manager.manager_api import ManagerService
from tests.scoped_test_support import prepare_explicit as _prepare


def _token(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))["token"]


def _http(base, token, method, path, body=None, key=None):
    data = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
    headers = {"Authorization": f"Bearer {token}", "X-Request-ID": key or "s3-remaining"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if key:
        headers["Idempotency-Key"] = key
    request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request) as response:
        raw = response.read()
        return response.status, json.loads(raw)["result"]


def _working(manager, issue_id, key):
    package = _prepare(manager, issue_id)
    propose = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.propose")
    view = manager.context_maintenance.create_view(package["package_id"], auth=propose, idempotency_key=f"{key}-view")
    record = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.record")
    return manager.record_working_conclusion(
        {"issue_id": issue_id, "expected_current_conclusion_id": None,
         "expected_conclusion_revision": 0, "package_id": package["package_id"],
         "view_id": view["view_id"], "statement": key, "evidence_refs": package["descriptor"]["seed_evidence_ids"], "reason": key},
        auth=record, idempotency_key=f"{key}-conclusion",
    )


def test_platform_principal_is_rejected_on_every_currentness_route_without_writes(tmp_path):
    manager = IssueManager.initialize(tmp_path / "platform-matrix", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scope")
        evidence_id = manager.add_evidence(kind="external", locator="urn:s3-platform", issue_id="scope")["evidence_id"]
        manager.evidence.register_platform(
            "s3-platform", display_name="S3 platform", capabilities=["manifest"],
            credential=manager.credentials.path_for("maintenance-agent"),
        )
        platform = manager.credentials.issue_actor(
            actor_id="s3-platform-agent", actor_kind="maintenance_agent",
            capabilities={"context.read", "conclusion.propose", "conclusion.record", "evidence.manifest.submit"},
            profiles={"platform-evidence-executor"}, principal_kind="service", platform_id="s3-platform",
            maintenance_credential=manager.credentials.path_for("maintenance-agent"),
        )
        organizer_token = _token(manager.credentials.path_for("organizer-agent"))
        platform_token = _token(platform["credential_path"])
        with ManagerService(manager.store.ledger_dir, port=0) as server:
            base = f"http://{server.address[0]}:{server.address[1]}"
            _, package = _http(base, organizer_token, "POST", "/v1/currentness/prepare",
                               {"issue_id": "scope", "evidence_ids": [evidence_id]}, "s3-platform-package")
            _, view = _http(base, organizer_token, "POST",
                            f"/v1/currentness/packages/{package['package_id']}/views",
                            {"budget_bytes": 8192}, "s3-platform-view")
            _, page = _http(base, organizer_token, "GET", f"/v1/currentness/views/{view['view_id']}")
            candidate_id = next(item["id"] for item in page["summary"]["catalog"] if item["kind"] == "candidate")
            working = {"issue_id": "scope", "expected_current_conclusion_id": None,
                       "expected_conclusion_revision": 0, "package_id": package["package_id"],
                       "view_id": view["view_id"], "statement": "platform denied",
                       "evidence_refs": package["descriptor"]["seed_evidence_ids"], "reason": "platform denied"}
            routes = [
                ("POST", "/v1/currentness/prepare", {"issue_id": "scope", "evidence_ids": []}, "s3-platform-denied-prepare"),
                ("POST", f"/v1/currentness/packages/{package['package_id']}/views", {"budget_bytes": 8192}, "s3-platform-denied-view"),
                ("GET", f"/v1/currentness/views/{view['view_id']}", None, None),
                ("GET", f"/v1/currentness/packages/{package['package_id']}", None, None),
                ("GET", f"/v1/currentness/views/{view['view_id']}/materials/{evidence_id}", None, None),
                ("GET", f"/v1/currentness/views/{view['view_id']}/entries/candidate/{candidate_id}", None, None),
                ("POST", "/v1/issues/scope/working-conclusion", working, "s3-platform-denied-conclusion"),
            ]
            for method, path, body, key in routes:
                with pytest.raises(urllib.error.HTTPError) as error:
                    _http(base, platform_token, method, path, body, key)
                assert error.value.code == 403
        assert manager.store.row("SELECT current_conclusion_id FROM issues WHERE issue_id='scope'")["current_conclusion_id"] is None
        assert manager.store.row("SELECT COUNT(*) AS n FROM context_package_views")["n"] == 1
        assert manager.store.row("SELECT COUNT(*) AS n FROM conclusion_revisions")["n"] == 0
    finally:
        manager.close()


def test_same_actor_different_run_and_same_run_different_request_are_isolated(tmp_path):
    path = tmp_path / "idempotency-matrix"
    manager = IssueManager.initialize(path, context_rule="scoped-v2")
    manager.create_issue("scope", "investigation", "Scope")
    package = _prepare(manager, "scope")
    propose = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.propose")
    view = manager.context_maintenance.create_view(package["package_id"], auth=propose, idempotency_key="run-matrix-view")
    request = {"issue_id": "scope", "expected_current_conclusion_id": None, "expected_conclusion_revision": 0,
               "package_id": package["package_id"], "view_id": view["view_id"], "statement": "run matrix",
               "evidence_refs": package["descriptor"]["seed_evidence_ids"], "reason": "run matrix"}
    organizer = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.record")
    actor_id, first_run = organizer.actor_id, organizer.run_id
    with manager.store.transaction() as conn:
        conn.execute("INSERT INTO agent_runs VALUES (?,?,NULL,'[]',datetime('now'),NULL)", ("s3-second-run", actor_id))
    issued = manager.credentials.issue_run_token(
        actor_id=actor_id, run_id="s3-second-run", capabilities={"conclusion.record"},
        ttl_seconds=300, maintenance_credential=manager.credentials.path_for("maintenance-agent"),
    )
    second_run = manager.credentials.resolve(issued["token"], "conclusion.record")
    assert first_run != second_run.run_id
    try:
        first = manager.record_working_conclusion(request, auth=organizer, idempotency_key="same-run-key")
        tables = ("issues", "conclusion_revisions", "basis_receipts", "request_idempotency", "audit_events")

        def snapshot():
            return {table: [tuple(row) for row in manager.store.conn.execute(f"SELECT * FROM {table} ORDER BY rowid")]
                    for table in tables}

        before = snapshot()
        second_request = {**request, "statement": "different request"}
        with pytest.raises(ConflictError):
            manager.record_working_conclusion(second_request, auth=organizer, idempotency_key="same-run-key")
        assert snapshot() == before
        manager.create_issue("other", "investigation", "Other")
        other_package = _prepare(manager, "other")
        other_view = manager.context_maintenance.create_view(
            other_package["package_id"], auth=propose, idempotency_key="other-run-view",
        )
        other_request = {**request, "issue_id": "other", "package_id": other_package["package_id"],
                         "view_id": other_view["view_id"], "evidence_refs": other_package["descriptor"]["seed_evidence_ids"], "statement": "second run"}
        second = manager.record_working_conclusion(other_request, auth=second_run, idempotency_key="same-run-key")
        assert second["conclusion_id"] == "other@r1"
        assert first["conclusion_id"] == "scope@r1"
        operations = {row[0] for row in manager.store.conn.execute(
            "SELECT operation FROM request_idempotency WHERE idempotency_key=?", ("same-run-key",),
        )}
        assert operations == {f"conclusion.record:{actor_id}:{first_run}",
                              f"conclusion.record:{actor_id}:{second_run.run_id}"}
    finally:
        manager.close()


def test_long_run_token_is_not_rejected_as_a_filename(tmp_path, monkeypatch):
    manager = IssueManager.initialize(tmp_path / "long-run-token", context_rule="scoped-v2")
    original_exists = Path.exists

    def exists(path):
        if path.name.startswith("run1.") or path.name == "ordinary-long-path":
            raise OSError(errno.ENAMETOOLONG, "synthetic name too long")
        return original_exists(path)

    try:
        monkeypatch.setattr(Path, "exists", exists)
        token = "run1." + "x" * 300
        assert manager.credentials._read(token) == (token, None)
        with pytest.raises(OSError) as error:
            manager.credentials._read("ordinary-long-path")
        assert error.value.errno == errno.ENAMETOOLONG
    finally:
        manager.close()
