from __future__ import annotations

import json

import pytest
from workflow_orchestrator.client import WorkflowAPIError, WorkflowClient

from issue_manager import IssueManager
from issue_manager.manager_api import ManagerService


def _token(ledger):
    return json.loads(
        (ledger / "credentials" / "organizer-agent.token").read_text(encoding="utf-8")
    )["token"]




def _relation(provider, relation_type, rationale):
    return {
        "provider_evidence_id": provider,
        "relation_type": relation_type,
        "rationale": rationale,
    }






def test_scoped_v2_http_contribution_failure_rolls_back_all_objects(tmp_path):
    ledger = tmp_path / "atomic-contribution"
    manager = IssueManager.initialize(ledger, context_rule="scoped-v2")
    manager.close()
    with ManagerService(ledger, port=0) as service:
        client = WorkflowClient(f"http://{service.address[0]}:{service.address[1]}", _token(ledger))
        client.create_issue("scope", "investigation", "Atomic contribution", idempotency_key="issue")
        first_request = {
            "issue_id": "scope", "kind": "observation", "source": "urn:atomic-a",
            "description": "A", "reason": "atomic setup", "related_evidence": [],
        }
        first = client.scoped_contribution(first_request, idempotency_key="atomic-a")
        assert client.scoped_contribution(first_request, idempotency_key="atomic-a") == first
        with pytest.raises(WorkflowAPIError) as error:
            client.scoped_contribution({
                "issue_id": "scope", "kind": "observation", "source": "urn:atomic-b",
                "description": "B", "reason": "missing provider",
                "related_evidence": [_relation("missing-evidence", "depends_on", "must fail")],
            }, idempotency_key="atomic-b")
        assert error.value.status == 404
        first_id = first["evidence"]["evidence_id"]
    manager = IssueManager(ledger)
    try:
        assert manager.store.row("SELECT COUNT(*) AS count FROM evidence_refs")["count"] == 1
        assert manager.store.row(
            "SELECT COUNT(*) AS count FROM scoped_evidence_relation_heads"
        )["count"] == 0
        row = manager.store.row(
            "SELECT evidence_id,declared_source_locator FROM evidence_refs WHERE evidence_id=?",
            (first_id,),
        )
        assert row["declared_source_locator"] == "urn:atomic-a"
        assert row["evidence_id"] == first_id
    finally:
        manager.close()


def test_scoped_contributions_share_declared_source_without_sharing_identity(tmp_path):
    ledger = tmp_path / "shared-source"
    manager = IssueManager.initialize(ledger)
    manager.close()
    with ManagerService(ledger, port=0) as service:
        client = WorkflowClient(f"http://{service.address[0]}:{service.address[1]}", _token(ledger))
        client.create_issue("scope", "investigation", "Shared source", idempotency_key="issue")
        source = "  synthetic:scan-a 来源🙂  "
        first_request = {
            "issue_id": "scope", "kind": "observation", "source": source,
            "description": "双峰被观察到", "reason": "record observation", "related_evidence": [],
        }
        with pytest.raises(WorkflowAPIError) as invalid_source:
            client.scoped_contribution(
                {**first_request, "source": "invalid\x00source"},
                idempotency_key="invalid-source",
            )
        assert invalid_source.value.status == 400
        first = client.scoped_contribution(first_request, idempotency_key="same-source-a")
        first_replay = client.scoped_contribution(first_request, idempotency_key="same-source-a")
        assert first_replay == first

        second = client.scoped_contribution({
            **first_request,
            "description": "未做 Rabi，峰归属未确认",
            "related_evidence": [_relation(first["evidence"]["evidence_id"], "depends_on", "interpret with observation A")],
        }, idempotency_key="same-source-b")
        assert second["evidence"]["evidence_id"] != first["evidence"]["evidence_id"]
        for contribution in (first["evidence"], second["evidence"]):
            assert contribution["declared_source_locator"] == source
            assert contribution["locator_role"] == "internal_identity"
            assert contribution["locator"].startswith("im-internal:scoped-contribution:")
        assert second["scoped_relations"][0]["source_evidence_id"] == second["evidence"]["evidence_id"]
        assert second["scoped_relations"][0]["target_evidence_id"] == first["evidence"]["evidence_id"]

        changed_retry = {**first_request, "description": "changed payload"}
        with pytest.raises(WorkflowAPIError) as error:
            client.scoped_contribution(changed_retry, idempotency_key="same-source-a")
        assert error.value.status == 409

        client.create_issue("other", "investigation", "Other issue", idempotency_key="issue-other")
        other = client.scoped_contribution({**first_request, "issue_id": "other"}, idempotency_key="same-source-other")
        assert other["evidence"]["evidence_id"] not in {
            first["evidence"]["evidence_id"], second["evidence"]["evidence_id"]
        }
        package = client.prepare_materials(
            "scope", [second["evidence"]["evidence_id"]], idempotency_key="shared-source-freeze"
        )
        view = client.create_view(package["package_id"], idempotency_key="shared-source-view")
        material = client.material(view["view_id"], second["evidence"]["evidence_id"])
        assert material["source"]["locator"] == source
        assert material["source"]["locator_kind"] == "declared"
        assert material["source"]["body_available"] is False
        material_record = json.loads(material["content_utf8"])
        assert material_record["source_locator"] == source
        assert material_record["locator_role"] == "internal_identity"
    manager = IssueManager(ledger)
    try:
        assert manager.store.row("SELECT COUNT(*) AS n FROM evidence_refs")['n'] == 3
        assert manager.store.row(
            "SELECT declared_source_locator FROM evidence_refs WHERE evidence_id=?",
            (other["evidence"]["evidence_id"],),
        )["declared_source_locator"] == source
        from issue_manager.desktop_queries import dispatch

        read_auth = manager.credentials.resolve(
            manager.credentials.path_for("organizer-agent"), "context.read"
        )
        listing = dispatch(
            manager, "GET", ["v1", "evidence"],
            {"q": [source], "limit": ["200"], "offset": ["0"]}, {},
            read_auth, "", None,
        )
        matched = [item for item in listing["items"] if item["declared_source_locator"] == source]
        assert len(matched) == 3
        assert all(item["source_locator"] == source for item in matched)
        assert all(item["locator_role"] == "internal_identity" for item in matched)
        duplicate_first = manager.add_evidence(kind="external", locator="urn:ordinary-dedupe")
        duplicate_again = manager.add_evidence(kind="external", locator="urn:ordinary-dedupe")
        assert duplicate_again["evidence_id"] == duplicate_first["evidence_id"]
    finally:
        manager.close()


def test_scoped_v2_http_rejects_stale_commit_without_overwriting_head(tmp_path):
    ledger = tmp_path / "stale-commit"
    manager = IssueManager.initialize(ledger, context_rule="scoped-v2")
    manager.close()
    with ManagerService(ledger, port=0) as service:
        client = WorkflowClient(f"http://{service.address[0]}:{service.address[1]}", _token(ledger))
        client.create_issue("scope", "investigation", "Stale commit", idempotency_key="issue")
        evidence = client.scoped_contribution({
            "issue_id": "scope", "kind": "observation", "source": "urn:stale",
            "description": "root", "reason": "stale setup", "related_evidence": [],
        }, idempotency_key="stale-evidence")["evidence"]["evidence_id"]
        package = client.prepare_materials("scope", [evidence], idempotency_key="stale-prepare")
        view = client.create_view(package["package_id"], idempotency_key="stale-view")
        inspected = client.inspect_issue("scope")
        first_request = {
            "issue_id": "scope", "expected_current_conclusion_id": None,
            "expected_conclusion_revision": inspected["issue"]["conclusion_revision"],
            "package_id": package["package_id"], "view_id": view["view_id"],
            "statement": "first", "evidence_refs": [evidence], "reason": "first",
        }
        first = client.record_working_conclusion(first_request, idempotency_key="stale-first")
        stale_request = {**first_request, "statement": "stale overwrite", "reason": "stale"}
        with pytest.raises(WorkflowAPIError) as error:
            client.record_working_conclusion(stale_request, idempotency_key="stale-second")
        assert error.value.status == 409
        assert client.inspect_issue("scope")["issue"]["current_conclusion_id"] == first["conclusion_id"]




def test_scoped_v2_u01_u02_u04_to_u08_over_public_http(tmp_path):
    ledger = tmp_path / "http-semantic-cases"
    manager = IssueManager.initialize(ledger, context_rule="scoped-v2")
    manager.close()
    with ManagerService(ledger, port=0) as service:
        client = WorkflowClient(f"http://{service.address[0]}:{service.address[1]}", _token(ledger))
        sequence = 0

        def add(issue_id, label, related=()):
            nonlocal sequence
            sequence += 1
            result = client.scoped_contribution({
                "issue_id": issue_id,
                "kind": "observation",
                "source": f"http:{issue_id}:{label}",
                "description": label,
                "reason": "public HTTP semantic acceptance",
                "related_evidence": list(related),
            }, idempotency_key=f"http-semantic-{sequence}")
            return result["evidence"]["evidence_id"]

        def relation(provider, relation_type, rationale):
            return _relation(provider, relation_type, rationale)

        def status(issue_id, root, expected):
            nonlocal sequence
            sequence += 1
            package = client.prepare_materials(
                issue_id, [root], idempotency_key=f"http-semantic-prepare-{sequence}"
            )
            view = client.create_view(
                package["package_id"], idempotency_key=f"http-semantic-view-{sequence}"
            )
            entry = client.view_entry(view["view_id"], "candidate", root)
            assert entry["status"] == expected
            return view

        # U01: C refutes A while B depends on A; B is excluded.
        client.create_issue("u01", "investigation", "U01", idempotency_key="http-u01-issue")
        a = add("u01", "A")
        b = add("u01", "B", [relation(a, "depends_on", "B requires A")])
        add("u01", "C", [relation(a, "refutes", "C refutes A")])
        status("u01", b, "excluded")

        # U02: two independent valid refuters remain effective together.
        client.create_issue("u02", "investigation", "U02", idempotency_key="http-u02-issue")
        a = add("u02", "A")
        add("u02", "C1", [relation(a, "refutes", "C1 refutes A")])
        add("u02", "C2", [relation(a, "refutes", "C2 refutes A")])
        status("u02", a, "excluded")

        # U04: a failed necessary basis makes the adopted root unavailable.
        client.create_issue("u04", "investigation", "U04", idempotency_key="http-u04-issue")
        a = add("u04", "A")
        b = add("u04", "B", [relation(a, "depends_on", "B requires A")])
        add("u04", "C", [relation(a, "refutes", "C refutes A")])
        status("u04", b, "excluded")

        # U05: an unavailable refuter no longer excludes an independent D.
        client.create_issue("u05", "investigation", "U05", idempotency_key="http-u05-issue")
        a = add("u05", "A")
        d = add("u05", "D")
        b = add("u05", "B", [relation(a, "depends_on", "B requires A"),
                               relation(d, "refutes", "B attacks D")])
        add("u05", "C", [relation(a, "refutes", "C refutes A")])
        status("u05", d, "included")

        # U06: refuting the refuter restores the original basis without selecting it.
        client.create_issue("u06", "investigation", "U06", idempotency_key="http-u06-issue")
        a = add("u06", "A")
        b = add("u06", "B", [relation(a, "depends_on", "B requires A")])
        c = add("u06", "C", [relation(a, "refutes", "C refutes A")])
        add("u06", "E", [relation(c, "refutes", "E refutes C")])
        status("u06", b, "included")

        # U07: multiple depends_on edges are an AND, not an OR.
        client.create_issue("u07", "investigation", "U07", idempotency_key="http-u07-issue")
        a1 = add("u07", "A1")
        a2 = add("u07", "A2")
        b = add("u07", "B", [relation(a1, "depends_on", "B requires A1"),
                               relation(a2, "depends_on", "B requires A2")])
        add("u07", "C", [relation(a1, "refutes", "C refutes A1")])
        status("u07", b, "excluded")

        # U08: derived_from preserves provenance but does not make A necessary.
        client.create_issue("u08", "investigation", "U08", idempotency_key="http-u08-issue")
        a = add("u08", "A")
        b = add("u08", "B", [relation(a, "derived_from", "B cites A")])
        add("u08", "C", [relation(a, "refutes", "C refutes A")])
        status("u08", b, "included")
