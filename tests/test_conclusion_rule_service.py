import threading
from dataclasses import replace

import pytest

from issue_manager import IssueManager
from issue_manager.conclusion_rule_service import ConclusionRuleService
from issue_manager.errors import ConflictError, NotFoundError, PermissionError, ValidationError
from issue_manager.integrity import validate_object_integrity
from tests.scoped_test_support import prepare_explicit

SCHEMA = {"type": "object", "properties": {"result": {"type": "string"}},
          "required": ["result"], "additionalProperties": False}


def test_issue_rule_is_versioned_and_replays_original(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    try:
        manager.create_issue("i", "investigation", "Example")
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "issue.write")
        rules = ConclusionRuleService(manager)
        assert rules.current("i")["revision"] == 0
        request = {"expected_revision": 0, "schema": SCHEMA, "reason": "Need a result"}
        first = rules.write("i", request, auth=auth, idempotency_key="one")
        rules.write("i", {"expected_revision": 1, "schema": {"type": "object"}, "reason": "Revise"},
                    auth=auth, idempotency_key="two")
        assert rules.write("i", request, auth=auth, idempotency_key="one") == first
        assert rules.current("i")["revision"] == 2
        with pytest.raises(ConflictError):
            rules.write("i", request, auth=auth, idempotency_key="three")
        with pytest.raises(PermissionError):
            rules.write("i", request, auth=replace(auth, capabilities=frozenset()), idempotency_key="four")
        assert manager.store.row("SELECT COUNT(*) AS n FROM issue_conclusion_rule_versions")["n"] == 2
    finally:
        manager.close()


def test_rule_failure_rolls_back_insert_and_idempotency(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    try:
        manager.create_issue("i", "investigation", "Example")
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "issue.write")
        rules = ConclusionRuleService(manager)
        def fail(point):
            if point == "conclusion.rule.before_commit":
                raise RuntimeError("injected")
        manager.store.fault_injector = fail
        request = {"expected_revision": 0, "schema": SCHEMA, "reason": "Need a result"}
        with pytest.raises(RuntimeError, match="injected"):
            rules.write("i", request, auth=auth, idempotency_key="one")
        assert rules.current("i")["revision"] == 0
        manager.store.fault_injector = None
        assert rules.write("i", request, auth=auth, idempotency_key="one")["revision"] == 1
    finally:
        manager.close()


def test_archived_issue_rejects_new_rule_but_recovers_original(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    try:
        manager.create_issue("i", "investigation", "Example")
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "issue.write")
        rules = ConclusionRuleService(manager)
        request = {"expected_revision": 0, "schema": SCHEMA, "reason": "Need a result"}
        first = rules.write("i", request, auth=auth, idempotency_key="one")
        manager.archive_issue("i", reason="Finished")
        assert rules.write("i", request, auth=auth, idempotency_key="one") == first
        with pytest.raises(NotFoundError):
            rules.write("i", {**request, "expected_revision": 1}, auth=auth, idempotency_key="two")
    finally:
        manager.close()


def test_working_conclusion_retains_original_rule_and_replays_after_rule_change(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    try:
        manager.create_issue("i", "investigation", "Example")
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.record")
        reader = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "context.read")
        package = prepare_explicit(manager, "i")
        view = manager.context_maintenance.create_view(package["package_id"], auth=reader, idempotency_key="view")
        request = {"issue_id": "i", "expected_current_conclusion_id": None,
                   "expected_conclusion_revision": 0, "package_id": package["package_id"],
                   "view_id": view["view_id"], "statement": "prior conclusion", "reason": "prior",
                   "evidence_refs": package["descriptor"]["seed_evidence_ids"]}
        first = manager.record_working_conclusion(request, auth=auth, idempotency_key="first")
        rules = ConclusionRuleService(manager)
        rules.write("i", {"expected_revision": 0, "schema": SCHEMA, "reason": "Need result"},
                    auth=auth, idempotency_key="rule")
        assert manager.record_working_conclusion(request, auth=auth, idempotency_key="first") == first
        stale = {**request, "expected_current_conclusion_id": first["conclusion_id"],
                 "expected_conclusion_revision": 1, "structured_outputs": {"result": "valid"}}
        with pytest.raises(ConflictError, match="rule changed"):
            manager.record_working_conclusion(stale, auth=auth, idempotency_key="new")
        inspected = manager.inspect_issue("i", auth=reader)
        assert inspected["current_conclusion"]["applied_rule"]["revision"] == 0
        assert inspected["current_conclusion"]["current_rule_comparison"]["valid"] is False
        integrity = validate_object_integrity(manager.store.conn, "conclusion_revision", first["conclusion_id"])
        assert integrity["valid"], integrity["findings"]
        with pytest.raises(ValidationError) as err:
            manager.validate_proposal({"issue_id": "i", "expected_conclusion_revision": 1,
                                       "statement": "new", "structured_outputs": {}})
        assert err.value.details["field_errors"][0]["code"] == "required"
        assert manager.history("i")["conclusions"][0]["applied_rule"]["revision"] == 0
    finally:
        manager.close()


def test_two_rule_writers_use_revision_cas(tmp_path):
    path = tmp_path / "ledger"
    manager = IssueManager.initialize(path)
    manager.create_issue("i", "investigation", "Example")
    manager.close()
    barrier = threading.Barrier(2)
    outcomes = []

    def writer(key):
        local = IssueManager(path)
        try:
            auth = local.credentials.resolve(local.credentials.path_for("organizer-agent"), "issue.write")
            barrier.wait()
            try:
                result = ConclusionRuleService(local).write(
                    "i", {"expected_revision": 0, "schema": SCHEMA, "reason": key},
                    auth=auth, idempotency_key=key)
                outcomes.append(result["revision"])
            except ConflictError:
                outcomes.append("conflict")
        finally:
            local.close()

    threads = [threading.Thread(target=writer, args=(name,)) for name in ("one", "two")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)
        assert not thread.is_alive()
    assert sorted(map(str, outcomes)) == ["1", "conflict"]


def test_rule_change_between_validation_and_working_commit_conflicts(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    other = None
    try:
        manager.create_issue("i", "investigation", "Example")
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.record")
        package = prepare_explicit(manager, "i")
        view = manager.context_maintenance.create_view(package["package_id"], auth=auth, idempotency_key="view")
        request = {"issue_id": "i", "expected_current_conclusion_id": None,
                   "expected_conclusion_revision": 0, "package_id": package["package_id"],
                   "view_id": view["view_id"], "statement": "result", "reason": "reason",
                   "evidence_refs": package["descriptor"]["seed_evidence_ids"]}
        other = IssueManager(tmp_path / "ledger")
        original_validate = manager.validate_proposal
        def validate_then_change(*args, **kwargs):
            result = original_validate(*args, **kwargs)
            other_auth = other.credentials.resolve(other.credentials.path_for("organizer-agent"), "issue.write")
            ConclusionRuleService(other).write("i", {"expected_revision": 0, "schema": SCHEMA, "reason": "Changed"},
                                               auth=other_auth, idempotency_key="rule")
            return result
        manager.validate_proposal = validate_then_change
        with pytest.raises(ConflictError, match="rule changed"):
            manager.record_working_conclusion(request, auth=auth, idempotency_key="original")
        assert manager.store.row("SELECT COUNT(*) AS n FROM conclusion_revisions")["n"] == 0
    finally:
        if other is not None:
            other.close()
        manager.close()


def test_prepared_proposal_rejects_changed_rule(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    try:
        manager.create_issue("i", "investigation", "Example")
        token = manager.proposals.make_snapshot_token("i", 0, [])
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "issue.write")
        ConclusionRuleService(manager).write("i", {"expected_revision": 0, "schema": SCHEMA, "reason": "Changed"},
                                             auth=auth, idempotency_key="rule")
        with pytest.raises(ConflictError, match="rule changed"):
            manager.proposals.verify_snapshot(token, {"issue_id": "i", "expected_conclusion_revision": 0, "basis": []})
    finally:
        manager.close()


def test_project_component_preserves_rule_versions(tmp_path):
    from issue_manager.project_component import export_component, prepare_component

    manager = IssueManager.initialize(tmp_path / "ledger")
    try:
        manager.create_issue("i", "investigation", "Example")
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "issue.write")
        ConclusionRuleService(manager).write("i", {"expected_revision": 0, "schema": SCHEMA, "reason": "Result"},
                                             auth=auth, idempotency_key="rule")
        path = tmp_path / "rules.component"
        export_component(manager, path)
        result = prepare_component(path, tmp_path / "restored")
        assert result["metadata"]["table_counts"]["issue_conclusion_rule_versions"] == 1
        restored = IssueManager(tmp_path / "restored")
        try:
            assert ConclusionRuleService(restored).current("i")["schema"] == SCHEMA
        finally:
            restored.close()
    finally:
        manager.close()


def test_working_conclusion_binding_rolls_back_with_conclusion(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    try:
        manager.create_issue("i", "investigation", "Example")
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.record")
        package = prepare_explicit(manager, "i")
        view = manager.context_maintenance.create_view(package["package_id"], auth=auth, idempotency_key="view")
        request = {"issue_id": "i", "expected_current_conclusion_id": None,
                   "expected_conclusion_revision": 0, "package_id": package["package_id"],
                   "view_id": view["view_id"], "statement": "result", "reason": "reason",
                   "evidence_refs": package["descriptor"]["seed_evidence_ids"]}
        def fail(point):
            if point == "conclusion.record.before_commit":
                raise RuntimeError("injected")
        manager.store.fault_injector = fail
        with pytest.raises(RuntimeError, match="injected"):
            manager.record_working_conclusion(request, auth=auth, idempotency_key="conclusion")
        assert manager.store.row("SELECT COUNT(*) AS n FROM conclusion_revisions")["n"] == 0
        assert manager.store.row("SELECT COUNT(*) AS n FROM conclusion_rule_bindings")["n"] == 0
        manager.store.fault_injector = None
        result = manager.record_working_conclusion(request, auth=auth, idempotency_key="conclusion")
        assert manager.store.row("SELECT revision FROM conclusion_rule_bindings WHERE conclusion_id=?",
                                 (result["conclusion_id"],))["revision"] == 0
    finally:
        manager.close()
