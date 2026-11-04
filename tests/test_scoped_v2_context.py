import json
from dataclasses import replace

import pytest
from workflow_orchestrator.client import WorkflowClient

from issue_manager import IssueManager
from issue_manager.errors import PermissionError, ValidationError
from issue_manager.manager_api import ManagerService
from issue_manager.scoped_projection import project
from issue_manager.scoped_semantics import ScopedNode, ScopedRelation, ScopedSnapshot, solve


def test_fresh_scoped_v2_uses_new_identity_and_pure_resolver(tmp_path):
    manager = IssueManager.initialize(tmp_path / "scoped-v2", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scoped v2")
        evidence_id = manager.add_evidence(kind="external", locator="urn:v2", issue_id="scope")["evidence_id"]
        package = manager.context_maintenance.prepare("scope", evidence_ids=[evidence_id])
        assert manager.context_rules.active()["rule_id"].startswith("context-currentness/scoped-v2:")
        assert package["descriptor"]["version"] == "context-currentness/scoped-v2"
        materials = package["actual_input"]["materials"]
        assert materials["roots"] == [evidence_id]
        assert materials["support_ids"] == [evidence_id]
        assert materials["candidate_states"][0]["status"] == "T"
        assert package["actual_input"]["comparison_context"]["rule_id"] == "context-currentness/scoped-v2"
    finally:
        manager.close()


def test_scoped_v2_keeps_discovery_separate_when_no_root_is_selected(tmp_path):
    manager = IssueManager.initialize(tmp_path / "discovery", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scoped v2 discovery")
        evidence_id = manager.add_evidence(kind="external", locator="urn:discovery", issue_id="scope")["evidence_id"]
        package = manager.context_maintenance.prepare("scope")
        materials = package["actual_input"]["materials"]
        assert materials["roots"] == []
        assert materials["support_ids"] == []
        assert materials["discovery_ids"] == [evidence_id]
    finally:
        manager.close()


def test_scoped_v2_view_path_accepts_only_frozen_scoped_package(tmp_path):
    manager = IssueManager.initialize(tmp_path / "view", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scoped v2 view")
        evidence_id = manager.add_evidence(kind="external", locator="urn:view", issue_id="scope")["evidence_id"]
        package = manager.context_maintenance.prepare("scope", evidence_ids=[evidence_id])
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.propose")
        view = manager.context_maintenance.create_view(package["package_id"], auth=auth, idempotency_key="v2-view")
        assert view["package_id"] == package["package_id"]
        assert {item["id"] for item in view["summary"]["catalog"] if item["kind"] == "evidence"} == {evidence_id}
    finally:
        manager.close()


def test_scoped_v2_conclusion_requires_exact_frozen_basis_roots(tmp_path):
    manager = IssueManager.initialize(tmp_path / "conclusion", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scoped v2 conclusion")
        evidence_id = manager.add_evidence(kind="external", locator="urn:conclusion", issue_id="scope")["evidence_id"]
        package = manager.context_maintenance.prepare("scope", evidence_ids=[evidence_id])
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.propose")
        view = manager.context_maintenance.create_view(package["package_id"], auth=auth, idempotency_key="conclusion-view")
        record = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.record")
        result = manager.record_working_conclusion(
            {"issue_id": "scope", "expected_current_conclusion_id": None,
             "expected_conclusion_revision": 0, "package_id": package["package_id"],
             "view_id": view["view_id"], "statement": "bounded", "evidence_refs": [evidence_id],
             "reason": "explicit basis"}, auth=record, idempotency_key="v2-conclusion",
        )
        assert result["conclusion_id"] == "scope@r1"
        use = manager.store.row(
            "SELECT proof_id,proof_hash,evidence_semantic_revision,manifest_id,manifest_hash "
            "FROM conclusion_evidence_uses WHERE conclusion_id=? AND evidence_id=?",
            (result["conclusion_id"], evidence_id),
        )
        proof = manager.store.row(
            "SELECT proof_id,proof_hash,semantic_revision,manifest_id,manifest_hash "
            "FROM evidence_proofs WHERE proof_id=(SELECT current_proof_id FROM evidence_refs WHERE evidence_id=?)",
            (evidence_id,),
        )
        assert use == {
            "proof_id": proof["proof_id"],
            "proof_hash": proof["proof_hash"],
            "evidence_semantic_revision": proof["semantic_revision"],
            "manifest_id": proof["manifest_id"],
            "manifest_hash": proof["manifest_hash"],
        }
        assert manager.doctor()["ok"]
        follow_current = manager.context_maintenance.prepare("scope")
        assert follow_current["descriptor"]["seed_evidence_ids"] == [evidence_id]
        explicit_discovery = manager.context_maintenance.prepare("scope", evidence_ids=[])
        assert explicit_discovery["descriptor"]["seed_evidence_ids"] == []
    finally:
        manager.close()


def test_scoped_v2_relation_preview_uses_the_common_solver(tmp_path):
    manager = IssueManager.initialize(tmp_path / "preview", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scoped v2 preview")
        target = manager.add_evidence(kind="external", locator="urn:target", issue_id="scope")["evidence_id"]
        source = manager.add_evidence(kind="external", locator="urn:source")["evidence_id"]
        read = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "context.read")
        write = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "evidence.relation.write")
        relation = manager.scoped_evidence_relations.create(
            scope_issue_id="scope", source_evidence_id=source, target_evidence_id=target,
            relation_type="refutes", rationale="v2 preview", auth=write,
            expected_source_token=manager.scoped_evidence_relations.binding(source, auth=read)["token"],
            expected_target_token=manager.scoped_evidence_relations.binding(target, auth=read)["token"],
            idempotency_key="v2-preview-relation",
        )
        preview = manager.scoped_evidence_relations.preview_selection(
            scope_issue_id="scope", seed_evidence_ids=[target], maximum_nodes=10,
            maximum_relations=10, auth=read,
        )
        assert preview["contract_id"] == "scoped-selection-preview/v2"
        selected = {item["candidate_id"]: item["status"] for item in preview["selection"]["candidates"]}
        assert selected[target] == "excluded"
        assert relation["relation_id"] in {item["relation_id"] for item in preview["projection"]["qualification_edges"]}
    finally:
        manager.close()


def test_scoped_v2_missing_provider_is_not_complete(tmp_path):
    manager = IssueManager.initialize(tmp_path / "provider", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scoped v2 provider")
        evidence_id = manager.add_evidence(kind="external", locator="urn:provider", issue_id="scope")["evidence_id"]
        descriptor = manager.context_maintenance.default_descriptor("scope", evidence_ids=[evidence_id])
        descriptor["provider_bindings"] = [{
            "issue_id": "missing-provider", "mode": "fixed", "conclusion_id": "missing@r1",
            "require_currentness": True,
        }]
        result = manager.context_maintenance.scoped_v2_resolver.resolve(descriptor, tolerate_errors=True)
        assert result.errors and result.complete is False
        assert any(item["code"] == "provider_issue_missing" for item in result.errors)
        assert result.contributions == set()
    finally:
        manager.close()


def test_scoped_v2_resolver_rejects_unsupported_staged_state_view(tmp_path):
    manager = IssueManager.initialize(tmp_path / "state-view", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scoped v2 state view")
        evidence_id = manager.add_evidence(kind="external", locator="urn:state-view", issue_id="scope")["evidence_id"]
        descriptor = manager.context_maintenance.default_descriptor("scope", evidence_ids=[evidence_id])
        with pytest.raises(ValidationError, match="staged state views"):
            manager.context_maintenance.scoped_v2_resolver.resolve(descriptor, state_view=object())
    finally:
        manager.close()


def test_scoped_v2_provider_binding_is_compared_and_contributes_cross_issue_currentness(tmp_path):
    manager = IssueManager.initialize(tmp_path / "provider-valid", context_rule="scoped-v2")
    try:
        manager.create_issue("provider", "investigation", "Provider")
        provider_evidence = manager.add_evidence(kind="external", locator="urn:provider-valid", issue_id="provider")["evidence_id"]
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.record")
        provider_package = manager.context_maintenance.prepare("provider", evidence_ids=[provider_evidence])
        provider_view = manager.context_maintenance.create_view(provider_package["package_id"], auth=auth, idempotency_key="provider-view")
        provider_result = manager.record_working_conclusion(
            {"issue_id": "provider", "expected_current_conclusion_id": None,
             "expected_conclusion_revision": 0, "package_id": provider_package["package_id"],
             "view_id": provider_view["view_id"], "statement": "provider", "evidence_refs": [provider_evidence],
             "reason": "provider root"}, auth=auth, idempotency_key="provider-conclusion",
        )
        manager.create_issue("consumer", "investigation", "Consumer")
        consumer_evidence = manager.add_evidence(kind="external", locator="urn:consumer", issue_id="consumer")["evidence_id"]
        rule_id = manager.context_rules.active()["rule_id"]
        descriptor = {
            "version": "context-currentness/scoped-v2", "rule_version_id": rule_id,
            "issue_id": "consumer", "seed_evidence_ids": [consumer_evidence],
            "provider_bindings": [{"issue_id": "provider", "mode": "fixed",
                                   "conclusion_id": provider_result["conclusion_id"],
                                   "require_currentness": True}],
        }
        package = manager.context_maintenance.prepare("consumer", descriptor=descriptor)
        provider_entries = package["actual_input"]["materials"]["providers"]
        assert provider_entries[0]["conclusion_id"] == provider_result["conclusion_id"]
        view = manager.context_maintenance.create_view(package["package_id"], auth=auth, idempotency_key="consumer-view")
        manager.record_working_conclusion(
            {"issue_id": "consumer", "expected_current_conclusion_id": None,
             "expected_conclusion_revision": 0, "package_id": package["package_id"],
             "view_id": view["view_id"], "statement": "consumer", "evidence_refs": [consumer_evidence],
             "reason": "consumer root"}, auth=auth, idempotency_key="consumer-conclusion",
        )
        edge = manager.store.row(
            "SELECT provider_conclusion_id FROM currentness_edge_contributions "
            "WHERE contribution_id=?", ("scoped-provider:consumer:provider",),
        )
        assert edge["provider_conclusion_id"] == provider_result["conclusion_id"]
    finally:
        manager.close()


def test_scoped_v2_pending_dependency_changes_comparison_without_changing_unknown_state():
    nodes = (ScopedNode("A", "new", "T"), ScopedNode("B", "v1", "T"), ScopedNode("E", "v1", "?"))
    existing = ScopedRelation("be", "r1", "B", "E", "v1", "v1", "depends_on")
    pending = ScopedRelation("ba", "r1", "B", "A", "v1", "old", "depends_on")
    before = project(ScopedSnapshot("scope", nodes, (existing,)), ["B"], solve(
        ScopedSnapshot("scope", nodes, (existing,))))
    after = project(ScopedSnapshot("scope", nodes, (existing, pending)), ["B"], solve(
        ScopedSnapshot("scope", nodes, (existing, pending))))
    assert before["gap"] != after["gap"]
    assert before["comparison"] != after["comparison"]
    assert after["comparison"]["pending_dependencies"][0]["relation_id"] == "ba"


def test_scoped_v2_candidate_catalog_entries_are_expandable(tmp_path):
    manager = IssueManager.initialize(tmp_path / "candidate-entry", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scoped v2 candidate")
        evidence_id = manager.add_evidence(kind="external", locator="urn:candidate", issue_id="scope")["evidence_id"]
        package = manager.context_maintenance.prepare("scope", evidence_ids=[evidence_id])
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.propose")
        view = manager.context_maintenance.create_view(package["package_id"], auth=auth, idempotency_key="candidate-view")
        assert any(item["kind"] == "candidate" and item["id"] == evidence_id
                   for item in view["summary"]["catalog"])
        expanded = manager.context_maintenance.entry(view["view_id"], "candidate", evidence_id, auth=auth)
        assert expanded["id"] == evidence_id
    finally:
        manager.close()




def test_scoped_v2_context_exposes_current_projection_partitions(tmp_path):
    manager = IssueManager.initialize(tmp_path / "context", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scoped v2 context")
        evidence_id = manager.add_evidence(kind="external", locator="urn:context", issue_id="scope")["evidence_id"]
        context_auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "context.read")
        result = manager.context("scope", "handoff", auth=context_auth)
        assert result["scoped_context"]["roots"] == []
        assert evidence_id in result["scoped_context"]["discovery_ids"]
    finally:
        manager.close()


def test_scoped_v2_context_rejects_platform_principal_without_candidate_access(tmp_path):
    manager = IssueManager.initialize(tmp_path / "permission", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scoped v2 permission")
        manager.add_evidence(kind="external", locator="urn:private-candidate", issue_id="scope")
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "context.read")
        platform_auth = replace(auth, platform_id="unrelated-platform")
        with pytest.raises(PermissionError):
            manager.context_maintenance.current_scoped_projection("scope", auth=platform_auth)
    finally:
        manager.close()


def test_scoped_v2_d_only_projection_ignores_unrelated_history_but_finds_new_attack(tmp_path):
    manager = IssueManager.initialize(tmp_path / "d-only", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scoped v2 D only")
        a = manager.add_evidence(kind="external", locator="urn:a", issue_id="scope")["evidence_id"]
        d = manager.add_evidence(kind="external", locator="urn:d", issue_id="scope")["evidence_id"]
        c = manager.add_evidence(kind="external", locator="urn:c")["evidence_id"]
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.record")
        read = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "context.read")
        write = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "evidence.relation.write")
        package = manager.context_maintenance.prepare("scope", evidence_ids=[d])
        view = manager.context_maintenance.create_view(package["package_id"], auth=auth, idempotency_key="d-view")
        manager.record_working_conclusion(
            {"issue_id": "scope", "expected_current_conclusion_id": None,
             "expected_conclusion_revision": 0, "package_id": package["package_id"],
             "view_id": view["view_id"], "statement": "D", "evidence_refs": [d],
             "reason": "independent D"}, auth=auth, idempotency_key="d-conclusion",
        )
        baseline = manager.context_maintenance.prepare("scope")
        assert baseline["actual_input"]["materials"]["support_ids"] == [d]
        source = manager.scoped_evidence_relations.binding(c, auth=read)["token"]
        target = manager.scoped_evidence_relations.binding(a, auth=read)["token"]
        manager.scoped_evidence_relations.create(
            scope_issue_id="scope", source_evidence_id=c, target_evidence_id=a,
            relation_type="refutes", rationale="unrelated A history", auth=write,
            expected_source_token=source, expected_target_token=target, idempotency_key="attack-a",
        )
        unrelated = manager.context_maintenance.prepare("scope")
        assert unrelated["actual_input"]["materials"]["support_ids"] == [d]
        assert unrelated["actual_input"]["comparison_context"] == baseline["actual_input"]["comparison_context"]
        source = manager.scoped_evidence_relations.binding(c, auth=read)["token"]
        target = manager.scoped_evidence_relations.binding(d, auth=read)["token"]
        manager.scoped_evidence_relations.create(
            scope_issue_id="scope", source_evidence_id=c, target_evidence_id=d,
            relation_type="refutes", rationale="new attack on D", auth=write,
            expected_source_token=source, expected_target_token=target, idempotency_key="attack-d",
        )
        attacked = manager.context_maintenance.prepare("scope")
        materials = attacked["actual_input"]["materials"]
        assert materials["support_ids"] == []
        assert materials["gap"][0]["node_id"] == d
    finally:
        manager.close()


def test_cross_issue_qualification_closure_and_new_attacker_subscriptions_over_http(tmp_path):
    ledger = tmp_path / "cross-issue-http"
    manager = IssueManager.initialize(ledger, context_rule="scoped-v2")
    manager.create_issue("parent", "sample", "Parent")
    for issue_id in ("claim", "basis", "challenge", "reply"):
        manager.create_issue(issue_id, "investigation", issue_id,
                             parent_issue_id="parent")
    a = manager.add_evidence(kind="external", locator="urn:cross:a", issue_id="claim")["evidence_id"]
    b = manager.add_evidence(kind="external", locator="urn:cross:b", issue_id="basis")["evidence_id"]
    same_b = manager.add_evidence(kind="external", locator="urn:cross:b", issue_id="claim")["evidence_id"]
    assert same_b == b
    c = manager.add_evidence(kind="external", locator="urn:cross:c", issue_id="challenge")["evidence_id"]
    e = manager.add_evidence(kind="external", locator="urn:cross:e", issue_id="reply")["evidence_id"]
    token = json.loads((ledger / "credentials" / "organizer-agent.token").read_text(encoding="utf-8"))["token"]
    manager.close()
    try:
        with ManagerService(ledger, port=0) as service:
            client = WorkflowClient(f"http://{service.address[0]}:{service.address[1]}", token)

            def relation(scope, source, target, kind, key):
                source_token = client.scoped_relation_binding(source)["token"]
                target_token = client.scoped_relation_binding(target)["token"]
                return client.create_scoped_relation({
                    "scope_issue_id": scope, "source_evidence_id": source,
                    "target_evidence_id": target, "relation_type": kind,
                    "rationale": "cross-Issue test evidence", "expected_source_token": source_token,
                    "expected_target_token": target_token,
                }, idempotency_key=key)

            relation("basis", b, a, "depends_on", "cross-dependency")
            package = client.prepare_materials("basis", [b], idempotency_key="cross-package")
            materials = client.currentness_package(package["package_id"])["actual_input"]["materials"]
            statuses = {row["candidate_id"]: row["status"] for row in materials["candidate_states"]}
            assert statuses[a] == statuses[b] == "T"
            assert set(materials["support_ids"]) == {a, b}
            claim_package = client.prepare_materials("claim", [b], idempotency_key="same-evidence-other-issue")
            claim_materials = client.currentness_package(claim_package["package_id"])["actual_input"]["materials"]
            claim_statuses = {row["candidate_id"]: row["status"]
                              for row in claim_materials["candidate_states"]}
            assert claim_statuses[a] == statuses[a] and claim_statuses[b] == statuses[b]
            assert set(claim_materials["support_ids"]) == set(materials["support_ids"])
            view = client.create_view(package["package_id"], idempotency_key="cross-view")
            client.record_working_conclusion({
                "issue_id": "basis", "expected_current_conclusion_id": None,
                "expected_conclusion_revision": 0, "package_id": package["package_id"],
                "view_id": view["view_id"], "statement": "B relies on A",
                "evidence_refs": [b], "reason": "cross-issue basis",
            }, idempotency_key="cross-conclusion")
            relation("challenge", c, a, "refutes", "cross-attack")
            attacked = client.prepare_materials("basis", [b], idempotency_key="cross-attacked")
            materials = client.currentness_package(attacked["package_id"])["actual_input"]["materials"]
            statuses = {row["candidate_id"]: row["status"] for row in materials["candidate_states"]}
            assert statuses[a] == statuses[b] == "F"
            assert client.inspect_issue("basis")["issue"]["freshness"] == "stale"
            relation("reply", e, c, "refutes", "cross-attack-reply")
            recovered = client.prepare_materials("basis", [b], idempotency_key="cross-recovered")
            materials = client.currentness_package(recovered["package_id"])["actual_input"]["materials"]
            statuses = {row["candidate_id"]: row["status"] for row in materials["candidate_states"]}
            assert statuses[a] == statuses[b] == "T"
            # Qualification recovery does not rewrite the frozen basis comparison.
            assert client.inspect_issue("basis")["issue"]["freshness"] == "stale"
    finally:
        manager = IssueManager(ledger)
        manager.close()


def test_scoped_v2_relation_withdrawal_and_restore_recompute_the_same_root(tmp_path):
    manager = IssueManager.initialize(tmp_path / "relation-recompute", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scoped v2 relation recompute")
        target = manager.add_evidence(kind="external", locator="urn:target", issue_id="scope")["evidence_id"]
        source = manager.add_evidence(kind="external", locator="urn:source")["evidence_id"]
        read = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "context.read")
        write = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "evidence.relation.write")
        relation = manager.scoped_evidence_relations.create(
            scope_issue_id="scope", source_evidence_id=source, target_evidence_id=target,
            relation_type="refutes", rationale="recompute", auth=write,
            expected_source_token=manager.scoped_evidence_relations.binding(source, auth=read)["token"],
            expected_target_token=manager.scoped_evidence_relations.binding(target, auth=read)["token"],
            idempotency_key="recompute-create",
        )
        attacked = manager.context_maintenance.prepare("scope", evidence_ids=[target])
        assert attacked["actual_input"]["materials"]["support_ids"] == []
        withdrawn = manager.scoped_evidence_relations.deactivate(
            relation["relation_id"], expected_version_id=relation["version_id"], reason="withdraw",
            auth=write, idempotency_key="recompute-withdraw",
        )
        after_withdraw = manager.context_maintenance.prepare("scope", evidence_ids=[target])
        assert after_withdraw["actual_input"]["materials"]["support_ids"] == [target]
        restored = manager.scoped_evidence_relations.reactivate(
            relation["relation_id"], expected_version_id=withdrawn["version_id"], reason="restore",
            auth=write, idempotency_key="recompute-restore",
        )
        assert restored["active"] is True
        withdrawn_package = manager.context_maintenance.prepare("scope", evidence_ids=[target])
        assert withdrawn_package["actual_input"]["materials"]["support_ids"] == []
    finally:
        manager.close()


def test_scoped_v2_http_prepare_view_record_and_idempotent_replay(tmp_path):
    ledger = tmp_path / "http-chain"
    manager = IssueManager.initialize(ledger, context_rule="scoped-v2")
    manager.create_issue("scope", "investigation", "Scoped v2 HTTP chain")
    evidence_id = manager.add_evidence(kind="external", locator="urn:http-chain", issue_id="scope")["evidence_id"]
    token = json.loads(
        (ledger / "credentials" / "organizer-agent.token").read_text(encoding="utf-8")
    )["token"]
    manager.close()
    try:
        with ManagerService(ledger, port=0) as service:
            client = WorkflowClient(f"http://{service.address[0]}:{service.address[1]}", token)
            package = client.prepare_materials("scope", [evidence_id], idempotency_key="http-prepare")
            view = client.create_view(package["package_id"], idempotency_key="http-view")
            inspected = client.inspect_issue("scope")
            request = {
                "issue_id": "scope", "expected_current_conclusion_id": None,
                "expected_conclusion_revision": inspected["issue"]["conclusion_revision"],
                "package_id": package["package_id"], "view_id": view["view_id"],
                "statement": "HTTP chain", "evidence_refs": [evidence_id],
                "reason": "HTTP chain root",
            }
            first = client.record_working_conclusion(request, idempotency_key="http-conclusion")
            replay = client.record_working_conclusion(request, idempotency_key="http-conclusion")
            assert replay == first
            entry = client.view_entry(view["view_id"], "candidate", evidence_id)
            assert entry["id"] == evidence_id
            current = client.prepare_materials("scope", None, idempotency_key="http-current")
            assert current["descriptor"]["seed_evidence_ids"] == [evidence_id]
            discovery = client.prepare_materials("scope", [], idempotency_key="http-discovery")
            assert discovery["descriptor"]["seed_evidence_ids"] == []
    finally:
        manager = IssueManager(ledger)
        manager.close()


def test_scoped_v2_preview_budget_rejects_before_returning_a_partial_graph(tmp_path):
    manager = IssueManager.initialize(tmp_path / "budget", context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Scoped v2 budget")
        target = manager.add_evidence(kind="external", locator="urn:budget-target", issue_id="scope")["evidence_id"]
        source = manager.add_evidence(kind="external", locator="urn:budget-source")["evidence_id"]
        read = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "context.read")
        write = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "evidence.relation.write")
        manager.scoped_evidence_relations.create(
            scope_issue_id="scope", source_evidence_id=source, target_evidence_id=target,
            relation_type="refutes", rationale="budget", auth=write,
            expected_source_token=manager.scoped_evidence_relations.binding(source, auth=read)["token"],
            expected_target_token=manager.scoped_evidence_relations.binding(target, auth=read)["token"],
            idempotency_key="budget-relation",
        )
        with pytest.raises(ValidationError):
            manager.scoped_evidence_relations.preview_selection(
                scope_issue_id="scope", seed_evidence_ids=[target], maximum_nodes=1,
                maximum_relations=10, auth=read,
            )
        assert manager.store.row(
            "SELECT COUNT(*) AS count FROM scoped_evidence_relation_heads"
        )["count"] == 1
    finally:
        manager.close()


def test_http_prepare_defaults_to_current_conclusion_roots(tmp_path):
    ledger = tmp_path / "default-roots-http"
    manager = IssueManager.initialize(ledger, context_rule="scoped-v2")
    try:
        manager.create_issue("scope", "investigation", "Default roots")
        adopted = manager.add_evidence(kind="external", locator="urn:adopted", issue_id="scope")["evidence_id"]
        other = manager.add_evidence(kind="external", locator="urn:unadopted", issue_id="scope")["evidence_id"]
        auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "conclusion.record")
        package = manager.context_maintenance.prepare("scope", evidence_ids=[adopted])
        view = manager.context_maintenance.create_view(package["package_id"], auth=auth, idempotency_key="view")
        manager.record_working_conclusion({"issue_id": "scope", "expected_current_conclusion_id": None,
            "expected_conclusion_revision": 0, "package_id": package["package_id"], "view_id": view["view_id"],
            "statement": "adopted", "evidence_refs": [adopted], "reason": "root"},
            auth=auth, idempotency_key="conclusion")
        token = json.loads(manager.credentials.path_for("organizer-agent").read_text(encoding="utf-8"))["token"]
    finally:
        manager.close()
    with ManagerService(ledger, port=0) as service:
        client = WorkflowClient(f"http://{service.address[0]}:{service.address[1]}", token)
        context = client.inspect_issue("scope")["scoped_context"]
        assert context["support_ids"] == [adopted]
        assert other in context["discovery_ids"]
        prepared = client.prepare_materials("scope", idempotency_key="default-prepare")
        assert prepared["descriptor"]["seed_evidence_ids"] == [adopted]
        assert other not in prepared["descriptor"]["seed_evidence_ids"]
