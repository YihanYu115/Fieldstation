from __future__ import annotations

import hashlib

import pytest

from issue_manager import IssueManager
from issue_manager.errors import ConflictError, ValidationError
from issue_manager.store import Store, new_id, now

ATTACHMENT = "project-record:原件/😀"


@pytest.fixture
def inbox(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    manager.create_issue("scope", "investigation", "Scope")
    manager.credentials.issue_actor(actor_id="curator", actor_kind="organizer_agent",
        capabilities={"context.read", "evidence.write", "evidence.relation.write"},
        maintenance_credential=manager.credentials.path_for("maintenance-agent"))
    auth = manager.credentials.resolve(manager.credentials.path_for("curator"), "evidence.write")
    raw = "Observation A. Calculation B."
    packet_id = new_id("fp")
    content_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    request_hash = hashlib.sha256(b"{}").hexdigest()
    timestamp = now()
    with manager.store.transaction() as conn:
        conn.execute("INSERT INTO field_packets(packet_id,request_id,issue_id,content,content_sha256,request_payload_sha256,sources_json,attachment_refs_json,created_at,created_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (packet_id, "intake", "scope", raw, content_hash, request_hash,
             '[{"locator":"project:embedded","provided_text":"前缀\\r\\nUnique😀"}]',
             '["project-record:原件/😀"]', timestamp, auth.actor_id))
        conn.execute("INSERT INTO field_packet_curation_heads VALUES (?,0,?)", (packet_id, timestamp))
    yield manager, auth, packet_id
    manager.close()


def _payload(packet_id, *, expected=0, related=(), attachment=False):
    origin = {"type": "packet_text", "quoted_text": "Observation A.", "start": 0}
    if attachment:
        origin = {"type": "attachment", "attachment_ref": ATTACHMENT, "part_locator": "rows 2-3",
                  "quoted_text": "声明 e\u0301😀\r\n下一行"}
    return {"packet_id": packet_id, "issue_id": "scope", "expected_curation_version": expected,
        "description": "Observation A.", "kind": "observation", "origin": origin,
        "source_locator": ATTACHMENT if attachment else f"im-field-packet:{packet_id}#content", "reason": "curator selected A",
        "related_evidence": list(related)}


def _counts(manager):
    return {table: manager.store.row(f"SELECT COUNT(*) AS n FROM {table}")["n"] for table in (
        "field_facts", "issue_evidence", "evidence_refs", "scoped_evidence_relation_versions",
        "field_fact_mapping_versions", "field_fact_mapping_heads", "field_packet_reviews", "audit_events", "domain_events")}


@pytest.mark.parametrize("point", ["field_curate.after_fact", "field_curate.after_evidence",
    "field_curate.after_relations", "field_curate.after_mapping", "field_curate.after_head"])
@pytest.mark.parametrize("attachment", [False, True])
def test_curated_item_fault_windows_rollback_and_retry_once(inbox, point, attachment):
    manager, auth, packet_id = inbox
    provider = manager.add_evidence(kind="report", locator="run://provider", issue_id="scope")["evidence_id"]
    related = [{"target_kind": "evidence_id", "target_ref": provider,
                "relation_type": "derived_from", "rationale": "explicitly named source"}]
    baseline = _counts(manager)
    issue = manager.store.row("SELECT freshness,current_conclusion_id,conclusion_revision FROM issues WHERE issue_id='scope'")
    called = False
    original = manager.store.fault_injector
    def fail_once(current):
        nonlocal called
        if current == point and not called:
            called = True
            raise RuntimeError("injected write-window failure")
        if original:
            original(current)
    manager.store.fault_injector = fail_once
    with pytest.raises(RuntimeError, match="injected"):
        manager.curate_field_item(**_payload(packet_id, related=related, attachment=attachment), auth=auth,
            idempotency_key=f"retry-{point}", request_id=f"request-{point}")
    assert _counts(manager) == baseline
    assert manager.store.row("SELECT version FROM field_packet_curation_heads WHERE packet_id=?", (packet_id,))["version"] == 0
    assert manager.store.row("SELECT freshness,current_conclusion_id,conclusion_revision FROM issues WHERE issue_id='scope'") == issue
    manager.store.fault_injector = None
    result = manager.curate_field_item(**_payload(packet_id, related=related, attachment=attachment), auth=auth,
        idempotency_key=f"retry-{point}", request_id=f"request-{point}")
    replay = manager.curate_field_item(**_payload(packet_id, related=related, attachment=attachment), auth=auth,
        idempotency_key=f"retry-{point}", request_id=f"request-{point}")
    assert replay["fact_ref"] == result["fact_ref"] and replay["idempotent_replay"]
    assert result["atomic"] is True and len(result["relation_ids"]) == 1
    assert manager.store.row("SELECT COUNT(*) AS n FROM field_facts WHERE packet_id=?", (packet_id,))["n"] == 1


@pytest.mark.parametrize("point", ["field_review.after_receipt", "field_review.after_head"])
@pytest.mark.parametrize("attachment", [False, True])
def test_review_fault_windows_rollback_and_retry_once(inbox, point, attachment):
    manager, auth, packet_id = inbox
    baseline = _counts(manager)
    unresolved = [{"origin": _payload(packet_id, attachment=True)["origin"], "reason": "原件未挂载"}] if attachment else []
    called = False
    def fail_once(current):
        nonlocal called
        if current == point and not called:
            called = True
            raise RuntimeError("injected review failure")
    manager.store.fault_injector = fail_once
    with pytest.raises(RuntimeError, match="injected"):
        manager.record_field_review(packet_id=packet_id, issue_id="scope", expected_curation_version=0,
            handled_fact_refs=[], unresolved=unresolved, reason="handoff", auth=auth,
            idempotency_key=f"review-{point}", request_id=f"review-request-{point}")
    assert _counts(manager) == baseline
    assert manager.store.row("SELECT version FROM field_packet_curation_heads WHERE packet_id=?", (packet_id,))["version"] == 0
    manager.store.fault_injector = None
    result = manager.record_field_review(packet_id=packet_id, issue_id="scope", expected_curation_version=0,
        handled_fact_refs=[], unresolved=unresolved, reason="handoff", auth=auth,
        idempotency_key=f"review-{point}", request_id=f"review-request-{point}")
    assert result["curation_version"] == 1
    replay = manager.record_field_review(packet_id=packet_id, issue_id="scope", expected_curation_version=0,
        handled_fact_refs=[], unresolved=unresolved, reason="handoff", auth=auth,
        idempotency_key=f"review-{point}", request_id=f"review-request-{point}")
    assert replay["review_id"] == result["review_id"] and replay["idempotent_replay"]
    assert manager.store.row("SELECT COUNT(*) AS n FROM field_packet_reviews WHERE packet_id=?", (packet_id,))["n"] == 1


def test_mapped_fact_can_be_a_relation_target_and_replay_is_single_write(inbox):
    manager, auth, packet_id = inbox
    first = manager.curate_field_item(**_payload(packet_id), auth=auth,
        idempotency_key="first", request_id="first")
    second_payload = _payload(packet_id, expected=1, related=[{"target_kind": "fact_ref",
        "target_ref": first["fact_ref"], "relation_type": "depends_on", "rationale": "necessary premise"}])
    second_payload["description"] = "Calculation B."
    second_payload["kind"] = "interpretation"
    second_payload["origin"] = {"type": "packet_text", "quoted_text": "Calculation B.", "start": 15}
    second = manager.curate_field_item(**second_payload, auth=auth,
        idempotency_key="second", request_id="second")
    replay = manager.curate_field_item(**second_payload, auth=auth,
        idempotency_key="second", request_id="second")
    assert replay["fact_ref"] == second["fact_ref"] and replay["idempotent_replay"] is True
    assert manager.store.row("SELECT COUNT(*) AS n FROM field_facts WHERE packet_id=?", (packet_id,))["n"] == 2
    assert second["relation_ids"]


def test_relation_targets_may_be_external_but_fact_refs_must_be_mapped(inbox):
    manager, auth, packet_id = inbox
    manager.create_issue("other", "investigation", "Other scope")
    foreign = manager.add_evidence(kind="report", locator="run://foreign", issue_id="other")["evidence_id"]
    curated = manager.curate_field_item(**_payload(packet_id, related=[{"target_kind": "evidence_id",
        "target_ref": foreign, "relation_type": "depends_on", "rationale": "explicit"}]),
        auth=auth, idempotency_key="foreign-target", request_id="foreign-target")
    relation = manager.scoped_evidence_relations.show(curated["relation_ids"][0], auth=auth)
    assert relation["scope_issue_id"] == "scope"
    assert relation["target_evidence_id"] == foreign
    assert manager.store.row("SELECT COUNT(*) AS n FROM issue_evidence WHERE issue_id='scope' AND evidence_id=?",
                             (foreign,))["n"] == 0
    after_success = _counts(manager)
    orphan_ref = new_id("fact")
    timestamp = now()
    with manager.store.transaction() as conn:
        conn.execute("INSERT INTO field_facts(fact_ref,packet_id,issue_id,description,kind,origin_json,source_locator,created_at,created_by) VALUES (?,?,?,?,?,?,?,?,?)",
            (orphan_ref, packet_id, "scope", "legacy unmapped", "observation", "{}", "run://source", timestamp, auth.actor_id))
    with pytest.raises(ConflictError, match="no Evidence mapping"):
        manager.curate_field_item(**_payload(packet_id, expected=1, related=[{"target_kind": "fact_ref",
            "target_ref": orphan_ref, "relation_type": "depends_on", "rationale": "explicit"}]),
            auth=auth, idempotency_key="unmapped-target", request_id="unmapped-target")
    assert manager.store.row("SELECT COUNT(*) AS n FROM field_facts WHERE packet_id=?", (packet_id,))["n"] == 2
    assert manager.store.row("SELECT version FROM field_packet_curation_heads WHERE packet_id=?", (packet_id,))["version"] == 1
    # Foreign Evidence was created before the baseline; each failed packet operation adds nothing.
    assert manager.store.row("SELECT COUNT(*) AS n FROM field_fact_mapping_versions")["n"] == after_success["field_fact_mapping_versions"]
    assert manager.store.row("SELECT COUNT(*) AS n FROM issue_evidence")["n"] == after_success["issue_evidence"]
    assert manager.store.row("SELECT COUNT(*) AS n FROM scoped_evidence_relation_versions")["n"] == after_success["scoped_evidence_relation_versions"]


def test_domain_service_validates_packet_origin_even_without_http(inbox):
    manager, auth, packet_id = inbox
    before = _counts(manager)
    wrong_locator = {**_payload(packet_id), "source_locator": "run://not-in-packet"}
    with pytest.raises(ValidationError, match="source locator"):
        manager.curate_field_item(**wrong_locator, auth=auth,
            idempotency_key="wrong-source", request_id="wrong-source")
    wrong_quote = {**_payload(packet_id),
                   "origin": {"type": "packet_text", "quoted_text": "Absent text."}}
    with pytest.raises(ValidationError, match="not present"):
        manager.curate_field_item(**wrong_quote, auth=auth,
            idempotency_key="wrong-origin", request_id="wrong-origin")
    with pytest.raises(ValidationError, match="not present"):
        manager.record_field_review(packet_id=packet_id, issue_id="scope",
            expected_curation_version=0, handled_fact_refs=[],
            unresolved=[{"origin": {"type": "packet_text", "quoted_text": "Absent text."},
                         "reason": "unclear"}], reason="handoff", auth=auth,
            idempotency_key="wrong-review-origin", request_id="wrong-review-origin")
    assert _counts(manager) == before


@pytest.mark.parametrize("state", [False, True, 0, None])
def test_direct_service_rejects_client_attachment_state_and_rechecks_internal_marker(inbox, state):
    from issue_manager.field_origin import resolve_origin

    manager, auth, packet_id = inbox
    payload = _payload(packet_id, attachment=True)
    before = _counts(manager)
    payload["origin"] = {**payload["origin"], "local_position_verified": state}
    with pytest.raises(ValidationError, match="server-only"):
        manager.curate_field_item(**payload, auth=auth, idempotency_key="forged", request_id="forged")
    with pytest.raises(ValidationError, match="server-only"):
        manager.record_field_review(packet_id=packet_id, issue_id="scope", expected_curation_version=0,
            handled_fact_refs=[], unresolved=[{"origin": payload["origin"], "reason": "gap"}], reason="gap",
            auth=auth, idempotency_key="forged-review", request_id="forged-review")
    raw = _payload(packet_id, attachment=True)["origin"]
    normalized, _ = resolve_origin({"attachment_refs": [ATTACHMENT]}, raw)
    normalized["attachment_ref"] = "project:foreign"
    payload["origin"] = normalized
    with pytest.raises(ValidationError, match="exactly match"):
        manager.curate_field_item(**payload, auth=auth, idempotency_key="internal-foreign", request_id="internal-foreign")
    normalized["attachment_ref"] = ATTACHMENT
    normalized["local_position_verified"] = True
    with pytest.raises(ValidationError, match="unverified"):
        manager.curate_field_item(**payload, auth=auth, idempotency_key="internal-verified", request_id="internal-verified")
    assert _counts(manager) == before


def test_inner_idempotency_retains_legacy_normalized_text_payloads(inbox):
    """Exercise domain replay independently of the HTTP request cache, with old inferred start."""
    import json

    from issue_manager.field_origin import resolve_origin
    from issue_manager.store import canonical_json

    manager, auth, packet_id = inbox
    packet = {"packet_id": packet_id, "content": "Observation A. Calculation B.",
              "sources": [{"locator": "project:embedded", "provided_text": "前缀\r\nUnique😀"}],
              "attachment_refs": [ATTACHMENT]}
    for index, raw in enumerate([{"type": "packet_text", "quoted_text": "Observation A."},
                                 {"type": "source_text", "source_index": 0, "quoted_text": "Unique😀"}]):
        normalized, locator = resolve_origin(packet, raw)
        expected = {**raw, "start": 0 if index == 0 else 4}
        assert normalized == expected
        payload = {**_payload(packet_id, expected=index), "origin": expected, "source_locator": locator}
        result = manager.curate_field_item(**payload, auth=auth, idempotency_key=f"legacy-{index}", request_id=f"legacy-{index}")
        # The stored domain digest uses exactly the previous API normalized shape.
        stored = manager.store.row("SELECT request_hash FROM request_idempotency WHERE idempotency_key=?", (f"legacy-{index}",))
        assert stored["request_hash"] == hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        replay = manager.curate_field_item(**{**payload, "origin": normalized}, auth=auth,
            idempotency_key=f"legacy-{index}", request_id=f"legacy-{index}")
        assert replay["fact_ref"] == result["fact_ref"] and replay["idempotent_replay"]
        with pytest.raises(ConflictError):
            manager.curate_field_item(**{**payload, "description": "different"}, auth=auth,
                idempotency_key=f"legacy-{index}", request_id=f"legacy-{index}")
    origin, _ = resolve_origin(packet, {"type": "source_text", "source_index": 0, "quoted_text": "Unique😀"})
    unresolved = [{"origin": dict(origin), "reason": "legacy gap"}]
    review = manager.record_field_review(packet_id=packet_id, issue_id="scope", expected_curation_version=2,
        handled_fact_refs=[], unresolved=unresolved, reason="legacy", auth=auth,
        idempotency_key="legacy-review", request_id="legacy-review")
    again = manager.record_field_review(packet_id=packet_id, issue_id="scope", expected_curation_version=2,
        handled_fact_refs=[], unresolved=unresolved, reason="legacy", auth=auth,
        idempotency_key="legacy-review", request_id="legacy-review")
    assert again["review_id"] == review["review_id"]
    row = manager.store.row("SELECT unresolved_json FROM field_packet_reviews WHERE review_id=?", (review["review_id"],))
    assert json.loads(row["unresolved_json"]) == unresolved


def test_direct_forged_false_cannot_hit_internal_normalized_replay(inbox):
    from issue_manager.field_origin import resolve_origin

    manager, auth, packet_id = inbox
    payload = _payload(packet_id, attachment=True)
    origin, _ = resolve_origin({"attachment_refs": [ATTACHMENT]}, payload["origin"])
    payload["origin"] = origin
    manager.curate_field_item(**payload, auth=auth, idempotency_key="http-shape", request_id="http-shape")
    before = _counts(manager)
    with pytest.raises(ValidationError, match="server-only"):
        manager.curate_field_item(**{**payload, "origin": dict(origin)}, auth=auth,
                                  idempotency_key="http-shape", request_id="http-shape")
    review_payload = dict(packet_id=packet_id, issue_id="scope", expected_curation_version=1,
                         handled_fact_refs=[], unresolved=[{"origin": origin, "reason": "gap"}], reason="gap")
    manager.record_field_review(**review_payload, auth=auth, idempotency_key="http-review-shape", request_id="http-review-shape")
    review_before = _counts(manager)
    with pytest.raises(ValidationError, match="server-only"):
        manager.record_field_review(**{**review_payload, "unresolved": [{"origin": dict(origin), "reason": "gap"}]},
            auth=auth, idempotency_key="http-review-shape", request_id="http-review-shape")
    assert _counts(manager) == review_before and review_before["field_facts"] == before["field_facts"]


def test_v4_backup_restore_preserves_packet_items_mapping_and_review(tmp_path):
    ledger = tmp_path / "restore-ledger"
    manager = IssueManager.initialize(ledger)
    manager.create_issue("scope", "investigation", "Scope")
    manager.credentials.issue_actor(actor_id="curator", actor_kind="organizer_agent",
        capabilities={"context.read", "evidence.write", "evidence.relation.write"},
        maintenance_credential=manager.credentials.path_for("maintenance-agent"))
    auth = manager.credentials.resolve(manager.credentials.path_for("curator"), "evidence.write")
    packet_id = new_id("fp")
    raw = "Observation A."
    timestamp = now()
    with manager.store.transaction() as conn:
        conn.execute("INSERT INTO field_packets(packet_id,request_id,issue_id,content,content_sha256,request_payload_sha256,sources_json,attachment_refs_json,created_at,created_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (packet_id, "receive", "scope", raw, hashlib.sha256(raw.encode()).hexdigest(), "digest", "[]", "[]", timestamp, auth.actor_id))
        conn.execute("INSERT INTO field_packet_curation_heads VALUES (?,0,?)", (packet_id, timestamp))
    fact = manager.curate_field_item(**_payload(packet_id), auth=auth, idempotency_key="curate", request_id="curate")
    review = manager.record_field_review(packet_id=packet_id, issue_id="scope", expected_curation_version=1,
        handled_fact_refs=[fact["fact_ref"]], unresolved=[], reason="complete handoff", auth=auth,
        idempotency_key="review", request_id="review")
    backup = Store.create_backup(ledger, label="field-v4-roundtrip", mode="full")
    manager.close()
    restored = Store.restore_backup(ledger, backup["backup_id"])
    assert restored["schema_version"] == 10
    manager = IssueManager(ledger)
    try:
        assert manager.store.row("SELECT version FROM field_packet_curation_heads WHERE packet_id=?", (packet_id,))["version"] == 2
        assert manager.store.row("SELECT evidence_id FROM field_fact_mapping_versions WHERE fact_ref=?", (fact["fact_ref"],))["evidence_id"] == fact["evidence_id"]
        assert manager.store.row("SELECT review_id FROM field_packet_reviews WHERE packet_id=?", (packet_id,))["review_id"] == review["review_id"]
    finally:
        manager.close()
