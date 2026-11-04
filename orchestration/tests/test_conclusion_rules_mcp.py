import pytest
from im_tools_harness import IMMCP, IMService


@pytest.fixture
def service(tmp_path):
    instance = IMService(tmp_path / "im")
    try:
        yield instance
    finally:
        instance.stop()


def test_strict_rule_discovery_and_independent_session(service):
    schema = {"type": "object", "properties": {"result": {"type": "string"}},
              "required": ["result"], "additionalProperties": False}
    with IMMCP(service, "curator") as manager:
        assert manager.call("list_issue_types", {})["items"]
        root = manager.call("save_contribution", {"kind": "observation", "source": "urn:test:rule",
            "text": "Observed.", "reason": "Evidence."})["evidence"]["evidence_id"]
        assert manager.call("read_conclusion_rule", {})["revision"] == 0
        previous = manager.call("save_working_conclusion", {"statement": "Earlier result", "evidence_ids": [root],
            "reason": "Evidence", "confidence": "low"})
        assert previous["revision_number"] == 1
        changed = manager.call("set_conclusion_rule", {"schema": schema, "reason": "Result required"})
        assert changed["revision"] == 1
        failure = manager.call("save_working_conclusion", {"statement": "Observed result", "evidence_ids": [root],
            "reason": "Evidence", "confidence": "low"})
        assert failure["error"]["effect"] == "not_committed"
        assert failure["error"]["details"]["field_errors"][0]["code"] == "required"
        invalid = manager.call("save_working_conclusion", {"statement": "Observed result", "evidence_ids": [root],
            "reason": "Evidence", "confidence": "low", "structured_outputs": {"result": "ok", "extra": 1}})
        assert invalid["error"]["details"]["field_errors"][0]["code"] == "unknown"
        many = {"result": "ok", **{f"extra{i}": i for i in range(40)}}
        invalid_many = manager.call("save_working_conclusion", {"statement": "Observed result", "evidence_ids": [root],
            "reason": "Evidence", "confidence": "low", "structured_outputs": many})
        assert invalid_many["error"]["details"]["fields_truncated"] is True
        assert invalid_many["error"]["details"]["error_count"] == 40
    with IMMCP(service, "reader") as reader:
        refused = reader.call("set_conclusion_rule", {"schema": schema, "reason": "No write permission"})
        assert refused["error"]["effect"] == "not_committed"
    profile = service.profile("curator", suffix="-new-session")
    with IMMCP(service, "curator", profile=profile) as conclusion:
        assert conclusion.call("read_conclusion_rule", {})["schema"] == schema
        before = conclusion.call("inspect_issue", {})
        assert before["current_conclusion"]["current_rule_comparison"]["valid"] is False
        history = conclusion.call("list_conclusion_history", {})
        assert history["items"][0]["applied_rule"]["revision"] == 0
        result = conclusion.call("save_working_conclusion", {"statement": "Observed result", "evidence_ids": [root],
            "reason": "Evidence", "confidence": "low", "structured_outputs": {"result": "observed"}})
        assert result["revision_number"] == 2
        assert conclusion.call("inspect_issue", {})["current_conclusion"]["applied_rule"]["revision"] == 1


def test_rule_lost_response_recovers_original_after_later_update(service):
    from im_transport_harness import FaultProxy

    with FaultProxy(service) as proxy:
        profile = service.profile("curator", endpoint=proxy.endpoint, suffix="-rule-recovery")
        with IMMCP(service, "curator", profile=profile) as first:
            proxy.inject("drop", path_suffix="/conclusion-rules/issue/A")
            lost = first.call("set_conclusion_rule", {"schema": {"type": "object"}, "reason": "First rule"})
            assert lost["error"]["effect"] == "unknown"
            delivery = lost["error"]["operation_id"]
        other = service.tools("curator", suffix="-later")
        later = other.call("set_conclusion_rule", {"schema": {"type": "object", "properties": {"x": {"type": "string"}}},
                                                   "reason": "Second rule"})
        assert later["revision"] == 2
        with IMMCP(service, "curator", profile=profile) as rebuilt:
            recovered = rebuilt.call("recover_delivery", {"delivery_id": delivery})
            assert recovered["revision"] == 1
            assert rebuilt.call("read_conclusion_rule", {})["revision"] == 2
        attempts = [e for e in proxy.events() if e["path"].endswith("/conclusion-rules/issue/A") and e.get("method") == "POST"]
        assert len(attempts) == 2
        for key in ("request_id", "idempotency_key", "body", "path"):
            assert attempts[0][key] == attempts[1][key]


def test_conclusion_lost_response_recovers_after_rule_change(service):
    from im_transport_harness import FaultProxy

    setup = service.tools("curator", suffix="-setup")
    root = setup.call("save_contribution", {"kind": "observation", "source": "urn:test:lost-conclusion",
        "text": "Observed.", "reason": "Evidence."})["evidence"]["evidence_id"]
    schema = {"type": "object", "properties": {"result": {"type": "string"}}, "required": ["result"]}
    assert setup.call("set_conclusion_rule", {"schema": schema, "reason": "First rule"})["revision"] == 1
    with FaultProxy(service) as proxy:
        profile = service.profile("curator", endpoint=proxy.endpoint, suffix="-lost-working-rule")
        with IMMCP(service, "curator", profile=profile) as first:
            proxy.inject("drop", path_suffix="/working-conclusion")
            lost = first.call("save_working_conclusion", {"statement": "Original conclusion", "evidence_ids": [root],
                "reason": "Evidence", "confidence": "low", "structured_outputs": {"result": "ok"}})
            assert lost["error"]["effect"] == "unknown"
            delivery = lost["error"]["operation_id"]
        second = {"type": "object", "properties": {"other": {"type": "string"}}, "required": ["other"]}
        assert setup.call("set_conclusion_rule", {"schema": second, "reason": "Next rule"})["revision"] == 2
        with IMMCP(service, "curator", profile=profile) as rebuilt:
            recovered = rebuilt.call("recover_delivery", {"delivery_id": delivery})
            assert recovered["revision_number"] == 1
            current = rebuilt.call("inspect_issue", {})
            assert current["current_conclusion"]["applied_rule"]["revision"] == 1
            assert current["current_conclusion"]["current_rule_comparison"]["valid"] is False
        attempts = [event for event in proxy.events() if event["path"].endswith("/working-conclusion")]
        assert len(attempts) == 2
        for key in ("request_id", "idempotency_key", "body", "path"):
            assert attempts[0][key] == attempts[1][key]
