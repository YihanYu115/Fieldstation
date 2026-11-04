from __future__ import annotations

import json

import pytest
from workflow_orchestrator.mcp_contract import (
    CONTRACT_VERSION,
    MAX_RESULT_BYTES,
    ContractError,
    connection_info,
    definitions,
    failure,
    response,
    validate,
)


def test_schema_validation_points_to_array_item_and_escapes_json_pointer():
    schema = {"type": "object", "properties": {"rows/~": {"type": "array", "items": {
        "type": "object", "properties": {"observed_context": {"type": "string"}},
        "required": ["observed_context"], "additionalProperties": False}},
        "related_evidence": {"type": "array"}}, "required": ["rows/~"], "additionalProperties": False}
    with pytest.raises(ContractError) as missing:
        validate([{"name": "curate", "inputSchema": schema}], "curate", {"rows/~": [{}]})
    assert missing.value.fields[0]["path"] == "/rows~1~0/0/observed_context"
    with pytest.raises(ContractError) as wrong_shape:
        validate([{"name": "curate", "inputSchema": schema}], "curate",
                 {"rows/~": [{"observed_context": "ok"}], "related_evidence": "[]"})
    assert wrong_shape.value.fields[0]["path"] == "/related_evidence"
    assert wrong_shape.value.fields[0]["expected_type"] == "array"


def test_unknown_tool_is_rejected_before_facade_and_errors_have_v2_shape():
    with pytest.raises(ContractError) as error:
        validate([], "unknown", {})
    payload = failure(error.value, operation="unknown", write=True)
    assert payload["contract_version"] == CONTRACT_VERSION
    assert payload["status"] == "needs_attention"
    assert payload["code"] == "tool_not_available"
    assert payload["effect"] == "not_committed"
    assert payload["retry_policy"] == "stop"
    normalized, serialized, is_error = response(payload, operation="unknown", write=True)
    assert is_error and json.loads(serialized) == normalized
    assert normalized["effect"] == "not_committed"




def test_tools_manifest_hash_tracks_dynamic_public_definitions_only():
    base = [{"name": "work", "description": "Read a page",
             "inputSchema": {"type": "object", "properties": {"profile": {"enum": ["local"]}},
                             "additionalProperties": False}}]
    public = definitions(base)
    info = connection_info("test", public, {"scope": "ROOT", "mode": "read"})
    assert info["tools_sha256"] == connection_info("test", public, {"scope": "ROOT"})["tools_sha256"]
    changed = definitions([{**base[0], "inputSchema": {"type": "object", "properties": {
        "profile": {"enum": ["local", "other"]}}, "additionalProperties": False}}])
    assert info["tools_sha256"] != connection_info("test", changed, {})["tools_sha256"]
    assert info["contract_version"] == CONTRACT_VERSION
    assert info["authorization_check"] == "not_performed"
    assert info["tools_hash_algorithm"].startswith("sha256(utf8(")


def test_oversized_write_receipt_keeps_delivery_identity_and_original_effect():
    committed, _, committed_error = response({"delivery_id": "delivery-committed",
        "packet_id": "packet-1", "content": "x" * (MAX_RESULT_BYTES + 1)},
        operation="submit_field_packet", write=True)
    assert committed_error is True
    assert committed["effect"] == "committed" and committed["delivery_id"] == "delivery-committed"
    assert committed["retry_policy"] == "stop"
    assert "packet-1" in committed["object_refs"].values()

    unknown, _, unknown_error = response({"contract_version": CONTRACT_VERSION,
        "status": "needs_attention", "code": "transport_error", "error": "transport_error",
        "operation": "save_working_conclusion", "layer": "transport",
        "message": "x" * (MAX_RESULT_BYTES + 1), "fields": [], "fields_truncated": False,
        "retry_policy": "recover_original", "effect": "unknown", "delivery_id": "delivery-unknown"},
        operation="save_working_conclusion", write=True)
    assert unknown_error is True
    assert unknown["effect"] == "unknown" and unknown["delivery_id"] == "delivery-unknown"
    assert unknown["retry_policy"] == "recover_original"




def test_http_attachment_diagnostics_are_bounded_and_do_not_copy_raw_details():
    from workflow_orchestrator.client import WorkflowAPIError
    from workflow_orchestrator.mcp_contract import failure

    details = {"origin_contract": "field-origin/v1", "fields": [
        {"path": "/unresolved/0/origin/attachment_ref", "rule": "registeredAttachment", "actual": "https://secret?token=private"},
        {"path": "/origin/https://secret?token=private", "rule": "registeredAttachment"},
        {"path": "/origin", "rule": ["untrusted"]},
    ] + [{"path": "/origin", "rule": "additionalProperties"}] * 20}
    error = failure(WorkflowAPIError(400, "validation_error", "raw SQL secret private", details),
                    operation="record_field_review", write=True)
    assert error["effect"] == "not_committed" and error["retry_policy"] == "correct_arguments"
    assert error["fields"][0] == {"path": "/unresolved/0/origin/attachment_ref", "rule": "registeredAttachment"}
    assert len(error["fields"]) <= 8 and error["fields_truncated"]
    assert "private" not in str(error) and "SQL" not in str(error)
    for status in (401, 403, 408, 425, 429, 500):
        other = failure(WorkflowAPIError(status, "error", "private", details), operation="record_field_review", write=True)
        assert other["fields"] == []
        assert other["effect"] == ("not_committed" if status in (401, 403) else "unknown")


def test_operation_guidance_explains_preconditions_without_remote_details_or_policy_changes():
    from workflow_orchestrator.client import WorkflowAPIError

    absent = failure(WorkflowAPIError(404, "not_found", "private raw SQL", {"recipient": "private"}),
        operation="curate_field_item", write=True)
    assert "target_ref" in absent["guidance"] and "fact_ref" in absent["guidance"]
    assert "private" not in json.dumps(absent) and "SQL" not in json.dumps(absent)
    assert absent["fields"] == []  # A 404 does not identify which object was missing.
    assert absent["effect"] == "not_committed" and absent["retry_policy"] == "stop"
    original = WorkflowAPIError(404, "not_found", "private")
    original.effect, original.delivery_id = "unknown", "original-delivery"
    unknown = failure(original, operation="curate_field_item", write=True)
    assert unknown["effect"] == "unknown" and unknown["retry_policy"] == "recover_original"
    assert unknown["delivery_id"] == "original-delivery" and "guidance" not in unknown
    for status in (401, 403, 409, 500):
        other = failure(WorkflowAPIError(status, "not_found", "private"),
            operation="curate_field_item", write=True)
        assert "guidance" not in other and "private" not in json.dumps(other)


def test_current_im_schema_rejects_oversized_roots_and_page_budgets():
    from workflow_orchestrator.im_tools import SPECS
    tools = list(SPECS.values())
    with pytest.raises(ContractError) as roots:
        validate(tools, "save_working_conclusion", {"statement": "bounded", "reason": "test",
            "evidence_ids": [str(i) for i in range(17)]})
    assert any(item["path"] == "/evidence_ids" for item in roots.value.fields)
    for invalid in (20000, True, "20000", 255):
        with pytest.raises(ContractError):
            validate(tools, "read_field_source", {"packet_id": "p", "max_bytes": invalid})
    with pytest.raises(ContractError):
        validate(tools, "read_field_source", {"packet_id": "p", "max_bytes": 1024, "start": -1})
