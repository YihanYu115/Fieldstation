from __future__ import annotations

import pytest
from workflow_orchestrator.im_contracts import _check_origin
from workflow_orchestrator.packet_contract import (
    FieldInboxError,
    canonical,
    normalize_packet,
    packet_budget,
)


@pytest.mark.parametrize("sample", ["ASCII", "中文", "😀𠮷", '\\"\r\n'])
def test_exact_canonical_boundary_preserves_text_and_matches_kernel(sample):
    from issue_manager.errors import ValidationError
    from issue_manager.field_inbox_api import _normalize_packet

    arguments = {"content": sample * 1000, "sources": [
        {"locator": str(i), "provided_text": "x" * 39000} for i in range(5)]}
    body = {"issue_id": "scope", **arguments, "attachment_refs": []}
    delta = len(canonical(body)) - 200000
    if delta > 0:
        arguments["sources"][-1]["provided_text"] = "x" * (39000 - delta)
    else:
        arguments["content"] += "x" * -delta
    normalized = normalize_packet("scope", arguments)
    assert len(canonical(normalized)) == 200000
    assert normalized == _normalize_packet({"issue_id": "scope", **arguments})
    assert normalized["content"].startswith(sample * 1000)
    budget = packet_budget(normalized)
    assert sum(budget["parts"].values()) == budget["actual"]
    assert budget["hash_version"] == "field-packet-canonical/v1"
    arguments["content"] += "x"
    with pytest.raises(FieldInboxError) as rejected:
        normalize_packet("scope", arguments)
    assert rejected.value.budget["actual"] == 200001
    assert rejected.value.budget["excess"] == 1
    with pytest.raises(ValidationError):
        _normalize_packet({"issue_id": "scope", **arguments})



def test_origin_matched_count_includes_overlapping_unicode_occurrences():
    with pytest.raises(FieldInboxError) as error:
        _check_origin({"content": "甲甲甲"}, {"type": "packet_text", "quoted_text": "甲甲"})
    assert error.value.matched_count == 2
