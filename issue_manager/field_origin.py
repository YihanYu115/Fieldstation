"""Lossless field anchors: strict public input and server-only normalized handoff.

No original is opened. The transaction rechecks every anchor against its packet.
The dict marker preserves the historical canonical idempotency payload while JSON
clients cannot manufacture the in-process handoff type.
"""
from __future__ import annotations

from typing import Any

from .errors import ValidationError
from .evidence_identity import identity_locator


class NormalizedOrigin(dict[str, Any]):
    """Internal API-to-domain value; not a public write shape or verification proof."""


def validate_handoff(origin: Any, *, path: str = "/origin") -> None:
    """Reject forged state even before a domain idempotency cache lookup."""
    if isinstance(origin, dict) and "local_position_verified" in origin:
        if not isinstance(origin, NormalizedOrigin):
            _invalid(path, "additionalProperties", "Attachment verification state is server-only")
        if origin.get("type") != "attachment" or origin["local_position_verified"] is not False:
            _invalid(path, "serverState", "Internal attachment state must remain unverified")


def _invalid(path: str, rule: str, message: str) -> None:
    raise ValidationError(message, details={"origin_contract": "field-origin/v1",
                                          "fields": [{"path": path, "rule": rule}]})


def anchor_text(value: Any, path: str, limit: int, *, locator: bool = False) -> str:
    if not isinstance(value, str):
        _invalid(path, "type", "Attachment anchor must be a string")
    if not value.strip():
        _invalid(path, "nonWhitespace", "Attachment anchor must be non-empty")
    if len(value) > limit:
        _invalid(path, "maxLength", "Attachment anchor exceeds its code-point limit")
    try:
        value.encode("utf-8")
        if locator:
            identity_locator(value)
    except (ValueError, UnicodeEncodeError):
        _invalid(path, "losslessLocator" if locator else "validUtf8Json",
                 "Attachment anchor has invalid encoding or forbidden control characters")
    return value


def _text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValidationError(f"{field} must be non-empty and at most {limit} characters")
    return value


def resolve_origin(packet: dict[str, Any], origin: Any, *, path: str = "/origin") -> tuple[dict[str, Any], str]:
    """Strict public parsing. Even false server state is forbidden in JSON input."""
    if not isinstance(origin, dict):
        _invalid(path, "type", "origin must be an object")
    kind = origin.get("type")
    if kind == "packet_text":
        quote = _text(origin.get("quoted_text"), "origin quoted_text", 4_000)
        if set(origin) - {"type", "quoted_text", "start"}:
            raise ValidationError("packet_text origin accepts type, quoted_text, and optional start")
        content = packet["content"]
        if "start" in origin:
            start = origin["start"]
            if isinstance(start, bool) or not isinstance(start, int) or start < 0 or content[start:start + len(quote)] != quote:
                raise ValidationError("origin start does not point to the exact quoted_text")
        else:
            first = content.find(quote)
            if first < 0:
                raise ValidationError("origin quoted_text is not present in packet content")
            if content.find(quote, first + 1) >= 0:
                raise ValidationError("origin quoted_text is ambiguous; provide start")
            start = first
        return ({"type": kind, "quoted_text": quote, "start": start},
                f"im-field-packet:{packet['packet_id']}#content")
    if kind == "source_text":
        quote = _text(origin.get("quoted_text"), "origin quoted_text", 4_000)
        if set(origin) - {"type", "quoted_text", "source_index", "start"} or not {
                "type", "quoted_text", "source_index"} <= set(origin):
            raise ValidationError("source_text origin needs type, quoted_text, source_index, and optional start")
        index = origin["source_index"]
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(packet["sources"]):
            raise ValidationError("origin source_index does not identify a source in this packet")
        text = packet["sources"][index]["provided_text"]
        if "start" in origin:
            start = origin["start"]
            if isinstance(start, bool) or not isinstance(start, int) or start < 0 or text[start:start + len(quote)] != quote:
                raise ValidationError("origin start does not point to the exact source_text excerpt")
        else:
            first = text.find(quote)
            if first < 0:
                raise ValidationError("origin quoted_text is not present in the selected source_text")
            if text.find(quote, first + 1) >= 0:
                raise ValidationError("origin quoted_text is ambiguous; provide start")
            start = first
        return ({"type": kind, "quoted_text": quote, "source_index": index, "start": start},
                packet["sources"][index]["locator"])
    if kind == "attachment":
        allowed = {"type", "quoted_text", "attachment_ref", "part_locator"}
        required = {"type", "attachment_ref", "part_locator"}
        if set(origin) - allowed:
            _invalid(path, "additionalProperties", "Attachment origin has unsupported fields; verification state is server-only")
        if not required <= set(origin):
            missing = sorted(required - set(origin))[0]
            _invalid(path + "/" + missing, "required", "Attachment origin needs type, attachment_ref, and part_locator")
        ref = anchor_text(origin["attachment_ref"], path + "/attachment_ref", 2_048, locator=True)
        if ref not in packet["attachment_refs"]:
            _invalid(path + "/attachment_ref", "registeredAttachment", "Attachment reference must exactly match this packet's registered string")
        part = anchor_text(origin["part_locator"], path + "/part_locator", 2_048, locator=True)
        normalized = NormalizedOrigin(type=kind, attachment_ref=ref,
                                      part_locator=part, local_position_verified=False)
        if "quoted_text" in origin:
            normalized["quoted_text"] = anchor_text(origin["quoted_text"], path + "/quoted_text", 4_000)
        return normalized, ref
    _invalid(path + "/type", "enum", "origin.type must be packet_text, source_text, or attachment")
    raise AssertionError("unreachable")


def revalidate_origin(packet: dict[str, Any], origin: Any, *, path: str = "/origin") -> tuple[dict[str, Any], str]:
    """Recompute against authority; only the internal marker may carry false state."""
    if isinstance(origin, NormalizedOrigin) and origin.get("type") == "attachment":
        if origin.get("local_position_verified") is not False:
            _invalid(path, "serverState", "Internal attachment state must remain unverified")
        origin = {key: value for key, value in origin.items() if key != "local_position_verified"}
    return resolve_origin(packet, origin, path=path)
