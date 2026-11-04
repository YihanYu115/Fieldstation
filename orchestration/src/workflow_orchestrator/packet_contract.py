"""Pure mechanical packet contract. No storage, fetching or content selection."""
from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Any

from .mcp_contract import ContractError, validate

MAX_PACKET_BYTES = 200_000
MAX_SOURCES = 16
MAX_ATTACHMENTS = 128
HASH_VERSION = "field-packet-canonical/v1"
GUIDANCE = ("原始数据、脚本和分析过程留在项目存储，用 attachment_refs 登记真实引用；"
            "content 交接工作、发现、条件、失败及未决点。读取原件由项目提供。"
            "不要把原件搬入 content 或拆多个 packet 绕过上限。")
PACKET_SCHEMA = {
    "type": "object", "properties": {
        "content": {"type": "string", "minLength": 1, "maxLength": 80_000,
                    "description": "写清本次做了什么、条件与执行状态、发现（含负面结果）、依据与限制、未决点；相关原件用真实引用，计数单位和检查性质在影响理解时自然说明。"},
        "sources": {"type": "array", "maxItems": MAX_SOURCES,
                    "description": "可选内嵌文字；不要求复制原始数据、脚本或分析过程。纯引用使用 attachment_refs。",
                    "items": {"type": "object", "properties": {
                        "locator": {"type": "string", "minLength": 1, "maxLength": 2_048},
                        "provided_text": {"type": "string", "minLength": 1, "maxLength": 40_000,
                                          "description": "自愿提供的真实原样文字摘录；空日志用交接描述，不制造非空原文。"},
                    }, "required": ["locator", "provided_text"], "additionalProperties": False}},
        "attachment_refs": {"type": "array", "maxItems": MAX_ATTACHMENTS,
                            "description": "外部材料引用字符串。需要留档的成果按项目契约取得准确引用；共享工作区路径本身不保证版本和保留。不上传二进制，不自动读取或核验地址。",
                            "items": {"type": "string", "minLength": 1, "maxLength": 2_048}},
    }, "required": ["content"], "additionalProperties": False,
}


class FieldInboxError(ContractError):
    """Safe field contract error, compatible with the existing facade."""

    phase: str
    effect: str
    budget: dict[str, Any]
    guidance: str
    delivery_id: str
    matched_count: int
    next_step: dict[str, Any]


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise FieldInboxError("invalid_arguments", "Arguments must be valid UTF-8 JSON values") from exc


def packet_budget(body: dict[str, Any]) -> dict[str, Any]:
    encoded = canonical(body)
    parts = {key: len(canonical(value)) for key, value in body.items()
             if key in {"issue_id", "content", "sources", "attachment_refs"}}
    unknown = sum(len(canonical(value)) for key, value in body.items() if key not in parts)
    if unknown:
        parts["unknown_values"] = unknown
    # Top-level values include their own quotes/brackets/escaping. Keys, colons,
    # commas and the outer braces are accounted for exactly once as overhead.
    parts["structure_and_keys"] = len(encoded) - sum(parts.values())
    largest: list[dict[str, Any]] = [{"path": "/content", "bytes": parts.get("content", 0)}]
    if isinstance(body.get("sources"), list):
        largest.extend({"path": f"/sources/{i}", "bytes": len(canonical(value))}
                       for i, value in enumerate(body["sources"]))
    largest.append({"path": "/attachment_refs", "bytes": parts.get("attachment_refs", 0)})
    return {"unit": "canonical_utf8_bytes", "limit": MAX_PACKET_BYTES,
            "actual": len(encoded), "excess": max(0, len(encoded) - MAX_PACKET_BYTES),
            "parts": parts, "largest_items": sorted(largest, key=lambda p: -p["bytes"])[:5],
            "hash_version": HASH_VERSION, "body_sha256": hashlib.sha256(encoded).hexdigest()}


def normalize_packet(issue_id: str, arguments: Any) -> dict[str, Any]:
    """Validate all fields and the complete budget before creating any intent."""
    fields: list[dict[str, Any]] = []
    truncated = False
    try:
        validate([{"name": "submit_field_packet", "inputSchema": PACKET_SCHEMA}],
                 "submit_field_packet", arguments)
    except ContractError as exc:
        fields, truncated = exc.fields, exc.fields_truncated
    body = {**arguments, "issue_id": issue_id} if isinstance(arguments, dict) else {"issue_id": issue_id}
    body.setdefault("sources", [])
    body.setdefault("attachment_refs", [])
    budget = None
    try:
        budget = packet_budget(body)
    except FieldInboxError:
        fields.append({"path": "", "rule": "validUtf8Json"})
    if isinstance(arguments, dict):
        # JSON Schema minLength does not reject whitespace-only strings.
        texts = [("/content", arguments.get("content"))]
        if isinstance(arguments.get("sources"), list):
            for i, source in enumerate(arguments["sources"]):
                if isinstance(source, dict):
                    texts.extend((f"/sources/{i}/{key}", source.get(key))
                                 for key in ("locator", "provided_text"))
        if isinstance(arguments.get("attachment_refs"), list):
            texts.extend((f"/attachment_refs/{i}", text)
                         for i, text in enumerate(arguments["attachment_refs"]))
            fields.extend({"path": f"/attachment_refs/{i}", "rule": "losslessLocator"}
                          for i, text in enumerate(arguments["attachment_refs"])
                          if isinstance(text, str) and any(
                              unicodedata.category(c) == "Cc" and c != "\t" for c in text))
        fields.extend({"path": path, "rule": "nonWhitespace", "expected_limit": 1,
                       "actual": 0, "unit": "non_whitespace_code_points"}
                      for path, text in texts if isinstance(text, str) and text and not text.strip())
    oversized = budget is not None and budget["excess"] > 0
    if oversized and budget is not None:
        fields.insert(0, {"path": "", "rule": "maxCanonicalUtf8Bytes",
                          "expected_limit": MAX_PACKET_BYTES, "actual": budget["actual"],
                          "unit": "canonical_utf8_bytes"})
    if fields:
        error = FieldInboxError("packet_too_large" if oversized and len(fields) == 1 else "invalid_arguments",
                                "Packet failed mechanical validation; correct the indicated fields",
                                fields=fields[:8], fields_truncated=truncated or len(fields) > 8)
        error.phase, error.effect = "validation", "not_committed"
        if budget is not None:
            error.budget = budget
        error.guidance = GUIDANCE
        raise error
    return body


def packet_capabilities() -> dict[str, Any]:
    return {"max_packet_bytes": MAX_PACKET_BYTES, "unit": "canonical_utf8_bytes",
            "normalization": "host issue_id; defaults sources=[] and attachment_refs=[]; sorted compact JSON, ensure_ascii=false; original text and CRLF preserved",
            "hash_version": HASH_VERSION, "max_content_code_points": 80_000,
            "max_source_code_points": 40_000, "max_sources": MAX_SOURCES,
            "max_attachment_refs": MAX_ATTACHMENTS, "max_locator_code_points": 2_048,
            "guidance": GUIDANCE, "workflow": "理解任务 → 工作交接和真实引用 → submit_field_packet → 核对 received；received 不表示原件已读取、科学已核验或队列已结算。"}
