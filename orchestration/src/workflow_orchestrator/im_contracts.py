"""Reviewed pure Inbox origin/schema helpers extracted from the existing adapter."""
from __future__ import annotations

import hashlib
import unicodedata
from typing import Any

from .packet_contract import FieldInboxError
from .relation_contract import SCOPED_RELATION_DESCRIPTION, SCOPED_RELATION_TYPES


def _text(value: Any, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise FieldInboxError("invalid_arguments", f"{name} must be non-empty and at most {limit} characters")
    return value


def _matched_count(text: str, quote: str) -> int:
    count, start = 0, 0
    while (match := text.find(quote, start)) >= 0:
        count += 1
        start = match + 1
    return count


def _origin_feedback(packet: dict[str, Any], origin: Any, packet_id: str,
                     path: str) -> tuple[list[dict[str, Any]], dict[str, Any] | None, int]:
    if not isinstance(origin, dict) or origin.get("type") not in {"packet_text", "source_text"}:
        return [], None, 0
    quote = origin.get("quoted_text")
    if not isinstance(quote, str) or not quote:
        return [], None, 0
    source_index = origin.get("source_index") if origin.get("type") == "source_text" else None
    if source_index is None:
        text = packet.get("content")
        base_origin: dict[str, Any] = {"type": "packet_text"}
    else:
        sources = packet.get("sources", [])
        if (isinstance(source_index, bool) or not isinstance(source_index, int)
                or not 0 <= source_index < len(sources)):
            return [], None, 0
        text = sources[source_index].get("provided_text", "")
        base_origin = {"type": "source_text", "source_index": source_index}
    if not isinstance(text, str):
        return [], None, 0
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    matches: list[int] = []
    cursor = 0
    while len(matches) < 4:
        found = text.find(quote, cursor)
        if found < 0:
            break
        matches.append(found)
        cursor = found + 1
    total_at_least = len(matches)
    candidates = [{
        "origin": {**base_origin, "quoted_text": quote, "start": start},
        "content_sha256": digest,
        "context": text[max(0, start - 80):min(len(text), start + len(quote) + 80)],
    } for start in matches[:3]]
    next_step = None
    if total_at_least > 3:
        args: dict[str, Any] = {"packet_id": packet_id, "quoted_text": quote,
                                "after_start": matches[2] + 1, "limit": 3}
        if source_index is not None:
            args["source_index"] = source_index
        next_step = {"tool": "locate_field_excerpt", "arguments": args,
                     "content_sha256": digest}
    return candidates, next_step, _matched_count(text, quote)


def _attach_origin_feedback(exc: FieldInboxError, packet: dict[str, Any], origin: Any,
                            packet_id: str, path: str) -> None:
    candidates, next_step, matched_count = _origin_feedback(packet, origin, packet_id, path)
    setattr(exc, "origin_pointer", path)
    setattr(exc, "origin_candidates", candidates)
    if matched_count:
        exc.matched_count = matched_count
        exc.guidance = ("选择同一来源中实际指向的精确位置；重复引文必须由参与者选择。"
                        if matched_count > 1 else "复制候选中的准确 Unicode 码点 start 后重新提交。")
    else:
        exc.guidance = "原选来源中没有逐字匹配；请核对原文，不要改写引文或切换来源。"
    if next_step is not None:
        exc.next_step = next_step


def _compact_curation_receipt(receipt: dict[str, Any], *, review: bool = False) -> dict[str, Any]:
    keys = ({"status", "packet_id", "review_id", "curation_version", "idempotent_replay"}
            if review else {"status", "packet_id", "fact_ref", "evidence_id", "mapping_id",
                "mapping_version", "relation_ids", "origin", "source_locator", "curation_version",
                "atomic", "idempotent_replay"})
    result = {key: receipt[key] for key in keys if key in receipt}
    if receipt.get("delivery_id") is not None:
        result["delivery_id"] = receipt["delivery_id"]
    if isinstance(receipt.get("delivery"), dict):
        result["delivery"] = {"state": receipt["delivery"].get("state"),
                              "replayed": bool(receipt["delivery"].get("replayed")),
                              "current_state_verified": False}
    elif receipt.get("delivery_id") is not None:
        result["delivery"] = {"state": "committed", "replayed": bool(receipt.get("delivery_replayed")),
                              "current_state_verified": False}
    result["verification"] = {"management_record": "not_read_after_commit",
        "independent_original": "not_performed", "scientific_validity": "not_assessed"}
    if (not review and isinstance(receipt.get("packet_id"), str)
            and isinstance(receipt.get("fact_ref"), str)):
        result["read"] = {"tool": "read_field_fact", "arguments": {
            "packet_id": receipt["packet_id"], "fact_ref": receipt["fact_ref"]}}
    if review and isinstance(receipt.get("review_id"), str):
        result["read"] = {"tool": "read_field_review", "arguments": {
            "packet_id": receipt["packet_id"], "review_id": receipt["review_id"]}}
    return result


def _check_origin(packet: dict[str, Any], origin: Any, *, path: str = "/origin") -> None:
    if not isinstance(origin, dict):
        raise FieldInboxError("invalid_origin", "origin must be an object")
    kind = origin.get("type")
    if kind == "packet_text":
        if set(origin) - {"type", "quoted_text", "start"}:
            raise FieldInboxError("invalid_origin", "packet_text origin has unsupported fields")
        quote = _text(origin.get("quoted_text"), "origin.quoted_text", 4_000)
        content = packet.get("content")
        if not isinstance(content, str):
            raise FieldInboxError("invalid_packet", "Packet content is unavailable for local origin validation")
        if "start" in origin:
            start = origin["start"]
            if isinstance(start, bool) or not isinstance(start, int) or start < 0 or content[start:start + len(quote)] != quote:
                raise FieldInboxError("invalid_origin", "origin.start does not match the exact packet excerpt")
        elif _matched_count(content, quote) != 1:
            error = FieldInboxError("invalid_origin", "Quoted text must occur exactly once or include start")
            error.matched_count = _matched_count(content, quote)
            raise error
    elif kind == "source_text":
        if set(origin) - {"type", "quoted_text", "source_index", "start"}:
            raise FieldInboxError("invalid_origin", "source_text origin has unsupported fields")
        quote = _text(origin.get("quoted_text"), "origin.quoted_text", 4_000)
        index = origin.get("source_index")
        sources = packet.get("sources", [])
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(sources):
            raise FieldInboxError("invalid_origin", "origin.source_index must select a source from this packet")
        source_text = sources[index].get("provided_text", "")
        if "start" in origin:
            start = origin["start"]
            if isinstance(start, bool) or not isinstance(start, int) or start < 0 or source_text[start:start + len(quote)] != quote:
                raise FieldInboxError("invalid_origin", "origin.start does not match the selected source excerpt")
        elif _matched_count(source_text, quote) != 1:
            error = FieldInboxError("invalid_origin", "Quoted text must occur exactly once or include start")
            error.matched_count = _matched_count(source_text, quote)
            raise error
    elif kind == "attachment":
        if set(origin) - {"type", "attachment_ref", "part_locator", "quoted_text"}:
            raise FieldInboxError("invalid_origin", "Attachment origin has unsupported fields; verification state is server-only",
                                  fields=[{"path": path, "rule": "additionalProperties"}])
        for key, limit in (("attachment_ref", 2048), ("part_locator", 2048), ("quoted_text", 4000)):
            if key == "quoted_text" and key not in origin:
                continue
            value = origin.get(key)
            rule = ("type" if not isinstance(value, str) else "nonWhitespace" if not value.strip()
                    else "maxLength" if len(value) > limit else None)
            if rule is None and isinstance(value, str):
                try:
                    value.encode("utf-8")
                    if key != "quoted_text" and any(unicodedata.category(c) == "Cc" and c != "\t" for c in value):
                        rule = "losslessLocator"
                except UnicodeEncodeError:
                    rule = "validUtf8Json"
            if rule:
                raise FieldInboxError("invalid_origin", "Attachment anchor failed the indicated contract rule",
                                      fields=[{"path": path + "/" + key, "rule": rule}])
        if origin.get("attachment_ref") not in packet.get("attachment_refs", []):
            raise FieldInboxError("invalid_origin", "origin.attachment_ref is not registered on this packet",
                                  fields=[{"path": path + "/attachment_ref", "rule": "registeredAttachment"}])
    else:
        raise FieldInboxError("invalid_origin", "origin.type must be packet_text, source_text, or attachment")


def _related_items(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > 8:
        raise FieldInboxError("invalid_arguments", "related_evidence must be an array with at most 8 entries")
    output = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"target_kind", "target_ref", "relation_type", "rationale"}:
            raise FieldInboxError("invalid_arguments", "Each related_evidence item needs target_kind, target_ref, relation_type, and rationale")
        if item.get("target_kind") not in {"fact_ref", "evidence_id"}:
            raise FieldInboxError("invalid_arguments", "target_kind must be fact_ref or evidence_id")
        relation_type = _text(item.get("relation_type"), "related_evidence.relation_type", 64)
        if relation_type not in SCOPED_RELATION_TYPES:
            raise FieldInboxError("invalid_arguments", "related_evidence.relation_type is unsupported")
        output.append({"target_kind": item["target_kind"],
            "target_ref": _text(item.get("target_ref"), "related_evidence.target_ref", 256),
            "relation_type": relation_type,
            "rationale": _text(item.get("rationale"), "related_evidence.rationale", 4_000)})
    return output


def _origin_schema() -> dict[str, Any]:
    return {"oneOf": [
        {"type": "object", "properties": {"type": {"const": "packet_text"},
            "quoted_text": {"type": "string", "minLength": 1, "maxLength": 4_000,
                            "description": "逐字复制 packet.content 中的连续原文。优先选可唯一定位的短引文，不能改写、拼接或用省略号替换。"},
            "start": {"type": "integer", "minimum": 0,
                      "description": "引文重复时填写其在 packet 原文中的零基 Unicode 字符位置；唯一匹配时省略。"}},
            "required": ["type", "quoted_text"], "additionalProperties": False},
        {"type": "object", "properties": {"type": {"const": "source_text"},
            "quoted_text": {"type": "string", "minLength": 1, "maxLength": 4_000,
                            "description": "逐字复制所选 sources[source_index].provided_text 中的连续原文；优先选择唯一引文。"},
            "source_index": {"type": "integer", "minimum": 0,
                             "description": "read_field_packet 返回的 sources 数组零基下标；不是 packet_id 或附件下标。"},
            "start": {"type": "integer", "minimum": 0,
                      "description": "引文重复时填写其在所选 provided_text 中的零基 Unicode 字符位置；唯一匹配时省略。"}},
            "required": ["type", "quoted_text", "source_index"], "additionalProperties": False},
        {"type": "object", "properties": {"type": {"const": "attachment"},
            "attachment_ref": {"type": "string", "minLength": 1, "maxLength": 2_048},
            "part_locator": {"type": "string", "minLength": 1, "maxLength": 2_048},
            "quoted_text": {"type": "string", "minLength": 1, "maxLength": 4_000}},
            "required": ["type", "attachment_ref", "part_locator"], "additionalProperties": False},
    ], "description": "精确引用 packet.content、sources[].provided_text 或声明附件。重复引文须有准确 start；不能猜偏移。附件 locator 不授予读取文件的能力，来源声明不等于已核验原件。"}


def _curate_schema() -> dict[str, Any]:
    return {
        "name": "curate_field_item",
        "description": "从 packet 保存一项可独立管理的观察或判断及其明确关系。每次显式传 packet_id；先保存可用前提，再引用真实 fact_ref/Evidence ID 保存派生判断。逐项交付并利用已有映射续接，不需先规划整个 packet。关系附在承载内容的 Evidence 上，不把登记指令建成 Evidence。",
        "inputSchema": {"type": "object", "properties": {
            "packet_id": {"type": "string", "minLength": 1, "maxLength": 80,
                          "description": "复制已释放 packet 的真实 ID；每次调用必填，不从前次 read 自动继承。"},
            "kind": {"type": "string", "enum": ["observation", "interpretation"],
                     "description": "观察选 observation；计算、解释或判断选 interpretation。"},
            "description": {"type": "string", "minLength": 1, "maxLength": 20_000,
                            "description": "保留使本条可独立理解的条件、单位、范围和不确定性；按可独立质疑、替换或复用的单位拆分，不机械逐行复制表格。"},
            "origin": _origin_schema(),
            "reason": {"type": "string", "minLength": 1, "maxLength": 4_000},
            "related_evidence": {"type": "array", "maxItems": 8,
                                 "description": "这是当前条目的出边，须由当前条目本身承载该关系；来源、必要前提、质疑和反驳不可互换。",
                                 "items": {
                "type": "object", "properties": {
                    "target_kind": {"type": "string", "enum": ["fact_ref", "evidence_id"],
                                    "description": "本 packet 已映射条目用 fact_ref；已入账 Evidence 用 evidence_id。原件标签（如 SYN-002）或原件 URI 属于来源，不是 Evidence ID。"},
                    "target_ref": {"type": "string", "minLength": 1, "maxLength": 256,
                                   "description": "按 target_kind 从写回执或 list_curated_field_items 的现有映射复制 fact_ref 或 evidence_id 原值；不能填原件标签、URI、evidence:<id> 或未保存的自拟编号。"},
                    "relation_type": {"type": "string", "enum": list(SCOPED_RELATION_TYPES),
                                      "description": SCOPED_RELATION_DESCRIPTION},
                    "rationale": {"type": "string", "minLength": 1, "maxLength": 4_000},
                }, "required": ["target_kind", "target_ref", "relation_type", "rationale"],
                "additionalProperties": False,
            }},
        }, "required": ["packet_id", "kind", "description", "origin", "reason"],
            "additionalProperties": False},
    }


def _review_schema() -> dict[str, Any]:
    return {"name": "record_field_review", "description": "记录 IM 领域 review 的处理范围、已处理事实和未解缺口。reason 按普通领域文本原样保存；review 本身不证明科学质量。",
            "inputSchema": {"type": "object", "properties": {
                "packet_id": {"type": "string", "minLength": 1, "maxLength": 80,
                              "description": "本次实际处理的已释放 packet ID；每次调用必填。"},
                "handled_fact_refs": {"type": "array", "maxItems": 100, "items": {"type": "string"},
                                      "description": "额外选择已处理事实；省略时自动收集本会话对该 packet 已确认的映射，不表示全文已阅。"},
                "unresolved": {"type": "array", "maxItems": 100,
                               "description": "未解决缺口对象的 JSON 数组；每项包含精确 origin 与 reason，不要将整个数组序列化为字符串。",
                               "items": {"type": "object",
                    "properties": {"origin": _origin_schema(),
                        "reason": {"type": "string", "minLength": 1, "maxLength": 4_000}},
                    "required": ["origin", "reason"], "additionalProperties": False}},
                "reason": {"type": "string", "minLength": 1, "maxLength": 4_000}},
                "required": ["packet_id", "reason"], "additionalProperties": False}}
