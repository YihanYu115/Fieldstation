"""Finite HTTP contract for Field Inbox v4 packets and curator handoff."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl, unquote_to_bytes

from .errors import ConflictError, NotFoundError, ValidationError
from .field_origin import anchor_text
from .field_origin import resolve_origin as _resolve_origin
from .store import canonical_json, new_id

MAX_PACKET_BYTES = 200_000
MAX_CONTENT_CHARS = 80_000
MAX_SOURCES = 16
MAX_SOURCE_TEXT_CHARS = 40_000
MAX_LOCATOR_CHARS = 2_048
MAX_ATTACHMENTS = 128
MAX_PAGE_SIZE = 50


def handles(method: str, parts: list[str]) -> bool:
    if method == "POST":
        return parts == ["v1", "field-packets"] or (
            len(parts) == 4 and parts[:2] == ["v1", "field-packets"]
            and parts[3] in {"curated-items", "reviews"}
        )
    if method != "GET":
        return False
    return parts == ["v1", "field-packets"] or (
        len(parts) == 3 and parts[:2] in (["v1", "field-packets"], ["v1", "field-facts"])
    ) or (
        len(parts) == 4 and parts[:2] == ["v1", "field-packets"]
        and parts[3] in {"curated-items", "reviews", "summary", "text", "locate", "review", "facts"}
    ) or (
        len(parts) == 5 and parts[:2] == ["v1", "field-packets"] and parts[3] == "facts"
    ) or (
        len(parts) == 4 and parts[:2] == ["v1", "field-facts"] and parts[3] == "mappings"
    )


def _decode(value: str) -> str:
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ValidationError("Malformed URL escape in field inbox path")
    try:
        decoded = unquote_to_bytes(value).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValidationError("Field inbox path is not valid UTF-8") from exc
    if not decoded.strip():
        raise ValidationError("Field inbox path parameter must be non-empty")
    return decoded


def _query(raw_query: str | dict[str, Any] | None) -> dict[str, str]:
    if raw_query is None:
        return {}
    if isinstance(raw_query, dict):
        result: dict[str, str] = {}
        for key, value in raw_query.items():
            if isinstance(value, list):
                if len(value) != 1:
                    raise ValidationError("Duplicate field inbox query parameter")
                value = value[0]
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValidationError("Field inbox query parameters must be strings")
            result[key] = value
        return result
    try:
        pairs = parse_qsl(raw_query, keep_blank_values=True, strict_parsing=True,
                          encoding="utf-8", errors="strict", max_num_fields=5) if raw_query else []
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValidationError("Invalid field inbox query string") from exc
    parsed: dict[str, str] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValidationError("Duplicate field inbox query parameter")
        parsed[key] = value
    return parsed


def _text(value: Any, field: str, limit: int, *, preserve: bool = True) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValidationError(f"{field} must be non-empty and at most {limit} characters")
    return value if preserve else value.strip()


def _int(values: dict[str, str], key: str, default: int, low: int, high: int) -> int:
    try:
        result = int(values.get(key, str(default)))
    except ValueError as exc:
        raise ValidationError(f"{key} must be an integer") from exc
    if not low <= result <= high:
        raise ValidationError(f"{key} must be between {low} and {high}")
    return result


def _normalize_packet(body: dict[str, Any]) -> dict[str, Any]:
    allowed = {"issue_id", "content", "sources", "attachment_refs"}
    if not isinstance(body, dict) or set(body) - allowed:
        raise ValidationError("Unknown field packet fields", details={"fields": sorted(set(body) - allowed)})
    issue_id = _text(body.get("issue_id"), "issue_id", 256, preserve=False)
    content = _text(body.get("content"), "content", MAX_CONTENT_CHARS)
    raw_sources = body.get("sources", [])
    if not isinstance(raw_sources, list) or len(raw_sources) > MAX_SOURCES:
        raise ValidationError(f"sources must contain at most {MAX_SOURCES} entries")
    sources = []
    for source in raw_sources:
        if not isinstance(source, dict) or set(source) != {"locator", "provided_text"}:
            raise ValidationError("Each source needs only locator and provided_text")
        sources.append({"locator": _text(source.get("locator"), "source locator", MAX_LOCATOR_CHARS),
                        "provided_text": _text(source.get("provided_text"), "source provided_text",
                                                MAX_SOURCE_TEXT_CHARS)})
    attachments = body.get("attachment_refs", [])
    if not isinstance(attachments, list) or len(attachments) > MAX_ATTACHMENTS:
        raise ValidationError(f"attachment_refs must contain at most {MAX_ATTACHMENTS} entries")
    attachments = [anchor_text(item, f"/attachment_refs/{i}", MAX_LOCATOR_CHARS, locator=True)
                   for i, item in enumerate(attachments)]
    normalized = {"issue_id": issue_id, "content": content, "sources": sources,
                  "attachment_refs": attachments}
    if len(canonical_json(normalized).encode("utf-8")) > MAX_PACKET_BYTES:
        raise ValidationError(f"Packet exceeds {MAX_PACKET_BYTES} UTF-8 bytes")
    return normalized


def _related_payload(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > 8:
        raise ValidationError("related_evidence must contain at most 8 entries")
    normalized = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "target_kind", "target_ref", "relation_type", "rationale"
        }:
            raise ValidationError("Each related_evidence item needs target_kind, target_ref, relation_type, and rationale")
        if item.get("target_kind") not in {"fact_ref", "evidence_id"}:
            raise ValidationError("related_evidence target_kind must be fact_ref or evidence_id")
        normalized.append({
            "target_kind": item["target_kind"],
            "target_ref": _text(item.get("target_ref"), "related_evidence target_ref", 256, preserve=False),
            "relation_type": _text(item.get("relation_type"), "relation_type", 64, preserve=False),
            "rationale": _text(item.get("rationale"), "relation rationale", 4_000),
        })
    return normalized


def _packet_detail(manager: Any, packet_id: str) -> dict[str, Any]:
    row = manager.store.row("SELECT * FROM field_packets WHERE packet_id=?", (packet_id,))
    if row is None:
        raise NotFoundError("Field packet was not found")
    head = manager.store.row("SELECT version,updated_at FROM field_packet_curation_heads WHERE packet_id=?",
                             (packet_id,))
    count = manager.store.row("SELECT COUNT(*) AS n FROM field_facts WHERE packet_id=?", (packet_id,))["n"]
    review = manager.store.row(
        "SELECT review_id,version,reason,created_at,created_by,handled_fact_refs_json,unresolved_json "
        "FROM field_packet_reviews WHERE packet_id=? ORDER BY version DESC LIMIT 1", (packet_id,))
    return {"packet_id": row["packet_id"], "issue_id": row["issue_id"],
            "request_id": row["request_id"], "received_at": row["created_at"],
            "created_by": row["created_by"], "status": "received",
            "content": row["content"], "content_sha256": row["content_sha256"],
            "sources": [{**s, "status": "declared_by_submitter"} for s in _loads(row["sources_json"])],
            "attachment_refs": _loads(row["attachment_refs_json"]),
            "original_access": manager.original_access_bindings.packet(row["issue_id"], packet_id),
            "curation_version": head["version"] if head else 0, "curated_item_count": count,
            "latest_review": ({"review_id": review["review_id"], "version": review["version"],
                               "reason": review["reason"], "created_at": review["created_at"],
                               "created_by": review["created_by"],
                               "handled_fact_refs": _loads(review["handled_fact_refs_json"]),
                               "unresolved": _loads(review["unresolved_json"])} if review else None)}


def _loads(value: str) -> Any:
    return json.loads(value)


def dispatch(manager: Any, method: str, parts: list[str], body: dict[str, Any], auth: Any,
             *, query: str | dict[str, Any] | None = None,
             request_id: str | None = None) -> Any:
    if method == "GET":
        with manager.store.read_transaction():
            return _dispatch(manager, method, parts, body, auth, query=query, request_id=request_id)
    return _dispatch(manager, method, parts, body, auth, query=query, request_id=request_id)


def _metadata(manager: Any, packet_id: str) -> dict[str, Any]:
    row = manager.store.row("SELECT packet_id,issue_id,created_at,created_by,substr(content,1,513) AS content_preview,length(content) AS content_chars,content_sha256,sources_json,attachment_refs_json FROM field_packets WHERE packet_id=?", (packet_id,))
    if row is None:
        raise NotFoundError("Field packet was not found")
    head = manager.store.row("SELECT version FROM field_packet_curation_heads WHERE packet_id=?", (packet_id,))
    counts = {r["kind"]: r["n"] for r in manager.store.rows(
        "SELECT kind,COUNT(*) AS n FROM field_facts WHERE packet_id=? GROUP BY kind", (packet_id,))}
    mapped_by_kind = {r["kind"]: r["n"] for r in manager.store.rows(
        "SELECT f.kind,COUNT(*) AS n FROM field_facts f JOIN field_fact_mapping_heads h USING(fact_ref) WHERE f.packet_id=? GROUP BY f.kind", (packet_id,))}
    sources = []
    for index, source in enumerate(_loads(row["sources_json"])):
        text = source.get("provided_text", "")
        sources.append({"source_index": index, "locator": source["locator"],
                        "body_available": bool(text), "content_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                        "utf8_bytes": len(text.encode("utf-8")), "status": "declared_by_submitter"})
    latest = manager.store.row("SELECT review_id,version FROM field_packet_reviews WHERE packet_id=? ORDER BY version DESC LIMIT 1", (packet_id,))
    return {"packet_id": packet_id, "issue_id": row["issue_id"], "received_at": row["created_at"],
            "created_by": row["created_by"], "status": "received", "content_sha256": row["content_sha256"],
            "content_preview": row["content_preview"][:512], "preview_complete": row["content_chars"] <= 512,
            "sources": sources, "attachment_refs": _loads(row["attachment_refs_json"]),
            "original_access": manager.original_access_bindings.packet(row["issue_id"], packet_id),
            "curation_version": head["version"] if head else 0,
            "curated_item_count": sum(counts.values()), "kind_counts": counts,
            "fact_count": sum(counts.values()), "current_mapping_kind_counts": mapped_by_kind,
            "count_semantics": {"fact_count": "all immutable field_facts in this packet",
                                "current_mapping_count": "facts with a current mapping head"},
            "mapped_item_count": manager.store.row("SELECT COUNT(*) AS n FROM field_facts f JOIN field_fact_mapping_heads h USING(fact_ref) WHERE f.packet_id=?", (packet_id,))["n"],
            "latest_review": latest, "statistics_complete": True}


def _text_source(manager: Any, packet_id: str, values: dict[str, str]) -> tuple[str, dict[str, Any]]:
    row = manager.store.row("SELECT content,sources_json FROM field_packets WHERE packet_id=?", (packet_id,))
    if row is None:
        raise NotFoundError("Field packet was not found")
    if "source_index" not in values:
        return row["content"], {"type": "packet_text"}
    sources = _loads(row["sources_json"])
    index = _int(values, "source_index", 0, 0, MAX_SOURCES - 1)
    if index >= len(sources) or not sources[index].get("provided_text"):
        raise NotFoundError("Requested source body is unavailable")
    return sources[index]["provided_text"], {"type": "source_text", "source_index": index}


def _dispatch(manager: Any, method: str, parts: list[str], body: dict[str, Any], auth: Any,
             *, query: str | dict[str, Any] | None = None,
             request_id: str | None = None) -> Any:
    values = _query(query)
    if method == "POST" and parts == ["v1", "field-packets"]:
        auth.require("intake.submit")
        if values or not request_id:
            raise ValidationError("Field packet submission requires X-Request-ID and no query parameters")
        payload = _normalize_packet(body)
        manager._issue(payload["issue_id"])
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        content_digest = hashlib.sha256(payload["content"].encode("utf-8")).hexdigest()
        existing = manager.store.row("SELECT * FROM field_packets WHERE request_id=?", (request_id,))
        if existing:
            if existing["request_payload_sha256"] != digest:
                raise ConflictError("Request ID was already used for different field packet content")
            return {"status": "received", "packet_id": existing["packet_id"],
                    "content_sha256": existing["content_sha256"], "idempotent_replay": True}
        packet_id = new_id("fp")
        timestamp = datetime.now().astimezone().isoformat(timespec="microseconds")
        with manager.store.transaction() as conn:
            conn.execute("INSERT INTO field_packets(packet_id,request_id,issue_id,content,content_sha256,request_payload_sha256,sources_json,attachment_refs_json,created_at,created_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (packet_id, request_id, payload["issue_id"], payload["content"], content_digest,
                          digest, canonical_json(payload["sources"]), canonical_json(payload["attachment_refs"]),
                          timestamp, auth.actor_id))
            manager.original_access_bindings.admit_packet(payload["issue_id"], packet_id,
                [s["locator"] for s in payload["sources"]] + payload["attachment_refs"])
            conn.execute("INSERT INTO field_packet_curation_heads(packet_id,version,updated_at) VALUES (?,0,?)",
                         (packet_id, timestamp))
            manager.store.audit(conn, actor=auth.actor_id, action="field_packet.receive",
                                object_type="field_packet", object_id=packet_id, before_revision=None,
                                after_revision=1, reason="Receive immutable field packet",
                                payload={"issue_id": payload["issue_id"], "content_sha256": content_digest})
        return {"status": "received", "packet_id": packet_id, "content_sha256": content_digest,
                "idempotent_replay": False}
    if method == "POST" and len(parts) == 4 and parts[3] == "curated-items":
        auth.require("evidence.write")
        if values or not request_id:
            raise ValidationError("Curated item submission requires X-Request-ID and no query parameters")
        packet_id = _decode(parts[2])
        allowed = {"issue_id", "expected_curation_version", "description", "kind", "origin", "reason", "related_evidence"}
        if not isinstance(body, dict) or set(body) - allowed:
            raise ValidationError("Unknown curated item fields")
        packet = _packet_detail(manager, packet_id)
        if body.get("issue_id") != packet["issue_id"]:
            raise ValidationError("Curated item Issue does not match packet Issue")
        origin, locator = _resolve_origin(packet, body.get("origin"))
        description = _text(body.get("description"), "description", 20_000)
        reason = _text(body.get("reason"), "reason", 4_000)
        kind = body.get("kind")
        if kind not in {"observation", "interpretation"}:
            raise ValidationError("kind must be observation or interpretation")
        version = body.get("expected_curation_version")
        if isinstance(version, bool) or not isinstance(version, int) or version < 0:
            raise ValidationError("expected_curation_version must be a non-negative integer")
        related = _related_payload(body.get("related_evidence", []))
        return manager.curate_field_item(packet_id=packet_id, issue_id=packet["issue_id"],
            expected_curation_version=version, description=description, kind=kind, origin=origin,
            source_locator=locator, reason=reason, related_evidence=related, auth=auth,
            idempotency_key=f"http:{auth.actor_id}:{auth.run_id}:{request_id}", request_id=request_id)
    if method == "POST" and len(parts) == 4 and parts[3] == "reviews":
        auth.require("evidence.write")
        if values or not request_id:
            raise ValidationError("Field review requires X-Request-ID and no query parameters")
        packet_id = _decode(parts[2])
        packet = _packet_detail(manager, packet_id)
        allowed = {"issue_id", "expected_curation_version", "handled_fact_refs", "unresolved", "reason"}
        if not isinstance(body, dict) or set(body) - allowed:
            raise ValidationError("Unknown field review fields")
        if body.get("issue_id") != packet["issue_id"]:
            raise ValidationError("Review Issue does not match packet Issue")
        version = body.get("expected_curation_version")
        if isinstance(version, bool) or not isinstance(version, int) or version < 0:
            raise ValidationError("expected_curation_version must be a non-negative integer")
        handled = body.get("handled_fact_refs", [])
        unresolved = body.get("unresolved", [])
        if not isinstance(handled, list) or len(handled) > 100 or not all(isinstance(x, str) for x in handled):
            raise ValidationError("handled_fact_refs must be a list of at most 100 fact_ref strings")
        known = {row["fact_ref"] for row in manager.store.rows("SELECT fact_ref FROM field_facts WHERE packet_id=?", (packet_id,))}
        if any(x not in known for x in handled):
            raise ValidationError("handled_fact_refs must belong to this packet")
        if not isinstance(unresolved, list) or len(unresolved) > 100:
            raise ValidationError("unresolved must contain at most 100 entries")
        normalized_unresolved = []
        for index, item in enumerate(unresolved):
            if not isinstance(item, dict) or set(item) != {"origin", "reason"}:
                raise ValidationError("Each unresolved entry needs origin and reason")
            anchor, _ = _resolve_origin(packet, item["origin"], path=f"/unresolved/{index}/origin")
            normalized_unresolved.append({"origin": anchor, "reason": _text(item["reason"], "unresolved reason", 4_000)})
        reason = _text(body.get("reason"), "reason", 4_000)
        return manager.record_field_review(packet_id=packet_id, issue_id=packet["issue_id"],
            expected_curation_version=version, handled_fact_refs=handled, unresolved=normalized_unresolved,
            reason=reason, auth=auth, idempotency_key=f"http:{auth.actor_id}:{auth.run_id}:{request_id}",
            request_id=request_id)
    if method == "GET" and parts == ["v1", "field-packets"]:
        auth.require("context.read")
        if set(values) - {"issue_id", "limit", "after_packet_id"} or not values.get("issue_id"):
            raise ValidationError("Packet listing requires issue_id and accepts limit and after_packet_id")
        issue_id = values["issue_id"]
        manager._issue(issue_id)
        limit = _int(values, "limit", 20, 1, MAX_PAGE_SIZE)
        cursor = values.get("after_packet_id")
        sql = "SELECT packet_id,created_at,content_sha256,sources_json,attachment_refs_json FROM field_packets WHERE issue_id=?"
        params: list[Any] = [issue_id]
        if cursor:
            anchor = manager.store.row("SELECT created_at,packet_id FROM field_packets WHERE issue_id=? AND packet_id=?", (issue_id, cursor))
            if not anchor:
                raise NotFoundError("after_packet_id is not present in this Issue packet list")
            sql += " AND (created_at<? OR (created_at=? AND packet_id<?))"
            params += [anchor["created_at"], anchor["created_at"], anchor["packet_id"]]
        rows = manager.store.rows(sql + " ORDER BY created_at DESC,packet_id DESC LIMIT ?", params + [limit + 1])
        page = rows[:limit]
        return {"issue_id": issue_id, "items": [{"packet_id": r["packet_id"], "received_at": r["created_at"],
            "source_locators": [s["locator"] for s in _loads(r["sources_json"])],
            "attachment_count": len(_loads(r["attachment_refs_json"])), "content_sha256": r["content_sha256"],
            "status": "received"} for r in page],
            "next_cursor": page[-1]["packet_id"] if len(rows) > limit else None, "count": len(page)}
    if method == "GET" and len(parts) == 3 and parts[:2] == ["v1", "field-packets"]:
        auth.require("context.read")
        if values:
            raise ValidationError("Packet detail does not accept query parameters")
        return _packet_detail(manager, _decode(parts[2]))
    if method == "GET" and len(parts) in {4, 5} and parts[:2] == ["v1", "field-packets"]:
        auth.require("context.read")
        packet_id = _decode(parts[2])
        packet = _metadata(manager, packet_id)
        if parts[3] == "summary":
            if set(values) - {"review_id"}:
                raise ValidationError("Summary accepts only review_id")
            review_id = values.get("review_id")
            if review_id:
                row = manager.store.row("SELECT * FROM field_packet_reviews WHERE packet_id=? AND review_id=?",
                                        (packet_id, review_id))
                if row is None:
                    raise NotFoundError("Review was not found in this packet")
                handled = _loads(row["handled_fact_refs_json"])
                kinds = manager.store.rows(
                    "SELECT kind,COUNT(*) AS n FROM field_facts WHERE packet_id=? AND fact_ref IN (" +
                    ",".join("?" for _ in handled) + ") GROUP BY kind", [packet_id, *handled]
                ) if handled else []
                selected = set(handled)
                total_facts = manager.store.row("SELECT COUNT(*) AS n FROM field_facts WHERE packet_id=?", (packet_id,))["n"]
                mapped_count = manager.store.row("SELECT COUNT(*) AS n FROM field_facts f JOIN field_fact_mapping_heads h USING(fact_ref) WHERE f.packet_id=?", (packet_id,))["n"]
                handled_in_packet = manager.store.row(
                    "SELECT COUNT(DISTINCT fact_ref) AS n FROM field_facts WHERE packet_id=? AND fact_ref IN (" +
                    ",".join("?" for _ in handled) + ")", [packet_id, *handled])["n"] if handled else 0
                handled_mapped = manager.store.row(
                    "SELECT COUNT(DISTINCT f.fact_ref) AS n FROM field_facts f JOIN field_fact_mapping_heads h USING(fact_ref) WHERE f.packet_id=? AND f.fact_ref IN (" +
                    ",".join("?" for _ in handled) + ")", [packet_id, *handled])["n"] if handled else 0
                packet.update({"review": {"review_id": row["review_id"], "version": row["version"],
                    "handled_count": len(handled), "handled_unique_count": len(selected),
                    "handled_kind_counts": {item["kind"]: item["n"] for item in kinds},
                    "unresolved_count": len(_loads(row["unresolved_json"])),
                    "current_unmapped_count": total_facts - mapped_count,
                    "handled_not_current_count": len(selected) - handled_in_packet,
                    "handled_without_current_mapping_count": handled_in_packet - handled_mapped,
                    "statistics_complete": True,
                    "reason_reference": {"tool": "read_field_review", "arguments": {"packet_id": packet_id,
                                         "review_id": row["review_id"]}}}})
            return packet
        if parts[3] in {"text", "locate"}:
            allowed = ({"source_index", "start", "max_bytes", "content_sha256"} if parts[3] == "text"
                       else {"source_index", "quoted_text", "after_start", "limit"})
            if set(values) - allowed:
                raise ValidationError("Unknown source read parameters")
            text, origin = _text_source(manager, packet_id, values)
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if parts[3] == "text":
                if values.get("content_sha256", digest) != digest:
                    raise ConflictError("Source content hash differs from the requested version")
                start = _int(values, "start", 0, 0, len(text))
                budget = _int(values, "max_bytes", 8192, 256, 16384)
                excerpt = text[start:].encode("utf-8")[:budget].decode("utf-8", errors="ignore")
                end = start + len(excerpt)
                return {"packet_id": packet_id, "content_utf8": excerpt, "start": start,
                        "next_cursor": end if end < len(text) else None, "complete": end == len(text),
                        "content_sha256": digest, "origin": origin}
            quote = _text(values.get("quoted_text"), "quoted_text", 4000)
            start = _int(values, "after_start", 0, 0, len(text))
            limit = _int(values, "limit", 3, 1, 8)
            matches: list[dict[str, Any]] = []
            while len(matches) <= limit:
                found = text.find(quote, start)
                if found < 0:
                    break
                matches.append({"origin": {**origin, "quoted_text": quote, "start": found},
                                "content_sha256": digest, "context": text[max(0, found-80):found+len(quote)+80]})
                start = found + 1
            return {"packet_id": packet_id, "matches": matches[:limit],
                    "next_cursor": matches[limit-1]["origin"]["start"]+1 if len(matches)>limit else None,
                    "complete": len(matches)<=limit, "content_sha256": digest,
                    "unique": len(matches)==1 and values.get("after_start", "0")=="0"}
        if parts[3] == "review":
            allowed = {"review_id", "after_handled", "after_unresolved", "max_bytes", "expected_curation_version"}
            if "review_id" not in values or set(values) - allowed:
                raise ValidationError("Review detail requires review_id and accepts bounded page parameters")
            if "expected_curation_version" in values:
                expected = _int(values, "expected_curation_version", 0, 0, 2**63-1)
                if expected != packet["curation_version"]:
                    raise ConflictError("Packet changed between review pages; restart from the current version",
                                        details={"expected": expected, "actual": packet["curation_version"]})
            row = manager.store.row("SELECT * FROM field_packet_reviews WHERE packet_id=? AND review_id=?", (packet_id, values["review_id"]))
            if row is None:
                raise NotFoundError("Review was not found in this packet")
            handled = _loads(row["handled_fact_refs_json"])
            unresolved = _loads(row["unresolved_json"])
            handled_start = _int(values, "after_handled", 0, 0, len(handled))
            unresolved_start = _int(values, "after_unresolved", 0, 0, len(unresolved))
            budget = _int(values, "max_bytes", 8192, 256, 16384)
            handled_page = handled[handled_start:]
            unresolved_page = unresolved[unresolved_start:]
            # Grow both independent pages until the UTF-8 response fits the requested budget.
            handled_page = handled_page[:min(100, len(handled_page))]
            unresolved_page = unresolved_page[:min(20, len(unresolved_page))]
            payload = {"packet_id": packet_id, "review_id": row["review_id"], "version": row["version"],
                    "handled_fact_refs": handled_page, "handled_count": len(handled),
                    "handled_next_cursor": handled_start + len(handled_page) if handled_start + len(handled_page) < len(handled) else None,
                    "unresolved": unresolved_page, "unresolved_count": len(unresolved),
                    "unresolved_next_cursor": unresolved_start + len(unresolved_page) if unresolved_start + len(unresolved_page) < len(unresolved) else None,
                    "reason": row["reason"], "created_by": row["created_by"],
                    "curation_version": packet["curation_version"]}
            while len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > budget:
                if len(unresolved_page) > 1:
                    unresolved_page = unresolved_page[:-1]
                elif len(handled_page) > 1:
                    handled_page = handled_page[:-1]
                elif unresolved_page:
                    unresolved_page = unresolved_page[:-1]
                elif handled_page:
                    handled_page = handled_page[:-1]
                else:
                    raise ValidationError("Review reason exceeds max_bytes; use packet summary or a larger page budget")
                payload["handled_fact_refs"] = handled_page
                payload["handled_next_cursor"] = handled_start + len(handled_page) if handled_start + len(handled_page) < len(handled) else None
                payload["unresolved"] = unresolved_page
                payload["unresolved_next_cursor"] = unresolved_start + len(unresolved_page) if unresolved_start + len(unresolved_page) < len(unresolved) else None
            # Counts use only the review's selected refs, not a scan of every fact in the packet.
            handled_kind_counts: dict[str, int] = {}
            for item in manager.store.rows("SELECT kind,COUNT(*) AS n FROM field_facts WHERE packet_id=? AND fact_ref IN (" +
                                           ",".join("?" for _ in handled) + ") GROUP BY kind", [packet_id, *handled]) if handled else []:
                handled_kind_counts[item["kind"]] = item["n"]
            payload["handled_kind_counts"] = handled_kind_counts
            payload["statistics_complete"] = True
            return payload
        if parts[3] == "facts":
            if len(parts) != 5 or values:
                raise ValidationError("Packet fact detail requires a fact_ref path and no query parameters")
            fact_ref = _decode(parts[4])
            row = manager.store.row("SELECT * FROM field_facts WHERE packet_id=? AND fact_ref=?", (packet_id, fact_ref))
            if row is None:
                raise NotFoundError("Fact was not found in this packet")
            mapping = manager.store.row("SELECT h.mapping_id,h.version,m.evidence_id,m.created_at,m.created_by,m.request_id FROM field_fact_mapping_heads h JOIN field_fact_mapping_versions m USING(mapping_id) WHERE h.fact_ref=?", (fact_ref,))
            return {"fact_ref": row["fact_ref"], "packet_id": packet_id, "issue_id": row["issue_id"],
                    "description": row["description"], "kind": row["kind"], "origin": _loads(row["origin_json"]),
                    "source_locator": row["source_locator"], "created_at": row["created_at"],
                    "created_by": row["created_by"], "mapping": dict(mapping) if mapping else None,
                    "original_access": manager.original_access_bindings.evidence(row["issue_id"], mapping["evidence_id"])
                    if mapping else []}
        if "expected_curation_version" in values:
            expected = _int(values, "expected_curation_version", 0, 0, 2**63-1)
            if expected != packet["curation_version"]:
                raise ConflictError("Packet changed between pages; restart from the current version",
                                    details={"expected": expected, "actual": packet["curation_version"]})
        if parts[3] == "curated-items":
            if set(values) - {"limit", "after_fact_ref", "expected_curation_version", "max_bytes"}:
                raise ValidationError("Curated item history accepts page size, byte budget and cursor")
            limit = _int(values, "limit", 20, 1, MAX_PAGE_SIZE)
            budget = _int(values, "max_bytes", 8192, 256, 16384)
            cursor = values.get("after_fact_ref")
            if cursor and not manager.store.row(
                    "SELECT 1 FROM field_facts WHERE packet_id=? AND fact_ref=?", (packet_id, cursor)):
                raise NotFoundError("after_fact_ref is not present in this packet")
            clause = " AND f.fact_ref>?" if cursor else ""
            params = [packet_id] + ([cursor] if cursor else []) + [limit + 1]
            rows = manager.store.rows("SELECT f.*,m.evidence_id,m.mapping_id,m.version AS mapping_version FROM field_facts f LEFT JOIN field_fact_mapping_heads h USING(fact_ref) LEFT JOIN field_fact_mapping_versions m ON m.mapping_id=h.mapping_id WHERE f.packet_id=?" + clause + " ORDER BY f.fact_ref LIMIT ?", params)
            items = [{"fact_ref": r["fact_ref"],
                      "description": r["description"] if len(r["description"].encode("utf-8")) <= 2048 else r["description"][:512],
                      "description_preview": r["description"][:512],
                      "preview_complete": len(r["description"].encode("utf-8")) <= 512,
                      "kind": r["kind"],
                      "origin": _loads(r["origin_json"]), "source_locator": r["source_locator"],
                      "created_at": r["created_at"], "created_by": r["created_by"],
                      "reference": {"kind": "field_fact", "id": r["fact_ref"], "scope_issue_id": packet["issue_id"],
                                    "version": packet["curation_version"], "readability": "available",
                                    "read": {"tool": "read_field_fact", "arguments": {"packet_id": packet_id,
                                            "fact_ref": r["fact_ref"]}}},
                      "mapping": ({"mapping_id": r["mapping_id"], "evidence_id": r["evidence_id"], "version": r["mapping_version"]} if r["mapping_id"] else None)} for r in rows[:limit]]
            has_more = len(rows) > limit
            while items and len(json.dumps({"items": items}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > budget:
                items.pop()
                has_more = True
            if not items and rows:
                raise ValidationError("One curated item exceeds max_bytes; read it by fact_ref with read_field_fact")
            return {"packet_id": packet_id, "issue_id": packet["issue_id"], "curation_version": packet["curation_version"], "items": items,
                    "next_cursor": items[-1]["fact_ref"] if has_more and items else None}
        if parts[3] == "reviews":
            if set(values) - {"limit", "before_version", "expected_curation_version"}:
                raise ValidationError("Review history accepts limit and before_version")
            limit = _int(values, "limit", 20, 1, MAX_PAGE_SIZE)
            try:
                before = int(values["before_version"]) if "before_version" in values else None
            except ValueError as exc:
                raise ValidationError("before_version must be an integer") from exc
            if before is not None and before < 1:
                raise ValidationError("Review limit must be 1 to 50 and cursor positive")
            clause = " AND version<?" if before is not None else ""
            params = [packet_id] + ([before] if before is not None else []) + [limit + 1]
            rows = manager.store.rows("SELECT * FROM field_packet_reviews WHERE packet_id=?" + clause + " ORDER BY version DESC LIMIT ?", params)
            items = [{"review_id": r["review_id"], "version": r["version"],
                      "handled_count": len(_loads(r["handled_fact_refs_json"])),
                      "unresolved_count": len(_loads(r["unresolved_json"])),
                      "reason_preview": r["reason"][:512], "reason_preview_complete": len(r["reason"]) <= 512,
                      "reference": {"kind": "field_review", "id": r["review_id"], "scope_issue_id": packet["issue_id"],
                                    "version": r["version"], "readability": "available",
                                    "read": {"tool": "read_field_review", "arguments": {"packet_id": packet_id,
                                            "review_id": r["review_id"]}}},
                      "created_at": r["created_at"], "created_by": r["created_by"]} for r in rows[:limit]]
            return {"packet_id": packet_id, "issue_id": packet["issue_id"], "curation_version": packet["curation_version"], "items": items,
                    "next_cursor": items[-1]["version"] if len(rows) > limit else None}
    if method == "GET" and len(parts) == 3 and parts[:2] == ["v1", "field-facts"]:
        auth.require("context.read")
        fact_ref = _decode(parts[2])
        row = manager.store.row("SELECT * FROM field_facts WHERE fact_ref=?", (fact_ref,))
        if not row:
            raise NotFoundError("Field fact was not found")
        mapping = manager.store.row("SELECT h.mapping_id,h.version,m.evidence_id,m.created_at,m.created_by,m.request_id FROM field_fact_mapping_heads h JOIN field_fact_mapping_versions m USING(mapping_id) WHERE h.fact_ref=?", (fact_ref,))
        return {"fact_ref": fact_ref, "packet_id": row["packet_id"], "issue_id": row["issue_id"],
                "description": row["description"], "kind": row["kind"], "origin": _loads(row["origin_json"]),
                "source_locator": row["source_locator"], "created_at": row["created_at"],
                "created_by": row["created_by"], "mapping": dict(mapping) if mapping else None,
                "original_access": manager.original_access_bindings.evidence(row["issue_id"], mapping["evidence_id"])
                if mapping else []}
    if method == "GET" and len(parts) == 4 and parts[:2] == ["v1", "field-facts"] and parts[3] == "mappings":
        auth.require("context.read")
        if set(values) - {"limit", "before_version"}:
            raise ValidationError("Mapping history accepts limit and before_version")
        fact_ref = _decode(parts[2])
        if manager.store.row("SELECT 1 FROM field_facts WHERE fact_ref=?", (fact_ref,)) is None:
            raise NotFoundError("Field fact was not found")
        limit = _int(values, "limit", 20, 1, MAX_PAGE_SIZE)
        try:
            before = int(values["before_version"]) if "before_version" in values else None
        except ValueError as exc:
            raise ValidationError("before_version must be an integer") from exc
        if not 1 <= limit <= MAX_PAGE_SIZE or (before is not None and before < 1):
            raise ValidationError("Mapping history limit must be 1 to 50 and cursor positive")
        clause = " AND version<?" if before is not None else ""
        params = [fact_ref] + ([before] if before is not None else []) + [limit + 1]
        rows = manager.store.rows("SELECT mapping_id,fact_ref,version,evidence_id,created_at,created_by,request_id FROM field_fact_mapping_versions WHERE fact_ref=?" + clause + " ORDER BY version DESC LIMIT ?", params)
        items = [dict(row) for row in rows[:limit]]
        return {"fact_ref": fact_ref, "items": items,
                "next_cursor": items[-1]["version"] if len(rows) > limit else None}
    raise NotFoundError("Unknown field inbox endpoint")
