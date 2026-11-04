"""Read-only, exact-Issue replay of immutable transaction facts, without scheduling."""
from __future__ import annotations

from urllib.parse import parse_qsl

from .errors import ConflictError, PermissionError, ValidationError


def handles(method: str, parts: list[str]) -> bool:
    return method == "GET" and parts == ["v1", "events"]


def dispatch(manager, query: str, auth):
    auth.require("context.read")
    # Like the subtree overview, a project fact feed must not leak platform peers.
    if auth.platform_id is not None:
        raise PermissionError("Platform-scoped principals cannot read a project event feed")
    try:
        pairs = parse_qsl(query, strict_parsing=True, keep_blank_values=True,
                          encoding="utf-8", errors="strict", max_num_fields=6)
        args = dict(pairs)
        if len(args) != len(pairs) or set(args) - {
            "issue_id", "after", "limit", "stream_id", "start"
        }:
            raise ValueError
        issue = args["issue_id"]
        after, limit = int(args.get("after", "0")), int(args.get("limit", "50"))
        if not issue.strip() or len(issue) > 256 or after < 0 or not 1 <= limit <= 50:
            raise ValueError
        if args.get("start") not in {None, "now"} or ("start" in args and "after" in args):
            raise ValueError
    except (KeyError, ValueError, UnicodeError) as exc:
        raise ValidationError("events requires issue_id, after>=0, limit=1..50 or start=now") from exc
    with manager.store.read_transaction():
        manager._issue(issue, active=False)
        stream = manager.store.row("SELECT stream_id FROM domain_event_stream WHERE singleton=1")["stream_id"]
        if args.get("stream_id", stream) != stream:
            raise ConflictError("Event stream changed; explicit rebind/replay authorization required")
        high = manager.store.row("SELECT COALESCE(MAX(sequence),0) AS n FROM domain_events")["n"]
        if after > high:
            raise ConflictError("Event position exceeds the restored stream; explicit reconciliation required")
        if args.get("start") == "now":
            return {"stream_id": stream, "issue_id": issue, "items": [],
                    "next_after": high, "high_watermark": high, "has_more": False}
        rows = manager.store.rows(
            "SELECT * FROM domain_events WHERE issue_id=? AND sequence>? AND sequence<=? "
            "ORDER BY sequence LIMIT ?", (issue, after, high, limit + 1))
        more = len(rows) > limit
        items = rows[:limit]
        return {"stream_id": stream, "issue_id": issue, "items": items,
                "next_after": items[-1]["sequence"] if more else high,
                "high_watermark": high, "has_more": more}
