"""Finite generic read routes for project browsing."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl

from .browse_service import BrowseService
from .errors import ConflictError, ValidationError

KINDS = {"issue", "children", "evidence", "detail", "neighbors", "conclusions"}


def handles(method: str, parts: list[str]) -> bool:
    return method == "GET" and len(parts) == 3 and parts[:2] == ["v1", "browse"]


def dispatch(manager, parts, query, auth):
    if parts[2] not in KINDS or re.search(r"%(?![0-9A-Fa-f]{2})", query):
        raise ValidationError("Invalid browse route/query")
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True,
                          encoding="utf-8", errors="strict")
        values = dict(pairs)
        if (len(values) != len(pairs) or set(values) - {
                "id", "limit", "cursor", "expected_snapshot", "split_observation"}):
            raise ValueError
        observation = values.get("split_observation")
        if observation is not None and (observation != "1" or parts[2] not in {"detail", "neighbors"}):
            raise ValueError
        limit = int(values.get("limit", "20"))
    except (ValueError, UnicodeError) as exc:
        raise ValidationError("Invalid browse query") from exc
    with manager.store.read_transaction():
        result = BrowseService(manager).read(parts[2], values.get("id", ""),
                                            auth=auth, limit=limit, cursor=values.get("cursor"),
                                            expected_snapshot=values.get("expected_snapshot"))
        if observation:
            from .direct_split_boundary import snapshot
            try:
                result["split_observation"] = snapshot(manager, values.get("id", ""), auth=auth)["snapshot"]
            except ConflictError as exc:
                if exc.details.get("code") != "split_boundary_too_large":
                    raise
                result["split_observation"] = {"status": "unavailable", "code": "split_boundary_too_large"}
        return result
