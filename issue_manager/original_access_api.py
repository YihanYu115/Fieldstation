"""Finite HTTP contract for inert project original-access instructions."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl

from .errors import ValidationError
from .original_access_service import OriginalAccessService


def handles(method: str, parts: list[str]) -> bool:
    return parts[:2] == ["v1", "original-access"]


def dispatch(manager, method, parts, body, query, auth):
    service = OriginalAccessService(manager)
    if method == "POST" and parts == ["v1", "original-access"] and not query:
        return service.write(body, auth=auth)
    if method != "GET" or len(parts) != 3 or parts[2] not in {"discover", "read"}:
        raise ValidationError("Invalid original-access route")
    try:
        if re.search(r"%(?![0-9A-Fa-f]{2})", query):
            raise ValueError
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True,
                          encoding="utf-8", errors="strict")
        values = dict(pairs)
        allowed = ({"issue_id", "reference", "contract_id", "limit", "cursor", "expected_snapshot"}
                   if parts[2] == "discover" else {"issue_id", "contract_id", "revision", "max_bytes", "evidence_id", "reference"})
        if len(values) != len(pairs) or set(values) - allowed or not values.get("issue_id"):
            raise ValueError
        for field in {"limit", "revision", "max_bytes"} & set(values):
            values[field] = int(values[field])
        if parts[2] == "read" and "evidence_id" not in values and not {"contract_id", "revision"} <= set(values):
            raise ValueError
    except (ValueError, UnicodeError) as exc:
        raise ValidationError("Invalid original-access query") from exc
    return getattr(service, parts[2])(**values, auth=auth)
