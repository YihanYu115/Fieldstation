"""HTTP boundary for the bounded, read-only Issue overview projection."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl

from .errors import ValidationError


def handles(method: str, parts: list[str]) -> bool:
    return method == "GET" and parts == ["v1", "issues", "overview"]


def dispatch(manager, query: str, auth):
    if re.search(r"%(?![0-9A-Fa-f]{2})", query):
        raise ValidationError("Malformed URL escape in overview query")
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True,
                          encoding="utf-8", errors="strict") if query else []
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValidationError("Invalid overview query string") from exc
    if len(pairs) != 1 or pairs[0][0] != "root" or not pairs[0][1].strip():
        raise ValidationError("overview accepts exactly one non-empty root parameter")
    return manager.issue_overview(pairs[0][1], auth=auth)
