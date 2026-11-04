"""Finite public HTTP boundary for Issue conclusion rules."""

from urllib.parse import parse_qsl

from .conclusion_rule_service import ConclusionRuleService
from .errors import PermissionError, ValidationError


def handles(method, parts):
    return len(parts) >= 2 and parts[:2] == ["v1", "conclusion-rules"]


def dispatch(manager, method, parts, body, query, auth, *, idempotency_key):
    if auth.platform_id is not None:
        raise PermissionError("Platform-scoped principals cannot access project conclusion rules")
    auth.require("context.read")
    service = ConclusionRuleService(manager)
    if method == "GET" and parts == ["v1", "conclusion-rules", "types"]:
        try:
            pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True) if query else []
            values = dict(pairs)
            if len(values) != len(pairs) or set(values) - {"limit", "cursor", "expected_snapshot"}:
                raise ValueError
            limit = int(values.get("limit", "20"))
            if not 1 <= limit <= 50:
                raise ValueError
        except ValueError as exc:
            raise ValidationError("Invalid Issue type catalog query") from exc
        with manager.store.read_transaction():
            entries = manager.registry.list_entries(kind="issue_type")
            from .browse_service import BrowseService
            BrowseService._budget(entries)
            items = []
            for entry in entries:
                if entry["state"] != "active":
                    continue
                definition = manager.registry.show_entry(entry["registration_id"])
                items.append({**entry, "schema": definition["semantic_definition"]["conclusion"]["structured_outputs_schema"]})
            return BrowseService(manager)._page(items, query=["conclusion-rule-types"], auth=auth,
                                               limit=limit, cursor=values.get("cursor"),
                                               expected_snapshot=values.get("expected_snapshot"))
    if len(parts) != 4 or parts[2] != "issue":
        raise ValidationError("Invalid conclusion rule route")
    issue_id = parts[3]
    if method == "POST" and not query:
        return service.write(issue_id, body, auth=auth, idempotency_key=idempotency_key)
    if method != "GET":
        raise ValidationError("Invalid conclusion rule method")
    try:
        pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True) if query else []
        if len(pairs) > 1 or (pairs and pairs[0][0] != "revision"):
            raise ValueError
        revision = int(pairs[0][1]) if pairs else None
        if revision is not None and revision < 0:
            raise ValueError
    except ValueError as exc:
        raise ValidationError("Invalid conclusion rule revision") from exc
    return service.current(issue_id, revision=revision)
