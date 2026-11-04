"""Shared planning decisions for Issue dependency relations."""
from __future__ import annotations

from typing import Any

from .errors import ConflictError, NotFoundError, ValidationError


def plan_add(view: Any, operation: dict[str, Any]) -> dict[str, Any]:
    consumer = str(operation["consumer"])
    provider = str(operation["provider"])
    relation_type = str(operation["relation_type"])
    consumer_issue = view.issue(consumer)
    provider_issue = view.issue(provider)
    if consumer_issue.get("work_status") in {"archived", "void"} or provider_issue.get("work_status") in {"archived", "void"}:
        raise NotFoundError("Issue not found or inactive")
    if consumer == provider:
        raise ValidationError("A relation cannot point to the same issue")
    impact_policy = operation.get("impact_policy") or view.manager.policy.default_impact(relation_type)
    if impact_policy not in {"hard", "soft", "notify", "none"}:
        raise ValidationError(f"Unknown impact policy: {impact_policy}")
    relation_key = (consumer, provider, relation_type)
    if not hasattr(view.manager, "context_maintenance") and (
        relation_key in view.new_issue_relations
        or any(
            row["provider_issue_id"] == provider and row["relation_type"] == relation_type
            for row in view.context_rows("relations", "consumer_issue_id", consumer)
        )
    ):
        raise ConflictError("This relation already exists (including inactive rows)")
    hard_cycle = impact_policy == "hard" and view.hard_issue_cycle(consumer, provider)
    return {
        "consumer": consumer,
        "provider": provider,
        "relation_type": relation_type,
        "impact_policy": impact_policy,
        "hard_cycle": hard_cycle,
        "reason": str(operation.get("reason", "")),
    }


def plan_lifecycle(view: Any, operation: dict[str, Any]) -> dict[str, Any]:
    relation_id = str(operation["relation_id"])
    relation = view.issue_relation(relation_id)
    if not relation:
        error = NotFoundError if operation.get("_direct") else ValidationError
        raise error(f"Relation not found: {relation_id}")
    action = str(operation["op"])
    target_active = action == "reactivate_relation"
    hard_cycle = (
        target_active
        and relation["impact_policy"] == "hard"
        and view.hard_issue_cycle(
            str(relation["consumer_issue_id"]), str(relation["provider_issue_id"]), excluding=relation_id
        )
    )
    return {
        "relation_id": relation_id,
        "relation": relation,
        "target_active": target_active,
        "hard_cycle": hard_cycle,
    }


def plan_impact(view: Any, operation: dict[str, Any]) -> dict[str, Any]:
    relation_id = str(operation["relation_id"])
    impact_policy = str(operation["impact_policy"])
    if impact_policy not in {"hard", "soft", "notify", "none"}:
        raise ValidationError(f"Unknown impact policy: {impact_policy}")
    relation = view.issue_relation(relation_id)
    if not relation:
        error = NotFoundError if operation.get("_direct") else ValidationError
        raise error(f"Relation not found: {relation_id}")
    hard_cycle = (
        bool(relation["active"])
        and impact_policy == "hard"
        and relation["impact_policy"] != "hard"
        and view.hard_issue_cycle(
            str(relation["consumer_issue_id"]), str(relation["provider_issue_id"]), excluding=relation_id
        )
    )
    return {
        "relation_id": relation_id,
        "relation": relation,
        "impact_policy": impact_policy,
        "hard_cycle": hard_cycle,
    }
