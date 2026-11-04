from __future__ import annotations

import pytest

from issue_manager.evidence_relation_impact import plan_change


def _relation(relation_id, consumer, provider, impact):
    return {
        "relation_id": relation_id,
        "consumer_evidence_id": consumer,
        "provider_evidence_id": provider,
        "relation_type": "depends_on",
        "impact_policy": impact,
        "active": 1,
        "rationale": relation_id,
    }


def _plan(relations, *, source="root"):
    return plan_change(
        "provider",
        relations=relations,
        affected_targets={
            "consumer-a": [{"issue_id": "issue-a", "conclusion_id": None}],
            "consumer-b": [{"issue_id": "issue-b", "conclusion_id": None}],
            "grandchild": [{"issue_id": "issue-c", "conclusion_id": None}],
        },
        provider_issue_ids={"provider": "issue-provider", "consumer-a": "issue-a"},
        source_event_type="test",
        source_event_id=source,
    )


def test_planner_is_deterministic_and_respects_strength_and_direction():
    relations = [
        _relation("soft-sibling", "consumer-b", "provider", "soft"),
        _relation("hard-direct", "consumer-a", "provider", "hard"),
        _relation("hard-downstream", "grandchild", "consumer-a", "hard"),
        _relation("informational", "consumer-b", "grandchild", "informational"),
    ]
    first = _plan(relations)
    second = _plan(list(reversed(relations)))
    assert first == second
    assert [item["relation_id"] for item in first] == [
        "hard-direct",
        "soft-sibling",
        "hard-downstream",
    ]
    assert all(item["provider_evidence_id"] != "consumer-b" for item in first)


def test_planner_preserves_locality_for_unrelated_sibling():
    relations = [
        _relation("changed", "consumer-a", "provider", "hard"),
        _relation("sibling", "consumer-b", "provider", "hard"),
        _relation("downstream", "grandchild", "consumer-a", "hard"),
    ]
    planned = _plan(relations)
    assert {item["relation_id"] for item in planned} == {
        "changed",
        "sibling",
        "downstream",
    }


def test_lifecycle_delta_starts_at_changed_edge_not_provider_siblings():
    relations = [
        _relation("changed", "consumer-a", "provider", "hard"),
        _relation("sibling", "consumer-b", "provider", "hard"),
        _relation("downstream", "grandchild", "consumer-a", "hard"),
    ]
    changed = next(row for row in relations if row["relation_id"] == "changed")
    planned = plan_change(
        "provider",
        relations=relations,
        delta_relation=changed,
        affected_targets={
            "consumer-a": [{"issue_id": "issue-a", "conclusion_id": None}],
            "consumer-b": [{"issue_id": "issue-b", "conclusion_id": None}],
            "grandchild": [{"issue_id": "issue-c", "conclusion_id": None}],
        },
        provider_issue_ids={"provider": "issue-provider", "consumer-a": "issue-a"},
        source_event_type="lifecycle",
    )
    assert [item["relation_id"] for item in planned] == ["changed", "downstream"]


def test_planner_rejects_unbounded_closure():
    relations = [
        _relation("one", "consumer-a", "provider", "hard"),
        _relation("two", "grandchild", "consumer-a", "hard"),
    ]
    with pytest.raises(ValueError, match="maximum closure"):
        plan_change(
            "provider",
            relations=relations,
            affected_targets={},
            provider_issue_ids={},
            source_event_type="test",
            maximum_nodes=1,
        )
