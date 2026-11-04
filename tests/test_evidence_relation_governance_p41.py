"""P4.1 regression tests for Evidence relation propagation semantics."""

from __future__ import annotations

from contextlib import closing

from issue_manager import IssueManager


def _evidence(manager: IssueManager, issue_id: str, label: str) -> str:
    return manager.add_evidence(
        kind="report",
        locator=f"fixture:p41:{issue_id}:{label}",
        issue_id=issue_id,
        description=label,
    )["evidence_id"]


def _settle_refresh(manager: IssueManager, issue_id: str) -> None:
    with manager.store.transaction() as conn:
        conn.execute(
            "UPDATE refresh_tasks SET state='applied',updated_at=created_at "
            "WHERE issue_id=? AND state IN "
            "('pending','blocked','ready','proposed','awaiting_approval')",
            (issue_id,),
        )
        conn.execute(
            "UPDATE issues SET freshness='fresh',updated_at=created_at WHERE issue_id=?",
            (issue_id,),
        )


def _two_provider_graph(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    manager.create_issue("provider-a", "investigation")
    manager.create_issue("provider-b", "investigation")
    manager.create_issue("consumer", "investigation")
    provider_a = _evidence(manager, "provider-a", "provider-a")
    provider_b = _evidence(manager, "provider-b", "provider-b")
    consumer = _evidence(manager, "consumer", "consumer")
    # Exercise the legacy issue-freshness path that relation propagation still
    # supports for pre-context-maintenance schemas.
    del manager.context_maintenance
    manager.store.before_commit = None
    return manager, provider_a, provider_b, consumer


def test_deactivate_keeps_direct_consumer_target_after_add_refresh_is_settled(tmp_path):
    with closing(IssueManager.initialize(tmp_path / "ledger")) as manager:
        manager.create_issue("provider", "investigation")
        manager.create_issue("consumer", "investigation")
        provider = _evidence(manager, "provider", "provider")
        consumer = _evidence(manager, "consumer", "consumer")
        del manager.context_maintenance
        manager.store.before_commit = None
        relation = manager.evidence_relations.add(
            consumer, provider, "depends_on", impact_policy="hard"
        )
        _settle_refresh(manager, "consumer")
        assert manager.store.rows(
            "SELECT * FROM refresh_tasks WHERE issue_id=? AND state IN "
            "('pending','blocked','ready','proposed','awaiting_approval')",
            ("consumer",),
        ) == []

        result = manager.evidence_relations.deactivate(
            relation["relation_id"], actor="organizer-agent", reason="withdraw dependency"
        )

        impact = next(
            item for item in result["impacts"] if item["relation_id"] == relation["relation_id"]
        )
        assert impact["affected_issue_id"] == "consumer"
        assert impact["refresh_task_id"] is not None
        assert impact["disposition"] == "refresh_enqueued"
        assert manager.store.row(
            "SELECT state FROM refresh_tasks WHERE issue_id=? AND state IN "
            "('pending','blocked','ready','proposed','awaiting_approval')",
            ("consumer",),
        )["state"] == "blocked"


def test_hard_then_soft_refresh_and_freshness_remain_monotonic(tmp_path):
    manager, provider_a, provider_b, consumer = _two_provider_graph(tmp_path)
    try:
        manager.evidence_relations.add(
            consumer, provider_a, "depends_on", impact_policy="hard"
        )
        manager.evidence_relations.add(
            consumer, provider_b, "supports", impact_policy="soft"
        )

        assert manager.store.row(
            "SELECT state FROM refresh_tasks WHERE issue_id=? AND state IN "
            "('pending','blocked','ready','proposed','awaiting_approval')",
            ("consumer",),
        )["state"] == "blocked"
        assert manager.show_issue("consumer")["freshness"] == "stale"
    finally:
        manager.close()


def test_soft_then_hard_refresh_escalates_to_blocked(tmp_path):
    manager, provider_a, provider_b, consumer = _two_provider_graph(tmp_path)
    try:
        manager.evidence_relations.add(
            consumer, provider_a, "supports", impact_policy="soft"
        )
        manager.evidence_relations.add(
            consumer, provider_b, "depends_on", impact_policy="hard"
        )

        assert manager.store.row(
            "SELECT state FROM refresh_tasks WHERE issue_id=? AND state IN "
            "('pending','blocked','ready','proposed','awaiting_approval')",
            ("consumer",),
        )["state"] == "blocked"
        assert manager.show_issue("consumer")["freshness"] == "stale"
    finally:
        manager.close()
