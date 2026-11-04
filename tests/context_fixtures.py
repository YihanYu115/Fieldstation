"""Explicit history fixtures and fault injection, never production write paths."""

from contextlib import contextmanager

from issue_manager.store import new_id


@contextmanager
def corrupt_history(manager, table):
    """Inject disk-corruption test data while restoring all guards atomically.

    These tests exercise integrity diagnostics, not authorized content edits.
    Keep journal triggers so currentness still observes the corrupt input.
    """
    if table not in {"conclusion_revisions", "record_revisions", "evidence_proofs"}:
        raise ValueError("Unsupported history corruption fixture")
    with manager.store.transaction() as conn:
        name = f"context_immutable_{table}_update"
        guard = conn.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone()
        if guard:
            conn.execute(f'DROP TRIGGER "{name}"')
        try:
            yield conn
        finally:
            if guard:
                conn.execute(guard[0])


def append_status_version(manager, conclusion_id, status):
    """A retained alternate status version for withdrawal-validation tests."""
    row = manager.store.row("SELECT * FROM conclusion_revisions WHERE conclusion_id=?", (conclusion_id,))
    row["conclusion_id"] = new_id("conclusion_fixture")
    row["status"] = status
    row["proposal_id"] = None
    row["revision_number"] = manager.store.row(
        "SELECT MAX(revision_number)+1 AS revision FROM conclusion_revisions WHERE issue_id=?", (row["issue_id"],)
    )["revision"]
    with manager.store.transaction() as conn:
        conn.execute(f'INSERT INTO conclusion_revisions ({",".join(row)}) VALUES ({",".join("?" for _ in row)})',
                     tuple(row.values()))
    return row["conclusion_id"]


def apply_reviewed_changeset(manager, credential, operations):
    created = manager.changesets.create(
        {"changeset_version": 1, "intent": "Reviewed test operation", "operations": operations}, credential=credential)
    manager.changesets.validate(created["changeset_id"], credential=credential)
    for index in range(created["risk"]["required_reviews"]):
        reviewer = manager.credentials.path_for(f"review-agent-{index + 1}")
        manager.changesets.claim_review(created["changeset_id"], credential=reviewer)
        manager.changesets.submit_review(created["changeset_id"], decision="pass", rationale="Reviewed the operation and inputs", credential=reviewer)
    return manager.changesets.apply(created["changeset_id"], credential=credential)
