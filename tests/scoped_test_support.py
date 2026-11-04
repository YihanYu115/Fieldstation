"""Explicit-root fixtures for transport, transaction and concurrency tests."""

def prepare_explicit(manager, issue_id, **kwargs):
    if "evidence_ids" not in kwargs:
        roots = [row["evidence_id"] for row in manager.store.rows(
            "SELECT evidence_id FROM issue_evidence WHERE issue_id=? ORDER BY evidence_id", (issue_id,))]
        if not roots:
            roots = [manager.add_evidence(kind="external", locator=f"urn:test:basis:{issue_id}",
                                          issue_id=issue_id)["evidence_id"]]
        kwargs["evidence_ids"] = roots
    return manager.context_maintenance.prepare(issue_id, **kwargs)
