"""Independent review duties and publication gates, separate from currentness."""

from __future__ import annotations

import json

from .errors import ConflictError, NotFoundError, PermissionError, ValidationError
from .store import canonical_json, new_id, now


class ContextObligationService:
    def __init__(self, manager):
        self.manager = manager
        self.store = manager.store

    def get(self, identity, *, state_view=None):
        if state_view is not None and identity in state_view.obligations:
            return state_view.obligations[identity]
        return self.store.row("SELECT * FROM context_workflow_obligations WHERE obligation_id=?", (identity,))

    def list(self, conclusion_id):
        return [{**row, "details": json.loads(row["details_json"])} for row in self.store.rows(
            "SELECT * FROM context_workflow_obligations WHERE conclusion_id=? ORDER BY obligation_id", (conclusion_id,))]

    def show(self, identity):
        row = self.get(identity)
        if not row:
            raise NotFoundError("Review obligation not found")
        return {**row, "details": json.loads(row["details_json"]), "events": self.store.rows(
            "SELECT * FROM context_workflow_obligation_events WHERE obligation_id=? ORDER BY revision", (identity,))}

    def blocking_for_issue(self, issue_id, *, state_view=None):
        rows = {row["obligation_id"]: row for row in self.store.rows(
            "SELECT o.* FROM context_workflow_obligations o JOIN conclusion_revisions c USING(conclusion_id) "
            "WHERE c.issue_id=? AND o.state='open' AND o.blocks_publication=1", (issue_id,))}
        if state_view is not None:
            for identity, row in state_view.obligations.items():
                rows.pop(identity, None)
                owner = self.store.row("SELECT issue_id FROM conclusion_revisions WHERE conclusion_id=?", (row["conclusion_id"],))
                if owner and owner["issue_id"] == issue_id and row["state"] == "open" and row["blocks_publication"]:
                    rows[identity] = row
        return sorted(rows)

    def require_publication(self, issue_id, *, state_view=None):
        blocked = self.blocking_for_issue(issue_id, state_view=state_view)
        if blocked:
            raise ConflictError("Independent review is required before formal publication", details={"obligation_ids": blocked})

    def preview(self, operation, *, state_view=None):
        action = operation.get("action")
        common = {"op", "action", "obligation_id", "reason"}
        fields = common | ({"conclusion_id", "details", "blocks_publication"} if action == "open" else {"expected_revision"})
        if action not in {"open", "complete", "cancel", "reopen"} or set(operation) != fields:
            raise ValidationError("Invalid independent review obligation operation")
        if any(not isinstance(operation[key], str) or not operation[key].strip() for key in ("obligation_id", "reason")):
            raise ValidationError("Obligation identity and reason must be nonempty strings")
        old = self.get(operation["obligation_id"], state_view=state_view)
        if action == "open":
            if old:
                raise ConflictError("Review obligation identity already exists")
            if not isinstance(operation["details"], dict) or type(operation["blocks_publication"]) is not bool:
                raise ValidationError("Obligation details must be an object and publication gate must be boolean")
            if not isinstance(operation["conclusion_id"], str) or not self.store.row(
                "SELECT 1 FROM conclusion_revisions WHERE conclusion_id=?", (operation["conclusion_id"],)):
                raise NotFoundError("Review obligation needs an existing conclusion version")
            new = {"obligation_id": operation["obligation_id"], "conclusion_id": operation["conclusion_id"],
                   "kind": "independent_review", "state": "open", "details_json": canonical_json(operation["details"]),
                   "blocks_publication": int(operation["blocks_publication"]), "revision": 0}
        else:
            if not old or type(operation["expected_revision"]) is not int or operation["expected_revision"] != old["revision"]:
                raise ConflictError("Review obligation revision changed or does not exist")
            if (action == "reopen") == (old["state"] == "open"):
                raise ConflictError("Review obligation transition does not apply to its current state")
            new = {**old, "state": {"complete": "completed", "cancel": "cancelled", "reopen": "open"}[action],
                   "revision": old["revision"] + 1}
        return {"before": old, "after": new}

    def assert_independent(self, conclusion_id, reviewer_actor, reviewer_run=None):
        author = self.store.row("SELECT c.created_by,p.proposer_actor_id,p.proposer_run_id AS created_run_id FROM conclusion_revisions c LEFT JOIN proposals p USING(proposal_id) "
                                "WHERE c.conclusion_id=?", (conclusion_id,))
        if author and reviewer_actor in {author["created_by"], author["proposer_actor_id"]}:
            raise PermissionError("A conclusion author cannot discharge its independent review obligation")
        if author and author["created_run_id"] and reviewer_run:
            def lineage(run):
                row = self.store.row("SELECT lineage_json FROM agent_runs WHERE run_id=?", (run,))
                return set(json.loads(row["lineage_json"])) | {run} if row else {run}
            if author["created_run_id"] in lineage(reviewer_run) or reviewer_run in lineage(author["created_run_id"]):
                raise PermissionError("The conclusion author's delegation lineage cannot discharge its review obligation")

    def execute(self, operation, *, actor, changeset_id, reviews):
        with self.store.transaction() as conn:
            preview = self.preview(operation)
            row = preview["after"]
            reviewers = []
            if operation["action"] in {"complete", "cancel"}:
                for review in reviews:
                    if review["decision"] == "pass":
                        self.assert_independent(row["conclusion_id"], review["reviewer_actor_id"], review["reviewer_run_id"])
                        reviewers.append(review["reviewer_actor_id"])
                if not reviewers:
                    raise PermissionError("Closing an independent review obligation requires a passed independent review")
            if preview["before"] is None:
                row = {**row, "created_at": now(), "created_by": actor}
                conn.execute(f'INSERT INTO context_workflow_obligations ({",".join(row)}) VALUES ({",".join("?" for _ in row)})', tuple(row.values()))
            else:
                conn.execute("UPDATE context_workflow_obligations SET state=?,revision=? WHERE obligation_id=?",
                             (row["state"], row["revision"], row["obligation_id"]))
            conn.execute("INSERT INTO context_workflow_obligation_events VALUES (?,?,?,?,?,?,?,?,?)",
                         (new_id("obligation_event"), row["obligation_id"], row["revision"], row["state"], actor,
                          operation["reason"], canonical_json(sorted(set(reviewers))), changeset_id, now()))
            return {"obligation_id": row["obligation_id"], "conclusion_id": row["conclusion_id"], "state": row["state"], "revision": row["revision"]}
