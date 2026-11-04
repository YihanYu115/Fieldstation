"""Atomic replacement of a named relationship with optimistic version checks."""

from __future__ import annotations

from .errors import ConflictError, NotFoundError, ValidationError
from .store import now


class RelationVersionService:
    def __init__(self, manager):
        self.manager = manager
        self.store = manager.store

    def preview(self, operation, *, state_view=None):
        from .changeset_state import StateView

        view = state_view or StateView(self.manager)
        domain = operation.get("domain")
        if domain not in {"issue", "evidence"}:
            raise ValidationError("Relation domain must be issue or evidence")
        table = "relations" if domain == "issue" else "evidence_relations"
        relation_id = operation.get("relation_id")
        old = view.issue_relation(relation_id) if domain == "issue" else view.evidence_relation(relation_id)
        head = view.material_head(domain, relation_id)
        if not old or not head:
            raise NotFoundError("Relation not found")
        if head["version_id"] != operation.get("expected_version_id"):
            raise ConflictError("Relation version changed; rebase replacement")
        if not old["active"]:
            raise ConflictError("An inactive relation must be explicitly reactivated before replacement")
        replacement = operation.get("replacement")
        fields = {f"consumer_{domain}_id", f"provider_{domain}_id", "relation_type", "impact_policy"}
        fields.add("reason" if domain == "issue" else "rationale")
        if not isinstance(replacement, dict) or not replacement or set(replacement) - fields:
            raise ValidationError("Replacement contains unsupported relation fields")
        if any(not isinstance(value, str) for value in replacement.values()):
            raise ValidationError("Replacement fields must be strings")
        if not isinstance(operation.get("reason"), str) or not operation["reason"].strip():
            raise ValidationError("Relation replacement needs a reason")
        new = {**old, **replacement}
        consumer, provider = new[f"consumer_{domain}_id"], new[f"provider_{domain}_id"]
        if consumer == provider:
            raise ValidationError("Relation endpoints must differ")
        from .relation_contracts import RELATION_ROLES

        if new["relation_type"] not in RELATION_ROLES[domain]:
            raise ValidationError("Unknown relation role")
        allowed_impact = {"hard", "soft", "notify", "none"} if domain == "issue" else {"hard", "soft", "informational"}
        if new["impact_policy"] not in allowed_impact:
            raise ValidationError("Unknown relation impact policy")
        if domain == "issue":
            for endpoint in (consumer, provider):
                if view.issue(endpoint)["work_status"] in {"archived", "void"}:
                    raise ValidationError("Replacement requires active Issue endpoints")
        else:
            new["consumer_snapshot_hash"] = self.manager.evidence_relations._snapshot_hash(view.evidence(consumer))
            new["provider_snapshot_hash"] = self.manager.evidence_relations._snapshot_hash(view.evidence(provider))
        if new["impact_policy"] == "hard":
            cycle = view.hard_issue_cycle if domain == "issue" else view.hard_evidence_cycle
            if cycle(consumer, provider, excluding=relation_id):
                raise ValidationError("Replacement violates the hard relation acyclicity contract")
        return {"domain": domain, "table": table, "before": old, "after": new, "version_id": head["version_id"]}

    def replace(self, operation, *, actor):
        with self.store.transaction() as conn:
            preview = self.preview(operation)
            new = preview["after"]
            if preview["before"] == new:
                return {"relation_id": new["relation_id"], "version_id": preview["version_id"], "unchanged": True}
            values = dict(operation["replacement"])
            if preview["domain"] == "evidence":
                values["provider_snapshot_hash"] = self.manager.evidence_relations._snapshot_hash(
                    self.manager.evidence_relations._evidence(new["provider_evidence_id"]))
                values["consumer_snapshot_hash"] = self.manager.evidence_relations._snapshot_hash(
                    self.manager.evidence_relations._evidence(new["consumer_evidence_id"]))
                values["updated_at"] = now()
            # Field names are restricted by preview, never supplied as SQL.
            assignments = ",".join(f'"{field}"=?' for field in values)
            conn.execute(f"UPDATE {preview['table']} SET {assignments} WHERE relation_id=?",
                         (*values.values(), new["relation_id"]))
            head = conn.execute("SELECT version_id FROM managed_relation_heads WHERE domain=? AND relation_id=?",
                                (preview["domain"], new["relation_id"])).fetchone()[0]
            self.store.audit(conn, actor=actor, action="relation.replace", object_type="relation",
                             object_id=new["relation_id"], before_revision=None, after_revision=None,
                             reason=operation["reason"], payload={"before_version_id": preview["version_id"],
                                                                "after_version_id": head})
            return {"relation_id": new["relation_id"], "before_version_id": preview["version_id"], "version_id": head}
