"""Issue-local, append-only structured conclusion rules."""

from __future__ import annotations

import hashlib
import json

from .conclusion_rule_schema import validate_conclusion_rule_schema
from .errors import ConflictError, PermissionError, ValidationError
from .store import canonical_json, now


class ConclusionRuleService:
    def __init__(self, manager):
        self.manager = manager
        self.store = manager.store

    def current(self, issue_id, *, issue=None, revision=None):
        issue = issue if issue is not None else self.manager._issue(issue_id, active=False)
        if revision == 0:
            row = None
        elif revision is None:
            row = self.store.row(
                "SELECT * FROM issue_conclusion_rule_versions WHERE issue_id=? "
                "ORDER BY revision DESC LIMIT 1", (issue_id,))
        else:
            row = self.store.row("SELECT * FROM issue_conclusion_rule_versions WHERE issue_id=? AND revision=?",
                                 (issue_id, revision))
            if row is None:
                from .errors import NotFoundError
                raise NotFoundError("Conclusion rule version not found")
        if row:
            schema = json.loads(row.pop("schema_json"))
            actual = hashlib.sha256(canonical_json(schema).encode("utf-8")).hexdigest()
            if actual != row["schema_hash"]:
                raise ConflictError("Conclusion rule schema hash mismatch")
            return {**row, "schema": schema, "source": "issue_override"}
        snapshot = self.manager._issue_semantic_snapshot(issue)
        schema = snapshot["definition"]["conclusion"]["structured_outputs_schema"]
        return {"issue_id": issue_id, "revision": 0, "schema": schema,
                "schema_hash": hashlib.sha256(canonical_json(schema).encode("utf-8")).hexdigest(),
                "source": "issue_type_snapshot"}

    def bind(self, conn, conclusion_id, rule):
        encoded = canonical_json(rule["schema"])
        conn.execute("INSERT INTO conclusion_rule_bindings VALUES (?,?,?,?,?)",
                     (conclusion_id, rule["issue_id"], rule["revision"], encoded, rule["schema_hash"]))

    def write(self, issue_id, body, *, auth, idempotency_key):
        auth.require("issue.write")
        auth.require("context.read")
        if auth.platform_id is not None:
            raise PermissionError("Platform-scoped principals cannot modify conclusion rules")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValidationError("Conclusion rule writes require an Idempotency-Key")
        if not isinstance(body, dict) or set(body) != {"expected_revision", "schema", "reason"}:
            raise ValidationError("Expected expected_revision, schema and reason")
        expected = body["expected_revision"]
        reason = body["reason"]
        if type(expected) is not int or expected < 0:
            raise ValidationError("expected_revision must be a nonnegative integer")
        if not isinstance(reason, str) or not reason.strip() or len(reason.encode("utf-8")) > 2048:
            raise ValidationError("reason must be nonempty and at most 2048 bytes")
        payload = {"issue_id": issue_id, **body}
        operation = f"conclusion.rule.write:{auth.actor_id}:{auth.run_id}"
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation, idempotency_key, payload)
            if replay is not None:
                return replay
            schema = validate_conclusion_rule_schema(body["schema"])
            self.manager._issue(issue_id)
            current = self.current(issue_id)
            if current["revision"] != expected:
                raise ConflictError("Conclusion rule changed; read current rule before updating",
                                    details={"expected_revision": expected,
                                             "current_revision": current["revision"]})
            encoded = canonical_json(schema)
            result = {"issue_id": issue_id, "revision": expected + 1, "schema": schema,
                      "schema_hash": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
                      "source": "issue_override", "reason": reason,
                      "created_at": now(), "created_by": auth.actor_id}
            conn.execute("INSERT INTO issue_conclusion_rule_versions VALUES (?,?,?,?,?,?,?)",
                         (issue_id, result["revision"], encoded, result["schema_hash"], reason,
                          result["created_at"], auth.actor_id))
            self.store.fault("conclusion.rule.after_insert")
            self.store.audit(conn, actor=auth.actor_id, action="conclusion.rule.write",
                             object_type="issue", object_id=issue_id,
                             before_revision=expected, after_revision=expected + 1,
                             reason=reason, payload=result)
            self.store.idempotency_record(conn, operation, idempotency_key, payload, result)
            self.store.fault("conclusion.rule.before_commit")
            return result
