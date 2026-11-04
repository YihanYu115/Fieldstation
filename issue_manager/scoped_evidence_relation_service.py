"""Authoritative service for the isolated S2 scoped Evidence relation domain."""
from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from contextlib import nullcontext
from typing import Any

from .context_rule_service import rule_capabilities
from .errors import ConflictError, NotFoundError, ValidationError
from .policy import EVIDENCE_IMPACT_ORDER, EVIDENCE_IMPACT_POLICIES
from .security import AuthContext
from .store import canonical_json, new_id, now

RELATION_TYPES = frozenset({
    "depends_on", "derived_from", "reproduces", "supports", "challenges",
    "amends", "duplicates", "context_for", "refutes",
})
CONTRACT_ID = "scoped-evidence-relation/v1"
MAX_HISTORY = 200
SERVER_MAX_NODES = 1000
SERVER_MAX_RELATIONS = 5000
MAX_SOURCE_RELATIONS = 5000
MAX_SOURCE_PAGE = 8
MAX_SOURCE_BYTES = 16_384


class ScopedEvidenceRelationService:
    def __init__(self, manager: Any):
        self.manager = manager
        self.store = manager.store

    @staticmethod
    def _check_request_key(key: str | None) -> str:
        if not isinstance(key, str) or not key.strip():
            raise ValidationError("Scoped relation writes require an idempotency key")
        return key.strip()

    @staticmethod
    def _binding(evidence: dict[str, Any]) -> tuple[dict[str, Any], str]:
        value = {
            "kind": "evidence_version",
            "evidence_id": evidence["evidence_id"],
            "semantic_revision": evidence.get("semantic_revision"),
            "proof_id": evidence.get("current_proof_id"),
            "manifest_id": evidence.get("current_manifest_id"),
            "content_hash": evidence.get("content_hash"),
            "lifecycle_status": evidence.get("lifecycle_status"),
            "quality_status": evidence.get("quality_status"),
        }
        encoded = canonical_json(value)
        token = "evidence-binding/v1:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        return value, token

    def _evidence(self, conn: sqlite3.Connection, evidence_id: str) -> dict[str, Any]:
        row = conn.execute("SELECT * FROM evidence_refs WHERE evidence_id=?", (evidence_id,)).fetchone()
        if not row:
            raise NotFoundError(f"Evidence not found: {evidence_id}")
        return dict(row)

    def _issue(self, conn: sqlite3.Connection, issue_id: str) -> None:
        if not conn.execute("SELECT 1 FROM issues WHERE issue_id=?", (issue_id,)).fetchone():
            raise NotFoundError(f"Issue not found: {issue_id}")

    def _authorize(self, auth: AuthContext, capability: str) -> None:
        auth.require(capability)

    def binding(self, evidence_id: str, *, auth: AuthContext) -> dict[str, Any]:
        self._authorize(auth, "context.read")
        with self.store.read_transaction() as conn:
            evidence = self._evidence(conn, evidence_id)
            self.manager.evidence.require_read_access(evidence_id, auth)
            value, token = self._binding(evidence)
            return {**value, "token": token}

    def _resolved_impact(self, relation_type: str, impact_policy: str | None) -> str:
        if relation_type not in RELATION_TYPES:
            raise ValidationError(f"Unknown scoped relation type: {relation_type!r}")
        defaults = self.manager.policy.evidence_relation_defaults()
        default = "soft" if relation_type == "refutes" else defaults[relation_type]
        effective = impact_policy or default
        if effective not in EVIDENCE_IMPACT_POLICIES:
            raise ValidationError(f"Unknown impact policy: {effective!r}")
        if EVIDENCE_IMPACT_ORDER[effective] < EVIDENCE_IMPACT_ORDER[default]:
            raise ValidationError("Impact policy cannot be weaker than the project default")
        return effective

    @staticmethod
    def _payload(operation: str, values: dict[str, Any]) -> dict[str, Any]:
        return {"contract_id": CONTRACT_ID, "operation": operation, **values}

    @staticmethod
    def _idempotency_operation(operation: str, auth: AuthContext) -> str:
        return f"scoped_relation.{operation}:{auth.actor_id}:{auth.run_id}"

    def _current(self, conn: sqlite3.Connection, relation_id: str) -> dict[str, Any]:
        row = conn.execute(
            "SELECT v.*,h.current_version_id FROM scoped_evidence_relation_heads h "
            "JOIN scoped_evidence_relation_versions v ON v.relation_id=h.relation_id "
            "AND v.version_id=h.current_version_id WHERE h.relation_id=?", (relation_id,)).fetchone()
        if not row:
            raise NotFoundError(f"Scoped relation not found: {relation_id}")
        return dict(row)

    def _write_version(self, conn: sqlite3.Connection, previous: dict[str, Any] | None, values: dict[str, Any], *, auth: AuthContext, audit_reason: str | None = None) -> dict[str, Any]:
        relation_id = previous["relation_id"] if previous else new_id("scoped_relation")
        revision = int(previous["revision"]) + 1 if previous else 1
        version_id = new_id("scoped_relation_version")
        record = {
            "version_id": version_id, "relation_id": relation_id, "revision": revision,
            "previous_version_id": previous["version_id"] if previous else None,
            "contract_id": CONTRACT_ID, "actor_id": auth.actor_id, "run_id": auth.run_id,
            "created_at": now(), **values,
        }
        conn.execute(
            "INSERT INTO scoped_evidence_relation_versions "
            "(version_id,relation_id,revision,previous_version_id,contract_id,scope_issue_id,"
            "source_evidence_id,target_evidence_id,relation_type,impact_policy,source_binding_json,"
            "target_binding_json,source_binding_token,target_binding_token,active,rationale,actor_id,run_id,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (record["version_id"], record["relation_id"], record["revision"], record["previous_version_id"],
             record["contract_id"], record["scope_issue_id"], record["source_evidence_id"], record["target_evidence_id"],
             record["relation_type"], record["impact_policy"], canonical_json(record["source_binding"]),
             canonical_json(record["target_binding"]), record["source_binding_token"], record["target_binding_token"],
             int(record["active"]), record["rationale"], record["actor_id"], record["run_id"], record["created_at"]),
        )
        self.store.fault("scoped_relation.after_version")
        if previous:
            changed = conn.execute(
                "UPDATE scoped_evidence_relation_heads SET current_version_id=? "
                "WHERE relation_id=? AND current_version_id=?",
                (version_id, relation_id, previous["version_id"]),
            ).rowcount
            if changed != 1:
                raise ConflictError("Scoped relation head changed concurrently")
        else:
            conn.execute("INSERT INTO scoped_evidence_relation_heads VALUES (?,?)", (relation_id, version_id))
        self.store.fault("scoped_relation.after_head")
        self.store.audit(conn, actor=auth.actor_id, action="scoped_relation." + ("create" if previous is None else "revise"),
                         object_type="scoped_evidence_relation", object_id=relation_id,
                         before_revision=previous["revision"] if previous else None, after_revision=revision,
                         reason=record["rationale"] if audit_reason is None else audit_reason,
                         payload=self._public(record))
        return self._public(record)

    @staticmethod
    def _public(row: dict[str, Any]) -> dict[str, Any]:
        result = dict(row)
        result.pop("source_binding", None)
        result.pop("target_binding", None)
        result["source_binding"] = json.loads(row["source_binding_json"]) if "source_binding_json" in row else row.get("source_binding")
        result["target_binding"] = json.loads(row["target_binding_json"]) if "target_binding_json" in row else row.get("target_binding")
        result["active"] = bool(result["active"])
        return result

    def create(self, *, scope_issue_id: str, source_evidence_id: str, target_evidence_id: str,
               relation_type: str, rationale: str, auth: AuthContext,
               expected_source_token: str, expected_target_token: str,
               impact_policy: str | None = None, idempotency_key: str | None = None,
               conn: sqlite3.Connection | None = None) -> dict[str, Any]:
        self._authorize(auth, "evidence.relation.write")
        key = self._check_request_key(idempotency_key)
        if not rationale.strip():
            raise ValidationError("Scoped relation rationale must be non-empty")
        effective = self._resolved_impact(relation_type, impact_policy)
        payload = self._payload("create", {"scope_issue_id": scope_issue_id, "source_evidence_id": source_evidence_id,
            "target_evidence_id": target_evidence_id, "relation_type": relation_type, "impact_policy": effective,
            "rationale": rationale, "expected_source_token": expected_source_token, "expected_target_token": expected_target_token})
        transaction = self.store.transaction() if conn is None else nullcontext(conn)
        with transaction as conn:
            self._issue(conn, scope_issue_id)
            source, target = self._evidence(conn, source_evidence_id), self._evidence(conn, target_evidence_id)
            self.manager.evidence.require_read_access(source_evidence_id, auth)
            self.manager.evidence.require_read_access(target_evidence_id, auth)
            operation = self._idempotency_operation("create", auth)
            replay = self.store.idempotency_lookup(operation, key, payload)
            if replay is not None:
                return replay
            source_binding, source_token = self._binding(source)
            target_binding, target_token = self._binding(target)
            if source_token != expected_source_token or target_token != expected_target_token:
                raise ConflictError("Evidence binding token is stale")
            result = self._write_version(conn, None, {"scope_issue_id": scope_issue_id, "source_evidence_id": source_evidence_id,
                "target_evidence_id": target_evidence_id, "relation_type": relation_type, "impact_policy": effective,
                "source_binding": source_binding, "target_binding": target_binding,
                "source_binding_token": source_token, "target_binding_token": target_token,
                "active": True, "rationale": rationale}, auth=auth)
            result["unchanged"] = False
            result["binding_current"] = True
            self.store.fault("scoped_relation.before_receipt")
            self.store.idempotency_record(conn, operation, key, payload, result)
            self.store.fault("scoped_relation.after_receipt_before_commit")
            return result

    def show(self, relation_id: str, *, auth: AuthContext) -> dict[str, Any]:
        self._authorize(auth, "context.read")
        with self.store.read_transaction() as conn:
            row = self._current(conn, relation_id)
            self.manager.evidence.require_read_access(row["source_evidence_id"], auth)
            self.manager.evidence.require_read_access(row["target_evidence_id"], auth)
            source = self._evidence(conn, row["source_evidence_id"])
            target = self._evidence(conn, row["target_evidence_id"])
            _, st = self._binding(source)
            _, tt = self._binding(target)
            result = self._public(row)
            result["binding_current"] = st == row["source_binding_token"] and tt == row["target_binding_token"]
            return result

    @staticmethod
    def _source_cursor(snapshot: str, offset: int) -> str:
        raw = canonical_json({"snapshot": snapshot, "offset": offset}).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    @staticmethod
    def _decode_source_cursor(cursor: str) -> tuple[str, int]:
        try:
            padded = cursor + "=" * (-len(cursor) % 4)
            value = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValidationError("Relation cursor is invalid") from exc
        if (not isinstance(value, dict) or set(value) != {"snapshot", "offset"}
                or not isinstance(value["snapshot"], str) or len(value["snapshot"]) != 64
                or isinstance(value["offset"], bool) or not isinstance(value["offset"], int)
                or value["offset"] < 0):
            raise ValidationError("Relation cursor is invalid")
        return value["snapshot"], value["offset"]

    def from_source(self, *, scope_issue_id: str, source_evidence_id: str, auth: AuthContext,
                    limit: int = MAX_SOURCE_PAGE, max_bytes: int = MAX_SOURCE_BYTES,
                    cursor: str | None = None, expected_snapshot: str | None = None,
                    relation_id: str | None = None) -> dict[str, Any]:
        """Read current relation heads for one source in one Issue, with a stable snapshot cursor."""
        self._authorize(auth, "context.read")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_SOURCE_PAGE:
            raise ValidationError(f"limit must be between 1 and {MAX_SOURCE_PAGE}")
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 256 <= max_bytes <= MAX_SOURCE_BYTES:
            raise ValidationError(f"max_bytes must be between 256 and {MAX_SOURCE_BYTES}")
        if not isinstance(scope_issue_id, str) or not scope_issue_id.strip():
            raise ValidationError("scope_issue_id is required")
        if not isinstance(source_evidence_id, str) or not source_evidence_id.strip():
            raise ValidationError("source_evidence_id is required")
        cursor_snapshot = None
        offset = 0
        if cursor is not None:
            if not isinstance(cursor, str) or not cursor:
                raise ValidationError("cursor must be a non-empty string")
            cursor_snapshot, offset = self._decode_source_cursor(cursor)
        if expected_snapshot is not None and (not isinstance(expected_snapshot, str)
                                               or len(expected_snapshot) != 64):
            raise ValidationError("expected_snapshot must be a SHA-256 token")

        with self.store.read_transaction() as conn:
            self._issue(conn, scope_issue_id)
            source = self._evidence(conn, source_evidence_id)
            self.manager.evidence.require_read_access(source_evidence_id, auth)
            source_binding, source_token = self._binding(source)
            raw_rows = conn.execute(
                "SELECT v.*,h.current_version_id FROM scoped_evidence_relation_heads h "
                "JOIN scoped_evidence_relation_versions v ON v.relation_id=h.relation_id "
                "AND v.version_id=h.current_version_id "
                "WHERE v.scope_issue_id=? AND v.source_evidence_id=? ORDER BY v.relation_id LIMIT ?",
                (scope_issue_id, source_evidence_id, MAX_SOURCE_RELATIONS + 1),
            ).fetchall()
            if len(raw_rows) > MAX_SOURCE_RELATIONS:
                raise ValidationError("Source relation set exceeds the bounded scan limit")
            records: list[dict[str, Any]] = []
            snapshot_rows: list[dict[str, Any]] = []
            for raw in raw_rows:
                row = dict(raw)
                # Fail closed for the whole page: an inaccessible endpoint must not leak
                # relation identity or metadata through a partially visible collection.
                self.manager.evidence.require_read_access(row["target_evidence_id"], auth)
                target = self._evidence(conn, row["target_evidence_id"])
                target_binding, target_token = self._binding(target)
                binding_current = (source_token == row["source_binding_token"]
                                   and target_token == row["target_binding_token"])
                public = self._public(row)
                public.update({"current_version_id": row["current_version_id"],
                               "binding_current": binding_current,
                               "source_binding": source_binding,
                               "target_binding": target_binding})
                records.append(public)
                snapshot_rows.append({"relation_id": row["relation_id"],
                                      "current_version_id": row["current_version_id"],
                                      "revision": row["revision"],
                                      "source_binding_token": source_token,
                                      "target_binding_token": target_token})
            snapshot_token = hashlib.sha256(canonical_json({
                "scope_issue_id": scope_issue_id, "source_evidence_id": source_evidence_id,
                "source_binding_token": source_token, "relations": snapshot_rows,
            }).encode("utf-8")).hexdigest()
            if ((cursor_snapshot is not None and cursor_snapshot != snapshot_token)
                    or (expected_snapshot is not None and expected_snapshot != snapshot_token)):
                raise ConflictError("Relation collection or endpoint binding changed; reread from the first page")
            if offset > len(records):
                raise ValidationError("Relation cursor is outside the current collection")
            if relation_id is not None:
                page_items = [item for item in records if item["relation_id"] == relation_id]
                if not page_items:
                    raise NotFoundError("Relation was not found for this source and scope")
                page_items = page_items[:1]
            else:
                page_items = records[offset:offset + limit]
            next_offset = offset + len(page_items)
            base: dict[str, Any] = {"scope_issue_id": scope_issue_id, "source_evidence_id": source_evidence_id,
                    "snapshot": {"token": snapshot_token, "relation_count": len(records),
                                 "source_binding_token": source_token,
                                 "source_binding": source_binding},
                    "items": [], "next_cursor": None, "complete": False,
                    "oversized_relation_ids": []}
            kept: list[dict[str, Any]] = []
            oversized: list[str] = []
            for item in page_items:
                candidate = kept + [item]
                probe = {**base, "items": candidate, "oversized_relation_ids": oversized}
                if len(canonical_json(probe).encode("utf-8")) <= max_bytes:
                    kept.append(item)
                    continue
                if not kept:
                    oversized.append(item["relation_id"])
                    next_offset = offset + 1
                else:
                    next_offset = offset + len(kept)
                break
            has_more = relation_id is None and next_offset < len(records)
            next_cursor = self._source_cursor(snapshot_token, next_offset) if has_more else None
            result = {**base, "items": kept, "oversized_relation_ids": oversized,
                      "next_cursor": next_cursor,
                      "complete": not has_more and not oversized,
                      "page_complete": not oversized}
            if len(canonical_json(result).encode("utf-8")) > max_bytes:
                raise ValidationError("Relation page metadata exceeds max_bytes")
            return result

    def history(self, relation_id: str, *, auth: AuthContext, limit: int = 50, cursor: int | None = None) -> dict[str, Any]:
        self._authorize(auth, "context.read")
        if not 1 <= limit <= MAX_HISTORY:
            raise ValidationError(f"History limit must be between 1 and {MAX_HISTORY}")
        with self.store.read_transaction() as conn:
            current = self._current(conn, relation_id)
            self.manager.evidence.require_read_access(current["source_evidence_id"], auth)
            self.manager.evidence.require_read_access(current["target_evidence_id"], auth)
            params: list[Any] = [relation_id]
            clause = ""
            if cursor is not None:
                if cursor < 1:
                    raise ValidationError("History cursor must be positive")
                clause = " AND revision < ?"
                params.append(cursor)
            params.append(limit + 1)
            rows = conn.execute("SELECT * FROM scoped_evidence_relation_versions WHERE relation_id=?" + clause + " ORDER BY revision DESC LIMIT ?", params).fetchall()
            values = [self._public(dict(row)) for row in rows[:limit]]
            return {"relation_id": relation_id, "items": values, "next_cursor": rows[limit - 1]["revision"] if len(rows) > limit else None}

    def _transition(self, relation_id: str, *, target_active: bool, expected_version_id: str,
                    reason: str, auth: AuthContext, idempotency_key: str | None, operation: str) -> dict[str, Any]:
        self._authorize(auth, "evidence.relation.write")
        key = self._check_request_key(idempotency_key)
        payload = self._payload(operation, {"relation_id": relation_id, "expected_version_id": expected_version_id, "reason": reason})
        with self.store.transaction() as conn:
            previous = self._current(conn, relation_id)
            self.manager.evidence.require_read_access(previous["source_evidence_id"], auth)
            self.manager.evidence.require_read_access(previous["target_evidence_id"], auth)
            operation_key = self._idempotency_operation(operation, auth)
            replay = self.store.idempotency_lookup(operation_key, key, payload)
            if replay is not None:
                return replay
            if previous["version_id"] != expected_version_id:
                raise ConflictError("Scoped relation head is stale")
            if bool(previous["active"]) == target_active:
                result = {**self._public(previous), "unchanged": True, "binding_current": self._binding_current(conn, previous)}
            else:
                result = self._write_version(conn, previous, {k: previous[k] for k in (
                    "scope_issue_id", "source_evidence_id", "target_evidence_id", "relation_type", "impact_policy",
                    "source_binding_token", "target_binding_token") } | {"source_binding": json.loads(previous["source_binding_json"]), "target_binding": json.loads(previous["target_binding_json"]), "active": target_active, "rationale": previous["rationale"]}, auth=auth, audit_reason=reason)
                result["unchanged"] = False
                result["binding_current"] = self._binding_current(conn, result)
            self.store.fault("scoped_relation.before_receipt")
            self.store.idempotency_record(conn, operation_key, key, payload, result)
            self.store.fault("scoped_relation.after_receipt_before_commit")
            return result

    def _binding_current(self, conn: sqlite3.Connection, row: dict[str, Any]) -> bool:
        source, target = self._evidence(conn, row["source_evidence_id"]), self._evidence(conn, row["target_evidence_id"])
        return self._binding(source)[1] == row["source_binding_token"] and self._binding(target)[1] == row["target_binding_token"]

    def deactivate(self, relation_id: str, *, expected_version_id: str, reason: str, auth: AuthContext, idempotency_key: str | None) -> dict[str, Any]:
        return self._transition(relation_id, target_active=False, expected_version_id=expected_version_id, reason=reason, auth=auth, idempotency_key=idempotency_key, operation="deactivate")

    def reactivate(self, relation_id: str, *, expected_version_id: str, reason: str, auth: AuthContext, idempotency_key: str | None) -> dict[str, Any]:
        return self._transition(relation_id, target_active=True, expected_version_id=expected_version_id, reason=reason, auth=auth, idempotency_key=idempotency_key, operation="reactivate")

    def revise(self, relation_id: str, *, expected_version_id: str, rationale: str | None = None,
               impact_policy: str | None = None, expected_source_token: str | None = None,
               expected_target_token: str | None = None, rebind: bool = False,
               auth: AuthContext, idempotency_key: str | None) -> dict[str, Any]:
        self._authorize(auth, "evidence.relation.write")
        key = self._check_request_key(idempotency_key)
        payload = self._payload("revise", {"relation_id": relation_id, "expected_version_id": expected_version_id,
            "rationale": rationale, "impact_policy": impact_policy, "expected_source_token": expected_source_token,
            "expected_target_token": expected_target_token, "rebind": rebind})
        with self.store.transaction() as conn:
            previous = self._current(conn, relation_id)
            self.manager.evidence.require_read_access(previous["source_evidence_id"], auth)
            self.manager.evidence.require_read_access(previous["target_evidence_id"], auth)
            operation_key = self._idempotency_operation("revise", auth)
            replay = self.store.idempotency_lookup(operation_key, key, payload)
            if replay is not None:
                return replay
            if previous["version_id"] != expected_version_id:
                raise ConflictError("Scoped relation head is stale")
            new_impact = self._resolved_impact(previous["relation_type"], impact_policy or previous["impact_policy"])
            source, target = self._evidence(conn, previous["source_evidence_id"]), self._evidence(conn, previous["target_evidence_id"])
            source_binding, source_token = self._binding(source)
            target_binding, target_token = self._binding(target)
            if rebind:
                if expected_source_token != source_token or expected_target_token != target_token:
                    raise ConflictError("Evidence binding token is stale")
            else:
                source_binding, source_token = json.loads(previous["source_binding_json"]), previous["source_binding_token"]
                target_binding, target_token = json.loads(previous["target_binding_json"]), previous["target_binding_token"]
            binding_changed = source_token != previous["source_binding_token"] or target_token != previous["target_binding_token"]
            changed = new_impact != previous["impact_policy"] or (rationale is not None and rationale != previous["rationale"]) or binding_changed
            if not changed:
                result = {**self._public(previous), "unchanged": True, "binding_current": self._binding_current(conn, previous)}
            else:
                result = self._write_version(conn, previous, {"scope_issue_id": previous["scope_issue_id"], "source_evidence_id": previous["source_evidence_id"], "target_evidence_id": previous["target_evidence_id"], "relation_type": previous["relation_type"], "impact_policy": new_impact, "source_binding": source_binding, "target_binding": target_binding, "source_binding_token": source_token, "target_binding_token": target_token, "active": bool(previous["active"]), "rationale": rationale if rationale is not None else previous["rationale"]}, auth=auth)
                result["unchanged"] = False
                result["binding_current"] = self._binding_current(conn, result)
            self.store.fault("scoped_relation.before_receipt")
            self.store.idempotency_record(conn, operation_key, key, payload, result)
            self.store.fault("scoped_relation.after_receipt_before_commit")
            return result

    def preview_selection(self, *, scope_issue_id: str, seed_evidence_ids: list[str],
                          maximum_nodes: int, maximum_relations: int,
                          auth: AuthContext) -> dict[str, Any]:
        self._authorize(auth, "context.read")
        if not isinstance(seed_evidence_ids, list) or not seed_evidence_ids:
            raise ValidationError("seed_evidence_ids must be a non-empty array")
        if any(not isinstance(item, str) or not item for item in seed_evidence_ids):
            raise ValidationError("seed_evidence_ids must be an array of non-empty strings")
        if not isinstance(maximum_nodes, int) or isinstance(maximum_nodes, bool) or maximum_nodes <= 0:
            raise ValidationError("maximum_nodes must be a positive integer")
        if not isinstance(maximum_relations, int) or isinstance(maximum_relations, bool) or maximum_relations <= 0:
            raise ValidationError("maximum_relations must be a positive integer")
        if maximum_nodes > SERVER_MAX_NODES:
            raise ValidationError(f"maximum_nodes exceeds server limit {SERVER_MAX_NODES}")
        if maximum_relations > SERVER_MAX_RELATIONS:
            raise ValidationError(f"maximum_relations exceeds server limit {SERVER_MAX_RELATIONS}")
        active_rule = self.manager.context_rules.active()["rule_id"]
        rule_capabilities(active_rule)
        return self._preview_scoped_v2(scope_issue_id, seed_evidence_ids,
                                       maximum_nodes, maximum_relations, auth, active_rule)

    def _preview_scoped_v2(self, scope_issue_id, seed_evidence_ids, maximum_nodes,
                           maximum_relations, auth, rule_id):
        """Preview the same v2 solver used by package preparation.

        The read-only preview and frozen packages use the same solver.
        """
        from .context_scoped_rule import SCOPED_V2_RULE_ID

        with self.store.read_transaction():
            resolved = self.manager.context_maintenance.scoped_v2_resolver.resolve(
                {
                    "version": SCOPED_V2_RULE_ID,
                    "rule_version_id": rule_id,
                    "issue_id": scope_issue_id,
                    "seed_evidence_ids": list(seed_evidence_ids),
                },
                maximum_nodes=maximum_nodes,
                maximum_relations=maximum_relations,
            )
        if resolved.errors or not resolved.complete:
            raise ValidationError("Scoped-v2 preview could not produce a complete snapshot")
        candidate_states = resolved.model_materials.get("candidate_states", [])
        if len(candidate_states) > maximum_nodes:
            raise ValidationError("Scoped-v2 preview exceeds maximum_nodes")
        if len(resolved.comparison_context.get("relations", [])) > maximum_relations:
            raise ValidationError("Scoped-v2 preview exceeds maximum_relations")
        for item in candidate_states:
            self.manager.evidence.require_read_access(item["candidate_id"], auth)
        projection = resolved.selection_trace.get("projection", {})
        snapshot_payload = {
            "scope_issue_id": scope_issue_id,
            "seeds": sorted(seed_evidence_ids),
            "comparison": resolved.comparison_context,
            "rule_id": rule_id,
        }
        snapshot_token = "scoped-selection-snapshot/v2:" + hashlib.sha256(
            canonical_json(snapshot_payload).encode("utf-8")
        ).hexdigest()
        candidates = []
        for item in candidate_states:
            status = {"T": "included", "F": "excluded", "?": "unresolved"}[item["status"]]
            candidates.append({"candidate_id": item["candidate_id"], "status": status,
                               "reasons": item.get("reasons", [])})
        return {
            "contract_id": "scoped-selection-preview/v2",
            "scope_issue_id": scope_issue_id,
            "snapshot_token": snapshot_token,
            "discovery": {
                "rule_id": SCOPED_V2_RULE_ID,
                "candidates": candidate_states,
                "boundary_refs": [],
                "diagnostics": resolved.selection_trace.get("diagnostics", []),
            },
            "selection": {
                "rule_id": SCOPED_V2_RULE_ID,
                "candidates": candidates,
                "diagnostics": resolved.selection_trace.get("diagnostics", []),
            },
            "projection": projection,
        }
