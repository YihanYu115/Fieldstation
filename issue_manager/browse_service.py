"""Bounded, read-only project browsing; never creates packages or domain state."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, cast

from .errors import ConflictError, NotFoundError, PermissionError, ValidationError
from .original_access_binding import project_root
from .security import AuthContext
from .store import canonical_json

MAX_COLLECTION = 10000
MAX_BYTES = 1024 * 1024


class BrowseService:
    def __init__(self, manager: Any):
        self.manager = manager
        self.store = manager.store

    def _issue(self, issue: str) -> dict[str, Any]:
        row = self.store.row("SELECT * FROM issues WHERE issue_id=?", (issue,))
        if row is None:
            raise NotFoundError(f"Issue not found: {issue}")
        return row

    def _memberships(self, evidence: str) -> list[str]:
        rows = self.store.rows("SELECT issue_id FROM issue_evidence WHERE evidence_id=? "
                               "ORDER BY issue_id LIMIT ?", (evidence, MAX_COLLECTION + 1))
        self._budget(rows)
        return [row["issue_id"] for row in rows]

    def _evidence(self, evidence: str, auth: AuthContext) -> dict[str, Any]:
        row = self.store.row("SELECT * FROM evidence_refs WHERE evidence_id=?", (evidence,))
        if row is None:
            raise NotFoundError(f"Evidence not found: {evidence}")
        self.manager.evidence.require_read_access(evidence, auth)
        memberships = self._memberships(evidence)
        row["issue_ids"] = memberships
        row["source_locator"] = row.get("declared_source_locator") or row["locator"]
        row["locator_role"] = "internal_identity" if row.get("declared_source_locator") else "source"
        return row

    @staticmethod
    def _budget(rows: list) -> None:
        if len(rows) > MAX_COLLECTION:
            raise ConflictError("Browse collection exceeds 10000 items; choose a smaller scope",
                                details={"code": "browse_too_large"})

    @staticmethod
    def _bounded(payload: dict) -> dict:
        if len(canonical_json(payload).encode("utf-8")) > MAX_BYTES:
            raise ConflictError("Browse response exceeds 1 MiB; reduce page size",
                                details={"code": "browse_too_large"})
        return payload

    def _page(self, rows: list[dict], *, query: list, auth: AuthContext,
              limit: int, cursor: str | None, expected_snapshot: str | None) -> dict:
        self._budget(rows)
        # Actual collection content includes memberships/bindings, not only a context clock.
        snapshot = hashlib.sha256(canonical_json([query, auth.actor_id, auth.run_id,
                                                  auth.platform_id, rows]).encode("utf-8")).hexdigest()
        offset = 0
        if cursor is not None:
            try:
                decoded = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")))
                if (not isinstance(decoded, list) or len(decoded) != 2
                        or type(decoded[1]) is not int or decoded[1] < 0):
                    raise ValueError
                previous, offset = decoded
            except (ValueError, UnicodeError, TypeError) as exc:
                raise ValidationError("Invalid browse cursor") from exc
            if previous != snapshot:
                raise ConflictError("Browse collection changed; restart from the first page",
                                    details={"code": "browse_snapshot_changed"})
        if expected_snapshot is not None and expected_snapshot != snapshot:
            raise ConflictError("Browse collection changed; restart from the first page",
                                details={"code": "browse_snapshot_changed"})
        items = rows[offset:offset + limit]
        more = offset + limit < len(rows)
        next_cursor = base64.urlsafe_b64encode(canonical_json([snapshot, offset + limit])
                                             .encode("utf-8")).decode("ascii") if more else None
        return self._bounded({"items": items, "snapshot": snapshot, "has_more": more,
                              "next_cursor": next_cursor, "complete": not more,
                              "total": len(rows), "max_bytes": MAX_BYTES})

    def read(self, kind: str, object_id: str, *, auth: AuthContext,
             limit: int = 20, cursor: str | None = None,
             expected_snapshot: str | None = None) -> dict:
        auth.require("context.read")
        if not object_id or type(limit) is not int or not 1 <= limit <= 50:
            raise ValidationError("id required; limit must be 1..50")
        with self.store.read_transaction():
            if kind in {"issue", "children", "evidence", "conclusions"}:
                issue = self._issue(object_id)
            if kind == "issue":
                projection = self.manager.inspect_issue(object_id, auth=auth)
                return self._bounded(projection)
            if kind == "conclusions":
                if auth.platform_id is not None:
                    raise PermissionError("Platform-scoped principals cannot browse conclusion history")
                values = self.store.rows("SELECT * FROM conclusion_revisions WHERE issue_id=? "
                                         "ORDER BY revision_number LIMIT ?", (object_id, MAX_COLLECTION + 1))
                self._budget(values)
                from .service import _clean_row
                rows = []
                for value in values:
                    item = cast(dict[str, Any], _clean_row(value))
                    try:
                        for evidence_id in item["evidence_refs"]:
                            self.manager.evidence.require_read_access(evidence_id, auth)
                    except PermissionError:
                        rows.append({"conclusion_id": item["conclusion_id"], "restricted": True,
                                     "diagnostic": "read_forbidden"})
                        continue
                    binding = self.store.row("SELECT revision,schema_hash FROM conclusion_rule_bindings WHERE conclusion_id=?",
                                             (item["conclusion_id"],))
                    item["applied_rule"] = binding
                    item["currentness"] = self.manager.context_maintenance.show(item["conclusion_id"])
                    rows.append(item)
            elif kind == "children":
                rows = self.store.rows("SELECT issue_id,parent_issue_id,title,issue_type,work_status,"
                                       "freshness,current_conclusion_id,conclusion_revision FROM issues "
                                       "WHERE parent_issue_id=? ORDER BY issue_id LIMIT ?",
                                       (issue["issue_id"], MAX_COLLECTION + 1))
            elif kind == "evidence":
                refs = self.store.rows("SELECT evidence_id FROM issue_evidence WHERE issue_id=? "
                                       "ORDER BY evidence_id LIMIT ?", (object_id, MAX_COLLECTION + 1))
                self._budget(refs)
                rows = []
                for ref in refs:
                    try:
                        item = self._evidence(ref["evidence_id"], auth)
                        rows.append({key: item[key] for key in (
                            "evidence_id", "kind", "short_description", "quality_status",
                            "lifecycle_status", "semantic_revision", "issue_ids")})
                    except PermissionError:
                        rows.append({"evidence_id": ref["evidence_id"], "restricted": True,
                                     "diagnostic": "read_forbidden"})
            elif kind == "detail":
                item = self._evidence(object_id, auth)
                roots: dict[str, str] = {}
                for issue_id in item["issue_ids"]:
                    roots.setdefault(project_root(self.store, issue_id), issue_id)
                bindings = []
                for project, issue_id in sorted(roots.items()):
                    for binding in self.manager.original_access_bindings.evidence(issue_id, object_id):
                        bindings.append({**binding, "root_issue_id": project, "issue_id": issue_id})
                        self._budget(bindings)
                item["original_access"] = bindings
                # Current authoritative body only; unbounded history stays on separate surfaces.
                return self._bounded({"evidence": item})
            elif kind == "neighbors":
                self._evidence(object_id, auth)
                scoped = self.store.rows(
                    "SELECT v.* FROM scoped_evidence_relation_heads h JOIN "
                    "scoped_evidence_relation_versions v ON v.version_id=h.current_version_id "
                    "WHERE v.source_evidence_id=? OR v.target_evidence_id=? ORDER BY v.relation_id LIMIT ?",
                    (object_id, object_id, MAX_COLLECTION + 1))
                ordinary = self.store.rows(
                    "SELECT *,consumer_evidence_id AS source_evidence_id,provider_evidence_id "
                    "AS target_evidence_id FROM evidence_relations WHERE consumer_evidence_id=? "
                    "OR provider_evidence_id=? ORDER BY relation_id LIMIT ?",
                    (object_id, object_id, MAX_COLLECTION + 1))
                self._budget(scoped + ordinary)
                rows = []
                for layer, values in (("scoped-v2", scoped), ("ordinary", ordinary)):
                    for relation in values:
                        try:
                            source = self._evidence(relation["source_evidence_id"], auth)
                            target = self._evidence(relation["target_evidence_id"], auth)
                            if layer == "scoped-v2":
                                relation = self.manager.scoped_evidence_relations.show(
                                    relation["relation_id"], auth=auth)
                            relation = dict(relation, layer=layer,
                                            source_issue_ids=source["issue_ids"],
                                            target_issue_ids=target["issue_ids"])
                        except PermissionError:
                            relation = {"layer": layer, "restricted": True, "diagnostic": "read_forbidden"}
                        rows.append(relation)
                rows.sort(key=lambda row: (row["layer"], row.get("relation_id", "")))
            else:
                raise ValidationError("Unknown browse kind")
            return self._page(rows, query=[kind, object_id], auth=auth, limit=limit,
                              cursor=cursor, expected_snapshot=expected_snapshot)
