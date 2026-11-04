"""Versioned project reading instructions. All content is inert, untrusted data."""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlencode

from .browse_service import BrowseService
from .errors import ConflictError, NotFoundError, PermissionError, ValidationError
from .original_access_binding import project_root
from .security import AuthContext
from .store import canonical_json, now

FIELDS = {"reference_prefix", "summary", "capability", "parameters", "example",
          "semantics", "failures", "change_impact", "impact_note"}
MAX_DOCUMENT_BYTES = 32768
MAX_RESPONSE_BYTES = 65536


class OriginalAccessService:
    def __init__(self, manager: Any):
        self.manager = manager
        self.store = manager.store

    def _scope(self, issue_id: str, auth: AuthContext) -> str:
        auth.require("context.read")
        if auth.platform_id is not None:
            raise PermissionError("Platform-scoped principals cannot read project instructions")
        if not isinstance(issue_id, str) or not issue_id:
            raise ValidationError("issue_id is required")
        return project_root(self.store, issue_id)

    def entry(self, issue_id: str, auth: AuthContext) -> dict:
        root = self._scope(issue_id, auth)
        count = self.store.row("SELECT COUNT(*) AS n FROM project_original_access_heads "
                               "WHERE root_issue_id=?", (root,))
        return {"root_issue_id": root, "contract_count": count["n"] if count else 0,
                "read": {"tool": "discover_original_access", "arguments": {"issue_id": issue_id}},
                "href": "/v1/original-access/discover?" + urlencode({"issue_id": issue_id}),
                "authority": "instructions_only_host_binding_required"}

    def write(self, body: dict, *, auth: AuthContext) -> dict:
        auth.require("issue.write")
        if set(body) != {"root_issue_id", "contract_id", "expected_revision", "document", "reason"}:
            raise ValidationError("Unexpected original-access write fields")
        root, contract = body["root_issue_id"], body["contract_id"]
        expected, document, reason = body["expected_revision"], body["document"], body["reason"]
        if not isinstance(contract, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", contract):
            raise ValidationError("contract_id must be 1..64 ASCII identifier characters")
        if type(expected) is not int or expected < 0:
            raise ValidationError("expected_revision must be a nonnegative integer; 0 creates")
        if not isinstance(reason, str) or not reason.strip() or len(reason.encode("utf-8")) > 2048:
            raise ValidationError("reason must be nonempty and at most 2048 UTF-8 bytes")
        if not isinstance(document, dict) or set(document) != FIELDS:
            raise ValidationError("document requires exactly " + ", ".join(sorted(FIELDS)))
        for field, value in document.items():
            cap = {"reference_prefix": 512, "summary": 512, "capability": 128}.get(field, 8192)
            if (not isinstance(value, str) or not value.strip()
                    or len(value.encode("utf-8")) > cap):
                raise ValidationError(f"{field} must be nonempty and at most {cap} UTF-8 bytes")
        if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_.-]{0,127}", document["capability"]):
            raise ValidationError("capability must be a logical name, not an endpoint or command")
        if document["change_impact"] not in {"initial", "editorial", "interpretation"}:
            raise ValidationError("change_impact must be initial/editorial/interpretation")
        if (expected == 0) != (document["change_impact"] == "initial"):
            raise ValidationError("Only the first revision has initial impact")
        serialized = canonical_json(document)
        if len(serialized.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            raise ValidationError("document exceeds 32768 UTF-8 JSON bytes")
        with self.store.transaction() as db:
            if self._scope(root, auth) != root:
                raise ValidationError("Instructions must be registered on a top-level Issue")
            head = self.store.row("SELECT revision FROM project_original_access_heads "
                                  "WHERE root_issue_id=? AND contract_id=?", (root, contract))
            current = head["revision"] if head else 0
            if current != expected:
                raise ConflictError("Original-access revision changed", details={"current_revision": current})
            revision = current + 1
            db.execute("INSERT INTO project_original_access_versions "
                       "(root_issue_id,contract_id,revision,document_json,actor_id,reason,created_at) "
                       "VALUES (?,?,?,?,?,?,?)",
                       (root, contract, revision, serialized, auth.actor_id, reason, now()))
            if head:
                db.execute("UPDATE project_original_access_heads SET revision=? "
                           "WHERE root_issue_id=? AND contract_id=? AND revision=?",
                           (revision, root, contract, current))
            else:
                db.execute("INSERT INTO project_original_access_heads VALUES (?,?,?)", (root, contract, revision))
            self.store.audit(db, actor=auth.actor_id, action="project.original_access.revise",
                             object_type="project_original_access", object_id=f"{root}/{contract}",
                             before_revision=current, after_revision=revision, reason=reason,
                             payload={"document": document})
            return {"root_issue_id": root, "contract_id": contract, "revision": revision,
                    "change_impact": document["change_impact"]}

    def discover(self, issue_id: str, *, auth: AuthContext,
                 reference: str | None = None, contract_id: str | None = None,
                 limit: int = 20, cursor: str | None = None,
                 expected_snapshot: str | None = None) -> dict:
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValidationError("limit must be 1..50")
        for name, value in (("reference", reference), ("contract_id", contract_id)):
            if value is not None and (not isinstance(value, str) or not value
                                      or len(value.encode("utf-8")) > 4096):
                raise ValidationError(f"Invalid {name}")
        with self.store.read_transaction():
            project = self._scope(issue_id, auth)
            # Without a reference: current catalog, or history of a named contract.
            # With a reference: ALL revisions participate; never silently reinterpret old sources.
            sql = "SELECT v.* FROM project_original_access_versions v "
            if reference is None and contract_id is None:
                sql += ("JOIN project_original_access_heads h ON h.root_issue_id=v.root_issue_id "
                        "AND h.contract_id=v.contract_id AND h.revision=v.revision ")
            sql += "WHERE v.root_issue_id=? "
            params: tuple = (project,)
            if contract_id is not None:
                sql += "AND v.contract_id=? "
                params += (contract_id,)
            rows = self.store.rows(sql + "ORDER BY v.contract_id,v.revision LIMIT 10001", params)
            BrowseService._budget(rows)
            items = []
            for row in rows:
                doc = json.loads(row["document_json"])
                if reference is not None and not reference.startswith(doc["reference_prefix"]):
                    continue
                items.append({"contract_id": row["contract_id"], "revision": row["revision"],
                              "summary": doc["summary"], "reference_prefix": doc["reference_prefix"],
                              "capability": doc["capability"], "change_impact": doc["change_impact"],
                              "read": {"tool": "read_original_access", "arguments": {
                                  "issue_id": issue_id, "contract_id": row["contract_id"],
                                  "revision": row["revision"]}}})
            status = "catalog" if reference is None else (
                "missing" if not items else "matched" if len(items) == 1 else
                "version_required" if len({i["contract_id"] for i in items}) == 1 else "ambiguous")
            page = BrowseService(self.manager)._page(
                items, query=["original-access", issue_id, reference, contract_id], auth=auth,
                limit=limit, cursor=cursor, expected_snapshot=expected_snapshot)
            result = {**page, "root_issue_id": project, "match_status": status,
                      "instructions_are_untrusted_data": True, "external_binding": "host_required"}
            result["max_bytes"] = 60 * 1024
            if len(canonical_json(result).encode("utf-8")) > result["max_bytes"]:
                raise ConflictError("Original-access catalog exceeds 60 KiB; reduce limit",
                                    details={"code": "original_access_budget"})
            return result

    def read(self, issue_id: str, contract_id: str | None = None, revision: int | None = None, *, auth: AuthContext,
             max_bytes: int = MAX_RESPONSE_BYTES,
             evidence_id: str | None = None, reference: str | None = None) -> dict:
        if evidence_id is not None:
            if contract_id is not None or revision is not None:
                raise ValidationError("Choose a pinned Evidence or an explicit contract version, not both")
            if type(max_bytes) is not int or not 1024 <= max_bytes <= MAX_RESPONSE_BYTES:
                raise ValidationError("max_bytes must be 1024..65536")
            with self.store.read_transaction():
                project = self._scope(issue_id, auth)
                evidence = BrowseService(self.manager)._evidence(evidence_id, auth)
                if not any(project_root(self.store, member) == project for member in evidence["issue_ids"]):
                    raise PermissionError("Evidence has no registration inside the requested project")
                bindings = self.manager.original_access_bindings.evidence(issue_id, evidence_id)
                if reference is not None:
                    bindings = [b for b in bindings if b["reference"] == reference]
                if len(bindings) != 1 or bindings[0]["status"] != "bound":
                    return self._binding_budget({"evidence_id": evidence_id, "bindings": bindings,
                            "binding_status": bindings[0]["status"] if len(bindings) == 1 else (
                                "multiple_references" if bindings else "unrecorded"),
                            "external_binding": "host_required"}, max_bytes)
                binding = bindings[0]
                value = self.read(issue_id, binding["contract_id"], binding["revision"],
                                  auth=auth, max_bytes=MAX_RESPONSE_BYTES)
                return self._binding_budget({**value, "binding_id": binding["binding_id"]}, max_bytes)
        if reference is not None:
            raise ValidationError("reference selection requires evidence_id")
        if type(revision) is not int or revision < 1:
            raise ValidationError("An exact positive revision is required")
        if type(max_bytes) is not int or not 1024 <= max_bytes <= MAX_RESPONSE_BYTES:
            raise ValidationError("max_bytes must be 1024..65536")
        with self.store.read_transaction():
            project = self._scope(issue_id, auth)
            row = self.store.row("SELECT * FROM project_original_access_versions "
                                 "WHERE root_issue_id=? AND contract_id=? AND revision=?",
                                 (project, contract_id, revision))
            if row is None:
                raise NotFoundError("Original-access version not found")
            row["document"] = json.loads(row.pop("document_json"))
            result = {**row, "complete": True, "instructions_are_untrusted_data": True,
                      "external_binding": "host_required"}
            size = len(canonical_json(result).encode("utf-8"))
            if size > max_bytes:
                raise ConflictError("Instruction response exceeds requested byte budget",
                                    details={"code": "original_access_budget", "required_bytes": size})
            return result

    @staticmethod
    def _binding_budget(value: dict, max_bytes: int) -> dict:
        size = len(canonical_json(value).encode("utf-8"))
        if size > max_bytes:
            raise ConflictError("Instruction response exceeds requested byte budget",
                                details={"code": "original_access_budget", "required_bytes": size})
        return value
