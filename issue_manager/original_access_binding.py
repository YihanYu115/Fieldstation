"""Immutable reading-contract choices made at reference admission, never at read time."""
from __future__ import annotations

import json
from typing import Any

from .errors import NotFoundError, ValidationError
from .store import canonical_json, new_id, now


def project_root(store: Any, issue_id: str) -> str:
    rows = store.rows(
        "WITH RECURSIVE ancestors(issue_id,parent_issue_id) AS ("
        "SELECT issue_id,parent_issue_id FROM issues WHERE issue_id=? UNION "
        "SELECT i.issue_id,i.parent_issue_id FROM issues i JOIN ancestors a "
        "ON i.issue_id=a.parent_issue_id) SELECT issue_id FROM ancestors "
        "WHERE parent_issue_id IS NULL", (issue_id,))
    if not rows:
        raise NotFoundError("Issue has no project root")
    return str(rows[0]["issue_id"])


class OriginalAccessBindings:
    def __init__(self, manager: Any):
        self.manager = manager
        self.store = manager.store

    def _capture(self, issue_id: str, reference: str, *, evidence_id: str | None = None,
                 packet_id: str | None = None, inherit_packet: str | None = None) -> dict:
        if not self.store.conn.in_transaction:
            raise ValidationError("Reference binding requires the admission transaction")
        root = project_root(self.store, issue_id)
        existing = self.store.row(
            "SELECT * FROM project_original_access_bindings WHERE root_issue_id=? AND reference=? "
            "AND (evidence_id=? OR packet_id=?)", (root, reference, evidence_id, packet_id))
        if existing:
            return existing
        status, contract, revision, inherited, candidates = "missing", None, None, None, []
        candidate_count = 0
        if reference.startswith(("im-internal:", "im-field-packet:")):
            status = "internal"
        elif inherit_packet is not None:
            source = self.store.row(
                "SELECT b.* FROM project_original_access_bindings b JOIN field_packets p "
                "ON p.packet_id=b.packet_id WHERE b.packet_id=? AND b.reference=? "
                "AND b.root_issue_id=? AND p.issue_id=?", (inherit_packet, reference, root, issue_id))
            if source:
                status, contract, revision = source["status"], source["contract_id"], source["revision"]
                inherited = source["binding_id"]
                candidates = json.loads(source["candidates_json"])
                candidate_count = source["candidate_count"]
            else:
                # No retroactive choice of today's contract for an older unbound packet.
                status = "legacy_unbound"
        else:
            rows = self.store.rows(
                "SELECT h.contract_id,h.revision,json_extract(v.document_json,'$.reference_prefix') AS prefix "
                "FROM project_original_access_heads h JOIN project_original_access_versions v "
                "USING(root_issue_id,contract_id,revision) WHERE h.root_issue_id=? "
                "ORDER BY h.contract_id LIMIT 10001", (root,))
            if len(rows) > 10000:
                status = "catalog_too_large"
            else:
                candidates = [{"contract_id": r["contract_id"], "revision": r["revision"]}
                              for r in rows if reference.startswith(r["prefix"])]
                candidate_count = len(candidates)
                if len(candidates) == 1:
                    status = "bound"
                    contract, revision = candidates[0]["contract_id"], candidates[0]["revision"]
                elif candidates:
                    status = "ambiguous"
        binding = new_id("access")
        self.store.conn.execute(
            "INSERT INTO project_original_access_bindings "
            "(binding_id,root_issue_id,evidence_id,packet_id,reference,status,contract_id,revision,"
            "inherited_from,candidates_json,candidate_count,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (binding, root, evidence_id, packet_id, reference, status, contract, revision,
             inherited, canonical_json(candidates[:50]), candidate_count, now()))
        self.store.fault("original_access.after_binding")
        return self.store.row("SELECT * FROM project_original_access_bindings WHERE binding_id=?", (binding,)) or {}

    def admit_evidence(self, issue_id: str, evidence_id: str, *, inherit_packet: str | None = None) -> list:
        row = self.store.row("SELECT locator,declared_source_locator FROM evidence_refs WHERE evidence_id=?",
                             (evidence_id,))
        if row is None:
            raise NotFoundError("Evidence not found")
        self._capture(issue_id, row["declared_source_locator"] or row["locator"],
                      evidence_id=evidence_id, inherit_packet=inherit_packet)
        return self.evidence(issue_id, evidence_id)

    def admit_packet(self, issue_id: str, packet_id: str, references: list[str]) -> None:
        for reference in dict.fromkeys(references):
            self._capture(issue_id, reference, packet_id=packet_id)

    @staticmethod
    def _present(row: dict, issue_id: str) -> dict:
        item = {"binding_id": row["binding_id"], "reference": row["reference"], "status": row["status"]}
        if row["inherited_from"]:
            item["inherited_from"] = row["inherited_from"]
        if row["status"] == "bound":
            item.update(contract_id=row["contract_id"], revision=row["revision"],
                        read={"tool": "read_original_access", "arguments": {
                            "issue_id": issue_id, "contract_id": row["contract_id"], "revision": row["revision"]}})
        elif row["status"] == "ambiguous":
            item["candidate_count"] = row["candidate_count"]
        return item

    def evidence(self, issue_id: str, evidence_id: str) -> list[dict]:
        root = project_root(self.store, issue_id)
        rows = self.store.rows("SELECT * FROM project_original_access_bindings "
                               "WHERE root_issue_id=? AND evidence_id=? ORDER BY reference", (root, evidence_id))
        return [self._present(row, issue_id) for row in rows]

    def packet(self, issue_id: str, packet_id: str) -> list[dict]:
        rows = self.store.rows("SELECT * FROM project_original_access_bindings WHERE packet_id=? ORDER BY reference",
                               (packet_id,))
        return [self._present(row, issue_id) for row in rows]
