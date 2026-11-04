"""Frozen preparation, receipt selection, and transactional indexed maintenance."""

from __future__ import annotations

import base64
import hashlib
import json
from contextlib import contextmanager
from typing import Any

from .context_resolver import normalized_equal, subscription_key
from .context_rule_service import rule_capabilities, rule_descriptor_version
from .context_scoped_rule import SCOPED_V2_RULE_ID
from .currentness_repository import CurrentnessRepository
from .errors import ConflictError, NotFoundError, ValidationError
from .store import canonical_json, new_id, now


class ContextMaintenanceService:
    # Manager HTTP responses add a request envelope around the presentation
    # payload. Keep that fixed protocol overhead inside the caller's budget.
    _PRESENTATION_ENVELOPE_RESERVE = 256

    def __init__(self, manager):
        self.manager = manager
        self.store = manager.store
        self.conn = self.store.conn
        self.repository = CurrentnessRepository(self.conn)
        from .context_scoped_v2_resolver import ContextScopedV2Resolver
        self.scoped_v2_resolver = ContextScopedV2Resolver(self.conn, manager=manager)

    @staticmethod
    def _package_evidence_ids(materials: dict[str, Any]) -> set[str]:
        ids = set(materials.get("evidence", {})) | set(materials.get("excluded_evidence", {}))
        ids.update(item.get("candidate_id") for item in materials.get("candidate_states", [])
                   if isinstance(item, dict) and isinstance(item.get("candidate_id"), str))
        for item in materials.get("relations", []):
            if isinstance(item, dict):
                ids.update(value for value in (item.get("source_id"), item.get("target_id"))
                            if isinstance(value, str))
        for provider in materials.get("providers", []):
            if not isinstance(provider, dict):
                continue
            conclusion = provider.get("conclusion")
            if not isinstance(conclusion, dict):
                continue
            refs = conclusion.get("evidence_refs", conclusion.get("evidence_refs_json", []))
            if isinstance(refs, str):
                try:
                    refs = json.loads(refs)
                except (TypeError, ValueError):
                    refs = []
            if isinstance(refs, list):
                ids.update(item for item in refs if isinstance(item, str))
        return ids

    def _resolver_for(self, definition):
        if definition.get("version") != SCOPED_V2_RULE_ID:
            raise ValidationError("Unsupported context descriptor; only scoped-v2 is supported")
        return self.scoped_v2_resolver

    @contextmanager
    def _package_transaction(self, *, diagnostic: bool):
        if not diagnostic:
            with self.store.transaction() as conn:
                yield conn
            return
        if self.conn.in_transaction:
            raise ConflictError("V2 diagnostic package preparation requires its own transaction")
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def validate_change(self, operation, *, state_view=None):
        action = operation.get("action")
        if action not in {"verify", "select", "revoke", "restore"}:
            raise ValidationError("Unknown context change action")
        if not isinstance(operation.get("allow_historical", False), bool):
            raise ValidationError("allow_historical must be boolean")
        if not isinstance(operation.get("reason"), str) or not operation["reason"].strip():
            raise ValidationError("Context changes need a reason")
        items = operation.get("items")
        if not isinstance(items, list) or not items:
            raise ValidationError("Context changes need at least one item")
        seen = set()
        for item in items:
            required = {"conclusion_id", "expected_receipt_id", "package_id" if action == "verify" else "receipt_id"}
            if action in {"revoke", "restore"}:
                required.add("expected_eligible")
            if not isinstance(item, dict) or set(item) != required or any(
                not isinstance(value, bool if key == "expected_eligible" else str) for key, value in item.items()
            ):
                raise ValidationError(f"Context change items require exactly {sorted(required)} as strings")
            conclusion_id = item["conclusion_id"]
            if conclusion_id in seen:
                raise ValidationError("A context change can select each conclusion only once")
            seen.add(conclusion_id)
            conclusion = self.store.row("SELECT issue_id FROM conclusion_revisions WHERE conclusion_id=?", (conclusion_id,))
            if not conclusion:
                raise NotFoundError("Conclusion not found")
            selected = self.store.row("SELECT receipt_id FROM basis_receipt_selections WHERE conclusion_id=?", (conclusion_id,))
            selected_id = selected["receipt_id"] if selected else ""
            if state_view is not None:
                selected_id = state_view.selected_receipts.get(conclusion_id, selected_id)
            if selected_id != item["expected_receipt_id"]:
                raise ConflictError("Selected receipt changed; read currentness and rebase the ChangeSet")
            if action == "verify":
                package = self.package(item["package_id"])
                if package["descriptor"]["issue_id"] != conclusion["issue_id"]:
                    raise ConflictError("Prepared input belongs to another issue")
                active_rule = self.manager.context_rules.active(state_view=state_view)
                if package["descriptor"].get("rule_version_id") != active_rule["rule_id"]:
                    raise ConflictError("Prepared input uses an inactive context rule")
                if not operation.get("allow_historical", False):
                    self.verify_package(item["package_id"], conclusion["issue_id"], state_view=state_view)
            else:
                receipt = self.store.row("SELECT conclusion_id FROM basis_receipts WHERE receipt_id=?", (item["receipt_id"],))
                if not receipt or receipt["conclusion_id"] != conclusion_id:
                    raise ConflictError("Receipt does not belong to this conclusion")
                if action in {"revoke", "restore"}:
                    eligibility = self.store.row("SELECT eligible FROM basis_receipt_eligibility WHERE receipt_id=?", (item["receipt_id"],))
                    eligible = bool(eligibility["eligible"]) if eligibility else None
                    if state_view is not None:
                        eligible = state_view.receipt_eligibility.get(item["receipt_id"], eligible)
                    if eligible != item["expected_eligible"]:
                        raise ConflictError("Receipt qualification changed; rebase the ChangeSet")
        return items

    def execute_change(self, operation, *, actor, identity=None):
        with self.store.transaction():
            items = self.validate_change(operation)
            receipts = []
            for item in items:
                action = operation["action"]
                if action == "verify":
                    receipts.append(self.attach_receipt(
                        item["conclusion_id"], item["package_id"], actor=actor, identity=identity,
                        allow_historical=operation.get("allow_historical", False),
                    ))
                elif action == "select":
                    self.select_receipt(item["conclusion_id"], item["receipt_id"], actor=actor)
                    receipts.append({"receipt_id": item["receipt_id"]})
                else:
                    self.set_receipt_eligibility(item["receipt_id"], action == "restore", actor=actor, reason=operation["reason"])
                    receipts.append({"receipt_id": item["receipt_id"]})
            self.flush()
            return {"receipts": receipts, "currentness": [self.show(item["conclusion_id"]) for item in items]}

    def package(self, package_id):
        row = self.store.row(
            "SELECT p.*,d.definition_json,r.definition_json AS rule_definition_json FROM context_input_packages p "
            "JOIN context_descriptors d USING(descriptor_id) JOIN context_rule_versions r USING(rule_id) WHERE package_id=?", (package_id,)
        )
        if not row:
            raise NotFoundError("Context input package not found")
        return {"package_id": package_id, "input_revision": row["input_revision"],
                "descriptor": json.loads(row["definition_json"]), "actual_input": json.loads(row["actual_input_json"]),
                "semantic_context": json.loads(row["semantic_context_json"]), "rule": json.loads(row["rule_definition_json"])}

    def current_scoped_projection(self, issue_id: str, *, auth=None) -> dict[str, Any]:
        """Read the current v2 projection without creating a package or view."""
        active = self.manager.context_rules.active()
        if rule_capabilities(active["rule_id"])["resolver"] != "scoped-v2":
            raise ConflictError("Current scoped projection requires an active scoped-v2 rule")
        with self.store.read_transaction():
            current = self.conn.execute(
                "SELECT current_conclusion_id FROM issues WHERE issue_id=?", (issue_id,)
            ).fetchone()
            roots: list[str] = []
            if current and current[0]:
                row = self.conn.execute(
                    "SELECT evidence_refs_json FROM conclusion_revisions WHERE conclusion_id=?", (current[0],)
                ).fetchone()
                if row:
                    roots = sorted(json.loads(row[0]))
            descriptor = self.default_descriptor(issue_id, evidence_ids=roots)
            resolved = self.scoped_v2_resolver.resolve(descriptor)
            materials = resolved.model_materials
            if auth is not None:
                for evidence_id in self._package_evidence_ids(materials):
                    self.manager.evidence.require_read_access(evidence_id, auth)
            return {
                "rule_id": active["rule_id"],
                "issue_id": issue_id,
                "conclusion_id": current[0] if current else None,
                "complete": resolved.complete and not resolved.errors,
                "errors": resolved.errors,
                "roots": materials.get("roots", []),
                "support_ids": materials.get("support_ids", []),
                "gap": materials.get("gap", []),
                "related_challenges": materials.get("related_challenges", []),
                "discovery_ids": materials.get("discovery_ids", []),
                "candidate_states": materials.get("candidate_states", []),
                "comparison": resolved.comparison_context,
            }

    def create_view(self, package_id: str, *, auth, budget_bytes: int = 32768,
                    presentation_rule_id: str = "scoped-summary/v1", idempotency_key: str | None = None):
        auth.require("conclusion.propose")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValidationError("Context views require an Idempotency-Key")
        if presentation_rule_id != "scoped-summary/v1":
            raise ValidationError("Unsupported context view presentation rule")
        if not isinstance(budget_bytes, int) or isinstance(budget_bytes, bool) or not 0 < budget_bytes <= 131072:
            raise ValidationError("budget_bytes must be an integer between 1 and 131072")
        package = self.package(package_id)
        if package["descriptor"].get("version") != SCOPED_V2_RULE_ID:
            raise ConflictError("Package is not a scoped package")
        package_materials = package["actual_input"].get("materials", {})
        for evidence_id in self._package_evidence_ids(package_materials):
            self.manager.evidence.require_read_access(evidence_id, auth)
        payload = {"package_id": package_id, "budget_bytes": budget_bytes, "presentation_rule_id": presentation_rule_id}
        operation_key = f"context.view:{auth.actor_id}:{auth.run_id}"
        view_id = new_id("context_view")
        with self.store.transaction() as conn:
            replay = self.store.idempotency_lookup(operation_key, idempotency_key, payload)
            if replay is not None:
                return replay
            # Validate the complete first page before inserting the row; a
            # failed presentation never leaves a view credential behind.
            self._view_summary(package, budget_bytes)
            conn.execute("INSERT INTO context_package_views VALUES (?,?,?,?,?,?,?,?)",
                         (view_id, package_id, package["descriptor"]["issue_id"], package["descriptor"]["rule_version_id"],
                         presentation_rule_id, budget_bytes, now(), auth.actor_id))
            result = {"view_id": view_id, "package_id": package_id, "budget_bytes": budget_bytes,
                "presentation_rule_id": presentation_rule_id,
                "summary": self._view_summary(package, budget_bytes)}
            self.store.idempotency_record(conn, operation_key, idempotency_key, payload, result)
            return result

    @staticmethod
    def _compact_relation(item):
        """Keep summaries bounded; full relation objects expand through entry()."""
        fields = (
            "relation_id", "version", "source_id", "target_id", "kind", "relation_type",
            "active", "binding_current", "source_binding", "target_binding",
            "source_binding_token", "target_binding_token", "source_state", "target_state",
        )
        return {key: item[key] for key in fields if key in item}

    @staticmethod
    def _compact_gap(item):
        """Keep an unresolved-root summary bounded; details remain in the frozen package."""
        fields = ("node_id", "state", "reasons")
        return {key: item[key] for key in fields if key in item}

    @staticmethod
    def _view_summary(package, budget_bytes, cursor=None):
        payload_budget = budget_bytes - ContextMaintenanceService._PRESENTATION_ENVELOPE_RESERVE
        if payload_budget <= 0:
            raise ValidationError("View budget is too small for the HTTP presentation envelope")

        def encoded_size(value):
            # The service normally emits compact canonical JSON, while callers
            # and the contract tests may measure the ordinary JSON spelling.
            # Budget against both so a page cannot grow past the advertised
            # byte limit merely because of serializer whitespace.
            return max(
                len(canonical_json(value).encode("utf-8")),
                len(json.dumps(value, ensure_ascii=False).encode("utf-8")),
            )

        materials = package["actual_input"].get("materials", {})
        issue = materials.get("issue", {})
        issue_display = {key: issue[key] for key in (
            "issue_id", "title", "issue_type", "scope_json", "parent_issue_id", "work_status",
        ) if key in issue}
        catalog_entries = [{"kind": "evidence", "id": item, "status": "included"}
                           for item in sorted(materials.get("evidence", {}))]
        status_names = {"T": "included", "F": "excluded", "?": "unresolved"}
        catalog_entries.extend(
            {"kind": "candidate", "id": item.get("candidate_id"),
             "status": status_names.get(item.get("status"), item.get("status"))}
            for item in materials.get("candidate_states", [])
        )
        catalog_entries.extend(
            {"kind": "relation", "id": item.get("relation_id"), "status": "current"}
            for item in materials.get("relations", [])
        )
        relation_summary = [
            ContextMaintenanceService._compact_relation(item)
            for item in materials.get("relations", [])
        ]
        partitions = {
            "support": sorted(materials.get("support_ids", [])),
            "gap": [ContextMaintenanceService._compact_gap(item)
                    for item in materials.get("gap", [])],
            "related_challenges": [
                ContextMaintenanceService._compact_relation(item)
                for item in materials.get("related_challenges", [])
            ],
            "discovery": sorted(materials.get("discovery_ids", [])),
        }
        # The existing integer cursor now walks one bounded presentation stream.
        # Keeping the stream here, rather than teaching the MCP client to fetch
        # more pages, makes every summary array page-budgeted while preserving
        # the existing GET /views/{id}?cursor= interface.
        stream = ([{"section": "catalog", "value": item} for item in catalog_entries]
                  + [{"section": "relations", "value": item} for item in relation_summary])
        stream.extend(
            {"section": f"partitions.{name}", "value": item}
            for name in ("support", "gap", "related_challenges", "discovery")
            for item in partitions[name]
        )
        offset = 0
        if cursor is not None:
            offset = cursor
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0 or offset > len(stream):
            raise ValidationError("Invalid view catalog cursor")
        chosen: list[dict[str, Any]] = []
        for index in range(offset, len(stream)):
            trial_items = chosen + [stream[index]]
            trial = {"issue": issue_display,
                     "seed_source_count": len(materials.get("seed_sources", [])),
                     "catalog": [item["value"] for item in trial_items
                                 if item["section"] == "catalog"],
                     "relations": [item["value"] for item in trial_items
                                   if item["section"] == "relations"],
                     "partitions": {
                         name: [item["value"] for item in trial_items
                               if item["section"] == f"partitions.{name}"]
                         for name in partitions
                     },
                     "relation_count": len(materials.get("relations", [])),
                     "partition_counts": {name: len(items) for name, items in partitions.items()},
                     "remaining": len(stream) - index - 1,
                     "next_cursor": index + 1 if index + 1 < len(stream) else None}
            if encoded_size(trial) > payload_budget:
                if not chosen:
                    raise ValidationError("View presentation entry exceeds the requested byte budget")
                break
            chosen.append(stream[index])
        page = chosen
        next_cursor = offset + len(page) if offset + len(page) < len(stream) else None
        summary = {"issue": issue_display,
                   "seed_source_count": len(materials.get("seed_sources", [])),
                   "catalog": [item["value"] for item in page if item["section"] == "catalog"],
                   "relations": [item["value"] for item in page if item["section"] == "relations"],
                   "partitions": {
                       name: [item["value"] for item in page
                              if item["section"] == f"partitions.{name}"]
                       for name in partitions
                   },
                   "relation_count": len(materials.get("relations", [])),
                   "partition_counts": {name: len(items) for name, items in partitions.items()},
                   "remaining": len(stream) - (offset + len(page)), "next_cursor": next_cursor}
        if encoded_size(summary) > payload_budget:
            raise ValidationError("View summary exceeds the requested byte budget")
        return summary

    def view(self, view_id: str, *, auth=None, cursor=None):
        row = self.store.row("SELECT * FROM context_package_views WHERE view_id=?", (view_id,))
        if not row:
            raise NotFoundError("Context package view not found")
        package = self.package(row["package_id"])
        if auth is not None:
            package_materials = package["actual_input"].get("materials", {})
            for evidence_id in self._package_evidence_ids(package_materials):
                self.manager.evidence.require_read_access(evidence_id, auth)
        return {"view_id": view_id, "package_id": row["package_id"], "issue_id": row["issue_id"],
                "budget_bytes": row["budget_bytes"], "presentation_rule_id": row["presentation_rule_id"],
                "summary": self._view_summary(package, row["budget_bytes"], cursor=cursor)}

    def entry(self, view_id: str, kind: str, entry_id: str, *, auth=None, cursor=None):
        """Expand one finite, frozen catalog entry without rereading heads."""
        if kind not in {"candidate", "relation", "boundary"}:
            raise ValidationError("Unsupported frozen view entry kind")
        row = self.store.row("SELECT * FROM context_package_views WHERE view_id=?", (view_id,))
        if not row:
            raise NotFoundError("Context package view not found")
        package = self.package(row["package_id"])
        # Reuse the complete object-level permission check used by GET view.
        self.view(view_id, auth=auth)
        trace = package["actual_input"].get("selection_trace", {})
        if kind == "candidate":
            selection = trace.get("selection", {})
            item = next((item for item in selection.get("candidates", [])
                         if item.get("candidate_id") == entry_id), None)
            if item is None:
                materials = package["actual_input"].get("materials", {})
                raw = next((item for item in materials.get("candidate_states", [])
                            if item.get("candidate_id") == entry_id), None)
                if raw is not None:
                    item = {
                        "candidate_id": entry_id,
                        "status": {"T": "included", "F": "excluded", "?": "unresolved"}.get(
                            raw.get("status"), raw.get("status")
                        ),
                        "exclusions": [], "diagnostics": raw.get("reasons", []),
                    }
            if item is None:
                raise NotFoundError("Frozen candidate entry not found")
            discovery = trace.get("discovery", {})
            reasons: list[str] = next((item.get("reasons", []) for item in discovery.get("candidates", [])
                            if item.get("candidate_id") == entry_id), [])
            materials = package["actual_input"].get("materials", {})
            partition = "discovery"
            if entry_id in set(materials.get("support_ids", [])):
                partition = "support"
            elif any(row.get("node_id") == entry_id for row in materials.get("gap", [])):
                partition = "gap"
            result = {"kind": kind, "id": entry_id, "status": item.get("status"),
                      "partition": partition,
                      "reasons": reasons, "exclusions": item.get("exclusions", []),
                      "diagnostics": item.get("diagnostics", [])}
        elif kind == "relation":
            item = next((item for item in trace.get("heads", [])
                         if item.get("relation_id") == entry_id), None)
            if item is None:
                item = next((item for item in package["actual_input"].get("materials", {}).get("relations", [])
                             if item.get("relation_id") == entry_id), None)
            if item is None:
                raise NotFoundError("Frozen relation entry not found")
            result = {"kind": kind, "id": entry_id, "relation": item}
        else:
            item = next((item for item in trace.get("discovery", {}).get("boundary_refs", [])
                         if item.get("relation_id") == entry_id), None)
            if item is None:
                raise NotFoundError("Frozen boundary entry not found")
            result = {"kind": kind, "id": entry_id, "boundary": item}
        encoded = canonical_json(result)
        budget = int(row["budget_bytes"]) - self._PRESENTATION_ENVELOPE_RESERVE
        if budget <= 0:
            raise ValidationError("View budget is too small for the HTTP presentation envelope")
        if cursor is None and len(encoded.encode("utf-8")) <= budget:
            return result
        offset = 0
        if cursor is not None:
            if not isinstance(cursor, str) or not cursor:
                raise ValidationError("cursor must be a nonempty string")
            try:
                decoded = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii") + b"=" * (-len(cursor) % 4)))
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValidationError("Invalid frozen entry cursor") from exc
            if (not isinstance(decoded, dict) or decoded.get("view_id") != view_id or
                    decoded.get("kind") != kind or decoded.get("entry_id") != entry_id or
                    not isinstance(decoded.get("offset"), int) or isinstance(decoded.get("offset"), bool) or
                    decoded["offset"] < 0):
                raise ValidationError("Cursor does not belong to this frozen entry")
            offset = decoded["offset"]
        if offset > len(encoded):
            raise ValidationError("Frozen entry cursor is outside the content")

        def make_cursor(next_offset):
            token = {"view_id": view_id, "kind": kind, "entry_id": entry_id, "offset": next_offset}
            return base64.urlsafe_b64encode(canonical_json(token).encode("utf-8")).decode("ascii").rstrip("=")

        end = offset
        while end < len(encoded):
            probe_cursor = make_cursor(end + 1) if end + 1 < len(encoded) else None
            probe = {"view_id": view_id, "kind": kind, "entry_id": entry_id, "offset": offset,
                     "content_utf8": encoded[offset:end + 1], "bytes": len(encoded[offset:end + 1].encode("utf-8")),
                     "complete": probe_cursor is None, "next_cursor": probe_cursor}
            if len(canonical_json(probe).encode("utf-8")) > budget:
                break
            end += 1
        if end == offset and offset < len(encoded):
            raise ValidationError("Frozen view entry metadata exceeds the requested byte budget")
        next_cursor = make_cursor(end) if end < len(encoded) else None
        return {"view_id": view_id, "kind": kind, "entry_id": entry_id, "offset": offset,
                "content_utf8": encoded[offset:end], "bytes": len(encoded[offset:end].encode("utf-8")),
                "complete": next_cursor is None, "next_cursor": next_cursor}

    def material_page(self, view_id: str, evidence_id: str, *, auth=None, cursor=None, mode="selected"):
        row = self.store.row("SELECT * FROM context_package_views WHERE view_id=?", (view_id,))
        if not row:
            raise NotFoundError("Context package view not found")
        package = self.package(row["package_id"])
        materials = package["actual_input"].get("materials", {})
        if mode not in {"selected", "excluded"}:
            raise ValidationError("Material expansion mode must be selected or excluded")
        evidence_pool = materials.get("evidence", {}) if mode == "selected" else materials.get("excluded_evidence", {})
        evidence = evidence_pool.get(evidence_id)
        if evidence is None:
            raise NotFoundError("Evidence is not available in this frozen package for the requested mode")
        if auth is not None:
            self.manager.evidence.require_read_access(evidence_id, auth)
        offset = 0
        if cursor is not None:
            if not isinstance(cursor, str) or not cursor:
                raise ValidationError("cursor must be a nonempty string")
            try:
                decoded = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii") + b"=" * (-len(cursor) % 4)))
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValidationError("Invalid material cursor") from exc
            if (not isinstance(decoded, dict) or decoded.get("view_id") != view_id or
                    decoded.get("evidence_id") != evidence_id or decoded.get("mode", "selected") != mode or
                    not isinstance(decoded.get("offset"), int) or isinstance(decoded.get("offset"), bool) or decoded["offset"] < 0):
                raise ValidationError("Cursor does not belong to this material")
            offset = decoded["offset"]
        presentation_evidence = evidence
        if evidence.get("declared_source_locator") is not None:
            presentation_evidence = {
                **evidence,
                "source_locator": evidence["declared_source_locator"],
                "locator_role": "internal_identity",
            }
        encoded = canonical_json(presentation_evidence)
        budget = int(row["budget_bytes"]) - self._PRESENTATION_ENVELOPE_RESERVE
        if budget <= 0:
            raise ValidationError("View budget is too small for the HTTP presentation envelope")
        if offset > len(encoded):
            raise ValidationError("Material cursor is outside the frozen content")
        def make_cursor(next_offset):
            token = {"view_id": view_id, "evidence_id": evidence_id, "mode": mode, "offset": next_offset}
            return base64.urlsafe_b64encode(canonical_json(token).encode("utf-8")).decode("ascii").rstrip("=")

        def page_for(end):
            next_cursor = make_cursor(end) if end < len(encoded) else None
            fragment = encoded[offset:end]
            return {"view_id": view_id, "evidence_id": evidence_id, "offset": offset,
                    "content_utf8": fragment, "bytes": len(fragment.encode("utf-8")),
                    "complete": next_cursor is None, "next_cursor": next_cursor,
                    "source": {"locator": evidence.get("declared_source_locator") or evidence.get("locator"),
                               "locator_kind": "declared" if evidence.get("declared_source_locator") is not None else "evidence",
                               "content_hash": evidence.get("content_hash"),
                               "original_access": {"read": {"tool": "read_original_access", "arguments": {
                                   "issue_id": package["descriptor"]["issue_id"], "evidence_id": evidence_id}}},
                               "body_available": False}}

        end = offset
        while end < len(encoded):
            probe = page_for(end + 1)
            if len(canonical_json(probe).encode("utf-8")) > budget:
                break
            end += 1
        if end == offset and offset < len(encoded):
            raise ValidationError("Frozen material metadata exceeds the requested byte budget")
        result = page_for(end)
        if len(canonical_json(result).encode("utf-8")) > budget:
            raise ValidationError("Material page exceeds the requested byte budget")
        return result

    def _descriptor(self, definition):
        raw = canonical_json(definition)
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        # Hashes accelerate lookup; equality is checked structurally.
        for row in self.conn.execute(
            "SELECT descriptor_id,definition_json FROM context_descriptors WHERE content_hash=?", (digest,)
        ):
            if normalized_equal(json.loads(row[1]), definition):
                return row[0]
        descriptor_id = new_id("context_descriptor")
        self.conn.execute("INSERT INTO context_descriptors VALUES (?,?,?,?,?)",
                          (descriptor_id, definition["rule_version_id"], raw, digest, now()))
        return descriptor_id

    def default_descriptor(self, issue_id, basis=(), evidence_ids=()):
        active_rule = self.manager.context_rules.active()
        descriptor_version = rule_descriptor_version(active_rule["rule_id"])
        bindings = []
        for item in basis:
            if item.get("basis_mode", "current") == "historical":
                version = self.conn.execute(
                    "SELECT conclusion_id FROM conclusion_revisions WHERE issue_id=? AND revision_number=?",
                    (item["issue_id"], item["conclusion_revision"])
                ).fetchone()
                bindings.append({"issue_id": item["issue_id"], "mode": "fixed",
                                 "conclusion_id": version[0] if version else None,
                                 "require_currentness": False})
            else:
                bindings.append({"issue_id": item["issue_id"], "mode": "follow-current",
                                 "require_currentness": bool(item.get("require_currentness", True))})
        return {"version": descriptor_version, "issue_id": issue_id,
                "rule_version_id": active_rule["rule_id"],
                "seed_evidence_ids": sorted(set(evidence_ids)),
                "provider_bindings": sorted(bindings, key=canonical_json)}

    def prepare(self, issue_id: str, *, basis=(), evidence_ids=None, descriptor=None,
                actor: str = "organizer-agent") -> dict[str, Any]:
        return self._prepare(issue_id, basis=basis, evidence_ids=evidence_ids,
                             descriptor=descriptor, actor=actor)

    def prepare_diagnostic(self, issue_id: str, *, basis=(), evidence_ids=None, descriptor=None,
                          actor: str = "organizer-agent", rule_id: str) -> dict[str, Any]:
        """Persist an internal package under an explicit supported resolver rule.

        This diagnostic path does not flush or write currentness and cannot be
        used to issue a receipt while the requested rule is inactive.
        """
        from .context_rule_service import supported_runtime_rules

        if rule_id not in supported_runtime_rules():
            raise ValidationError("Unsupported context rule is unavailable for diagnostics")
        return self._prepare(issue_id, basis=basis, evidence_ids=evidence_ids,
                             descriptor=descriptor, actor=actor, diagnostic_rule_id=rule_id)

    def _prepare(self, issue_id: str, *, basis=(), evidence_ids=(), descriptor=None,
                 actor: str = "organizer-agent", diagnostic_rule_id: str | None = None) -> dict[str, Any]:
        definition = self.default_descriptor(issue_id, basis, [] if evidence_ids is None else evidence_ids) if descriptor is None else dict(descriptor)
        if not isinstance(definition, dict):
            raise ValidationError("Context descriptor must be an object")
        active_rule = self.manager.context_rules.active()
        if diagnostic_rule_id is None:
            definition = {"rule_version_id": active_rule["rule_id"], **definition}
            if definition["rule_version_id"] != active_rule["rule_id"]:
                raise ConflictError("New preparation must use the active rule version")
        else:
            from .context_rule_service import supported_runtime_rules

            supported = supported_runtime_rules()
            if diagnostic_rule_id not in supported:
                raise ValidationError("Unsupported internal diagnostic context rule")
            diagnostic_definition = supported[diagnostic_rule_id]
            if descriptor is None:
                definition["version"] = diagnostic_definition["version"]
                definition["rule_version_id"] = diagnostic_rule_id
            elif definition.get("version") != diagnostic_definition["version"]:
                raise ValidationError("Diagnostic descriptor has a different rule version")
            elif definition.get("rule_version_id", diagnostic_rule_id) != diagnostic_rule_id:
                raise ValidationError("Diagnostic descriptor has a different rule identity")
            else:
                definition["rule_version_id"] = diagnostic_rule_id
        if definition.get("issue_id") != issue_id:
            raise ConflictError("Context descriptor belongs to another issue")
        with self._package_transaction(diagnostic=diagnostic_rule_id is not None):
            if descriptor is None and diagnostic_rule_id is None:
                head = self.conn.execute(
                    "SELECT current_conclusion_id FROM issues WHERE issue_id=?", (issue_id,)
                ).fetchone()
                if head and head[0]:
                    definition["prior_conclusion_id"] = head[0]
                    if (
                        definition.get("version") == SCOPED_V2_RULE_ID
                        and evidence_ids is None
                        and not definition.get("seed_evidence_ids")
                    ):
                        prior = self.conn.execute(
                            "SELECT evidence_refs_json FROM conclusion_revisions WHERE conclusion_id=?",
                            (head[0],),
                        ).fetchone()
                        if prior:
                            definition["seed_evidence_ids"] = sorted(json.loads(prior[0]))
            # Finish earlier mutations within an enclosing ChangeSet before
            # recording the input revision of this preparation.
            if diagnostic_rule_id is None:
                self.flush()
            resolver = self._resolver_for(definition)
            resolved = resolver.resolve(definition)
            descriptor_id = self._descriptor(definition)
            package_id = new_id("context_input")
            comparison_context = resolved.comparison_context or resolved.semantic
            semantic = canonical_json(comparison_context)
            revision = self.conn.execute("SELECT revision FROM context_input_clock").fetchone()[0]
            actual = {"materials": resolved.model_materials,
                      "comparison_context": resolved.comparison_context,
                      "selection_trace": resolved.selection_trace,
                      "raw_inputs": resolved.actual_reads,
                      "resolution_errors": resolved.errors}
            self.conn.execute("INSERT INTO context_input_packages VALUES (?,?,?,?,?,?,?,?)",
                              (package_id, descriptor_id, canonical_json(actual), semantic,
                               hashlib.sha256(semantic.encode("utf-8")).hexdigest(), revision, now(), actor))
        return {"package_id": package_id, "input_revision": revision, "actual_input": actual,
                "descriptor": definition, "resolution_errors": resolved.errors}

    def attach_receipt(self, conclusion_id: str, package_id: str, *, actor: str,
                       identity: dict[str, Any] | None = None, allow_historical: bool = False):
        """Attach only a package prepared before generation; never synthesize it."""
        with self.store.transaction():
            row = self.conn.execute(
                "SELECT p.descriptor_id,p.semantic_context_json,d.definition_json "
                "FROM context_input_packages p JOIN context_descriptors d USING(descriptor_id) "
                "WHERE package_id=?", (package_id,)
            ).fetchone()
            if row is None:
                raise NotFoundError("Context input package not found")
            definition = json.loads(row[2])
            active_rule = self.manager.context_rules.active()
            if definition.get("rule_version_id") != active_rule["rule_id"]:
                raise ConflictError("Prepared input uses an inactive context rule")
            conclusion = self.conn.execute(
                "SELECT issue_id FROM conclusion_revisions WHERE conclusion_id=?", (conclusion_id,)
            ).fetchone()
            if not conclusion or conclusion[0] != definition["issue_id"]:
                raise ConflictError("Context input package belongs to another conclusion issue")
            resolved = self._resolver_for(definition).resolve(definition)
            matches = not resolved.errors and normalized_equal(resolved.semantic, json.loads(row[1]))
            if not matches and not allow_historical:
                raise ConflictError("Relevant context changed after preparation")
            receipt_id = new_id("basis_receipt")
            revision = self.conn.execute("SELECT revision FROM context_input_clock").fetchone()[0]
            self.conn.execute("INSERT INTO basis_receipts VALUES (?,?,?,?,?,?)",
                              (receipt_id, conclusion_id, package_id, canonical_json(identity or {}), now(), actor))
            self.conn.execute("INSERT INTO basis_receipt_eligibility VALUES (?,1,'issued',?)",
                              (receipt_id, revision))
            self.conn.execute(
                "INSERT INTO basis_receipt_selections VALUES (?,?) ON CONFLICT(conclusion_id) "
                "DO UPDATE SET receipt_id=excluded.receipt_id", (conclusion_id, receipt_id)
            )
            self.conn.execute(
                "INSERT INTO conclusion_context_selections VALUES (?,?) ON CONFLICT(conclusion_id) "
                "DO UPDATE SET descriptor_id=excluded.descriptor_id", (conclusion_id, row[0])
            )
            self.store.audit(self.conn, actor=actor, action="context.receipt.issue",
                             object_type="conclusion", object_id=conclusion_id,
                             before_revision=None, after_revision=None, reason="Context verification",
                             payload={"receipt_id": receipt_id, "package_id": package_id,
                                      "matches_at_commit": matches})
        return {"receipt_id": receipt_id, "matches_at_commit": matches}

    def verify_package(self, package_id: str, issue_id: str, *, state_view=None):
        row = self.conn.execute(
            "SELECT p.semantic_context_json,d.definition_json FROM context_input_packages p "
            "JOIN context_descriptors d USING(descriptor_id) WHERE package_id=?", (package_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("Context input package not found")
        definition = json.loads(row[1])
        if definition["issue_id"] != issue_id:
            raise ConflictError("Context package belongs to another issue")
        try:
            resolved = self._resolver_for(definition).resolve(definition, state_view=state_view)
        except ValidationError as exc:
            raise ConflictError("Prepared input uses an inactive or unsupported context rule") from exc
        if resolved.errors or not normalized_equal(resolved.semantic, json.loads(row[0])):
            raise ConflictError("Relevant context changed after preparation")

    def select_receipt(self, conclusion_id: str, receipt_id: str, *, actor: str):
        with self.store.transaction():
            receipt = self.conn.execute(
                "SELECT p.descriptor_id FROM basis_receipts r JOIN context_input_packages p USING(package_id) "
                "WHERE receipt_id=? AND conclusion_id=?", (receipt_id, conclusion_id)
            ).fetchone()
            if receipt is None:
                raise NotFoundError("Receipt does not belong to this conclusion version")
            self.conn.execute(
                "INSERT INTO basis_receipt_selections VALUES (?,?) ON CONFLICT(conclusion_id) "
                "DO UPDATE SET receipt_id=excluded.receipt_id", (conclusion_id, receipt_id)
            )
            self.conn.execute(
                "INSERT INTO conclusion_context_selections VALUES (?,?) ON CONFLICT(conclusion_id) "
                "DO UPDATE SET descriptor_id=excluded.descriptor_id", (conclusion_id, receipt[0])
            )
            self.store.audit(self.conn, actor=actor, action="context.receipt.select",
                             object_type="conclusion", object_id=conclusion_id, before_revision=None,
                             after_revision=None, reason="Select verification receipt", payload={"receipt_id": receipt_id})
        return self.show(conclusion_id)

    def set_receipt_eligibility(self, receipt_id: str, eligible: bool, *, actor: str, reason: str):
        with self.store.transaction():
            revision = self.conn.execute("SELECT revision FROM context_input_clock").fetchone()[0]
            changed = self.conn.execute(
                "UPDATE basis_receipt_eligibility SET eligible=?,reason=?,revision=? WHERE receipt_id=?",
                (int(eligible), reason, revision, receipt_id)
            )
            if not changed.rowcount:
                raise NotFoundError("Receipt not found")
            self.store.audit(self.conn, actor=actor, action="context.receipt.eligibility",
                             object_type="basis_receipt", object_id=receipt_id, before_revision=None,
                             after_revision=None, reason=reason, payload={"eligible": eligible})

    def verify_group(self, items: list[dict[str, str]], *, actor: str):
        """Joint verification of already-saved candidate versions, atomically.

        Packages refer to final content versions, never to each other's receipt
        hashes. Failure of any package check rolls back the entire group.
        """
        with self.store.transaction():
            return [self.attach_receipt(item["conclusion_id"], item["package_id"], actor=actor,
                                        identity={"verification": "joint"}) for item in items]

    def why(self, conclusion_id: str):
        from collections import deque

        state = self.show(conclusion_id)
        queue = deque([(conclusion_id, [conclusion_id])])
        seen = set()
        witness = None
        while queue:
            node, path = queue.popleft()
            if node in seen:
                continue
            seen.add(node)
            current = self.show(node)
            if current.get("local_mismatch"):
                witness = {"root": node, "path": list(reversed(path)), "reasons": current["reasons"]}
                break
            for row in self.conn.execute(
                "SELECT DISTINCT provider_conclusion_id FROM currentness_edge_contributions "
                "WHERE consumer_conclusion_id=? ORDER BY provider_conclusion_id", (node,)
            ):
                queue.append((row[0], path + [row[0]]))
        return {**state, "witness": witness, "explanation_scope": "one-shortest-root-path"}

    def flush(self):
        """Called before outer commit. No input changes can escape maintenance."""
        if not self.conn.in_transaction:
            raise RuntimeError("Context maintenance needs a transaction")
        checkpoint = self.conn.execute("SELECT event_id FROM context_maintenance_checkpoint").fetchone()[0]
        events = self.conn.execute(
            "SELECT event_id,object_kind,before_json,after_json FROM context_input_events "
            "WHERE event_id>? ORDER BY event_id", (checkpoint,)
        ).fetchall()
        candidates: set[str] = set()
        for _, table, before, after in events:
            for raw in (before, after):
                values = json.loads(raw)
                for column, value in values.items():
                    key = subscription_key(table, column, value)
                    candidates.update(self._subscription_candidates(key))
                if table in {"conclusion_revisions", "basis_receipt_selections",
                             "conclusion_context_selections"} and values.get("conclusion_id"):
                    candidates.add(values["conclusion_id"])
                if table == "basis_receipt_eligibility" and values.get("receipt_id"):
                    candidates.update(row[0] for row in self.conn.execute(
                        "SELECT conclusion_id FROM basis_receipt_selections WHERE receipt_id=?",
                        (values["receipt_id"],)
                    ))
        # Indexed startup/recovery work only; ordinary operations have none.
        candidates.update(row[0] for row in self.conn.execute(
            "SELECT conclusion_id FROM conclusion_currentness "
            "WHERE maintenance_state IN ('pending','failed')"
        ))
        reasons, contributions = {}, {}
        pending = list(candidates)
        while pending:
            conclusion_id = pending.pop()
            if conclusion_id in reasons:
                continue
            conclusion = self.conn.execute(
                "SELECT issue_id FROM conclusion_revisions WHERE conclusion_id=?", (conclusion_id,)
            ).fetchone()
            if conclusion is None:
                raise ConflictError("A maintained conclusion version was deleted")
            selected = self.conn.execute(
                "SELECT d.definition_json FROM conclusion_context_selections s "
                "JOIN context_descriptors d USING(descriptor_id) WHERE conclusion_id=?", (conclusion_id,)
            ).fetchone()
            definition = json.loads(selected[0]) if selected else self.default_descriptor(conclusion[0])
            resolved = self._resolver_for(definition).resolve(definition, tolerate_errors=True)
            if not resolved.complete:
                # Preserve prior boundary watches and contributions until a
                # successful resolution replaces them. The failed consumer is
                # itself a root, so uncertain incoming edges cannot clean it.
                for key, raw in self.conn.execute(
                    "SELECT subscription_key,descriptor_json FROM context_subscriptions WHERE conclusion_id=?", (conclusion_id,)
                ):
                    resolved.subscriptions.setdefault(key, json.loads(raw))
                resolved.contributions.update((row[0], row[1]) for row in self.conn.execute(
                    "SELECT provider_conclusion_id,contribution_id FROM currentness_edge_contributions WHERE consumer_conclusion_id=?",
                    (conclusion_id,)))
            receipt = self.conn.execute(
                "SELECT p.semantic_context_json,e.eligible FROM basis_receipt_selections s "
                "JOIN basis_receipts r USING(receipt_id) JOIN context_input_packages p USING(package_id) "
                "LEFT JOIN basis_receipt_eligibility e USING(receipt_id) WHERE s.conclusion_id=?", (conclusion_id,)
            ).fetchone()
            local = list(resolved.errors)
            if not receipt:
                local.append({"code": "basis_receipt_missing"})
            elif not receipt[1]:
                local.append({"code": "basis_receipt_ineligible"})
            elif not normalized_equal(json.loads(receipt[0]), resolved.semantic):
                local.append({"code": "context_mismatch"})
            reasons[conclusion_id] = local
            contributions[conclusion_id] = resolved.contributions
            self.conn.execute("DELETE FROM context_subscriptions WHERE conclusion_id=?", (conclusion_id,))
            self.conn.executemany("INSERT INTO context_subscriptions VALUES (?,?,?)",
                                  [(conclusion_id, key, canonical_json(value))
                                   for key, value in resolved.subscriptions.items()])
            for provider, _ in resolved.contributions:
                row = self.conn.execute(
                    "SELECT maintenance_state FROM conclusion_currentness WHERE conclusion_id=?", (provider,)
                ).fetchone()
                if not row or row[0] != "ready":
                    pending.append(provider)
        changed_rows = []
        if reasons:
            revision = self.conn.execute("SELECT revision FROM context_input_clock").fetchone()[0]
            update = self.repository.apply(revision=revision, local_reasons=reasons, contributions=contributions)
            for conclusion_id in set(reasons) | update.region:
                state = self.conn.execute(
                    "SELECT needs_update FROM conclusion_currentness WHERE conclusion_id=?", (conclusion_id,)
                ).fetchone()
                desired = "stale" if state[0] else "fresh"
                issue = self.conn.execute(
                    "SELECT issue_id,freshness FROM issues WHERE current_conclusion_id=?", (conclusion_id,)
                ).fetchone()
                if issue and issue[1] != desired:
                    self.conn.execute("UPDATE issues SET freshness=? WHERE issue_id=?", (desired, issue[0]))
                    changed_rows.append({"issue_id": issue[0], "from": issue[1], "to": desired})
        if events:
            self.conn.execute("UPDATE context_maintenance_checkpoint SET event_id=?", (events[-1][0],))
        return {"changed": changed_rows, "count": len(changed_rows)}

    def _subscription_candidates(self, subscription_key: str) -> list[str]:
        """Return candidates from the authoritative subscription index.

        Keeping this small query behind a method lets measurement tooling observe
        the real candidate discovery result without changing the maintenance
        transaction or substituting a known set of conclusion IDs.
        """
        return [
            row[0]
            for row in self.conn.execute(
                "SELECT conclusion_id FROM context_subscriptions WHERE subscription_key=?",
                (subscription_key,),
            )
        ]

    def show(self, conclusion_id: str):
        row = self.store.row("SELECT * FROM conclusion_currentness WHERE conclusion_id=?", (conclusion_id,))
        if row is None:
            row = {"conclusion_id": conclusion_id, "maintenance_state": "pending", "needs_update": 1,
                   "local_mismatch": 1, "computed_revision": None,
                   "reason_json": canonical_json([{"code": "currentness_cache_missing"}])}
        pending = self.conn.execute(
            "SELECT EXISTS(SELECT 1 FROM context_input_events WHERE event_id>"
            "(SELECT event_id FROM context_maintenance_checkpoint WHERE singleton=1))"
        ).fetchone()[0]
        if pending:
            row["maintenance_state"] = "pending"
        selected = self.store.row(
            "SELECT s.receipt_id,e.eligible,r.package_id FROM basis_receipt_selections s "
            "JOIN basis_receipts r USING(receipt_id) JOIN basis_receipt_eligibility e USING(receipt_id) "
            "WHERE s.conclusion_id=?", (conclusion_id,)
        )
        row["selected_receipt_id"] = selected["receipt_id"] if selected else ""
        row["selected_receipt"] = selected
        row["workflow_obligations"] = self.manager.context_obligations.list(conclusion_id)
        owner = self.store.row("SELECT issue_id FROM conclusion_revisions WHERE conclusion_id=?", (conclusion_id,))
        row["blocking_obligation_ids"] = self.manager.context_obligations.blocking_for_issue(owner["issue_id"]) if owner else []
        row["publication_blocked"] = bool(row["blocking_obligation_ids"])
        return {**row, "currentness": ("needs_update" if row["needs_update"] else "current")
                if row["maintenance_state"] == "ready" else None,
                "reasons": json.loads(row["reason_json"])}


    def rebuild(self):
        """Explicit recovery only; normal writes never invoke this full rebuild."""
        with self.store.transaction():
            self.conn.execute("UPDATE conclusion_currentness SET maintenance_state='pending'")
            self.conn.execute(
                "INSERT OR IGNORE INTO conclusion_currentness "
                "SELECT conclusion_id,1,1,'pending',0,'[]' FROM conclusion_revisions"
            )
            return self.flush()

    def audit(self, *, limit=100):
        """Read-only full reference, independent of incremental graph maintenance.

        Re-resolve authoritative inputs, compare subscriptions/contributions and
        iterate the least fixed point from the empty set. This diagnoses SQL
        state; it does not prove selector intent or automatically repair it.
        """
        owns_snapshot = not self.conn.in_transaction
        if owns_snapshot:
            self.conn.execute("BEGIN")
        try:
            return self._audit_snapshot(limit=limit)
        finally:
            if owns_snapshot:
                self.conn.rollback()

    def _audit_snapshot(self, *, limit):
        roots: set[str] = set()
        edges: set[tuple[str, str]] = set()
        findings: list[dict[str, Any]] = []
        nodes = self.store.rows("SELECT conclusion_id,issue_id FROM conclusion_revisions")
        for node in nodes:
            conclusion_id = node["conclusion_id"]
            selection = self.store.row(
                "SELECT d.definition_json FROM conclusion_context_selections s "
                "JOIN context_descriptors d USING(descriptor_id) WHERE conclusion_id=?", (conclusion_id,)
            )
            descriptor = json.loads(selection["definition_json"]) if selection else self.default_descriptor(node["issue_id"])
            resolved = self._resolver_for(descriptor).resolve(descriptor, tolerate_errors=True)
            if not resolved.complete:
                findings.append({"code": "context_resolution_failed", "conclusion_id": conclusion_id,
                                 "errors": resolved.errors})
            receipt = self.store.row(
                "SELECT p.semantic_context_json,e.eligible FROM basis_receipt_selections s "
                "JOIN basis_receipts r USING(receipt_id) JOIN context_input_packages p USING(package_id) "
                "LEFT JOIN basis_receipt_eligibility e USING(receipt_id) WHERE s.conclusion_id=?", (conclusion_id,)
            )
            local = bool(resolved.errors) or not receipt or not receipt["eligible"] or (
                not normalized_equal(json.loads(receipt["semantic_context_json"]), resolved.semantic)
            )
            if local:
                roots.add(conclusion_id)
            edges.update((provider, conclusion_id) for provider, _ in resolved.contributions)
            stored_edges = {(row[0], row[1]) for row in self.conn.execute(
                "SELECT provider_conclusion_id,contribution_id FROM currentness_edge_contributions "
                "WHERE consumer_conclusion_id=?", (conclusion_id,)
            )}
            if resolved.complete and stored_edges != resolved.contributions:
                findings.append({"code": "dependency_contribution_mismatch", "conclusion_id": conclusion_id})
            subscriptions = {row[0] for row in self.conn.execute(
                "SELECT subscription_key FROM context_subscriptions WHERE conclusion_id=?", (conclusion_id,)
            )}
            if resolved.complete and subscriptions != set(resolved.subscriptions):
                findings.append({"code": "subscription_mismatch", "conclusion_id": conclusion_id})
            cache = self.store.row("SELECT * FROM conclusion_currentness WHERE conclusion_id=?", (conclusion_id,))
            if cache is None:
                findings.append({"code": "missing_currentness_cache", "conclusion_id": conclusion_id})
            elif bool(cache["local_mismatch"]) != bool(local):
                findings.append({"code": "local_root_mismatch", "conclusion_id": conclusion_id})
        expected: set[str] = set()
        while True:
            following = roots | {consumer for provider, consumer in edges if provider in expected}
            if following == expected:
                break
            expected = following
        for node in nodes:
            conclusion_id = node["conclusion_id"]
            cache = self.store.row("SELECT * FROM conclusion_currentness WHERE conclusion_id=?", (conclusion_id,))
            if cache and (cache["maintenance_state"] != "ready" or bool(cache["needs_update"]) != (conclusion_id in expected)):
                findings.append({"code": "currentness_fixed_point_mismatch", "conclusion_id": conclusion_id})
        return {"ok": not findings, "mode": "read-only-full-reference", "nodes": len(nodes),
                "edges": len(edges), "roots": len(roots), "finding_count": len(findings),
                "findings": findings[:limit]}
