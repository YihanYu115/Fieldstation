from __future__ import annotations

import builtins
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import (
    ConflictError,
    LocatorIdentityInvalidError,
    ManifestPlatformMismatchError,
    NotFoundError,
    PlatformL0IdentityConflictError,
    ValidationError,
)
from .evidence_identity import identity_locator, resolve_intake_identity
from .security import AuthContext, CredentialResolver
from .store import canonical_json, new_id, now

if TYPE_CHECKING:
    from .service import IssueManager


class IntakeService:
    V1_REQUIRED_FIELDS = {
        "packet_version",
        "request_id",
        "target",
        "topic",
        "question",
        "actions",
        "observations",
        "interpretation",
        "alternatives",
        "confidence",
        "next_action",
        "evidence",
    }
    LINK_TYPES = {
        "followup_of",
        "tests_hypothesis_of",
        "challenges",
        "amends",
        "duplicates",
        "grouped_with",
        "split_from",
    }

    def __init__(self, manager: "IssueManager"):
        self.manager = manager
        self.store = manager.store
        self.credentials = CredentialResolver(self.store)

    def _ensure_evidence(
        self,
        conn: Any,
        evidence: dict[str, Any],
        *,
        auth: AuthContext,
        target_scope: str | None,
        timestamp: str,
    ) -> tuple[str, bool]:
        kind = evidence["kind"]
        locator = evidence["locator"]
        manifest = evidence.get("manifest")
        manifest_platform_id = (
            manifest.get("platform_id") if isinstance(manifest, dict) else None
        )
        try:
            identity = resolve_intake_identity(
                platform_id=auth.platform_id,
                kind=kind,
                locator=locator,
                manifest_platform_id=manifest_platform_id,
            )
        except ValueError as exc:
            if auth.platform_id is not None and manifest_platform_id not in {
                None,
                auth.platform_id,
            }:
                raise ManifestPlatformMismatchError(
                    "Manifest platform does not match the authenticated Intake principal",
                    details={
                        "expected_platform": auth.platform_id,
                        "actual_platform": manifest_platform_id,
                    },
                ) from exc
            raise LocatorIdentityInvalidError(str(exc)) from exc
        except TypeError as exc:
            raise LocatorIdentityInvalidError(str(exc)) from exc
        platform_id = identity["source_platform_id"]
        identity_namespace = identity["identity_namespace"]
        identity_key = identity["identity_key"]
        if platform_id and not conn.execute(
            "SELECT 1 FROM platform_sources WHERE platform_id=? AND status='active'",
            (platform_id,),
        ).fetchone():
            raise ValidationError(f"Active platform source not found: {platform_id}")
        existing = conn.execute(
            "SELECT evidence_id,kind,identity_locator,identity_namespace "
            "FROM evidence_refs WHERE identity_key=?",
            (identity_key,),
        ).fetchone()
        if existing:
            if (
                existing["kind"] != kind
                or existing["identity_locator"] != identity["identity_locator"]
                or existing["identity_namespace"] != identity_namespace
            ):
                raise PlatformL0IdentityConflictError(
                    "The derived Intake identity is occupied by an incompatible Evidence",
                    details={
                        "identity_key": identity_key,
                        "conflicting_evidence_id": existing["evidence_id"],
                    },
                )
            return str(existing["evidence_id"]), False

        evidence_id = new_id("ev")
        content_identity = manifest.get("content_identity", {}) if isinstance(manifest, dict) else {}
        digest = (
            content_identity.get("digest") if isinstance(content_identity, dict) else None
        )
        conn.execute(
            "INSERT INTO evidence_refs("
            "evidence_id,kind,locator,normalized_locator,identity_locator,search_locator,"
            "locator_identity_version,identity_key,identity_namespace,"
            "target_scope,short_description,quality_status,content_hash,lifecycle_status,"
            "created_at,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?, 'unknown',?,'active',?,?)",
            (
                evidence_id,
                kind,
                locator,
                identity["normalized_locator"],
                identity["identity_locator"],
                identity["search_locator"],
                identity["locator_identity_version"],
                identity_key,
                identity_namespace,
                target_scope,
                str(evidence.get("description", "intake evidence")),
                digest,
                timestamp,
                auth.actor_id,
            ),
        )
        if identity_namespace == "platform":
            after = {
                "evidence_id": evidence_id,
                "source_platform_id": platform_id,
                "binding_state": "bound",
                "source_key": identity_key,
                "binding_revision": 1,
            }
            conn.execute(
                "INSERT INTO evidence_source_bindings("
                "evidence_id,source_platform_id,binding_state,source_key,binding_revision,"
                "created_at,created_by,reviewed_at,reviewed_by,reason) "
                "VALUES (?,?,'bound',?,1,?,?,NULL,NULL,?)",
                (
                    evidence_id,
                    platform_id,
                    identity_key,
                    timestamp,
                    auth.actor_id,
                    "platform-scoped Intake identity creation",
                ),
            )
            conn.execute(
                "INSERT INTO evidence_source_binding_events("
                "binding_event_id,evidence_id,before_json,after_json,event_type,reason,actor_id,"
                "run_id,created_at,reviewed_changeset_id,review_ids_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,NULL,'[]')",
                (
                    new_id("binding_event"),
                    evidence_id,
                    canonical_json({}),
                    canonical_json(after),
                    "source_declared",
                    "platform-scoped Intake identity creation",
                    auth.actor_id,
                    auth.run_id,
                    timestamp,
                ),
            )
        else:
            conn.execute(
                "INSERT INTO evidence_source_bindings("
                "evidence_id,source_platform_id,binding_state,source_key,binding_revision,"
                "created_at,created_by,reviewed_at,reviewed_by,reason) "
                "VALUES (?,NULL,'legacy_unbound',NULL,1,?,?,NULL,NULL,?)",
                (
                    evidence_id,
                    timestamp,
                    auth.actor_id,
                    "Intake Evidence created without a source Manifest",
                ),
            )
        self.manager.evidence.recalculate(
            evidence_id,
            trigger_object_type="intake_evidence",
            trigger_object_id=evidence_id,
            reason="initial declared Intake Evidence proof",
            auth=auth,
            conn=conn,
            semantic_change_class="initial",
        )
        return evidence_id, True

    def _validate_packet(self, packet: dict[str, Any]) -> None:
        version = packet.get("packet_version")
        if version == 1:
            missing = sorted(self.V1_REQUIRED_FIELDS - set(packet))
            if missing:
                raise ValidationError(f"Intake packet is missing required fields: {missing}")
            if not isinstance(packet["target"], dict) or not packet["target"].get("sample"):
                raise ValidationError("Intake target must contain sample")
            if packet["confidence"] not in {"low", "medium", "high"}:
                raise ValidationError("Intake confidence must be low, medium, or high")
        elif version == 2:
            if not isinstance(packet.get("request_id"), str) or not packet["request_id"].strip():
                raise ValidationError("Intake v2 requires a non-empty request_id")
            hints = packet.get("routing_hints", {})
            if not isinstance(hints, dict):
                raise ValidationError("routing_hints must be an object")
            forbidden = {"issue_id", "exact_issue_id", "canonical_issue_id"} & set(hints)
            if forbidden:
                raise ValidationError("routing_hints cannot assert an exact Issue ID")
            confidence = packet.get("confidence", "unknown")
            if confidence not in {"unknown", "low", "medium", "high"}:
                raise ValidationError("Intake confidence must be unknown, low, medium, or high")
        else:
            raise ValidationError("Only intake packet_version 1 or 2 is supported")
        for field in ("actions", "observations", "interpretation", "alternatives", "evidence"):
            if not isinstance(packet.get(field, []), list):
                raise ValidationError(f"Intake field {field!r} must be a list")
        if version == 2 and not any(
            packet.get(field) for field in ("actions", "observations", "evidence")
        ):
            raise ValidationError(
                "Intake v2 requires at least one action, observation, or evidence"
            )
        for item in packet.get("evidence", []):
            if not isinstance(item, dict) or not item.get("kind") or "locator" not in item:
                raise ValidationError("Each intake evidence item needs kind and locator")
            if not isinstance(item["kind"], str):
                raise ValidationError("Intake evidence kind must be a string")
            try:
                identity_locator(item["locator"])
            except (TypeError, ValueError) as exc:
                raise LocatorIdentityInvalidError(str(exc)) from exc
            if "manifest" in item:
                if version != 2:
                    raise ValidationError("Evidence Manifest is supported only by Intake v2")
                self.manager.evidence.validate_manifest(item["manifest"])

    @staticmethod
    def _v2_view(packet: dict[str, Any]) -> dict[str, Any]:
        if packet.get("packet_version") == 2:
            view = dict(packet)
        else:
            target = packet.get("target", {})
            view = {
                **packet,
                "packet_version": 2,
                "routing_hints": {
                    "sample": target.get("sample"),
                    "components": target.get("qubits", []),
                    "topic": packet.get("topic"),
                },
                "legacy_packet_version": 1,
            }
        defaults: dict[str, Any] = {
            "question": None,
            "actions": [],
            "observations": [],
            "interpretation": [],
            "alternatives": [],
            "confidence": "unknown",
            "next_action": None,
            "evidence": [],
            "proposed_changes": [],
            "related_packets": [],
        }
        for key, value in defaults.items():
            view.setdefault(key, value)
        known = {
            "packet_version",
            "legacy_packet_version",
            "request_id",
            "routing_hints",
            "target",
            "topic",
            "question",
            "actions",
            "observations",
            "interpretation",
            "alternatives",
            "confidence",
            "next_action",
            "evidence",
            "proposed_changes",
            "related_packets",
            "extensions",
        }
        unknown = {key: value for key, value in packet.items() if key not in known}
        if unknown:
            extensions = dict(view.get("extensions", {}))
            extensions.setdefault("unrecognized", {}).update(unknown)
            view["extensions"] = extensions
        return view

    def submit(
        self,
        packet: dict[str, Any],
        *,
        credential: str | Path,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "intake.submit")
        self._validate_packet(packet)
        if any("manifest" in item for item in packet.get("evidence", [])):
            auth.require("evidence.manifest.submit")
        payload = json.loads(canonical_json(packet))
        key = idempotency_key or str(packet["request_id"])
        operation_payload = {"packet": payload, "actor_id": auth.actor_id}
        replay = self.store.idempotency_lookup("intake.submit", key, operation_payload)
        if replay:
            return {**replay, "idempotent_replay": True}
        packet_hash = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        packet_id = new_id("packet")
        task_id = new_id("triage")
        result = {
            "packet_id": packet_id,
            "request_id": packet["request_id"],
            "status": "pending",
            "triage_task_id": task_id,
            "packet_hash": packet_hash,
            "manifest_ids": [],
            "evidence_ids": [],
            "evidence_identities": [],
        }
        timestamp = now()
        with self.store.transaction() as conn:
            existing_request = conn.execute(
                "SELECT packet_id,packet_hash,status FROM intake_packets WHERE request_id=?",
                (packet["request_id"],),
            ).fetchone()
            if existing_request:
                if existing_request["packet_hash"] != packet_hash:
                    raise ConflictError(
                        f"Intake request_id {packet['request_id']!r} was reused with different content"
                    )
                existing_task = conn.execute(
                    "SELECT triage_task_id FROM triage_tasks WHERE packet_id=?",
                    (existing_request["packet_id"],),
                ).fetchone()
                if not existing_task:
                    raise ConflictError(
                        f"Intake packet {existing_request['packet_id']} has no triage task"
                    )
                return {
                    "packet_id": existing_request["packet_id"],
                    "request_id": packet["request_id"],
                    "status": existing_request["status"],
                    "triage_task_id": existing_task["triage_task_id"],
                    "packet_hash": packet_hash,
                    "idempotent_replay": True,
                }
            conn.execute(
                "INSERT INTO intake_packets("
                "packet_id,packet_version,request_id,packet_json,packet_hash,status,submitted_by,"
                "submitted_run_id,created_at,updated_at) VALUES (?,?,?,?,?,'pending',?,?,?,?)",
                (
                    packet_id,
                    packet["packet_version"],
                    packet["request_id"],
                    canonical_json(payload),
                    packet_hash,
                    auth.actor_id,
                    auth.run_id,
                    timestamp,
                    timestamp,
                ),
            )
            for index, evidence in enumerate(packet.get("evidence", [])):
                metadata = {
                    key: value for key, value in evidence.items() if key not in {"kind", "locator"}
                }
                evidence_id, _ = self._ensure_evidence(
                    conn,
                    evidence,
                    auth=auth,
                    target_scope=canonical_json(payload.get("routing_hints", {})),
                    timestamp=timestamp,
                )
                identity_row = conn.execute(
                    "SELECT e.identity_namespace,e.identity_key,e.normalized_locator,"
                    "e.identity_locator,e.search_locator,e.locator_identity_version,"
                    "b.source_platform_id FROM evidence_refs e "
                    "LEFT JOIN evidence_source_bindings b ON b.evidence_id=e.evidence_id "
                    "WHERE e.evidence_id=?",
                    (evidence_id,),
                ).fetchone()
                result["evidence_ids"].append(evidence_id)
                result["evidence_identities"].append(
                    {
                        "evidence_id": evidence_id,
                        "identity_algorithm": "locator-v2-exact",
                        **dict(identity_row),
                    }
                )
                conn.execute(
                    "INSERT INTO intake_evidence(packet_id,ordinal,kind,locator,metadata_json) "
                    "VALUES (?,?,?,?,?)",
                    (
                        packet_id,
                        index,
                        evidence["kind"],
                        evidence["locator"],
                        canonical_json(metadata),
                    ),
                )
                conn.execute(
                    "UPDATE intake_evidence SET evidence_id=? WHERE packet_id=? AND ordinal=?",
                    (evidence_id, packet_id, index),
                )
                if "manifest" in evidence:
                    saved = self.manager.evidence._submit_manifest_auth(
                        evidence_id,
                        evidence["manifest"],
                        auth=auth,
                        source_packet_id=packet_id,
                        supersedes_manifest_id=evidence.get("manifest_supersedes"),
                        idempotency_key=f"intake-manifest:{packet_id}:{index}",
                        conn=conn,
                    )
                    result["manifest_ids"].append(saved["manifest_id"])
            conn.execute(
                "INSERT INTO triage_tasks("
                "triage_task_id,packet_id,state,created_at,updated_at"
                ") VALUES (?,?,'pending',?,?)",
                (task_id, packet_id, timestamp, timestamp),
            )
            self.store.idempotency_record(conn, "intake.submit", key, operation_payload, result)
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="intake.submit",
                object_type="intake_packet",
                object_id=packet_id,
                before_revision=None,
                after_revision=1,
                reason="",
                payload=result,
            )
            self.manager.evidence._activity(
                conn,
                "intake.submitted",
                "intake_packet",
                packet_id,
                [],
                {
                    "packet_id": packet_id,
                    "request_id": packet["request_id"],
                    "manifest_ids": result["manifest_ids"],
                },
                platform_id=auth.platform_id,
            )
            for relation in packet.get("related_packets", []):
                if not isinstance(relation, dict):
                    raise ValidationError("related_packets entries must be objects")
                target = relation.get("packet_id")
                link_type = relation.get("type")
                if link_type not in self.LINK_TYPES or not target:
                    raise ValidationError(
                        "related_packets entries need packet_id and a supported type"
                    )
                if not conn.execute(
                    "SELECT 1 FROM intake_packets WHERE packet_id=?", (target,)
                ).fetchone():
                    raise ValidationError(f"Related packet does not exist: {target}")
                conn.execute(
                    "INSERT INTO intake_packet_links (link_id,source_packet_id,target_packet_id,link_type,proposed_by,proposed_run_id,rationale,created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        new_id("packet_link"),
                        packet_id,
                        target,
                        link_type,
                        auth.actor_id,
                        auth.run_id,
                        str(relation.get("rationale", "submitted with packet")),
                        now(),
                    ),
                )
        return result

    def list(self, status: str | None = None, *, limit: int = 100) -> list[dict[str, Any]]:
        if status:
            return self.store.rows(
                "SELECT p.packet_id,p.request_id,p.status,p.created_at,p.updated_at,"
                "t.triage_task_id,t.state AS triage_state,t.claimed_by,t.lease_until "
                "FROM intake_packets p JOIN triage_tasks t ON t.packet_id=p.packet_id "
                "WHERE p.status=? ORDER BY p.created_at LIMIT ?",
                (status, limit),
            )
        return self.store.rows(
            "SELECT p.packet_id,p.request_id,p.status,p.created_at,p.updated_at,"
            "t.triage_task_id,t.state AS triage_state,t.claimed_by,t.lease_until "
            "FROM intake_packets p JOIN triage_tasks t ON t.packet_id=p.packet_id "
            "ORDER BY p.created_at LIMIT ?",
            (limit,),
        )

    def show(self, packet_id: str) -> dict[str, Any]:
        packet = self.store.row("SELECT * FROM intake_packets WHERE packet_id=?", (packet_id,))
        if not packet:
            raise NotFoundError(f"Intake packet not found: {packet_id}")
        packet["packet"] = json.loads(packet.pop("packet_json"))
        packet["packet_v2"] = self._v2_view(packet["packet"])
        packet["evidence"] = [
            {**item, "metadata": json.loads(item.pop("metadata_json"))}
            for item in self.store.rows(
                "SELECT * FROM intake_evidence WHERE packet_id=? ORDER BY ordinal", (packet_id,)
            )
        ]
        packet["triage"] = self.store.row(
            "SELECT * FROM triage_tasks WHERE packet_id=?", (packet_id,)
        )
        if packet["triage"]:
            packet["triage_events"] = self.store.rows(
                "SELECT * FROM triage_events WHERE triage_task_id=? ORDER BY created_at",
                (packet["triage"]["triage_task_id"],),
            )
        packet["links"] = self.store.rows(
            "SELECT * FROM intake_packet_links WHERE source_packet_id=? OR target_packet_id=? "
            "ORDER BY created_at,link_id",
            (packet_id, packet_id),
        )
        packet["questions"] = self.store.rows(
            "SELECT * FROM intake_questions WHERE packet_id=? ORDER BY created_at", (packet_id,)
        )
        packet["answers"] = self.store.rows(
            "SELECT * FROM intake_answers WHERE packet_id=? ORDER BY created_at", (packet_id,)
        )
        return packet

    def _task(self, packet_id: str) -> dict[str, Any]:
        task = self.store.row("SELECT * FROM triage_tasks WHERE packet_id=?", (packet_id,))
        if not task:
            raise NotFoundError(f"Triage task not found for packet {packet_id}")
        return task

    @staticmethod
    def _lease(minutes: int) -> str:
        return (datetime.now().astimezone() + timedelta(minutes=minutes)).isoformat(
            timespec="seconds"
        )

    def claim(
        self, packet_id: str, *, credential: str | Path, lease_minutes: int = 15
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "triage.manage")
        task = self._task(packet_id)
        timestamp = now()
        if task["state"] == "claimed" and task["lease_until"] and task["lease_until"] > timestamp:
            if task["claimed_run_id"] != auth.run_id:
                raise ConflictError(
                    f"Packet {packet_id} is leased by {task['claimed_by']} until {task['lease_until']}"
                )
        if task["state"] not in {"pending", "retry", "claimed", "needs_input"}:
            raise ConflictError(f"Triage task is not claimable from state {task['state']!r}")
        lease_until = self._lease(max(1, lease_minutes))
        with self.store.transaction() as conn:
            locked_value = conn.execute(
                "SELECT * FROM triage_tasks WHERE packet_id=?", (packet_id,)
            ).fetchone()
            if not locked_value:
                raise NotFoundError(f"Triage task not found for packet {packet_id}")
            locked = dict(locked_value)
            current_time = now()
            if (
                locked["state"] == "claimed"
                and locked["lease_until"]
                and locked["lease_until"] > current_time
                and locked["claimed_run_id"] != auth.run_id
            ):
                raise ConflictError(
                    f"Packet {packet_id} is leased by {locked['claimed_by']} until {locked['lease_until']}"
                )
            if locked["state"] not in {"pending", "retry", "claimed", "needs_input"}:
                raise ConflictError(f"Triage task is not claimable from state {locked['state']!r}")
            conn.execute(
                "UPDATE triage_tasks SET state='claimed',claimed_by=?,claimed_run_id=?,lease_until=?,"
                "attempt_count=attempt_count+1,updated_at=? WHERE triage_task_id=?",
                (auth.actor_id, auth.run_id, lease_until, timestamp, locked["triage_task_id"]),
            )
            conn.execute(
                "UPDATE intake_packets SET status='claimed',updated_at=? WHERE packet_id=?",
                (timestamp, packet_id),
            )
            self._event(
                conn, locked["triage_task_id"], "claimed", auth, {"lease_until": lease_until}
            )
        return {
            "packet_id": packet_id,
            "triage_task_id": locked["triage_task_id"],
            "state": "claimed",
            "claimed_by": auth.actor_id,
            "claimed_run_id": auth.run_id,
            "lease_until": lease_until,
        }

    def heartbeat(
        self, packet_id: str, *, credential: str | Path, lease_minutes: int = 15
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "triage.manage")
        task = self._owned_task(packet_id, auth)
        lease_until = self._lease(max(1, lease_minutes))
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE triage_tasks SET lease_until=?,updated_at=? WHERE triage_task_id=?",
                (lease_until, now(), task["triage_task_id"]),
            )
            self._event(
                conn, task["triage_task_id"], "heartbeat", auth, {"lease_until": lease_until}
            )
        return {"packet_id": packet_id, "lease_until": lease_until}

    def release(self, packet_id: str, *, credential: str | Path) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "triage.manage")
        task = self._owned_task(packet_id, auth)
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE triage_tasks SET state='pending',claimed_by=NULL,claimed_run_id=NULL,"
                "lease_until=NULL,updated_at=? WHERE triage_task_id=?",
                (now(), task["triage_task_id"]),
            )
            conn.execute(
                "UPDATE intake_packets SET status='pending',updated_at=? WHERE packet_id=?",
                (now(), packet_id),
            )
            self._event(conn, task["triage_task_id"], "released", auth, {})
        return {"packet_id": packet_id, "state": "pending"}

    def _owned_task(self, packet_id: str, auth: AuthContext) -> dict[str, Any]:
        task = self._task(packet_id)
        if task["state"] != "claimed" or task["claimed_run_id"] != auth.run_id:
            raise ConflictError("Triage task must be claimed by this agent run")
        if task["lease_until"] and task["lease_until"] < now():
            raise ConflictError("Triage lease expired; claim the packet again")
        return task

    def attach(self, packet_id: str, issue_id: str, *, credential: str | Path) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "triage.manage")
        task = self._owned_task(packet_id, auth)
        from .changeset_state import StateView
        from .intake_planner import plan_attach

        decision = plan_attach(
            StateView(self.manager),
            {"op": "attach_packet", "packet_id": packet_id, "issue_id": issue_id, "_direct": True},
        )
        issue = decision["issue"]
        packet_row = self.store.row(
            "SELECT packet_json,routing_state,routing_snapshot_json,routing_policy_version "
            "FROM intake_packets WHERE packet_id=?",
            (packet_id,),
        )
        if not packet_row:
            raise NotFoundError(f"Intake packet not found: {packet_id}")
        packet = json.loads(packet_row["packet_json"])
        if packet_row.get("routing_state") == "unique":
            view = self._v2_view(packet)
            hints = view.get("routing_hints", {})
            components = hints.get("components", [])
            if not isinstance(components, list):
                components = [components]
            current_routing = self.manager.resolve(
                sample=str(hints.get("sample") or ""),
                qubit=str(components[0]) if len(components) == 1 else None,
                topic=str(hints.get("topic") or ""),
            )
            if (
                current_routing.get("status") != "unique"
                or current_routing.get("match", {}).get("issue_id") != issue_id
            ):
                raise ConflictError("Routing changed before attach; resolve and triage the packet again")
        evidence_ids: list[str] = []
        new_work_revision = issue["working_revision"] + 1
        entry_id = new_id("work")
        body = self._packet_work_body(packet)
        with self.store.transaction() as conn:
            evidence_rows = conn.execute(
                "SELECT * FROM intake_evidence WHERE packet_id=? ORDER BY ordinal", (packet_id,)
            ).fetchall()
            for evidence in evidence_rows:
                evidence_id = evidence["evidence_id"]
                if not evidence_id:
                    metadata = json.loads(evidence["metadata_json"])
                    evidence_id, _ = self._ensure_evidence(
                        conn,
                        {
                            "kind": evidence["kind"],
                            "locator": evidence["locator"],
                            "description": metadata.get("description", "intake evidence"),
                        },
                        auth=auth,
                        target_scope=canonical_json(packet.get("target", {})),
                        timestamp=now(),
                    )
                conn.execute(
                    "INSERT OR IGNORE INTO issue_evidence VALUES (?,?,?,?)",
                    (issue_id, evidence_id, now(), auth.actor_id),
                )
                self.manager.original_access_bindings.admit_evidence(issue_id, evidence_id)
                conn.execute(
                    "UPDATE intake_evidence SET evidence_id=? WHERE packet_id=? AND ordinal=?",
                    (evidence_id, packet_id, evidence["ordinal"]),
                )
                evidence_ids.append(evidence_id)
            conn.execute(
                "INSERT INTO working_entries("
                "entry_id,issue_id,entry_type,body,evidence_refs_json,created_at,created_by,"
                "policy_version,source_packet_id) VALUES (?,?, 'observation',?,?,?,?,?,?)",
                (
                    entry_id,
                    issue_id,
                    body,
                    canonical_json(evidence_ids),
                    now(),
                    auth.actor_id,
                    self.manager.policy.version,
                    packet_id,
                ),
            )
            conn.execute(
                "UPDATE issues SET working_revision=?,updated_at=? WHERE issue_id=?",
                (new_work_revision, now(), issue_id),
            )
            conn.execute(
                "UPDATE intake_packets SET status='attached',attached_issue_id=?,updated_at=? "
                "WHERE packet_id=?",
                (issue_id, now(), packet_id),
            )
            conn.execute(
                "UPDATE triage_tasks SET state='proposed',updated_at=? WHERE triage_task_id=?",
                (now(), task["triage_task_id"]),
            )
            self._event(
                conn,
                task["triage_task_id"],
                "attached",
                auth,
                {"issue_id": issue_id, "entry_id": entry_id, "evidence_ids": evidence_ids},
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="triage.attach",
                object_type="intake_packet",
                object_id=packet_id,
                before_revision=None,
                after_revision=new_work_revision,
                reason="",
                payload={"issue_id": issue_id, "entry_id": entry_id, "evidence_ids": evidence_ids},
            )
        return {
            "packet_id": packet_id,
            "issue_id": issue_id,
            "entry_id": entry_id,
            "evidence_ids": evidence_ids,
            "state": "proposed",
        }

    @staticmethod
    def _packet_work_body(packet: dict[str, Any]) -> str:
        parts = [f"Question: {packet.get('question') or 'unspecified'}"]
        for label, field in (
            ("Actions", "actions"),
            ("Observations", "observations"),
            ("Interpretation", "interpretation"),
            ("Alternatives", "alternatives"),
        ):
            values = packet.get(field, [])
            parts.append(f"{label}: " + ("; ".join(str(value) for value in values) or "none"))
        parts.extend(
            [
                f"Confidence: {packet.get('confidence', 'unknown')}",
                f"Next action: {packet.get('next_action') or 'unspecified'}",
            ]
        )
        return "\n".join(parts)

    def create_episode(
        self,
        packet_id: str,
        *,
        parent_issue_id: str,
        issue_id: str,
        title: str | None,
        credential: str | Path,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "triage.manage")
        self._owned_task(packet_id, auth)
        packet = self.show(packet_id)["packet_v2"]
        hints = packet.get("routing_hints", {})
        components = hints.get("components", [])
        scope = {"sample": hints.get("sample")}
        if isinstance(components, list) and len(components) == 1:
            scope["qubit"] = components[0]
        with self.store.transaction():
            self.manager.create_issue(
                issue_id,
                "episode",
                title or packet.get("question") or f"Episode from {packet_id}",
                parent_issue_id=parent_issue_id,
                scope=scope,
                topic=hints.get("topic"),
                actor=auth.actor_id,
            )
            relation = self.manager.add_relation(
                parent_issue_id,
                issue_id,
                "rolls_up_from",
                actor=auth.actor_id,
                reason=f"created from intake packet {packet_id}",
            )
            attached = self.attach(packet_id, issue_id, credential=credential)
        return {"created_issue_id": issue_id, "relation_id": relation["relation_id"], **attached}

    def needs_input(
        self, packet_id: str, question: str, *, credential: str | Path
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "triage.manage")
        task = self._owned_task(packet_id, auth)
        if not question.strip():
            raise ValidationError("needs-input question cannot be empty")
        with self.store.transaction() as conn:
            question_id = new_id("question")
            conn.execute(
                "INSERT INTO intake_questions VALUES (?,?,?,'open',?,?,?,NULL)",
                (question_id, packet_id, question, auth.actor_id, auth.run_id, now()),
            )
            conn.execute(
                "UPDATE triage_tasks SET state='needs_input',question=?,lease_until=NULL,updated_at=? "
                "WHERE triage_task_id=?",
                (question, now(), task["triage_task_id"]),
            )
            conn.execute(
                "UPDATE intake_packets SET status='needs_input',updated_at=? WHERE packet_id=?",
                (now(), packet_id),
            )
            self._event(conn, task["triage_task_id"], "needs_input", auth, {"question": question})
        return {
            "packet_id": packet_id,
            "state": "needs_input",
            "question": question,
            "question_id": question_id,
        }

    def disposition(
        self,
        packet_id: str,
        disposition: str,
        *,
        reason: str,
        credential: str | Path,
        issue_id: str | None = None,
        conclusion_id: str | None = None,
        proposal_id: str | None = None,
        evidence_request_id: str | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "triage.disposition")
        task = self._task(packet_id)
        if task["claimed_run_id"] != auth.run_id or task["state"] not in {
            "claimed",
            "proposed",
            "applied",
            "needs_input",
            "retry",
        }:
            raise ConflictError("Only the owning triage run can disposition this packet")
        allowed = {
            "no_impact",
            "supports_current",
            "challenges_current",
            "amends_previous",
            "proposal_created",
            "duplicate",
            "rejected",
            "needs_input",
            "evidence_requested",
        }
        if disposition not in allowed:
            raise ValidationError(f"Unknown triage disposition: {disposition}")
        if not reason.strip():
            raise ValidationError("Triage disposition requires a reason")
        if issue_id:
            self.manager._issue(issue_id, active=False)
        if conclusion_id:
            target = self.store.row("SELECT issue_id FROM conclusion_revisions WHERE conclusion_id=?", (conclusion_id,))
            if not target:
                raise NotFoundError(f"Conclusion not found: {conclusion_id}")
            if issue_id and target["issue_id"] != issue_id:
                raise ValidationError("Triage disposition Conclusion belongs to another Issue")
            issue_id = target["issue_id"]
        if proposal_id:
            proposal = self.store.row("SELECT issue_id FROM proposals WHERE proposal_id=?", (proposal_id,))
            if not proposal:
                raise NotFoundError(f"Proposal not found: {proposal_id}")
            if issue_id and proposal["issue_id"] != issue_id:
                raise ValidationError("Triage disposition Proposal belongs to another Issue")
        if evidence_request_id:
            request = self.store.row(
                "SELECT evidence_request_id FROM evidence_requests WHERE evidence_request_id=?",
                (evidence_request_id,),
            )
            if not request:
                raise NotFoundError(f"Evidence Request not found: {evidence_request_id}")
        if disposition == "proposal_created" and not proposal_id:
            raise ValidationError("proposal_created disposition requires proposal_id")
        if disposition == "evidence_requested" and not evidence_request_id:
            raise ValidationError("evidence_requested disposition requires evidence_request_id")
        link_types = self.active_link_types(packet_id)
        if "challenges" in link_types and disposition != "challenges_current":
            raise ValidationError("A challenges packet must use challenges_current disposition")
        if "amends" in link_types and disposition != "amends_previous":
            raise ValidationError("An amends packet must use amends_previous disposition")
        existing = self.store.row(
            "SELECT * FROM triage_dispositions WHERE packet_id=?", (packet_id,)
        )
        result = {
            "packet_id": packet_id,
            "disposition": disposition,
            "issue_id": issue_id,
            "conclusion_id": conclusion_id,
            "proposal_id": proposal_id,
            "evidence_request_id": evidence_request_id,
            "reason": reason.strip(),
        }
        if existing:
            comparable = {key: existing.get(key) for key in result}
            if comparable == result:
                return {**result, "existing": True}
            raise ConflictError("Triage disposition is append-only and already exists")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO triage_dispositions VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    packet_id,
                    disposition,
                    issue_id,
                    conclusion_id,
                    proposal_id,
                    evidence_request_id,
                    reason.strip(),
                    auth.actor_id,
                    auth.run_id,
                    now(),
                ),
            )
            if disposition in {"challenges_current", "amends_previous"} and issue_id:
                issue = self.manager._issue(issue_id, active=False)
                self.manager._enqueue_refresh(
                    conn,
                    issue_id=issue_id,
                    trigger_issue_id=issue_id,
                    from_revision=issue["conclusion_revision"],
                    to_revision=issue["conclusion_revision"],
                    reason_type="manual",
                    priority=90 if disposition == "challenges_current" else 70,
                )
                if not hasattr(self.manager, "context_maintenance"):
                    conn.execute(
                        "UPDATE issues SET freshness='impact_review',updated_at=? WHERE issue_id=? "
                        "AND freshness='fresh'", (now(), issue_id),
                    )
            self._event(conn, task["triage_task_id"], "disposition", auth, result)
            self.manager.evidence._activity(
                conn,
                "triage.disposition.recorded",
                "intake_packet",
                packet_id,
                [issue_id] if issue_id else [],
                result,
                platform_id=auth.platform_id,
            )
        return result

    def complete(self, packet_id: str, *, credential: str | Path) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "triage.manage")
        task = self._task(packet_id)
        if task["claimed_run_id"] != auth.run_id or task["state"] not in {
            "claimed",
            "proposed",
            "applied",
        }:
            raise ConflictError("Only the owning triage run can complete this packet")
        disposition = self.store.row(
            "SELECT * FROM triage_dispositions WHERE packet_id=?", (packet_id,)
        )
        if not disposition:
            raise ValidationError("Triage cannot complete without a semantic disposition")
        if disposition["disposition"] in {"needs_input", "evidence_requested"}:
            raise ConflictError(
                f"Triage remains open while disposition is {disposition['disposition']!r}"
            )
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE triage_tasks SET state='completed',lease_until=NULL,updated_at=? "
                "WHERE triage_task_id=?",
                (now(), task["triage_task_id"]),
            )
            conn.execute(
                "UPDATE intake_packets SET status='completed',updated_at=? WHERE packet_id=?",
                (now(), packet_id),
            )
            self._event(conn, task["triage_task_id"], "completed", auth, {})
        return {"packet_id": packet_id, "state": "completed"}

    def claim_batch(
        self,
        *,
        credential: str | Path,
        sample: str | None = None,
        component: str | None = None,
        topic: str | None = None,
        limit: int = 20,
        lease_minutes: int = 15,
    ) -> dict[str, Any]:
        self.credentials.resolve(credential, "triage.manage")
        claimed: list[dict[str, Any]] = []
        for row in self.list("pending", limit=max(1, min(limit * 5, 500))):
            packet = self.show(row["packet_id"])["packet_v2"]
            hints = packet.get("routing_hints", {})
            components = hints.get("components", [])
            if sample and self.manager._normalize_term(
                str(hints.get("sample", ""))
            ) != self.manager._normalize_term(sample):
                continue
            if component and self.manager._normalize_term(component) not in {
                self.manager._normalize_term(str(item)) for item in components
            }:
                continue
            if topic and self.manager._normalize_term(
                str(hints.get("topic", ""))
            ) != self.manager._normalize_term(topic):
                continue
            claimed.append(
                self.claim(row["packet_id"], credential=credential, lease_minutes=lease_minutes)
            )
            if len(claimed) >= max(1, limit):
                break
        return {"claimed": claimed, "count": len(claimed)}

    def active_link_types(self, packet_id: str, *, state_view=None) -> set[str]:
        rows = (state_view.context_rows("intake_packet_links", "source_packet_id", packet_id)
                if state_view is not None else self.store.rows(
                    "SELECT * FROM intake_packet_links WHERE source_packet_id=?", (packet_id,)))
        return {row["link_type"] for row in rows if row.get("active", 1)}

    def link(
        self,
        source_packet_id: str,
        target_packet_id: str,
        link_type: str,
        *,
        rationale: str,
        credential: str | Path,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "triage.manage")
        self.show(source_packet_id)
        self.show(target_packet_id)
        if source_packet_id == target_packet_id:
            raise ValidationError("A packet cannot link to itself")
        if link_type not in self.LINK_TYPES:
            raise ValidationError(f"Unknown packet link type: {link_type}")
        if not rationale.strip():
            raise ValidationError("Packet link rationale is required")
        link_id = new_id("packet_link")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO intake_packet_links (link_id,source_packet_id,target_packet_id,link_type,proposed_by,proposed_run_id,rationale,created_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    link_id,
                    source_packet_id,
                    target_packet_id,
                    link_type,
                    auth.actor_id,
                    auth.run_id,
                    rationale,
                    now(),
                ),
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="intake.link",
                object_type="intake_packet",
                object_id=source_packet_id,
                before_revision=None,
                after_revision=None,
                reason=rationale,
                payload={"target_packet_id": target_packet_id, "link_type": link_type},
            )
        return {
            "link_id": link_id,
            "source_packet_id": source_packet_id,
            "target_packet_id": target_packet_id,
            "link_type": link_type,
        }

    def group(
        self,
        packet_ids: builtins.list[str],
        *,
        episode_issue_id: str | None = None,
        credential: str | Path,
        group_kind: str = "group",
        plan: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "triage.manage")
        unique_ids: builtins.list[str] = builtins.list(dict.fromkeys(packet_ids))
        if not unique_ids:
            raise ValidationError("A packet group cannot be empty")
        if group_kind not in {"group", "split", "merge"}:
            raise ValidationError("group_kind must be group, split, or merge")
        if episode_issue_id:
            self.manager._issue(episode_issue_id)
        for packet_id in unique_ids:
            self.show(packet_id)
        group_id = new_id("intake_group")
        projections = (plan or {}).get("projections", []) if group_kind == "split" else []
        if group_kind == "split" and not projections:
            raise ValidationError("A split plan requires a non-empty projections list")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO intake_groups VALUES (?,?,?,?,?,?,?)",
                (
                    group_id,
                    group_kind,
                    episode_issue_id,
                    canonical_json(plan or {}),
                    auth.actor_id,
                    auth.run_id,
                    now(),
                ),
            )
            for packet_id in unique_ids:
                if projections:
                    for index, projection in enumerate(projections):
                        conn.execute(
                            "INSERT INTO intake_group_members VALUES (?,?,?)",
                            (group_id, packet_id, str(projection.get("key", index))),
                        )
                else:
                    conn.execute(
                        "INSERT INTO intake_group_members VALUES (?,?,'')", (group_id, packet_id)
                    )
            if len(unique_ids) > 1:
                anchor = unique_ids[0]
                for packet_id in unique_ids[1:]:
                    conn.execute(
                        "INSERT OR IGNORE INTO intake_packet_links (link_id,source_packet_id,target_packet_id,link_type,proposed_by,proposed_run_id,rationale,created_at) VALUES (?,?,?,?,?,?,?,?)",
                        (
                            new_id("packet_link"),
                            packet_id,
                            anchor,
                            "grouped_with",
                            auth.actor_id,
                            auth.run_id,
                            f"member of {group_id}",
                            now(),
                        ),
                    )
        return {
            "group_id": group_id,
            "group_kind": group_kind,
            "packet_ids": unique_ids,
            "episode_issue_id": episode_issue_id,
            "plan": plan or {},
        }

    def split(
        self,
        packet_id: str,
        plan: dict[str, Any],
        *,
        credential: str | Path,
    ) -> dict[str, Any]:
        return self.group([packet_id], credential=credential, group_kind="split", plan=plan)

    def merge(
        self,
        packet_ids: builtins.list[str],
        *,
        primary_packet_id: str,
        credential: str | Path,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "triage.manage")
        if primary_packet_id not in packet_ids:
            raise ValidationError("primary_packet_id must be one of the merged packets")
        result = self.group(packet_ids, credential=credential, group_kind="merge")
        with self.store.transaction() as conn:
            for packet_id in dict.fromkeys(packet_ids):
                if packet_id == primary_packet_id:
                    continue
                conn.execute(
                    "UPDATE intake_packets SET status='merged',merged_into_packet_id=?,updated_at=? "
                    "WHERE packet_id=?",
                    (primary_packet_id, now(), packet_id),
                )
                conn.execute(
                    "UPDATE triage_tasks SET state='completed',updated_at=? WHERE packet_id=?",
                    (now(), packet_id),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO intake_packet_links (link_id,source_packet_id,target_packet_id,link_type,proposed_by,proposed_run_id,rationale,created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        new_id("packet_link"),
                        packet_id,
                        primary_packet_id,
                        "duplicates",
                        auth.actor_id,
                        auth.run_id,
                        f"merged in {result['group_id']}",
                        now(),
                    ),
                )
        return {**result, "primary_packet_id": primary_packet_id}

    def reject(self, packet_id: str, *, reason: str, credential: str | Path) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "triage.manage")
        if not reason.strip():
            raise ValidationError("Reject reason is required")
        task = self._task(packet_id)
        if task["state"] == "claimed":
            self._owned_task(packet_id, auth)
        elif task["state"] not in {"pending", "retry", "needs_input"}:
            raise ConflictError(f"Packet cannot be rejected from triage state {task['state']}")
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE triage_tasks SET state='rejected',last_error=?,lease_until=NULL,updated_at=? "
                "WHERE triage_task_id=?",
                (reason, now(), task["triage_task_id"]),
            )
            conn.execute(
                "UPDATE intake_packets SET status='rejected',last_triage_error=?,updated_at=? "
                "WHERE packet_id=?",
                (reason, now(), packet_id),
            )
            self._event(conn, task["triage_task_id"], "rejected", auth, {"reason": reason})
        return {"packet_id": packet_id, "state": "rejected", "reason": reason}

    def answer(
        self, packet_id: str, answer: dict[str, Any], *, credential: str | Path
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "intake.submit")
        question = self.store.row(
            "SELECT * FROM intake_questions WHERE packet_id=? AND state='open' "
            "ORDER BY created_at DESC LIMIT 1",
            (packet_id,),
        )
        if not question:
            raise ConflictError(f"Packet {packet_id} has no open intake question")
        answer_id = new_id("answer")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO intake_answers VALUES (?,?,?,?,?,?,?)",
                (
                    answer_id,
                    question["question_id"],
                    packet_id,
                    canonical_json(answer),
                    auth.actor_id,
                    auth.run_id,
                    now(),
                ),
            )
            conn.execute(
                "UPDATE intake_questions SET state='answered',answered_at=? WHERE question_id=?",
                (now(), question["question_id"]),
            )
            conn.execute(
                "UPDATE intake_packets SET status='pending',updated_at=? WHERE packet_id=?",
                (now(), packet_id),
            )
            conn.execute(
                "UPDATE triage_tasks SET state='retry',question=NULL,claimed_by=NULL,claimed_run_id=NULL,"
                "lease_until=NULL,updated_at=? WHERE packet_id=?",
                (now(), packet_id),
            )
        return {
            "packet_id": packet_id,
            "question_id": question["question_id"],
            "answer_id": answer_id,
            "state": "answered",
        }

    def complete_batch(
        self, packet_ids: builtins.list[str], *, credential: str | Path
    ) -> dict[str, Any]:
        completed = [self.complete(packet_id, credential=credential) for packet_id in packet_ids]
        return {"completed": completed, "count": len(completed)}

    @staticmethod
    def _event(
        conn: Any,
        task_id: str,
        event_type: str,
        auth: AuthContext,
        payload: dict[str, Any],
    ) -> None:
        conn.execute(
            "INSERT INTO triage_events VALUES (?,?,?,?,?,?,?)",
            (
                new_id("triage_event"),
                task_id,
                event_type,
                auth.actor_id,
                auth.run_id,
                canonical_json(payload),
                now(),
            ),
        )
