from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import (
    AnalysisPlatformMismatchError,
    ConflictError,
    EvidenceBindingConflictError,
    EvidencePlatformMismatchError,
    LeaseExpiredError,
    ManifestRevisionStaleError,
    NotFoundError,
    PermissionError,
    PrivateResourceForbiddenError,
    ValidationError,
)
from .security import AuthContext, CredentialResolver
from .store import canonical_json, new_id, now

if TYPE_CHECKING:
    from .service import IssueManager


REQUEST_TYPES = {"metadata", "existence", "preview", "statistics", "reanalysis"}
OPEN_STATES = {"pending", "claimed", "running"}
REQUEST_ROLES = {
    "source_verification",
    "independent_verification",
    "conflict_resolution",
}
TYPE_CAPABILITY = {
    "metadata": "metadata",
    "existence": "existence",
    "preview": "preview",
    "statistics": "statistics",
    "reanalysis": "reanalysis",
}


def _loads(value: str | None, fallback: Any) -> Any:
    return json.loads(value) if value is not None else fallback


class EvidenceRequestService:
    """Platform-scoped, lease-safe asynchronous evidence request queue."""

    def __init__(self, manager: "IssueManager"):
        self.manager = manager
        self.store = manager.store
        self.credentials = CredentialResolver(self.store)

    @staticmethod
    def _deadline(value: str | None) -> str | None:
        if value is None:
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValidationError("deadline_at must be an ISO-8601 timestamp") from exc
        if parsed.tzinfo is None:
            raise ValidationError("deadline_at must include a timezone")
        return parsed.isoformat(timespec="seconds")

    @staticmethod
    def _reject_executable_payload(value: Any, path: str = "method_constraints") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = str(key).lower().replace("-", "_")
                if normalized in {"code", "source_code", "shell", "command", "executable"}:
                    raise ValidationError(
                        f"Evidence Requests cannot carry executable payloads ({path}.{key})"
                    )
                EvidenceRequestService._reject_executable_payload(item, f"{path}.{key}")
        elif isinstance(value, list):
            if len(value) > 4096:
                raise ValidationError(f"{path} contains an oversized array")
            for index, item in enumerate(value):
                EvidenceRequestService._reject_executable_payload(item, f"{path}[{index}]")
        elif isinstance(value, str) and len(value.encode("utf-8")) > 64 * 1024:
            raise ValidationError(f"{path} contains an oversized string")

    def create(
        self,
        *,
        evidence_id: str,
        platform_id: str,
        request_type: str,
        question: str,
        requested_outputs: list[Any],
        priority: int,
        credential: str | Path,
        issue_id: str | None = None,
        proposal_id: str | None = None,
        source_packet_id: str | None = None,
        method_constraints: dict[str, Any] | None = None,
        deadline_at: str | None = None,
        request_role: str = "source_verification",
        requested_manifest_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "evidence.request.create")
        if request_type not in REQUEST_TYPES:
            raise ValidationError(f"Unknown Evidence Request type: {request_type}")
        if request_role not in REQUEST_ROLES:
            raise ValidationError(f"Unknown Evidence Request role: {request_role}")
        if request_role == "conflict_resolution":
            auth.require("evidence.resolve")
        if not question.strip():
            raise ValidationError("Evidence Request question cannot be empty")
        if not isinstance(requested_outputs, list) or not requested_outputs:
            raise ValidationError("Evidence Request requested_outputs must be a non-empty list")
        if not 0 <= int(priority) <= 100:
            raise ValidationError("Evidence Request priority must be between 0 and 100")
        constraints = {} if method_constraints is None else method_constraints
        if not isinstance(constraints, dict):
            raise ValidationError("method_constraints must be an object")
        self._reject_executable_payload(constraints)
        platform = self.store.row(
            "SELECT * FROM platform_sources WHERE platform_id=? AND status='active'", (platform_id,)
        )
        if not platform:
            raise ValidationError(f"Active platform source not found: {platform_id}")
        platform_capabilities = set(_loads(platform["capabilities_json"], []))
        if TYPE_CAPABILITY[request_type] not in platform_capabilities:
            raise ValidationError(
                f"Platform {platform_id!r} does not advertise {TYPE_CAPABILITY[request_type]!r}"
            )
        evidence = self.store.row(
            "SELECT lifecycle_status,current_manifest_id FROM evidence_refs WHERE evidence_id=?",
            (evidence_id,),
        )
        if not evidence or evidence["lifecycle_status"] != "active":
            raise NotFoundError(f"Active evidence not found: {evidence_id}")
        binding = self.store.row(
            "SELECT * FROM evidence_source_bindings WHERE evidence_id=?", (evidence_id,)
        )
        if binding and binding["binding_state"] == "binding_conflict":
            raise EvidenceBindingConflictError(
                "Evidence source binding is in conflict", details={"evidence_id": evidence_id}
            )
        if (
            request_role == "source_verification"
            and binding
            and binding["binding_state"] in {"bound", "inferred"}
            and binding["source_platform_id"] != platform_id
        ):
            raise EvidencePlatformMismatchError(
                "Source verification request must target the Evidence source platform",
                details={
                    "evidence_id": evidence_id,
                    "expected_platform": binding["source_platform_id"],
                    "actual_platform": platform_id,
                },
            )
        current_manifest_id = evidence.get("current_manifest_id")
        pinned_manifest_id = requested_manifest_id or current_manifest_id
        if requested_manifest_id and requested_manifest_id != current_manifest_id:
            raise ManifestRevisionStaleError(
                "Evidence Request must pin the current Manifest",
                details={
                    "evidence_id": evidence_id,
                    "current_manifest_id": current_manifest_id,
                    "requested_manifest_id": requested_manifest_id,
                },
            )
        pinned_manifest = (
            self.store.row(
                "SELECT manifest_hash FROM evidence_manifests WHERE manifest_id=?",
                (pinned_manifest_id,),
            )
            if pinned_manifest_id
            else None
        )
        pinned_manifest_hash = pinned_manifest["manifest_hash"] if pinned_manifest else None
        if issue_id:
            self.manager._issue(issue_id)
        if proposal_id and not self.store.row(
            "SELECT 1 FROM proposals WHERE proposal_id=?", (proposal_id,)
        ):
            raise NotFoundError(f"Proposal not found: {proposal_id}")
        if source_packet_id and not self.store.row(
            "SELECT 1 FROM intake_packets WHERE packet_id=?", (source_packet_id,)
        ):
            raise NotFoundError(f"Intake packet not found: {source_packet_id}")
        deadline = self._deadline(deadline_at)
        payload = {
            "evidence_id": evidence_id,
            "platform_id": platform_id,
            "issue_id": issue_id,
            "proposal_id": proposal_id,
            "source_packet_id": source_packet_id,
            "request_type": request_type,
            "question": question.strip(),
            "requested_outputs": requested_outputs,
            "method_constraints": constraints,
            "priority": int(priority),
            "deadline_at": deadline,
            "request_role": request_role,
            "requested_manifest_id": pinned_manifest_id,
            "requested_manifest_hash": pinned_manifest_hash,
            "actor_id": auth.actor_id,
            "run_id": auth.run_id,
        }
        replay = self.store.idempotency_lookup("evidence.request.create", idempotency_key, payload)
        if replay:
            return {**replay, "idempotent_replay": True}
        for candidate in self.store.rows(
            "SELECT * FROM evidence_requests WHERE evidence_id=? AND platform_id=? "
            "AND request_type=? AND request_role=? AND state IN ('pending','claimed','running') "
            "AND requested_manifest_id IS ? ORDER BY created_at",
            (
                evidence_id,
                platform_id,
                request_type,
                request_role,
                pinned_manifest_id,
            ),
        ):
            if (
                candidate["question"] == question.strip()
                and _loads(candidate["requested_outputs_json"], []) == requested_outputs
                and _loads(candidate["method_constraints_json"], {}) == constraints
            ):
                return {
                    "evidence_request_id": candidate["evidence_request_id"],
                    "evidence_id": evidence_id,
                    "platform_id": platform_id,
                    "request_version": candidate["request_version"],
                    "request_type": request_type,
                    "request_role": request_role,
                    "requested_manifest_id": pinned_manifest_id,
                    "requested_manifest_hash": pinned_manifest_hash,
                    "state": candidate["state"],
                    "priority": candidate["priority"],
                    "deadline_at": candidate["deadline_at"],
                    "existing": True,
                }
        request_id = new_id("evidence_request")
        timestamp = now()
        result = {
            "evidence_request_id": request_id,
            "evidence_id": evidence_id,
            "platform_id": platform_id,
            "request_version": 1,
            "request_type": request_type,
            "state": "pending",
            "priority": int(priority),
            "deadline_at": deadline,
            "request_role": request_role,
            "requested_manifest_id": pinned_manifest_id,
            "requested_manifest_hash": pinned_manifest_hash,
        }
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO evidence_requests("
                "evidence_request_id,evidence_id,platform_id,issue_id,proposal_id,source_packet_id,"
                "request_version,request_type,question,requested_outputs_json,"
                "method_constraints_json,priority,state,created_by,created_run_id,claimed_by,"
                "claimed_run_id,lease_until,lease_generation,created_at,updated_at,deadline_at,"
                "last_error,request_role,requested_manifest_id,requested_manifest_hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    request_id,
                    evidence_id,
                    platform_id,
                    issue_id,
                    proposal_id,
                    source_packet_id,
                    1,
                    request_type,
                    question.strip(),
                    canonical_json(requested_outputs),
                    canonical_json(constraints),
                    int(priority),
                    "pending",
                    auth.actor_id,
                    auth.run_id,
                    None,
                    None,
                    None,
                    0,
                    timestamp,
                    timestamp,
                    deadline,
                    None,
                    request_role,
                    pinned_manifest_id,
                    pinned_manifest_hash,
                ),
            )
            self._event(conn, request_id, "created", auth, result)
            self.store.idempotency_record(
                conn, "evidence.request.create", idempotency_key, payload, result
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="evidence.request.create",
                object_type="evidence_request",
                object_id=request_id,
                before_revision=None,
                after_revision=1,
                reason=question.strip(),
                payload=result,
            )
            self.manager.evidence.recalculate(
                evidence_id,
                trigger_object_type="evidence_request",
                trigger_object_id=request_id,
                reason="verification requested",
                auth=auth,
                conn=conn,
            )
            self.manager.evidence._activity(
                conn,
                "evidence.request.created",
                "evidence_request",
                request_id,
                [issue_id] if issue_id else self.manager.evidence._issue_ids(evidence_id, conn),
                result,
                platform_id=platform_id,
            )
        return result

    def show(self, request_id: str) -> dict[str, Any]:
        row = self.store.row(
            "SELECT * FROM evidence_requests WHERE evidence_request_id=?", (request_id,)
        )
        if not row:
            raise NotFoundError(f"Evidence Request not found: {request_id}")
        for source, target, fallback in (
            ("requested_outputs_json", "requested_outputs", []),
            ("method_constraints_json", "method_constraints", {}),
        ):
            row[target] = _loads(row.pop(source), fallback)
        row["events"] = self.store.rows(
            "SELECT * FROM evidence_request_events WHERE evidence_request_id=? "
            "ORDER BY created_at,request_event_id",
            (request_id,),
        )
        for event in row["events"]:
            event["payload"] = _loads(event.pop("payload_json"), {})
        responses = self.store.rows(
            "SELECT * FROM evidence_responses WHERE evidence_request_id=? ORDER BY created_at",
            (request_id,),
        )
        for response in responses:
            for source, target, fallback in (
                ("input_snapshot_json", "input_snapshot", {}),
                ("result_json", "result", {}),
                ("artifact_ids_json", "artifact_ids", []),
                ("output_hashes_json", "output_hashes", {}),
                ("artifact_platform_snapshot_json", "artifact_platform_snapshot", {}),
                ("analysis_platform_snapshot_json", "analysis_platform_snapshot", {}),
            ):
                response[target] = _loads(response.pop(source), fallback)
        row["responses"] = responses
        return row

    def show_for_auth(self, request_id: str, auth: AuthContext) -> dict[str, Any]:
        row = self.store.row(
            "SELECT platform_id FROM evidence_requests WHERE evidence_request_id=?", (request_id,)
        )
        if not row:
            raise NotFoundError(f"Evidence Request not found: {request_id}")
        if auth.platform_id and row["platform_id"] != auth.platform_id:
            raise PrivateResourceForbiddenError(
                "Evidence Request is private to another platform",
                details={"evidence_request_id": request_id},
            )
        if not auth.platform_id and auth.actor_kind not in {
            "organizer_agent",
            "review_agent",
            "maintenance_agent",
        }:
            raise PrivateResourceForbiddenError("Principal cannot read private Evidence Requests")
        return self.show(request_id)

    def list_for_evidence(
        self, evidence_id: str, *, platform_id: str | None = None
    ) -> list[dict[str, Any]]:
        where = "evidence_id=?"
        params: tuple[Any, ...] = (evidence_id,)
        if platform_id is not None:
            where += " AND platform_id=?"
            params += (platform_id,)
        return [
            self.show(row["evidence_request_id"])
            for row in self.store.rows(
                f"SELECT evidence_request_id FROM evidence_requests WHERE {where} "
                "ORDER BY created_at",
                params,
            )
        ]

    @staticmethod
    def _lease(minutes: int) -> str:
        return (datetime.now().astimezone() + timedelta(minutes=max(1, minutes))).isoformat(
            timespec="seconds"
        )

    def claim(
        self,
        *,
        credential: str | Path,
        capabilities: list[str] | None = None,
        limit: int = 1,
        lease_minutes: int = 15,
        idempotency_key: str | None = None,
    ) -> list[dict[str, Any]]:
        auth = self.credentials.resolve(credential, "evidence.request.execute")
        if not auth.platform_id:
            raise PermissionError("Evidence Request execution requires a platform-scoped principal")
        if not 1 <= int(limit) <= 100:
            raise ValidationError("claim limit must be between 1 and 100")
        offered = set(capabilities or REQUEST_TYPES)
        unknown = offered - REQUEST_TYPES
        if unknown:
            raise ValidationError(f"Unknown executor request capabilities: {sorted(unknown)}")
        platform = self.store.row(
            "SELECT capabilities_json,status FROM platform_sources WHERE platform_id=?",
            (auth.platform_id,),
        )
        if not platform or platform["status"] != "active":
            raise PermissionError("Executor platform is not active")
        platform_caps = set(_loads(platform["capabilities_json"], []))
        supported = {
            request_type
            for request_type in offered
            if TYPE_CAPABILITY[request_type] in platform_caps
        }
        payload = {
            "actor_id": auth.actor_id,
            "run_id": auth.run_id,
            "platform_id": auth.platform_id,
            "capabilities": sorted(supported),
            "limit": int(limit),
            "lease_minutes": max(1, int(lease_minutes)),
        }
        replay = self.store.idempotency_lookup("evidence.request.claim", idempotency_key, payload)
        if replay:
            return [{**item, "idempotent_replay": True} for item in replay["items"]]
        if not supported:
            return []
        claimed: list[dict[str, Any]] = []
        timestamp = now()
        lease_until = self._lease(lease_minutes)
        placeholders = ",".join("?" for _ in supported)
        with self.store.transaction() as conn:
            expired_deadlines = conn.execute(
                "SELECT evidence_request_id,evidence_id FROM evidence_requests "
                "WHERE platform_id=? AND state IN ('pending','claimed','running') "
                "AND deadline_at IS NOT NULL AND deadline_at<?",
                (auth.platform_id, timestamp),
            ).fetchall()
            for expired in expired_deadlines:
                conn.execute(
                    "UPDATE evidence_requests SET state='expired',lease_until=NULL,updated_at=? "
                    "WHERE evidence_request_id=?",
                    (timestamp, expired["evidence_request_id"]),
                )
                self._event(
                    conn,
                    expired["evidence_request_id"],
                    "expired",
                    auth,
                    {"reason": "deadline elapsed"},
                )
            rows = conn.execute(
                f"SELECT * FROM evidence_requests WHERE platform_id=? "
                f"AND request_type IN ({placeholders}) AND (state='pending' OR "
                "(state IN ('claimed','running') AND lease_until IS NOT NULL AND lease_until<=?)) "
                "AND (deadline_at IS NULL OR deadline_at>=?) "
                "ORDER BY priority DESC,created_at,evidence_request_id LIMIT ?",
                (auth.platform_id, *sorted(supported), timestamp, timestamp, int(limit)),
            ).fetchall()
            for value in rows:
                row = dict(value)
                generation = int(row["lease_generation"]) + 1
                cursor = conn.execute(
                    "UPDATE evidence_requests SET state='claimed',claimed_by=?,claimed_run_id=?,"
                    "lease_until=?,lease_generation=?,updated_at=?,last_error=NULL "
                    "WHERE evidence_request_id=? AND lease_generation=?",
                    (
                        auth.actor_id,
                        auth.run_id,
                        lease_until,
                        generation,
                        timestamp,
                        row["evidence_request_id"],
                        row["lease_generation"],
                    ),
                )
                if cursor.rowcount != 1:
                    continue
                item = {
                    "evidence_request_id": row["evidence_request_id"],
                    "evidence_id": row["evidence_id"],
                    "platform_id": row["platform_id"],
                    "request_version": row["request_version"],
                    "request_type": row["request_type"],
                    "request_role": row.get("request_role", "source_verification"),
                    "requested_manifest_id": row.get("requested_manifest_id"),
                    "requested_manifest_hash": row.get("requested_manifest_hash"),
                    "question": row["question"],
                    "requested_outputs": _loads(row["requested_outputs_json"], []),
                    "method_constraints": _loads(row["method_constraints_json"], {}),
                    "lease_until": lease_until,
                    "lease_generation": generation,
                    "state": "claimed",
                }
                claimed.append(item)
                self._event(conn, row["evidence_request_id"], "claimed", auth, item)
                self.manager.evidence._activity(
                    conn,
                    "evidence.request.claimed",
                    "evidence_request",
                    row["evidence_request_id"],
                    [row["issue_id"]] if row["issue_id"] else [],
                    item,
                    platform_id=auth.platform_id,
                )
            self.store.idempotency_record(
                conn,
                "evidence.request.claim",
                idempotency_key,
                payload,
                {"items": claimed},
            )
        return claimed

    def _owned(
        self,
        request_id: str,
        auth: AuthContext,
        lease_generation: int,
        *,
        allow_expired: bool = False,
    ) -> dict[str, Any]:
        row = self.store.row(
            "SELECT * FROM evidence_requests WHERE evidence_request_id=?", (request_id,)
        )
        if not row:
            raise NotFoundError(f"Evidence Request not found: {request_id}")
        if row["platform_id"] != auth.platform_id:
            raise PermissionError("Evidence Request belongs to another platform")
        if row["claimed_by"] != auth.actor_id or row["claimed_run_id"] != auth.run_id:
            raise ConflictError("Evidence Request is not leased by this executor run")
        if int(row["lease_generation"]) != int(lease_generation):
            raise LeaseExpiredError("Evidence Request lease generation is stale")
        if not allow_expired and row["lease_until"] and row["lease_until"] < now():
            raise LeaseExpiredError("Evidence Request lease expired; reclaim it first")
        return row

    def heartbeat(
        self,
        request_id: str,
        *,
        lease_generation: int,
        credential: str | Path,
        lease_minutes: int = 15,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "evidence.request.execute")
        row = self._owned(request_id, auth, lease_generation)
        if row["state"] not in {"claimed", "running"}:
            raise ConflictError(f"Cannot heartbeat request in state {row['state']!r}")
        lease_until = self._lease(lease_minutes)
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE evidence_requests SET state='running',lease_until=?,updated_at=? "
                "WHERE evidence_request_id=?",
                (lease_until, now(), request_id),
            )
            self._event(
                conn,
                request_id,
                "heartbeat",
                auth,
                {"lease_until": lease_until, "lease_generation": lease_generation},
            )
        return {
            "evidence_request_id": request_id,
            "state": "running",
            "lease_until": lease_until,
            "lease_generation": lease_generation,
        }

    def release(
        self,
        request_id: str,
        *,
        lease_generation: int,
        credential: str | Path,
        reason: str = "",
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "evidence.request.execute")
        row = self._owned(request_id, auth, lease_generation, allow_expired=True)
        if row["state"] in {"answered", "failed", "cancelled", "expired"}:
            return {"evidence_request_id": request_id, "state": row["state"], "existing": True}
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE evidence_requests SET state='pending',claimed_by=NULL,claimed_run_id=NULL,"
                "lease_until=NULL,updated_at=?,last_error=? WHERE evidence_request_id=?",
                (now(), reason or None, request_id),
            )
            self._event(conn, request_id, "released", auth, {"reason": reason})
        return {"evidence_request_id": request_id, "state": "pending"}

    def respond(
        self,
        request_id: str,
        *,
        request_version: int,
        lease_generation: int,
        response_type: str,
        statement: str,
        input_snapshot: dict[str, Any],
        result: dict[str, Any],
        credential: str | Path,
        artifact_ids: list[str] | None = None,
        output_hashes: dict[str, str] | None = None,
        analysis_run_id: str | None = None,
        manifest_id: str | None = None,
        manifest_hash: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "evidence.request.execute")
        row = self.store.row(
            "SELECT * FROM evidence_requests WHERE evidence_request_id=?", (request_id,)
        )
        if not row:
            raise NotFoundError(f"Evidence Request not found: {request_id}")
        if row["platform_id"] != auth.platform_id:
            raise PermissionError("Evidence Request belongs to another platform")
        request_role = row.get("request_role", "source_verification")
        if request_role == "conflict_resolution":
            raise PermissionError(
                "Conflict resolution requires an Organizer/Reviewer resolution workflow"
            )
        current = self.store.row(
            "SELECT current_manifest_id FROM evidence_refs WHERE evidence_id=?",
            (row["evidence_id"],),
        )
        if row.get("requested_manifest_id") != (current or {}).get("current_manifest_id"):
            raise ManifestRevisionStaleError(
                "Evidence Request targets a superseded Manifest revision",
                details={
                    "evidence_request_id": request_id,
                    "requested_manifest_id": row.get("requested_manifest_id"),
                    "current_manifest_id": (current or {}).get("current_manifest_id"),
                },
            )
        qualified_manifest_id = manifest_id or row.get("requested_manifest_id")
        qualified_manifest_hash = manifest_hash or row.get("requested_manifest_hash")
        if qualified_manifest_id != row.get("requested_manifest_id") or (
            qualified_manifest_hash != row.get("requested_manifest_hash")
        ):
            raise ManifestRevisionStaleError(
                "Evidence Response must preserve the Request Manifest ID/hash",
                details={"evidence_request_id": request_id},
            )
        if int(row["request_version"]) != int(request_version):
            raise ConflictError("Evidence Response targets a stale request revision")
        if response_type != row["request_type"]:
            raise ValidationError("Evidence Response type must match the claimed request type")
        if not statement.strip():
            raise ValidationError("Evidence Response statement cannot be empty")
        if not isinstance(input_snapshot, dict) or not isinstance(result, dict):
            raise ValidationError("Response input_snapshot and result must be objects")
        forbidden = {"effective_verification_level", "verification_level", "claimed_level"}
        if forbidden & set(result):
            raise ValidationError("Executors cannot submit an effective verification level")
        artifacts = sorted(set(artifact_ids or []))
        actual_hashes: dict[str, str] = {}
        artifact_platform_snapshot: dict[str, dict[str, Any]] = {}
        for artifact_id in artifacts:
            if not self.store.row(
                "SELECT 1 FROM artifacts WHERE artifact_id=?", (artifact_id,)
            ):
                raise ValidationError(f"Response Artifact not found: {artifact_id}")
            artifact = self.manager.artifacts.require_platform_artifact(
                artifact_id, str(auth.platform_id)
            )
            actual_hashes[artifact_id] = artifact["sha256"]
            artifact_platform_snapshot[artifact_id] = {
                "platform_id": auth.platform_id,
                "sha256": artifact["sha256"],
                "role": artifact["role"],
            }
        if output_hashes is not None and output_hashes != actual_hashes:
            raise ValidationError("Response output_hashes do not match registered Artifact content")
        if response_type == "reproduction" and not analysis_run_id:
            raise ValidationError("A reproduction response requires analysis_run_id")
        analysis_platform_snapshot: dict[str, Any] = {}
        if response_type in {"reproduction", "reanalysis"}:
            if not analysis_run_id:
                raise ValidationError("A reproduction response requires a frozen AnalysisRun")
            analysis_run = self.manager.artifacts.require_platform_analysis_run(
                analysis_run_id, str(auth.platform_id)
            )
            if qualified_manifest_id:
                pinned = _loads(analysis_run.get("input_manifest_hashes_json"), {}).get(
                    row["evidence_id"], {}
                )
                if pinned.get("manifest_id") != qualified_manifest_id or pinned.get(
                    "manifest_hash"
                ) != qualified_manifest_hash:
                    raise AnalysisPlatformMismatchError(
                        "AnalysisRun does not pin the requested Manifest ID/hash",
                        details={"analysis_run_id": analysis_run_id},
                    )
            registered_outputs = {
                item["artifact_id"]
                for item in self.store.rows(
                    "SELECT artifact_id FROM analysis_outputs WHERE analysis_run_id=?",
                    (analysis_run_id,),
                )
            }
            if not set(artifacts).issubset(registered_outputs):
                raise ValidationError(
                    "Reproduction response Artifacts must be registered AnalysisRun outputs"
                )
            analysis_platform_snapshot = {
                "analysis_run_id": analysis_run_id,
                "platform_id": analysis_run["platform_id"],
                "state": analysis_run["state"],
                "input_manifest": _loads(
                    analysis_run.get("input_manifest_hashes_json"), {}
                ).get(row["evidence_id"]),
            }
        response_payload = {
            "evidence_request_id": request_id,
            "request_version": int(request_version),
            "platform_id": auth.platform_id,
            "responder_actor_id": auth.actor_id,
            "responder_run_id": auth.run_id,
            "response_type": response_type,
            "statement": statement.strip(),
            "input_snapshot": input_snapshot,
            "result": result,
            "artifact_ids": artifacts,
            "output_hashes": actual_hashes,
            "analysis_run_id": analysis_run_id,
            "request_role": request_role,
            "qualified_manifest_id": qualified_manifest_id,
            "qualified_manifest_hash": qualified_manifest_hash,
            "artifact_platform_snapshot": artifact_platform_snapshot,
            "analysis_platform_snapshot": analysis_platform_snapshot,
            "lease_generation": int(lease_generation),
            "token_epoch": int(auth.token_epoch or 0),
        }
        response_hash = hashlib.sha256(
            canonical_json(response_payload).encode("utf-8")
        ).hexdigest()
        replay = self.store.idempotency_lookup(
            "evidence.request.respond", idempotency_key, response_payload
        )
        if replay:
            return {**replay, "idempotent_replay": True}
        if row["state"] == "answered":
            existing = self.store.row(
                "SELECT evidence_response_id,response_hash FROM evidence_responses "
                "WHERE evidence_request_id=? ORDER BY created_at DESC LIMIT 1",
                (request_id,),
            )
            if existing and existing["response_hash"] == response_hash:
                return {
                    **existing,
                    "evidence_request_id": request_id,
                    "state": "answered",
                    "existing": True,
                }
            raise ConflictError("Evidence Request was already answered with different content")
        row = self._owned(request_id, auth, lease_generation)
        if row["state"] not in {"claimed", "running"}:
            raise ConflictError(f"Cannot answer request in state {row['state']!r}")
        response_id = new_id("evidence_response")
        response = {
            "evidence_response_id": response_id,
            "evidence_request_id": request_id,
            "response_hash": response_hash,
            "state": "answered",
        }
        attestation_type = {
            "existence": "existence",
            "metadata": "metadata",
            "content": "content",
            "snapshot": "snapshot",
            "preview": "snapshot",
            "statistics": "content",
            "reproduction": "reproduction",
            "reanalysis": "reproduction",
        }.get(response_type)
        if not attestation_type:
            raise ValidationError(f"Unknown Evidence Response type: {response_type}")
        attestation_state = "conflict" if bool(result.get("conflict")) else "valid"
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO evidence_responses("
                "evidence_response_id,evidence_request_id,request_version,platform_id,"
                "responder_actor_id,responder_run_id,response_type,statement,input_snapshot_json,"
                "result_json,artifact_ids_json,output_hashes_json,analysis_run_id,lease_generation,"
                "token_epoch,response_hash,created_at,request_role,qualified_manifest_id,"
                "qualified_manifest_hash,artifact_platform_snapshot_json,"
                "analysis_platform_snapshot_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    response_id,
                    request_id,
                    int(request_version),
                    auth.platform_id,
                    auth.actor_id,
                    auth.run_id,
                    response_type,
                    statement.strip(),
                    canonical_json(input_snapshot),
                    canonical_json(result),
                    canonical_json(artifacts),
                    canonical_json(actual_hashes),
                    analysis_run_id,
                    int(lease_generation),
                    int(auth.token_epoch or 0),
                    response_hash,
                    now(),
                    request_role,
                    qualified_manifest_id,
                    qualified_manifest_hash,
                    canonical_json(artifact_platform_snapshot),
                    canonical_json(analysis_platform_snapshot),
                ),
            )
            conn.execute(
                "UPDATE evidence_requests SET state='answered',lease_until=NULL,updated_at=? "
                "WHERE evidence_request_id=?",
                (now(), request_id),
            )
            self._event(conn, request_id, "answered", auth, response)
            self.manager.evidence._attest_auth(
                row["evidence_id"],
                attestation_type=attestation_type,
                method=f"evidence-request:{request_id}",
                input_snapshot={
                    **input_snapshot,
                    "evidence_request_id": request_id,
                    "request_version": int(request_version),
                    "response_hash": response_hash,
                },
                result=result,
                auth=auth,
                manifest_id=qualified_manifest_id,
                artifact_ids=artifacts,
                analysis_run_id=analysis_run_id,
                state=attestation_state,
                attestation_role=(
                    "independent"
                    if request_role == "independent_verification"
                    else "source"
                ),
                qualified_manifest_hash=qualified_manifest_hash,
                idempotency_key=f"response-attestation:{response_hash}",
                conn=conn,
            )
            self.store.idempotency_record(
                conn,
                "evidence.request.respond",
                idempotency_key,
                response_payload,
                response,
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="evidence.request.respond",
                object_type="evidence_response",
                object_id=response_id,
                before_revision=None,
                after_revision=1,
                reason=statement.strip(),
                payload=response,
            )
            if row.get("source_packet_id"):
                conn.execute(
                    "UPDATE triage_tasks SET state='retry',updated_at=?,last_error=NULL "
                    "WHERE packet_id=? AND state='needs_input'",
                    (now(), row["source_packet_id"]),
                )
                conn.execute(
                    "UPDATE intake_packets SET status='pending',updated_at=? "
                    "WHERE packet_id=? AND status='needs_input'",
                    (now(), row["source_packet_id"]),
                )
            self.manager.evidence._activity(
                conn,
                "evidence.request.answered",
                "evidence_response",
                response_id,
                [row["issue_id"]] if row["issue_id"] else [],
                response,
                platform_id=auth.platform_id,
            )
        return response

    def fail(
        self,
        request_id: str,
        *,
        lease_generation: int,
        error: str,
        credential: str | Path,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "evidence.request.execute")
        current = self.store.row(
            "SELECT * FROM evidence_requests WHERE evidence_request_id=?", (request_id,)
        )
        if not current:
            raise NotFoundError(f"Evidence Request not found: {request_id}")
        if current["state"] == "answered":
            return {"evidence_request_id": request_id, "state": "answered", "existing": True}
        row = self._owned(request_id, auth, lease_generation, allow_expired=True)
        if row["state"] == "failed":
            return {"evidence_request_id": request_id, "state": "failed", "existing": True}
        if not error.strip():
            raise ValidationError("Failing an Evidence Request requires an error")
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE evidence_requests SET state='failed',lease_until=NULL,last_error=?,updated_at=? "
                "WHERE evidence_request_id=?",
                (error.strip(), now(), request_id),
            )
            self._event(conn, request_id, "failed", auth, {"error": error.strip()})
            self.manager.evidence.recalculate(
                row["evidence_id"],
                trigger_object_type="evidence_request",
                trigger_object_id=request_id,
                reason="verification request failed",
                auth=auth,
                conn=conn,
            )
        return {"evidence_request_id": request_id, "state": "failed", "error": error.strip()}

    @staticmethod
    def _event(
        conn: sqlite3.Connection,
        request_id: str,
        event_type: str,
        auth: AuthContext,
        payload: dict[str, Any],
    ) -> None:
        conn.execute(
            "INSERT INTO evidence_request_events VALUES (?,?,?,?,?,?,?)",
            (
                new_id("request_event"),
                request_id,
                event_type,
                auth.actor_id,
                auth.run_id,
                canonical_json(payload),
                now(),
            ),
        )
