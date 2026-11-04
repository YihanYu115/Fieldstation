from __future__ import annotations

import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .conflict_governance import (
    build_resolution_operation,
    content_hash,
    insert_governed_receipt,
    validate_resolution_binding,
)
from .errors import ConflictError, NotFoundError, ReviewRequiredError, ValidationError
from .store import canonical_json, new_id, now, sha256_file
from .strict_json import require_strict_json

if TYPE_CHECKING:
    from .security import AuthContext
    from .service import IssueManager


FIELD_BUNDLE_VERSION = "issue-manager-field-bundle/v1"
EVENT_TYPES = {
    "question",
    "action",
    "observation",
    "interpretation",
    "alternative",
    "decision",
    "next_action",
    "evidence_locator",
    "record_patch",
    "relationship_hint",
}


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


class FieldBundleService:
    def __init__(self, manager: IssueManager):
        self.manager = manager
        self.store = manager.store

    @staticmethod
    def _actor(auth: AuthContext | None, capability: str, fallback: str) -> str:
        if auth is None:
            return fallback
        auth.require(capability)
        return auth.actor_id

    @staticmethod
    def _read(source: str | Path | dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], Path | None]:
        if isinstance(source, dict):
            manifest = source.get("manifest", source)
            events = source.get("events", [])
            root = None
        else:
            root = Path(source).resolve()
            if not root.is_dir():
                raise ValidationError(f"Field Bundle path is not a directory: {root}")
            try:
                manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
                events = [
                    json.loads(line)
                    for line in (root / "events.jsonl").read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValidationError(f"Cannot read Field Bundle: {exc}") from exc
        if not isinstance(manifest, dict):
            raise ValidationError("Field Bundle manifest must be an object")
        if not isinstance(events, list) or not all(isinstance(event, dict) for event in events):
            raise ValidationError("Field Bundle events must be an object list")
        return dict(manifest), [dict(event) for event in events], root

    def validate_bundle(self, source: str | Path | dict[str, Any]) -> dict[str, Any]:
        manifest, events, root = self._read(source)
        required = {
            "bundle_id", "bundle_version", "created_by", "created_at",
            "source_namespace", "source_owner",
        }
        missing = sorted(required - set(manifest))
        if missing:
            raise ValidationError(f"Field Bundle manifest is missing fields: {missing}")
        if manifest["bundle_version"] not in {"1", 1, FIELD_BUNDLE_VERSION}:
            raise ValidationError(f"Unsupported Field Bundle version: {manifest['bundle_version']!r}")
        if any(
            not str(manifest[field]).strip()
            for field in ("bundle_id", "source_namespace", "source_owner")
        ):
            raise ValidationError(
                "Field Bundle ID, source namespace, and source owner cannot be empty"
            )
        attachment_results: list[dict[str, Any]] = []
        inventory = manifest.get("attachments", manifest.get("attachment_inventory", []))
        if not isinstance(inventory, list):
            raise ValidationError("Field Bundle attachment inventory must be an array")
        for item in inventory:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("path"), str)
                or not isinstance(item.get("sha256"), str)
            ):
                raise ValidationError("Attachment inventory entries require path and sha256")
            relative = Path(item["path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValidationError(f"Unsafe Field Bundle attachment path: {relative}")
            expected_hash = str(item["sha256"]).lower()
            if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
                raise ValidationError(f"Invalid attachment sha256: {relative}")
            actual_hash = None
            size = item.get("size")
            if size is not None and (
                isinstance(size, bool) or not isinstance(size, int) or size < 0
            ):
                raise ValidationError(f"Invalid attachment size: {relative}")
            if root is not None:
                attachment_path = (root / relative).resolve()
                if root not in attachment_path.parents:
                    raise ValidationError(f"Attachment escapes Field Bundle root: {relative}")
                if not attachment_path.is_file():
                    raise ValidationError(f"Field Bundle attachment is missing: {relative}")
                actual_hash = sha256_file(attachment_path)
                if size is not None and attachment_path.stat().st_size != size:
                    raise ValidationError(f"Field Bundle attachment size mismatch: {relative}")
                size = attachment_path.stat().st_size
            if actual_hash is not None and actual_hash != expected_hash:
                raise ValidationError(f"Field Bundle attachment hash mismatch: {relative}")
            attachment_results.append(
                {
                    "path": str(relative),
                    "sha256": expected_hash,
                    "size": size,
                    "mime_type": str(
                        item.get("mime_type")
                        or mimetypes.guess_type(str(relative))[0]
                        or "application/octet-stream"
                    ),
                    "available": actual_hash is not None,
                    "local_path": str(attachment_path) if root is not None else None,
                }
            )
        event_results: list[dict[str, Any]] = []
        seen_event_ids: set[str] = set()
        for index, raw_event in enumerate(events):
            event = dict(raw_event)
            declared_hash = event.pop("event_hash", None)
            event_type = event.get("event_type", event.get("type"))
            if event_type not in EVENT_TYPES:
                raise ValidationError(f"Unsupported Field Bundle event type at index {index}: {event_type!r}")
            event_id = str(event.get("event_id", index))
            if event_id in seen_event_ids:
                raise ConflictError(f"Duplicate Field Bundle event ID: {event_id}")
            seen_event_ids.add(event_id)
            actual_hash = _hash(event)
            if declared_hash and declared_hash != actual_hash:
                raise ValidationError(f"Field Bundle event hash mismatch at index {index}")
            event_results.append(
                {"event_index": index, "event_id": event_id, "event_type": event_type, "event": event, "event_hash": actual_hash}
            )
        canonical_manifest = dict(manifest)
        canonical_manifest.pop("content_hash", None)
        content_hash = _hash(
            {
                "manifest": canonical_manifest,
                "event_hashes": [item["event_hash"] for item in event_results],
                "attachments": [
                    {key: item[key] for key in ("path", "sha256", "size", "mime_type")}
                    for item in attachment_results
                ],
            }
        )
        declared_content_hash = manifest.get("content_hash")
        if declared_content_hash and declared_content_hash != content_hash:
            raise ValidationError("Field Bundle content hash does not match its contents")
        return {
            "valid": True,
            "manifest": canonical_manifest,
            "events": event_results,
            "attachments": attachment_results,
            "attachments_complete": all(item["available"] for item in attachment_results),
            "attachments_missing": sorted(
                {item["sha256"] for item in attachment_results if not item["available"]}
            ),
            "content_hash": content_hash,
        }

    def _conflicts(self, validated: dict[str, Any]) -> list[dict[str, Any]]:
        manifest = validated["manifest"]
        conflicts: list[dict[str, Any]] = []
        known = manifest.get("known_issue_revisions", {})
        if not isinstance(known, dict):
            raise ValidationError("known_issue_revisions must be an object")
        for issue_id, expected in known.items():
            issue = self.store.row(
                "SELECT working_revision,conclusion_revision FROM issues WHERE issue_id=?",
                (issue_id,),
            )
            if not issue:
                conflicts.append({"code": "issue_missing", "issue_id": issue_id})
                continue
            if isinstance(expected, int):
                expected = {"working_revision": expected}
            if not isinstance(expected, dict):
                raise ValidationError("Known Issue revision values must be integers or objects")
            for revision_key in ("working_revision", "conclusion_revision"):
                if revision_key in expected and int(expected[revision_key]) != int(issue[revision_key]):
                    conflicts.append(
                        {
                            "code": "base_revision_changed",
                            "issue_id": issue_id,
                            "revision_kind": revision_key,
                            "expected": int(expected[revision_key]),
                            "actual": int(issue[revision_key]),
                        }
                    )
        for event in validated["events"]:
            if event["event_type"] != "record_patch":
                continue
            payload = event["event"]
            record_id = payload.get("record_instance_id")
            expected_revision = payload.get("base_record_revision_id")
            if not record_id:
                conflicts.append({"code": "record_target_missing", "event_index": event["event_index"]})
                continue
            record = self.store.row(
                "SELECT current_revision_id FROM record_instances WHERE record_instance_id=?", (record_id,)
            )
            if not record:
                conflicts.append({"code": "record_missing", "record_instance_id": record_id})
            elif expected_revision and expected_revision != record["current_revision_id"]:
                conflicts.append(
                    {
                        "code": "record_revision_changed",
                        "record_instance_id": record_id,
                        "expected": expected_revision,
                        "actual": record["current_revision_id"],
                    }
                )
        return conflicts

    def upload(
        self,
        source: str | Path | dict[str, Any],
        *,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "upload offline field bundle",
        dry_run: bool = False,
    ) -> dict[str, Any]:
        actor = self._actor(auth, "field_bundle.submit", actor)
        validated = self.validate_bundle(source)
        manifest = validated["manifest"]
        bundle_id = str(manifest["bundle_id"])
        existing = self.store.row(
            "SELECT field_bundle_id,content_hash,state FROM field_bundles WHERE field_bundle_id=?",
            (bundle_id,),
        )
        if existing:
            if existing["content_hash"] != validated["content_hash"]:
                raise ConflictError(
                    f"Field Bundle ID {bundle_id!r} was already uploaded with different content"
                )
            missing = self.store.rows(
                "SELECT attachment_path,expected_sha256,expected_size FROM field_bundle_attachments "
                "WHERE field_bundle_id=? AND upload_state<>'verified' ORDER BY attachment_path",
                (bundle_id,),
            )
            return {
                "field_bundle_id": bundle_id,
                "content_hash": validated["content_hash"],
                "state": existing["state"],
                "attachments_missing": missing,
                "receipts": self.receipts(bundle_id),
                "idempotent_replay": True,
                "would_write": False,
            }
        head_row = self.store.row(
            "SELECT COALESCE(MAX(activity_sequence),0) AS cursor FROM activity_events"
        )
        context_cursor = int((head_row or {"cursor": 0})["cursor"])
        base_cursor = manifest.get("base_activity_cursor")
        if base_cursor is not None and (
            isinstance(base_cursor, bool) or not isinstance(base_cursor, int) or base_cursor < 0
        ):
            raise ValidationError("base_activity_cursor must be a non-negative integer")
        delta_count = 0
        if base_cursor is not None:
            delta_row = self.store.row(
                "SELECT COUNT(*) AS n FROM activity_events WHERE activity_sequence>?",
                (base_cursor,),
            )
            delta_count = int((delta_row or {"n": 0})["n"])
        local_artifacts: dict[str, dict[str, Any]] = {}
        for attachment in validated["attachments"]:
            if attachment["available"]:
                local_artifacts[attachment["path"]] = self._persist_attachment_file(
                    Path(attachment["local_path"]), attachment, actor
                )
            else:
                existing_artifact = self.store.row(
                    "SELECT * FROM artifacts WHERE sha256=?", (attachment["sha256"],)
                )
                if existing_artifact and self.manager.artifacts.verify(
                    existing_artifact["artifact_id"]
                )["ok"]:
                    local_artifacts[attachment["path"]] = existing_artifact
        missing_attachments = [
            item for item in validated["attachments"] if item["path"] not in local_artifacts
        ]
        state = "received" if missing_attachments else "staged"
        conflicts = [] if missing_attachments else self._conflicts(validated)
        if conflicts:
            state = "needs_triage"
        preview = {
            "field_bundle_id": bundle_id,
            "content_hash": validated["content_hash"],
            "state": state,
            "event_count": len(validated["events"]),
            "attachment_count": len(validated["attachments"]),
            "attachments_missing": [
                {key: item[key] for key in ("path", "sha256", "size")}
                for item in missing_attachments
            ],
            "conflicts": conflicts,
            "base_activity_cursor": base_cursor,
            "context_cursor": context_cursor,
            "activity_delta_count": delta_count,
        }
        if dry_run:
            return {**preview, "would_write": False}
        timestamp = now()
        upload_tokens: list[dict[str, str]] = []
        upload_token_by_hash: dict[str, str] = {}
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO field_bundles(field_bundle_id,bundle_version,source_namespace,"
                "source_owner,manifest_json,content_hash,state,base_activity_cursor,parent_bundle_id,"
                "created_at,created_by,uploaded_at,routing_state_revision,apply_cursor,last_error_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0,0,'{}')",
                (
                    bundle_id, str(manifest["bundle_version"]),
                    str(manifest["source_namespace"]), str(manifest["source_owner"]),
                    canonical_json(manifest), validated["content_hash"], state, base_cursor,
                    manifest.get("parent_bundle_id"), str(manifest["created_at"]), actor, timestamp,
                ),
            )
            conflict_event_indices = {
                item.get("event_index") for item in conflicts if item.get("event_index") is not None
            }
            for event in validated["events"]:
                event_state = "pending" if missing_attachments else (
                    "needs_triage"
                    if event["event_index"] in conflict_event_indices
                    or (conflicts and event["event_type"] == "record_patch")
                    else "staged"
                )
                conn.execute(
                    "INSERT INTO field_bundle_events("
                    "field_bundle_event_id,field_bundle_id,event_index,event_type,event_json,event_hash,"
                    "processing_state,result_json,target_object_type,target_object_id,"
                    "target_revision_id,state_revision) VALUES (?,?,?,?,?,?,?,?,NULL,NULL,NULL,0)",
                    (
                        new_id("field_event"), bundle_id, event["event_index"], event["event_type"],
                        canonical_json(event["event"]), event["event_hash"], event_state,
                        canonical_json({"action": "awaiting_attachments" if missing_attachments else "staged_for_routing", "preserved": True}),
                    ),
                )
            for attachment in validated["attachments"]:
                artifact = local_artifacts.get(attachment["path"])
                token = None
                if not artifact:
                    token = upload_token_by_hash.get(attachment["sha256"])
                    if token is None:
                        token = secrets.token_urlsafe(32)
                        upload_token_by_hash[attachment["sha256"]] = token
                        upload_tokens.append(
                            {
                                "path": attachment["path"],
                                "sha256": attachment["sha256"],
                                "upload_token": token,
                            }
                        )
                conn.execute(
                    "INSERT INTO field_bundle_attachments VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        bundle_id, attachment["path"], attachment["sha256"], attachment["size"],
                        attachment["mime_type"], artifact.get("artifact_id") if artifact else None,
                        hashlib.sha256(token.encode()).hexdigest() if token else None,
                        "verified" if artifact else "missing",
                        int(attachment["size"] or artifact.get("size", 0)) if artifact else 0,
                        timestamp, timestamp if artifact else None,
                    ),
                )
                if artifact:
                    conn.execute(
                        "INSERT OR IGNORE INTO artifact_links VALUES (?,?,?,?,?,?)",
                        (artifact["artifact_id"], "field_bundle", bundle_id, attachment["path"], timestamp, actor),
                    )
            receipt_result = {
                **preview,
                "events": [
                    {"event_index": event["event_index"], "event_hash": event["event_hash"]}
                    for event in validated["events"]
                ],
            }
            receipt_hash = _hash(receipt_result)
            receipt_id = new_id("field_receipt")
            conn.execute(
                "INSERT INTO field_bundle_receipts VALUES (?,?,?,?,?,?,?,?)",
                (
                    receipt_id, bundle_id, validated["content_hash"],
                    canonical_json(receipt_result), receipt_hash, context_cursor, timestamp, actor,
                ),
            )
            event_id = self.store.audit(
                conn, actor=actor, action="field_bundle.begin_upload", object_type="field_bundle",
                object_id=bundle_id, before_revision=None, after_revision=0, reason=reason,
                payload={**preview, "receipt_hash": receipt_hash},
            )
        return {
            **preview,
            "upload_tokens": upload_tokens,
            "field_bundle_receipt_id": receipt_id,
            "receipt_hash": receipt_hash,
            "event_id": event_id,
            "idempotent_replay": False,
            "would_write": True,
        }

    def _persist_attachment_file(
        self, source: Path, attachment: dict[str, Any], actor: str
    ) -> dict[str, Any]:
        content = source.read_bytes()
        if hashlib.sha256(content).hexdigest() != attachment["sha256"]:
            raise ValidationError(f"Attachment changed during upload: {attachment['path']}")
        return self._persist_attachment_content(content, attachment, actor)

    def _persist_attachment_content(
        self, content: bytes, attachment: dict[str, Any], actor: str
    ) -> dict[str, Any]:
        digest = hashlib.sha256(content).hexdigest()
        if digest != attachment["sha256"]:
            raise ValidationError("Uploaded Field Bundle blob hash does not match inventory")
        if attachment.get("size") is not None and len(content) != int(attachment["size"]):
            raise ValidationError("Uploaded Field Bundle blob size does not match inventory")
        object_path = (
            self.store.ledger_dir / "artifacts" / "objects" / "sha256" / digest[:2] / digest
        )
        object_path.parent.mkdir(parents=True, exist_ok=True)
        if not object_path.exists():
            temporary = object_path.with_suffix(f".tmp-{os.getpid()}-{new_id('field_blob')}")
            temporary.write_bytes(content)
            os.replace(temporary, object_path)
        existing = self.store.row("SELECT * FROM artifacts WHERE sha256=?", (digest,))
        if existing:
            return existing
        artifact_id = new_id("artifact")
        created = now()
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO artifacts(artifact_id,kind,role,mime_type,sha256,size,storage_uri,"
                "original_locator,created_at,created_by,frozen_at) VALUES (?,?, 'evidence',?,?,?,?,?,?,?,NULL)",
                (
                    artifact_id, Path(attachment["path"]).suffix.lstrip(".") or "file",
                    attachment["mime_type"], digest, len(content),
                    object_path.relative_to(self.store.ledger_dir).as_posix(),
                    f"field-bundle:{attachment['path']}", created, actor,
                ),
            )
        return self.store.row("SELECT * FROM artifacts WHERE artifact_id=?", (artifact_id,)) or {}

    def upload_blob(
        self,
        bundle_id: str,
        sha256: str,
        content: bytes,
        *,
        upload_token: str,
        offset: int = 0,
        final: bool = True,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
    ) -> dict[str, Any]:
        actor = self._actor(auth, "field_bundle.submit", actor)
        bundle = self.store.row("SELECT * FROM field_bundles WHERE field_bundle_id=?", (bundle_id,))
        if not bundle:
            raise NotFoundError(f"Field Bundle not found: {bundle_id}")
        if auth and auth.actor_kind not in {"organizer_agent", "maintenance_agent"} and (
            auth.actor_id not in {bundle["source_owner"], bundle["created_by"]}
        ):
            raise ValidationError("Field Bundle upload token is outside the principal scope")
        attachment = self.store.row(
            "SELECT * FROM field_bundle_attachments WHERE field_bundle_id=? AND expected_sha256=? "
            "AND upload_state<>'verified' ORDER BY attachment_path LIMIT 1",
            (bundle_id, sha256.lower()),
        )
        if not attachment:
            verified = self.store.row(
                "SELECT artifact_id FROM field_bundle_attachments WHERE field_bundle_id=? "
                "AND expected_sha256=? AND upload_state='verified' LIMIT 1",
                (bundle_id, sha256.lower()),
            )
            if verified:
                return {"field_bundle_id": bundle_id, "sha256": sha256, "artifact_id": verified["artifact_id"], "idempotent_replay": True}
            raise NotFoundError("Field Bundle attachment upload target not found")
        actual_token_hash = hashlib.sha256(upload_token.encode()).hexdigest()
        if not hmac.compare_digest(actual_token_hash, str(attachment["upload_token_hash"])):
            raise ValidationError("Field Bundle upload token is invalid")
        upload_dir = self.store.ledger_dir / "field_uploads" / bundle_id
        upload_dir.mkdir(parents=True, exist_ok=True)
        part = upload_dir / f"{sha256}.part"
        current_size = part.stat().st_size if part.exists() else 0
        if offset < current_size:
            with part.open("rb") as stream:
                stream.seek(offset)
                if stream.read(len(content)) == content:
                    return {"field_bundle_id": bundle_id, "sha256": sha256, "received_bytes": current_size, "idempotent_replay": True}
            raise ConflictError("Chunk retry does not match already uploaded bytes")
        if offset != current_size:
            raise ConflictError(
                "Field Bundle chunks must be uploaded in order",
                details={"expected_offset": current_size, "received_offset": offset},
            )
        with part.open("ab") as stream:
            stream.write(content)
        received = part.stat().st_size
        expected_size = attachment.get("expected_size")
        if expected_size is not None and received > int(expected_size):
            part.unlink(missing_ok=True)
            raise ValidationError("Uploaded Field Bundle blob exceeds declared size")
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE field_bundle_attachments SET upload_state='uploading',received_bytes=? "
                "WHERE field_bundle_id=? AND attachment_path=?",
                (received, bundle_id, attachment["attachment_path"]),
            )
        if not final:
            return {"field_bundle_id": bundle_id, "sha256": sha256, "received_bytes": received, "complete": False}
        blob = part.read_bytes()
        artifact = self._persist_attachment_content(
            blob,
            {
                "path": attachment["attachment_path"], "sha256": attachment["expected_sha256"],
                "size": attachment["expected_size"], "mime_type": attachment["mime_type"],
            },
            actor,
        )
        part.unlink(missing_ok=True)
        with self.store.transaction() as conn:
            matching_paths = conn.execute(
                "SELECT attachment_path FROM field_bundle_attachments WHERE field_bundle_id=? "
                "AND expected_sha256=? AND upload_state<>'verified'",
                (bundle_id, attachment["expected_sha256"]),
            ).fetchall()
            conn.execute(
                "UPDATE field_bundle_attachments SET artifact_id=?,upload_state='verified',"
                "received_bytes=?,verified_at=?,upload_token_hash=NULL "
                "WHERE field_bundle_id=? AND expected_sha256=?",
                (
                    artifact["artifact_id"],
                    received,
                    now(),
                    bundle_id,
                    attachment["expected_sha256"],
                ),
            )
            for matching_path in matching_paths:
                conn.execute(
                    "INSERT OR IGNORE INTO artifact_links VALUES (?,?,?,?,?,?)",
                    (
                        artifact["artifact_id"],
                        "field_bundle",
                        bundle_id,
                        matching_path["attachment_path"],
                        now(),
                        actor,
                    ),
                )
        remaining = self.store.rows(
            "SELECT attachment_path,expected_sha256 FROM field_bundle_attachments "
            "WHERE field_bundle_id=? AND upload_state<>'verified'",
            (bundle_id,),
        )
        next_state = bundle["state"]
        if not remaining:
            shown = self.show(bundle_id)
            validated = {
                "manifest": shown["manifest"],
                "events": [
                    {
                        "event_index": event["event_index"], "event_type": event["event_type"],
                        "event": event["event"], "event_hash": event["event_hash"],
                    }
                    for event in shown["events"]
                ],
            }
            conflicts = self._conflicts(validated)
            next_state = "needs_triage" if conflicts else "staged"
            conflict_event_indices = {
                item.get("event_index")
                for item in conflicts
                if item.get("event_index") is not None
            }
            with self.store.transaction() as conn:
                conn.execute(
                    "UPDATE field_bundles SET state=?,routing_state_revision=routing_state_revision+1 "
                    "WHERE field_bundle_id=? AND state='received'",
                    (next_state, bundle_id),
                )
                for pending_event in conn.execute(
                    "SELECT field_bundle_event_id,event_index,event_type FROM field_bundle_events "
                    "WHERE field_bundle_id=? AND processing_state='pending'",
                    (bundle_id,),
                ).fetchall():
                    event_state = (
                        "needs_triage"
                        if pending_event["event_index"] in conflict_event_indices
                        or (conflicts and pending_event["event_type"] == "record_patch")
                        else "staged"
                    )
                    conn.execute(
                        "UPDATE field_bundle_events SET processing_state=?,"
                        "state_revision=state_revision+1,result_json=? "
                        "WHERE field_bundle_event_id=?",
                        (
                            event_state,
                            canonical_json(
                                {
                                    "action": (
                                        "needs_triage"
                                        if event_state == "needs_triage"
                                        else "staged_for_routing"
                                    ),
                                    "conflicts": conflicts if event_state == "needs_triage" else [],
                                    "preserved": True,
                                }
                            ),
                            pending_event["field_bundle_event_id"],
                        ),
                    )
        return {
            "field_bundle_id": bundle_id, "sha256": sha256,
            "artifact_id": artifact["artifact_id"], "received_bytes": received,
            "attachments_missing": remaining, "state": next_state, "complete": not remaining,
        }

    def renew_upload_tokens(
        self,
        bundle_id: str,
        *,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
    ) -> dict[str, Any]:
        actor = self._actor(auth, "field_bundle.submit", actor)
        bundle = self.store.row("SELECT * FROM field_bundles WHERE field_bundle_id=?", (bundle_id,))
        if not bundle:
            raise NotFoundError(f"Field Bundle not found: {bundle_id}")
        if auth and auth.actor_kind not in {"organizer_agent", "maintenance_agent"} and (
            auth.actor_id not in {bundle["source_owner"], bundle["created_by"]}
        ):
            raise ValidationError("Field Bundle is outside the principal scope")
        missing = self.store.rows(
            "SELECT attachment_path,expected_sha256 FROM field_bundle_attachments "
            "WHERE field_bundle_id=? AND upload_state<>'verified' ORDER BY attachment_path",
            (bundle_id,),
        )
        tokens: list[dict[str, str]] = []
        token_by_hash: dict[str, str] = {}
        with self.store.transaction() as conn:
            for item in missing:
                token = token_by_hash.setdefault(
                    item["expected_sha256"], secrets.token_urlsafe(32)
                )
                conn.execute(
                    "UPDATE field_bundle_attachments SET upload_token_hash=? "
                    "WHERE field_bundle_id=? AND attachment_path=?",
                    (
                        hashlib.sha256(token.encode()).hexdigest(), bundle_id,
                        item["attachment_path"],
                    ),
                )
                if not any(
                    existing["sha256"] == item["expected_sha256"] for existing in tokens
                ):
                    tokens.append(
                        {
                            "path": item["attachment_path"],
                            "sha256": item["expected_sha256"],
                            "upload_token": token,
                        }
                    )
        return {"field_bundle_id": bundle_id, "upload_tokens": tokens, "issued_to": actor}

    def show(self, bundle_id: str) -> dict[str, Any]:
        bundle = self.store.row(
            "SELECT * FROM field_bundles WHERE field_bundle_id=?", (bundle_id,)
        )
        if not bundle:
            raise NotFoundError(f"Field Bundle not found: {bundle_id}")
        result = dict(bundle)
        result["manifest"] = json.loads(result.pop("manifest_json"))
        result["last_error"] = json.loads(result.pop("last_error_json"))
        result["events"] = []
        for raw in self.store.rows(
            "SELECT * FROM field_bundle_events WHERE field_bundle_id=? ORDER BY event_index",
            (bundle_id,),
        ):
            event = dict(raw)
            event["event"] = json.loads(event.pop("event_json"))
            event["result"] = json.loads(event.pop("result_json"))
            event["state"] = event["processing_state"]
            if event["processing_state"] == "needs_triage":
                # Keep the v9 response spelling while exposing the v10 state explicitly.
                event["processing_state"] = "triage"
            result["events"].append(event)
        result["attachments"] = self.store.rows(
            "SELECT attachment_path,expected_sha256,expected_size,mime_type,artifact_id,"
            "upload_state,received_bytes,verified_at FROM field_bundle_attachments "
            "WHERE field_bundle_id=? ORDER BY attachment_path",
            (bundle_id,),
        )
        result["receipts"] = self.receipts(bundle_id)
        return result

    def _route_action(
        self, event: dict[str, Any], manifest: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str | None]:
        payload = event["event"]
        hints = manifest.get("target_hints", {})
        if not isinstance(hints, dict):
            hints = {}
        target_issue = payload.get("target_issue_id") or payload.get("issue_id") or hints.get("issue_id")
        event_type = event["event_type"]
        if event_type == "record_patch":
            data = payload.get("data", payload.get("patch"))
            if not isinstance(data, dict):
                return None, "record_patch requires object data"
            if payload.get("record_instance_id"):
                if not payload.get("base_record_revision_id"):
                    return None, "record_base_revision_required"
                return {
                    "action_type": "record_revise",
                    "record_instance_id": str(payload["record_instance_id"]),
                    "base_record_revision_id": payload.get("base_record_revision_id"),
                    "data": data,
                    "profile": str(payload.get("profile", "draft")),
                    "evidence_links": payload.get("evidence_links", []),
                    "conflict_policy": str(
                        payload.get("conflict_policy", "create_conflict")
                    ),
                }, None
            template = payload.get("record_template") or payload.get("template_reference") or hints.get("record_template")
            if target_issue and template:
                return {
                    "action_type": "record_create", "target_issue_id": str(target_issue),
                    "template_reference": str(template), "data": data,
                    "profile": str(payload.get("profile", "draft")),
                    "evidence_links": payload.get("evidence_links", []),
                }, None
            return None, "record_patch target or template is ambiguous"
        if event_type == "evidence_locator":
            locator = payload.get("locator")
            if not isinstance(locator, str) or not locator.strip():
                return None, "evidence_locator requires locator"
            return {
                "action_type": "evidence_create", "target_issue_id": str(target_issue) if target_issue else None,
                "kind": str(payload.get("kind", "external")), "locator": locator,
                "description": str(payload.get("description", payload.get("body", ""))),
            }, None
        if not target_issue:
            return None, "event has no unambiguous target Issue"
        entry_type = {
            "question": "question", "observation": "observation",
            "interpretation": "analysis", "decision": "decision_candidate",
        }.get(event_type, "note")
        body = payload.get("body", payload.get("text", payload.get("statement")))
        if not isinstance(body, str) or not body.strip():
            body = canonical_json(payload)
        return {
            "action_type": "working_entry", "target_issue_id": str(target_issue),
            "entry_type": entry_type, "body": body,
            "evidence_refs": payload.get("evidence_refs", []),
        }, None

    def _normalize_action(self, action: dict[str, Any]) -> dict[str, Any]:
        """Validate and freeze the one action shape shared by route, triage, and apply."""
        if not isinstance(action, dict):
            raise ValidationError("Field Bundle action must be an object")
        require_strict_json(action, path="$.action")
        action_type = str(action.get("action_type", action.get("action", "")))
        if action_type not in {
            "working_entry",
            "record_create",
            "record_revise",
            "evidence_create",
        }:
            raise ValidationError(f"Unsupported Field Bundle action: {action_type!r}")
        if action_type == "record_revise":
            record_instance_id = str(action.get("record_instance_id", "")).strip()
            base_revision_id = str(action.get("base_record_revision_id", "")).strip()
            if not record_instance_id or not base_revision_id:
                raise ValidationError(
                    "record_revise requires an explicit Record and base Revision",
                    details={
                        "errors": [
                            {
                                "path": "$.base_record_revision_id",
                                "code": "record_base_revision_required",
                                "message": "base Record Revision is required",
                            }
                        ]
                    },
                )
            record = self.store.row(
                "SELECT lifecycle_status FROM record_instances WHERE record_instance_id=?",
                (record_instance_id,),
            )
            if not record:
                raise ValidationError(
                    "record_revise target Record does not exist",
                    details={"code": "record_target_missing"},
                )
            if record["lifecycle_status"] != "active":
                raise ValidationError(
                    "record_revise target Record is not active",
                    details={"code": "record_target_inactive"},
                )
            base = self.store.row(
                "SELECT record_instance_id FROM record_revisions WHERE record_revision_id=?",
                (base_revision_id,),
            )
            if not base or base["record_instance_id"] != record_instance_id:
                raise ValidationError(
                    "base Record Revision does not belong to the target Record",
                    details={"code": "record_base_revision_mismatch"},
                )
            data = action.get("data")
            if not isinstance(data, dict):
                raise ValidationError("record_revise data must be an object")
            evidence_links = action.get("evidence_links", [])
            if not isinstance(evidence_links, list):
                raise ValidationError("record_revise evidence_links must be an array")
            conflict_policy = str(action.get("conflict_policy", "create_conflict"))
            if conflict_policy != "create_conflict":
                raise ValidationError(
                    "record_revise conflict_policy must be create_conflict"
                )
            return {
                "action_type": action_type,
                "record_instance_id": record_instance_id,
                "base_record_revision_id": base_revision_id,
                "data": data,
                "profile": str(action.get("profile", "draft")),
                "evidence_links": evidence_links,
                "conflict_policy": conflict_policy,
            }
        if action_type == "record_create":
            issue_id = str(action.get("target_issue_id", "")).strip()
            reference = str(
                action.get("template_reference", action.get("record_template_registration_id", ""))
            ).strip()
            if not issue_id or not reference:
                raise ValidationError(
                    "record_create requires target_issue_id and a Record Template"
                )
            issue = self.manager._issue(issue_id)
            template = self.manager.registry.resolve(
                reference, kind="record_template", for_creation=True
            )
            applicable_ids = {
                item["target_registration_id"]
                for item in template.get("reference_locks", [])
                if item["target_kind"] == "issue_type"
                and item["json_pointer"].startswith("/applies_to_issue_types/")
            }
            if (
                template["definition"].get("applies_to_issue_types")
                and issue.get("issue_type_registration_id") not in applicable_ids
            ):
                raise ValidationError(
                    "record_create template does not apply to the target Issue type"
                )
            data = action.get("data")
            if not isinstance(data, dict):
                raise ValidationError("record_create data must be an object")
            evidence_links = action.get("evidence_links", [])
            if not isinstance(evidence_links, list):
                raise ValidationError("record_create evidence_links must be an array")
            return {
                "action_type": action_type,
                "target_issue_id": issue_id,
                "issue_type_registration_id": issue["issue_type_registration_id"],
                "issue_type_content_hash": issue["issue_type_content_hash"],
                "template_reference": template["registration_id"],
                "record_template_registration_id": template["registration_id"],
                "record_template_content_hash": template["content_hash"],
                "data": data,
                "profile": str(action.get("profile", "draft")),
                "evidence_links": evidence_links,
            }
        if action_type == "working_entry":
            issue_id = str(action.get("target_issue_id", "")).strip()
            body = str(action.get("body", ""))
            if not issue_id or not body.strip():
                raise ValidationError("working_entry requires target_issue_id and body")
            self.manager._issue(issue_id)
            evidence_refs = action.get("evidence_refs", [])
            if not isinstance(evidence_refs, list):
                raise ValidationError("working_entry evidence_refs must be an array")
            return {
                "action_type": action_type,
                "target_issue_id": issue_id,
                "entry_type": str(action.get("entry_type", "note")),
                "body": body,
                "evidence_refs": evidence_refs,
            }
        locator = str(action.get("locator", "")).strip()
        if not locator:
            raise ValidationError("evidence_create requires locator")
        evidence_issue_id = action.get("target_issue_id")
        if evidence_issue_id:
            self.manager._issue(str(evidence_issue_id))
        return {
            "action_type": action_type,
            "target_issue_id": str(evidence_issue_id) if evidence_issue_id else None,
            "kind": str(action.get("kind", "external")),
            "locator": locator,
            "description": str(action.get("description", "")),
        }

    @staticmethod
    def _action_identity(action: dict[str, Any]) -> tuple[Any, ...]:
        return (
            action.get("target_issue_id"),
            action.get("record_instance_id"),
            action.get("base_record_revision_id"),
            action.get("record_template_registration_id"),
            action.get("record_template_content_hash"),
            action.get("conflict_policy"),
            "valid",
        )

    def route(
        self,
        bundle_id: str,
        *,
        expected_revision: int | None = None,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "route staged field bundle events",
        dry_run: bool = False,
    ) -> dict[str, Any]:
        actor = self._actor(auth, "field_bundle.triage", actor)
        bundle = self.show(bundle_id)
        if bundle["state"] not in {"staged", "needs_triage", "routing", "ready"}:
            raise ConflictError(f"Field Bundle cannot be routed from state {bundle['state']}")
        if expected_revision is not None and expected_revision != bundle["routing_state_revision"]:
            raise ConflictError(
                "Field Bundle routing state changed concurrently",
                details={"expected_revision": expected_revision, "current_revision": bundle["routing_state_revision"]},
            )
        routed: list[dict[str, Any]] = []
        triage: list[dict[str, Any]] = []
        for event in bundle["events"]:
            event_state = event.get("state", event["processing_state"])
            if event_state in {"applied", "replayed", "rejected"}:
                continue
            action, problem = self._route_action(event, bundle["manifest"])
            if action:
                try:
                    action = self._normalize_action(action)
                except ValidationError as exc:
                    code = exc.details.get("code")
                    errors = exc.details.get("errors", [])
                    if not code and errors:
                        code = errors[0].get("code")
                    triage.append(
                        {
                            "field_bundle_event_id": event["field_bundle_event_id"],
                            "event_index": event["event_index"],
                            "reason": code or str(exc),
                        }
                    )
                    continue
                routed.append({"field_bundle_event_id": event["field_bundle_event_id"], "event_index": event["event_index"], "action": action})
            else:
                triage.append({"field_bundle_event_id": event["field_bundle_event_id"], "event_index": event["event_index"], "reason": problem})
        target_state = "needs_triage" if triage else "ready"
        preview = {"field_bundle_id": bundle_id, "state": target_state, "routed": routed, "needs_triage": triage}
        if dry_run:
            return {**preview, "would_write": False}
        with self.store.transaction() as conn:
            updated = conn.execute(
                "UPDATE field_bundles SET state='routing',routing_state_revision=routing_state_revision+1 "
                "WHERE field_bundle_id=? AND routing_state_revision=?",
                (bundle_id, bundle["routing_state_revision"]),
            )
            if updated.rowcount != 1:
                raise ConflictError("Field Bundle changed concurrently")
            for item in routed:
                action_hash = _hash(item["action"])
                conn.execute(
                    "INSERT OR IGNORE INTO field_bundle_event_actions("
                    "field_bundle_event_action_id,field_bundle_event_id,action_index,action_type,"
                    "action_json,action_hash,state,result_json,created_at,created_by,target_issue_id,"
                    "target_record_instance_id,base_record_revision_id,record_template_registration_id,"
                    "record_template_content_hash,conflict_policy,validation_state) "
                    "VALUES (?,?,?,?,?,?,'ready','{}',?,?,?,?,?,?,?,?,'valid')",
                    (
                        new_id("field_action"), item["field_bundle_event_id"], 0,
                        item["action"]["action_type"], canonical_json(item["action"]), action_hash,
                        now(), actor, *self._action_identity(item["action"])[:-1],
                    ),
                )
                conn.execute(
                    "UPDATE field_bundle_events SET processing_state='ready',state_revision=state_revision+1,"
                    "result_json=? WHERE field_bundle_event_id=?",
                    (canonical_json({"action": item["action"]}), item["field_bundle_event_id"]),
                )
            for item in triage:
                conn.execute(
                    "UPDATE field_bundle_events SET processing_state='needs_triage',"
                    "state_revision=state_revision+1,result_json=? WHERE field_bundle_event_id=?",
                    (canonical_json({"action": "needs_triage", "reason": item["reason"]}), item["field_bundle_event_id"]),
                )
            conn.execute(
                "UPDATE field_bundles SET state=? WHERE field_bundle_id=?",
                (target_state, bundle_id),
            )
            event_id = self.store.audit(
                conn, actor=actor, action="field_bundle.route", object_type="field_bundle",
                object_id=bundle_id, before_revision=bundle["routing_state_revision"],
                after_revision=bundle["routing_state_revision"] + 1, reason=reason, payload=preview,
            )
        return {**preview, "event_id": event_id, "would_write": True}

    def triage(
        self,
        field_bundle_event_id: str,
        decision: dict[str, Any] | str,
        *,
        expected_revision: int,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "resolve Field Bundle event triage",
    ) -> dict[str, Any]:
        actor = self._actor(auth, "field_bundle.triage", actor)
        event = self.store.row(
            "SELECT * FROM field_bundle_events WHERE field_bundle_event_id=?",
            (field_bundle_event_id,),
        )
        if not event:
            raise NotFoundError(f"Field Bundle event not found: {field_bundle_event_id}")
        if int(event["state_revision"]) != expected_revision:
            raise ConflictError(
                "Field Bundle event changed concurrently",
                details={"expected_revision": expected_revision, "current_revision": event["state_revision"]},
            )
        if event["processing_state"] != "needs_triage":
            raise ConflictError(f"Field Bundle event is not awaiting triage: {event['processing_state']}")
        normalized = {"action": decision} if isinstance(decision, str) else dict(decision)
        action_name = str(normalized.get("action", ""))
        requested_actions = normalized.get("actions")
        if requested_actions is not None and (
            not isinstance(requested_actions, list)
            or not requested_actions
            or not all(isinstance(item, dict) for item in requested_actions)
        ):
            raise ValidationError("Field Bundle split triage actions must be a non-empty object array")
        if action_name == "reject":
            target_state, actions = "rejected", []
        elif requested_actions is not None:
            actions = [self._normalize_action(dict(item)) for item in requested_actions]
            target_state = "ready"
        elif action_name in {"working_entry", "record_create", "record_revise", "evidence_create"}:
            candidate = {key: value for key, value in normalized.items() if key != "action"}
            candidate["action_type"] = action_name
            actions = [self._normalize_action(candidate)]
            target_state = "ready"
        else:
            raise ValidationError(f"Unsupported Field Bundle triage decision: {action_name!r}")
        with self.store.transaction() as conn:
            if actions:
                existing_count = int(conn.execute(
                    "SELECT COUNT(*) FROM field_bundle_event_actions WHERE field_bundle_event_id=?",
                    (field_bundle_event_id,),
                ).fetchone()[0])
                for offset, action in enumerate(actions):
                    conn.execute(
                        "INSERT INTO field_bundle_event_actions("
                        "field_bundle_event_action_id,field_bundle_event_id,action_index,action_type,"
                        "action_json,action_hash,state,result_json,created_at,created_by,target_issue_id,"
                        "target_record_instance_id,base_record_revision_id,record_template_registration_id,"
                        "record_template_content_hash,conflict_policy,validation_state) "
                        "VALUES (?,?,?,?,?,?,'ready','{}',?,?,?,?,?,?,?,?,'valid')",
                        (
                            new_id("field_action"), field_bundle_event_id,
                            existing_count + offset, action["action_type"],
                            canonical_json(action), _hash(action), now(), actor,
                            *self._action_identity(action)[:-1],
                        ),
                    )
            updated = conn.execute(
                "UPDATE field_bundle_events SET processing_state=?,state_revision=state_revision+1,"
                "result_json=? WHERE field_bundle_event_id=? AND state_revision=?",
                (target_state, canonical_json({"triage_decision": normalized}), field_bundle_event_id, expected_revision),
            )
            if updated.rowcount != 1:
                raise ConflictError("Field Bundle event changed concurrently")
            remaining = int(conn.execute(
                "SELECT COUNT(*) FROM field_bundle_events WHERE field_bundle_id=? "
                "AND processing_state='needs_triage' AND field_bundle_event_id<>?",
                (event["field_bundle_id"], field_bundle_event_id),
            ).fetchone()[0])
            conn.execute(
                "UPDATE field_bundles SET state=?,routing_state_revision=routing_state_revision+1 "
                "WHERE field_bundle_id=?",
                ("needs_triage" if remaining else "ready", event["field_bundle_id"]),
            )
            audit_id = self.store.audit(
                conn, actor=actor, action="field_bundle.triage", object_type="field_bundle_event",
                object_id=field_bundle_event_id, before_revision=expected_revision,
                after_revision=expected_revision + 1, reason=reason, payload=normalized,
            )
        return {"field_bundle_event_id": field_bundle_event_id, "state": target_state, "state_revision": expected_revision + 1, "event_id": audit_id}

    def _apply_action(
        self,
        event: dict[str, Any],
        action_row: dict[str, Any],
        action: dict[str, Any] | str,
        actor: str | None = None,
    ) -> dict[str, Any]:
        # Preserve the old private test/helper shape: _apply_action(event, action, actor).
        if actor is None and isinstance(action, str):
            actor = action
            action = action_row
            normalized_for_row = self._normalize_action(action)
            action_row = {
                "field_bundle_event_action_id": "direct-validation",
                "action_hash": _hash(normalized_for_row),
                "target_issue_id": self._action_identity(normalized_for_row)[0],
                "target_record_instance_id": self._action_identity(normalized_for_row)[1],
                "base_record_revision_id": self._action_identity(normalized_for_row)[2],
                "record_template_registration_id": self._action_identity(normalized_for_row)[3],
                "record_template_content_hash": self._action_identity(normalized_for_row)[4],
                "conflict_policy": self._action_identity(normalized_for_row)[5],
                "validation_state": self._action_identity(normalized_for_row)[6],
            }
        if not isinstance(action, dict) or actor is None:
            raise ValidationError("Field Action and actor are required")
        normalized = self._normalize_action(action)
        if _hash(normalized) != action_row["action_hash"]:
            raise ConflictError("Stored Field Action does not match its normalized hash")
        explicit = self._action_identity(normalized)
        stored = (
            action_row.get("target_issue_id"),
            action_row.get("target_record_instance_id"),
            action_row.get("base_record_revision_id"),
            action_row.get("record_template_registration_id"),
            action_row.get("record_template_content_hash"),
            action_row.get("conflict_policy"),
            action_row.get("validation_state"),
        )
        if explicit != stored:
            raise ConflictError("Stored Field Action identity columns drifted from action_json")
        action = normalized
        action_type = action["action_type"]
        idempotency_key = f"field:{event['event_hash']}:{_hash(action)}"
        if action_type == "working_entry":
            return self.manager.append_work(
                str(action.get("target_issue_id", "")), str(action.get("body", "")),
                entry_type=str(action.get("entry_type", "note")),
                evidence_refs=action.get("evidence_refs", []), actor=actor,
                reason="Field Bundle routed Working Entry", idempotency_key=idempotency_key,
            )
        if action_type == "evidence_create":
            return self.manager.add_evidence(
                kind=str(action.get("kind", "external")), locator=str(action.get("locator", "")),
                issue_id=action.get("target_issue_id"), description=str(action.get("description", "")),
                actor=actor, reason="Field Bundle declared Evidence", idempotency_key=idempotency_key,
            )
        if action_type == "record_create":
            return self.manager.records.create(
                str(action.get("target_issue_id", "")), str(action.get("template_reference", "")),
                data=action.get("data", {}), profile=str(action.get("profile", "draft")),
                evidence_links=action.get("evidence_links", []), source_mode="field_bundle",
                actor=actor, reason="Field Bundle created Record",
            )
        if action_type == "record_revise":
            current = self.store.row(
                "SELECT current_revision_id FROM record_instances WHERE record_instance_id=?",
                (action["record_instance_id"],),
            )
            if not current:
                raise ConflictError("Field Action target Record disappeared")
            if current["current_revision_id"] != action["base_record_revision_id"]:
                conflict_id = "conflict_" + hashlib.sha256(
                    f"field_bundle:{action_row['field_bundle_event_action_id']}:"
                    f"{action_row['action_hash']}".encode("utf-8")
                ).hexdigest()[:32]
                self.store.conn.execute(
                    "INSERT OR IGNORE INTO integration_conflicts("
                    "integration_conflict_id,source_kind,source_job_id,source_item_id,"
                    "source_namespace,source_owner,external_object_type,external_object_id,"
                    "existing_mapping_id,existing_internal_revision_id,previous_external_hash,"
                    "candidate_external_hash,raw_fragment_json,mapped_candidate_json,"
                    "mapping_registration_id,mapping_content_hash,state,state_revision,"
                    "resolution_action,resolution_reason,detected_at,detected_by,resolved_at,resolved_by) "
                    "SELECT ?, 'field_bundle',e.field_bundle_id,?,b.source_namespace,b.source_owner,"
                    "'record_revision',?,NULL,?,?,?,e.event_json,?,NULL,NULL,'open',0,NULL,'',?,?,"
                    "NULL,NULL FROM field_bundle_events e JOIN field_bundles b "
                    "ON b.field_bundle_id=e.field_bundle_id WHERE e.field_bundle_event_id=?",
                    (
                        conflict_id,
                        action_row["field_bundle_event_action_id"],
                        action["record_instance_id"],
                        current["current_revision_id"],
                        action["base_record_revision_id"],
                        action_row["action_hash"],
                        canonical_json(action),
                        now(),
                        actor,
                        event["field_bundle_event_id"],
                    ),
                )
                return {
                    "state": "conflicted",
                    "integration_conflict_id": conflict_id,
                    "record_instance_id": action["record_instance_id"],
                    "base_record_revision_id": action["base_record_revision_id"],
                    "current_record_revision_id": current["current_revision_id"],
                    "normalized_action_hash": action_row["action_hash"],
                }
            return self.manager.records.revise(
                str(action.get("record_instance_id", "")), action.get("data", {}),
                expected_revision_id=action.get("base_record_revision_id"),
                profile=str(action.get("profile", "draft")),
                evidence_links=action.get("evidence_links", []), source_mode="field_bundle",
                actor=actor, reason="Field Bundle revised Record",
            )
        raise ValidationError(f"Unsupported routed Field Bundle action: {action_type}")

    def _apply_once(
        self,
        bundle_id: str,
        *,
        expected_revision: int | None = None,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "apply routed Field Bundle atomically",
    ) -> dict[str, Any]:
        actor = self._actor(auth, "field_bundle.apply", actor)
        bundle = self.show(bundle_id)
        if bundle["state"] == "applied":
            return {"field_bundle_id": bundle_id, "state": "applied", "receipts": bundle["receipts"], "idempotent_replay": True}
        if bundle["state"] == "staged":
            self.route(bundle_id, expected_revision=bundle["routing_state_revision"], actor=actor, auth=auth)
            bundle = self.show(bundle_id)
        if bundle["state"] != "ready":
            raise ConflictError(f"Field Bundle is not ready to apply: {bundle['state']}")
        if expected_revision is not None and expected_revision != bundle["routing_state_revision"]:
            raise ConflictError("Field Bundle changed concurrently")
        results: list[dict[str, Any]] = []
        with self.store.transaction() as conn:
            updated = conn.execute(
                "UPDATE field_bundles SET state='applying' WHERE field_bundle_id=? AND state='ready'",
                (bundle_id,),
            )
            if updated.rowcount != 1:
                raise ConflictError("Field Bundle changed concurrently")
            for event in bundle["events"]:
                event_state = event.get("state", event["processing_state"])
                if event_state == "rejected":
                    results.append({"event_index": event["event_index"], "state": "rejected"})
                    continue
                if event_state in {"applied", "replayed"}:
                    results.append({"event_index": event["event_index"], "state": "replayed", "result": event["result"]})
                    continue
                actions = conn.execute(
                    "SELECT * FROM field_bundle_event_actions WHERE field_bundle_event_id=? "
                    "ORDER BY action_index",
                    (event["field_bundle_event_id"],),
                ).fetchall()
                event_results = []
                for raw_action in actions:
                    action_row = dict(raw_action)
                    action = json.loads(action_row["action_json"])
                    result = self._apply_action(event, action_row, action, actor)
                    event_results.append(result)
                    action_state = "conflicted" if result.get("state") == "conflicted" else "applied"
                    conn.execute(
                        "UPDATE field_bundle_event_actions SET state=?,result_json=? "
                        "WHERE field_bundle_event_action_id=?",
                        (action_state, canonical_json(result), action_row["field_bundle_event_action_id"]),
                    )
                primary = event_results[-1] if event_results else {}
                object_type = next((key.removesuffix("_id") for key in primary if key.endswith("_id") and key not in {"event_id"}), None)
                object_id = primary.get(f"{object_type}_id") if object_type else None
                event_conflicted = any(item.get("state") == "conflicted" for item in event_results)
                conn.execute(
                    "UPDATE field_bundle_events SET processing_state=?,result_json=?,"
                    "target_object_type=?,target_object_id=?,state_revision=state_revision+1 "
                    "WHERE field_bundle_event_id=?",
                    (
                        "needs_triage" if event_conflicted else "applied",
                        canonical_json(event_results), object_type, object_id,
                        event["field_bundle_event_id"],
                    ),
                )
                results.append({"event_index": event["event_index"], "state": "conflicted" if event_conflicted else "applied", "results": event_results})
                self.store.fault(f"field_bundle.apply.after_event.{event['event_index']}")
            has_conflicts = any(item["state"] == "conflicted" for item in results)
            final_state = "needs_triage" if has_conflicts else "applied"
            receipt_result = {"field_bundle_id": bundle_id, "state": final_state, "events": results}
            receipt_hash = _hash(receipt_result)
            receipt_id = new_id("field_receipt")
            cursor = int((conn.execute("SELECT COALESCE(MAX(activity_sequence),0) FROM activity_events").fetchone() or [0])[0])
            conn.execute(
                "INSERT INTO field_bundle_receipts VALUES (?,?,?,?,?,?,?,?)",
                (receipt_id, bundle_id, bundle["content_hash"], canonical_json(receipt_result), receipt_hash, cursor, now(), actor),
            )
            conn.execute(
                "UPDATE field_bundles SET state=?,apply_cursor=?,routing_state_revision=routing_state_revision+1 "
                "WHERE field_bundle_id=?",
                (final_state, len(results), bundle_id),
            )
            event_id = self.store.audit(
                conn, actor=actor, action="field_bundle.apply", object_type="field_bundle",
                object_id=bundle_id, before_revision=bundle["routing_state_revision"],
                after_revision=bundle["routing_state_revision"] + 1, reason=reason,
                payload={**receipt_result, "receipt_hash": receipt_hash},
            )
        return {**receipt_result, "field_bundle_receipt_id": receipt_id, "receipt_hash": receipt_hash, "event_id": event_id, "idempotent_replay": False}

    def apply(
        self,
        bundle_id: str,
        *,
        expected_revision: int | None = None,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "apply routed Field Bundle atomically",
    ) -> dict[str, Any]:
        """Apply one atomic bundle and leave an explicit retry path after failures."""
        bundle = self.show(bundle_id)
        if bundle["state"] == "applied":
            return {
                "field_bundle_id": bundle_id,
                "state": "applied",
                "receipts": bundle["receipts"],
                "idempotent_replay": True,
            }
        if bundle["state"] == "staged":
            self.route(
                bundle_id,
                expected_revision=bundle["routing_state_revision"],
                actor=actor,
                auth=auth,
            )
            bundle = self.show(bundle_id)
        if bundle["state"] != "ready":
            raise ConflictError(f"Field Bundle is not ready to apply: {bundle['state']}")
        if (
            expected_revision is not None
            and expected_revision != bundle["routing_state_revision"]
        ):
            raise ConflictError("Field Bundle changed concurrently")
        from .integrity import assert_not_quarantined

        assert_not_quarantined(
            self.store.conn,
            "field_bundle",
            bundle_id,
            "block_integration_apply",
        )
        for action in self.store.rows(
            "SELECT a.field_bundle_event_action_id FROM field_bundle_event_actions a "
            "JOIN field_bundle_events e ON e.field_bundle_event_id=a.field_bundle_event_id "
            "WHERE e.field_bundle_id=? ORDER BY e.event_index,a.action_index",
            (bundle_id,),
        ):
            assert_not_quarantined(
                self.store.conn,
                "field_bundle_action",
                str(action["field_bundle_event_action_id"]),
                "block_integration_apply",
            )
        try:
            return self._apply_once(
                bundle_id,
                expected_revision=bundle["routing_state_revision"],
                actor=actor,
                auth=auth,
                reason=reason,
            )
        except Exception as exc:
            failure = {"error_type": type(exc).__name__, "message": str(exc)}
            failed_actor = self._actor(auth, "field_bundle.apply", actor)
            with self.store.transaction() as conn:
                current = conn.execute(
                    "SELECT state,routing_state_revision FROM field_bundles "
                    "WHERE field_bundle_id=?",
                    (bundle_id,),
                ).fetchone()
                if current and current["state"] == "ready":
                    conn.execute(
                        "UPDATE field_bundles SET state='failed',last_error_json=?,"
                        "routing_state_revision=routing_state_revision+1 "
                        "WHERE field_bundle_id=? AND state='ready'",
                        (canonical_json(failure), bundle_id),
                    )
                    conn.execute(
                        "UPDATE field_bundle_events SET processing_state='failed',"
                        "state_revision=state_revision+1,result_json=? "
                        "WHERE field_bundle_id=? AND processing_state='ready'",
                        (canonical_json(failure), bundle_id),
                    )
                    self.store.audit(
                        conn,
                        actor=failed_actor,
                        action="field_bundle.apply_failed",
                        object_type="field_bundle",
                        object_id=bundle_id,
                        before_revision=int(current["routing_state_revision"]),
                        after_revision=int(current["routing_state_revision"]) + 1,
                        reason=reason,
                        payload=failure,
                    )
            raise

    def retry(
        self,
        bundle_id: str,
        *,
        expected_revision: int,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "retry failed Field Bundle",
    ) -> dict[str, Any]:
        actor = self._actor(auth, "field_bundle.triage", actor)
        bundle = self.show(bundle_id)
        if bundle["state"] != "failed" or bundle["routing_state_revision"] != expected_revision:
            raise ConflictError("Field Bundle is not retryable at the expected revision")
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE field_bundle_events SET processing_state='staged',state_revision=state_revision+1 "
                "WHERE field_bundle_id=? AND processing_state='failed'",
                (bundle_id,),
            )
            conn.execute(
                "UPDATE field_bundles SET state='staged',last_error_json='{}',"
                "routing_state_revision=routing_state_revision+1 WHERE field_bundle_id=?",
                (bundle_id,),
            )
            event_id = self.store.audit(
                conn, actor=actor, action="field_bundle.retry", object_type="field_bundle",
                object_id=bundle_id, before_revision=expected_revision,
                after_revision=expected_revision + 1, reason=reason, payload={},
            )
        return {"field_bundle_id": bundle_id, "state": "staged", "routing_state_revision": expected_revision + 1, "event_id": event_id}

    def receipts(self, bundle_id: str) -> list[dict[str, Any]]:
        receipts = self.store.rows(
            "SELECT * FROM field_bundle_receipts WHERE field_bundle_id=? ORDER BY created_at",
            (bundle_id,),
        )
        for receipt in receipts:
            receipt["result"] = json.loads(receipt.pop("result_json"))
        return receipts

    def conflicts(self, bundle_id: str) -> list[dict[str, Any]]:
        if not self.store.row(
            "SELECT 1 FROM field_bundles WHERE field_bundle_id=?", (bundle_id,)
        ):
            raise NotFoundError(f"Field Bundle not found: {bundle_id}")
        rows = self.store.rows(
            "SELECT * FROM integration_conflicts WHERE source_kind='field_bundle' "
            "AND source_job_id=? ORDER BY detected_at,integration_conflict_id",
            (bundle_id,),
        )
        for row in rows:
            row["raw_fragment"] = json.loads(row.pop("raw_fragment_json"))
            row["mapped_candidate"] = json.loads(row.pop("mapped_candidate_json"))
            row["resolutions"] = self.store.rows(
                "SELECT * FROM integration_conflict_resolutions "
                "WHERE integration_conflict_id=? ORDER BY to_revision",
                (row["integration_conflict_id"],),
            )
            for resolution in row["resolutions"]:
                resolution["details"] = json.loads(resolution.pop("details_json"))
        return rows

    def propose_resolution(
        self,
        conflict_id: str,
        action: str,
        *,
        resolution_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        operation = build_resolution_operation(
            self.store,
            "field_bundle",
            conflict_id,
            action,
            resolution_payload=resolution_payload,
        )
        return {
            "conflict_id": conflict_id,
            "operation": operation,
            "changeset": {
                "changeset_version": 1,
                "intent": f"Resolve Field conflict {conflict_id}",
                "operations": [operation],
            },
        }

    def resolution_receipt(self, conflict_id: str) -> dict[str, Any]:
        receipt = self.store.row(
            "SELECT * FROM governed_conflict_resolution_receipts "
            "WHERE conflict_domain='field_bundle' AND conflict_id=?",
            (conflict_id,),
        )
        if not receipt:
            raise NotFoundError(f"Field conflict resolution receipt not found: {conflict_id}")
        receipt["review_ids"] = json.loads(receipt.pop("review_ids_json"))
        return receipt

    def resolve_conflict(
        self,
        conflict_id: str,
        decision: dict[str, Any] | str,
        *,
        expected_revision: int,
        reviewed_changeset_id: str | None = None,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "resolve Field Bundle Record conflict",
        _governance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        actor = self._actor(auth, "field_bundle.triage", actor)
        conflict = self.store.row(
            "SELECT * FROM integration_conflicts WHERE integration_conflict_id=? "
            "AND source_kind='field_bundle'",
            (conflict_id,),
        )
        if not conflict:
            raise NotFoundError(f"Field Bundle conflict not found: {conflict_id}")
        if int(conflict["state_revision"]) != expected_revision:
            raise ConflictError(
                "Field Bundle conflict changed concurrently",
                details={
                    "expected_revision": expected_revision,
                    "current_revision": conflict["state_revision"],
                },
            )
        if conflict["state"] not in {"open", "needs_more_information"}:
            return {
                "integration_conflict_id": conflict_id,
                "state": conflict["state"],
                "idempotent_replay": True,
            }
        normalized = {"action": decision} if isinstance(decision, str) else dict(decision)
        action = str(normalized.get("action", ""))
        supported = {
            "accept_as_new_revision",
            "create_competing_record",
            "keep_internal",
            "needs_more_information",
            "reject_candidate",
        }
        if action not in supported:
            raise ValidationError(
                f"Unsupported Field Bundle conflict resolution: {action!r}"
            )
        action_row = self.store.row(
            "SELECT a.*,e.field_bundle_event_id,e.field_bundle_id FROM "
            "field_bundle_event_actions a JOIN field_bundle_events e "
            "ON e.field_bundle_event_id=a.field_bundle_event_id "
            "WHERE a.field_bundle_event_action_id=?",
            (conflict["source_item_id"],),
        )
        if not action_row:
            raise ConflictError("Field Bundle conflict source Action is missing")
        candidate = json.loads(action_row["action_json"])
        record_instance_id = str(candidate["record_instance_id"])
        instance = self.store.row(
            "SELECT * FROM record_instances WHERE record_instance_id=?",
            (record_instance_id,),
        )
        if not instance:
            raise ConflictError("Field Bundle conflict target Record is missing")
        result: dict[str, Any] = {}
        target_state = "resolved"
        action_state = "rejected"
        event_state = "rejected"
        with self.store.transaction() as conn:
            from .integrity import assert_not_quarantined

            assert_not_quarantined(
                conn,
                "integration_conflict",
                conflict_id,
                "block_integration_apply",
            )
            assert_not_quarantined(
                conn,
                "field_bundle_action",
                str(action_row["field_bundle_event_action_id"]),
                "block_integration_apply",
            )
            if _governance is not None:
                validate_resolution_binding(conn, "field_bundle", _governance["operation"])
                governed_payload = {
                    key: value for key, value in normalized.items() if key != "action"
                }
                if (
                    _governance["operation"]["resolution"] != action
                    or _governance["operation"]["resolution_payload_hash"]
                    != content_hash(governed_payload)
                ):
                    raise ValidationError(
                        "Field conflict decision does not match the governed ChangeSet operation"
                    )
            current = conn.execute(
                "SELECT r.validation_profile,i.current_revision_id FROM record_instances i "
                "JOIN record_revisions r ON r.record_revision_id=i.current_revision_id "
                "WHERE i.record_instance_id=?",
                (record_instance_id,),
            ).fetchone()
            if not current:
                raise ConflictError("Field Bundle conflict target Record is missing")
            used_in_report = conn.execute(
                "SELECT 1 FROM report_build_inputs WHERE object_type='record_revision' "
                "AND object_id=? LIMIT 1",
                (current["current_revision_id"],),
            ).fetchone()
            formal = bool(
                current["validation_profile"] in {"accepted", "canonical", "report"}
                or used_in_report
            )
            if formal and _governance is None:
                proposed = build_resolution_operation(
                    self.store,
                    "field_bundle",
                    conflict_id,
                    action,
                    resolution_payload={
                        key: value for key, value in normalized.items() if key != "action"
                    },
                )
                raise ReviewRequiredError(
                    "Resolving a formal or reported Record conflict requires an exact reviewed ChangeSet operation",
                    details={
                        "code": "governed_conflict_changeset_required",
                        "deprecated_reviewed_changeset_id": reviewed_changeset_id,
                        "proposed_operation": proposed,
                    },
                )
            if action in {"accept_as_new_revision", "create_competing_record"}:
                if action == "accept_as_new_revision":
                    result = self.manager.records.revise(
                        record_instance_id,
                        candidate["data"],
                        expected_revision_id=current["current_revision_id"],
                        profile=str(candidate.get("profile", "draft")),
                        evidence_links=candidate.get("evidence_links", []),
                        source_mode="field_bundle",
                        actor=actor,
                        reason=reason,
                    )
                else:
                    result = self.manager.records.create(
                        instance["issue_id"],
                        instance["record_template_registration_id"],
                        data=candidate["data"],
                        profile=str(candidate.get("profile", "draft")),
                        evidence_links=candidate.get("evidence_links", []),
                        source_mode="field_bundle",
                        actor=actor,
                        reason=reason,
                    )
                action_state = "applied"
                event_state = "applied"
            elif action == "needs_more_information":
                target_state = "needs_more_information"
                action_state = "conflicted"
                event_state = "needs_triage"
            resolution_id = new_id("conflict_resolution")
            conn.execute(
                "INSERT INTO integration_conflict_resolutions VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    resolution_id,
                    conflict_id,
                    expected_revision,
                    expected_revision + 1,
                    action,
                    reason,
                    canonical_json({**normalized, "result": result}),
                    _governance["changeset_id"] if _governance else None,
                    now(),
                    actor,
                ),
            )
            updated = conn.execute(
                "UPDATE integration_conflicts SET state=?,state_revision=state_revision+1,"
                "resolution_action=?,resolution_reason=?,resolved_at=?,resolved_by=? "
                "WHERE integration_conflict_id=? AND state_revision=?",
                (
                    target_state,
                    action,
                    reason,
                    now() if target_state == "resolved" else None,
                    actor if target_state == "resolved" else None,
                    conflict_id,
                    expected_revision,
                ),
            )
            if updated.rowcount != 1:
                raise ConflictError("Field Bundle conflict changed concurrently")
            conn.execute(
                "UPDATE field_bundle_event_actions SET state=?,result_json=? "
                "WHERE field_bundle_event_action_id=?",
                (action_state, canonical_json(result), action_row["field_bundle_event_action_id"]),
            )
            conn.execute(
                "UPDATE field_bundle_events SET processing_state=?,result_json=?,"
                "state_revision=state_revision+1 WHERE field_bundle_event_id=?",
                (
                    event_state,
                    canonical_json({"conflict_resolution": action, "result": result}),
                    action_row["field_bundle_event_id"],
                ),
            )
            unresolved = int(
                conn.execute(
                    "SELECT COUNT(*) FROM integration_conflicts WHERE source_kind='field_bundle' "
                    "AND source_job_id=? AND state<>'resolved'",
                    (conflict["source_job_id"],),
                ).fetchone()[0]
            )
            pending = int(
                conn.execute(
                    "SELECT COUNT(*) FROM field_bundle_events WHERE field_bundle_id=? "
                    "AND processing_state IN ('pending','staged','ready','needs_triage','failed')",
                    (conflict["source_job_id"],),
                ).fetchone()[0]
            )
            bundle_state = "needs_triage" if unresolved or pending else "applied"
            conn.execute(
                "UPDATE field_bundles SET state=?,routing_state_revision=routing_state_revision+1 "
                "WHERE field_bundle_id=?",
                (bundle_state, conflict["source_job_id"]),
            )
            audit_id = self.store.audit(
                conn,
                actor=actor,
                action="field_bundle.conflict.resolve",
                object_type="integration_conflict",
                object_id=conflict_id,
                before_revision=expected_revision,
                after_revision=expected_revision + 1,
                reason=reason,
                payload={"action": action, "state": target_state, "result": result},
            )
            governed_receipt = None
            if _governance is not None:
                governed_receipt = insert_governed_receipt(
                    conn,
                    domain="field_bundle",
                    operation=_governance["operation"],
                    changeset_id=_governance["changeset_id"],
                    changeset_hash=_governance["changeset_hash"],
                    operation_ordinal=int(_governance["operation_ordinal"]),
                    operation_hash=_governance["operation_hash"],
                    review_ids=list(_governance["review_ids"]),
                    result=result,
                    actor=actor,
                    event_id=audit_id,
                )
        return {
            "integration_conflict_id": conflict_id,
            "state": target_state,
            "state_revision": expected_revision + 1,
            "action": action,
            "result": result,
            "event_id": audit_id,
            "governed_resolution_receipt": governed_receipt,
            "idempotent_replay": False,
        }

    def catch_up(
        self,
        source: str | Path,
        *,
        source_namespace: str,
        source_owner: str,
        scope: dict[str, Any],
        time_range: dict[str, Any],
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        root = Path(source).resolve()
        files = [root] if root.is_file() else sorted(path for path in root.rglob("*") if path.is_file())
        if not files:
            raise ValidationError("Catch-up source contains no files")
        events: list[dict[str, Any]] = []
        for index, path in enumerate(files):
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                text = ""
            events.append(
                {
                    "event_id": f"catch-up-{index}",
                    "event_type": "observation",
                    "body": text,
                    "source_path": str(path.relative_to(root) if root.is_dir() else path.name),
                    "source_sha256": sha256_file(path),
                    "scope": scope,
                    "time_range": time_range,
                    "catch_up": True,
                }
            )
        manifest_seed = {
            "source_namespace": source_namespace,
            "source_owner": source_owner,
            "scope": scope,
            "time_range": time_range,
            "event_hashes": [_hash(event) for event in events],
        }
        bundle_id = f"field-catchup-{_hash(manifest_seed)[:24]}"
        bundle = {
            "manifest": {
                "bundle_id": bundle_id,
                "bundle_version": FIELD_BUNDLE_VERSION,
                "created_by": actor,
                "created_at": now(),
                "source_namespace": source_namespace,
                "source_owner": source_owner,
                "target_hints": scope,
                "catch_up": True,
                "attachments": [],
            },
            "events": events,
        }
        return self.upload(bundle, actor=actor, auth=auth, reason="catch-up offline notes", dry_run=dry_run)
