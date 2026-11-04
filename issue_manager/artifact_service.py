from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import (
    AnalysisPlatformMismatchError,
    ArtifactPlatformMismatchError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from .security import AuthContext, CredentialResolver
from .store import canonical_json, new_id, now, sha256_file

if TYPE_CHECKING:
    from .service import IssueManager


ROLE_ORDER = {"scratch": 0, "evidence": 1, "frozen": 2}


class ArtifactService:
    def __init__(self, manager: "IssueManager"):
        self.manager = manager
        self.store = manager.store
        self.credentials = CredentialResolver(self.store)

    def add(
        self,
        path: str | Path,
        *,
        role: str,
        kind: str | None = None,
        credential: str | Path,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "artifact.manage")
        if role not in ROLE_ORDER:
            raise ValidationError("Artifact role must be scratch, evidence, or frozen")
        source = Path(path).resolve()
        if not source.is_file():
            raise ValidationError(f"Artifact source is not a file: {source}")
        digest = sha256_file(source)
        request_payload = {
            "path": str(source),
            "sha256": digest,
            "role": role,
            "kind": kind,
        }
        replay = self.store.idempotency_lookup("artifact.add", idempotency_key, request_payload)
        if replay:
            return {**replay, "idempotent_replay": True}
        existing = self.store.row("SELECT * FROM artifacts WHERE sha256=?", (digest,))
        mime_type = mimetypes.guess_type(source.name)[0] or "application/octet-stream"
        artifact_id = existing["artifact_id"] if existing else new_id("artifact")
        object_path = self._object_path(digest)
        object_path.parent.mkdir(parents=True, exist_ok=True)
        if not object_path.exists():
            temp_path = object_path.with_suffix(f".tmp-{os.getpid()}-{new_id('copy')}")
            shutil.copyfile(source, temp_path)
            if sha256_file(temp_path) != digest:
                temp_path.unlink(missing_ok=True)
                raise ValidationError("Artifact changed while being copied")
            self.store.fault("artifact.after_temp_copy")
            os.replace(temp_path, object_path)
            self.store.fault("artifact.after_object_placed")
        elif sha256_file(object_path) != digest:
            raise ConflictError(f"Content-addressed object is corrupt: {object_path}")
        effective_role = role
        if existing and ROLE_ORDER[existing["role"]] > ROLE_ORDER[role]:
            effective_role = existing["role"]
        result = {
            "artifact_id": artifact_id,
            "sha256": digest,
            "size": source.stat().st_size,
            "role": effective_role,
            "storage_uri": object_path.relative_to(self.store.ledger_dir).as_posix(),
            "deduplicated": bool(existing),
        }
        with self.store.transaction() as conn:
            locked_value = conn.execute(
                "SELECT * FROM artifacts WHERE sha256=?", (digest,)
            ).fetchone()
            locked_existing = dict(locked_value) if locked_value else None
            if locked_existing:
                artifact_id = locked_existing["artifact_id"]
                result["artifact_id"] = artifact_id
                result["deduplicated"] = True
                if ROLE_ORDER[str(locked_existing["role"])] > ROLE_ORDER[str(result["role"])]:
                    result["role"] = locked_existing["role"]
            if not locked_existing:
                conn.execute(
                    "INSERT INTO artifacts("
                    "artifact_id,kind,role,mime_type,sha256,size,storage_uri,original_locator,"
                    "created_at,created_by,frozen_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        artifact_id,
                        kind or source.suffix.lstrip(".") or "file",
                        role,
                        mime_type,
                        digest,
                        source.stat().st_size,
                        result["storage_uri"],
                        str(source),
                        now(),
                        auth.actor_id,
                        now() if role == "frozen" else None,
                    ),
                )
            elif ROLE_ORDER[role] > ROLE_ORDER[locked_existing["role"]]:
                conn.execute(
                    "UPDATE artifacts SET role=?,frozen_at=CASE WHEN ?='frozen' THEN ? ELSE frozen_at END "
                    "WHERE artifact_id=?",
                    (role, role, now(), artifact_id),
                )
                result["role"] = role
            conn.execute(
                "INSERT OR IGNORE INTO artifact_locations VALUES (?,?,?)",
                (artifact_id, str(source), now()),
            )
            self.store.idempotency_record(
                conn, "artifact.add", idempotency_key, request_payload, result
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="artifact.add",
                object_type="artifact",
                object_id=artifact_id,
                before_revision=None,
                after_revision=1,
                reason="",
                payload=result,
            )
        if role == "frozen":
            self._write_manifest(artifact_id)
        return result

    def _object_path(self, digest: str) -> Path:
        return self.store.ledger_dir / "artifacts" / "objects" / "sha256" / digest[:2] / digest

    def add_scoped_content(
        self,
        content: bytes,
        *,
        filename: str,
        mime_type: str,
        role: str,
        auth: AuthContext,
    ) -> dict[str, Any]:
        """Register a bounded platform upload without exposing a server filesystem path."""
        auth.require("artifact.manage-scoped")
        if not auth.platform_id:
            raise ValidationError("Scoped Artifact registration requires a platform principal")
        if role not in {"evidence", "frozen"}:
            raise ValidationError("Platform Artifacts must use evidence or frozen role")
        if not content or len(content) > 10 * 1024 * 1024:
            raise ValidationError("Platform Artifact must be between 1 byte and 10 MiB")
        digest = hashlib.sha256(content).hexdigest()
        object_path = self._object_path(digest)
        object_path.parent.mkdir(parents=True, exist_ok=True)
        if object_path.exists():
            if sha256_file(object_path) != digest:
                raise ConflictError(f"Content-addressed object is corrupt: {object_path}")
        else:
            temporary = object_path.with_suffix(f".tmp-{os.getpid()}-{new_id('upload')}")
            temporary.write_bytes(content)
            if sha256_file(temporary) != digest:
                temporary.unlink(missing_ok=True)
                raise ValidationError("Uploaded Artifact hash changed while being stored")
            self.store.fault("artifact.after_temp_copy")
            os.replace(temporary, object_path)
            self.store.fault("artifact.after_object_placed")
        existing = self.store.row("SELECT * FROM artifacts WHERE sha256=?", (digest,))
        artifact_id = existing["artifact_id"] if existing else new_id("artifact")
        locator = f"platform:{auth.platform_id}:{filename}"
        effective_role = role
        if existing and ROLE_ORDER[existing["role"]] > ROLE_ORDER[role]:
            effective_role = existing["role"]
        with self.store.transaction() as conn:
            if not existing:
                conn.execute(
                    "INSERT INTO artifacts(artifact_id,kind,role,mime_type,sha256,size,storage_uri,"
                    "original_locator,created_at,created_by,frozen_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        artifact_id,
                        Path(filename).suffix.lstrip(".") or "file",
                        role,
                        mime_type or "application/octet-stream",
                        digest,
                        len(content),
                        object_path.relative_to(self.store.ledger_dir).as_posix(),
                        locator,
                        now(),
                        auth.actor_id,
                        now() if role == "frozen" else None,
                    ),
                )
            elif ROLE_ORDER[role] > ROLE_ORDER[existing["role"]]:
                conn.execute(
                    "UPDATE artifacts SET role=?,frozen_at=CASE WHEN ?='frozen' THEN ? "
                    "ELSE frozen_at END WHERE artifact_id=?",
                    (role, role, now(), artifact_id),
                )
                effective_role = role
            conn.execute(
                "INSERT OR IGNORE INTO artifact_locations VALUES (?,?,?)",
                (artifact_id, locator, now()),
            )
            conn.execute(
                "INSERT OR IGNORE INTO artifact_links VALUES (?,?,?,?,?,?)",
                (
                    artifact_id,
                    "platform_source",
                    auth.platform_id,
                    "uploaded_by",
                    now(),
                    auth.actor_id,
                ),
            )
            result = {
                "artifact_id": artifact_id,
                "sha256": digest,
                "size": len(content),
                "role": effective_role,
                "storage_uri": object_path.relative_to(self.store.ledger_dir).as_posix(),
                "deduplicated": bool(existing),
                "platform_id": auth.platform_id,
            }
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="artifact.add_scoped",
                object_type="artifact",
                object_id=artifact_id,
                before_revision=None,
                after_revision=1,
                reason="",
                payload=result,
            )
        if effective_role == "frozen":
            self._write_manifest(artifact_id)
        return result

    def artifact_platforms(self, artifact_id: str) -> list[str]:
        if not self.store.row("SELECT 1 FROM artifacts WHERE artifact_id=?", (artifact_id,)):
            raise NotFoundError(f"Artifact not found: {artifact_id}")
        return [
            row["object_id"]
            for row in self.store.rows(
                "SELECT DISTINCT object_id FROM artifact_links WHERE artifact_id=? "
                "AND object_type='platform_source' ORDER BY object_id",
                (artifact_id,),
            )
        ]

    def require_platform_artifact(self, artifact_id: str, platform_id: str) -> dict[str, Any]:
        """Validate Artifact integrity and platform ownership through one shared path."""
        artifact = self.store.row(
            "SELECT a.* FROM artifacts a JOIN artifact_links l ON l.artifact_id=a.artifact_id "
            "WHERE a.artifact_id=? AND l.object_type='platform_source' AND l.object_id=?",
            (artifact_id, platform_id),
        )
        if not artifact or not self.verify(artifact_id)["ok"]:
            raise ArtifactPlatformMismatchError(
                "Artifact is not a valid Artifact owned by the scoped platform",
                details={
                    "artifact_id": artifact_id,
                    "expected_platform": platform_id,
                    "actual_platforms": self.artifact_platforms(artifact_id),
                },
            )
        return artifact

    # Backwards-compatible private alias for the existing internal callers.
    _require_platform_artifact = require_platform_artifact

    def require_platform_analysis_run(
        self, analysis_run_id: str, platform_id: str, *, frozen: bool = True
    ) -> dict[str, Any]:
        run = self.store.row(
            "SELECT * FROM analysis_runs WHERE analysis_run_id=?", (analysis_run_id,)
        )
        if not run or run.get("platform_id") != platform_id or (
            frozen and run.get("state") != "frozen"
        ):
            raise AnalysisPlatformMismatchError(
                "AnalysisRun does not belong to the scoped platform",
                details={
                    "analysis_run_id": analysis_run_id,
                    "expected_platform": platform_id,
                    "actual_platform": run.get("platform_id") if run else None,
                },
            )
        method = self.store.row(
            "SELECT * FROM analysis_methods WHERE method_id=?", (run["method_id"],)
        )
        if (
            not method
            or method.get("scope") != "platform"
            or method.get("platform_id") != platform_id
        ):
            raise AnalysisPlatformMismatchError(
                "AnalysisRun method does not belong to the scoped platform",
                details={
                    "analysis_run_id": analysis_run_id,
                    "method_id": run.get("method_id"),
                    "expected_platform": platform_id,
                    "actual_platform": method.get("platform_id") if method else None,
                },
            )
        script = self.require_platform_artifact(method["script_artifact_id"], platform_id)
        if script["sha256"] != method["source_hash"]:
            raise AnalysisPlatformMismatchError(
                "AnalysisRun method script hash no longer matches its registered source",
                details={"analysis_run_id": analysis_run_id, "method_id": method["method_id"]},
            )
        for item in self.store.rows(
            "SELECT input_type,input_id FROM analysis_inputs WHERE analysis_run_id=?",
            (analysis_run_id,),
        ):
            if item["input_type"] == "artifact":
                self.require_platform_artifact(item["input_id"], platform_id)
        outputs = self.store.rows(
            "SELECT a.* FROM analysis_outputs o JOIN artifacts a "
            "ON a.artifact_id=o.artifact_id WHERE o.analysis_run_id=?",
            (analysis_run_id,),
        )
        if not outputs:
            raise AnalysisPlatformMismatchError(
                "AnalysisRun has no registered output Artifacts",
                details={"analysis_run_id": analysis_run_id},
            )
        for output in outputs:
            owned = self.require_platform_artifact(output["artifact_id"], platform_id)
            if frozen and owned["role"] != "frozen":
                raise AnalysisPlatformMismatchError(
                    "Frozen AnalysisRun output is not a frozen platform Artifact",
                    details={
                        "analysis_run_id": analysis_run_id,
                        "artifact_id": output["artifact_id"],
                        "expected_platform": platform_id,
                    },
                )
        return run

    def register_scoped_method(
        self,
        script_artifact_id: str,
        *,
        name: str,
        git_commit: str | None,
        dirty_hash: str | None,
        auth: AuthContext,
    ) -> dict[str, Any]:
        auth.require("analysis.register-scoped")
        if not auth.platform_id:
            raise ValidationError("Scoped AnalysisMethod registration requires a platform principal")
        artifact = self._require_platform_artifact(script_artifact_id, auth.platform_id)
        if artifact["role"] != "frozen":
            raise ValidationError("AnalysisMethod script Artifact must be frozen")
        if not name.strip():
            raise ValidationError("AnalysisMethod name cannot be empty")
        existing = self.store.row(
            "SELECT * FROM analysis_methods WHERE script_artifact_id=? AND source_hash=? "
            "AND scope='platform' AND platform_id=?",
            (script_artifact_id, artifact["sha256"], auth.platform_id),
        )
        if existing:
            return {**existing, "existing": True}
        method_id = new_id("method")
        result = {
            "method_id": method_id,
            "name": name.strip(),
            "script_artifact_id": script_artifact_id,
            "source_hash": artifact["sha256"],
            "git_commit": git_commit,
            "dirty_hash": dirty_hash,
        }
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO analysis_methods("
                "method_id,name,script_artifact_id,source_hash,git_commit,dirty_hash,created_at,"
                "created_by,scope,platform_id) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    method_id,
                    name.strip(),
                    script_artifact_id,
                    artifact["sha256"],
                    git_commit,
                    dirty_hash,
                    now(),
                    auth.actor_id,
                    "platform",
                    auth.platform_id,
                ),
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="analysis.method.register_scoped",
                object_type="analysis_method",
                object_id=method_id,
                before_revision=None,
                after_revision=1,
                reason="",
                payload={**result, "platform_id": auth.platform_id},
            )
        return result

    def register_scoped_run(
        self,
        method_id: str,
        *,
        inputs: list[dict[str, str]],
        outputs: list[str],
        config: dict[str, Any],
        environment: dict[str, Any],
        freeze: bool,
        auth: AuthContext,
    ) -> dict[str, Any]:
        auth.require("analysis.register-scoped")
        if not auth.platform_id:
            raise ValidationError("Scoped AnalysisRun registration requires a platform principal")
        method = self.store.row(
            "SELECT * FROM analysis_methods WHERE method_id=?", (method_id,)
        )
        if not method:
            raise NotFoundError(f"Analysis method not found: {method_id}")
        if method.get("scope") != "platform" or method.get("platform_id") != auth.platform_id:
            raise AnalysisPlatformMismatchError(
                "AnalysisMethod does not belong to the scoped platform",
                details={
                    "method_id": method_id,
                    "expected_platform": auth.platform_id,
                    "actual_platform": method.get("platform_id"),
                },
            )
        self._require_platform_artifact(method["script_artifact_id"], auth.platform_id)
        if not outputs:
            raise ValidationError("AnalysisRun requires at least one output Artifact")
        validated_inputs: list[tuple[str, str, str, str]] = []
        manifest_snapshots: dict[str, dict[str, str]] = {}
        for item in inputs:
            input_type = str(item.get("type", ""))
            input_id = str(item.get("id", ""))
            snapshot = self._validate_input(input_type, input_id)
            if input_type == "evidence":
                manifest = self.store.row(
                    "SELECT manifest_id,manifest_hash FROM evidence_manifests WHERE evidence_id=? "
                    "AND manifest_id=(SELECT current_manifest_id FROM evidence_refs "
                    "WHERE evidence_id=?)",
                    (input_id, input_id),
                ) or self.store.row(
                    "SELECT manifest_id,manifest_hash FROM evidence_manifests WHERE evidence_id=? "
                    "ORDER BY manifest_revision DESC LIMIT 1",
                    (input_id,),
                )
                if not manifest:
                    raise ValidationError("AnalysisRun evidence input requires a current Manifest")
                requested_manifest_id = item.get("manifest_id")
                requested_manifest_hash = item.get("manifest_hash")
                if requested_manifest_id and requested_manifest_id != manifest["manifest_id"]:
                    raise ValidationError("AnalysisRun evidence input Manifest is stale")
                if requested_manifest_hash and requested_manifest_hash != manifest["manifest_hash"]:
                    raise ValidationError("AnalysisRun evidence input Manifest hash is stale")
                manifest_snapshots[input_id] = {
                    "manifest_id": manifest["manifest_id"],
                    "manifest_hash": manifest["manifest_hash"],
                }
                snapshot.update(manifest_snapshots[input_id])
            if input_type == "artifact":
                self._require_platform_artifact(input_id, auth.platform_id)
            validated_inputs.append((input_type, input_id, now(), canonical_json(snapshot)))
        for output in outputs:
            self._require_platform_artifact(output, auth.platform_id)
        run_id = new_id("analysis")
        timestamp = now()
        state = "frozen" if freeze else "registered"
        with self.store.transaction() as conn:
            if freeze:
                for output in outputs:
                    conn.execute(
                        "UPDATE artifacts SET role='frozen',frozen_at=COALESCE(frozen_at,?) "
                        "WHERE artifact_id=?",
                        (timestamp, output),
                    )
            conn.execute(
                "INSERT INTO analysis_runs("
                "analysis_run_id,method_id,config_json,environment_json,state,created_at,created_by,"
                "frozen_at,platform_id,input_manifest_hashes_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    run_id,
                    method_id,
                    canonical_json(config),
                    canonical_json(environment),
                    state,
                    timestamp,
                    auth.actor_id,
                    timestamp if freeze else None,
                    auth.platform_id,
                    canonical_json(manifest_snapshots),
                ),
            )
            conn.executemany(
                "INSERT INTO analysis_inputs(analysis_run_id,input_type,input_id,validated_at,"
                "validation_snapshot) VALUES (?,?,?,?,?)",
                [(run_id, *item) for item in validated_inputs],
            )
            conn.executemany(
                "INSERT INTO analysis_outputs VALUES (?,?,?)",
                [(run_id, artifact_id, "output") for artifact_id in outputs],
            )
            result = {
                "analysis_run_id": run_id,
                "method_id": method_id,
                "state": state,
                "inputs": inputs,
                "outputs": outputs,
                "platform_id": auth.platform_id,
            }
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="analysis.run.register_scoped",
                object_type="analysis_run",
                object_id=run_id,
                before_revision=None,
                after_revision=1,
                reason="",
                payload=result,
            )
        for artifact_id in outputs:
            self._write_manifest(artifact_id)
        return result

    def show(self, artifact_id: str) -> dict[str, Any]:
        row = self.store.row("SELECT * FROM artifacts WHERE artifact_id=?", (artifact_id,))
        if not row:
            raise NotFoundError(f"Artifact not found: {artifact_id}")
        row["locations"] = self.store.rows(
            "SELECT locator,observed_at FROM artifact_locations WHERE artifact_id=? ORDER BY observed_at",
            (artifact_id,),
        )
        row["links"] = self.store.rows(
            "SELECT object_type,object_id,link_role,created_at FROM artifact_links "
            "WHERE artifact_id=? ORDER BY object_type,object_id",
            (artifact_id,),
        )
        return row

    def link(
        self,
        artifact_id: str,
        *,
        object_type: str,
        object_id: str,
        link_role: str,
        credential: str | Path,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "artifact.manage")
        self.show(artifact_id)
        if object_type == "issue":
            self.manager._issue(object_id, active=False)
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO artifact_links VALUES (?,?,?,?,?,?)",
                (artifact_id, object_type, object_id, link_role, now(), auth.actor_id),
            )
        self._write_manifest(artifact_id)
        return {
            "artifact_id": artifact_id,
            "object_type": object_type,
            "object_id": object_id,
            "link_role": link_role,
        }

    def freeze(self, artifact_id: str, *, credential: str | Path) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "artifact.manage")
        verification = self.verify(artifact_id)
        if not verification["ok"]:
            raise ValidationError(f"Artifact {artifact_id} failed verification")
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE artifacts SET role='frozen',frozen_at=COALESCE(frozen_at,?) WHERE artifact_id=?",
                (now(), artifact_id),
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="artifact.freeze",
                object_type="artifact",
                object_id=artifact_id,
                before_revision=None,
                after_revision=None,
                reason="",
                payload={"artifact_id": artifact_id, "sha256": verification["sha256"]},
            )
        manifest = self._write_manifest(artifact_id)
        return {"artifact_id": artifact_id, "role": "frozen", "manifest": str(manifest)}

    def verify(self, artifact_id: str) -> dict[str, Any]:
        artifact = self.store.row("SELECT * FROM artifacts WHERE artifact_id=?", (artifact_id,))
        if not artifact:
            raise NotFoundError(f"Artifact not found: {artifact_id}")
        path = self.store.ledger_dir / artifact["storage_uri"]
        exists = path.is_file()
        actual = sha256_file(path) if exists else None
        size = path.stat().st_size if exists else None
        return {
            "artifact_id": artifact_id,
            "ok": exists and actual == artifact["sha256"] and size == artifact["size"],
            "exists": exists,
            "sha256": actual,
            "expected_sha256": artifact["sha256"],
            "size": size,
            "expected_size": artifact["size"],
        }

    def materialize(
        self,
        artifact_id: str,
        destination: str | Path,
        *,
        credential: str | Path,
    ) -> dict[str, Any]:
        self.credentials.resolve(credential, "artifact.manage")
        artifact = self.show(artifact_id)
        verification = self.verify(artifact_id)
        if not verification["ok"]:
            raise ValidationError(f"Artifact {artifact_id} failed verification")
        source = self.store.ledger_dir / artifact["storage_uri"]
        target = Path(destination).resolve()
        if target.exists():
            if not target.is_file() or sha256_file(target) != artifact["sha256"]:
                raise ConflictError(f"Destination exists with different content: {target}")
            return {"artifact_id": artifact_id, "path": str(target), "existing": True}
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        return {"artifact_id": artifact_id, "path": str(target), "existing": False}

    def _write_manifest(self, artifact_id: str) -> Path:
        artifact = self.show(artifact_id)
        path = self.store.ledger_dir / "artifacts" / "manifests" / f"{artifact_id}.json"
        temp_path = path.with_suffix(f".tmp-{os.getpid()}-{new_id('manifest')}")
        temp_path.write_text(
            json.dumps(artifact, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(temp_path, path)
        return path

    def verify_manifest(self, artifact_id: str) -> dict[str, Any]:
        artifact = self.show(artifact_id)
        path = self.store.ledger_dir / "artifacts" / "manifests" / f"{artifact_id}.json"
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {
                "artifact_id": artifact_id,
                "ok": False,
                "manifest": str(path),
                "error": str(exc),
            }
        fields = ("artifact_id", "sha256", "size", "storage_uri", "role")
        mismatches = {
            field: {"expected": artifact[field], "actual": manifest.get(field)}
            for field in fields
            if manifest.get(field) != artifact[field]
        }
        return {
            "artifact_id": artifact_id,
            "ok": not mismatches,
            "manifest": str(path),
            "mismatches": mismatches,
        }

    def rebuild_manifests(self, *, credential: str | Path) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "artifact.manage")
        artifact_ids = [
            row["artifact_id"]
            for row in self.store.rows("SELECT artifact_id FROM artifacts ORDER BY artifact_id")
        ]
        paths = [str(self._write_manifest(artifact_id)) for artifact_id in artifact_ids]
        with self.store.transaction() as conn:
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="artifact.manifests.rebuild",
                object_type="ledger",
                object_id=str(self.store.ledger_dir),
                before_revision=None,
                after_revision=None,
                reason="rebuild deterministic Artifact manifests",
                payload={"artifact_ids": artifact_ids},
            )
        return {"count": len(paths), "manifests": paths}

    def register_method(
        self,
        script: str | Path,
        *,
        name: str | None,
        credential: str | Path,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "artifact.manage")
        source = Path(script).resolve()
        artifact = self.add(source, role="frozen", kind="analysis_script", credential=credential)
        git_commit, dirty_hash = self._git_fingerprint(source)
        method_id = new_id("method")
        result = {
            "method_id": method_id,
            "name": name or source.stem,
            "script_artifact_id": artifact["artifact_id"],
            "source_hash": artifact["sha256"],
            "git_commit": git_commit,
            "dirty_hash": dirty_hash,
        }
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO analysis_methods("
                "method_id,name,script_artifact_id,source_hash,git_commit,dirty_hash,created_at,"
                "created_by,scope,platform_id) VALUES (?,?,?,?,?,?,?,?,?,NULL)",
                (
                    method_id,
                    result["name"],
                    artifact["artifact_id"],
                    artifact["sha256"],
                    git_commit,
                    dirty_hash,
                    now(),
                    auth.actor_id,
                    "shared-reviewed",
                ),
            )
        return result

    @staticmethod
    def _git_fingerprint(source: Path) -> tuple[str | None, str | None]:
        try:
            commit = subprocess.run(
                ["git", "-C", str(source.parent), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                check=True,
            ).stdout.strip()
            patch = subprocess.run(
                ["git", "-C", str(source.parent), "diff", "--binary", "--", str(source)],
                capture_output=True,
                check=True,
            ).stdout
            import hashlib

            dirty_hash = hashlib.sha256(patch).hexdigest() if patch else None
            return commit, dirty_hash
        except (OSError, subprocess.CalledProcessError):
            return None, None

    def register_run(
        self,
        method_id: str,
        *,
        inputs: list[dict[str, str]],
        outputs: list[str],
        config: dict[str, Any],
        environment: dict[str, Any] | None,
        credential: str | Path,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "artifact.manage")
        method = self.store.row(
            "SELECT method_id FROM analysis_methods WHERE method_id=?", (method_id,)
        )
        if not method:
            raise NotFoundError(f"Analysis method not found: {method_id}")
        validated_inputs: list[tuple[str, str, str, str]] = []
        for item in inputs:
            input_type = str(item.get("type", ""))
            input_id = str(item.get("id", ""))
            snapshot = self._validate_input(input_type, input_id)
            validated_inputs.append((input_type, input_id, now(), canonical_json(snapshot)))
        for output in outputs:
            self.show(output)
            if not self.verify(output)["ok"]:
                raise ValidationError(f"Analysis output Artifact failed verification: {output}")
        run_id = new_id("analysis")
        env = environment or {
            "python": sys.version,
            "platform": sys.platform,
        }
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO analysis_runs("
                "analysis_run_id,method_id,config_json,environment_json,state,created_at,created_by,"
                "frozen_at,platform_id,input_manifest_hashes_json) "
                "VALUES (?,?,?,?,'registered',?,?,NULL,NULL,?)",
                (
                    run_id,
                    method_id,
                    canonical_json(config),
                    canonical_json(env),
                    now(),
                    auth.actor_id,
                    canonical_json({}),
                ),
            )
            conn.executemany(
                "INSERT INTO analysis_inputs(analysis_run_id,input_type,input_id,validated_at,"
                "validation_snapshot) VALUES (?,?,?,?,?)",
                [(run_id, *item) for item in validated_inputs],
            )
            conn.executemany(
                "INSERT INTO analysis_outputs VALUES (?,?,?)",
                [(run_id, artifact_id, "output") for artifact_id in outputs],
            )
        for artifact_id in outputs:
            self._write_manifest(artifact_id)
        return {
            "analysis_run_id": run_id,
            "method_id": method_id,
            "state": "registered",
            "inputs": inputs,
            "outputs": outputs,
        }

    def _validate_input(self, input_type: str, input_id: str) -> dict[str, Any]:
        if not input_type or not input_id:
            raise ValidationError("Each AnalysisRun input needs non-empty type and id")
        if input_type == "dataset":
            if "::dataset=" not in input_id:
                raise ValidationError("Dataset input must use '<full-path>::dataset=<number>'")
            path_part, dataset_number = input_id.rsplit("::dataset=", 1)
            if not path_part or not dataset_number.isdigit():
                raise ValidationError("Dataset input must use '<full-path>::dataset=<number>'")
            return {"type": input_type, "locator": input_id, "valid": True}
        lookups = {
            "evidence": ("evidence_refs", "evidence_id", "lifecycle_status='active'"),
            "artifact": ("artifacts", "artifact_id", None),
            "method": ("analysis_methods", "method_id", None),
            "analysis_run": ("analysis_runs", "analysis_run_id", "state='frozen'"),
        }
        if input_type not in lookups:
            raise ValidationError(
                "AnalysisRun input type must be dataset, evidence, artifact, method, or analysis_run"
            )
        table, column, predicate = lookups[input_type]
        sql = f"SELECT * FROM {table} WHERE {column}=?"
        if predicate:
            sql += f" AND {predicate}"
        found = self.store.row(sql, (input_id,))
        if not found:
            raise ValidationError(
                f"AnalysisRun input does not reference an active {input_type}: {input_id}"
            )
        if input_type == "artifact" and not self.verify(input_id)["ok"]:
            raise ValidationError(f"AnalysisRun input Artifact failed verification: {input_id}")
        return {"type": input_type, "id": input_id, "valid": True}

    def freeze_run(self, run_id: str, *, credential: str | Path) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "artifact.manage")
        run = self.store.row("SELECT * FROM analysis_runs WHERE analysis_run_id=?", (run_id,))
        if not run:
            raise NotFoundError(f"Analysis run not found: {run_id}")
        method = self.store.row(
            "SELECT m.*,a.artifact_id FROM analysis_methods m JOIN artifacts a "
            "ON a.artifact_id=m.script_artifact_id WHERE m.method_id=?",
            (run["method_id"],),
        )
        if not method or not self.verify(method["script_artifact_id"])["ok"]:
            raise ValidationError("Analysis method script is missing or corrupt")
        inputs = self.store.rows(
            "SELECT input_type,input_id FROM analysis_inputs WHERE analysis_run_id=?", (run_id,)
        )
        for item in inputs:
            self._validate_input(item["input_type"], item["input_id"])
        outputs = self.store.rows(
            "SELECT artifact_id FROM analysis_outputs WHERE analysis_run_id=?", (run_id,)
        )
        for output in outputs:
            self.freeze(output["artifact_id"], credential=credential)
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE analysis_runs SET state='frozen',frozen_at=? WHERE analysis_run_id=?",
                (now(), run_id),
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="analysis.freeze",
                object_type="analysis_run",
                object_id=run_id,
                before_revision=None,
                after_revision=None,
                reason="",
                payload={"outputs": [item["artifact_id"] for item in outputs]},
            )
        return {"analysis_run_id": run_id, "state": "frozen"}
