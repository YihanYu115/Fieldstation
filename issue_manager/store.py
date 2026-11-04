from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import shutil
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterator
from uuid import uuid4

from .current_schema import CURRENT_SCHEMA_SQL
from .default_policy import default_policy_text
from .errors import (
    ConflictError,
    IdempotencyConflictError,
    MigrationResolutionError,
    MigrationResolutionStaleError,
    NotFoundError,
    ValidationError,
)
from .policy import Policy
from .schema import LATEST_SCHEMA_VERSION
from .strict_json import strict_json_dumps


def now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def canonical_json(value: Any) -> str:
    return strict_json_dumps(value)


def _normalize_legacy_policy_for_v9(policy: dict[str, Any]) -> dict[str, Any]:
    """Apply the documented, deterministic pre-v9 Policy compatibility rewrite."""
    from .default_policy import DEFAULT_POLICY

    normalized = json.loads(json.dumps(policy, ensure_ascii=False, allow_nan=True))
    if "approval" in normalized and "publication" not in normalized:
        normalized.pop("approval", None)
        normalized["publication"] = DEFAULT_POLICY["publication"]
    for key in ("publication_requirements", "risk_policy", "evidence", "resolver"):
        if key not in normalized:
            normalized[key] = DEFAULT_POLICY[key]
    requirement_defaults = DEFAULT_POLICY.get("publication_requirements")
    requirements = normalized.get("publication_requirements")
    if isinstance(requirement_defaults, dict) and isinstance(requirements, dict):
        for target, defaults in requirement_defaults.items():
            current = requirements.setdefault(target, {})
            if not isinstance(current, dict) or not isinstance(defaults, dict):
                continue
            for key, value in defaults.items():
                current.setdefault(key, value)
    version = normalized.get("policy_version", 1)
    if isinstance(version, int) and not isinstance(version, bool) and version < 7:
        normalized["policy_version"] = 7
    return normalized


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Store:
    before_commit: Callable[[], None] | None = None

    @staticmethod
    def _configure_connection(
        conn: sqlite3.Connection, *, enable_wal: bool = True
    ) -> sqlite3.Connection:
        """Apply the connection-local durability and locking policy.

        SQLite's ``synchronous`` setting is connection-local.  Keep this in
        one path so fresh initialization, normal product writes, and the
        small maintenance writes used during backup/restore do not silently
        fall back to a weaker setting.
        """
        conn.execute("PRAGMA foreign_keys = ON")
        if enable_wal:
            conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA busy_timeout = 5000")
        return conn

    def __init__(self, ledger_dir: str | Path, *, fresh_context_rule: str | None = None):
        self.ledger_dir = Path(ledger_dir).resolve()
        self._recover_interrupted_restore(self.ledger_dir)
        self.db_path = self.ledger_dir / "issue_ledger.sqlite"
        self.policy_path = self.ledger_dir / "policy.yaml"
        self.secret_path = self.ledger_dir / ".ledger_secret"
        self.fault_injector: Any = None
        self.fresh_context_rule = fresh_context_rule
        self._savepoint_counter = 0
        if not self.db_path.exists():
            raise ValidationError(
                f"Ledger is not initialized at {self.ledger_dir}; run 'issuectl init' first"
            )
        self.policy = Policy.load(self.policy_path)
        # Probe the version with a plain connection first.  `_connect()` turns
        # on WAL and other connection pragmas, which can modify a database;
        # unsupported files must be rejected without changing their bytes.
        probe = sqlite3.connect(self.db_path)
        try:
            version = self._schema_version(probe)
            if version == LATEST_SCHEMA_VERSION and fresh_context_rule is None:
                from .context_scoped_rule import SCOPED_V2_RULE_DEFINITION, scoped_v2_rule_id

                active = probe.execute("SELECT r.rule_id,r.definition_json FROM context_rule_selections s JOIN context_rule_versions r USING(rule_id) WHERE s.singleton=1").fetchone()
                if (active is None or active[0] != scoped_v2_rule_id() or
                        canonical_json(json.loads(active[1])) != canonical_json(SCOPED_V2_RULE_DEFINITION)):
                    raise ValidationError("Unsupported context rule; initialize a new scoped-v2 project. Existing files were not upgraded.")
        finally:
            probe.close()
        if version != LATEST_SCHEMA_VERSION:
            raise ValidationError(
                f"Unsupported database schema identity {version}; "
                f"this kernel accepts only fresh schema {LATEST_SCHEMA_VERSION}."
            )
        self.conn = self._connect()
        self._ensure_secret()
        self._ensure_audit_checkpoint()
        self._harden_permissions()
        self._record_policy_snapshot()
        self._bootstrap_identities()
        from .project_component import installation

        binding = installation(self)
        if binding and binding["execution_isolated"]:
            def authorize(action, table, column, database, source):
                if action in {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
                              sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_ALTER_TABLE,
                              sqlite3.SQLITE_DROP_TABLE, sqlite3.SQLITE_CREATE_TRIGGER,
                              sqlite3.SQLITE_DROP_TRIGGER}:
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            self.conn.set_authorizer(authorize)

    @classmethod
    def initialize(cls, ledger_dir: str | Path, *, context_rule: str = "scoped-v2") -> "Store":
        if context_rule != "scoped-v2":
            raise ValidationError("Only scoped-v2 fresh initialization is supported")
        root = Path(ledger_dir).resolve()
        root.mkdir(parents=True, exist_ok=True)
        (root / "backups").mkdir(exist_ok=True)
        (root / "exports" / "issues").mkdir(parents=True, exist_ok=True)
        (root / "credentials").mkdir(exist_ok=True)
        (root / "artifacts" / "objects" / "sha256").mkdir(parents=True, exist_ok=True)
        (root / "artifacts" / "manifests").mkdir(parents=True, exist_ok=True)
        (root / "runtime").mkdir(parents=True, exist_ok=True)
        (root / "reports").mkdir(parents=True, exist_ok=True)
        policy_path = root / "policy.yaml"
        if not policy_path.exists():
            policy_path.write_text(default_policy_text(), encoding="utf-8", newline="\n")
        db_path = root / "issue_ledger.sqlite"
        created_new_database = not db_path.exists()
        if not db_path.exists():
            initializing_path = root / "issue_ledger.sqlite.initializing"
            if initializing_path.exists():
                initializing_path.unlink()
            conn = sqlite3.connect(initializing_path)
            try:
                cls._configure_connection(conn, enable_wal=False)
                conn.execute("BEGIN")
                cls._execute_sql_script(conn, CURRENT_SCHEMA_SQL)
                from .evidence_applicability_schema import install_evidence_applicability_v18

                install_evidence_applicability_v18(conn)
                from .context_scoped_rule import SCOPED_V2_RULE_DEFINITION, scoped_v2_rule_id

                rule_id = scoped_v2_rule_id()
                conn.execute("INSERT INTO context_rule_versions VALUES (?,?,?)",
                             (rule_id, canonical_json(SCOPED_V2_RULE_DEFINITION), now()))
                conn.execute("INSERT INTO context_rule_selections VALUES (1,?)", (rule_id,))
                conn.commit()
            except Exception:
                conn.rollback()
                conn.close()
                initializing_path.unlink(missing_ok=True)
                raise
            finally:
                conn.close()
            initializing_path.replace(db_path)
        store = cls(root, fresh_context_rule=context_rule if created_new_database else None)
        if created_new_database:
            store._bootstrap_new_project_applicability_curators()
        store._bootstrap_identities()
        return store

    def fault(self, point: str) -> None:
        """Invoke the optional test fault hook at a named transaction boundary."""
        if self.fault_injector is not None:
            self.fault_injector(point)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return self._configure_connection(conn)

    @staticmethod
    def _schema_version(conn: sqlite3.Connection) -> int:
        try:
            row = conn.execute(
                "SELECT version FROM schema_identity WHERE singleton=1"
            ).fetchone()
        except sqlite3.DatabaseError:
            return 0
        return int(row[0]) if row else 0


    @staticmethod
    def _execute_sql_script(conn: sqlite3.Connection, script: str) -> None:
        """Execute a SQL script without sqlite3.executescript's implicit COMMIT."""
        statement = ""
        for line in script.splitlines(keepends=True):
            statement += line
            if sqlite3.complete_statement(statement):
                sql = statement.strip()
                statement = ""
                if sql:
                    conn.execute(sql)
        if Store._has_sql_content(statement):
            raise ValidationError("Migration SQL ended with an incomplete statement")

    @staticmethod
    def _has_sql_content(statement: str) -> bool:
        """Return whether pending script text contains anything beyond whitespace/comments."""
        index = 0
        length = len(statement)
        while index < length:
            char = statement[index]
            following = statement[index + 1] if index + 1 < length else ""
            if char.isspace():
                index += 1
            elif char == "-" and following == "-":
                newline = statement.find("\n", index + 2)
                index = length if newline < 0 else newline + 1
            elif char == "/" and following == "*":
                end = statement.find("*/", index + 2)
                if end < 0:
                    return False
                index = end + 2
            else:
                return True
        return False






















    @classmethod
    def create_backup(
        cls, ledger_dir: str | Path, *, label: str = "manual", mode: str = "metadata"
    ) -> dict[str, Any]:
        root = Path(ledger_dir).resolve()
        db_path = root / "issue_ledger.sqlite"
        if not db_path.exists():
            raise ValidationError(f"Ledger is not initialized at {root}")
        if mode not in {"metadata", "full"}:
            raise ValidationError("Backup mode must be 'metadata' or 'full'")
        backup_id = f"backup_{datetime.now().strftime('%Y%m%dT%H%M%S')}_{uuid4().hex[:8]}"
        backup_dir = root / "backups" / backup_id
        backup_dir.mkdir(parents=True, exist_ok=False)
        backup_db = backup_dir / "issue_ledger.sqlite"
        source = sqlite3.connect(db_path)
        target = sqlite3.connect(backup_db)
        try:
            cls._configure_connection(target, enable_wal=False)
            source.backup(target)
        finally:
            target.close()
            source.close()
        manifest: dict[str, Any] = {
            "backup_id": backup_id,
            "label": label,
            "created_at": now(),
            "mode": mode,
            "database": "issue_ledger.sqlite",
            "sha256": sha256_file(backup_db),
            "files": {},
            "artifacts": [],
        }
        for name in ("policy.yaml", ".ledger_secret"):
            source_file = root / name
            if source_file.exists():
                target_file = backup_dir / name
                shutil.copyfile(source_file, target_file)
                manifest["files"][name] = sha256_file(target_file)
        credentials = root / "credentials"
        if credentials.exists():
            shutil.copytree(credentials, backup_dir / "credentials")
            for credential_file in sorted((backup_dir / "credentials").glob("*.token")):
                relative = credential_file.relative_to(backup_dir).as_posix()
                manifest["files"][relative] = sha256_file(credential_file)
        artifact_manifests = root / "artifacts" / "manifests"
        if artifact_manifests.exists():
            target_manifests = backup_dir / "artifacts" / "manifests"
            shutil.copytree(artifact_manifests, target_manifests)
            for artifact_manifest in sorted(target_manifests.glob("*.json")):
                relative = artifact_manifest.relative_to(backup_dir).as_posix()
                manifest["files"][relative] = sha256_file(artifact_manifest)
        if mode == "full":
            conn = sqlite3.connect(backup_db)
            conn.row_factory = sqlite3.Row
            try:
                has_artifacts = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='artifacts'"
                ).fetchone()
                artifacts = (
                    [
                        dict(row)
                        for row in conn.execute(
                            "SELECT artifact_id,sha256,size,storage_uri,role FROM artifacts"
                        ).fetchall()
                    ]
                    if has_artifacts
                    else []
                )
            finally:
                conn.close()
            for artifact in artifacts:
                source_object = root / artifact["storage_uri"]
                if not source_object.is_file():
                    raise ValidationError(
                        f"Cannot create full backup; Artifact {artifact['artifact_id']} object is missing"
                    )
                if (
                    sha256_file(source_object) != artifact["sha256"]
                    or source_object.stat().st_size != artifact["size"]
                ):
                    raise ValidationError(
                        f"Cannot create full backup; Artifact {artifact['artifact_id']} failed verification"
                    )
                artifact_relative = Path(artifact["storage_uri"])
                target_object = backup_dir / artifact_relative
                target_object.parent.mkdir(parents=True, exist_ok=True)
                reused = False
                for previous in sorted(
                    (root / "backups").glob("backup_*/manifest.json"), reverse=True
                ):
                    if previous.parent == backup_dir:
                        continue
                    candidate = previous.parent / artifact_relative
                    if (
                        candidate.is_file()
                        and candidate.stat().st_size == artifact["size"]
                        and sha256_file(candidate) == artifact["sha256"]
                    ):
                        try:
                            os.link(candidate, target_object)
                            reused = True
                            break
                        except OSError:
                            break
                if not reused:
                    shutil.copyfile(source_object, target_object)
                manifest["artifacts"].append(
                    {
                        "artifact_id": artifact["artifact_id"],
                        "sha256": artifact["sha256"],
                        "size": artifact["size"],
                        "relative_path": artifact_relative.as_posix(),
                    }
                )
        manifest_path = backup_dir / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        manifest_hash = sha256_file(manifest_path)
        (backup_dir / "manifest.sha256").write_text(
            manifest_hash + "\n", encoding="utf-8", newline="\n"
        )
        live_conn = sqlite3.connect(db_path)
        try:
            live_conn.execute(
                "INSERT OR REPLACE INTO artifact_backup_sets VALUES (?,?,?,?)",
                (backup_id, mode, manifest_hash, manifest["created_at"]),
            )
            live_conn.executemany(
                "INSERT OR REPLACE INTO artifact_backup_objects VALUES (?,?,?,?,?)",
                [
                    (
                        backup_id,
                        item["artifact_id"],
                        item["sha256"],
                        item["size"],
                        item["relative_path"],
                    )
                    for item in manifest["artifacts"]
                ],
            )
            live_conn.commit()
        finally:
            live_conn.close()
        manifest["manifest_sha256"] = manifest_hash
        return manifest

    @classmethod
    def list_backups(cls, ledger_dir: str | Path) -> list[dict[str, Any]]:
        root = Path(ledger_dir).resolve() / "backups"
        if not root.exists():
            return []
        result: list[dict[str, Any]] = []
        for manifest_path in sorted(root.glob("backup_*/manifest.json"), reverse=True):
            try:
                result.append(json.loads(manifest_path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                result.append({"backup_id": manifest_path.parent.name, "invalid_manifest": True})
        return result

    @classmethod
    def verify_backup(cls, ledger_dir: str | Path, backup_id: str) -> dict[str, Any]:
        root = Path(ledger_dir).resolve()
        backup_dir = root / "backups" / backup_id
        manifest_path = backup_dir / "manifest.json"
        db_path = backup_dir / "issue_ledger.sqlite"
        if not manifest_path.exists() or not db_path.exists():
            raise NotFoundError(f"Backup not found: {backup_id}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest_hash_path = backup_dir / "manifest.sha256"
        manifest_hash_matches = bool(
            manifest_hash_path.is_file()
            and manifest_hash_path.read_text(encoding="utf-8").strip() == sha256_file(manifest_path)
        )
        actual_hash = sha256_file(db_path)
        conn = sqlite3.connect(db_path)
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            version = cls._schema_version(conn)
        finally:
            conn.close()
        file_mismatches = []
        for relative, expected in manifest.get("files", {}).items():
            file_path = backup_dir / relative
            if not file_path.is_file() or sha256_file(file_path) != expected:
                file_mismatches.append(relative)
        rebuildable_manifest_mismatches = [
            relative for relative in file_mismatches if relative.startswith("artifacts/manifests/")
        ]
        critical_file_mismatches = [
            relative
            for relative in file_mismatches
            if relative not in rebuildable_manifest_mismatches
        ]
        artifact_mismatches = []
        for artifact in manifest.get("artifacts", []):
            object_path = backup_dir / artifact["relative_path"]
            if (
                not object_path.is_file()
                or object_path.stat().st_size != artifact["size"]
                or sha256_file(object_path) != artifact["sha256"]
            ):
                artifact_mismatches.append(artifact["artifact_id"])
        ok = (
            actual_hash == manifest.get("sha256")
            and integrity == "ok"
            and manifest_hash_matches
            and not critical_file_mismatches
            and not artifact_mismatches
        )
        return {
            "backup_id": backup_id,
            "ok": ok,
            "sha256_matches": actual_hash == manifest.get("sha256"),
            "manifest_hash_matches": manifest_hash_matches,
            "integrity": integrity,
            "schema_version": version,
            "file_mismatches": file_mismatches,
            "rebuildable_manifest_mismatches": rebuildable_manifest_mismatches,
            "artifact_mismatches": artifact_mismatches,
            "mode": manifest.get("mode", "metadata"),
        }

    @classmethod
    def restore_backup(cls, ledger_dir: str | Path, backup_id: str) -> dict[str, Any]:
        root = Path(ledger_dir).resolve()
        verification = cls.verify_backup(root, backup_id)
        if not verification["ok"]:
            raise ValidationError(f"Backup {backup_id} failed verification")
        if verification["schema_version"] != LATEST_SCHEMA_VERSION:
            raise ValidationError(
                f"Backup schema v{verification['schema_version']} must be migrated explicitly "
                f"before restore into schema v{LATEST_SCHEMA_VERSION}"
            )
        manifest = json.loads(
            (root / "backups" / backup_id / "manifest.json").read_text(encoding="utf-8")
        )
        safety_degraded = False
        try:
            safety = cls.create_backup(
                root,
                label=f"pre-restore-{backup_id}",
                mode="full" if manifest.get("mode") == "full" else "metadata",
            )
        except ValidationError:
            if manifest.get("mode") != "full":
                raise
            safety = cls.create_backup(
                root, label=f"pre-restore-{backup_id}-metadata-only", mode="metadata"
            )
            safety_degraded = True
        runtime = root / "runtime"
        runtime.mkdir(parents=True, exist_ok=True)
        work = Path(tempfile.mkdtemp(prefix="restore-", dir=runtime))
        target_stage = work / "target"
        rollback_stage = work / "rollback"
        journal_path = runtime / "restore_journal.json"
        journal: dict[str, Any] = {
            "restore_id": new_id("restore"),
            "pid": os.getpid(),
            "backup_id": backup_id,
            "safety_backup_id": safety["backup_id"],
            "target_stage": str(target_stage),
            "rollback_stage": str(rollback_stage),
            "phase": "staging",
            "started_at": now(),
        }
        cls._write_restore_journal(journal_path, journal)
        cls._set_raw_maintenance(root, True)
        try:
            cls._prepare_restore_stage(root, backup_id, target_stage)
            cls._prepare_restore_stage(
                root,
                safety["backup_id"],
                rollback_stage,
                validate_artifacts=not safety_degraded,
            )
            journal["phase"] = "switching"
            cls._write_restore_journal(journal_path, journal)
            cls._activate_restore_stage(root, target_stage)
            journal["phase"] = "verifying_active"
            cls._write_restore_journal(journal_path, journal)

            from .service import IssueManager

            manager = IssueManager(root)
            try:
                with manager.store.transaction() as conn:
                    metadata = conn.execute(
                        "SELECT token_epoch FROM manager_metadata WHERE singleton=1"
                    ).fetchone()
                    old_epoch = int(metadata[0]) if metadata else 1
                    token_epoch = old_epoch + 1
                    conn.execute(
                        "UPDATE manager_metadata SET active_generation=?,token_epoch=?,"
                        "maintenance_mode=0,updated_at=? WHERE singleton=1",
                        (backup_id, token_epoch, now()),
                    )
                    conn.execute(
                        "UPDATE service_tokens SET revoked_at=COALESCE(revoked_at,?)",
                        (now(),),
                    )
                    manager.store.audit(
                        conn,
                        actor="maintenance-service",
                        action="backup.restore",
                        object_type="ledger",
                        object_id=str(root),
                        before_revision=None,
                        after_revision=None,
                        reason=f"restore {backup_id}",
                        payload={
                            "restored_backup_id": backup_id,
                            "pre_restore_backup_id": safety["backup_id"],
                            "old_token_epoch": old_epoch,
                            "new_token_epoch": token_epoch,
                        },
                    )
                post_restore_doctor = manager.doctor()
            finally:
                manager.close()
            if not post_restore_doctor["ok"]:
                raise ValidationError(f"Backup {backup_id} failed post-restore doctor verification")
            journal["phase"] = "completed"
            journal["completed_at"] = now()
            cls._write_restore_journal(journal_path, journal)
            return {
                "restored": backup_id,
                "pre_restore_backup_id": safety["backup_id"],
                "schema_version": verification["schema_version"],
                "mode": verification["mode"],
                "pre_restore_backup_degraded": safety_degraded,
                "token_epoch": token_epoch,
                "manifests_rebuilt": True,
                "doctor": post_restore_doctor,
            }
        except Exception:
            journal["phase"] = "rolling_back"
            cls._write_restore_journal(journal_path, journal)
            if rollback_stage.exists():
                cls._activate_restore_stage(root, rollback_stage)
                journal["phase"] = "rolled_back"
                journal["rolled_back_at"] = now()
                cls._write_restore_journal(journal_path, journal)
            else:
                cls._set_raw_maintenance(root, False)
                journal["phase"] = "staging_failed"
                journal["failed_at"] = now()
                cls._write_restore_journal(journal_path, journal)
            raise
        finally:
            if work.exists() and journal.get("phase") in {
                "completed",
                "rolled_back",
                "staging_failed",
            }:
                shutil.rmtree(work)

    @staticmethod
    def _write_restore_journal(path: Path, journal: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(f".tmp-{uuid4().hex}")
        temporary.write_text(
            json.dumps(journal, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(temporary, path)

    @classmethod
    def _prepare_restore_stage(
        cls,
        root: Path,
        backup_id: str,
        stage: Path,
        *,
        validate_artifacts: bool = True,
    ) -> None:
        backup_dir = root / "backups" / backup_id
        manifest = json.loads((backup_dir / "manifest.json").read_text(encoding="utf-8"))
        stage.mkdir(parents=True, exist_ok=False)
        source = sqlite3.connect(backup_dir / "issue_ledger.sqlite")
        target = sqlite3.connect(stage / "issue_ledger.sqlite")
        try:
            cls._configure_connection(target, enable_wal=False)
            source.backup(target)
        finally:
            target.close()
            source.close()
        for name in ("policy.yaml", ".ledger_secret"):
            source_file = backup_dir / name
            if not source_file.is_file():
                raise ValidationError(f"Backup {backup_id} is missing required {name}")
            shutil.copyfile(source_file, stage / name)
        for directory in ("credentials",):
            source_directory = backup_dir / directory
            if source_directory.exists():
                shutil.copytree(source_directory, stage / directory)
            else:
                (stage / directory).mkdir(parents=True)
        (stage / "artifacts" / "objects").mkdir(parents=True)
        (stage / "artifacts" / "manifests").mkdir(parents=True)
        backed_objects = {item["artifact_id"]: item for item in manifest.get("artifacts", [])}
        conn = sqlite3.connect(stage / "issue_ledger.sqlite")
        conn.row_factory = sqlite3.Row
        try:
            artifacts = [dict(row) for row in conn.execute("SELECT * FROM artifacts")]
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            foreign_keys = conn.execute("PRAGMA foreign_key_check").fetchall()
        finally:
            conn.close()
        if integrity != "ok" or foreign_keys:
            raise ValidationError(f"Backup {backup_id} failed staged SQLite validation")
        for artifact in artifacts:
            backed = backed_objects.get(artifact["artifact_id"])
            source_object = (
                backup_dir / backed["relative_path"] if backed else root / artifact["storage_uri"]
            )
            if not source_object.is_file():
                if not validate_artifacts:
                    # A degraded safety snapshot preserves the damaged live state;
                    # missing objects must not prevent restoring a valid full backup.
                    continue
                raise ValidationError(
                    f"Staged restore is missing Artifact {artifact['artifact_id']}"
                )
            artifact_valid = (
                source_object.stat().st_size != artifact["size"]
                or sha256_file(source_object) != artifact["sha256"]
            )
            if artifact_valid and validate_artifacts:
                raise ValidationError(
                    f"Staged restore Artifact {artifact['artifact_id']} failed verification"
                )
            target_object = stage / artifact["storage_uri"]
            target_object.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(source_object, target_object)
            except OSError:
                shutil.copyfile(source_object, target_object)
        (stage / "runtime").mkdir(exist_ok=True)

        from .service import IssueManager

        manager = IssueManager(stage)
        try:
            for artifact in manager.store.rows("SELECT artifact_id FROM artifacts"):
                manager.artifacts._write_manifest(artifact["artifact_id"])
            staged_doctor: dict[str, Any] = manager.doctor() if validate_artifacts else {"ok": True}
        finally:
            manager.close()
        if not staged_doctor["ok"]:
            raise ValidationError(
                f"Backup {backup_id} failed staged doctor verification: "
                f"{staged_doctor['findings'][:1]}"
            )

    @classmethod
    def _activate_restore_stage(cls, root: Path, stage: Path) -> None:
        runtime = root / "runtime"
        runtime.mkdir(parents=True, exist_ok=True)
        staged_objects = stage / "artifacts" / "objects"
        if staged_objects.exists():
            for source_object in staged_objects.rglob("*"):
                if not source_object.is_file():
                    continue
                relative = source_object.relative_to(staged_objects)
                target_object = root / "artifacts" / "objects" / relative
                target_object.parent.mkdir(parents=True, exist_ok=True)
                if target_object.is_file() and sha256_file(target_object) == sha256_file(
                    source_object
                ):
                    continue
                incoming = target_object.with_suffix(f".restore-{uuid4().hex}.tmp")
                shutil.copyfile(source_object, incoming)
                os.replace(incoming, target_object)
        for directory in ("credentials", "artifacts/manifests"):
            staged_directory = stage / directory
            incoming_directory = runtime / f"incoming-{uuid4().hex}"
            shutil.copytree(staged_directory, incoming_directory)
            live_directory = root / directory
            retired = runtime / f"retired-{uuid4().hex}"
            live_directory.parent.mkdir(parents=True, exist_ok=True)
            if live_directory.exists():
                os.replace(live_directory, retired)
            os.replace(incoming_directory, live_directory)
            if retired.exists():
                shutil.rmtree(retired)
        for name in ("policy.yaml", ".ledger_secret", "issue_ledger.sqlite"):
            incoming = runtime / f"incoming-{uuid4().hex}-{Path(name).name}"
            shutil.copyfile(stage / name, incoming)
            os.replace(incoming, root / name)
        db_path = root / "issue_ledger.sqlite"
        for suffix in ("-wal", "-shm"):
            Path(str(db_path) + suffix).unlink(missing_ok=True)

    @classmethod
    def _recover_interrupted_restore(cls, root: Path) -> None:
        journal_path = root / "runtime" / "restore_journal.json"
        if not journal_path.is_file():
            return
        try:
            journal = json.loads(journal_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if journal.get("pid") == os.getpid():
            return
        if journal.get("phase") in {"staging", "staging_failed"}:
            cls._set_raw_maintenance(root, False)
            journal["phase"] = "staging_abandoned"
            journal["abandoned_at"] = now()
            cls._write_restore_journal(journal_path, journal)
            return
        if journal.get("phase") not in {"switching", "verifying_active", "rolling_back"}:
            return
        rollback_stage = Path(str(journal.get("rollback_stage", "")))
        if not rollback_stage.is_dir():
            raise ValidationError(
                "Interrupted restore requires rollback, but its staged safety generation is missing"
            )
        cls._activate_restore_stage(root, rollback_stage)
        journal["phase"] = "auto_rolled_back"
        journal["auto_rolled_back_at"] = now()
        cls._write_restore_journal(journal_path, journal)

    @staticmethod
    def _set_raw_maintenance(root: Path, enabled: bool) -> None:
        db_path = root / "issue_ledger.sqlite"
        if not db_path.is_file():
            return
        conn = sqlite3.connect(db_path)
        try:
            Store._configure_connection(conn)
            table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='manager_metadata'"
            ).fetchone()
            if table:
                conn.execute(
                    "UPDATE manager_metadata SET maintenance_mode=?,updated_at=? WHERE singleton=1",
                    (1 if enabled else 0, now()),
                )
                conn.commit()
        finally:
            conn.close()

    def close(self) -> None:
        self.conn.close()

    def _ensure_secret(self) -> None:
        if not self.secret_path.exists():
            self.secret_path.write_text(secrets.token_hex(32), encoding="utf-8", newline="\n")

    def _harden_permissions(self) -> None:
        """Apply owner-only POSIX modes where the host filesystem supports them."""
        for path, mode in (
            (self.ledger_dir, 0o700),
            (self.ledger_dir / "credentials", 0o700),
            (self.db_path, 0o600),
            (self.policy_path, 0o600),
            (self.secret_path, 0o600),
        ):
            try:
                if path.exists():
                    os.chmod(path, mode)
            except OSError:
                # Windows ACL isolation is supplied by the Manager service account.
                continue

    @property
    def secret(self) -> bytes:
        return self.secret_path.read_text(encoding="utf-8").strip().encode("ascii")

    def _bootstrap_identities(self) -> None:
        from .security import BOOTSTRAP_IDENTITIES, CAPABILITY_PROFILES, credential_hash

        credential_dir = self.ledger_dir / "credentials"
        credential_dir.mkdir(exist_ok=True)
        complete = True
        for profile_name, capabilities in CAPABILITY_PROFILES.items():
            profile = self.conn.execute(
                "SELECT 1 FROM capability_profiles WHERE profile_name=?", (profile_name,)
            ).fetchone()
            stored = {
                row[0]
                for row in self.conn.execute(
                    "SELECT capability FROM profile_capabilities WHERE profile_name=?",
                    (profile_name,),
                ).fetchall()
            }
            complete = complete and bool(profile) and set(capabilities) <= stored
        for actor_id, spec in BOOTSTRAP_IDENTITIES.items():
            actor = self.conn.execute(
                "SELECT 1 FROM actors WHERE actor_id=?", (actor_id,)
            ).fetchone()
            stored = {
                row[0]
                for row in self.conn.execute(
                    "SELECT capability FROM actor_capabilities WHERE actor_id=?", (actor_id,)
                ).fetchall()
            }
            stored_profiles = {
                row[0]
                for row in self.conn.execute(
                    "SELECT profile_name FROM principal_profile_assignments WHERE actor_id=?",
                    (actor_id,),
                ).fetchall()
            }
            active_run = self.conn.execute(
                "SELECT 1 FROM agent_runs WHERE actor_id=? AND ended_at IS NULL LIMIT 1",
                (actor_id,),
            ).fetchone()
            complete = (
                complete
                and bool(actor)
                and bool(active_run)
                and set(spec["capabilities"]) <= stored
                and set(spec.get("profiles", set())) <= stored_profiles
            )
        if complete:
            return
        with self.transaction() as conn:
            for profile_name, capabilities in CAPABILITY_PROFILES.items():
                conn.execute(
                    "INSERT OR IGNORE INTO capability_profiles VALUES (?,?,?)",
                    (profile_name, f"Built-in {profile_name} capability profile", now()),
                )
                conn.executemany(
                    "INSERT OR IGNORE INTO profile_capabilities VALUES (?,?)",
                    [(profile_name, capability) for capability in sorted(capabilities)],
                )
            for actor_id, spec in BOOTSTRAP_IDENTITIES.items():
                existing = conn.execute(
                    "SELECT actor_id FROM actors WHERE actor_id=?", (actor_id,)
                ).fetchone()
                token_path = credential_dir / f"{actor_id}.token"
                if existing:
                    conn.executemany(
                        "INSERT OR IGNORE INTO actor_capabilities VALUES (?,?,?)",
                        [(actor_id, capability, now()) for capability in spec["capabilities"]],
                    )
                    conn.executemany(
                        "INSERT OR IGNORE INTO principal_profile_assignments VALUES (?,?,?,?)",
                        [
                            (actor_id, profile, now(), "bootstrap")
                            for profile in spec.get("profiles", set())
                        ],
                    )
                    continue
                token = secrets.token_urlsafe(32)
                run_id = new_id("run")
                conn.execute(
                    "INSERT INTO actors(actor_id,actor_kind,display_name,credential_hash,active,created_at,"
                    "principal_kind,metadata_json) VALUES (?,?,?,?,1,?,?, '{}')",
                    (
                        actor_id,
                        spec["kind"],
                        spec["display_name"],
                        credential_hash(token),
                        now(),
                        "service" if spec["kind"] == "maintenance_agent" else "ai_agent",
                    ),
                )
                conn.executemany(
                    "INSERT INTO actor_capabilities VALUES (?,?,?)",
                    [(actor_id, capability, now()) for capability in spec["capabilities"]],
                )
                conn.execute(
                    "INSERT INTO agent_runs VALUES (?,?,NULL,'[]',?,NULL)",
                    (run_id, actor_id, now()),
                )
                conn.executemany(
                    "INSERT INTO principal_profile_assignments VALUES (?,?,?,?)",
                    [
                        (actor_id, profile, now(), "bootstrap")
                        for profile in spec.get("profiles", set())
                    ],
                )
                token_path.write_text(
                    json.dumps({"token": token, "actor_id": actor_id, "run_id": run_id}, indent=2)
                    + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
                try:
                    os.chmod(token_path, 0o600)
                except OSError:
                    pass

    def _bootstrap_new_project_applicability_curators(self) -> None:
        """Grant the curator profile only while creating a new project ledger."""
        from .security import CAPABILITY_PROFILES

        profile = "evidence-curator"
        capabilities = CAPABILITY_PROFILES[profile]
        with self.transaction() as conn:
            for actor_id in ("organizer-agent", "maintenance-agent"):
                conn.execute(
                    "INSERT OR IGNORE INTO principal_profile_assignments "
                    "(actor_id,profile_name,assigned_at,assigned_by) VALUES (?,?,?,?)",
                    (actor_id, profile, now(), "bootstrap"),
                )
                conn.executemany(
                    "INSERT OR IGNORE INTO actor_capabilities(actor_id,capability,granted_at) "
                    "VALUES (?,?,?)",
                    [(actor_id, capability, now()) for capability in sorted(capabilities)],
                )

    def _record_policy_snapshot(self) -> None:
        raw = self.policy.path.read_text(encoding="utf-8")
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        existing = self.conn.execute(
            "SELECT content_hash FROM policy_snapshots WHERE policy_version = ?",
            (self.policy.version,),
        ).fetchone()
        if existing and existing["content_hash"] != digest:
            raise ValidationError(
                "policy.yaml changed without incrementing policy_version; bump the version explicitly"
            )
        if existing:
            return
        self.conn.execute(
            "INSERT OR IGNORE INTO policy_snapshots(policy_version, policy_json, content_hash, recorded_at) "
            "VALUES (?, ?, ?, ?)",
            (self.policy.version, raw, digest, now()),
        )
        self.conn.commit()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        if self.conn.in_transaction:
            self._savepoint_counter += 1
            savepoint = f"nested_{self._savepoint_counter}"
            self.conn.execute(f"SAVEPOINT {savepoint}")
            try:
                yield self.conn
                self.conn.execute(f"RELEASE SAVEPOINT {savepoint}")
            except Exception:
                self.conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                self.conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                raise
            return
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            yield self.conn
            before_commit = getattr(self, "before_commit", None)
            if before_commit is not None:
                before_commit()
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    @contextmanager
    def read_transaction(self) -> Iterator[sqlite3.Connection]:
        """Yield one SQLite snapshot without turning a read into a write.

        The workflow facts endpoint deliberately reads all of its related rows
        from one snapshot.  It must not use the normal ``BEGIN IMMEDIATE``
        helper: a facts lookup is not an implicit lease, commit, or journal
        mutation.
        """
        if self.conn.in_transaction:
            self._savepoint_counter += 1
            savepoint = f"read_{self._savepoint_counter}"
            self.conn.execute(f"SAVEPOINT {savepoint}")
            try:
                yield self.conn
                self.conn.execute(f"RELEASE SAVEPOINT {savepoint}")
            except Exception:
                self.conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                self.conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                raise
            return
        try:
            self.conn.execute("BEGIN")
            yield self.conn
        finally:
            if self.conn.in_transaction:
                self.conn.rollback()

    def row(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        found = self.conn.execute(sql, params).fetchone()
        return dict(found) if found else None

    def rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        return [dict(row) for row in self.conn.execute(sql, params).fetchall()]

    def migration_findings(self, classification: str | None = None) -> list[dict[str, Any]]:
        params: tuple[Any, ...] = ()
        clause = ""
        if classification:
            clause = " WHERE classification=?"
            params = (classification,)
        findings = self.rows(
            "SELECT * FROM migration_findings"
            + clause
            + " ORDER BY migration_version,classification,finding_id",
            params,
        )
        for finding in findings:
            finding["details"] = json.loads(finding.pop("details_json"))
            finding["resolution"] = (
                json.loads(finding.pop("resolution_json"))
                if finding.get("resolution_json")
                else None
            )
            finding["receipt"] = (
                self.row(
                    "SELECT * FROM migration_finding_resolution_receipts WHERE receipt_id=?",
                    (finding["resolution_receipt_id"],),
                )
                if finding.get("resolution_receipt_id")
                else None
            )
        return findings

    def migration_finding(self, finding_id: str) -> dict[str, Any]:
        from .migration_resolution import show_finding

        return show_finding(self, finding_id)

    def migration_finding_actions(self, finding_id: str) -> dict[str, Any]:
        from .migration_resolution import actions_for_finding

        return actions_for_finding(self, finding_id)

    def validate_migration_finding_resolution(
        self, finding_id: str, resolution: dict[str, Any]
    ) -> dict[str, Any]:
        from .migration_resolution import validate_resolution

        return validate_resolution(self, finding_id, resolution)

    def migration_finding_receipt(self, receipt_id: str) -> dict[str, Any]:
        receipt = self.row(
            "SELECT * FROM migration_finding_resolution_receipts WHERE receipt_id=?",
            (receipt_id,),
        )
        if not receipt:
            raise NotFoundError(f"Migration finding receipt not found: {receipt_id}")
        attempt = self.row(
            "SELECT * FROM migration_finding_resolution_attempts WHERE attempt_id=?",
            (receipt["accepted_attempt_id"],),
        )
        if not attempt:
            raise ConflictError("Migration finding receipt has no accepted attempt")
        attempt["resolution"] = json.loads(attempt.pop("resolution_json"))
        attempt["validation_result"] = json.loads(attempt.pop("validation_result_json"))
        for column in ("invariant_parameters_json", "postcondition_json"):
            if column in receipt:
                receipt[column.removesuffix("_json")] = json.loads(receipt.pop(column))
        dependencies = self.rows(
            "SELECT * FROM migration_resolution_dependencies WHERE receipt_id=? ORDER BY ordinal",
            (receipt_id,),
        )
        for dependency in dependencies:
            dependency["required_states"] = json.loads(dependency.pop("required_states_json"))
            dependency["snapshot"] = json.loads(dependency.pop("snapshot_json"))
        return {**receipt, "attempt": attempt, "dependencies": dependencies}

    def create_migration_policy_repair(
        self,
        finding_id: str,
        *,
        replacement_policy: dict[str, Any] | None = None,
        replacement_bundle: dict[str, Any] | None = None,
        issue_binding_map: dict[str, str] | None = None,
        actor: str,
    ) -> dict[str, Any]:
        from .policy_repair import create_policy_repair

        return create_policy_repair(
            self,
            finding_id,
            replacement_policy=replacement_policy,
            replacement_bundle=replacement_bundle,
            issue_binding_map=issue_binding_map,
            actor=actor,
        )

    def migration_policy_repair(self, repair_id: str) -> dict[str, Any]:
        from .policy_repair import show_policy_repair

        return show_policy_repair(self, repair_id)

    def validate_migration_policy_repair(self, repair_id: str) -> dict[str, Any]:
        from .policy_repair import validate_policy_repair

        return validate_policy_repair(self, repair_id)

    def apply_migration_policy_repair(
        self, repair_id: str, *, actor: str, reason: str = "apply exact Policy repair"
    ) -> dict[str, Any]:
        candidate = self.migration_policy_repair(repair_id)
        if candidate["state"] == "draft":
            candidate = self.validate_migration_policy_repair(repair_id)
        finding = self.migration_finding(candidate["finding_id"])
        return self.resolve_migration_finding(
            candidate["finding_id"],
            {
                "action": "apply_policy_repair",
                "subject_hash": finding["subject_hash"],
                "repair_id": repair_id,
                "repair_hash": candidate["plan_hash"],
                "reason": reason,
            },
            actor=actor,
        )

    def create_integrity_quarantine(
        self,
        finding_id: str,
        *,
        scopes: list[str],
        reason: str,
        actor: str,
    ) -> dict[str, Any]:
        from .integrity import create_quarantine

        return create_quarantine(self, finding_id, scopes=scopes, reason=reason, actor=actor)

    def integrity_quarantine(self, quarantine_id: str) -> dict[str, Any]:
        from .integrity import show_quarantine

        return show_quarantine(self, quarantine_id)

    def release_integrity_quarantine(
        self,
        quarantine_id: str,
        *,
        repair_receipt_id: str,
        actor: str,
    ) -> dict[str, Any]:
        from .integrity import release_quarantine

        return release_quarantine(
            self,
            quarantine_id,
            repair_receipt_id=repair_receipt_id,
            actor=actor,
        )

    def replay_migration_finding_receipt(
        self,
        receipt_id: str,
        *,
        full: bool = True,
        persist: bool = False,
        actor: str = "doctor",
    ) -> dict[str, Any]:
        from .migration_resolution import replay_receipt

        return replay_receipt(self, receipt_id, full=full, persist=persist, actor=actor)

    def resolve_migration_finding(
        self,
        finding_id: str,
        resolution: dict[str, Any],
        *,
        actor: str,
    ) -> dict[str, Any]:
        from .migration_resolution import apply_resolution

        result = apply_resolution(self, finding_id, resolution, actor=actor)
        if not result.get("accepted"):
            error_type = (
                MigrationResolutionStaleError
                if result.get("validation", {}).get("code") == "migration_resolution_stale"
                else MigrationResolutionError
            )
            raise error_type(
                "Migration finding resolution was rejected",
                details=result,
            )
        return result

    def idempotency_lookup(
        self, operation: str, key: str | None, payload: dict[str, Any]
    ) -> dict[str, Any] | None:
        if not key:
            return None
        request_hash = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        row = self.row(
            "SELECT request_hash,stored_response FROM request_idempotency "
            "WHERE operation=? AND idempotency_key=?",
            (operation, key),
        )
        if not row:
            return None
        if row["request_hash"] != request_hash:
            raise IdempotencyConflictError(
                f"Idempotency key {key!r} was already used with a different {operation} payload"
            )
        return json.loads(row["stored_response"])

    def idempotency_record(
        self,
        conn: sqlite3.Connection,
        operation: str,
        key: str | None,
        payload: dict[str, Any],
        response: dict[str, Any],
    ) -> None:
        if not key:
            return
        request_hash = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        conn.execute(
            "INSERT INTO request_idempotency VALUES (?,?,?,?,?)",
            (operation, key, request_hash, canonical_json(response), now()),
        )

    def api_request_lookup(
        self,
        *,
        actor_id: str,
        run_id: str,
        idempotency_key: str,
        payload: dict[str, Any],
    ) -> dict[str, Any] | None:
        request_hash = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        row = self.row(
            "SELECT * FROM api_requests WHERE actor_id=? AND run_id=? AND idempotency_key=?",
            (actor_id, run_id, idempotency_key),
        )
        if not row:
            return None
        if row["payload_hash"] != request_hash:
            raise IdempotencyConflictError(
                f"Idempotency key {idempotency_key!r} was already used with a different request"
            )
        if row["state"] == "in_progress":
            return {"state": "in_progress", "request_id": row["request_id"]}
        if row["state"] == "succeeded" and row["response_json"]:
            return {
                "state": "succeeded",
                "request_id": row["request_id"],
                "response": json.loads(row["response_json"]),
            }
        if row["state"] == "failed" and row["response_json"]:
            stored_response = json.loads(row["response_json"])
            if row["error_code"] == "internal_error" and int(stored_response.get("status", 0)) >= 500:
                return {"state": "retryable_failure", "request_id": row["request_id"]}
            return {
                "state": "failed",
                "request_id": row["request_id"],
                "response": stored_response,
                "error_code": row["error_code"],
            }
        return None

    def api_request_begin(
        self,
        conn: sqlite3.Connection,
        *,
        request_id: str,
        idempotency_key: str,
        actor_id: str,
        run_id: str,
        method: str,
        route: str,
        operation: str,
        payload: dict[str, Any],
    ) -> None:
        request_hash = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        conn.execute(
            "INSERT INTO api_requests(request_id,idempotency_key,actor_id,run_id,method,route,"
            "operation,payload_hash,state,response_json,error_code,created_at,completed_at) "
            "VALUES (?,?,?,?,?,?,?,?, 'in_progress',NULL,NULL,?,NULL)",
            (
                request_id,
                idempotency_key,
                actor_id,
                run_id,
                method,
                route,
                operation,
                request_hash,
                now(),
            ),
        )

    @staticmethod
    def api_request_succeed(
        conn: sqlite3.Connection, request_id: str, response: dict[str, Any]
    ) -> None:
        conn.execute(
            "UPDATE api_requests SET state='succeeded',response_json=?,completed_at=? "
            "WHERE request_id=? AND state='in_progress'",
            (canonical_json(response), now(), request_id),
        )

    @staticmethod
    def api_request_fail(
        conn: sqlite3.Connection,
        request_id: str,
        *,
        error_code: str,
        response: dict[str, Any],
    ) -> None:
        conn.execute(
            "UPDATE api_requests SET state='failed',response_json=?,error_code=?,completed_at=? "
            "WHERE request_id=? AND state='in_progress'",
            (canonical_json(response), error_code, now(), request_id),
        )

    def manager_metadata(self) -> dict[str, Any]:
        return self.row("SELECT * FROM manager_metadata WHERE singleton=1") or {
            "active_generation": "active",
            "token_epoch": 1,
            "maintenance_mode": 0,
        }

    def set_maintenance_mode(self, enabled: bool) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE manager_metadata SET maintenance_mode=?,updated_at=? WHERE singleton=1",
                (1 if enabled else 0, now()),
            )

    def _checkpoint_signature(
        self,
        *,
        event_count: int,
        chain_head: str,
        timestamp: str,
        policy_version: int,
        token_epoch: int,
    ) -> str:
        payload = canonical_json(
            {
                "event_count": event_count,
                "chain_head": chain_head,
                "timestamp": timestamp,
                "policy_version": policy_version,
                "token_epoch": token_epoch,
            }
        ).encode("utf-8")
        return hmac.new(self.secret, payload, hashlib.sha256).hexdigest()

    def _append_audit_checkpoint(
        self, conn: sqlite3.Connection, *, chain_head: str, timestamp: str
    ) -> None:
        event_count = int(conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
        metadata = conn.execute(
            "SELECT token_epoch FROM manager_metadata WHERE singleton=1"
        ).fetchone()
        token_epoch = int(metadata[0]) if metadata else 1
        signature = self._checkpoint_signature(
            event_count=event_count,
            chain_head=chain_head,
            timestamp=timestamp,
            policy_version=self.policy.version,
            token_epoch=token_epoch,
        )
        conn.execute(
            "INSERT INTO audit_checkpoints VALUES (?,?,?,?,?,?,?)",
            (
                new_id("audit_checkpoint"),
                event_count,
                chain_head,
                timestamp,
                self.policy.version,
                token_epoch,
                signature,
            ),
        )

    def _ensure_audit_checkpoint(self) -> None:
        tables = {
            row[0]
            for row in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "audit_checkpoints" not in tables:
            return
        latest = self.conn.execute(
            "SELECT event_hash,timestamp FROM audit_events ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        if not latest or not latest["event_hash"]:
            return
        count = int(self.conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0])
        checkpoint = self.conn.execute(
            "SELECT event_count,chain_head FROM audit_checkpoints ORDER BY event_count DESC LIMIT 1"
        ).fetchone()
        if checkpoint and int(checkpoint["event_count"]) == count:
            return
        with self.transaction() as conn:
            self._append_audit_checkpoint(
                conn, chain_head=str(latest["event_hash"]), timestamp=str(latest["timestamp"])
            )

    def verify_audit_chain(self) -> list[dict[str, Any]]:
        """Verify payloads, links, envelopes, and signed checkpoints without mutation."""

        findings: list[dict[str, Any]] = []
        events = self.rows("SELECT * FROM audit_events ORDER BY rowid")
        previous_hash: str | None = None
        for index, event in enumerate(events, start=1):
            actual_payload_hash = hashlib.sha256(event["payload_json"].encode("utf-8")).hexdigest()
            if event["payload_hash"] != actual_payload_hash:
                findings.append(
                    {
                        "code": "audit_payload_hash_mismatch",
                        "event_id": event["event_id"],
                        "event_number": index,
                        "expected": actual_payload_hash[:16],
                        "actual": str(event["payload_hash"])[:16],
                        "repairable": False,
                    }
                )
                break
            if event.get("previous_event_hash") != previous_hash:
                findings.append(
                    {
                        "code": "audit_previous_hash_mismatch",
                        "event_id": event["event_id"],
                        "event_number": index,
                        "expected": (previous_hash or "")[:16],
                        "actual": str(event.get("previous_event_hash") or "")[:16],
                        "repairable": False,
                    }
                )
                break
            envelope = canonical_json(
                {
                    "event_id": event["event_id"],
                    "timestamp": event["timestamp"],
                    "actor": event["actor"],
                    "action": event["action"],
                    "object_type": event["object_type"],
                    "object_id": event["object_id"],
                    "before_revision": event["before_revision"],
                    "after_revision": event["after_revision"],
                    "reason": event["reason"],
                    "payload_hash": event["payload_hash"],
                    "policy_version": event["policy_version"],
                    "previous_event_hash": event["previous_event_hash"],
                }
            )
            expected_hash = hashlib.sha256(envelope.encode("utf-8")).hexdigest()
            if event.get("event_hash") != expected_hash:
                findings.append(
                    {
                        "code": "audit_event_hash_mismatch",
                        "event_id": event["event_id"],
                        "event_number": index,
                        "expected": expected_hash[:16],
                        "actual": str(event.get("event_hash") or "")[:16],
                        "repairable": False,
                    }
                )
                break
            previous_hash = event["event_hash"]

        checkpoints = self.rows("SELECT * FROM audit_checkpoints ORDER BY event_count")
        from .project_component import installation

        binding = installation(self)
        anchors = binding["historical_checkpoints"] if binding else {}
        for checkpoint in checkpoints:
            expected_signature = self._checkpoint_signature(
                event_count=int(checkpoint["event_count"]),
                chain_head=checkpoint["chain_head"],
                timestamp=checkpoint["timestamp"],
                policy_version=int(checkpoint["policy_version"]),
                token_epoch=int(checkpoint["token_epoch"]),
            )
            portable_anchor = anchors.get(checkpoint["checkpoint_id"])
            signature_valid = (
                hmac.compare_digest(portable_anchor, hashlib.sha256(canonical_json(checkpoint).encode("utf-8")).hexdigest())
                if portable_anchor else hmac.compare_digest(checkpoint["signature"], expected_signature)
            )
            if not signature_valid:
                findings.append(
                    {
                        "code": "audit_checkpoint_mismatch",
                        "checkpoint_id": checkpoint["checkpoint_id"],
                        "repairable": False,
                    }
                )
                break
            count = int(checkpoint["event_count"])
            if count > len(events):
                findings.append(
                    {
                        "code": "audit_event_count_mismatch",
                        "checkpoint_id": checkpoint["checkpoint_id"],
                        "expected": count,
                        "actual": len(events),
                        "repairable": False,
                    }
                )
                break
            if count and events[count - 1].get("event_hash") != checkpoint["chain_head"]:
                findings.append(
                    {
                        "code": "audit_checkpoint_mismatch",
                        "checkpoint_id": checkpoint["checkpoint_id"],
                        "event_number": count,
                        "repairable": False,
                    }
                )
                break
        if events:
            if not checkpoints or int(checkpoints[-1]["event_count"]) != len(events):
                findings.append(
                    {
                        "code": "audit_event_count_mismatch",
                        "expected": int(checkpoints[-1]["event_count"]) if checkpoints else 0,
                        "actual": len(events),
                        "repairable": False,
                    }
                )
        elif checkpoints:
            findings.append(
                {
                    "code": "audit_event_count_mismatch",
                    "expected": int(checkpoints[-1]["event_count"]),
                    "actual": 0,
                    "repairable": False,
                }
            )
        return findings

    def audit(
        self,
        conn: sqlite3.Connection,
        *,
        actor: str,
        action: str,
        object_type: str,
        object_id: str,
        before_revision: int | None,
        after_revision: int | None,
        reason: str,
        payload: dict[str, Any],
    ) -> str:
        event_id = new_id("evt")
        timestamp = now()
        payload_json = canonical_json(payload)
        payload_hash = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        previous = conn.execute(
            "SELECT event_hash FROM audit_events WHERE event_hash IS NOT NULL "
            "ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        previous_hash = previous[0] if previous else None
        envelope = canonical_json(
            {
                "event_id": event_id,
                "timestamp": timestamp,
                "actor": actor,
                "action": action,
                "object_type": object_type,
                "object_id": object_id,
                "before_revision": before_revision,
                "after_revision": after_revision,
                "reason": reason,
                "payload_hash": payload_hash,
                "policy_version": self.policy.version,
                "previous_event_hash": previous_hash,
            }
        )
        event_hash = hashlib.sha256(envelope.encode("utf-8")).hexdigest()
        conn.execute(
            "INSERT INTO audit_events("
            "event_id,timestamp,actor,action,object_type,object_id,before_revision,after_revision,"
            "reason,payload_hash,payload_json,policy_version,previous_event_hash,event_hash"
            ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event_id,
                timestamp,
                actor,
                action,
                object_type,
                object_id,
                before_revision,
                after_revision,
                reason,
                payload_hash,
                payload_json,
                self.policy.version,
                previous_hash,
                event_hash,
            ),
        )
        self._append_audit_checkpoint(conn, chain_head=event_hash, timestamp=timestamp)
        return event_id
