"""Kernel-owned portable snapshots and new-instance preparation; never a merge."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path
from uuid import uuid4

from project_package.archive import canonical, digest, pack, safe_name, unpack

from ._version import __version__
from .context_scoped_rule import SCOPED_V2_RULE_DEFINITION, scoped_v2_rule_id
from .current_schema import CURRENT_SCHEMA_SQL
from .errors import PermissionError, ValidationError
from .policy import Policy
from .schema import SCHEMA_VERSION
from .security import credential_hash
from .store import Store, now

COMPONENT_FORMAT = "issue-manager-im-component/v1"
INSTALLATION_FILE = ".project-installation.json"


def generator_identity() -> str:
    root = Path(__file__).resolve().parent
    files = [path for path in sorted(root.iterdir()) if path.suffix in {'.py', '.sql'}]
    return hashlib.sha256(canonical([[path.name, digest(path)] for path in files])).hexdigest()


def schema_inventory(db: sqlite3.Connection) -> list[tuple]:
    return [(kind, name, table, re.sub(r"\s+", " ", sql or "").strip())
            for kind, name, table, sql in db.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]


def validate_database(path: Path) -> dict:
    with closing(sqlite3.connect(":memory:")) as reference:
        reference.executescript(CURRENT_SCHEMA_SQL)
        from .evidence_applicability_schema import install_evidence_applicability_v18

        install_evidence_applicability_v18(reference)
        expected = schema_inventory(reference)
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        db.enable_load_extension(False)
        db.execute("PRAGMA trusted_schema=OFF")
        if schema_inventory(db) != expected:
            raise ValidationError("Unexpected IM schema, index, trigger or view; no migration supported")
        if Store._schema_version(db) != SCHEMA_VERSION:
            raise ValidationError("Unsupported schema identity; no migration supported")
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok" or db.execute("PRAGMA foreign_key_check").fetchone():
            raise ValidationError("IM SQLite integrity check failed")
        active = db.execute("SELECT rule_id,definition_json FROM context_rule_selections JOIN context_rule_versions USING(rule_id) WHERE singleton=1").fetchone()
        if not active or active[0] != scoped_v2_rule_id() or json.loads(active[1]) != SCOPED_V2_RULE_DEFINITION:
            raise ValidationError("Unsupported rule identity")
        roots = [row[0] for row in db.execute("SELECT issue_id FROM issues WHERE parent_issue_id IS NULL ORDER BY issue_id")]
        counts = {name: db.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
                  for kind, name, _, _ in expected if kind == "table"}
        return {"schema_version": SCHEMA_VERSION, "rule_id": scoped_v2_rule_id(), "roots": roots, "table_counts": counts,
                "schema_sha256": hashlib.sha256(canonical(expected)).hexdigest()}


def _artifact_files(db: sqlite3.Connection, root: Path) -> list[Path]:
    files = []
    for artifact_id, sha, size, uri, role in db.execute("SELECT artifact_id,sha256,size,storage_uri,role FROM artifacts ORDER BY artifact_id"):
        safe_name(artifact_id)
        if not re.fullmatch(r"artifacts/objects/sha256/[0-9a-f]{2}/[0-9a-f]{64}", uri) or not uri.endswith(sha):
            raise ValidationError("Artifact storage path is not a managed immutable object")
        path = root / uri
        if not path.resolve().is_relative_to(root.resolve()):
            raise ValidationError("Managed Artifact escapes its ledger")
        if path.is_symlink() or not path.is_file() or path.stat().st_size != size or digest(path) != sha:
            raise ValidationError(f"Missing or damaged managed Artifact {artifact_id}")
        files.append(path)
        manifest = root / "artifacts" / "manifests" / f"{artifact_id}.json"
        if manifest.is_symlink() or (role == 'frozen' and not manifest.is_file()):
            raise ValidationError(f"Missing or unsafe frozen Artifact manifest {artifact_id}")
        if not manifest.exists():
            continue
        if manifest.stat().st_size > 8 * 1024**2:
            raise ValidationError('Artifact manifest exceeds 8 MiB')
        data = json.loads(manifest.read_text(encoding="utf-8"))
        if any(data.get(k) != v for k, v in {"artifact_id": artifact_id, "sha256": sha, "size": size, "storage_uri": uri}.items()):
            raise ValidationError("Artifact manifest disagrees with database")
        files.append(manifest)
    return files


def _external_references(db: sqlite3.Connection) -> list[dict]:
    # Enumerate declared locator fields only. Never open them or fetch URLs.
    result = []
    report_bytes = 0
    for kind, table, _, _ in schema_inventory(db):
        if kind != "table":
            continue
        columns = [row[1] for row in db.execute(f'PRAGMA table_info("{table}")')
                   if row[1] in {"source_uri", "original_locator", "locator", "source_locator", "declared_source_locator"}
                   or (table == "project_original_access_bindings" and row[1] == "reference")]
        for column in columns:
            for rowid, value in db.execute(f'SELECT rowid,"{column}" FROM "{table}" WHERE "{column}" IS NOT NULL AND "{column}" != \'\''):
                item = {"table": table, "row": rowid, "field": column, "reference": value,
                        "availability": "reference_only"}
                report_bytes += len(canonical(item)) + 1
                if report_bytes > 8 * 1024**2:
                    raise ValidationError('External reference inventory exceeds 8 MiB')
                result.append(item)
    return result


def export_component(manager, target: Path) -> dict:
    if manager.store.verify_audit_chain():
        raise ValidationError("Source audit chain verification failed")
    work = target.with_suffix(".work")
    work.mkdir(parents=True, exist_ok=False)
    try:
        dbpath = work / "issue_ledger.sqlite"
        with closing(sqlite3.connect(manager.store.db_path)) as source_db, closing(sqlite3.connect(dbpath)) as backup:
            source_db.backup(backup)
            backup.execute('PRAGMA journal_mode=DELETE')
        info = validate_database(dbpath)
        shutil.copyfile(manager.store.policy_path, work / "policy.yaml")
        with closing(sqlite3.connect(dbpath)) as db:
            files = _artifact_files(db, manager.store.ledger_dir)
            for source in set(files):
                destination = work / source.relative_to(manager.store.ledger_dir)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
            _artifact_files(db, work)
            external = _external_references(db)
            (work / "external-references.json").write_bytes(canonical(external))
            watermark = db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            # Authentication verifiers are installation data; keep identities/grants/history.
            for actor_id, in db.execute("SELECT actor_id FROM actors").fetchall():
                db.execute("UPDATE actors SET credential_hash=? WHERE actor_id=?", ("portable-disabled:" + uuid4().hex, actor_id))
            db.execute("UPDATE service_tokens SET nonce='portable-disabled:' || token_id")
            db.execute("UPDATE field_bundle_attachments SET upload_token_hash=NULL")
            db.commit()
            artifacts = db.execute("SELECT COUNT(*),COALESCE(SUM(size),0) FROM artifacts").fetchone()
        return pack(work, target, {"format": COMPONENT_FORMAT, "generator": __version__, 'generator_code_sha256': generator_identity(), **info,
                                  "snapshot_at": now(), "audit_watermark": watermark,
                                  "artifacts": {"count": artifacts[0], "bytes": artifacts[1]},
                                  "external_reference_count": len(external),
                                  "authentication": "disabled", "historical_backups": "not_carried"})
    finally:
        shutil.rmtree(work)


def validate_component(source: Path, work: Path) -> dict:
    metadata = unpack(source, work, expected_format=COMPONENT_FORMAT)
    allowed = {'format', 'generator', 'generator_code_sha256', 'schema_version', 'rule_id', 'roots', 'table_counts', 'schema_sha256',
               'snapshot_at', 'audit_watermark', 'artifacts', 'external_reference_count',
               'authentication', 'historical_backups', 'files'}
    if set(metadata) != allowed or metadata['authentication'] != 'disabled' or metadata['historical_backups'] != 'not_carried':
        raise ValidationError('Unexpected IM component manifest contract')
    inventory = {item["path"] for item in metadata["files"]}
    info = validate_database(work / "issue_ledger.sqlite")
    if any(metadata.get(key) != value for key, value in info.items()):
        raise ValidationError("IM manifest identity/counts disagree with database")
    if (work / 'policy.yaml').stat().st_size > 8 * 1024**2 or (work / 'external-references.json').stat().st_size > 8 * 1024**2:
        raise ValidationError('Component control file exceeds 8 MiB')
    Policy.load(work / "policy.yaml")
    with closing(sqlite3.connect(work / "issue_ledger.sqlite")) as db:
        files = _artifact_files(db, work)
        expected = {"issue_ledger.sqlite", "policy.yaml", "external-references.json",
                    *(path.relative_to(work).as_posix() for path in files)}
        if inventory != expected:
            raise ValidationError("Unexpected IM component file")
        external = _external_references(db)
        if (work / 'external-references.json').read_bytes() != canonical(external) or metadata['external_reference_count'] != len(external):
            raise ValidationError('External reference inventory mismatch')
        if db.execute("SELECT 1 FROM actors WHERE credential_hash NOT LIKE 'portable-disabled:%'").fetchone() or db.execute("SELECT 1 FROM service_tokens WHERE nonce NOT LIKE 'portable-disabled:%'").fetchone():
            raise ValidationError("Portable component contains active authentication verifiers")
    return metadata


def checkpoint_anchor(store: Store) -> dict:
    return {row["checkpoint_id"]: hashlib.sha256(canonical(row)).hexdigest()
            for row in store.rows("SELECT * FROM audit_checkpoints")}


def installation(store: Store) -> dict | None:
    path = store.ledger_dir / INSTALLATION_FILE
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    signature = data.pop("signature", "")
    if not hmac.compare_digest(signature, hmac.new(store.secret, canonical(data), hashlib.sha256).hexdigest()):
        raise PermissionError("Installation binding is damaged")
    return data


def prepare_component(source: Path, work: Path) -> dict:
    metadata = validate_component(source, work)
    store = Store(work)
    try:
        anchors = checkpoint_anchor(store)
        token = secrets.token_urlsafe(32)
        with store.transaction() as db:
            epoch = int(store.manager_metadata()["token_epoch"]) + 1
            # A portable copy is a new installation, never an old consumer's stream.
            db.execute("UPDATE domain_event_stream SET stream_id=? WHERE singleton=1", (uuid4().hex,))
            db.execute("UPDATE manager_metadata SET token_epoch=?,active_generation=?,updated_at=? WHERE singleton=1", (epoch, uuid4().hex, now()))
            db.execute("UPDATE actors SET credential_hash=? WHERE actor_id='maintenance-agent'", (credential_hash(token),))
            store.audit(db, actor="maintenance-agent", action="project.install", object_type="ledger",
                        object_id="new-installation", before_revision=None, after_revision=None,
                        reason="Portable installation; historical checkpoints anchored, execution isolated",
                        payload={"source_component_sha256": digest(source), "epoch": epoch,
                                 "historical_checkpoint_count": len(anchors), "authentication_rebuilt": True})
        (work / "credentials").mkdir(exist_ok=True)
        (work / "credentials" / "maintenance-agent.token").write_bytes(canonical({"token": token, "actor_id": "maintenance-agent"}))
        binding = {"installation_id": uuid4().hex, "execution_isolated": True,
                   "source_component_sha256": digest(source), "historical_checkpoints": anchors}
        binding["signature"] = hmac.new(store.secret, canonical(binding), hashlib.sha256).hexdigest()
        (work / INSTALLATION_FILE).write_bytes(canonical(binding))
        for directory in ("backups", "exports/issues", "runtime", "reports"):
            (work / directory).mkdir(parents=True, exist_ok=True)
    finally:
        store.close()
    from .service import IssueManager
    manager = IssueManager(work)
    try:
        doctor = manager.doctor()
        # Expired source leases are historical facts; isolation blocks them, no reap.
        allowed = {"expired_triage_lease", "expired_evidence_request_lease", "expired_review_lease"}
        blocking = [f for f in doctor["findings"] if f.get("blocking", True) and f["code"] not in allowed]
        if blocking:
            raise ValidationError("Prepared component doctor failed", details={"findings": blocking})
        return {"metadata": metadata, "execution_isolated": True, "doctor": doctor,
                "installation_id": binding["installation_id"]}
    finally:
        manager.close()
