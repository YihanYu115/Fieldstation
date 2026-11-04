from __future__ import annotations

import csv
import hashlib
import json
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

if TYPE_CHECKING:
    from .security import AuthContext
    from .service import IssueManager


BUILTIN_ADAPTERS = {
    "json-records-v1": {"version": "1.0.0", "formats": ["json", "jsonl"]},
    "csv-table-v1": {"version": "1.0.0", "formats": ["csv", "tsv"]},
    "markdown-frontmatter-v1": {"version": "1.0.0", "formats": ["md", "markdown"]},
}
IMPORT_STATES = {
    "created",
    "inspected",
    "staged",
    "needs_mapping",
    "needs_input",
    "validated",
    "review_required",
    "ready",
    "applying",
    "applied",
    "partially_applied",
    "failed",
    "cancelled",
}


def _hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _adapter_hash(name: str) -> str:
    return _hash({"name": name, **BUILTIN_ADAPTERS[name], "protocol": "import-adapter/v1"})


def _set_path(target: dict[str, Any], path: str, value: Any) -> None:
    pieces = path.split(".")
    current = target
    for piece in pieces[:-1]:
        child = current.setdefault(piece, {})
        if not isinstance(child, dict):
            raise ValidationError(f"Mapping target path collides at {path!r}")
        current = child
    current[pieces[-1]] = value


def _coerce(value: Any, value_type: str | None) -> Any:
    if value_type is None or value is None:
        return value
    if value_type == "string":
        return str(value)
    if value_type == "integer":
        return int(value)
    if value_type == "number":
        return float(value)
    if value_type == "boolean":
        if isinstance(value, bool):
            return value
        lowered = str(value).strip().casefold()
        if lowered in {"true", "1", "yes", "y"}:
            return True
        if lowered in {"false", "0", "no", "n"}:
            return False
        raise ValueError(f"Cannot coerce {value!r} to boolean")
    if value_type == "json":
        return json.loads(value) if isinstance(value, str) else value
    raise ValueError(f"Unsupported mapping coercion: {value_type}")


class ImportService:
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
    def _source_files(source: Path) -> list[Path]:
        if source.is_file():
            return [source]
        if not source.is_dir():
            raise ValidationError(f"Import source does not exist: {source}")
        return sorted(path for path in source.rglob("*") if path.is_file())

    @staticmethod
    def _json_items(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        try:
            if path.suffix.casefold() == ".jsonl":
                values = [
                    json.loads(line)
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                metadata: dict[str, Any] = {}
            else:
                value = json.loads(path.read_text(encoding="utf-8"))
                metadata = dict(value) if isinstance(value, dict) else {}
                values = value.get("items", []) if isinstance(value, dict) else value
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError(f"Cannot parse JSON import source {path}: {exc}") from exc
        if isinstance(values, dict):
            values = [values]
        if not isinstance(values, list) or not all(isinstance(item, dict) for item in values):
            raise ValidationError(f"JSON import source {path} must contain object records")
        return [dict(item) for item in values], metadata

    @staticmethod
    def _csv_items(path: Path) -> list[dict[str, Any]]:
        try:
            with path.open("r", encoding="utf-8-sig", newline="") as stream:
                delimiter = "\t" if path.suffix.casefold() == ".tsv" else ","
                return [dict(row) for row in csv.DictReader(stream, delimiter=delimiter)]
        except (OSError, UnicodeDecodeError, csv.Error) as exc:
            raise ValidationError(f"Cannot parse tabular import source {path}: {exc}") from exc

    @staticmethod
    def _frontmatter(path: Path) -> dict[str, Any]:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ValidationError(f"Cannot read Markdown import source {path}: {exc}") from exc
        metadata: dict[str, Any] = {}
        body = text
        if text.startswith("---\n") or text.startswith("---\r\n"):
            normalized = text.replace("\r\n", "\n")
            end = normalized.find("\n---\n", 4)
            if end < 0:
                raise ValidationError(f"Markdown frontmatter is not closed: {path}")
            raw = normalized[4:end].strip()
            body = normalized[end + 5 :]
            if raw.startswith("{"):
                value = json.loads(raw)
                if not isinstance(value, dict):
                    raise ValidationError("Markdown JSON frontmatter must be an object")
                metadata = value
            else:
                for line in raw.splitlines():
                    if not line.strip() or line.lstrip().startswith("#"):
                        continue
                    if ":" not in line:
                        raise ValidationError(f"Unsupported frontmatter line in {path}: {line!r}")
                    key, value = line.split(":", 1)
                    parsed: Any = value.strip()
                    if parsed.startswith(("[", "{", '"')) or parsed in {"true", "false", "null"}:
                        try:
                            parsed = json.loads(parsed)
                        except json.JSONDecodeError:
                            pass
                    metadata[key.strip()] = parsed
        return {**metadata, "body": body}

    def _inspect_files(self, source: Path, adapter_name: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
        files = self._source_files(source)
        if not files:
            raise ValidationError("Import source contains no files")
        inventory = [
            {
                "path": str(path.relative_to(source) if source.is_dir() else path.name),
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
            for path in files
        ]
        items: list[dict[str, Any]] = []
        source_metadata: dict[str, Any] = {}
        for path in files:
            suffix = path.suffix.casefold()
            if adapter_name == "json-records-v1":
                if suffix not in {".json", ".jsonl"}:
                    continue
                parsed, metadata = self._json_items(path)
                source_metadata.update(
                    {
                        key: value
                        for key, value in metadata.items()
                        if key != "items" and key not in source_metadata
                    }
                )
            elif adapter_name == "csv-table-v1":
                if suffix not in {".csv", ".tsv"}:
                    continue
                parsed = self._csv_items(path)
            elif adapter_name == "markdown-frontmatter-v1":
                if suffix not in {".md", ".markdown"}:
                    continue
                parsed = [self._frontmatter(path)]
            else:
                raise ValidationError(f"Unknown built-in import adapter: {adapter_name}")
            for row_number, raw in enumerate(parsed, start=1):
                items.append(
                    {
                        "raw_location": f"{inventory[files.index(path)]['path']}#{row_number}",
                        "raw": raw,
                    }
                )
        if not items:
            raise ValidationError(f"No records matched adapter {adapter_name}")
        return items, inventory, source_metadata

    def inspect(
        self,
        source: str | Path,
        *,
        adapter_name: str,
        source_namespace: str,
        source_owner: str,
        source_system: str = "",
        source_exported_at: str | None = None,
        source_timezone: str | None = None,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "inspect external records",
        dry_run: bool = False,
    ) -> dict[str, Any]:
        actor = self._actor(auth, "import.inspect", actor)
        if adapter_name not in BUILTIN_ADAPTERS:
            raise ValidationError(
                f"Adapter {adapter_name!r} is not a built-in allowlisted import adapter"
            )
        if not source_namespace.strip() or not source_owner.strip():
            raise ValidationError("source_namespace and source_owner are required")
        path = Path(source).resolve()
        items, inventory, metadata = self._inspect_files(path, adapter_name)
        source_exported_at = source_exported_at or metadata.get("source_exported_at")
        source_timezone = source_timezone or metadata.get("source_timezone")
        source_system = source_system or str(metadata.get("source_system", adapter_name))
        if not source_system.strip():
            raise ValidationError("source_system is required")
        bundle = {
            "bundle_format": "issue-manager-import-bundle/v1",
            "source_namespace": source_namespace,
            "source_owner": source_owner,
            "source_system": source_system,
            "source_exported_at": source_exported_at,
            "source_timezone": source_timezone,
            "adapter": {
                "name": adapter_name,
                "version": BUILTIN_ADAPTERS[adapter_name]["version"],
                "hash": _adapter_hash(adapter_name),
            },
            "source_files": inventory,
            "items": items,
            "relationships": [],
            "attachments": [],
            "warnings": [],
        }
        bundle_hash = _hash(bundle)
        existing = self.store.row(
            "SELECT import_job_id,state FROM import_jobs WHERE source_namespace=? "
            "AND source_owner=? AND bundle_hash=?",
            (source_namespace, source_owner, bundle_hash),
        )
        if existing:
            return {**existing, "bundle_hash": bundle_hash, "idempotent_replay": True, "would_write": False}
        preview = {
            "adapter": bundle["adapter"],
            "source_files": inventory,
            "item_count": len(items),
            "bundle_hash": bundle_hash,
        }
        if dry_run:
            return {**preview, "would_write": False}
        job_id = new_id("import_job")
        timestamp = now()
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO import_jobs(import_job_id,state,source_namespace,source_owner,"
                "source_system,source_exported_at,source_timezone,adapter_name,adapter_version,"
                "adapter_hash,mapping_registration_id,mapping_content_hash,source_files_json,"
                "bundle_json,bundle_hash,created_at,created_by,updated_at,reviewed_changeset_id,"
                "apply_cursor) VALUES (?, 'inspected',?,?,?,?,?,?,?,?,NULL,NULL,?,?,?,?,?,?,NULL,0)",
                (
                    job_id,
                    source_namespace,
                    source_owner,
                    source_system,
                    source_exported_at,
                    source_timezone,
                    adapter_name,
                    BUILTIN_ADAPTERS[adapter_name]["version"],
                    _adapter_hash(adapter_name),
                    canonical_json(inventory),
                    canonical_json(bundle),
                    bundle_hash,
                    timestamp,
                    actor,
                    timestamp,
                ),
            )
            event_id = self.store.audit(
                conn,
                actor=actor,
                action="import.inspect",
                object_type="import_job",
                object_id=job_id,
                before_revision=None,
                after_revision=1,
                reason=reason,
                payload=preview,
            )
        return {
            **preview,
            "import_job_id": job_id,
            "state": "inspected",
            "event_id": event_id,
            "idempotent_replay": False,
            "would_write": True,
        }

    def submit_bundle(
        self,
        bundle: dict[str, Any],
        *,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "submit normalized import bundle",
    ) -> dict[str, Any]:
        """Accept adapter output without granting the adapter ledger access."""
        actor = self._actor(auth, "import.inspect", actor)
        if not isinstance(bundle, dict) or bundle.get("bundle_format") != "issue-manager-import-bundle/v1":
            raise ValidationError("Normalized Import Bundle must use issue-manager-import-bundle/v1")
        required = {"source_namespace", "source_owner", "source_system", "adapter", "source_files", "items"}
        missing = sorted(required - set(bundle))
        if missing:
            raise ValidationError(f"Normalized Import Bundle is missing fields: {missing}")
        adapter = bundle["adapter"]
        if not isinstance(adapter, dict):
            raise ValidationError("Normalized Import Bundle adapter must be an object")
        adapter_name = str(adapter.get("name", ""))
        adapter_version = str(adapter.get("version", ""))
        adapter_digest = str(adapter.get("hash", ""))
        identity_values = {
            "source_namespace": str(bundle.get("source_namespace", "")),
            "source_owner": str(bundle.get("source_owner", "")),
            "source_system": str(bundle.get("source_system", "")),
            "adapter.name": adapter_name,
            "adapter.version": adapter_version,
            "adapter.hash": adapter_digest,
        }
        blank = sorted(key for key, value in identity_values.items() if not value.strip())
        if blank:
            raise ValidationError(
                "Normalized Import Bundle identity fields cannot be blank",
                details={"blank_fields": blank},
            )
        if adapter_name in BUILTIN_ADAPTERS:
            if (
                adapter_version != BUILTIN_ADAPTERS[adapter_name]["version"]
                or adapter_digest != _adapter_hash(adapter_name)
            ):
                raise ValidationError("Built-in adapter identity does not match the core descriptor")
        else:
            allowed = self.store.row(
                "SELECT 1 AS allowed FROM adapter_allowlist WHERE adapter_kind='import' "
                "AND adapter_name=? AND adapter_version=? AND executable_hash=? AND enabled=1",
                (adapter_name, adapter_version, adapter_digest),
            )
            if not allowed:
                raise ValidationError("Import adapter is not in the local executable allowlist")
            verification = self.manager.adapters.verify(
                f"{adapter_name}@{adapter_version}", kind="import"
            )
            if not verification["ok"]:
                raise ConflictError(
                    "Import adapter executable changed after local installation",
                    details=verification,
                )
        if not isinstance(bundle["source_files"], list) or not isinstance(bundle["items"], list):
            raise ValidationError("Normalized Import Bundle source_files and items must be arrays")
        normalized_items: list[dict[str, Any]] = []
        for index, item in enumerate(bundle["items"]):
            if not isinstance(item, dict):
                raise ValidationError(f"Normalized Import item {index} must be an object")
            raw = item.get("raw", item.get("data", item))
            if not isinstance(raw, dict):
                raise ValidationError(f"Normalized Import item {index} raw fragment must be an object")
            normalized_items.append(
                {"raw_location": str(item.get("raw_location", f"items[{index}]")), "raw": raw}
            )
        canonical_bundle = {
            **bundle,
            "items": normalized_items,
            "relationships": list(bundle.get("relationships", [])),
            "attachments": list(bundle.get("attachments", [])),
            "warnings": list(bundle.get("warnings", [])),
        }
        bundle_hash = _hash(canonical_bundle)
        source_namespace = str(bundle["source_namespace"])
        source_owner = str(bundle["source_owner"])
        existing = self.store.row(
            "SELECT import_job_id,state FROM import_jobs WHERE source_namespace=? "
            "AND source_owner=? AND bundle_hash=?",
            (source_namespace, source_owner, bundle_hash),
        )
        if existing:
            return {**existing, "bundle_hash": bundle_hash, "idempotent_replay": True}
        job_id = new_id("import_job")
        timestamp = now()
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO import_jobs(import_job_id,state,source_namespace,source_owner,"
                "source_system,source_exported_at,source_timezone,adapter_name,adapter_version,"
                "adapter_hash,mapping_registration_id,mapping_content_hash,source_files_json,"
                "bundle_json,bundle_hash,created_at,created_by,updated_at,reviewed_changeset_id,"
                "apply_cursor) VALUES (?, 'inspected',?,?,?,?,?,?,?,?,NULL,NULL,?,?,?,?,?,?,NULL,0)",
                (
                    job_id,
                    source_namespace,
                    source_owner,
                    str(bundle["source_system"]),
                    bundle.get("source_exported_at"),
                    bundle.get("source_timezone"),
                    adapter_name,
                    adapter_version,
                    adapter_digest,
                    canonical_json(bundle["source_files"]),
                    canonical_json(canonical_bundle),
                    bundle_hash,
                    timestamp,
                    actor,
                    timestamp,
                ),
            )
            event_id = self.store.audit(
                conn,
                actor=actor,
                action="import.bundle.submit",
                object_type="import_job",
                object_id=job_id,
                before_revision=None,
                after_revision=1,
                reason=reason,
                payload={
                    "bundle_hash": bundle_hash,
                    "adapter": adapter,
                    "item_count": len(normalized_items),
                },
            )
        return {
            "import_job_id": job_id,
            "state": "inspected",
            "bundle_hash": bundle_hash,
            "item_count": len(normalized_items),
            "event_id": event_id,
            "idempotent_replay": False,
        }

    def _mapping(self, reference: str | None) -> dict[str, Any] | None:
        if not reference:
            return None
        return self.manager.registry.resolve(reference, kind="mapping_profile", for_creation=True)

    @staticmethod
    def _mapping_rules(definition: dict[str, Any]) -> list[dict[str, Any]]:
        raw = definition.get("mappings", definition.get("field_mappings", []))
        if isinstance(raw, dict):
            return [{"source": source, "target": target} for source, target in raw.items()]
        if not isinstance(raw, list) or not all(isinstance(item, dict) for item in raw):
            raise ValidationError("Mapping profile mappings must be an object or rule list")
        return [dict(item) for item in raw]

    def stage(
        self,
        import_job_id: str,
        *,
        mapping_reference: str | None = None,
        target_issue_id: str | None = None,
        target_template_reference: str | None = None,
        migration_level: str = "structure",
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "stage mapped external records",
        dry_run: bool = False,
    ) -> dict[str, Any]:
        actor = self._actor(auth, "import.stage", actor)
        job = self.store.row("SELECT * FROM import_jobs WHERE import_job_id=?", (import_job_id,))
        if not job:
            raise NotFoundError(f"Import job not found: {import_job_id}")
        if job["state"] not in {"inspected", "needs_mapping", "staged"}:
            raise ConflictError(f"Import job cannot be staged from state {job['state']}")
        if migration_level not in {"index", "structure", "evidence_backfill"}:
            raise ValidationError(f"Unsupported migration level: {migration_level}")
        mapping = self._mapping(mapping_reference)
        definition = mapping["definition"] if mapping else {}
        rules = self._mapping_rules(definition) if mapping else []
        bundle = json.loads(job["bundle_json"])
        staged: list[dict[str, Any]] = []
        item_errors: list[dict[str, Any]] = []
        for index, item in enumerate(bundle["items"]):
            raw = item["raw"]
            external_type_field = str(definition.get("external_object_type_field", "external_object_type"))
            external_id_field = str(definition.get("external_object_id_field", "external_object_id"))
            external_type = str(raw.get(external_type_field, definition.get("external_object_type", "record")))
            if not external_type.strip():
                item_errors.append(
                    {"item_index": index, "field_path": external_type_field, "code": "external_type_required", "message": "external object type is required"}
                )
            external_id = raw.get(external_id_field, raw.get("id"))
            if external_id is None or str(external_id).strip() == "":
                item_errors.append(
                    {"item_index": index, "field_path": external_id_field, "code": "external_id_required", "message": "external object ID is required"}
                )
                external_id = f"missing-{index}"
            mapped: dict[str, Any] = {}
            consumed = {external_type_field, external_id_field, "id"}
            for rule in rules:
                source_field = str(rule.get("source", ""))
                target_field = str(rule.get("target", ""))
                if not source_field or not target_field:
                    item_errors.append(
                        {"item_index": index, "field_path": "", "code": "mapping_rule", "message": "mapping rule requires source and target"}
                    )
                    continue
                if source_field not in raw:
                    if rule.get("required"):
                        item_errors.append(
                            {"item_index": index, "field_path": source_field, "code": "source_field_missing", "message": "required source field is missing"}
                        )
                    continue
                try:
                    mapped_value = _coerce(raw[source_field], rule.get("coerce"))
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    item_errors.append(
                        {"item_index": index, "field_path": source_field, "code": "coercion_failed", "message": str(exc)}
                    )
                    continue
                if rule.get("unit"):
                    mapped_value = {"value": mapped_value, "unit": rule["unit"]}
                _set_path(mapped, target_field, mapped_value)
                consumed.add(source_field)
            if not rules:
                candidate = raw.get("data", raw)
                mapped = dict(candidate) if isinstance(candidate, dict) else {"value": candidate}
                consumed.update(raw if candidate is raw else {"data"})
            extensions = {
                "unmapped": {key: raw[key] for key in sorted(set(raw) - consumed)},
                "raw_fragment_hash": _hash(raw),
            }
            issue_id = target_issue_id or raw.get(
                str(definition.get("target_issue_field", "target_issue_id"))
            ) or definition.get("target_issue_id")
            if issue_id and not self.store.row(
                "SELECT 1 FROM issues WHERE issue_id=?", (str(issue_id),)
            ):
                item_errors.append(
                    {
                        "item_index": index,
                        "field_path": "target_issue_id",
                        "code": "target_unresolved",
                        "message": f"Target Issue does not exist: {issue_id}",
                    }
                )
                issue_id = None
            template_ref = target_template_reference or raw.get(
                str(definition.get("target_template_field", "template_ref"))
            ) or definition.get("target_template_ref")
            template_id = None
            if template_ref:
                try:
                    template_id = self.manager.registry.resolve(
                        str(template_ref), kind="record_template", for_creation=True
                    )["registration_id"]
                except (NotFoundError, ConflictError, ValidationError) as exc:
                    item_errors.append(
                        {"item_index": index, "field_path": "template_ref", "code": "template_unresolved", "message": str(exc)}
                    )
            staged.append(
                {
                    "item_index": index,
                    "external_object_type": external_type,
                    "external_object_id": str(external_id),
                    "raw_location": item["raw_location"],
                    "raw": raw,
                    "raw_fragment_hash": _hash(raw),
                    "mapped": mapped,
                    "extensions": extensions,
                    "migration_level": migration_level,
                    "target_issue_id": str(issue_id) if issue_id else None,
                    "target_template_registration_id": template_id,
                }
            )
        state = "needs_mapping" if item_errors else "staged"
        preview = {
            "import_job_id": import_job_id,
            "state": state,
            "items": len(staged),
            "errors": item_errors,
            "mapping_registration_id": mapping["registration_id"] if mapping else None,
            "mapping_content_hash": mapping["content_hash"] if mapping else None,
        }
        if dry_run:
            return {**preview, "would_write": False}
        with self.store.transaction() as conn:
            conn.execute("DELETE FROM import_item_errors WHERE import_item_id IN (SELECT import_item_id FROM import_items WHERE import_job_id=?)", (import_job_id,))
            conn.execute("DELETE FROM import_items WHERE import_job_id=?", (import_job_id,))
            item_ids: dict[int, str] = {}
            for item in staged:
                item_id = new_id("import_item")
                item_ids[item["item_index"]] = item_id
                conn.execute(
                    "INSERT INTO import_items(import_item_id,import_job_id,item_index,"
                    "external_object_type,external_object_id,raw_location,raw_fragment_json,"
                    "raw_fragment_hash,mapped_data_json,extensions_json,migration_level,validation_state,"
                    "target_issue_id,target_template_registration_id,applied_object_type,applied_object_id) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,'pending',?,?,NULL,NULL)",
                    (
                        item_id,
                        import_job_id,
                        item["item_index"],
                        item["external_object_type"],
                        item["external_object_id"],
                        item["raw_location"],
                        canonical_json(item["raw"]),
                        item["raw_fragment_hash"],
                        canonical_json(item["mapped"]),
                        canonical_json(item["extensions"]),
                        item["migration_level"],
                        item["target_issue_id"],
                        item["target_template_registration_id"],
                    ),
                )
            for error in item_errors:
                conn.execute(
                    "INSERT INTO import_item_errors VALUES (?,?,?,?,?,?)",
                    (
                        new_id("import_error"),
                        item_ids[error["item_index"]],
                        error["field_path"],
                        error["code"],
                        error["message"],
                        "{}",
                    ),
                )
            conn.execute(
                "UPDATE import_jobs SET state=?,mapping_registration_id=?,mapping_content_hash=?,updated_at=? "
                "WHERE import_job_id=?",
                (
                    state,
                    mapping["registration_id"] if mapping else None,
                    mapping["content_hash"] if mapping else None,
                    now(),
                    import_job_id,
                ),
            )
            event_id = self.store.audit(
                conn,
                actor=actor,
                action="import.stage",
                object_type="import_job",
                object_id=import_job_id,
                before_revision=1,
                after_revision=2,
                reason=reason,
                payload=preview,
            )
        return {**preview, "event_id": event_id, "would_write": True}

    def validate(
        self,
        import_job_id: str,
        *,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "validate staged external records",
    ) -> dict[str, Any]:
        actor = self._actor(auth, "import.review", actor)
        job = self.store.row("SELECT * FROM import_jobs WHERE import_job_id=?", (import_job_id,))
        if not job:
            raise NotFoundError(f"Import job not found: {import_job_id}")
        if job["state"] not in {
            "staged", "needs_mapping", "validated", "ready", "partially_applied"
        }:
            raise ConflictError(f"Import job cannot be validated from state {job['state']}")
        items = self.store.rows(
            "SELECT * FROM import_items WHERE import_job_id=? ORDER BY item_index", (import_job_id,)
        )
        results: list[dict[str, Any]] = []
        any_invalid = False
        with self.store.transaction() as conn:
            for item in items:
                conn.execute("DELETE FROM import_item_errors WHERE import_item_id=?", (item["import_item_id"],))
                errors: list[dict[str, str]] = []
                if item["migration_level"] != "index" and not item["target_issue_id"]:
                    errors.append({"field_path": "target_issue_id", "code": "target_required", "message": "target Issue is required"})
                elif item["target_issue_id"] and not self.store.row("SELECT 1 FROM issues WHERE issue_id=?", (item["target_issue_id"],)):
                    errors.append({"field_path": "target_issue_id", "code": "target_unknown", "message": "target Issue does not exist"})
                if item["migration_level"] != "index" and not item["target_template_registration_id"]:
                    errors.append({"field_path": "template", "code": "template_required", "message": "Record template is required"})
                elif item["target_template_registration_id"]:
                    try:
                        validation = self.manager.records.validate_data(
                            item["target_template_registration_id"],
                            json.loads(item["mapped_data_json"]),
                            profile="draft",
                        )
                        errors.extend(validation["errors"])
                    except (ValidationError, NotFoundError, ConflictError) as exc:
                        errors.append({"field_path": "template", "code": "template_validation", "message": str(exc)})
                mapping = self.store.row(
                    "SELECT source_object_mapping_id,external_content_hash FROM external_object_mappings "
                    "WHERE source_namespace=? AND source_owner=? AND external_object_type=? "
                    "AND external_object_id=? AND mapping_role='record'",
                    (
                        job["source_namespace"],
                        job["source_owner"],
                        item["external_object_type"],
                        item["external_object_id"],
                    ),
                )
                if errors:
                    state = "invalid"
                    any_invalid = True
                elif mapping and mapping["external_content_hash"] == item["raw_fragment_hash"]:
                    state = "replayed"
                elif mapping:
                    state = "conflict"
                else:
                    duplicate = self.store.row(
                        "SELECT source_object_mapping_id FROM external_object_mappings "
                        "WHERE external_content_hash=? AND NOT(source_namespace=? AND source_owner=? "
                        "AND external_object_type=? AND external_object_id=?) LIMIT 1",
                        (
                            item["raw_fragment_hash"],
                            job["source_namespace"],
                            job["source_owner"],
                            item["external_object_type"],
                            item["external_object_id"],
                        ),
                    )
                    state = "possible_duplicate" if duplicate else "valid"
                conn.execute(
                    "UPDATE import_items SET validation_state=? WHERE import_item_id=?",
                    (state, item["import_item_id"]),
                )
                if state == "conflict" and mapping:
                    target = conn.execute(
                        "SELECT internal_revision_id FROM external_mapping_targets "
                        "WHERE source_object_mapping_id=? ORDER BY linked_at DESC LIMIT 1",
                        (mapping["source_object_mapping_id"],),
                    ).fetchone()
                    conflict_id = "conflict_" + hashlib.sha256(
                        f"import:{item['import_item_id']}:{item['raw_fragment_hash']}".encode()
                    ).hexdigest()[:32]
                    conn.execute(
                        "INSERT OR IGNORE INTO integration_conflicts("
                        "integration_conflict_id,source_kind,source_job_id,source_item_id,"
                        "source_namespace,source_owner,external_object_type,external_object_id,"
                        "existing_mapping_id,existing_internal_revision_id,previous_external_hash,"
                        "candidate_external_hash,raw_fragment_json,mapped_candidate_json,"
                        "mapping_registration_id,mapping_content_hash,state,state_revision,"
                        "resolution_action,resolution_reason,detected_at,detected_by,resolved_at,resolved_by) "
                        "VALUES (?,'import',?,?,?,?,?,?,?,?,?,?,?,?,?,?,'open',0,NULL,'',?,?,NULL,NULL)",
                        (
                            conflict_id, import_job_id, item["import_item_id"],
                            job["source_namespace"], job["source_owner"],
                            item["external_object_type"], item["external_object_id"],
                            mapping["source_object_mapping_id"],
                            target["internal_revision_id"] if target else None,
                            mapping["external_content_hash"], item["raw_fragment_hash"],
                            item["raw_fragment_json"], item["mapped_data_json"],
                            job["mapping_registration_id"], job["mapping_content_hash"],
                            now(), actor,
                        ),
                    )
                for error in errors:
                    conn.execute(
                        "INSERT INTO import_item_errors VALUES (?,?,?,?,?,?)",
                        (
                            new_id("import_error"),
                            item["import_item_id"],
                            str(error.get("field_path", "")),
                            str(error.get("code", "validation")),
                            str(error.get("message", "invalid item")),
                            canonical_json(error),
                        ),
                    )
                results.append(
                    {"item_index": item["item_index"], "state": state, "errors": errors}
                )
            target_state = "needs_mapping" if any_invalid else "validated"
            conn.execute(
                "UPDATE import_jobs SET state=?,updated_at=? WHERE import_job_id=?",
                (target_state, now(), import_job_id),
            )
            event_id = self.store.audit(
                conn,
                actor=actor,
                action="import.validate",
                object_type="import_job",
                object_id=import_job_id,
                before_revision=2,
                after_revision=3,
                reason=reason,
                payload={"state": target_state, "items": results},
            )
        return {"import_job_id": import_job_id, "state": target_state, "items": results, "event_id": event_id}

    def plan(self, import_job_id: str) -> dict[str, Any]:
        job = self.show(import_job_id)
        counts: dict[str, int] = {}
        for item in job["items"]:
            counts[item["validation_state"]] = counts.get(item["validation_state"], 0) + 1
        levels: dict[str, int] = {}
        would_create: dict[str, int] = {
            "external_mapping": 0,
            "record": 0,
            "working_entry": 0,
            "evidence_candidate": 0,
            "manifest_candidate": 0,
        }
        for item in job["items"]:
            if item["validation_state"] not in {"valid", "possible_duplicate"}:
                continue
            level = item["migration_level"]
            levels[level] = levels.get(level, 0) + 1
            would_create["external_mapping"] += 1
            if level in {"structure", "evidence_backfill"}:
                would_create["record"] += 1
                would_create["working_entry"] += 1
            if level == "evidence_backfill":
                would_create["evidence_candidate"] += 1
                would_create["manifest_candidate"] += 1
        return {
            "import_job_id": import_job_id,
            "state": job["state"],
            "counts": counts,
            "would_create_records": would_create["record"],
            "migration_levels": levels,
            "would_create_objects": would_create,
            "would_replay": counts.get("replayed", 0),
            "conflicts": counts.get("conflict", 0),
            "invalid": counts.get("invalid", 0),
            "unmapped_fields": sum(
                len(item["extensions"].get("unmapped", {})) for item in job["items"]
            ),
            "would_write": False,
        }

    def apply(
        self,
        import_job_id: str,
        *,
        reviewed_changeset_id: str | None = None,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "apply validated import atomically",
        dry_run: bool = False,
    ) -> dict[str, Any]:
        actor = self._actor(auth, "import.apply", actor)
        job = self.store.row("SELECT * FROM import_jobs WHERE import_job_id=?", (import_job_id,))
        if not job:
            raise NotFoundError(f"Import job not found: {import_job_id}")
        if job["state"] == "applied":
            receipts = self.receipt(import_job_id)
            return {"import_job_id": import_job_id, "state": "applied", "receipts": receipts, "idempotent_replay": True, "would_write": False}
        if job["state"] != "validated":
            raise ConflictError(f"Import job must be validated before apply; current state is {job['state']}")
        plan = self.plan(import_job_id)
        if plan["invalid"]:
            raise ValidationError("Import contains invalid items", details=plan)
        if dry_run:
            return {**plan, "would_write": False}
        items = self.store.rows(
            "SELECT * FROM import_items WHERE import_job_id=? ORDER BY item_index", (import_job_id,)
        )
        applied: list[dict[str, Any]] = []
        conflicts: list[dict[str, Any]] = []
        with self.store.transaction() as conn:
            from .integrity import assert_not_quarantined

            conn.execute(
                "UPDATE import_jobs SET state='applying',reviewed_changeset_id=?,updated_at=? "
                "WHERE import_job_id=? AND state='validated'",
                (reviewed_changeset_id, now(), import_job_id),
            )
            for item in items:
                assert_not_quarantined(
                    conn,
                    "import_item",
                    str(item["import_item_id"]),
                    "block_integration_apply",
                )
                state = item["validation_state"]
                if state == "applied":
                    applied.append(
                        {
                            "item_index": item["item_index"],
                            "state": "replayed",
                            "object_type": item["applied_object_type"],
                            "object_id": item["applied_object_id"],
                        }
                    )
                    continue
                if state == "replayed":
                    mapping = conn.execute(
                        "SELECT source_object_mapping_id FROM external_object_mappings "
                        "WHERE source_namespace=? AND source_owner=? AND external_object_type=? "
                        "AND external_object_id=? AND mapping_role='record'",
                        (
                            job["source_namespace"],
                            job["source_owner"],
                            item["external_object_type"],
                            item["external_object_id"],
                        ),
                    ).fetchone()
                    conn.execute(
                        "UPDATE import_items SET applied_object_type='external_mapping',"
                        "applied_object_id=? WHERE import_item_id=?",
                        (mapping["source_object_mapping_id"] if mapping else None, item["import_item_id"]),
                    )
                    applied.append({"item_index": item["item_index"], "state": "replayed"})
                    continue
                if state == "conflict":
                    conflicts.append(
                        {
                            "item_index": item["item_index"],
                            "external_object_id": item["external_object_id"],
                            "candidate_hash": item["raw_fragment_hash"],
                            "resolution": "candidate_revision_requires_triage",
                        }
                    )
                    continue
                if state not in {"valid", "possible_duplicate"}:
                    raise ValidationError(
                        f"Import item {item['item_index']} is not applyable: {state}"
                    )
                mapping_id = new_id("external_mapping")
                timestamp = now()
                conn.execute(
                    "INSERT INTO external_object_mappings(source_object_mapping_id,source_namespace,"
                    "source_owner,external_object_type,external_object_id,mapping_role,"
                    "first_import_job_id,latest_import_job_id,external_content_hash,"
                    "mapping_profile_registration_id,mapping_profile_content_hash,created_at,updated_at) "
                    "VALUES (?,?,?,?,?,'record',?,?,?,?,?,?,?)",
                    (
                        mapping_id,
                        job["source_namespace"],
                        job["source_owner"],
                        item["external_object_type"],
                        item["external_object_id"],
                        import_job_id,
                        import_job_id,
                        item["raw_fragment_hash"],
                        job["mapping_registration_id"],
                        job["mapping_content_hash"],
                        timestamp,
                        timestamp,
                    ),
                )
                if item["migration_level"] == "index":
                    conn.execute(
                        "UPDATE import_items SET validation_state='applied',"
                        "applied_object_type='external_index',applied_object_id=? "
                        "WHERE import_item_id=?",
                        (mapping_id, item["import_item_id"]),
                    )
                    applied.append(
                        {
                            "item_index": item["item_index"], "state": "applied",
                            "migration_level": "index", "source_object_mapping_id": mapping_id,
                            "created_objects": ["external_mapping", "search_index"],
                        }
                    )
                    continue
                record = self.manager.records.create(
                    item["target_issue_id"],
                    item["target_template_registration_id"],
                    data=json.loads(item["mapped_data_json"]),
                    source_mode="imported",
                    source_object_mapping_id=mapping_id,
                    actor=actor,
                    reason=f"{reason}; external {item['external_object_type']}/{item['external_object_id']}",
                )
                conn.execute(
                    "INSERT INTO external_mapping_targets VALUES (?,?,?,?,?)",
                    (
                        mapping_id,
                        "record_instance",
                        record["record_instance_id"],
                        record["record_revision_id"],
                        timestamp,
                    ),
                )
                working = self.manager.append_work(
                    item["target_issue_id"],
                    "Imported external object "
                    f"{item['external_object_type']}/{item['external_object_id']} with "
                    f"unmapped fields {canonical_json(json.loads(item['extensions_json']).get('unmapped', {}))}",
                    entry_type="note",
                    actor=actor,
                    reason="structure migration preserves external context",
                    idempotency_key=f"import-work:{item['import_item_id']}:{item['raw_fragment_hash']}",
                )
                evidence = None
                manifest_candidate = None
                candidate_id = None
                if item["migration_level"] == "evidence_backfill":
                    evidence = self.manager.add_evidence(
                        kind="external",
                        locator=(
                            f"import:{job['source_namespace']}:{job['source_owner']}:"
                            f"{item['external_object_type']}:{item['external_object_id']}:"
                            f"{item['raw_fragment_hash']}"
                        ),
                        issue_id=item["target_issue_id"],
                        description="Imported source fragment; Manifest candidate requires platform review",
                        content_hash=item["raw_fragment_hash"],
                        actor=actor,
                        reason="evidence_backfill creates declared Evidence only",
                        idempotency_key=f"import-evidence:{item['import_item_id']}:{item['raw_fragment_hash']}",
                    )
                    manifest_candidate = {
                        "format": "issue-manager-evidence-manifest-candidate/v1",
                        "source_namespace": job["source_namespace"],
                        "source_owner": job["source_owner"],
                        "source_system": job["source_system"],
                        "external_object_type": item["external_object_type"],
                        "external_object_id": item["external_object_id"],
                        "raw_location": item["raw_location"],
                        "raw_fragment_hash": item["raw_fragment_hash"],
                        "evidence_id": evidence["evidence_id"],
                        "review_requirement": (
                            "materialize through a registered platform Manifest submission; "
                            "do not infer Attestations or verified Proofs"
                        ),
                    }
                    candidate_id = new_id("manifest_candidate")
                    conn.execute(
                        "INSERT INTO import_manifest_candidates VALUES "
                        "(?,?,?,?,?,?,?,?,?,'pending_review',?,?)",
                        (
                            candidate_id, import_job_id, item["import_item_id"],
                            evidence["evidence_id"], job["source_namespace"],
                            job["source_owner"], job["source_system"],
                            item["raw_fragment_hash"], canonical_json(manifest_candidate),
                            timestamp, actor,
                        ),
                    )
                conn.execute(
                    "UPDATE import_items SET validation_state='applied',applied_object_type='record_instance',"
                    "applied_object_id=? WHERE import_item_id=?",
                    (record["record_instance_id"], item["import_item_id"]),
                )
                applied.append(
                    {
                        "item_index": item["item_index"],
                        "state": "applied",
                        "record_instance_id": record["record_instance_id"],
                        "record_revision_id": record["record_revision_id"],
                        "source_object_mapping_id": mapping_id,
                        "migration_level": item["migration_level"],
                        "working_entry_id": working.get("entry_id"),
                        "evidence_id": evidence.get("evidence_id") if evidence else None,
                        "import_manifest_candidate_id": candidate_id,
                        "manifest_candidate": manifest_candidate,
                        "created_objects": (
                            ["external_mapping", "record", "working_entry"]
                            + (["evidence_candidate", "manifest_candidate"] if evidence else [])
                        ),
                    }
                )
                self.store.fault(f"import.apply.after_item.{item['item_index']}")
            final_state = "partially_applied" if conflicts else "applied"
            receipt_result = {
                "import_job_id": import_job_id,
                "state": final_state,
                "applied": applied,
                "conflicts": conflicts,
                "from_cursor": 0,
                "to_cursor": len(items),
            }
            receipt_hash = _hash(receipt_result)
            receipt_id = new_id("import_receipt")
            chunk_row = conn.execute(
                "SELECT COALESCE(MAX(chunk_index),-1)+1 AS chunk_index FROM import_receipts "
                "WHERE import_job_id=?",
                (import_job_id,),
            ).fetchone()
            chunk_index = int(chunk_row["chunk_index"])
            conn.execute(
                "INSERT INTO import_receipts VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    receipt_id,
                    import_job_id,
                    chunk_index,
                    int(job["apply_cursor"]),
                    len(items),
                    canonical_json(receipt_result),
                    receipt_hash,
                    now(),
                    actor,
                ),
            )
            conn.execute(
                "UPDATE import_jobs SET state=?,apply_cursor=?,updated_at=? WHERE import_job_id=?",
                (final_state, len(items), now(), import_job_id),
            )
            event_id = self.store.audit(
                conn,
                actor=actor,
                action="import.apply",
                object_type="import_job",
                object_id=import_job_id,
                before_revision=3,
                after_revision=4,
                reason=reason,
                payload={**receipt_result, "receipt_hash": receipt_hash},
            )
        return {
            **receipt_result,
            "import_receipt_id": receipt_id,
            "receipt_hash": receipt_hash,
            "event_id": event_id,
            "idempotent_replay": False,
            "would_write": True,
        }

    def show(self, import_job_id: str) -> dict[str, Any]:
        job = self.store.row("SELECT * FROM import_jobs WHERE import_job_id=?", (import_job_id,))
        if not job:
            raise NotFoundError(f"Import job not found: {import_job_id}")
        result = dict(job)
        result["source_files"] = json.loads(result.pop("source_files_json"))
        result["bundle"] = json.loads(result.pop("bundle_json"))
        result["items"] = []
        for raw in self.store.rows(
            "SELECT * FROM import_items WHERE import_job_id=? ORDER BY item_index", (import_job_id,)
        ):
            item = dict(raw)
            item["raw_fragment"] = json.loads(item.pop("raw_fragment_json"))
            item["mapped_data"] = json.loads(item.pop("mapped_data_json"))
            item["extensions"] = json.loads(item.pop("extensions_json"))
            item["errors"] = self.store.rows(
                "SELECT field_path,error_code,message,details_json FROM import_item_errors "
                "WHERE import_item_id=? ORDER BY import_error_id",
                (item["import_item_id"],),
            )
            result["items"].append(item)
        result["manifest_candidates"] = []
        for candidate in self.store.rows(
            "SELECT * FROM import_manifest_candidates WHERE import_job_id=? "
            "ORDER BY created_at,import_manifest_candidate_id",
            (import_job_id,),
        ):
            candidate["candidate"] = json.loads(candidate.pop("candidate_json"))
            result["manifest_candidates"].append(candidate)
        return result

    def conflicts(self, import_job_id: str) -> list[dict[str, Any]]:
        if not self.store.row("SELECT 1 FROM import_jobs WHERE import_job_id=?", (import_job_id,)):
            raise NotFoundError(f"Import job not found: {import_job_id}")
        rows = self.store.rows(
            "SELECT * FROM integration_conflicts WHERE source_kind='import' AND source_job_id=? "
            "ORDER BY detected_at,integration_conflict_id",
            (import_job_id,),
        )
        for row in rows:
            row["raw_fragment"] = json.loads(row.pop("raw_fragment_json"))
            row["mapped_candidate"] = json.loads(row.pop("mapped_candidate_json"))
            row["resolutions"] = self.store.rows(
                "SELECT * FROM integration_conflict_resolutions WHERE integration_conflict_id=? "
                "ORDER BY to_revision",
                (row["integration_conflict_id"],),
            )
            for resolution in row["resolutions"]:
                resolution["details"] = json.loads(resolution.pop("details_json"))
        return rows

    def propose_resolution(
        self,
        import_job_id: str,
        conflict_id: str,
        action: str,
        *,
        resolution_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        conflict = self.store.row(
            "SELECT source_job_id FROM integration_conflicts "
            "WHERE integration_conflict_id=? AND source_kind='import'",
            (conflict_id,),
        )
        if not conflict or conflict["source_job_id"] != import_job_id:
            raise NotFoundError(f"Import conflict not found: {conflict_id}")
        operation = build_resolution_operation(
            self.store,
            "import",
            conflict_id,
            action,
            resolution_payload=resolution_payload,
        )
        return {
            "import_job_id": import_job_id,
            "conflict_id": conflict_id,
            "operation": operation,
            "changeset": {
                "changeset_version": 1,
                "intent": f"Resolve Import conflict {conflict_id}",
                "operations": [operation],
            },
        }

    def resolution_receipt(self, conflict_id: str) -> dict[str, Any]:
        receipt = self.store.row(
            "SELECT * FROM governed_conflict_resolution_receipts "
            "WHERE conflict_domain='import' AND conflict_id=?",
            (conflict_id,),
        )
        if not receipt:
            raise NotFoundError(f"Import conflict resolution receipt not found: {conflict_id}")
        receipt["review_ids"] = json.loads(receipt.pop("review_ids_json"))
        return receipt

    def resolve_conflict(
        self,
        import_job_id: str,
        conflict_id: str,
        decision: dict[str, Any] | str,
        *,
        expected_revision: int,
        reviewed_changeset_id: str | None = None,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "resolve external update conflict",
        _governance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        actor = self._actor(auth, "import.review", actor)
        conflict = self.store.row(
            "SELECT * FROM integration_conflicts WHERE integration_conflict_id=? "
            "AND source_kind='import' AND source_job_id=?",
            (conflict_id, import_job_id),
        )
        if not conflict:
            raise NotFoundError(f"Import conflict not found: {conflict_id}")
        if int(conflict["state_revision"]) != expected_revision:
            raise ConflictError(
                "Import conflict changed concurrently",
                details={"expected_revision": expected_revision, "current_revision": conflict["state_revision"]},
            )
        if conflict["state"] not in {"open", "needs_more_information"}:
            return {"integration_conflict_id": conflict_id, "state": conflict["state"], "idempotent_replay": True}
        normalized = {"action": decision} if isinstance(decision, str) else dict(decision)
        action = str(normalized.get("action", ""))
        supported = {
            "accept_as_new_revision", "keep_internal_and_update_mapping",
            "create_competing_record", "split_identity", "reject_candidate",
            "needs_more_information",
        }
        if action not in supported:
            raise ValidationError(f"Unsupported Import conflict resolution: {action!r}")
        item = self.store.row("SELECT * FROM import_items WHERE import_item_id=?", (conflict["source_item_id"],))
        if not item:
            raise ConflictError("Import conflict source item is missing")
        result: dict[str, Any] = {}
        target_state = "resolved"
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
                "import_item",
                str(item["import_item_id"]),
                "block_integration_apply",
            )
            if _governance is not None:
                validate_resolution_binding(conn, "import", _governance["operation"])
                governed_payload = {
                    key: value for key, value in normalized.items() if key != "action"
                }
                if (
                    _governance["operation"]["resolution"] != action
                    or _governance["operation"]["resolution_payload_hash"]
                    != content_hash(governed_payload)
                ):
                    raise ValidationError(
                        "Import conflict decision does not match the governed ChangeSet operation"
                    )
            target = conn.execute(
                "SELECT * FROM external_mapping_targets WHERE source_object_mapping_id=? "
                "AND internal_object_type='record_instance' ORDER BY linked_at LIMIT 1",
                (conflict["existing_mapping_id"],),
            ).fetchone()
            current = None
            used_in_report = None
            if target:
                current = conn.execute(
                    "SELECT r.validation_profile FROM record_instances i JOIN record_revisions r "
                    "ON r.record_revision_id=i.current_revision_id WHERE i.record_instance_id=?",
                    (target["internal_object_id"],),
                ).fetchone()
                used_in_report = conn.execute(
                    "SELECT 1 FROM report_build_inputs bi JOIN record_instances i "
                    "ON i.current_revision_id=bi.object_id WHERE bi.object_type='record_revision' "
                    "AND i.record_instance_id=? LIMIT 1",
                    (target["internal_object_id"],),
                ).fetchone()
            formal = bool(
                (
                    current
                    and current["validation_profile"]
                    in {"accepted", "canonical", "report"}
                )
                or used_in_report
            )
            if formal and _governance is None:
                proposed = build_resolution_operation(
                    self.store,
                    "import",
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
                if action == "accept_as_new_revision" and not target:
                    raise ConflictError("Conflict mapping has no internal Record target")
                mapped = json.loads(conflict["mapped_candidate_json"])
                if action == "accept_as_new_revision":
                    record = self.manager.records.revise(
                        target["internal_object_id"], mapped,
                        expected_revision_id=target["internal_revision_id"], profile="draft",
                        source_mode="imported", source_object_mapping_id=conflict["existing_mapping_id"],
                        actor=actor, reason=reason,
                    )
                    conn.execute(
                        "UPDATE external_mapping_targets SET internal_revision_id=?,linked_at=? "
                        "WHERE source_object_mapping_id=? AND internal_object_type='record_instance' "
                        "AND internal_object_id=?",
                        (record["record_revision_id"], now(), conflict["existing_mapping_id"], target["internal_object_id"]),
                    )
                    result = record
                else:
                    record = self.manager.records.create(
                        item["target_issue_id"], item["target_template_registration_id"],
                        data=mapped, profile="draft", source_mode="imported",
                        source_object_mapping_id=conflict["existing_mapping_id"], actor=actor,
                        reason=reason,
                    )
                    conn.execute(
                        "INSERT INTO external_mapping_targets VALUES (?,?,?,?,?)",
                        (
                            conflict["existing_mapping_id"], "record_instance",
                            record["record_instance_id"], record["record_revision_id"], now(),
                        ),
                    )
                    result = record
                conn.execute(
                    "UPDATE external_object_mappings SET external_content_hash=?,"
                    "latest_import_job_id=?,updated_at=? WHERE source_object_mapping_id=?",
                    (conflict["candidate_external_hash"], import_job_id, now(), conflict["existing_mapping_id"]),
                )
                conn.execute(
                    "UPDATE import_items SET validation_state='applied',applied_object_type='record_instance',"
                    "applied_object_id=? WHERE import_item_id=?",
                    (record["record_instance_id"], item["import_item_id"]),
                )
            elif action == "keep_internal_and_update_mapping":
                conn.execute(
                    "UPDATE external_object_mappings SET external_content_hash=?,latest_import_job_id=?,"
                    "updated_at=? WHERE source_object_mapping_id=?",
                    (conflict["candidate_external_hash"], import_job_id, now(), conflict["existing_mapping_id"]),
                )
                conn.execute(
                    "UPDATE import_items SET validation_state='replayed',applied_object_type='external_mapping',"
                    "applied_object_id=? WHERE import_item_id=?",
                    (conflict["existing_mapping_id"], item["import_item_id"]),
                )
            elif action == "split_identity":
                new_identity = str(normalized.get("external_object_id", "")).strip()
                if not new_identity:
                    raise ValidationError("split_identity requires external_object_id")
                conn.execute(
                    "UPDATE import_items SET external_object_id=?,validation_state='valid' "
                    "WHERE import_item_id=?",
                    (new_identity, item["import_item_id"]),
                )
                result["external_object_id"] = new_identity
            elif action == "reject_candidate":
                conn.execute(
                    "UPDATE import_items SET validation_state='replayed',applied_object_type='external_mapping',"
                    "applied_object_id=? WHERE import_item_id=?",
                    (conflict["existing_mapping_id"], item["import_item_id"]),
                )
            else:
                target_state = "needs_more_information"
            resolution_id = new_id("conflict_resolution")
            conn.execute(
                "INSERT INTO integration_conflict_resolutions VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    resolution_id, conflict_id, expected_revision, expected_revision + 1,
                    action, reason, canonical_json({**normalized, "result": result}),
                    _governance["changeset_id"] if _governance else None, now(), actor,
                ),
            )
            updated = conn.execute(
                "UPDATE integration_conflicts SET state=?,state_revision=state_revision+1,"
                "resolution_action=?,resolution_reason=?,resolved_at=?,resolved_by=? "
                "WHERE integration_conflict_id=? AND state_revision=?",
                (
                    target_state, action, reason,
                    now() if target_state == "resolved" else None,
                    actor if target_state == "resolved" else None,
                    conflict_id, expected_revision,
                ),
            )
            if updated.rowcount != 1:
                raise ConflictError("Import conflict changed concurrently")
            unresolved = int(conn.execute(
                "SELECT COUNT(*) FROM integration_conflicts WHERE source_kind='import' "
                "AND source_job_id=? AND state<>'resolved'",
                (import_job_id,),
            ).fetchone()[0])
            conn.execute(
                "UPDATE import_jobs SET state=?,updated_at=? WHERE import_job_id=?",
                ("partially_applied" if unresolved else "validated", now(), import_job_id),
            )
            audit_id = self.store.audit(
                conn, actor=actor, action="import.conflict.resolve", object_type="integration_conflict",
                object_id=conflict_id, before_revision=expected_revision,
                after_revision=expected_revision + 1, reason=reason,
                payload={"action": action, "state": target_state, "result": result},
            )
            governed_receipt = None
            if _governance is not None:
                governed_receipt = insert_governed_receipt(
                    conn,
                    domain="import",
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
            "integration_conflict_id": conflict_id, "state": target_state,
            "state_revision": expected_revision + 1, "action": action,
            "result": result, "event_id": audit_id,
            "governed_resolution_receipt": governed_receipt,
        }

    def revalidate(self, import_job_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.validate(import_job_id, **kwargs)

    def resume(
        self,
        import_job_id: str,
        *,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "resume resolved Import job",
    ) -> dict[str, Any]:
        unresolved = [item for item in self.conflicts(import_job_id) if item["state"] != "resolved"]
        if unresolved:
            raise ConflictError(
                "Import job still has unresolved conflicts",
                details={"conflict_ids": [item["integration_conflict_id"] for item in unresolved]},
            )
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE import_jobs SET state='validated',updated_at=? WHERE import_job_id=? "
                "AND state IN ('partially_applied','validated')",
                (now(), import_job_id),
            )
        return self.apply(import_job_id, actor=actor, auth=auth, reason=reason)

    def cancel_remaining(
        self,
        import_job_id: str,
        *,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
        reason: str = "cancel unresolved Import items",
    ) -> dict[str, Any]:
        actor = self._actor(auth, "import.review", actor)
        job = self.store.row("SELECT state FROM import_jobs WHERE import_job_id=?", (import_job_id,))
        if not job:
            raise NotFoundError(f"Import job not found: {import_job_id}")
        if job["state"] in {"applied", "cancelled"}:
            return {
                "import_job_id": import_job_id,
                "state": job["state"],
                "idempotent_replay": True,
            }
        if job["state"] not in {"partially_applied", "validated"}:
            raise ConflictError(
                f"Import job has no reviewed remainder to cancel: {job['state']}"
            )
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE integration_conflicts SET state='cancelled',resolution_action='cancel_remaining',"
                "resolution_reason=?,state_revision=state_revision+1,resolved_at=?,resolved_by=? "
                "WHERE source_kind='import' AND source_job_id=? AND state<>'resolved'",
                (reason, now(), actor, import_job_id),
            )
            conn.execute(
                "UPDATE import_jobs SET state='cancelled',updated_at=? WHERE import_job_id=?",
                (now(), import_job_id),
            )
        return {
            "import_job_id": import_job_id,
            "state": "cancelled",
            "idempotent_replay": False,
        }

    def receipt(self, import_job_id: str) -> list[dict[str, Any]]:
        if not self.store.row("SELECT 1 FROM import_jobs WHERE import_job_id=?", (import_job_id,)):
            raise NotFoundError(f"Import job not found: {import_job_id}")
        receipts = self.store.rows(
            "SELECT * FROM import_receipts WHERE import_job_id=? ORDER BY chunk_index",
            (import_job_id,),
        )
        for receipt in receipts:
            receipt["result"] = json.loads(receipt.pop("result_json"))
        return receipts
