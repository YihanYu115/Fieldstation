"""Finite authenticated binary component operations with host-bound storage."""
from __future__ import annotations

import hashlib
import hmac
import json
import shutil
from http import HTTPStatus
from pathlib import Path
from uuid import uuid4

from project_package.archive import MAX_ARCHIVE, atomic_save, canonical, pack

from .errors import PermissionError, ValidationError
from .project_component import (
    _external_references,
    export_component,
    prepare_component,
    validate_component,
    validate_database,
)


def stream_reply(handler, path: Path):
    handler.send_response(200)
    handler.send_header("Content-Type", "application/octet-stream")
    handler.send_header("Content-Length", str(path.stat().st_size))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    with path.open("rb") as stream:
        shutil.copyfileobj(stream, handler.wfile, 1024 * 1024)


def receive(handler, target: Path):
    try:
        size = int(handler.headers.get("Content-Length", "0"))
    except ValueError as exc:
        raise ValidationError("Invalid Content-Length") from exc
    if not 0 < size <= MAX_ARCHIVE or handler.headers.get("Transfer-Encoding"):
        raise ValidationError("Binary upload outside budget")
    if shutil.disk_usage(target.parent).free < size * 4 + 16 * 1024**2:
        raise ValidationError("Insufficient staging disk space")
    handler.connection.settimeout(60)
    try:
        with target.open("xb") as output:
            remaining = size
            while remaining:
                chunk = handler.rfile.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValidationError("Interrupted upload")
                output.write(chunk)
                remaining -= len(chunk)
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def handle(handler, manager) -> None:
    from urllib.parse import urlsplit

    parsed = urlsplit(handler.path)
    parts = parsed.path.strip("/").split("/")[2:]
    if parsed.query or not parts:
        raise ValidationError("Invalid component route")
    auth = handler._auth(manager, None, "backup.manage")
    auth.require("maintenance")
    if auth.platform_id is not None or handler.server.project_runtime is None:
        raise PermissionError("Whole-ledger project management is not bound")
    owner = hashlib.sha256(canonical([auth.actor_id, auth.run_id])).hexdigest()[:16]
    root = handler.server.project_runtime / owner
    root.mkdir(parents=True, exist_ok=True)
    if handler.command == "GET" and parts == ["info"]:
        info = validate_database(manager.store.db_path)
        objects = manager.store.conn.execute('SELECT COUNT(*),COALESCE(SUM(size),0) FROM artifacts').fetchone()
        info['artifacts'] = {'count': objects[0], 'bytes': objects[1]}
        info['external_reference_count'] = len(_external_references(manager.store.conn))
        info['instance_id'] = hmac.new(manager.store.secret, b'project-host-instance/v1', hashlib.sha256).hexdigest()
        handler._json(HTTPStatus.OK, {"result": info})
        return
    if handler.command == "POST" and parts == ["upload"]:
        upload_id = uuid4().hex[:16]
        receive(handler, root / f"{upload_id}.upload")
        handler._json(HTTPStatus.OK, {"result": {"upload_id": upload_id}})
        return
    if handler.command == "POST" and parts == ["export"]:
        body = handler._body()
        if set(body) != {"request_id"} or not isinstance(body["request_id"], str) or not 1 <= len(body["request_id"]) <= 256:
            raise ValidationError("Export requires only a bounded request_id")
        job_id = hashlib.sha256(canonical([owner, body["request_id"]])).hexdigest()[:16]
        path = root / f"{job_id}.component"
        receipt = root / f"{job_id}.json"
        if not receipt.exists():
            path.unlink(missing_ok=True)
            work = path.with_suffix('.work')
            if work.exists():
                shutil.rmtree(work)
            info = export_component(manager, path)
            atomic_save(receipt, {"job_id": job_id, "metadata": info})
        handler._json(HTTPStatus.OK, {"result": json.loads(receipt.read_text(encoding="utf-8"))})
        return
    if len(parts) != 2 or parts[0] not in {"download", "validate", "prepare", "prepared", "discard"}:
        raise ValidationError("Unknown component operation")
    operation, item_id = parts
    if len(item_id) != 16 or any(c not in "0123456789abcdef" for c in item_id):
        raise ValidationError("Invalid opaque component id")
    if handler.command == "GET" and operation in {"download", "prepared"}:
        receipt = root / f'{item_id}.{"json" if operation == "download" else "prepare.json"}'
        if not receipt.is_file():
            raise ValidationError('Component transfer is not complete')
        stream_reply(handler, root / f"{item_id}.{'component' if operation == 'download' else 'prepared'}")
        return
    if handler.command == 'POST' and operation == 'discard' and handler._body() == {}:
        for suffix in ('upload', 'validate', 'validate.json', 'prepare', 'prepare.json', 'prepared'):
            path = root / f'{item_id}.{suffix}'
            if path.is_dir():
                if not path.resolve().is_relative_to(root.resolve()):
                    raise ValidationError('cleanup target escaped component staging')
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
        handler._json(HTTPStatus.OK, {'result': {'discarded': True}})
        return
    if handler.command != "POST" or operation not in {"validate", "prepare"} or handler._body() != {}:
        raise ValidationError("Invalid component request")
    source = root / f"{item_id}.upload"
    stage = root / f"{item_id}.{operation}"
    receipt = root / f"{item_id}.{operation}.json"
    if not receipt.exists():
        if stage.exists():
            shutil.rmtree(stage)
        try:
            if operation == "validate":
                info = validate_component(source, stage)
                shutil.rmtree(stage)
            else:
                info = prepare_component(source, stage)
                prepared = root / f"{item_id}.prepared"
                pack(stage, prepared, {"format": "issue-manager-prepared-component/v1"})
                shutil.rmtree(stage)
            atomic_save(receipt, info)
        except BaseException:
            if stage.exists():
                shutil.rmtree(stage)
            raise
    handler._json(HTTPStatus.OK, {"result": json.loads(receipt.read_text(encoding="utf-8"))})
