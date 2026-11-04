"""Strict ZIP parsing shared by the trusted host and kernel component service."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import unicodedata
import zipfile
from pathlib import Path
from typing import Any

FORMAT = "issue-manager-project-package/v1"
MAX_ARCHIVE = 2 * 1024**3
MAX_TOTAL = 8 * 1024**3
MAX_FILE = 4 * 1024**3
MAX_FILES = 100000
MAX_MANIFEST = 8 * 1024**2


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def unique(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate JSON key")
    return result


def load(raw: bytes):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)


def atomic_save(path: Path, value: dict) -> None:
    temporary = path.with_suffix('.writing')
    with temporary.open('wb') as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def safe_name(name: str) -> str:
    if not isinstance(name, str) or not name or len(name) > 80 or name != unicodedata.normalize("NFC", name):
        raise ValueError("invalid name")
    if name[-1] in ". " or re.search(r'[\x00-\x1f<>:"/\\|?*]', name) or name in {".", ".."}:
        raise ValueError("invalid name")
    if name.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"{p}{i}" for p in ("COM", "LPT") for i in range(1, 10))}:
        raise ValueError("reserved name")
    return name


def member_path(name: str) -> str:
    if not isinstance(name, str) or len(name) > 1024 or "\\" in name or name.startswith("/"):
        raise ValueError("unsafe archive path")
    for part in name.split("/"):
        safe_name(part)
    return name


def pack(directory: Path, target: Path, metadata: dict) -> dict:
    files: list[dict[str, Any]] = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("links forbidden")
        if path.is_file():
            name = member_path(path.relative_to(directory).as_posix())
            files.append({"path": name, "size": path.stat().st_size, "sha256": digest(path)})
    if len(files) > MAX_FILES or sum(item["size"] for item in files) > MAX_TOTAL or any(item["size"] > MAX_FILE for item in files):
        raise ValueError("export file inventory exceeds budget")
    manifest = {**metadata, "files": files}
    raw = canonical(manifest)
    if len(raw) > MAX_MANIFEST:
        raise ValueError("manifest too large")
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as z:
        z.writestr("manifest.json", raw)
        z.writestr("manifest.sha256", hashlib.sha256(raw).hexdigest())
        for item in files:
            z.write(directory / item["path"], item["path"])
    if target.stat().st_size > MAX_ARCHIVE:
        target.unlink()
        raise ValueError("archive too large")
    return manifest


def _unpack(source: Path, directory: Path, *, expected_format: str = FORMAT) -> dict:
    if source.stat().st_size > MAX_ARCHIVE:
        raise ValueError("archive too large")
    with zipfile.ZipFile(source) as z:
        entries = z.infolist()
        if len(entries) > MAX_FILES + 2:
            raise ValueError("too many members")
        seen = set()
        total = 0
        for entry in entries:
            name = member_path(entry.filename)
            key = unicodedata.normalize("NFC", name).casefold()
            mode = entry.external_attr >> 16
            if key in seen or entry.is_dir() or entry.flag_bits & 1 or stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                raise ValueError("duplicate, link, directory or encrypted member")
            seen.add(key)
            if entry.file_size > MAX_FILE or entry.file_size > max(1, entry.compress_size) * 200:
                raise ValueError("member budget exceeded")
            total += entry.file_size
        if total > MAX_TOTAL:
            raise ValueError("unpacked budget exceeded")
        if not {"manifest.json", "manifest.sha256"} <= set(z.namelist()):
            raise ValueError("missing manifest")
        if z.getinfo("manifest.json").file_size > MAX_MANIFEST or z.getinfo("manifest.sha256").file_size != 64:
            raise ValueError("invalid manifest budget")
        raw = z.read("manifest.json")
        if hashlib.sha256(raw).hexdigest().encode("ascii") != z.read("manifest.sha256"):
            raise ValueError("manifest checksum mismatch")
        manifest = load(raw)
        if not isinstance(manifest, dict) or manifest.get("format") != expected_format or not isinstance(manifest.get("files"), list):
            raise ValueError("unknown package format")
        declared = {}
        for item in manifest["files"]:
            if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
                raise ValueError("invalid file declaration")
            name = member_path(item["path"])
            if name in declared or name in {"manifest.json", "manifest.sha256"} or type(item["size"]) is not int or not re.fullmatch("[0-9a-f]{64}", item["sha256"]):
                raise ValueError("invalid file inventory")
            declared[name] = item
        if set(z.namelist()) != {*declared, "manifest.json", "manifest.sha256"}:
            raise ValueError("undeclared or missing member")
        directory.mkdir(parents=True, exist_ok=False)
        if shutil.disk_usage(directory.parent).free < total * 3 + 16 * 1024**2:
            directory.rmdir()
            raise ValueError("insufficient disk budget")
        try:
            for name, item in declared.items():
                info = z.getinfo(name)
                if info.file_size != item["size"]:
                    raise ValueError("size mismatch")
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as stream, path.open("xb") as output:
                    shutil.copyfileobj(stream, output, 1024 * 1024)
                if digest(path) != item["sha256"]:
                    raise ValueError("file checksum mismatch")
        except BaseException:
            shutil.rmtree(directory)
            raise
        return manifest


def unpack(source: Path, directory: Path, *, expected_format: str = FORMAT) -> dict:
    try:
        return _unpack(source, directory, expected_format=expected_format)
    except (zipfile.BadZipFile, zipfile.LargeZipFile, KeyError, TypeError, RecursionError) as exc:
        raise ValueError('invalid or damaged project archive') from exc
