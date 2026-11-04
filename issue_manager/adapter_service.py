from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import (
    AdapterExecutionError,
    AdapterOutputError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from .store import canonical_json, new_id, now, sha256_file
from .strict_json import strict_json_loads

if TYPE_CHECKING:
    from .security import AuthContext
    from .service import IssueManager


ADAPTER_PROTOCOL = "issue-manager-adapter/v1"
ADAPTER_KINDS = {"import", "report"}
DEFAULT_STDERR_LIMIT = 64 * 1024
MAXIMUM_ADAPTER_BYTES = 100 * 1024 * 1024


class AdapterService:
    """Local-operator adapter allowlist and bounded neutral JSON execution protocol."""

    def __init__(self, manager: IssueManager):
        self.manager = manager
        self.store = manager.store

    @staticmethod
    def _actor(auth: AuthContext | None, actor: str) -> str:
        if auth is not None:
            auth.require("maintenance")
            return auth.actor_id
        return actor

    @staticmethod
    def _descriptor(source: str | Path | dict[str, Any]) -> dict[str, Any]:
        if isinstance(source, dict):
            descriptor = dict(source)
        else:
            if not isinstance(source, (str, Path)):
                raise ValidationError(
                    "Adapter descriptor source must be a mapping or filesystem path"
                )
            try:
                descriptor = strict_json_loads(
                    Path(source).read_text(encoding="utf-8"),
                    path="$.adapter_descriptor",
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
                raise ValidationError(f"Cannot read Adapter descriptor: {exc}") from exc
        if not isinstance(descriptor, dict):
            raise ValidationError("Adapter descriptor must be a JSON object")
        required = {"kind", "name", "version", "protocol_version"}
        missing = sorted(required - set(descriptor))
        if missing:
            raise ValidationError(f"Adapter descriptor is missing fields: {missing}")
        unknown = sorted(
            set(descriptor)
            - {
                "kind", "name", "version", "protocol_version", "description",
                "timeout_seconds", "maximum_output_bytes", "maximum_stdout_bytes",
                "maximum_stderr_bytes", "maximum_decoded_output_bytes", "input_schema",
                "output_schema",
            }
        )
        if unknown:
            raise ValidationError(f"Unknown Adapter descriptor fields: {unknown}")
        if descriptor["kind"] not in ADAPTER_KINDS:
            raise ValidationError(f"Unsupported Adapter kind: {descriptor['kind']!r}")
        if descriptor["protocol_version"] != ADAPTER_PROTOCOL:
            raise ValidationError(
                f"Unsupported Adapter protocol: {descriptor['protocol_version']!r}"
            )
        for field in ("name", "version"):
            if not isinstance(descriptor[field], str) or not descriptor[field].strip():
                raise ValidationError(f"Adapter descriptor {field} cannot be blank")
        timeout = descriptor.get("timeout_seconds", 30)
        maximum = descriptor.get("maximum_output_bytes", 10 * 1024 * 1024)
        if not isinstance(timeout, int) or timeout < 1 or timeout > 300:
            raise ValidationError("Adapter timeout_seconds must be between 1 and 300")
        if (
            isinstance(maximum, bool)
            or not isinstance(maximum, int)
            or maximum < 1024
            or maximum > MAXIMUM_ADAPTER_BYTES
        ):
            raise ValidationError("Adapter maximum_output_bytes is outside the allowed range")
        limits = {
            "maximum_stdout_bytes": descriptor.get("maximum_stdout_bytes", maximum),
            "maximum_stderr_bytes": descriptor.get(
                "maximum_stderr_bytes", DEFAULT_STDERR_LIMIT
            ),
            "maximum_decoded_output_bytes": descriptor.get(
                "maximum_decoded_output_bytes", maximum
            ),
        }
        for field, value in limits.items():
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1024
                or value > MAXIMUM_ADAPTER_BYTES
            ):
                raise ValidationError(f"Adapter {field} is outside the allowed range")
        descriptor["timeout_seconds"] = timeout
        descriptor["maximum_output_bytes"] = maximum
        descriptor.update(limits)
        return descriptor

    @staticmethod
    def limits_snapshot(descriptor: dict[str, Any]) -> dict[str, int]:
        legacy = int(descriptor.get("maximum_output_bytes", 10 * 1024 * 1024))
        return {
            "timeout_seconds": int(descriptor.get("timeout_seconds", 30)),
            "maximum_stdout_bytes": int(
                descriptor.get("maximum_stdout_bytes", legacy)
            ),
            "maximum_stderr_bytes": int(
                descriptor.get("maximum_stderr_bytes", DEFAULT_STDERR_LIMIT)
            ),
            "maximum_decoded_output_bytes": int(
                descriptor.get("maximum_decoded_output_bytes", legacy)
            ),
        }

    def install(
        self,
        descriptor_source: str | Path | dict[str, Any],
        executable: str | Path,
        *,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
    ) -> dict[str, Any]:
        actor = self._actor(auth, actor)
        descriptor = self._descriptor(descriptor_source)
        executable_path = Path(executable).resolve()
        if not executable_path.is_file():
            raise ValidationError(f"Adapter executable is not a file: {executable_path}")
        executable_hash = sha256_file(executable_path)
        descriptor_hash = hashlib.sha256(
            canonical_json(descriptor).encode("utf-8")
        ).hexdigest()
        existing = self.store.row(
            "SELECT * FROM adapter_allowlist WHERE adapter_kind=? AND adapter_name=? "
            "AND adapter_version=? AND executable_hash=?",
            (
                descriptor["kind"], descriptor["name"], descriptor["version"],
                executable_hash,
            ),
        )
        if existing:
            return {**existing, "idempotent_replay": True}
        installed_at = now()
        verification = {
            "executable_exists": True,
            "executable_hash": executable_hash,
            "descriptor_hash": descriptor_hash,
            "protocol_version": descriptor["protocol_version"],
        }
        receipt_id = new_id("adapter_receipt")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO adapter_allowlist("
                "adapter_kind,adapter_name,adapter_version,executable_hash,descriptor_json,enabled,"
                "installed_at,installed_by,executable_path,descriptor_hash,protocol_version,"
                "verified_at,disabled_reason) VALUES (?,?,?,?,?,1,?,?,?,?,?,?, '')",
                (
                    descriptor["kind"], descriptor["name"], descriptor["version"],
                    executable_hash, canonical_json(descriptor), installed_at, actor,
                    str(executable_path), descriptor_hash, descriptor["protocol_version"],
                    installed_at,
                ),
            )
            conn.execute(
                "INSERT INTO adapter_install_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    receipt_id, descriptor["kind"], descriptor["name"], descriptor["version"],
                    str(executable_path), executable_hash, descriptor_hash,
                    descriptor["protocol_version"], canonical_json(verification),
                    installed_at, actor,
                ),
            )
            event_id = self.store.audit(
                conn, actor=actor, action="adapter.install", object_type="adapter",
                object_id=f"{descriptor['kind']}:{descriptor['name']}@{descriptor['version']}",
                before_revision=None, after_revision=1, reason="local operator installation",
                payload={**verification, "receipt_id": receipt_id},
            )
        return {
            "adapter_kind": descriptor["kind"], "adapter_name": descriptor["name"],
            "adapter_version": descriptor["version"], "executable_path": str(executable_path),
            "executable_hash": executable_hash, "descriptor_hash": descriptor_hash,
            "enabled": True, "verified_at": installed_at,
            "adapter_install_receipt_id": receipt_id, "event_id": event_id,
            "idempotent_replay": False,
        }

    def list(self) -> list[dict[str, Any]]:
        return self.store.rows(
            "SELECT adapter_kind,adapter_name,adapter_version,executable_hash,executable_path,"
            "descriptor_hash,protocol_version,enabled,installed_at,installed_by,verified_at,"
            "disabled_reason,state_revision FROM adapter_allowlist "
            "ORDER BY adapter_kind,adapter_name,adapter_version"
        )

    def _find(self, reference: str, kind: str | None = None) -> dict[str, Any]:
        if "@" not in reference:
            raise ValidationError("Adapter reference must be name@version")
        name, version = reference.rsplit("@", 1)
        params: list[Any] = [name, version]
        kind_clause = ""
        if kind:
            kind_clause = " AND adapter_kind=?"
            params.append(kind)
        rows = self.store.rows(
            "SELECT * FROM adapter_allowlist WHERE adapter_name=? AND adapter_version=?"
            + kind_clause
            + " ORDER BY installed_at DESC",
            tuple(params),
        )
        if not rows:
            raise NotFoundError(f"Adapter is not installed: {reference}")
        if len(rows) > 1:
            enabled = [row for row in rows if row["enabled"]]
            if len(enabled) == 1:
                return enabled[0]
            raise ConflictError(f"Adapter reference is ambiguous: {reference}")
        return rows[0]

    def _find_exact(
        self,
        *,
        kind: str,
        name: str,
        version: str,
        executable_hash: str,
    ) -> dict[str, Any] | None:
        return self.store.row(
            "SELECT * FROM adapter_allowlist WHERE adapter_kind=? AND adapter_name=? "
            "AND adapter_version=? AND executable_hash=?",
            (kind, name, version, executable_hash),
        )

    @staticmethod
    def _verify_row(adapter: dict[str, Any]) -> dict[str, Any]:
        executable = Path(adapter["executable_path"])
        actual_hash = sha256_file(executable) if executable.is_file() else None
        try:
            descriptor = json.loads(adapter["descriptor_json"])
            descriptor_hash = hashlib.sha256(
                canonical_json(descriptor).encode("utf-8")
            ).hexdigest()
        except (json.JSONDecodeError, TypeError, ValidationError):
            descriptor_hash = None
            descriptor = {}
        ok = (
            actual_hash == adapter["executable_hash"]
            and descriptor_hash == adapter["descriptor_hash"]
            and descriptor.get("protocol_version") == adapter["protocol_version"]
        )
        return {
            "adapter_kind": adapter["adapter_kind"],
            "adapter_name": adapter["adapter_name"],
            "adapter_version": adapter["adapter_version"],
            "enabled": bool(adapter["enabled"]),
            "ok": ok,
            "expected_executable_hash": adapter["executable_hash"],
            "actual_executable_hash": actual_hash,
            "expected_descriptor_hash": adapter["descriptor_hash"],
            "actual_descriptor_hash": descriptor_hash,
        }

    def verify(self, reference: str, *, kind: str | None = None) -> dict[str, Any]:
        adapter = self._find(reference, kind)
        result = self._verify_row(adapter)
        result["limits"] = self.limits_snapshot(json.loads(adapter["descriptor_json"]))
        result["state_revision"] = int(adapter["state_revision"])
        result["protocol_version"] = adapter["protocol_version"]
        return result

    def set_enabled(
        self,
        reference: str,
        enabled: bool,
        *,
        reason: str = "",
        kind: str | None = None,
        expected_revision: int | None = None,
        actor: str = "organizer-agent",
        auth: AuthContext | None = None,
    ) -> dict[str, Any]:
        actor = self._actor(auth, actor)
        adapter = self._find(reference, kind)
        current_revision = int(adapter["state_revision"])
        if expected_revision is not None and expected_revision != current_revision:
            raise ConflictError("Adapter state changed concurrently")
        if enabled and not self.verify(reference, kind=kind)["ok"]:
            raise ConflictError("Adapter cannot be enabled because local verification failed")
        if not enabled and not reason.strip():
            raise ValidationError("Disabling an Adapter requires a reason")
        with self.store.transaction() as conn:
            updated = conn.execute(
                "UPDATE adapter_allowlist SET enabled=?,disabled_reason=?,verified_at=?,"
                "state_revision=state_revision+1 WHERE adapter_kind=? AND adapter_name=? "
                "AND adapter_version=? AND executable_hash=? AND state_revision=?",
                (
                    1 if enabled else 0, "" if enabled else reason,
                    now() if enabled else adapter["verified_at"], adapter["adapter_kind"],
                    adapter["adapter_name"], adapter["adapter_version"], adapter["executable_hash"],
                    current_revision,
                ),
            )
            if updated.rowcount != 1:
                raise ConflictError("Adapter state changed concurrently")
            event_id = self.store.audit(
                conn, actor=actor, action="adapter.enable" if enabled else "adapter.disable",
                object_type="adapter", object_id=f"{adapter['adapter_name']}@{adapter['adapter_version']}",
                before_revision=current_revision, after_revision=current_revision + 1, reason=reason,
                payload={"enabled": enabled},
            )
        return {
            "adapter_name": adapter["adapter_name"],
            "adapter_version": adapter["adapter_version"],
            "enabled": enabled,
            "state_revision": current_revision + 1,
            "event_id": event_id,
        }

    def execute(
        self,
        reference: str,
        *,
        kind: str,
        payload: dict[str, Any],
        expected_identity: dict[str, Any] | None = None,
        limits: dict[str, int] | None = None,
    ) -> dict[str, Any]:
        from .project_component import installation

        if installation(self.store):
            raise ValidationError("Imported installation is execution isolated; adapters cannot execute")
        if kind not in ADAPTER_KINDS:
            raise ValidationError(f"Unsupported Adapter kind: {kind}")
        if expected_identity is not None:
            adapter = self._find_exact(
                kind=kind,
                name=str(expected_identity["adapter_name"]),
                version=str(expected_identity["adapter_version"]),
                executable_hash=str(expected_identity["adapter_executable_hash"]),
            )
            if adapter is None:
                raise AdapterExecutionError(
                    "Frozen Adapter implementation is unavailable",
                    code="adapter_identity_unavailable",
                    details={"identity": expected_identity},
                )
        else:
            adapter = self._find(reference, kind)
        verification = self._verify_row(adapter)
        if expected_identity is not None:
            identity_checks = {
                "adapter_name": adapter["adapter_name"],
                "adapter_version": adapter["adapter_version"],
                "adapter_executable_hash": adapter["executable_hash"],
                "adapter_descriptor_hash": adapter["descriptor_hash"],
                "adapter_protocol_version": adapter["protocol_version"],
                "adapter_state_revision": int(adapter["state_revision"]),
            }
            drift = {
                key: {"expected": expected_identity.get(key), "actual": actual}
                for key, actual in identity_checks.items()
                if expected_identity.get(key) != actual
            }
            if drift or not adapter["enabled"] or not verification["ok"]:
                raise AdapterExecutionError(
                    "Frozen Adapter identity drifted",
                    code="adapter_identity_drift",
                    details={"findings": drift, "verification": verification},
                )
        if not adapter["enabled"]:
            raise ConflictError(f"Adapter is disabled: {reference}")
        if not verification["ok"]:
            with self.store.transaction() as conn:
                self.store.audit(
                    conn,
                    actor="system",
                    action="adapter.security_drift",
                    object_type="adapter",
                    object_id=reference,
                    before_revision=int(adapter["state_revision"]),
                    after_revision=int(adapter["state_revision"]),
                    reason="execution refused after Adapter verification drift",
                    payload=verification,
                )
            raise ConflictError(
                "Adapter executable or descriptor hash drifted after installation",
                details=verification,
            )
        descriptor = json.loads(adapter["descriptor_json"])
        effective_limits = dict(limits or self.limits_snapshot(descriptor))
        request = {
            "protocol": ADAPTER_PROTOCOL,
            "kind": kind,
            "request": payload,
        }
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
        }
        if os.name == "nt":
            for name in ("SystemRoot", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"):
                if value := os.environ.get(name):
                    environment[name] = value
        completed = self._bounded_execute(
            adapter,
            request,
            limits=effective_limits,
            environment=environment,
        )
        post_verification = self._verify_row(adapter)
        if not post_verification["ok"]:
            raise AdapterExecutionError(
                "Adapter implementation changed during execution",
                code="adapter_identity_drift",
                details={"phase": "after_execution", "verification": post_verification},
            )
        try:
            stdout_text = completed["stdout"].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise AdapterOutputError(
                "Adapter output is not UTF-8",
                code="adapter_output_not_utf8",
                details=completed["details"],
            ) from exc
        try:
            result = strict_json_loads(stdout_text, path="$.adapter_output")
        except (ValidationError, json.JSONDecodeError, ValueError) as exc:
            raise AdapterOutputError(
                "Adapter output is not one strict JSON object",
                code="adapter_output_invalid_json",
                details=completed["details"],
            ) from exc
        if not isinstance(result, dict):
            raise AdapterOutputError(
                "Adapter output must be a JSON object",
                code="adapter_output_schema_invalid",
                details=completed["details"],
            )
        if kind == "import" and result.get("bundle_format") != "issue-manager-import-bundle/v1":
            raise AdapterOutputError(
                "Import Adapter did not return a Normalized Import Bundle",
                code="adapter_output_schema_invalid",
                details=completed["details"],
            )
        if kind == "report" and not isinstance(result.get("content_base64"), str):
            raise AdapterOutputError(
                "Report Renderer must return content_base64 and metadata",
                code="adapter_output_schema_invalid",
                details=completed["details"],
            )
        return {
            "adapter": f"{adapter['adapter_name']}@{adapter['adapter_version']}",
            "executable_hash": adapter["executable_hash"],
            "descriptor_hash": adapter["descriptor_hash"],
            "result": result,
            "stderr": completed["stderr"].decode("utf-8", errors="replace"),
            "limits": effective_limits,
            "metrics": completed["details"],
        }

    @staticmethod
    def _bounded_execute(
        adapter: dict[str, Any],
        request: dict[str, Any],
        *,
        limits: dict[str, int],
        environment: dict[str, str],
    ) -> dict[str, Any]:
        required_limits = {
            "timeout_seconds",
            "maximum_stdout_bytes",
            "maximum_stderr_bytes",
            "maximum_decoded_output_bytes",
        }
        if set(limits) != required_limits or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in limits.values()
        ):
            raise ValidationError("Frozen Adapter limits snapshot is invalid")
        start = time.monotonic()
        popen_options: dict[str, Any] = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "cwd": None,
            "env": environment,
            "shell": False,
        }
        if os.name == "nt":
            popen_options["creationflags"] = getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
        else:
            popen_options["start_new_session"] = True
        stdout = bytearray()
        stderr = bytearray()
        observed = {"stdout": 0, "stderr": 0}
        stop_reason: list[str] = []
        stop_event = threading.Event()
        lock = threading.Lock()
        process: subprocess.Popen[bytes] | None = None

        def reader(stream: Any, name: str, limit: int, destination: bytearray) -> None:
            try:
                while True:
                    chunk = stream.read(64 * 1024)
                    if not chunk:
                        break
                    with lock:
                        observed[name] += len(chunk)
                        remaining = max(0, limit - len(destination))
                        if remaining:
                            destination.extend(chunk[:remaining])
                        if observed[name] > limit and not stop_reason:
                            stop_reason.append(f"adapter_{name}_limit_exceeded")
                            stop_event.set()
            finally:
                stream.close()

        with tempfile.TemporaryDirectory(prefix="issue-manager-adapter-") as temporary:
            popen_options["cwd"] = temporary
            try:
                process = subprocess.Popen([adapter["executable_path"]], **popen_options)
            except OSError as exc:
                raise AdapterExecutionError(
                    "Adapter process could not be started",
                    code="adapter_nonzero_exit",
                    details={"exit_status": None, "elapsed_milliseconds": 0},
                ) from exc
            assert process.stdout is not None and process.stderr is not None
            stdout_reader = threading.Thread(
                target=reader,
                args=(
                    process.stdout,
                    "stdout",
                    limits["maximum_stdout_bytes"],
                    stdout,
                ),
                daemon=True,
            )
            stderr_reader = threading.Thread(
                target=reader,
                args=(
                    process.stderr,
                    "stderr",
                    limits["maximum_stderr_bytes"],
                    stderr,
                ),
                daemon=True,
            )
            stdout_reader.start()
            stderr_reader.start()
            assert process.stdin is not None
            try:
                process.stdin.write((canonical_json(request) + "\n").encode("utf-8"))
                process.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            finally:
                process.stdin.close()
            deadline = start + limits["timeout_seconds"]
            while process.poll() is None:
                if stop_event.wait(timeout=0.02):
                    break
                if time.monotonic() >= deadline:
                    stop_reason.append("adapter_timeout")
                    break
            if stop_reason and process.poll() is None:
                try:
                    if os.name == "nt":
                        system_root = environment.get("SystemRoot") or environment.get(
                            "WINDIR", r"C:\Windows"
                        )
                        taskkill = str(Path(system_root) / "System32" / "taskkill.exe")
                        terminated = subprocess.run(
                            [
                                taskkill,
                                "/PID",
                                str(process.pid),
                                "/T",
                                "/F",
                            ],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=1.0,
                            check=False,
                            shell=False,
                            env=environment,
                        )
                        if terminated.returncode != 0:
                            raise OSError("taskkill could not terminate Adapter tree")
                    else:
                        kill_process_group = getattr(os, "killpg", None)
                        if kill_process_group is None:
                            raise OSError("process-group termination is unavailable")
                        kill_process_group(process.pid, signal.SIGTERM)
                    process.wait(timeout=0.5)
                except (OSError, subprocess.TimeoutExpired):
                    if os.name == "nt":
                        process.kill()
                    else:
                        try:
                            kill_process_group = getattr(os, "killpg", None)
                            if kill_process_group is None:
                                raise OSError(
                                    "process-group termination is unavailable"
                                )
                            kill_process_group(
                                process.pid, getattr(signal, "SIGKILL", signal.SIGTERM)
                            )
                        except OSError:
                            process.kill()
                    try:
                        process.wait(timeout=1.0)
                    except subprocess.TimeoutExpired as exc:
                        raise AdapterExecutionError(
                            "Adapter process could not be terminated",
                            code="adapter_termination_failed",
                            details={
                                "elapsed_milliseconds": int(
                                    (time.monotonic() - start) * 1000
                                )
                            },
                        ) from exc
            if process.poll() is None:
                process.wait()
            # On Windows, terminating a process tree does not always make the
            # inherited pipe handles visible as EOF to reader threads. Close
            # the parent handles before joining so the temporary cwd can be
            # reclaimed and the timeout remains bounded.
            process.stdout.close()
            process.stderr.close()
            stdout_reader.join(timeout=1.0)
            stderr_reader.join(timeout=1.0)
            if stdout_reader.is_alive() or stderr_reader.is_alive():
                raise AdapterExecutionError(
                    "Adapter output readers could not be reclaimed",
                    code="adapter_termination_failed",
                    details={
                        "elapsed_milliseconds": int(
                            (time.monotonic() - start) * 1000
                        )
                    },
                )
        elapsed = int((time.monotonic() - start) * 1000)
        details = {
            "maximum_stdout_bytes": limits["maximum_stdout_bytes"],
            "maximum_stderr_bytes": limits["maximum_stderr_bytes"],
            "observed_stdout_bytes": observed["stdout"],
            "observed_stderr_bytes": observed["stderr"],
            "elapsed_milliseconds": elapsed,
            "exit_status": process.returncode if process else None,
            "adapter_identity_hash": hashlib.sha256(
                canonical_json(
                    {
                        "kind": adapter["adapter_kind"],
                        "name": adapter["adapter_name"],
                        "version": adapter["adapter_version"],
                        "executable_hash": adapter["executable_hash"],
                        "descriptor_hash": adapter["descriptor_hash"],
                    }
                ).encode("utf-8")
            ).hexdigest(),
            "stderr": bytes(stderr).decode("utf-8", errors="replace"),
        }
        if stop_reason:
            code = stop_reason[0]
            error_type = AdapterExecutionError if code == "adapter_timeout" else AdapterOutputError
            raise error_type(
                "Adapter execution exceeded a frozen resource limit",
                code=code,
                details=details,
            )
        if process is None or process.returncode != 0:
            raise AdapterExecutionError(
                f"Adapter exited with status {process.returncode if process else None}",
                code="adapter_nonzero_exit",
                details=details,
            )
        return {
            "stdout": bytes(stdout),
            "stderr": bytes(stderr),
            "details": details,
        }
