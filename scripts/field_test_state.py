"""Manage external ledgers, checkpoints and fresh host sessions for field tests.

The command is a test-host utility. It uses issuectl's backup contract and the
public Manager HTTP API for state checks; role agents only receive the endpoint,
their role token file, and a fresh MCP journal path.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
from uuid import uuid4

from issue_manager import IssueManager

RUNTIME_NAME = "field-test-run.json"
ROLE_CAPABILITIES = {
    "field": {"issue.write", "context.read", "evidence.write"},
    "curator": {"context.read", "issue.write", "evidence.write", "evidence.relation.write"},
    "conclusion": {"context.read", "conclusion.propose", "conclusion.record"},
}


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _issuectl(ledger: str | Path, *arguments: str) -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "-m", "issue_manager", "--ledger", str(ledger), *arguments],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True,
        encoding="utf-8", timeout=120,
    )
    if result.returncode:
        raise RuntimeError(f"issuectl failed ({result.returncode}): {result.stdout.strip()} {result.stderr.strip()}")
    return json.loads(result.stdout)


def _run_dir(path: Path) -> Path:
    run_dir = path.resolve()
    if any((parent / ".git").exists() for parent in (run_dir, *run_dir.parents)):
        raise ValueError("Run directory must be outside a source checkout")
    return run_dir


def _runtime(run_dir: Path) -> tuple[Path, dict[str, Any]]:
    path = run_dir / RUNTIME_NAME
    if not path.is_file():
        raise ValueError(f"Not a field-test run directory: {run_dir}")
    return path, _read(path)


def _process_matches(pid: int, ledger: Path) -> bool:
    if os.name == "nt":
        expected = str(ledger).replace("'", "''")
        script = (
            "$p=Get-CimInstance Win32_Process -Filter 'ProcessId = %d' -ErrorAction SilentlyContinue; "
            "if ($p -and $p.CommandLine.Contains('%s') -and $p.CommandLine.Contains('issue_manager')) "
            "{ [Console]::Write('Y') }" % (pid, expected)
        )
        result = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                                capture_output=True, timeout=10)
        return result.returncode == 0 and result.stdout == b"Y"
    proc = Path(f"/proc/{pid}/cmdline")
    try:
        command = proc.read_bytes().replace(b"\0", b" ").decode("utf-8", errors="replace")
    except FileNotFoundError:
        return False
    return str(ledger) in command and "issue_manager" in command


def _stop_service(runtime: dict[str, Any], ledger: Path) -> None:
    service = runtime.get("service")
    if not service:
        return
    pid = int(service["pid"])
    if not _process_matches(pid, ledger):
        if not _pid_alive(pid):
            runtime["service"] = None
            return
        raise RuntimeError(f"Refusing to stop PID {pid}: it is not the recorded Manager for this ledger")
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], check=True,
                       capture_output=True, timeout=15)
    else:
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and _pid_alive(pid):
        time.sleep(0.1)
    if _pid_alive(pid):
        raise RuntimeError(f"Manager process {pid} did not stop")
    runtime["service"] = None


def _pid_alive(pid: int) -> bool:
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel32.WaitForSingleObject.restype = ctypes.c_uint32
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if not handle:
            return False
        try:
            return kernel32.WaitForSingleObject(handle, 0) == 0x00000102  # WAIT_TIMEOUT
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _start_service(run_dir: Path, runtime: dict[str, Any]) -> dict[str, Any]:
    ledger = Path(runtime["ledger"])
    log_path = run_dir / "service" / f"manager-{runtime['generation']}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("ab")
    proc = subprocess.Popen(
        [sys.executable, "-u", "-m", "issue_manager", "--ledger", str(ledger),
         "serve", "--host", "127.0.0.1", "--port", "0"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=log,
        cwd=Path(__file__).resolve().parents[1],
        creationflags=((subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_BREAKAWAY_FROM_JOB
                        | subprocess.CREATE_NO_WINDOW)
                       if os.name == "nt" else 0),
        start_new_session=(os.name != "nt"),
    )
    try:
        line = proc.stdout.readline() if proc.stdout else b""
        if not line:
            raise RuntimeError("Manager did not publish its endpoint")
        published = json.loads(line.decode("utf-8"))
        endpoint = published["endpoint"]
        health = _http(endpoint, "", "GET", "/v1/health", anonymous=True)
        if health.get("runtime") != "scoped-v2" or health.get("schema_version") != runtime["schema_version"]:
            raise RuntimeError("Started Manager reports an unexpected runtime or schema")
        runtime["service"] = {"pid": proc.pid, "endpoint": endpoint, "log": str(log_path)}
        return runtime["service"]
    except Exception:
        proc.terminate()
        proc.wait(timeout=10)
        raise
    finally:
        if proc.stdout:
            proc.stdout.close()
        log.close()


def _http(endpoint: str, token: str, method: str, route: str, body: Any = None,
          *, anonymous: bool = False) -> Any:
    headers = {"Accept": "application/json"}
    if not anonymous:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if method != "GET":
        data = json.dumps(body or {}, ensure_ascii=False).encode("utf-8")
        headers.update({"Content-Type": "application/json", "Idempotency-Key": "field-host-" + uuid4().hex,
                        "X-Request-ID": uuid4().hex})
    request = Request(endpoint + route, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8"))
        except ValueError:
            detail = {"message": str(exc)}
        raise RuntimeError(f"Manager HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Manager endpoint unavailable: {exc}") from exc
    return payload["result"]


def _mint_role(run_dir: Path, runtime: dict[str, Any], role: str) -> dict[str, str]:
    if role not in ROLE_CAPABILITIES:
        raise ValueError(f"Unknown role: {role}")
    manager = IssueManager(runtime["ledger"])
    try:
        actor = f"field-{role}-g{runtime['generation']}"
        principal = manager.credentials.issue_actor(
            actor_id=actor, actor_kind="organizer_agent", principal_kind="ai_agent",
            capabilities=ROLE_CAPABILITIES[role],
            maintenance_credential=manager.credentials.path_for("maintenance-agent"),
        )
        token_file = manager.credentials.path_for(actor)
        issued = manager.credentials.issue_run_token(
            actor_id=actor, run_id=principal["run_id"], capabilities=ROLE_CAPABILITIES[role],
            ttl_seconds=24 * 60 * 60,
            maintenance_credential=manager.credentials.path_for("maintenance-agent"),
        )
        token_file.write_text(json.dumps({"token": issued["token"], "actor_id": actor,
                                          "run_id": principal["run_id"],
                                          "token_id": issued["token_id"]}, indent=2) + "\n",
                              encoding="utf-8", newline="\n")
        try:
            os.chmod(token_file, 0o600)
        except OSError:
            pass
    finally:
        manager.close()
    session_id = f"{role}-g{runtime['generation']}-{uuid4().hex[:8]}"
    session_dir = run_dir / "sessions" / session_id
    session_dir.mkdir(parents=True, exist_ok=False)
    journal = session_dir / "mcp-journal.jsonl"
    journal.touch()
    binding = {"role": role, "actor_id": actor, "token_file": str(token_file),
               "endpoint": runtime["service"]["endpoint"], "mcp_journal": str(journal),
               "generation": runtime["generation"], "session_id": session_id,
               "token_id": issued["token_id"], "created_at": _utc()}
    _write(session_dir / "binding.json", binding)
    runtime["current_session"] = binding
    return binding


def _revoke_binding(runtime: dict[str, Any], binding: dict[str, Any] | None) -> None:
    if not binding:
        return
    manager = IssueManager(runtime["ledger"])
    try:
        manager.credentials.revoke_run_token(
            binding["token_id"],
            maintenance_credential=manager.credentials.path_for("maintenance-agent"),
        )
    finally:
        manager.close()


def _public_snapshot(runtime: dict[str, Any], issue_id: str, role: str,
                     binding: dict[str, str] | None = None,
                     relation_ids: list[str] | None = None) -> dict[str, Any]:
    binding = binding or _mint_role(Path(runtime["run_dir"]), runtime, role)
    token = _read(Path(binding["token_file"]))["token"]
    result = _http(binding["endpoint"], token, "GET", "/v1/context?" + urlencode({"issue": issue_id}))
    issue = result.get("issue") or {}
    conclusion = result.get("current_conclusion") or {}
    currentness = conclusion.get("currentness") or {}
    projection = result.get("scoped_context") or {}
    return {
        "issue_id": issue_id,
        "issue_head": issue.get("revision", issue.get("working_revision")),
        "current_conclusion_id": issue.get("current_conclusion_id"),
        "conclusion_currentness": currentness.get("currentness"),
        "evidence_ids": sorted(_collect_scoped_evidence_ids(projection)),
        "relations": {
            relation_id: _http(binding["endpoint"], token, "GET",
                               "/v1/scoped-evidence-relations/" + quote(relation_id, safe=""))
            for relation_id in (relation_ids or [])
        },
        "scoped_projection": projection,
    }


def _collect_scoped_evidence_ids(projection: dict[str, Any]) -> set[str]:
    """Collect Evidence IDs from the public scoped-v2 projection shape."""
    found: set[str] = set()
    for field in ("roots", "support_ids", "discovery_ids"):
        values = projection.get(field, [])
        if isinstance(values, list):
            found.update(item for item in values if isinstance(item, str))
    candidates = projection.get("candidate_states", [])
    if isinstance(candidates, list):
        found.update(
            item["candidate_id"]
            for item in candidates
            if isinstance(item, dict) and isinstance(item.get("candidate_id"), str)
        )
    return found


def _verify_expectations(snapshot: dict[str, Any], expectations: dict[str, Any]) -> None:
    for key in ("issue_head", "current_conclusion_id", "conclusion_currentness"):
        if key in expectations and snapshot.get(key) != expectations[key]:
            raise RuntimeError(f"State mismatch for {key}: expected {expectations[key]!r}, got {snapshot.get(key)!r}")
    for evidence_id in expectations.get("evidence_ids", []):
        if evidence_id not in snapshot["evidence_ids"]:
            raise RuntimeError(f"Expected Evidence {evidence_id} is absent from the public scoped projection")
    for relation_id, expected in expectations.get("relations", {}).items():
        actual = snapshot["relations"].get(relation_id)
        if actual is None or actual.get("active") is not expected:
            raise RuntimeError(f"Scoped relation {relation_id} active state mismatch: expected {expected!r}, got {actual}")


def _require_same_business_state(expected: dict[str, Any], actual: dict[str, Any], state_name: str) -> None:
    keys = ("issue_head", "current_conclusion_id", "conclusion_currentness", "evidence_ids")
    mismatches = {key: {"expected": expected.get(key), "actual": actual.get(key)}
                  for key in keys if expected.get(key) != actual.get(key)}
    expected_relations = {key: value.get("active") for key, value in expected.get("relations", {}).items()}
    actual_relations = {key: value.get("active") for key, value in actual.get("relations", {}).items()}
    if expected_relations != actual_relations:
        mismatches["relations"] = {"expected": expected_relations, "actual": actual_relations}
    if mismatches:
        raise RuntimeError(f"Public business state changed around {state_name}: {mismatches}")


def command_init(args: argparse.Namespace) -> dict[str, Any]:
    run_dir = _run_dir(args.run_dir)
    if run_dir.exists() and any(run_dir.iterdir()):
        raise ValueError(f"Refusing to reuse non-empty run directory: {run_dir}")
    run_dir.mkdir(parents=True, exist_ok=True)
    ledger = run_dir / "ledger"
    manager = IssueManager.initialize(ledger, context_rule="scoped-v2")
    try:
        schema_version = manager.store._schema_version(manager.store.conn)
        rule_id = manager.context_rules.active()["rule_id"]
    finally:
        manager.close()
    runtime = {"format": 1, "run_id": args.run_id or run_dir.name,
               "run_dir": str(run_dir), "ledger": str(ledger), "ledger_id": uuid4().hex,
               "issue_id": args.issue_id, "schema_version": schema_version,
               "runtime": "scoped-v2", "rule_id": rule_id, "generation": 1,
               "states": {}, "receipts": [], "service": None, "created_at": _utc()}
    _write(run_dir / RUNTIME_NAME, runtime)
    _start_service(run_dir, runtime)
    _write(run_dir / RUNTIME_NAME, runtime)
    try:
        binding = _mint_role(run_dir, runtime, args.role)
    except Exception:
        _stop_service(runtime, ledger)
        _write(run_dir / RUNTIME_NAME, runtime)
        raise
    _write(run_dir / RUNTIME_NAME, runtime)
    return {"run_dir": str(run_dir), "ledger": str(ledger), "runtime": runtime["runtime"],
            "schema_version": schema_version, "rule_id": rule_id, "session": binding}


def command_checkpoint(args: argparse.Namespace) -> dict[str, Any]:
    run_dir = _run_dir(args.run_dir)
    runtime_path, runtime = _runtime(run_dir)
    if runtime.get("service") is None:
        raise RuntimeError("No managed Manager session is active")
    state_name = args.state.upper()
    if state_name not in {"S0", "S1", "S2", "S3", "S4"}:
        raise ValueError("State must be one of S0, S1, S2, S3, S4")
    receipt_rows = _read(args.receipts) if args.receipts else []
    if not isinstance(receipt_rows, (list, dict)):
        raise ValueError("Receipts file must contain a JSON array or object of public HTTP receipts")
    if not args.issue_id:
        raise ValueError("--issue-id is required to capture a public state snapshot")
    binding = runtime.get("current_session")
    try:
        snapshot = _public_snapshot(runtime, args.issue_id, args.role, binding,
                                    list(args.relation_id or []))
        expected = _read(args.expect) if args.expect else {}
        if not isinstance(expected, dict):
            raise ValueError("Expectations file must contain a JSON object")
        if not isinstance(args.objects, dict) or not args.objects or any(
                not isinstance(key, str) or not key.strip() or not isinstance(value, str) or not value.strip()
                for key, value in args.objects.items()):
            raise ValueError("Objects file must map non-empty stable labels to non-empty returned IDs")
        if not receipt_rows:
            raise ValueError("Receipts file must record at least one public HTTP receipt")
        if "issue_head" not in expected or "current_conclusion_id" not in expected:
            raise ValueError("Expectations must specify issue_head and current_conclusion_id")
        if isinstance(expected["issue_head"], bool) or not isinstance(expected["issue_head"], int):
            raise ValueError("issue_head expectation must be an integer")
        if any(relation_id not in expected.get("relations", {}) for relation_id in (args.relation_id or [])):
            raise ValueError("Expectations must specify the active state for each --relation-id")
        _verify_expectations(snapshot, expected)
    except Exception as exc:
        _stop_service(runtime, Path(runtime["ledger"]))
        _revoke_binding(runtime, binding)
        runtime["current_session"] = None
        runtime["halted"] = {"reason": str(exc), "at": _utc(), "state": state_name}
        _write(runtime_path, runtime)
        raise
    runtime["receipts"].append({"state": state_name, "items": receipt_rows})
    _stop_service(runtime, Path(runtime["ledger"]))
    _revoke_binding(runtime, binding)
    runtime["service"] = None
    runtime["current_session"] = None
    runtime["checkpoint_in_progress"] = state_name
    _write(runtime_path, runtime)
    try:
        backup = _issuectl(runtime["ledger"], "backup", "create", "--label", f"field-{state_name}",
                           "--mode", "full")
        verified = _issuectl(runtime["ledger"], "backup", "verify", backup["backup_id"])
        if not verified.get("ok") or verified.get("schema_version") != runtime["schema_version"]:
            raise RuntimeError(f"Checkpoint backup verification failed: {verified}")
    except Exception as exc:
        runtime["halted"] = {"reason": str(exc), "at": _utc(), "state": state_name}
        _write(runtime_path, runtime)
        raise
    state = {"state": state_name, "issue_id": args.issue_id, "snapshot": snapshot,
             "expectations": expected, "receipts": receipt_rows,
             "objects": args.objects or {},
             "backup_id": backup["backup_id"], "backup_sha256": backup.get("sha256"),
             "verified_at": _utc()}
    runtime["states"][state_name] = state
    runtime.setdefault("objects", {}).update(args.objects or {})
    runtime["generation"] += 1
    try:
        _start_service(run_dir, runtime)
        session = _mint_role(run_dir, runtime, args.next_role or args.role)
        after_restart = _public_snapshot(runtime, args.issue_id, session["role"], session,
                                         list(snapshot["relations"]))
        _require_same_business_state(snapshot, after_restart, state_name)
    except Exception as exc:
        _stop_service(runtime, Path(runtime["ledger"]))
        _revoke_binding(runtime, runtime.get("current_session"))
        runtime["halted"] = {"reason": str(exc), "at": _utc(), "state": state_name}
        _write(runtime_path, runtime)
        raise
    _write(runtime_path, runtime)
    return {"state": state_name, "backup_id": backup["backup_id"],
            "verified": verified, "session": session}


def command_restore(args: argparse.Namespace) -> dict[str, Any]:
    run_dir = _run_dir(args.run_dir)
    runtime_path, runtime = _runtime(run_dir)
    state_name = args.state.upper()
    state = runtime["states"].get(state_name)
    if not state:
        raise ValueError(f"No checkpoint exists for {state_name}")
    ledger = Path(runtime["ledger"])
    _stop_service(runtime, ledger)
    old_binding = runtime.get("current_session")
    _revoke_binding(runtime, old_binding)
    runtime["service"] = None
    runtime["current_session"] = None
    runtime["restore_in_progress"] = state_name
    _write(runtime_path, runtime)
    try:
        verification = _issuectl(ledger, "backup", "verify", state["backup_id"])
        if not verification.get("ok"):
            raise RuntimeError(f"Checkpoint no longer verifies: {verification}")
        restored = _issuectl(ledger, "backup", "restore", state["backup_id"])
        identity = _issuectl(ledger, "status")
        if (identity.get("schema_version") != runtime["schema_version"]
                or identity.get("runtime") != runtime["runtime"]
                or identity.get("rule_id") != runtime["rule_id"]):
            raise RuntimeError(f"Restored ledger identity mismatch: {identity}")
    except Exception as exc:
        runtime["halted"] = {"reason": str(exc), "at": _utc(), "state": state_name}
        _write(runtime_path, runtime)
        raise
    runtime["generation"] += 1
    _start_service(run_dir, runtime)
    try:
        binding = _mint_role(run_dir, runtime, args.role)
    except Exception as exc:
        _stop_service(runtime, ledger)
        runtime["halted"] = {"reason": str(exc), "at": _utc(), "state": state_name}
        _write(runtime_path, runtime)
        raise
    actual = _public_snapshot(runtime, state["issue_id"], args.role, binding,
                              list(state["snapshot"].get("relations", {})))
    try:
        _verify_expectations(actual, state["expectations"])
        _require_same_business_state(state["snapshot"], actual, state_name)
    except Exception as exc:
        _stop_service(runtime, ledger)
        _revoke_binding(runtime, binding)
        runtime["halted"] = {"reason": str(exc), "at": _utc(), "state": state_name}
        _write(runtime_path, runtime)
        raise
    runtime["last_restore"] = {"state": state_name, "backup_id": state["backup_id"],
                               "restore": restored, "verified_at": _utc()}
    _write(runtime_path, runtime)
    return {"restored_state": state_name, "restore": restored,
            "public_state_verified": True, "session": runtime["current_session"]}


def command_rotate(args: argparse.Namespace) -> dict[str, Any]:
    """Rotate a role session without changing ledger business state."""
    run_dir = _run_dir(args.run_dir)
    runtime_path, runtime = _runtime(run_dir)
    if runtime.get("halted"):
        raise RuntimeError("Run is halted; refusing an implicit resume")
    old_binding = runtime.get("current_session")
    if runtime.get("service") is None or not old_binding:
        raise RuntimeError("Role rotation requires an active managed session")
    issue_id = args.issue_id or runtime["issue_id"]
    before = _public_snapshot(runtime, issue_id, old_binding["role"], old_binding)
    _stop_service(runtime, Path(runtime["ledger"]))
    _revoke_binding(runtime, old_binding)
    runtime["current_session"] = None
    from_generation = runtime["generation"]
    runtime["generation"] += 1
    _write(runtime_path, runtime)
    new_binding = None
    try:
        _start_service(run_dir, runtime)
        new_binding = _mint_role(run_dir, runtime, args.next_role)
        after = _public_snapshot(runtime, issue_id, args.next_role, new_binding)
        _require_same_business_state(before, after, f"role rotation to {args.next_role}")
    except Exception as exc:
        _stop_service(runtime, Path(runtime["ledger"]))
        _revoke_binding(runtime, new_binding or runtime.get("current_session"))
        runtime["current_session"] = None
        runtime["halted"] = {"reason": str(exc), "at": _utc(), "state": "role_rotation"}
        _write(runtime_path, runtime)
        raise
    row = {"from_role": old_binding["role"], "to_role": args.next_role,
           "from_generation": from_generation, "to_generation": runtime["generation"],
           "issue_id": issue_id, "old_token_revoked": True,
           "public_business_state_verified": True,
           "snapshot": {key: after[key] for key in (
               "issue_head", "current_conclusion_id", "conclusion_currentness", "evidence_ids", "relations")}}
    runtime.setdefault("session_rotations", []).append(row)
    _write(runtime_path, runtime)
    return {"rotation": row, "session": new_binding}


def command_status(args: argparse.Namespace) -> dict[str, Any]:
    run_dir = _run_dir(args.run_dir)
    _, runtime = _runtime(run_dir)
    return {"run_id": runtime["run_id"], "run_dir": str(run_dir),
            "ledger": runtime["ledger"], "schema_version": runtime["schema_version"],
            "rule_id": runtime["rule_id"], "generation": runtime["generation"],
            "states": {key: {"backup_id": row["backup_id"], "issue_id": row["issue_id"],
                              "snapshot": row["snapshot"], "receipts": row["receipts"],
                              "objects": row["objects"]}
                       for key, row in runtime["states"].items()},
            "session": runtime.get("current_session"), "service": runtime.get("service"),
            "session_rotations": runtime.get("session_rotations", []),
            "halted": runtime.get("halted")}


def command_close(args: argparse.Namespace) -> dict[str, Any]:
    run_dir = _run_dir(args.run_dir)
    runtime_path, runtime = _runtime(run_dir)
    _stop_service(runtime, Path(runtime["ledger"]))
    has_session = bool(runtime.get("current_session"))
    _revoke_binding(runtime, runtime.get("current_session"))
    runtime["current_session"] = None
    runtime["closed_at"] = _utc()
    _write(runtime_path, runtime)
    return {"run_id": runtime["run_id"], "service_stopped": True,
            "session_revoked": has_session}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="create a fresh external ledger and start its Manager")
    init.add_argument("--run-dir", required=True, type=Path)
    init.add_argument("--run-id")
    init.add_argument("--issue-id", required=True)
    init.add_argument("--role", choices=ROLE_CAPABILITIES, default="field")
    checkpoint = commands.add_parser("checkpoint", help="check public state, back it up, then rotate the session")
    checkpoint.add_argument("--run-dir", required=True, type=Path)
    checkpoint.add_argument("--state", required=True)
    checkpoint.add_argument("--issue-id", required=True)
    checkpoint.add_argument("--role", choices=ROLE_CAPABILITIES, default="curator")
    checkpoint.add_argument("--next-role", choices=ROLE_CAPABILITIES)
    checkpoint.add_argument("--receipts", required=True, type=Path)
    checkpoint.add_argument("--expect", required=True, type=Path)
    checkpoint.add_argument("--objects", required=True, type=Path,
                            help="JSON object mapping stable labels to returned Issue/Evidence/relation IDs")
    checkpoint.add_argument("--relation-id", action="append",
                            help="Scoped relation ID whose active status should be captured")
    restore = commands.add_parser("restore", help="stop Manager, restore checkpoint, mint a new session and verify")
    restore.add_argument("--run-dir", required=True, type=Path)
    restore.add_argument("--state", required=True)
    restore.add_argument("--role", choices=ROLE_CAPABILITIES, default="curator")
    rotate = commands.add_parser("rotate", help="revoke the active role session and issue a new role session after public state verification")
    rotate.add_argument("--run-dir", required=True, type=Path)
    rotate.add_argument("--next-role", choices=ROLE_CAPABILITIES, required=True)
    rotate.add_argument("--issue-id")
    status = commands.add_parser("status", help="show run and checkpoint metadata")
    status.add_argument("--run-dir", required=True, type=Path)
    close = commands.add_parser("close", help="stop the managed Manager and revoke its active role token")
    close.add_argument("--run-dir", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "checkpoint":
        args.objects = _read(args.objects) if args.objects else {}
    handlers = {"init": command_init, "checkpoint": command_checkpoint,
                "restore": command_restore, "rotate": command_rotate,
                "status": command_status, "close": command_close}
    try:
        result = handlers[args.command](args)
    except Exception as exc:
        parser.exit(2, f"field-test-state: {exc}\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
