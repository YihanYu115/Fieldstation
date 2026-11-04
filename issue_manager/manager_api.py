"""Narrow HTTP boundary used by the generic orchestration adapter.

The Manager intentionally exposes only the fresh-project scoped-v2 workflow. Domain
services remain internal; migration, Workbench and role-specific routes are not public.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ._version import __version__
from .errors import (
    ConflictError,
    IdempotencyConflictError,
    IssueManagerError,
    MaintenanceModeError,
    NotFoundError,
    PermissionError,
    ReviewRequiredError,
    ValidationError,
)
from .security import AuthContext
from .service import IssueManager
from .strict_json import strict_json_dumps, strict_json_loads

LOGGER = logging.getLogger("issue_manager.manager_api")


def _status_for(error: Exception) -> HTTPStatus:
    if isinstance(error, MaintenanceModeError):
        return HTTPStatus.SERVICE_UNAVAILABLE
    if isinstance(error, NotFoundError):
        return HTTPStatus.NOT_FOUND
    if isinstance(error, (ReviewRequiredError, ConflictError)):
        return HTTPStatus.CONFLICT
    if isinstance(error, PermissionError):
        return HTTPStatus.FORBIDDEN
    if isinstance(error, ValidationError):
        return HTTPStatus.BAD_REQUEST
    return HTTPStatus.INTERNAL_SERVER_ERROR


def _required_text(body: dict[str, Any], field: str) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be a non-empty string")
    return value.strip()


class _ManagerHandler(BaseHTTPRequestHandler):
    server: "_ManagerHttpServer"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: HTTPStatus, payload: Any) -> None:
        raw = (strict_json_dumps(payload) + "\n").encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 2 * 1024 * 1024:
                raise ValidationError("Manager request body exceeds 2 MiB")
            value = strict_json_loads(self.rfile.read(length).decode("utf-8-sig", errors="strict"), path="$") if length else {}
        except ValidationError:
            raise
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError(f"Request body is not valid UTF-8 JSON: {exc}") from exc
        if not isinstance(value, dict):
            raise ValidationError("Request JSON must be an object")
        # Escaped unpaired surrogates are accepted by json.loads but cannot be
        # hashed/stored as canonical UTF-8. Reject before the request journal,
        # so malformed attachment text cannot become an internal 500 outcome.
        try:
            json.dumps(value, ensure_ascii=False).encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValidationError("Request JSON text must be UTF-8 encodable") from exc
        return value

    def _credential(self) -> str:
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            raise PermissionError("Manager requests require an Authorization: Bearer run token")
        value = authorization[7:].strip()
        if not value:
            raise PermissionError("Bearer run token is empty")
        return value

    def _auth(
        self,
        manager: IssueManager,
        auth: AuthContext | None,
        capability: str | None = None,
    ) -> AuthContext:
        resolved = auth or manager.credentials.resolve(self._credential())
        if capability:
            resolved.require(capability)
        return resolved

    def _dispatch(
        self,
        manager: IssueManager,
        body: dict[str, Any],
        *,
        auth: AuthContext | None = None,
    ) -> Any:
        parsed = urlparse(self.path)
        parts = [part for part in parsed.path.split("/") if part]

        if self.command == "GET" and parts == ["v1", "health"]:
            return {
                "ok": True,
                "runtime": "scoped-v2",
                "package_version": __version__,
                "schema_version": manager.store._schema_version(manager.store.conn),
            }

        from . import (
            browse_api,
            conclusion_rule_api,
            context_api,
            direct_split_api,
            domain_events_api,
            field_inbox_api,
            issue_overview_api,
            original_access_api,
            scoped_evidence_contribution_api,
            scoped_evidence_relation_api,
            working_conclusion_api,
        )

        if direct_split_api.handles(self.command, parts):
            current_auth = self._auth(manager, auth)
            return direct_split_api.dispatch(manager, self.command, parts, body, parsed.query, current_auth,
                                             idempotency_key=self.headers.get("Idempotency-Key"))

        if conclusion_rule_api.handles(self.command, parts):
            current_auth = self._auth(manager, auth, "issue.write" if self.command == "POST" else "context.read")
            return conclusion_rule_api.dispatch(manager, self.command, parts, body, parsed.query, current_auth,
                                                idempotency_key=self.headers.get("Idempotency-Key"))

        if domain_events_api.handles(self.command, parts):
            return domain_events_api.dispatch(manager, parsed.query, self._auth(manager, auth, "context.read"))

        if original_access_api.handles(self.command, parts):
            current_auth = self._auth(manager, auth, "context.read" if self.command == "GET" else "issue.write")
            return original_access_api.dispatch(manager, self.command, parts, body, parsed.query, current_auth)

        if browse_api.handles(self.command, parts):
            current_auth = self._auth(manager, auth, "context.read")
            return browse_api.dispatch(manager, parts, parsed.query, current_auth)

        if field_inbox_api.handles(self.command, parts):
            if self.command == "POST" and parts == ["v1", "field-packets"]:
                capability = "intake.submit"
            elif self.command == "POST" and len(parts) == 4 and parts[3] in {"curated-items", "reviews"}:
                capability = "evidence.write"
            else:
                capability = "context.read"
            current_auth = self._auth(manager, auth, capability)
            return field_inbox_api.dispatch(
                manager, self.command, parts, body, current_auth,
                query=parsed.query,
                request_id=self.headers.get("X-Request-ID"),
            )

        if working_conclusion_api.handles(self.command, parts):
            current_auth = self._auth(manager, auth, "conclusion.record")
            return working_conclusion_api.dispatch(
                manager, body, current_auth,
                idempotency_key=self.headers.get("Idempotency-Key"),
            )

        if scoped_evidence_contribution_api.handles(self.command, parts):
            current_auth = self._auth(manager, auth)
            return scoped_evidence_contribution_api.dispatch(
                manager, body, current_auth,
                idempotency_key=self.headers.get("Idempotency-Key"),
            )

        if scoped_evidence_relation_api.handles(self.command, parts):
            capability = "context.read"
            if self.command != "GET" and parts != [
                "v1", "scoped-evidence-relations", "preview-selection"
            ]:
                capability = "evidence.relation.write"
            current_auth = self._auth(manager, auth, capability)
            return scoped_evidence_relation_api.dispatch(
                manager, self.command, parts, body, current_auth,
                self.headers.get("Idempotency-Key"), query=parsed.query,
            )

        if context_api.handles(self.command, parts):
            current_auth = self._auth(manager, auth, "context.read")
            return context_api.dispatch(
                manager, self.command, parts, body, current_auth,
                query=parsed.query,
                idempotency_key=self.headers.get("Idempotency-Key"),
            )

        if issue_overview_api.handles(self.command, parts):
            current_auth = self._auth(manager, auth, "context.read")
            return issue_overview_api.dispatch(manager, parsed.query, current_auth)

        if self.command == "GET" and parts == ["v1", "context"]:
            query = parse_qs(parsed.query, keep_blank_values=True)
            if set(query) - {"issue", "intent"} or any(len(value) != 1 for value in query.values()):
                raise ValidationError("context accepts one issue and optional intent parameter")
            issue_id = query.get("issue", [""])[0]
            if not issue_id:
                raise ValidationError("context requires the issue query parameter")
            current_auth = self._auth(manager, auth, "context.read")
            return manager.inspect_issue(issue_id, auth=current_auth)

        if self.command == "POST" and parts == ["v1", "issues"]:
            current_auth = self._auth(manager, auth, "issue.write")
            allowed = {"issue_id", "issue_type", "title", "reason", "parent_issue_id", "scope", "issue_type_registration_id"}
            unknown = set(body) - allowed
            if unknown:
                raise ValidationError("Unknown issue fields", details={"fields": sorted(unknown)})
            reason = body.get("reason", "")
            if not isinstance(reason, str):
                raise ValidationError("reason must be a string")
            for field in ("parent_issue_id", "issue_type_registration_id"):
                if body.get(field) is not None:
                    _required_text(body, field)
            if body.get("scope") is not None and not isinstance(body["scope"], dict):
                raise ValidationError("scope must be an object")
            key = self.headers.get("Idempotency-Key")
            return manager.create_issue(
                _required_text(body, "issue_id"),
                _required_text(body, "issue_type"),
                _required_text(body, "title"),
                parent_issue_id=_required_text(body, "parent_issue_id") if body.get("parent_issue_id") is not None else None,
                scope=body.get("scope"),
                issue_type_registration_id=_required_text(body, "issue_type_registration_id") if body.get("issue_type_registration_id") is not None else None,
                actor=current_auth.actor_id,
                reason=reason,
                idempotency_key=f"http:{current_auth.actor_id}:{current_auth.run_id}:{key}",
            )

        if self.command == "GET" and len(parts) == 3 and parts[:2] == ["v1", "issues"]:
            self._auth(manager, auth, "context.read")
            return manager.show_issue(parts[2])

        raise NotFoundError("Manager API route not found")

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/v1/project-component/"):
            self._handle_component()
            return
        request_id = self.headers.get("X-Request-ID")
        manager: IssueManager | None = None
        try:
            manager = IssueManager(self.server.ledger_dir)
            result = self._dispatch(manager, {})
            self._json(HTTPStatus.OK, {"request_id": request_id, "result": result})
        except IssueManagerError as exc:
            self._domain_error(request_id, exc)
        except Exception:
            LOGGER.exception("Unhandled Manager read failure request_id=%s", request_id)
            self._internal_error(request_id)
        finally:
            if manager:
                manager.close()

    def do_POST(self) -> None:  # noqa: N802
        if self.path.startswith("/v1/project-component/"):
            self._handle_component()
            return
        self._handle_write()

    def _handle_component(self) -> None:
        from .project_component_api import handle

        try:
            with self.server.write_coordinator:
                manager = IssueManager(self.server.ledger_dir)
                try:
                    handle(self, manager)
                finally:
                    manager.close()
        except IssueManagerError as exc:
            self._domain_error(None, exc)
        except (ValueError, OSError, sqlite3.Error) as exc:
            self._domain_error(None, ValidationError(str(exc)))

    def do_PUT(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_PATCH(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def do_DELETE(self) -> None:  # noqa: N802
        self._method_not_allowed()

    def _method_not_allowed(self) -> None:
        self._json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"request_id": self.headers.get("X-Request-ID"), "error": "method_not_allowed"},
        )

    def _handle_write(self) -> None:
        request_id = self.headers.get("X-Request-ID")
        idempotency_key = self.headers.get("Idempotency-Key")
        if not request_id or not idempotency_key:
            self._json(
                HTTPStatus.BAD_REQUEST,
                {
                    "request_id": request_id,
                    "error": "validation_error",
                    "message": "Manager writes require X-Request-ID and Idempotency-Key",
                },
            )
            return
        if not self.server.begin_write():
            self._json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {
                    "request_id": request_id,
                    "error": "maintenance_mode",
                    "message": "Manager is shutting down and no longer accepts writes",
                },
            )
            return

        manager: IssueManager | None = None
        try:
            body = self._body()
            credential = self._credential()
            failed_response: tuple[HTTPStatus, dict[str, Any]] | None = None
            with self.server.write_coordinator:
                manager = IssueManager(self.server.ledger_dir)
                auth = manager.credentials.resolve(credential)
                from .project_component import installation

                binding = installation(manager.store)
                if binding and binding["execution_isolated"]:
                    raise PermissionError("Imported installation is execution isolated; domain writes are disabled")
                route = urlparse(self.path).path
                request_payload = {"method": self.command, "route": route, "body": body}
                with manager.store.transaction() as conn:
                    if manager.store.manager_metadata()["maintenance_mode"]:
                        raise MaintenanceModeError("Manager is in maintenance mode")
                    replay = manager.store.api_request_lookup(
                        actor_id=auth.actor_id,
                        run_id=auth.run_id,
                        idempotency_key=idempotency_key,
                        payload=request_payload,
                    )
                    if replay and replay["state"] == "succeeded":
                        result = replay["response"]["value"]
                        if route.startswith("/v1/field-packets") and isinstance(result, dict):
                            result = {**result, "idempotent_replay": True}
                        if route == "/v1/direct-evidence-splits" and isinstance(result, dict):
                            auth.require("context.read")
                            auth.require("evidence.write")
                            if body.get("relation_decisions") or body.get("new_relations"):
                                auth.require("evidence.relation.write")
                            manager.evidence.require_read_access(body["source_evidence_id"], auth)
                            for child in result["parts"]:
                                manager.evidence.require_read_access(child["evidence_id"], auth)
                            result = {**result, "idempotent_replay": True}
                    elif replay and replay["state"] == "failed":
                        stored = replay["response"]
                        failed_response = (HTTPStatus(int(stored["status"])), dict(stored["body"]))
                    elif replay and replay["state"] != "retryable_failure":
                        raise ConflictError(
                            "An identical request is still in progress",
                            details={"original_request_id": replay["request_id"]},
                        )
                    else:
                        if replay and replay["state"] == "retryable_failure":
                            if replay["request_id"] != request_id:
                                raise IdempotencyConflictError(
                                    "Retry of a failed request must keep its original X-Request-ID"
                                )
                            conn.execute(
                                "UPDATE api_requests SET state='in_progress',response_json=NULL,error_code=NULL,completed_at=NULL "
                                "WHERE request_id=? AND state='failed' AND error_code='internal_error'",
                                (request_id,),
                            )
                        else:
                            if conn.execute(
                                "SELECT 1 FROM api_requests WHERE request_id=?", (request_id,)
                            ).fetchone():
                                raise IdempotencyConflictError(
                                    f"Request ID {request_id!r} was already used"
                                )
                            manager.store.api_request_begin(
                                conn,
                                request_id=request_id,
                                idempotency_key=idempotency_key,
                                actor_id=auth.actor_id,
                                run_id=auth.run_id,
                                method=self.command,
                                route=route,
                                operation=route,
                                payload=request_payload,
                            )
                        conn.execute("SAVEPOINT api_request_dispatch")
                        try:
                            result = self._dispatch(manager, body, auth=auth)
                        except IssueManagerError as exc:
                            self._rollback_dispatch(conn)
                            status = _status_for(exc)
                            payload = self._domain_error_payload(request_id, exc)
                            manager.store.api_request_fail(
                                conn, request_id, error_code=exc.code,
                                response={"status": int(status), "body": payload},
                            )
                            failed_response = (status, payload)
                        except sqlite3.IntegrityError:
                            LOGGER.exception("SQLite constraint failure request_id=%s", request_id)
                            self._rollback_dispatch(conn)
                            error = ConflictError("Concurrent mutation conflict")
                            status = _status_for(error)
                            payload = self._domain_error_payload(request_id, error)
                            manager.store.api_request_fail(
                                conn, request_id, error_code=error.code,
                                response={"status": int(status), "body": payload},
                            )
                            failed_response = (status, payload)
                        except Exception:
                            LOGGER.exception("Unhandled Manager write failure request_id=%s", request_id)
                            self._rollback_dispatch(conn)
                            status = HTTPStatus.INTERNAL_SERVER_ERROR
                            payload = self._internal_error_payload(request_id)
                            manager.store.api_request_fail(
                                conn, request_id, error_code="internal_error",
                                response={"status": int(status), "body": payload},
                            )
                            failed_response = (status, payload)
                        else:
                            conn.execute("RELEASE SAVEPOINT api_request_dispatch")
                            manager.store.api_request_succeed(conn, request_id, {"value": result})
            if failed_response:
                self._json(*failed_response)
            else:
                self._json(HTTPStatus.OK, {"request_id": request_id, "result": result})
        except IssueManagerError as exc:
            self._domain_error(request_id, exc)
        except sqlite3.IntegrityError:
            LOGGER.exception("SQLite constraint failure request_id=%s", request_id)
            self._domain_error(request_id, ConflictError("Concurrent mutation conflict"))
        except Exception:
            LOGGER.exception("Unhandled Manager write failure request_id=%s", request_id)
            self._internal_error(request_id)
        finally:
            if manager:
                manager.close()
            self.server.end_write()

    @staticmethod
    def _rollback_dispatch(conn: sqlite3.Connection) -> None:
        conn.execute("ROLLBACK TO SAVEPOINT api_request_dispatch")
        conn.execute("RELEASE SAVEPOINT api_request_dispatch")

    def _domain_error(self, request_id: str | None, exc: IssueManagerError) -> None:
        self._json(_status_for(exc), self._domain_error_payload(request_id, exc))

    @staticmethod
    def _domain_error_payload(request_id: str | None, exc: IssueManagerError) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "request_id": request_id,
            "error": exc.code,
            "message": str(exc),
        }
        if exc.details:
            payload["details"] = exc.details
        return payload

    def _internal_error(self, request_id: str | None) -> None:
        self._json(HTTPStatus.INTERNAL_SERVER_ERROR, self._internal_error_payload(request_id))

    @staticmethod
    def _internal_error_payload(request_id: str | None) -> dict[str, Any]:
        return {
            "request_id": request_id,
            "error": "internal_error",
            "message": "The Manager encountered an internal error; consult the local log",
        }


class _ManagerHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], ledger_dir: Path, project_runtime: Path | None = None):
        self.ledger_dir = ledger_dir
        self.project_runtime = project_runtime
        self.write_coordinator = threading.RLock()
        self.write_state = threading.Condition()
        self.accepting_writes = True
        self.active_writes = 0
        super().__init__(address, _ManagerHandler)

    def begin_write(self) -> bool:
        with self.write_state:
            if not self.accepting_writes:
                return False
            self.active_writes += 1
            return True

    def end_write(self) -> None:
        with self.write_state:
            self.active_writes -= 1
            self.write_state.notify_all()

    def stop_and_drain_writes(self) -> None:
        with self.write_state:
            self.accepting_writes = False
            while self.active_writes:
                self.write_state.wait(timeout=0.2)


class _LedgerProcessLock:
    def __init__(self, ledger_dir: Path, *, write_owner_record: bool = True):
        runtime = ledger_dir / "runtime"
        runtime.mkdir(parents=True, exist_ok=True)
        self.path = runtime / "manager.lock"
        self.stream = self.path.open("a+b")
        if write_owner_record and self.path.stat().st_size == 0:
            self.stream.write(b"0")
            self.stream.flush()
        self.stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                getattr(msvcrt, "locking")(self.stream.fileno(), getattr(msvcrt, "LK_NBLCK"), 1)
            else:
                import fcntl

                getattr(fcntl, "flock")(
                    self.stream.fileno(), getattr(fcntl, "LOCK_EX") | getattr(fcntl, "LOCK_NB")
                )
        except OSError as exc:
            self.stream.close()
            raise ConflictError(f"Another Manager Service already owns ledger {ledger_dir}") from exc
        if write_owner_record:
            self.stream.seek(0)
            self.stream.truncate()
            self.stream.write(json.dumps({"pid": os.getpid()}, ensure_ascii=False).encode("utf-8"))
            self.stream.flush()

    def close(self) -> None:
        if self.stream.closed:
            return
        try:
            self.stream.seek(0)
            if os.name == "nt":
                import msvcrt

                getattr(msvcrt, "locking")(self.stream.fileno(), getattr(msvcrt, "LK_UNLCK"), 1)
            else:
                import fcntl

                getattr(fcntl, "flock")(self.stream.fileno(), getattr(fcntl, "LOCK_UN"))
        finally:
            self.stream.close()


class ManagerService:
    """Process-locked, single-writer HTTP boundary for the orchestration adapter."""

    def __init__(self, ledger_dir: str | Path, host: str = "127.0.0.1", port: int = 8765,
                 *, project_runtime: str | Path | None = None):
        if not host.strip():
            raise ValidationError("Manager Service host cannot be empty")
        if host not in {"127.0.0.1", "localhost", "::1"}:
            LOGGER.warning(
                "Manager API is binding to %s without built-in TLS; use a trusted network or "
                "TLS-terminating reverse proxy",
                host,
            )
        self.ledger_dir = Path(ledger_dir).resolve()
        package_runtime = Path(project_runtime).resolve() if project_runtime else None
        checkout = Path(__file__).resolve().parents[1]
        if package_runtime:
            if checkout == package_runtime or checkout in package_runtime.parents or package_runtime == self.ledger_dir or self.ledger_dir in package_runtime.parents:
                raise ValidationError("Project staging must be outside checkout and ledger")
            package_runtime.mkdir(parents=True, exist_ok=True)
        self.process_lock = _LedgerProcessLock(self.ledger_dir)
        try:
            self.server = _ManagerHttpServer((host, port), self.ledger_dir, package_runtime)
        except Exception:
            self.process_lock.close()
            raise
        self.thread: threading.Thread | None = None
        self._closed = False

    @property
    def address(self) -> tuple[str, int]:
        host, port = self.server.server_address[:2]
        return str(host), int(port)

    def serve_forever(self) -> None:
        self.server.serve_forever(poll_interval=0.2)

    def start(self) -> tuple[str, int]:
        if self.thread and self.thread.is_alive():
            return self.address
        self.thread = threading.Thread(
            target=self.serve_forever, name="issue-manager-service", daemon=True
        )
        self.thread.start()
        return self.address

    def close(self) -> None:
        if self._closed:
            return
        if self.thread and self.thread.is_alive():
            self.server.shutdown()
            self.server.stop_and_drain_writes()
            self.thread.join(timeout=5)
        self.server.server_close()
        self.process_lock.close()
        self._closed = True

    def __enter__(self) -> "ManagerService":
        self.start()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()
