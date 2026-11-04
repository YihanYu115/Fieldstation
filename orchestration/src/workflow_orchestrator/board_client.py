"""Board-only finite HTTP client with immutable per-action recovery."""

from __future__ import annotations

import http.client
import os
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener

from .board_contracts import BOARD_WRITES, digest, normalize
from .tools_client import NoRedirect
from .tools_contracts import ToolError, canonical, decode, fail, identifier
from .tools_journal import ActionJournal

READ_ROUTES = {
    "get_message": ("messages", "message_id"),
    "get_handoff": ("handoffs", "message_id"),
    "get_board_instruction": ("instructions", "instruction_id"),
    "list_messages": ("messages", None),
    "list_handoffs": ("handoffs", None),
    "list_board_instructions": ("instructions", None),
    "list_board_instruction_events": ("instruction-events", None),
}


class BoardClient:
    def __init__(
        self,
        endpoint: str,
        token: str,
        journal_path: str | Path,
        *,
        token_env: str = "BOARD_TOKEN",
        timeout: float = 5,
    ):
        url = urlsplit(endpoint)
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username
            or url.password
            or url.path not in {"", "/"}
            or url.query
            or url.fragment
        ):
            fail("invalid_configuration", "endpoint must be a fixed HTTP(S) origin")
        if not token or not token.isascii() or any(c.isspace() for c in token):
            fail("invalid_configuration", "host must inject a bearer token")
        if not 0 < timeout <= 60:
            fail("invalid_configuration", "timeout must be in (0,60] seconds")
        self.endpoint, self._token, self.timeout = endpoint.rstrip("/"), token, timeout
        self.token_env = token_env
        self.journal = ActionJournal(journal_path)
        with self.journal.lock():
            saved = self.journal.load()["binding"]
            if saved is not None and any(
                saved.get(k) != v
                for k, v in {
                    "endpoint": self.endpoint,
                    "surface": "board",
                    "token_env": token_env,
                    "credential_sha256": digest(token),
                }.items()
            ):
                raise ToolError(
                    "recovery_binding_changed",
                    "original connection or authorization source changed",
                    effect="unknown",
                )
        identity = self._request("GET", "/v1/identity", bound=False)
        required = {"service_id", "principal_id", "kind", "recipient", "principal_binding"}
        if (
            not required <= identity.keys()
            or any(not isinstance(identity[k], str) for k in required)
            or identity["kind"] not in {"human", "service"}
            or identity.get("modules") != ["board"]
        ):
            fail("invalid_response", "endpoint did not return a Board identity")
        self.binding = {k: identity[k] for k in required}
        self.binding.update(
            endpoint=self.endpoint,
            surface="board",
            token_env=token_env,
            credential_sha256=digest(token),
        )
        self.journal.bind(self.binding)

    @classmethod
    def from_connection(cls, connection: dict[str, str], journal_path: str | Path) -> BoardClient:
        if set(connection) != {"endpoint", "token_env"}:
            fail("invalid_configuration", "connection requires endpoint and token_env only")
        return cls(
            connection["endpoint"],
            os.environ.get(connection["token_env"], ""),
            journal_path,
            token_env=connection["token_env"],
        )

    def _headers_match(self, headers: Any) -> bool:
        return all(headers.get(k) == v for k, v in self._identity_headers().items())

    def _identity_headers(self) -> dict[str, str]:
        return {
            "X-Workflow-Service-ID": self.binding["service_id"],
            "X-Workflow-Principal-ID": self.binding["principal_id"],
            "X-Workflow-Board-Binding": self.binding["principal_binding"],
        }

    def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None, *, bound: bool = True
    ) -> dict[str, Any]:
        effect = "unknown" if method == "POST" else "not_committed"
        headers = {"Authorization": "Bearer " + self._token, "Content-Type": "application/json"}
        if bound:
            headers.update(self._identity_headers())
        request = Request(
            self.endpoint + path,
            method=method,
            headers=headers,
            data=canonical(body).encode() if body is not None else None,
        )
        try:
            with build_opener(NoRedirect()).open(request, timeout=self.timeout) as response:
                payload = response.read(2 * 1024 * 1024 + 1)
                if len(payload) > 2 * 1024 * 1024:
                    raise ToolError(
                        "invalid_response", "response exceeds finite bound", effect=effect
                    )
                if bound and not self._headers_match(response.headers):
                    raise ToolError(
                        "recovery_binding_changed", "response binding differs", effect=effect
                    )
                value = decode(payload)
                if not isinstance(value, dict) or "error" in value:
                    raise ToolError(
                        "invalid_response", "unrecognized success response", effect=effect
                    )
                if method == "POST" and (
                    value.get("operation_id") != (body or {}).get("operation_id")
                    or value.get("service_id") != self.binding["service_id"]
                    or type(value.get("replayed")) is not bool
                    or not isinstance(value.get("read_path"), str)
                    or not (
                        isinstance(value.get("message"), dict)
                        or isinstance(value.get("handoff"), dict)
                        or isinstance(value.get("instruction"), dict)
                    )
                ):
                    raise ToolError(
                        "invalid_response", "write receipt is incomplete", effect=effect
                    )
                return dict(value)
        except HTTPError as exc:
            try:
                payload = exc.read(262145)
                trusted = (
                    not bound
                    or self._headers_match(exc.headers)
                    or (
                        exc.code == 401
                        and exc.headers.get("X-Workflow-Service-ID") == self.binding["service_id"]
                    )
                )
                try:
                    value = decode(payload) if len(payload) <= 262144 else None
                except ToolError:
                    value = None
                error = value.get("error") if isinstance(value, dict) else None
                recognized = (
                    isinstance(error, dict)
                    and isinstance(error.get("code"), str)
                    and isinstance(error.get("message"), str)
                    and error.get("effect") in {"not_committed", "unknown"}
                )
                definitive = (
                    trusted
                    and recognized
                    and 400 <= exc.code < 500
                    and exc.code not in {408, 425, 429}
                )
                if recognized and isinstance(error, dict):
                    raise ToolError(
                        error["code"],
                        error["message"],
                        status=exc.code,
                        effect=error["effect"] if definitive else effect,
                    ) from None
                raise ToolError(
                    "invalid_response", "unrecognized HTTP error", status=exc.code, effect=effect
                ) from None
            except (OSError, http.client.HTTPException):
                raise ToolError(
                    "transport_unknown",
                    "HTTP error response incomplete",
                    status=exc.code,
                    effect=effect,
                ) from None
            finally:
                exc.close()
        except (URLError, TimeoutError, OSError, http.client.HTTPException):
            raise ToolError(
                "transport_unknown",
                "HTTP response unavailable; recover original action",
                effect=effect,
            ) from None
        except ToolError as exc:
            if exc.code == "invalid_input":
                raise ToolError(
                    "invalid_response", "response is not valid JSON", effect=effect
                ) from None
            raise

    def _verify(self) -> None:
        if (
            self.endpoint != self.binding["endpoint"]
            or digest(self._token) != self.binding["credential_sha256"]
            or self.token_env != self.binding["token_env"]
        ):
            raise ToolError(
                "recovery_binding_changed", "original local connection changed", effect="unknown"
            )
        identity = self._request("GET", "/v1/identity")
        if any(
            identity.get(k) != self.binding[k]
            for k in ("service_id", "principal_id", "kind", "recipient", "principal_binding")
        ):
            raise ToolError(
                "recovery_binding_changed",
                "host-bound identity changed",
                status=409,
                effect="unknown",
            )

    def read(self, action: str, **arguments: Any) -> dict[str, Any]:
        if action not in READ_ROUTES:
            fail("invalid_input", "unsupported Board read")
        route, key = READ_ROUTES[action]
        path = "/v1/board/" + route
        if key:
            target = identifier(arguments.pop(key), key)
            if arguments:
                fail("invalid_input", "unexpected read fields")
            path += "/" + target
        else:
            query = {
                k: str(v).lower() if isinstance(v, bool) else v
                for k, v in arguments.items()
                if v is not None
            }
            if query:
                path += "?" + urlencode(query)
        self._verify()
        return self._request("GET", path)

    def write(self, action: str, **arguments: Any) -> dict[str, Any]:
        if action not in BOARD_WRITES:
            fail("invalid_input", "unsupported Board write")
        arguments = dict(arguments)
        if {"operation_id", "expected_revision", "actor"} & arguments.keys():
            fail("invalid_input", "operation identity, actor and revision are host-managed")
        if action == "answer_handoff":
            target = identifier(arguments.pop("message_id"), "message_id")
            original = self.read("get_handoff", message_id=target)
            arguments["expected_revision"] = original["revision"]
            path = "/v1/board/handoffs/" + target + "/answer"
        elif action == "revoke_board_instruction":
            target = identifier(arguments.pop("instruction_id"), "instruction_id")
            original = self.read("get_board_instruction", instruction_id=target)
            arguments["expected_revision"] = original["revision"]
            path = "/v1/board/instructions/" + target + "/revoke"
        else:
            path = (
                "/v1/board/"
                + {
                    "post_message": "messages",
                    "post_handoff": "handoffs",
                    "create_board_instruction": "instructions",
                }[action]
            )
        # Reject host-only fields even for the two CAS operations before capturing state.
        # normalize is the service contract; only this program supplies operation_id/revision.
        body = normalize(action, {**arguments, "operation_id": "op-" + uuid.uuid4().hex})
        self._verify()
        operation_id = body["operation_id"]
        intent = {
            "operation_id": operation_id,
            "binding": self.binding,
            "action": action,
            "path": path,
            "body": body,
            "state": "pending",
            "sent": False,
        }
        intent["sha256"] = self._intent_digest(intent)
        with self.journal.lock():
            value = self.journal.load()
            self._bound(value)
            value["actions"][operation_id] = intent
            try:
                self.journal.save(value)
            except OSError:
                raise ToolError("journal_write_failed", "intent not saved; no POST sent") from None
        try:
            return self.recover(operation_id)
        except ToolError as exc:
            if exc.operation_id is None:
                exc.operation_id = operation_id
            raise
        except Exception as exc:
            raise ToolError("tool_error", "Recover the original operation", effect="unknown",
                            operation_id=operation_id) from exc

    @staticmethod
    def _intent_digest(intent: dict[str, Any]) -> str:
        return digest({k: intent[k] for k in ("operation_id", "binding", "action", "path", "body")})

    def _bound(self, value: dict[str, Any]) -> None:
        if value["binding"] != self.binding:
            raise ToolError("recovery_binding_changed", "journal binding changed", effect="unknown")

    def recover(self, operation_id: str) -> dict[str, Any]:
        with self.journal.lock():
            value = self.journal.load()
            self._bound(value)
            intent = value["actions"].get(operation_id)
            if intent is None:
                fail("not_found", "original action is absent", status=404)
            if (
                intent.get("operation_id") != operation_id
                or intent.get("binding") != self.binding
                or intent.get("sha256") != self._intent_digest(intent)
                or intent.get("body", {}).get("operation_id") != operation_id
            ):
                raise ToolError(
                    "intent_conflict",
                    "original ID, binding, body, target or version changed",
                    effect="unknown",
                )
            try:
                self._verify()
            except ToolError as exc:
                exc.operation_id = operation_id
                if intent.get("sent"):
                    exc.effect = "unknown"
                raise
            if intent["state"] == "confirmed":
                return dict(intent["receipt"])
            if intent["state"] == "rejected":
                error = intent["error"]
                raise ToolError(
                    error["code"],
                    error["message"],
                    effect=error["effect"],
                    operation_id=operation_id,
                )
            previous_send = intent["sent"]
            try:
                intent["sent"] = True
                try:
                    self.journal.save(value)
                except OSError:
                    raise ToolError(
                        "journal_write_failed",
                        "send marker not saved; no new POST sent",
                        effect="unknown" if previous_send else "not_committed",
                    ) from None
                result = self._request("POST", intent["path"], intent["body"])
            except ToolError as exc:
                exc.operation_id = operation_id
                if previous_send and exc.code in {
                    "unauthorized",
                    "forbidden",
                    "recovery_binding_changed",
                    "service_identity_changed",
                    "principal_identity_changed",
                }:
                    exc.effect = "unknown"
                if exc.effect != "unknown":
                    intent.update(state="rejected", error=exc.result()["error"])
                    try:
                        self.journal.save(value)
                    except OSError:
                        pass
                raise
            intent.update(state="confirmed", receipt=result)
            try:
                self.journal.save(value)
            except OSError:
                raise ToolError(
                    "journal_write_failed",
                    "receipt not saved; recover original action",
                    effect="unknown",
                    operation_id=operation_id,
                ) from None
            return result

    def recover_pending(self) -> list[dict[str, Any]]:
        with self.journal.lock():
            pending = [
                key
                for key, value in self.journal.load()["actions"].items()
                if value["state"] == "pending"
            ]
        results = []
        for operation_id in pending:
            try:
                results.append(self.recover(operation_id))
            except ToolError as exc:
                results.append(exc.result())
        return results
