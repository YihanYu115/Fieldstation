"""Finite standalone Board HTTP. Trusted configuration binds human and recipients."""

from __future__ import annotations

import hmac
import os
import re
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .board_contracts import BOARD_ACTIONS, BoardPrincipal
from .board_records import BoardRecords
from .tools_contracts import ToolError, canonical, decode, fail, fields, identifier, text
from .tools_http import ToolsHandler


def load_board_service(
    path: str | Path,
) -> tuple[BoardRecords, list[tuple[str, BoardPrincipal]], tuple[str, int]]:
    config = fields(
        decode(Path(path).read_text(encoding="utf-8")), {"database_path", "listen", "principals"}
    )
    listen = fields(config["listen"], {"host", "port"})
    host = text(listen["host"], "listen host")
    port = listen["port"]
    if type(port) is not int or not 0 <= port <= 65535:
        fail("invalid_configuration", "listen port must be 0..65535")
    if not isinstance(config["principals"], list) or not config["principals"]:
        fail("invalid_configuration", "explicit host-bound principals are required")
    bindings: list[tuple[str, BoardPrincipal]] = []
    for value in config["principals"]:
        fields(
            value,
            {
                "principal_id",
                "token_env",
                "actions",
                "kind",
                "recipient",
                "allowed_recipients",
            },
        )
        name = identifier(value["principal_id"], "principal_id")
        token = os.environ.get(text(value["token_env"], "token_env"), "")
        if not token or not token.isascii() or any(c.isspace() for c in token):
            fail("invalid_configuration", "host must inject each bearer token")
        if any(
            hmac.compare_digest(token, old[0]) or name == old[1].principal_id for old in bindings
        ):
            fail("invalid_configuration", "tokens and principal IDs must be unambiguous")
        if not isinstance(value["kind"], str) or value["kind"] not in {"human", "service"}:
            fail("invalid_configuration", "kind must be human or service")
        recipient = identifier(value["recipient"], "recipient")
        for key in ("actions", "allowed_recipients"):
            if not isinstance(value[key], list) or any(not isinstance(v, str) for v in value[key]):
                fail("invalid_configuration", key + " must be an explicit string list")
        if any(action not in BOARD_ACTIONS for action in value["actions"]):
            fail(
                "invalid_configuration", "finite Board permissions are required"
            )
        recipients = frozenset(
            identifier(item, "allowed recipient") for item in value["allowed_recipients"]
        )
        bindings.append(
            (
                token,
                BoardPrincipal(
                    name, frozenset(value["actions"]), value["kind"], recipient, recipients
                ),
            )
        )
    return BoardRecords(config["database_path"]), bindings, (host, port)


class BoardHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True

    def __init__(
        self,
        address: tuple[str, int],
        records: BoardRecords,
        bindings: list[tuple[str, BoardPrincipal]],
    ):
        self.queue, self.bindings = records, bindings
        super().__init__(address, BoardHandler)


class BoardHandler(ToolsHandler):
    # Reuse only bounded I/O, bearer authentication, quiet logs and GET/POST adapters.
    server: Any

    def _principal(self) -> BoardPrincipal:
        principal = super()._principal()
        assert isinstance(principal, BoardPrincipal)
        return principal

    def _send(self, status: int, result: dict[str, Any], principal: Any) -> None:
        encoded = canonical(result).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Workflow-Service-ID", self.server.queue.service_id)
        if principal:
            self.send_header("X-Workflow-Principal-ID", principal.principal_id)
            self.send_header("X-Workflow-Board-Binding", principal.binding_id)
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)
        self.close_connection = True

    def _dispatch(self, write: bool) -> None:
        principal = None
        body: dict[str, Any] = {}
        try:
            principal = self._principal()
            expected = {
                "X-Workflow-Service-ID": self.server.queue.service_id,
                "X-Workflow-Principal-ID": principal.principal_id,
                "X-Workflow-Board-Binding": principal.binding_id,
            }
            for header, actual in expected.items():
                if len(self.headers.get_all(header, [])) > 1:
                    fail("invalid_input", "duplicate identity header")
                if self.headers.get(header) is not None and self.headers[header] != actual:
                    fail(
                        "recovery_binding_changed",
                        "request is bound to a different service or principal configuration",
                        status=409,
                    )
            url = urlsplit(self.path)
            query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
            if any(len(v) != 1 for v in query.values()):
                fail("invalid_input", "duplicate query field")
            params: dict[str, Any] = {k: v[0] for k, v in query.items()}
            if write:
                if params or self.headers.get("Transfer-Encoding") is not None:
                    fail("invalid_input", "POST accepts a bounded JSON body only")
                lengths = self.headers.get_all("Content-Length", [])
                if (
                    len(lengths) != 1
                    or not lengths[0].isdigit()
                    or not 0 < int(lengths[0]) <= 131072
                ):
                    fail("invalid_input", "JSON body must be 1..131072 bytes")
                if self.headers.get_content_type() != "application/json":
                    fail("invalid_input", "Content-Type must be application/json")
                body = decode(self.rfile.read(int(lengths[0])))
                if not isinstance(body, dict):
                    fail("invalid_input", "JSON body must be an object")
                action, target = self._write_route(url.path)
                result = self.server.queue.write(principal, action, target, body)
            elif url.path == "/v1/identity":
                fields(params, set())
                result = self.server.queue.identity(principal)
            else:
                result = self._read(principal, url.path, params)
            self._send(200, result, principal)
        except ToolError as exc:
            if isinstance(body, dict) and isinstance(body.get("operation_id"), str):
                exc.operation_id = body["operation_id"]
            self._send(exc.status, exc.result(), principal)
        except (ValueError, UnicodeError):
            self._send(
                400,
                ToolError("invalid_input", "invalid request encoding or query").result(),
                principal,
            )
        except Exception:
            self._send(
                500,
                ToolError(
                    "service_error",
                    "request could not be confirmed",
                    status=500,
                    effect="unknown" if write else "not_committed",
                ).result(),
                principal,
            )

    @staticmethod
    def _write_route(path: str) -> tuple[str, str]:
        routes = {
            "/v1/board/messages": "post_message",
            "/v1/board/handoffs": "post_handoff",
            "/v1/board/instructions": "create_board_instruction",
        }
        if path in routes:
            return routes[path], ""
        match = re.fullmatch(
            r"/v1/board/(handoffs|instructions)/([A-Za-z0-9_.:-]+)/(answer|revoke)", path
        )
        if match and (match[1], match[3]) in {("handoffs", "answer"), ("instructions", "revoke")}:
            return (
                "answer_handoff" if match[1] == "handoffs" else "revoke_board_instruction"
            ), match[2]
        fail("not_found", "no such Board write route", status=404)

    def _read(self, principal: BoardPrincipal, path: str, params: dict[str, Any]) -> dict[str, Any]:
        collections = {
            "messages": "list_messages",
            "handoffs": "list_handoffs",
            "instructions": "list_board_instructions",
            "instruction-events": "list_board_instruction_events",
        }
        match = re.fullmatch(
            r"/v1/board/(messages|handoffs|instructions|instruction-events)(?:/([A-Za-z0-9_.:-]+))?(/events)?",
            path,
        )
        if not match:
            fail("not_found", "no such Board read route", status=404)
        name, target, events = match.groups()
        if events:
            if name != "instructions" or not target:
                fail("not_found", "no such event route", status=404)
            fields(params, set(), {"issue_id", "cursor", "limit", "after_sequence"})
            params["instruction_id"] = target
            action = "list_board_instruction_events"
        elif target:
            fields(params, set())
            if name == "instruction-events":
                fail("not_found", "no such read route", status=404)
            action = {
                "messages": "get_message",
                "handoffs": "get_handoff",
                "instructions": "get_board_instruction",
            }[name]
            return self.server.queue.get(principal, action, target)
        else:
            action = collections[name]
        allowed = {"issue_id", "cursor", "limit", "after_sequence"}
        if action == "list_messages":
            allowed.add("scope_tag")
        if action == "list_handoffs":
            allowed.add("status")
        if action == "list_board_instructions":
            allowed.add("include_revoked")
        if action == "list_board_instruction_events":
            allowed.add("instruction_id")
        fields(params, set(), allowed)
        if "issue_id" in params:
            text(params["issue_id"], "issue_id")
        if "scope_tag" in params:
            text(params["scope_tag"], "scope_tag", 128)
        if "include_revoked" in params:
            if params["include_revoked"] not in {"true", "false"}:
                fail("invalid_input", "include_revoked must be true or false")
            params["include_revoked"] = params["include_revoked"] == "true"
        if "limit" in params:
            params["limit"] = self._limit(params)
        if "after_sequence" in params:
            value = params["after_sequence"]
            if not value.isascii() or not value.isdigit() or len(value) > 19:
                fail("invalid_input", "after_sequence must be a nonnegative 64-bit integer")
            params["after_sequence"] = int(value)
        return self.server.queue.list(principal, action, **params)
