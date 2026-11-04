"""Finite authenticated HTTP surface for independently enabled record tools."""
from __future__ import annotations

import hmac
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .task_queue import TaskQueue
from .tools_contracts import (
    ACTIONS,
    Principal,
    ToolError,
    canonical,
    decode,
    fail,
    fields,
    identifier,
    text,
)


def load_json(path: str | Path) -> Any:
    return decode(Path(path).read_text(encoding='utf-8'))


def load_service(path: str | Path) -> tuple[TaskQueue, list[tuple[str, Principal]], tuple[str, int]]:
    config = fields(load_json(path), {'database_path', 'listen', 'principals'})
    listen = fields(config['listen'], {'host', 'port'})
    host = text(listen['host'], 'listen host')
    port = listen['port']
    if type(port) is not int or not 0 <= port <= 65535:
        fail('invalid_configuration', 'listen port must be 0..65535')
    if not isinstance(config['principals'], list) or not config['principals']:
        fail('invalid_configuration', 'at least one explicit host-bound principal is required')
    bindings: list[tuple[str, Principal]] = []
    for value in config['principals']:
        value = fields(value, {'principal_id', 'token_env', 'actions'})
        name = identifier(value['principal_id'], 'principal_id')
        env_name = text(value['token_env'], 'token_env')
        token = os.environ.get(env_name, '')
        if not token or any(c.isspace() for c in token) or not token.isascii():
            fail('invalid_configuration', 'host must inject each configured bearer token')
        if any(hmac.compare_digest(token, existing[0]) for existing in bindings):
            fail('invalid_configuration', 'a bearer token cannot bind multiple principals')
        actions = value['actions']
        if not isinstance(actions, list) or any(action not in ACTIONS for action in actions):
            fail('invalid_configuration', 'unknown tool permission')
        bindings.append((token, Principal(name, frozenset(actions))))
    return TaskQueue(config['database_path']), bindings, (host, port)


class ToolsHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = True

    def __init__(self, address: tuple[str, int], queue: TaskQueue,
                 bindings: list[tuple[str, Principal]]):
        self.queue, self.bindings = queue, bindings
        super().__init__(address, ToolsHandler)


class ToolsHandler(BaseHTTPRequestHandler):
    server: ToolsHTTPServer
    protocol_version = 'HTTP/1.1'

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, format: str, *args: Any) -> None:
        # No request bodies, headers or tokens in service output.
        pass

    def _principal(self) -> Principal:
        values = self.headers.get_all('Authorization', [])
        if len(values) != 1 or not values[0].startswith('Bearer '):
            fail('unauthorized', 'one host-bound bearer token is required', status=401)
        token = values[0][7:]
        if not token.isascii():
            fail('unauthorized', 'invalid bearer token', status=401)
        for expected, principal in self.server.bindings:
            if hmac.compare_digest(token, expected):
                return principal
        fail('unauthorized', 'invalid bearer token', status=401)

    def _send(self, status: int, result: dict[str, Any], principal: Principal | None) -> None:
        encoded = canonical(result).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(encoded)))
        self.send_header('X-Workflow-Service-ID', self.server.queue.service_id)
        if principal:
            self.send_header('X-Workflow-Principal-ID', principal.principal_id)
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(encoded)
        self.close_connection = True

    def _dispatch(self, write: bool) -> None:
        principal = None
        body: dict[str, Any] = {}
        try:
            principal = self._principal()
            service_id = self.headers.get('X-Workflow-Service-ID')
            principal_id = self.headers.get('X-Workflow-Principal-ID')
            if service_id is not None and service_id != self.server.queue.service_id:
                fail('service_identity_changed', 'request is bound to a different service', status=409)
            if principal_id is not None and principal_id != principal.principal_id:
                fail('principal_identity_changed', 'request is bound to a different principal', status=409)
            url = urlsplit(self.path)
            query = parse_qs(url.query, keep_blank_values=True, strict_parsing=True)
            if any(len(values) != 1 for values in query.values()):
                fail('invalid_input', 'duplicate query field')
            params = {key: values[0] for key, values in query.items()}
            if write:
                if params or self.headers.get('Transfer-Encoding') is not None:
                    fail('invalid_input', 'POST accepts a bounded JSON body only')
                lengths = self.headers.get_all('Content-Length', [])
                if len(lengths) != 1 or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= 65536:
                    fail('invalid_input', 'JSON body must be 1..65536 bytes')
                if self.headers.get_content_type() != 'application/json':
                    fail('invalid_input', 'Content-Type must be application/json')
                body = decode(self.rfile.read(int(lengths[0])))
                if not isinstance(body, dict):
                    fail('invalid_input', 'JSON body must be an object')
                path = url.path
                if path == '/v1/queue/tasks':
                    result = self.server.queue.write(principal, 'publish_task', '', body)
                else:
                    match = re.fullmatch(r'/v1/queue/tasks/([A-Za-z0-9_.:-]+)/(claim|replies)', path)
                    if not match:
                        fail('not_found', 'no such write route', status=404)
                    action = 'claim_task' if match[2] == 'claim' else 'reply_task'
                    result = self.server.queue.write(principal, action, match[1], body)
            elif url.path == '/v1/identity':
                fields(params, set())
                result = self.server.queue.identity(principal)
            else:
                if url.path == '/v1/queue/tasks':
                    fields(params, set(), {'issue_id', 'claimed', 'cursor', 'limit'})
                    if 'issue_id' in params:
                        text(params['issue_id'], 'issue_id')
                    if 'claimed' in params and params['claimed'] not in {'true', 'false'}:
                        fail('invalid_input', 'claimed must be true or false')
                    result = self.server.queue.list(
                        principal, issue_id=params.get('issue_id'),
                        claimed=({'true': True, 'false': False}.get(params.get('claimed', ''))),
                        cursor=params.get('cursor'), limit=self._limit(params))
                else:
                    match = re.fullmatch(r'/v1/queue/tasks/([A-Za-z0-9_.:-]+)(/replies)?', url.path)
                    if not match:
                        fail('not_found', 'no such read route', status=404)
                    if match[2]:
                        fields(params, set(), {'cursor', 'limit'})
                        result = self.server.queue.list(principal, task_id=match[1],
                                                        cursor=params.get('cursor'), limit=self._limit(params))
                    else:
                        fields(params, set())
                        result = self.server.queue.get(principal, match[1])
            self._send(200, result, principal)
        except ToolError as exc:
            if isinstance(body, dict) and isinstance(body.get('operation_id'), str):
                exc.operation_id = body['operation_id']
            self._send(exc.status, exc.result(), principal)
        except (ValueError, UnicodeError):
            self._send(400, ToolError('invalid_input', 'invalid request encoding or query').result(), principal)
        except Exception:
            error = ToolError('service_error', 'request could not be confirmed', status=500,
                              effect='unknown' if write else 'not_committed',
                              operation_id=body.get('operation_id') if isinstance(body, dict) else None)
            self._send(500, error.result(), principal)

    @staticmethod
    def _limit(params: dict[str, str]) -> int:
        value = params.get('limit', '20')
        if not value.isascii() or not value.isdigit() or len(value) > 2:
            fail('invalid_input', 'limit must be an integer from 1 to 50')
        return int(value)

    def do_GET(self) -> None:
        self._dispatch(False)

    def do_POST(self) -> None:
        self._dispatch(True)
