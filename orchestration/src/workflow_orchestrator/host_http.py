"""Authenticated finite host routes; no process-management or arbitrary proxy API."""
from __future__ import annotations

import hmac
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .host_contracts import principal_binding
from .launch_host import LaunchHost
from .tools_contracts import ToolError, canonical, decode, fail


class HostHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], host: LaunchHost):
        self.host = host
        self.stopping = threading.Event()
        super().__init__(address, HostHandler)
        self.observer = threading.Thread(target=self._observe, daemon=True)
        self.observer.start()

    def _observe(self) -> None:
        while not self.stopping.wait(.5):
            try:
                self.host.resume_prepared()
            except Exception:
                # A failed pass never releases occupancy or authorizes another spawn.
                # The next bounded pass retains the same accepted records/identities.
                pass

    def server_close(self) -> None:
        self.stopping.set()
        self.observer.join(timeout=5)
        # Sessions are foreground OS processes independent of the HTTP server's lifetime.
        # Restart only observes the persisted original identity; never terminates children.
        super().server_close()


class HostHandler(BaseHTTPRequestHandler):
    server: HostHTTPServer
    protocol_version = 'HTTP/1.1'

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def principal(self) -> dict[str, Any]:
        values = self.headers.get_all('Authorization', [])
        if len(values) != 1 or not values[0].startswith('Bearer ') or not values[0].isascii():
            fail('unauthorized', 'one host-bound bearer token required', status=401)
        for p in self.server.host.config['principals']:
            if hmac.compare_digest(values[0][7:], os.environ[p['token_env']]):
                return p
        fail('unauthorized', 'invalid bearer token', status=401)

    def send(self, status: int, value: dict[str, Any], p: dict[str, Any] | None) -> None:
        encoded = canonical(value).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(encoded)))
        self.send_header('X-Workflow-Service-ID', self.server.host.service_id)
        if p:
            self.send_header('X-Workflow-Principal-ID', p['principal_id'])
            self.send_header('X-Workflow-Host-Binding', principal_binding(p))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(encoded)
        self.close_connection = True

    def dispatch(self, write: bool) -> None:
        p = None
        body: Any = None
        try:
            p = self.principal()
            expected = {'X-Workflow-Service-ID': self.server.host.service_id,
                        'X-Workflow-Principal-ID': p['principal_id'],
                        'X-Workflow-Host-Binding': principal_binding(p)}
            for key, actual in expected.items():
                values = self.headers.get_all(key, [])
                if len(values) > 1 or (values and values[0] != actual):
                    fail('host_binding_changed', 'request host or caller binding differs', status=409)
            url = urlsplit(self.path)
            if url.query or url.fragment:
                fail('invalid_input', 'host routes accept no query parameters')
            host = self.server.host
            if write:
                if url.path != '/v1/launches':
                    fail('not_found', 'no such host write route', status=404)
                lengths = self.headers.get_all('Content-Length', [])
                if (self.headers.get('Transfer-Encoding') is not None or len(lengths) != 1
                        or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= 16384
                        or self.headers.get_content_type() != 'application/json'):
                    fail('invalid_input', 'launch requires 1..16384 bytes of finite JSON')
                body = decode(self.rfile.read(int(lengths[0])))
                result = host.launch(p, body)
            elif url.path == '/v1/identity':
                result = host.identity(p)
            elif url.path == '/v1/status':
                result = host.status(p)
            elif url.path in {'/v1/catalog', '/v1/catalog/queue'}:
                result = host.catalog(p, queue_only=url.path.endswith('/queue'))
            else:
                match = re.fullmatch(r'/v1/launches/by-request/([A-Za-z0-9_.:-]{1,128})', url.path)
                if not match:
                    fail('not_found', 'no such host read route', status=404)
                result = host.query(p, match[1])
            self.send(200, result, p)
        except ToolError as exc:
            if write and isinstance(body, dict) and isinstance(body.get('request_id'), str):
                value = {'outcome': 'unknown' if exc.effect == 'unknown' else 'rejected',
                         'request_id': body['request_id'], 'error': exc.result()['error']}
                self.send(exc.status, value, p)
            else:
                self.send(exc.status, exc.result(), p)
        except Exception:
            error = ToolError('host_error', 'request could not be confirmed', status=500,
                              effect='unknown' if write else 'not_committed').result()
            self.send(500, error, p)

    def do_GET(self) -> None:
        self.dispatch(False)

    def do_POST(self) -> None:
        self.dispatch(True)
