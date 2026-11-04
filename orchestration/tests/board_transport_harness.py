"""Test-only process HTTP gateway; inject transport failures, never simulate Board domain state."""

from __future__ import annotations

import http.client
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class FaultProxy:
    def __init__(self, service):
        from queue_tools_harness import ManagedProcess

        self.process = ManagedProcess(
            [sys.executable, "-B", __file__, "--worker", service.endpoint],
            service.path,
            os.environ.copy(),
            "board-fault-proxy",
        )
        try:
            self.endpoint = json.loads(self.process.line())["endpoint"]
        except BaseException:
            self.process.close()
            raise

    def control(self, **command):
        self.process.process.stdin.write(json.dumps(command) + "\n")
        self.process.process.stdin.flush()
        return json.loads(self.process.line())

    def inject(self, mode, status=503, *, html=False, method="POST", payload=None):
        self.control(mode=mode, status=status, html=html, method=method, payload=payload)

    def events(self):
        return self.control(query=True)["events"]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        try:
            self.control(close=True)
            self.process.process.wait(15)
        finally:
            self.process.close()


def worker(upstream):
    lock = threading.Lock()
    state = {"fault": None, "events": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def forward(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            with lock:
                fault = state["fault"]
                if fault and self.command == fault["method"]:
                    state["fault"] = None
                else:
                    fault = None
            event = {
                "method": self.command,
                "path": self.path,
                "request_id": self.headers.get("X-Request-ID"),
                "idempotency_key": self.headers.get("Idempotency-Key"),
                "body": json.loads(body) if body else None,
                "fault": fault,
                "forwarded": not fault or fault["mode"] != "before",
            }
            if event["forwarded"]:
                remote = urlsplit(upstream)
                connection = http.client.HTTPConnection(remote.hostname, remote.port, timeout=8)
                try:
                    headers = dict(self.headers)
                    if fault and fault["mode"] == "invalid_auth":
                        headers["Authorization"] = "Bearer invalid-synthetic-r1-token"
                    connection.request(self.command, self.path, body or None, headers=headers)
                    response = connection.getresponse()
                    status, payload = response.status, response.read()
                    response_headers = response.getheaders()
                    event.update(upstream_status=status, upstream_envelope=json.loads(payload))
                finally:
                    connection.close()
            else:
                status, payload = 0, b""
                response_headers = []
            if fault and fault["mode"] != "invalid_auth":
                status = fault["status"]
                payload = (
                    b"<html>Temporarily unavailable</html>"
                    if fault["html"]
                    else json.dumps(
                        {
                            "error": "temporary_gateway_response",
                            "message": "Retry the original request.",
                            "details": {"synthetic_gateway": True},
                        }
                    ).encode()
                )
                if fault.get("payload") is not None:
                    payload = fault["payload"].encode("utf-8")
            event["returned_status"] = "dropped" if fault and fault["mode"] == "drop" else status
            with lock:
                state["events"].append(event)
            if fault and fault["mode"] == "drop":
                self.close_connection = True
                return
            self.send_response(status)
            for key, value in response_headers:
                if key.lower().startswith("x-workflow-"):
                    self.send_header(key, value)
            self.send_header(
                "Content-Type", "text/html" if fault and fault["html"] else "application/json"
            )
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)

        do_GET = forward
        do_POST = forward

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(json.dumps({"endpoint": "http://127.0.0.1:" + str(server.server_port)}), flush=True)
    try:
        for line in sys.stdin:
            command = json.loads(line)
            if command.get("close"):
                print(json.dumps({"closed": True}), flush=True)
                break
            with lock:
                if command.get("query"):
                    value = {"events": list(state["events"])}
                else:
                    state["fault"] = command
                    value = {"configured": True}
            print(json.dumps(value), flush=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(10)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--worker":
        raise SystemExit("test HTTP gateway requires --worker <upstream>")
    worker(sys.argv[2])
