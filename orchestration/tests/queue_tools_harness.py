"""Real process/HTTP/stdio test host. Tokens exist only in child environment."""
from __future__ import annotations

import ctypes
import http.client
import json
import os
import queue
import secrets
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from workflow_orchestrator.tools_contracts import ACTIONS

RUNTIME = Path(os.environ['WORKFLOW_STEP_RUNTIME'])
SOURCE = Path(__file__).resolve().parents[1] / 'src'


def evidence(name, value):
    path = RUNTIME / 'evidence' / (name + '.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def event(value):
    # Separate process writers and serialize threads: no cross-process append fragments.
    path = RUNTIME / 'evidence' / ('processes-' + str(os.getpid()) + '.jsonl')
    with EVENT_LOCK:
        _event(path, value)


EVENT_LOCK = threading.Lock()


def _event(path, value):
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(value, ensure_ascii=False) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def creation_identity(process):
    if os.name == 'nt':
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.POINTER(ctypes.c_uint64)] * 4
        kernel.GetProcessTimes.restype = ctypes.c_int
        values = [ctypes.c_uint64() for _ in range(4)]
        if not kernel.GetProcessTimes(int(process._handle), *[ctypes.byref(v) for v in values]):
            raise ctypes.WinError(ctypes.get_last_error())
        return {'pid': process.pid, 'creation_filetime': values[0].value}
    return {'pid': process.pid, 'start_ticks': Path(f'/proc/{process.pid}/stat').read_text().split()[21]}


class WindowsDescendant:
    """Own an OS handle to a child created by the console/venv launcher."""
    def __init__(self, pid, parent_pid, image, owner):
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel.OpenProcess.restype = ctypes.c_void_p
        self._handle = kernel.OpenProcess(0x1000 | 0x001 | 0x100000, False, pid)
        if not self._handle:
            raise ProcessLookupError(pid)
        self.pid, self.kernel, self.name = pid, kernel, owner + '/launcher-child'
        self.identity = creation_identity(self)
        event({'event': 'created', 'name': self.name, 'identity': self.identity,
               'parent_pid': parent_pid, 'image': image, 'ownership': 'descendant OS handle'})

    def close(self):
        kernel = self.kernel
        kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        kernel.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        code = ctypes.c_uint32()
        assert kernel.GetExitCodeProcess(self._handle, ctypes.byref(code))
        if code.value == 259:
            assert creation_identity(self) == self.identity
            assert kernel.TerminateProcess(self._handle, 1)
            assert kernel.WaitForSingleObject(self._handle, 10000) == 0
        assert kernel.GetExitCodeProcess(self._handle, ctypes.byref(code))
        assert code.value != 259
        event({'event': 'closed', 'name': self.name, 'identity': self.identity,
               'returncode': code.value, 'residual_alive': False})
        kernel.CloseHandle(self._handle)


def child_process_snapshot():
    if os.name != 'nt':
        return []
    from ctypes import wintypes
    class Entry(ctypes.Structure):
        _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD),
                    ('pid', wintypes.DWORD), ('heap', ctypes.c_size_t), ('module', wintypes.DWORD),
                    ('threads', wintypes.DWORD), ('parent', wintypes.DWORD), ('priority', wintypes.LONG),
                    ('flags', wintypes.DWORD), ('image', wintypes.WCHAR * 260)]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.CreateToolhelp32Snapshot(2, 0)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry = Entry()
        entry.dwSize = ctypes.sizeof(Entry)
        rows = []
        exists = kernel.Process32FirstW(handle, ctypes.byref(entry))
        while exists:
            rows.append((entry.pid, entry.parent, entry.image))
            exists = kernel.Process32NextW(handle, ctypes.byref(entry))
        return rows
    finally:
        kernel.CloseHandle(handle)


class ManagedProcess:
    def __init__(self, command, cwd, env, name):
        self.name, self.log = name, Path(cwd) / (name + '-stderr.log')
        self.stderr = self.log.open('w', encoding='utf-8')
        self.process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=self.stderr, text=True,
                                        encoding='utf-8', bufsize=1,
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        self.identity = creation_identity(self.process)
        self.descendants = {}
        event({'event': 'created', 'name': name, 'identity': self.identity, 'command': command,
               'cwd': str(cwd), 'at': datetime.now(timezone.utc).isoformat()})
        self.lines = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.process.stdout:
            self.lines.put(line)

    def line(self, timeout=20):
        try:
            line = self.lines.get(timeout=timeout)
            self.capture_descendants()
            return line
        except queue.Empty:
            raise AssertionError(f'child produced no line; exit={self.process.poll()}, log={self.log}') from None

    def capture_descendants(self):
        if os.name != 'nt' or self.process.poll() is not None:
            return
        assert creation_identity(self.process) == self.identity
        # A historical descendant PID is not an ancestry grant for later snapshots.
        # Retain its original handle for cleanup, but only live original identities
        # may establish ownership of newly observed children.
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        parents = {self.process.pid}
        for pid, child in self.descendants.items():
            if (kernel.WaitForSingleObject(child._handle, 0) == 258
                    and creation_identity(child) == child.identity):
                parents.add(pid)
        rows = child_process_snapshot()
        changed = True
        while changed:
            changed = False
            for pid, parent, image in rows:
                if parent in parents and pid not in parents and pid not in self.descendants:
                    try:
                        self.descendants[pid] = WindowsDescendant(pid, parent, image, self.name)
                    except ProcessLookupError:
                        continue
                    parents.add(pid)
                    changed = True

    def close(self):
        self.capture_descendants()
        for child in reversed(list(self.descendants.values())):
            child.close()
        self.descendants.clear()
        process = self.process
        if process.poll() is None:
            current = creation_identity(process)
            assert current == self.identity, 'original process creation identity changed; do not terminate'
            process.terminate()  # Windows uses the original process handle, not a reused PID.
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            assert creation_identity(process) == self.identity
            process.kill()
            process.wait(timeout=10)
        self.reader.join(timeout=5)
        for stream in (process.stdin, process.stdout):
            stream.close()
        self.stderr.close()
        event({'event': 'closed', 'name': self.name, 'identity': self.identity,
               'returncode': process.returncode, 'residual_alive': process.poll() is None,
               'at': datetime.now(timezone.utc).isoformat()})


def command_env(extra=None):
    env = os.environ.copy()
    env.pop('PYTHONPATH', None)
    if os.environ.get('WORKFLOW_TEST_CLI'):
        command = [os.environ['WORKFLOW_TEST_CLI']]
        if os.environ.get('WORKFLOW_TEST_PACKAGE_ROOT'):
            env['PYTHONPATH'] = os.environ['WORKFLOW_TEST_PACKAGE_ROOT']
    else:
        command = [sys.executable, '-B', '-m', 'workflow_orchestrator.tools_cli']
        env['PYTHONPATH'] = os.environ.get('WORKFLOW_TEST_PACKAGE_ROOT', str(SOURCE))
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    if extra:
        env.update(extra)
    return command, env


def raw(endpoint, token, method, path, body=None, extra_headers=None):
    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
    headers.update(extra_headers or {})
    req = Request(endpoint + path, data=json.dumps(body).encode() if body is not None else None,
                  method=method, headers=headers)
    try:
        with urlopen(req, timeout=8) as response:
            return response.status, json.loads(response.read())
    except HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        finally:
            exc.close()


class Service:
    def __init__(self, path):
        self.path = path
        path.mkdir(parents=True, exist_ok=True)
        self.tokens = {name: secrets.token_urlsafe(24) for name in ('manager', 'worker', 'worker2', 'reader', 'c')}
        self.config = {'database_path': str(path / 'queue.sqlite'), 'listen': {'host': '127.0.0.1', 'port': 0},
                       'principals': [{'principal_id': name, 'token_env': 'TEST_QUEUE_' + name.upper(),
                                       'actions': ['list_tasks', 'get_task', 'list_task_replies']
                                                  if name == 'reader' else sorted(ACTIONS)}
                                      for name in self.tokens]}
        self.process = None
        self.start()

    def start(self):
        config_path = self.path / 'service.json'
        config_path.write_text(json.dumps(self.config), encoding='utf-8')
        command, env = command_env({'TEST_QUEUE_' + name.upper(): token for name, token in self.tokens.items()})
        process = ManagedProcess(command + ['serve', '--services', 'queue', '--config', str(config_path)],
                                 self.path, env, 'queue-service')
        self.process = process
        try:
            line = json.loads(process.line())
            self.endpoint = 'http://127.0.0.1:' + str(line['listening'][1])
            self.service_id = line['service_id']
            self.config['listen']['port'] = line['listening'][1]
        except BaseException:
            self.stop()
            raise

    def stop(self):
        if self.process:
            self.process.close()
            self.process = None

    def counts(self):
        with sqlite3.connect(self.config['database_path']) as db:
            return {name: db.execute('SELECT COUNT(*) FROM ' + name).fetchone()[0]
                    for name in ('tasks', 'claims', 'replies', 'receipts')}

    def profile(self, tools=None, principal='manager', **extra):
        value = {'connection': {'endpoint': self.endpoint, 'token_env': 'MCP_QUEUE_TOKEN'},
                 'default_issue_id': 'A', 'tools': tools or sorted(ACTIONS),
                 'journal_path': str(self.path / ('mcp-' + principal + '.json'))}
        value.update(extra)
        path = self.path / ('profile-' + principal + '.json')
        path.write_text(json.dumps(value), encoding='utf-8')
        return path


@contextmanager
def running_service(path):
    service = Service(path)
    try:
        yield service
    finally:
        service.stop()


class MCP:
    def __init__(self, service, principal='manager', profile=None):
        self.access = secrets.token_urlsafe(24)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        self.url = f'http://127.0.0.1:{port}/mcp'
        self.next_id = 0
        command, env = command_env({'MCP_QUEUE_TOKEN': service.tokens[principal], 'TEST_MCP_ACCESS': self.access})
        registry = service.path / ('mcp-registry-' + secrets.token_hex(8) + '.json')
        self.process = ManagedProcess(command + ['mcp', '--profile', str(profile or service.profile()),
            '--registry', str(registry), '--port', str(port), '--token-env', 'TEST_MCP_ACCESS'],
            service.path, env, 'mcp-' + principal)
        try:
            for _ in range(200):
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    if self.process.process.poll() is not None:
                        raise AssertionError('MCP exited during startup')
                    time.sleep(.05)
            else:
                raise AssertionError('MCP startup timed out')
            self.rpc('initialize', {'protocolVersion': '2025-03-26',
                'capabilities': {}, 'clientInfo': {'name': 'queue-test', 'version': '1'}})
        except BaseException:
            self.close()
            raise

    def send(self, value):
        # Stateless Streamable HTTP does not retain initialized notifications.
        if 'id' in value:
            raise ValueError('use rpc for requests')

    def rpc(self, method, params):
        self.next_id += 1
        request = Request(self.url, json.dumps({'jsonrpc': '2.0', 'id': self.next_id,
            'method': method, 'params': params}).encode('utf-8'), headers={
            'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream',
            'MCP-Protocol-Version': '2025-03-26', 'Authorization': 'Bearer ' + self.access})
        with urlopen(request, timeout=30) as response:
            result = json.load(response)
        assert 'error' not in result, result
        return result['result']

    def call(self, name, arguments):
        result = self.rpc('tools/call', {'name': name, 'arguments': arguments})
        return result.get('structuredContent') or json.loads(result['content'][0]['text'])

    def close(self):
        self.process.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class DropProxy:
    """Actual HTTP forwarder drops a response only after the service has replied."""
    def __init__(self, endpoint):
        self.upstream = endpoint
        self.drop = 0
        self.committed = []
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def forward(self):
                remote = urlsplit(proxy.upstream)
                conn = http.client.HTTPConnection(remote.hostname, remote.port, timeout=8)
                try:
                    body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                    conn.request(self.command, self.path, body or None, headers=dict(self.headers))
                    response = conn.getresponse()
                    payload = response.read()
                    if self.command == 'POST' and proxy.drop:
                        proxy.drop -= 1
                        proxy.committed.append(json.loads(payload))
                        self.close_connection = True
                        return
                    self.send_response(response.status)
                    for key, value in response.getheaders():
                        if key.lower() not in {'transfer-encoding', 'connection', 'server', 'date'}:
                            self.send_header(key, value)
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(payload)
                finally:
                    conn.close()
            do_GET = forward
            do_POST = forward

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.endpoint = 'http://127.0.0.1:' + str(self.server.server_port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(10)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
