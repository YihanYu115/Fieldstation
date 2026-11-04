"""Real host/source/client/foreground-CLI tests with exact owned-process cleanup."""
from __future__ import annotations

import json
import os
import secrets
import socket
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from queue_tools_harness import (
    ManagedProcess,
    WindowsDescendant,
    child_process_snapshot,
    command_env,
    raw,
)
from workflow_orchestrator.host_client import HostClient


def wait_for(fn, *, seconds=25):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(.05)
    raise AssertionError(f'condition did not become true: {last}')


class HostProcess(ManagedProcess):
    def capture_descendants(self):
        # Only capture the installed console-launcher's interpreter, never session grandchildren.
        if not os.environ.get('WORKFLOW_TEST_CLI') or self.process.poll() is not None:
            return
        for pid, parent, image in child_process_snapshot():
            if parent == self.process.pid and pid not in self.descendants:
                try:
                    self.descendants[pid] = WindowsDescendant(pid, parent, image, self.name)
                except ProcessLookupError:
                    pass


class Host:
    def __init__(self, path, queue=None, board=None, im=None, *, maximum=2, mode='zero', fault=None,
                 mcp_profile_mutator=None, config_mutator=None):
        self.path = path
        path.mkdir(parents=True, exist_ok=True)
        self.tokens = {name: secrets.token_urlsafe(24) for name in ('caller', 'other', 'limited')}
        connections, injected = {}, {}
        for name, service, actor in [('queue', queue, 'worker'), ('board', board, 'worker'), ('im', im, 'experimenter')]:
            if service:
                connections[name] = {'endpoint': service.endpoint, 'token_env': 'SESSION_' + name.upper()}
                injected['SESSION_' + name.upper()] = service.tokens[actor]
        self.injected = {**injected, **{'HOST_' + k.upper(): v for k, v in self.tokens.items()}}
        self.script = path / 'synthetic_cli.py'
        self.script.write_bytes(Path(__file__).with_name('host_synthetic_cli.py').read_bytes())
        helper = Path(__file__).with_name('queue_tools_harness.py').read_text(encoding='utf-8')
        helper = helper.replace('from workflow_orchestrator.tools_contracts import ACTIONS', 'ACTIONS = set()')
        (path / 'synthetic_process_helper.py').write_text(helper, encoding='utf-8')
        mcp = []
        if queue:
            mcp.append({'surface': 'queue', 'connection': 'queue', 'tools': ['get_task', 'reply_task', 'list_task_replies']})
        if im:
            mcp.append({'surface': 'im', 'connection': 'im', 'tools': ['list_field_packets', 'submit_field_packet', 'save_contribution']})
        self.mcp_processes = []
        for item in mcp:
            surface = item['surface']
            token_name = 'ACCESS_' + surface.upper()
            self.injected[token_name] = secrets.token_urlsafe(24)
            profile = {'surface': surface, 'connection': connections[surface], 'tools': item['tools'],
                       'journal_path': str(path / (surface + '-base-actions.json'))}
            if mcp_profile_mutator:
                # The fixture constructs the MCP service independently from the Host configuration.
                profile = mcp_profile_mutator(surface, profile, self.injected)
            profile_file = path / (surface + '-base-profile.json')
            profile_file.write_text(json.dumps(profile), encoding='utf-8')
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            command, env = command_env(self.injected)
            proc = ManagedProcess(command + ['mcp', '--profile', str(profile_file), '--registry',
                                  str(path / (surface + '-base-owner.json')), '--port', str(port),
                                  '--token-env', token_name], path, env, 'service-mcp-' + surface)
            self.mcp_processes.append(proc)
            item.update(http_url=f'http://127.0.0.1:{port}/mcp', http_token_env=token_name)
            try:
                def ready():
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.2):
                            return True
                    except OSError:
                        if proc.process.poll() is not None:
                            raise AssertionError('MCP service exited')
                        return False
                wait_for(ready)
            except BaseException:
                for active in reversed(self.mcp_processes):
                    active.close()
                raise
        self.original_env = {k: os.environ.get(k) for k in self.injected}
        os.environ.update(self.injected)
        self.config = {'database_path': str(path / 'host.sqlite'), 'runtime_path': str(path / 'host-runtime'),
                       'listen': {'host': '127.0.0.1', 'port': 0}, 'max_active_runs': maximum,
                       'connections': connections,
                       'model_profiles': {'synthetic': {'command': [sys._base_executable, '-B', str(self.script), mode], 'cwd': str(path),
                                                       'adapter': 'codex', 'env_names': ['PYTHONPATH', 'WORKFLOW_TEST_CLI', 'WORKFLOW_STEP_RUNTIME']}},
                       'role_profiles': {role: {'role': role, 'model_profile': 'synthetic',
                                              'catalog': {'role_name': role, 'responsibility': 'Synthetic role',
                                                          'profile_name': role, 'purpose': 'Program test',
                                                          'model_description': 'Synthetic', 'queue_consumer': True},
                                              'prompt': 'Inspect the actual source. Preserve failures if useful. Tools are optional.', 'mcp': mcp}
                                         for role in ('experimenter', 'scientist', 'manager', 'curator')},
                       'principals': [{'principal_id': name, 'token_env': 'HOST_' + name.upper(),
                                       'actions': ['launch', 'query', 'status'],
                                       'role_profiles': ['manager'] if name == 'limited' else ['experimenter', 'scientist', 'manager', 'curator'],
                                       'connections': list(connections)} for name in self.tokens]}
        self.process = None
        self.workers = {}
        self.fault = fault
        if config_mutator:
            config_mutator(self.config)
        try:
            self.start()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _mcp_ready(request, process):
        try:
            with urlopen(request, timeout=1) as response:
                return response.status == 200
        except URLError:
            if process.process.poll() is not None:
                raise AssertionError('MCP service exited')
            return False

    def start(self):
        config = self.path / 'host.json'
        config.write_text(json.dumps(self.config, ensure_ascii=False, indent=2), encoding='utf-8')
        command, env = command_env(self.injected)
        if self.fault:
            # Test-only wrapper, not a product configuration/API. Real host logic/HTTP/OS remain intact.
            test_entry = self.path / 'fault_host.py'
            test_entry.write_text(FAULT_HOST, encoding='utf-8')
            command = [os.environ.get('WORKFLOW_TEST_PYTHON', sys.executable), '-B', str(test_entry)]
            args = [str(config), json.dumps(self.fault)]
        else:
            args = ['host', '--config', str(config)]
        self.process = HostProcess(command + args, self.path, env, 'host-service')
        try:
            info = json.loads(self.process.line())
            self.endpoint = 'http://127.0.0.1:' + str(info['listening'][1])
            self.config['listen']['port'] = info['listening'][1]
            self.service_id = info['service_id']
        except BaseException:
            self.stop()
            raise

    def stop(self):
        if self.process:
            self.capture_workers()
            self.process.close()
            self.process = None

    def client(self, actor='caller', suffix=''):
        return HostClient({'endpoint': self.endpoint, 'token_env': 'HOST_' + actor.upper()}, self.path / ('client-' + actor + suffix + '.json'), timeout=30)

    def request(self, service, task, *, kind='queue.task', role='experimenter', request_id=None, **extra):
        source = {'connection': 'queue' if kind == 'queue.task' else 'im' if kind == 'inbox.packet' else 'board',
                  'kind': kind, 'item_id': task, 'issue_id': 'A'}
        if kind != 'inbox.packet':
            source['service_id'] = service.service_id
        return {'request_id': request_id or 'req-' + secrets.token_hex(10), 'rule_id': 'manual-synthetic',
                'source': source, 'role_profile': role, **extra}

    def capture_workers(self):
        for file in (self.path / 'host-runtime' / 'sessions').glob('*/starts.jsonl'):
            for line in file.read_text(encoding='utf-8').splitlines():
                identity = json.loads(line)['identity']
                key = (identity['pid'], identity['creation_filetime'])
                if key not in self.workers:
                    try:
                        child = WindowsDescendant(identity['pid'], 0, 'synthetic_cli.py', 'host-session')
                        if child.identity != identity:
                            child.kernel.CloseHandle(child._handle)
                            continue
                        self.workers[key] = child
                    except ProcessLookupError:
                        pass

    def starts(self):
        return [json.loads(line) for file in (self.path / 'host-runtime' / 'sessions').glob('*/starts.jsonl')
                for line in file.read_text(encoding='utf-8').splitlines()]

    def session(self, result):
        return self.path / 'host-runtime' / 'sessions' / result['run_id']

    def finish(self, result):
        session = self.session(result)
        wait_for(lambda: (session / 'starts.jsonl').exists())
        self.capture_workers()
        (session / 'exit.flag').touch()
        return wait_for(lambda: (row if (row := self.client().by_request(result['request_id']))['run']['state'] == 'exited' else None))

    def close(self):
        try:
            self.stop()
            self.capture_workers()
            for child in self.workers.values():
                child.close()
            self.workers.clear()
        finally:
            for active in reversed(self.mcp_processes):
                active.close()
            self.mcp_processes.clear()
            for k, v in self.original_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def publish(service, **extra):
    profile = extra.pop('experimenter_profile', 'experimenter')
    status, result = raw(service.endpoint, service.tokens['manager'], 'POST', '/v1/queue/tasks',
                         {'operation_id': 'op-pub-' + secrets.token_hex(8), 'issue_id': 'A',
                          'instructions': 'Measure the unresolved shift; preserve negative and partial results.',
                          'experimenter_profile': profile, **extra})
    assert status == 200, result
    return result['task_id']


FAULT_HOST = r"""
import json,os,sys,time
from pathlib import Path
from workflow_orchestrator.host_contracts import load_config
from workflow_orchestrator.host_http import HostHTTPServer
from workflow_orchestrator.launch_host import LaunchHost
config=load_config(sys.argv[1]); fault=json.loads(sys.argv[2]); directory=Path(sys.argv[1]).parent
host=None

def inject(point, record):
    if point!=fault['point'] or (directory/'fault-consumed').exists(): return
    (directory/'fault-consumed').touch()
    (directory/'fault-ready').write_text(json.dumps({'point':point,'record':record}),encoding='utf-8')
    if fault['mode']=='crash': os._exit(71)
    if fault['mode']=='disk': raise OSError('synthetic durable failure')
    if fault['mode']=='create_failed':
        host.config['model_profiles'][record['model_profile']]['command'][0]=str(directory/'absent-foreground.exe')
        return
    if fault['mode']=='os_unknown':
        import workflow_orchestrator.launch_host as module
        module.observe=lambda pid,original=None,**kw: {'state':'unknown','reason':'injected_os_access_denied','os_error':5}
        return
    if fault['mode']=='send_marker_disk':
        original=host.records.save
        def once(value):
            host.records.save=original
            raise OSError('synthetic claim send-marker persistence failure')
        host.records.save=once
        return
    if fault['mode']=='intent_disk':
        original=host.records.start_intent
        def once(*args):
            host.records.start_intent=original
            raise OSError('synthetic spawn-intent persistence failure')
        host.records.start_intent=once
        return
    if fault['mode']=='pause':
        deadline=time.monotonic()+60
        while not (directory/'fault-release').exists() and time.monotonic()<deadline: time.sleep(.05)

host=LaunchHost(config,fault=inject)
original_resume=host.resume_prepared

def resume_with_test_barrier():
    # Only test-owned preparation is held; process observation remains real.
    held = (fault.get('background_barrier') and not (directory/'background-release').exists())
    held = held or ((directory/'fault-consumed').exists() and not (directory/'fault-release').exists())
    if held:
        host.observe_all()
        return
    original_resume()

host.resume_prepared=resume_with_test_barrier
with HostHTTPServer((config['listen']['host'],config['listen']['port']),host) as server:
    host.resume_prepared()
    print(json.dumps({'listening':list(server.server_address),'service_id':host.service_id}),flush=True)
    server.serve_forever(poll_interval=.1)
"""
