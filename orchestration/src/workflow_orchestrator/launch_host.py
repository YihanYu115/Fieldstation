"""Reliable finite foreground launch host; only technical facts are managed here."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any, Callable

from .host_contracts import (
    ACTIVE,
    authority,
    connection_binding,
    digest,
    normalize,
    principal_binding,
)
from .host_process import observe
from .host_records import HostRecords
from .host_sources import Sources
from .run_lock import exclusive
from .tools_contracts import ToolError, canonical, fail


def atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('w', encoding='utf-8', newline='\n') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_json(path: Path, value: Any) -> None:
    atomic_text(path, canonical(value) + '\n')


class LaunchHost:
    def __init__(self, config: dict[str, Any], *, fault: Callable[[str, dict[str, Any]], None] | None = None):
        self.config, self.runtime = config, Path(config['runtime_path'])
        self.runtime.mkdir(parents=True, exist_ok=True)
        connections = {k: connection_binding(v) for k, v in config['connections'].items()}
        principals = {p['principal_id']: principal_binding(p) for p in config['principals']}
        models = {k: {**v, 'env_binding': {name: digest(os.environ.get(name))
                  for name in v.get('env_names', [])}} for k, v in config['model_profiles'].items()}
        binding = {k: v for k, v in config.items() if k not in {'listen', 'principals', 'connections', 'model_profiles'}}
        binding.update(connections=connections, principals=principals, model_profiles=models)
        binding['queue_contract'] = 'workflow-tools-queue-3'
        binding['mcp_access_bindings'] = {m['http_token_env']: digest(os.environ[m['http_token_env']])
            for role in config['role_profiles'].values() for m in role['mcp']}
        self.records = HostRecords(config['database_path'], binding)
        self.service_id = self.records.service_id
        self.sources = Sources(config['connections'], self.runtime)
        self.children: dict[str, subprocess.Popen] = {}
        self.children_lock = threading.Lock()
        self.fault = fault or (lambda point, record: None)

    def identity(self, principal: dict[str, Any]) -> dict[str, Any]:
        return {'service_id': self.service_id, 'modules': ['host'], 'principal_id': principal['principal_id'],
                'principal_binding': principal_binding(principal)}

    def catalog(self, principal: dict[str, Any], *, queue_only: bool = False) -> dict[str, Any]:
        authority(principal, 'catalog')
        items = []
        for name in sorted(principal['role_profiles']):
            profile = self.config['role_profiles'][name]
            metadata = profile.get('catalog')
            if metadata is None or (queue_only and not metadata['queue_consumer']):
                continue
            items.append({'role': profile['role'], 'profile': name,
                          'model_profile': profile['model_profile'], **metadata})
        return {'service_id': self.service_id, 'scope': 'this_host',
                'filter': 'queue' if queue_only else 'all', 'items': items}

    @staticmethod
    def public(record: dict[str, Any]) -> dict[str, Any]:
        return {k: record.get(k) for k in ('request', 'run_id', 'state', 'phase', 'role', 'model_profile',
                'accepted_at', 'claim', 'spawn_intent', 'process', 'observation', 'error', 'session_path')}

    def prepare(self, request: dict[str, Any]) -> dict[str, Any]:
        profile = self.config['role_profiles'].get(request['role_profile'])
        if profile is None:
            fail('invalid_configuration', 'role profile is not installed')
        roles = {r['role'] for r in self.config['role_profiles'].values()}
        if set(request['conditions']['idle_roles']) - roles:
            fail('invalid_input', 'idle_roles must name configured role labels')
        item, binding = self.sources.read(request['source'])
        model = profile['model_profile']
        if request['source']['kind'] == 'queue.task':
            if item.get('experimenter_profile') != request['role_profile']:
                fail('profile_mismatch', 'Queue experimenter configuration must match the actual task', status=409)
            if not profile.get('catalog', {}).get('queue_consumer', False):
                fail('profile_mismatch', 'configuration cannot consume Queue tasks', status=409)
            if 'model_profile' in request:
                fail('profile_mismatch', 'Queue cannot override the configured model', status=409)
        if request.get('model_profile', model) != model or model not in self.config['model_profiles']:
            fail('profile_mismatch', 'model must match the task or configured role default', status=409)
        if profile['mcp'] and self.config['model_profiles'][model].get('adapter') != 'codex':
            fail('profile_mismatch', 'selected model requires the codex MCP launch adapter', status=409)
        return {'role': profile['role'], 'model_profile': model, 'source_binding': binding,
                'source_content_sha256': self.sources.content_digest(item), 'source_input': item}

    def launch(self, principal: dict[str, Any], value: Any) -> dict[str, Any]:
        request = normalize(value)
        authority(principal, 'launch', request)
        owner = principal_binding(principal)
        original = self.records.lookup(request['request_id'], owner, request)
        replayed = original is not None
        if original is None:
            prepared = self.prepare(request)
            self.observe_all()
            self.fault('before_admission', prepared)
            original, replayed = self.records.admit(owner, request, prepared, self.config['max_active_runs'])
        if original is None:
            return {'outcome': 'busy', 'request_id': request['request_id'], 'reason': 'host_capacity_or_idle_roles'}
        self.advance(original['request']['request_id'], owner)
        current = self.records.lookup(request['request_id'], owner, request)
        assert current is not None
        return {'outcome': 'accepted', 'request_id': request['request_id'], 'run_id': current['run_id'],
                'replayed': replayed, 'run': self.public(current)}

    def query(self, principal: dict[str, Any], request_id: str) -> dict[str, Any]:
        authority(principal, 'query')
        record = self.records.lookup(request_id, principal_binding(principal))
        if record is None:
            fail('not_found', 'request has not been accepted', status=404)
        authority(principal, 'query', record['request'])
        self.observe_one(record)
        current = self.records.lookup(request_id, principal_binding(principal))
        assert current is not None
        return {'outcome': 'accepted', 'request_id': request_id, 'run_id': current['run_id'], 'run': self.public(current)}

    def status(self, principal: dict[str, Any]) -> dict[str, Any]:
        authority(principal, 'status')
        self.observe_all()
        records = self.records.all()
        roles = {p['role'] for p in self.config['role_profiles'].values()}
        return {'service_id': self.service_id, 'scope': 'this_host', 'max_active_runs': self.config['max_active_runs'],
                'active_runs': sum(r['state'] in ACTIVE for r in records),
                'by_role': {role: sum(r['state'] in ACTIVE and r['role'] == role for r in records) for role in sorted(roles)}}

    def advance(self, request_id: str, owner: str) -> None:
        record = self.records.lookup(request_id, owner)
        if record is None or record['state'] not in ACTIVE:
            return
        try:
            with exclusive(self.runtime / 'locks' / (record['run_id'] + '.lock'), wait_seconds=0):
                record = self.records.lookup(request_id, owner)
                assert record is not None
                if record['state'] not in ACTIVE:
                    return
                if record['spawn_intent'] is not None:
                    self._observe_locked(record)
                    return
                try:
                    self._prepare_and_spawn(record)
                except ToolError as exc:
                    uncertain = exc.effect == 'unknown' or exc.code in {'transport_unknown', 'journal_write_failed'}
                    record.update(state='unknown' if uncertain else 'failed', error=exc.result()['error'])
                    self.records.save(record)
                except OSError:
                    # A failed durable write cannot disprove a previous claim or spawn.
                    # Do not overwrite on disk with an in-memory intent that failed to persist.
                    return
        except RuntimeError:
            return  # Another original execution owns this run; it is not permission to spawn.

    def _prepare_and_spawn(self, record: dict[str, Any]) -> None:
        request = record['request']
        source = request['source']
        try:
            item, binding = self.sources.read(source)
        except ToolError as exc:
            if record['claim'] and record['claim']['sent']:
                exc.effect = 'unknown'
            raise
        if binding != record['source_binding'] or self.sources.content_digest(item) != record['source_content_sha256']:
            raise ToolError('source_binding_changed', 'original source identity, content or revision differs', status=409,
                            effect='unknown' if record['claim'] and record['claim']['sent'] and not record['claim']['receipt'] else 'not_committed')
        try:
            # Bind and check every required MCP surface before claiming the Queue task.
            session = self._session(record)
        except ToolError as exc:
            # A previously sent claim without a receipt remains unknown even if
            # this preparation attempt cannot validate the MCP binding.
            if record['claim'] and record['claim']['sent'] and not record['claim']['receipt']:
                exc.effect = 'unknown'
            raise
        if source['kind'] == 'queue.task':
            if record['claim'] is None:
                self.fault('before_claim_intent', record)
                record['claim'] = {'body': {'operation_id': 'op-' + uuid.uuid4().hex},
                                   'path': '/v1/queue/tasks/' + source['item_id'] + '/claim',
                                   'binding': binding, 'sent': False, 'receipt': None}
                record.update(phase='claim_prepared')
                self.records.save(record)  # Original ID is attached to run BEFORE any POST.
                self.fault('after_claim_intent', record)
            claim = record['claim']
            if claim['receipt'] is None:
                previous_send = claim['sent']
                claim['sent'] = True
                record.update(state='unknown', phase='claim_sending')
                self.records.save(record)
                try:
                    result = self.sources.claim(source, claim)
                except ToolError as exc:
                    if previous_send and exc.code in {'unauthorized', 'forbidden', 'source_identity_changed', 'recovery_binding_changed'}:
                        exc.effect = 'unknown'
                    raise
                self.fault('after_claim_send', record)
                self.fault('before_claim_receipt', record)
                claim['receipt'] = result
                record.update(phase='claimed', state='accepted', error=None)
                self.records.save(record)
        record['session_path'] = str(session)
        self.records.save(record)
        self.fault('before_spawn_intent', record)
        if not self.records.start_intent(record, self.config['max_active_runs']):
            return
        self.fault('after_spawn_intent', record)
        # From here every ambiguous failure retains the intent and MUST NOT create again.
        try:
            self.fault('before_create', record)
            model = self.config['model_profiles'][record['model_profile']]
            env = self._environment(record, session)
            command = list(model['command'])
            if model.get('adapter') == 'codex':
                if len(command) > 1 and command[1] in {'exec', 'e'} and '--ignore-user-config' not in command:
                    command.append('--ignore-user-config')
                context = json.loads((session / 'input.json').read_text(encoding='utf-8'))
                for item in context['mcp']:
                    value = '{url=' + json.dumps(item['url']) + ',bearer_token_env_var=' + json.dumps(item['bearer_token_env']) + '}'
                    command.extend(['-c', 'mcp_servers.' + item.get('name', item['surface']) + '=' + value])
            with (session / 'stdout.log').open('ab') as out, (session / 'stderr.log').open('ab') as err:
                child = subprocess.Popen(command, cwd=model['cwd'], env=env, stdin=subprocess.DEVNULL,
                                         stdout=out, stderr=err, shell=False, close_fds=True,
                                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW") if os.name == 'nt' else 0)
            with self.children_lock:
                self.children[record['run_id']] = child
            self.fault('after_create', record)
            observation = observe(child.pid, handle=int(getattr(child, '_handle')) if os.name == 'nt' else None)
            record['process'] = {'pid': child.pid, 'identity': observation.get('identity')}
            record['observation'] = observation
            record.update(state=observation['state'], phase='observing')
            self.fault('before_process_save', record)
            self.records.save(record)
        except OSError:
            # Popen's error means CreateProcess did not return a process; once child exists it is ambiguous.
            if 'child' not in locals():
                record.update(state='failed', phase='create_failed', error={'code': 'create_failed',
                              'message': 'foreground process was not created', 'effect': 'not_committed'})
                self.records.save(record)
            # If receipt save failed, leave persisted intent; observation cannot authorize a new launch.
            return

    def _session(self, record: dict[str, Any]) -> Path:
        from urllib.error import HTTPError, URLError
        from urllib.request import Request, build_opener

        from .tools_client import NoRedirect
        from .tools_contracts import decode
        profile = self.config['role_profiles'][record['request']['role_profile']]
        session = self.runtime / 'sessions' / record['run_id']
        session.mkdir(parents=True, exist_ok=True)
        manifest = []
        for mcp in profile['mcp']:
            surface = mcp['surface']
            connection = self.config['connections'][mcp['connection']]
            expected = {'surface': surface, 'endpoint': connection['endpoint'].rstrip('/'),
                        'credential_sha256': hashlib.sha256(os.environ[connection['token_env']].encode('utf-8')).hexdigest(),
                        'tools': mcp['tools'], 'default_issue_id': record['request']['source']['issue_id'],
                        'default_task_id': None}
            if surface == 'queue' and record['request']['source']['kind'] == 'queue.task':
                expected['default_task_id'] = record['request']['source']['item_id']
            server_name = mcp.get('name', surface)
            session_id = record['run_id'] + '-' + server_name
            registration = {'session_id': session_id, 'tools': mcp['tools'],
                            'default_issue_id': record['request']['source']['issue_id']}
            if expected['default_task_id'] is not None:
                registration['default_task_id'] = expected['default_task_id']
            request = Request(mcp['http_url'][:-4] + '/internal/sessions',
                data=canonical(registration).encode('utf-8'), headers={
                'Authorization': 'Bearer ' + os.environ[mcp['http_token_env']],
                'Content-Type': 'application/json'})
            try:
                with build_opener(NoRedirect()).open(request, timeout=5) as response:
                    raw = response.read(262145)
                    if len(raw) > 262144:
                        raise ToolError('invalid_response', 'MCP binding response too large')
                    binding = decode(raw)
            except HTTPError as exc:
                code = exc.code
                exc.close()
                if code == 409:
                    raise ToolError('mcp_binding_changed', 'original HTTP MCP session binding differs') from None
                raise ToolError('mcp_unavailable', 'original MCP session registration needs retry',
                                effect='unknown') from None
            except (URLError, OSError):
                raise ToolError('mcp_unavailable', 'original MCP session registration needs retry',
                                effect='unknown') from None
            if binding != expected:
                raise ToolError('mcp_binding_changed', 'HTTP MCP profile does not match this session')
            manifest.append({'surface': surface, 'url': mcp['http_url'][:-4] + '/sessions/' + session_id + '/mcp',
                             'bearer_token_env': mcp['http_token_env'], 'tools': mcp['tools'],
                             **({'name': server_name} if 'name' in mcp else {})})
        context = {'request_id': record['request']['request_id'], 'run_id': record['run_id'],
                   'source': record['request']['source'], 'source_input': record['source_input'],
                   'default_issue_id': record['request']['source']['issue_id'],
                   'role_profile': record['request']['role_profile'], 'role': record['role'],
                   'model_profile': record['model_profile'], 'prompt': profile['prompt'],
                   'mcp': manifest, 'read_path': self._read_path(record['request']['source'])}
        if record['request']['source']['kind'] == 'queue.task':
            context['task_id'] = record['request']['source']['item_id']
        config_path = session / 'mcp.toml'
        config = ''.join('[mcp_servers.' + item.get('name', item['surface']) + ']\nurl = ' + json.dumps(item['url'])
                         + '\nbearer_token_env_var = ' + json.dumps(item['bearer_token_env']) + '\n\n'
                         for item in manifest)
        atomic_text(config_path, config)
        context['mcp_config_path'] = str(config_path)
        atomic_json(session / 'input.json', context)
        return session

    @staticmethod
    def _read_path(source: dict[str, Any]) -> str:
        return {'queue.task': '/v1/queue/tasks/', 'board.message': '/v1/board/messages/',
                'board.handoff': '/v1/board/handoffs/', 'inbox.packet': '/v1/field-packets/'}[source['kind']] + source['item_id']

    def _environment(self, record: dict[str, Any], session: Path) -> dict[str, str]:
        model = self.config['model_profiles'][record['model_profile']]
        # Only trusted config can choose additional env sources. Caller/host credentials are not inherited.
        base = {'SYSTEMROOT', 'SYSTEMDRIVE', 'WINDIR', 'PATH', 'PATHEXT', 'COMSPEC', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA',
                'TEMP', 'TMP', 'TMPDIR', 'PYTHONIOENCODING', 'PYTHONDONTWRITEBYTECODE', 'PYTHONPYCACHEPREFIX'}
        allowed = {k.upper() for k in base | set(model.get('env_names', []))}
        env = {k: v for k, v in os.environ.items() if k.upper() in allowed}
        role = self.config['role_profiles'][record['request']['role_profile']]
        from .mcp_sessions import session_token
        for mcp in role['mcp']:
            name = mcp['http_token_env']
            env[name] = session_token(os.environ[name], record['run_id'] + '-' + mcp.get('name', mcp['surface']))
        env.update(WORKFLOW_SESSION_INPUT=str(session / 'input.json'), WORKFLOW_SESSION_DIRECTORY=str(session),
                   WORKFLOW_MCP_CONFIG=str(session / 'mcp.toml'))
        return env

    def observe_one(self, record: dict[str, Any]) -> None:
        if record['state'] not in ACTIVE or record['spawn_intent'] is None:
            return
        try:
            with exclusive(self.runtime / 'locks' / (record['run_id'] + '.lock')):
                current = self.records.lookup(record['request']['request_id'], record['owner'])
                assert current is not None
                if current['state'] in ACTIVE:
                    self._observe_locked(current)
        except (RuntimeError, OSError):
            pass

    def _observe_locked(self, record: dict[str, Any]) -> None:
        process = record['process']
        if not process or not process.get('identity'):
            record.update(state='unknown', phase='spawn_unknown', observation={
                'state': 'unknown', 'reason': 'spawn_intent_without_durable_process_identity'})
        else:
            with self.children_lock:
                child = self.children.get(record['run_id'])
            observation = observe(process['pid'], process['identity'],
                                  handle=int(getattr(child, '_handle')) if child is not None and os.name == 'nt' else None)
            record.update(state=observation['state'], phase='observing', observation=observation)
            if observation['state'] == 'exited' and child is not None:
                child.wait(timeout=0)
                with self.children_lock:
                    self.children.pop(record['run_id'], None)
        self.records.save(record)

    def observe_all(self) -> None:
        for record in self.records.all():
            self.observe_one(record)

    def resume_prepared(self) -> None:
        for record in self.records.all():
            self.advance(record['request']['request_id'], record['owner'])
