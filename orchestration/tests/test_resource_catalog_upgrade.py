import asyncio
import hashlib
import json
import sqlite3
import threading
from pathlib import Path

import pytest
from workflow_orchestrator.host_catalog import read_catalog
from workflow_orchestrator.host_contracts import normalize
from workflow_orchestrator.host_http import HostHTTPServer
from workflow_orchestrator.launch_host import LaunchHost
from workflow_orchestrator.listener_state import ListenerState
from workflow_orchestrator.task_queue import DDL, TaskQueue
from workflow_orchestrator.tools_contracts import ACTIONS, Principal, ToolError
from workflow_orchestrator.tools_mcp import HostCatalogTools


def metadata(queue):
    return {'role_name': 'Operator', 'responsibility': 'Perform work', 'profile_name': 'Option',
            'purpose': 'Use for experiments', 'model_description': 'Synthetic', 'queue_consumer': queue}


def test_queue_new_contract_and_legacy_refusal(tmp_path):
    principal = Principal('actor', ACTIONS)
    q = TaskQueue(tmp_path / 'queue.db')
    body = {'operation_id': 'op1', 'issue_id': 'A', 'instructions': 'work', 'experimenter_profile': 'option'}
    result = q.write(principal, 'publish_task', '', body)
    assert result['task']['experimenter_profile'] == 'option'
    assert q.write(principal, 'publish_task', '', body)['replayed']
    with pytest.raises(ToolError):
        q.write(principal, 'publish_task', '', {**body, 'model_profile': 'override'})
    with pytest.raises(ToolError):
        q.write(principal, 'publish_task', '', {**body, 'role_profile': 'old'})
    legacy = tmp_path / 'legacy.db'
    with sqlite3.connect(legacy) as db:
        db.executescript(DDL.replace('experimenter_profile TEXT NOT NULL', 'role_profile TEXT NOT NULL, model_profile TEXT'))
        db.execute("INSERT INTO tool_meta VALUES ('schema','workflow-tools-queue-2')")
    before = hashlib.sha256(legacy.read_bytes()).digest()
    with pytest.raises(ToolError, match='no migration'):
        TaskQueue(legacy)
    assert hashlib.sha256(legacy.read_bytes()).digest() == before


def test_catalog_http_authorization_and_mcp_facade(monkeypatch):
    monkeypatch.setenv('CATALOG_TOKEN', 'test-token')
    p = {'principal_id': 'reader', 'token_env': 'CATALOG_TOKEN', 'actions': ['catalog'],
         'role_profiles': ['a', 'b'], 'connections': ['q']}
    host = LaunchHost.__new__(LaunchHost)
    host.service_id = 'host-1'
    host.config = {'principals': [p], 'role_profiles': {
        'a': {'role': 'custom', 'model_profile': 'm1', 'catalog': metadata(True), 'prompt': 'SECRET'},
        'b': {'role': 'custom', 'model_profile': 'm2', 'catalog': metadata(False)},
        'hidden': {'role': 'other', 'model_profile': 'm3', 'catalog': metadata(True)}}}
    host.resume_prepared = lambda: None
    server = HostHTTPServer(('127.0.0.1', 0), host)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        connection = {'endpoint': 'http://127.0.0.1:' + str(server.server_port), 'token_env': 'CATALOG_TOKEN'}
        all_items = read_catalog(connection)
        assert [x['profile'] for x in all_items['items']] == ['a', 'b']
        assert 'SECRET' not in str(all_items)
        facade = HostCatalogTools({'connection': connection, 'tools': ['list_host_catalog']})
        assert [x['profile'] for x in facade.call('list_host_catalog', {'queue_only': True})['items']] == ['a']
        p['actions'] = ['status']
        with pytest.raises(ToolError) as exc:
            read_catalog(connection)
        assert exc.value.code == 'forbidden'
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_example_guidance_is_returned_by_host_catalog(monkeypatch):
    guidance = json.loads((Path(__file__).resolve().parents[1] / 'examples/host_role_guidance.json')
                          .read_text(encoding='utf-8'))
    monkeypatch.setenv('GUIDANCE_CATALOG_TOKEN', 'test-token')
    principal = {'principal_id': 'reader', 'token_env': 'GUIDANCE_CATALOG_TOKEN', 'actions': ['catalog'],
                 'role_profiles': list(guidance), 'connections': ['catalog']}
    host = LaunchHost.__new__(LaunchHost)
    host.service_id = 'host-guidance'
    host.config = {'principals': [principal], 'role_profiles': {
        name: {**profile, 'model_profile': 'synthetic'} for name, profile in guidance.items()}}
    host.resume_prepared = lambda: None
    server = HostHTTPServer(('127.0.0.1', 0), host)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        facade = HostCatalogTools({'connection': {
            'endpoint': 'http://127.0.0.1:' + str(server.server_port),
            'token_env': 'GUIDANCE_CATALOG_TOKEN'}, 'tools': ['list_host_catalog']})
        items = {item['profile']: item for item in facade.call('list_host_catalog', {})['items']}
        assert set(items) == set(guidance)
        assert '已有材料' in items['curator']['responsibility']
        assert '不默认等待整理员审核' in items['conclusion']['responsibility']
        assert 'Board 明确请求' in items['conclusion']['responsibility']
        assert '主动通过 Board' in guidance['manager']['prompt']
        assert items['experimenter']['queue_consumer'] is True
        assert all(not item['queue_consumer'] for name, item in items.items() if name != 'experimenter')
        assert all('prompt' not in item for item in items.values())
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_host_checks_actual_task_before_claim():
    host = LaunchHost.__new__(LaunchHost)
    host.config = {'role_profiles': {'a': {'role': 'custom', 'model_profile': 'm',
                                           'catalog': metadata(True), 'mcp': []}},
                   'model_profiles': {'m': {}}}
    class Source:
        def read(self, source):
            return {'experimenter_profile': 'a'}, {'service_id': 'queue'}
        def content_digest(self, item):
            return 'digest'
    host.sources = Source()
    request = normalize({'request_id': 'r', 'rule_id': 'x', 'role_profile': 'a',
                         'source': {'connection': 'q', 'kind': 'queue.task', 'item_id': 't',
                                    'issue_id': 'A', 'service_id': 'queue'}})
    assert host.prepare(request)['model_profile'] == 'm'
    for mutation in ({'model_profile': 'm'}, {'role_profile': 'other'}):
        with pytest.raises(ToolError):
            host.prepare({**request, **mutation})
    host.config['role_profiles']['a']['catalog']['queue_consumer'] = False
    with pytest.raises(ToolError, match='cannot consume'):
        host.prepare(request)


def test_distinct_host_catalogs_and_offline_failure(monkeypatch):
    monkeypatch.setenv('CATALOG_TOKEN', 'test-token')
    principal = {'principal_id': 'reader', 'token_env': 'CATALOG_TOKEN', 'actions': ['catalog'],
                 'role_profiles': ['same', 'second', 'third'], 'connections': ['q']}
    servers = []
    try:
        for host_id in ('one', 'two'):
            host = LaunchHost.__new__(LaunchHost)
            host.service_id = host_id
            host.config = {'principals': [principal], 'role_profiles': {
                name: {'role': 'custom', 'model_profile': host_id, 'catalog': metadata(True)}
                for name in principal['role_profiles']}}
            host.resume_prepared = lambda: None
            server = HostHTTPServer(('127.0.0.1', 0), host)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            servers.append((server, thread))
        connections = [{'endpoint': 'http://127.0.0.1:' + str(server.server_port),
                        'token_env': 'CATALOG_TOKEN'} for server, _ in servers]
        results = [read_catalog(connection) for connection in connections]
        assert [r['service_id'] for r in results] == ['one', 'two']
        assert [r['items'][0]['model_profile'] for r in results] == ['one', 'two']
        assert all(len(r['items']) == 3 for r in results)
        server, thread = servers.pop()
        server.shutdown()
        server.server_close()
        thread.join()
        with pytest.raises(ToolError):
            read_catalog(connections[1], timeout=1)
    finally:
        for server, thread in servers:
            server.shutdown()
            server.server_close()
            thread.join()


def test_old_listener_rejected(tmp_path):
    path = tmp_path / 'listener.sqlite'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE metadata (format TEXT NOT NULL)')
        db.execute("INSERT INTO metadata VALUES ('workflow-listener-1')")
        db.execute('CREATE TABLE watches (x TEXT)')
        db.execute('CREATE TABLE candidates (x TEXT)')
        db.execute('CREATE TABLE actions (x TEXT)')
    before = hashlib.sha256(path.read_bytes()).digest()
    with pytest.raises(ToolError):
        ListenerState(tmp_path)
    assert hashlib.sha256(path.read_bytes()).digest() == before


def test_catalog_real_streamable_http_session(tmp_path, monkeypatch):
    from test_http_mcp_core import call, client, http_mcp, register
    from workflow_orchestrator.mcp_sessions import session_token
    monkeypatch.setenv('MCP_QUEUE_TOKEN', 'test-token')
    p = {'principal_id': 'reader', 'token_env': 'MCP_QUEUE_TOKEN', 'actions': ['catalog'],
         'role_profiles': ['a'], 'connections': ['q']}
    host = LaunchHost.__new__(LaunchHost)
    host.service_id = 'host-1'
    host.config = {'principals': [p], 'role_profiles': {
        'a': {'role': 'custom', 'model_profile': 'm1', 'catalog': metadata(True)}}}
    host.resume_prepared = lambda: None
    server = HostHTTPServer(('127.0.0.1', 0), host)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        profile = {'surface': 'host', 'connection': {
            'endpoint': 'http://127.0.0.1:' + str(server.server_port), 'token_env': 'MCP_QUEUE_TOKEN'},
            'tools': ['list_host_catalog'], 'journal_path': str(tmp_path / 'unused.json')}
        with http_mcp(None, profile, 'test-token', tmp_path) as (base, _):
            register(base, 'manager', 'A', ['list_host_catalog'])
            async def run():
                async with client(base + '/sessions/manager/mcp', session_token('synthetic-secret', 'manager')) as session:
                    result = await call(session, 'list_host_catalog', {'queue_only': True})
                    assert result['service_id'] == 'host-1'
                    assert [item['profile'] for item in result['items']] == ['a']
            asyncio.run(run())
        assert not (tmp_path / 'unused.json').exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_two_queue_configurations_launch_their_bound_models(tmp_path):
    from copy import deepcopy

    from host_tools_harness import Host, publish, wait_for
    from queue_tools_harness import Service, raw
    queue = Service(tmp_path / 'queue')
    def configure(config):
        config['model_profiles']['another'] = deepcopy(config['model_profiles']['synthetic'])
        config['role_profiles']['scientist']['role'] = 'experimenter'
        config['role_profiles']['scientist']['model_profile'] = 'another'
    try:
        with Host(tmp_path / 'host', queue, maximum=2, config_mutator=configure) as host:
            tasks = [publish(queue), publish(queue, experimenter_profile='scientist')]
            results = [host.client().launch(host.request(queue, task, role=role))
                       for task, role in zip(tasks, ['experimenter', 'scientist'])]
            assert all(r['outcome'] == 'accepted' for r in results)
            wait_for(lambda: len(host.starts()) == 2)
            assert {x['context']['model_profile'] for x in host.starts()} == {'synthetic', 'another'}
            assert queue.counts()['claims'] == 2
            for task in tasks:
                status, record = raw(queue.endpoint, queue.tokens['manager'], 'GET', '/v1/queue/tasks/' + task)
                assert status == 200 and record['claim']
    finally:
        queue.stop()


def test_host_rejects_invalid_queue_configuration_before_claim(tmp_path):
    from host_tools_harness import Host, publish
    from queue_tools_harness import Service
    queue = Service(tmp_path / 'queue')
    def configure(config):
        config['role_profiles']['scientist']['catalog']['queue_consumer'] = False
    try:
        with Host(tmp_path / 'host', queue, config_mutator=configure) as host:
            nonconsumer = publish(queue, experimenter_profile='scientist')
            unknown = publish(queue, experimenter_profile='absent')
            ordinary = publish(queue)
            attempts = [host.request(queue, nonconsumer, role='scientist'),
                        host.request(queue, unknown, role='absent'),
                        host.request(queue, ordinary, role='scientist'),
                        host.request(queue, ordinary, model_profile='synthetic')]
            for request in attempts:
                result = host.client().launch(request)
                assert result['outcome'] == 'rejected', result
                assert queue.counts()['claims'] == 0
    finally:
        queue.stop()
