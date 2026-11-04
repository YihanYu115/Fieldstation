"""Public Streamable HTTP paths with the official MCP client and isolated services."""
import asyncio
import json
import socket
import time
from contextlib import asynccontextmanager, contextmanager
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import httpx
from board_tools_harness import running_board
from im_tools_harness import IMService
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from queue_tools_harness import ManagedProcess, command_env, running_service
from workflow_orchestrator.mcp_sessions import session_token


@contextmanager
def http_mcp(service, profile, token, tmp):
    if isinstance(profile, dict):
        file = tmp / 'profile.json'
        file.write_text(json.dumps(profile), encoding='utf-8')
    else:
        file = profile
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    command, env = command_env({'MCP_QUEUE_TOKEN': token, 'MCP_HTTP_TOKEN': 'synthetic-secret'})
    process = ManagedProcess(command + ['mcp', '--profile', str(file), '--registry', str(tmp / 'registry.json'),
        '--port', str(port), '--token-env', 'MCP_HTTP_TOKEN'], tmp, env, 'http-mcp')
    base = f'http://127.0.0.1:{port}'
    try:
        for _ in range(200):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1):
                    break
            except OSError:
                if process.process.poll() is not None:
                    raise AssertionError('MCP process exited')
                time.sleep(.05)
        else:
            raise AssertionError('MCP startup timed out')
        yield base, process
    finally:
        process.close()


@asynccontextmanager
async def client(url, token='synthetic-secret'):
    async with httpx.AsyncClient(headers={'Authorization': 'Bearer ' + token}, timeout=15) as http:
        async with streamable_http_client(url, http_client=http) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


async def call(session, name, arguments):
    result = await session.call_tool(name, arguments)
    return result.structuredContent or json.loads(result.content[0].text)


def register(base, session_id, issue, tools, task=None):
    value = {'session_id': session_id, 'default_issue_id': issue, 'tools': tools}
    if task:
        value['default_task_id'] = task
    req = Request(base + '/internal/sessions', json.dumps(value).encode(), headers={
        'Authorization': 'Bearer synthetic-secret', 'Content-Type': 'application/json'})
    with urlopen(req, timeout=8) as response:
        return json.load(response)


def test_queue_sessions_and_disconnect(tmp_path):
    with running_service(tmp_path / 'queue') as service:
        profile = service.profile(tools=['publish_task', 'list_tasks'])
        with http_mcp(service, profile, service.tokens['manager'], service.path) as (base, process):
            register(base, 'session-a', 'A', ['publish_task', 'list_tasks'])
            register(base, 'session-b', 'B', ['publish_task', 'list_tasks'])
            wrong = Request(base + '/sessions/session-b/mcp', b'{}', headers={
                'Authorization': 'Bearer ' + session_token('synthetic-secret', 'session-a')})
            try:
                urlopen(wrong, timeout=8)
            except HTTPError as exc:
                assert exc.code == 401
                exc.close()
            else:
                raise AssertionError('another session token was accepted')
            async def run():
                for sid in ['session-a', 'session-b']:
                    async with client(base + '/sessions/' + sid + '/mcp', session_token('synthetic-secret', sid)) as m:
                        made = await call(m, 'publish_task', {'instructions': 'same words', 'experimenter_profile': 'worker'})
                        assert made.get('task_id'), made
                        items = (await call(m, 'list_tasks', {}))['items']
                        assert len(items) == 1 and items[0]['issue_id'] == ('A' if sid.endswith('a') else 'B')
                assert process.process.poll() is None
                async with client(base + '/mcp') as m:
                    result = await call(m, 'publish_task', {'issue_id': 'C', 'instructions': 'base session', 'experimenter_profile': 'worker'})
                    assert result['task']['issue_id'] == 'C'
            asyncio.run(run())
            assert service.counts()['tasks'] == 3


def test_board_http(tmp_path):
    with running_board(tmp_path / 'board') as service:
        profile = service.profile(tools=['post_message', 'list_messages'])
        with http_mcp(service, profile, service.tokens['manager'], service.path) as (base, _):
            async def run():
                async with client(base + '/mcp') as m:
                    result = await call(m, 'post_message', {'text': 'Test message'})
                    assert result.get('message_id'), result
                    assert len((await call(m, 'list_messages', {}))['items']) == 1
            asyncio.run(run())


def test_im_http(tmp_path):
    service = IMService(tmp_path / 'im')
    try:
        profile = service.profile(tools=['submit_field_packet', 'list_field_packets', 'get_delivery_status'])
        with http_mcp(service, profile, service.tokens['experimenter'], service.path) as (base, _):
            async def run():
                async with client(base + '/mcp') as m:
                    result = await call(m, 'submit_field_packet', {'content': 'Synthetic failed scan'})
                    assert result['status'] == 'received', result
                    status = await m.call_tool('get_delivery_status', {'delivery_id': result['delivery_id']})
                    assert status.isError is False
                    assert status.structuredContent['state'] == 'confirmed'
                    assert status.structuredContent['error'] is None
                    assert status.structuredContent['receipt']['packet_id'] == result['packet_id']
                    missing = await m.call_tool('get_delivery_status', {'delivery_id': 'missing-delivery'})
                    assert missing.isError is True
                    assert missing.structuredContent['error']['code'] == 'not_found'
                    assert (await call(m, 'list_field_packets', {}))['count'] == 1
            asyncio.run(run())
    finally:
        service.stop()


def test_queue_original_recovery_and_restart(tmp_path):
    from queue_tools_harness import DropProxy
    from workflow_orchestrator.tools_client import ToolsClient
    with running_service(tmp_path / 'queue') as service, DropProxy(service.endpoint) as proxy:
        profile = service.profile(tools=['publish_task', 'list_tasks'], connection={
            'endpoint': proxy.endpoint, 'token_env': 'MCP_QUEUE_TOKEN'})
        with http_mcp(service, profile, service.tokens['manager'], service.path) as (base, _):
            async def run():
                async with client(base + '/mcp') as m:
                    proxy.drop = 1
                    result = await call(m, 'publish_task', {'instructions': 'Recover original', 'experimenter_profile': 'worker'})
                    assert result['error']['effect'] == 'unknown', result
                    return result['error']['operation_id']
            operation = asyncio.run(run())
            assert service.counts()['tasks'] == 1
        direct = ToolsClient(proxy.endpoint, service.tokens['manager'], service.path / 'mcp-manager.json')
        receipt = direct.recover(operation)
        assert receipt['operation_id'] == operation
        assert service.counts()['tasks'] == 1
        with http_mcp(service, profile, service.tokens['manager'], service.path) as (base, _):
            async def after_restart():
                async with client(base + '/mcp') as m:
                    assert len((await call(m, 'list_tasks', {}))['items']) == 1
            asyncio.run(after_restart())


def test_downstream_unavailable_then_reconnect(tmp_path):
    with running_service(tmp_path / 'queue') as service:
        profile = service.profile(tools=['list_tasks'])
        with http_mcp(service, profile, service.tokens['manager'], service.path) as (base, process):
            service.stop()
            request = Request(base + '/mcp', b'{}', headers={'Authorization': 'Bearer synthetic-secret',
                'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'})
            try:
                urlopen(request, timeout=8)
            except HTTPError as exc:
                assert exc.code == 503
                exc.close()
            else:
                raise AssertionError('downstream unexpectedly available')
            assert process.process.poll() is None
            service.start()
            async def restored():
                async with client(base + '/mcp') as m:
                    assert (await call(m, 'list_tasks', {}))['items'] == []
            asyncio.run(restored())


def test_im_lost_response_recovers_original(tmp_path):
    from queue_tools_harness import DropProxy
    service = IMService(tmp_path / 'im')
    try:
        with DropProxy(service.endpoint) as proxy:
            profile = service.profile(tools=['submit_field_packet', 'list_field_packets', 'recover_delivery'], endpoint=proxy.endpoint)
            with http_mcp(service, profile, service.tokens['experimenter'], service.path) as (base, _):
                async def run():
                    async with client(base + '/mcp') as m:
                        proxy.drop = 1
                        lost_response = await m.call_tool('submit_field_packet', {'content': 'Original synthetic measurement'})
                        assert lost_response.isError is True
                        lost = lost_response.structuredContent
                        assert lost['error']['effect'] == 'unknown', lost
                        restored_response = await m.call_tool('recover_delivery', {'delivery_id': lost['error']['operation_id']})
                        assert restored_response.isError is False
                        restored = restored_response.structuredContent
                        assert restored['idempotent_replay'] is True, restored
                        assert (await call(m, 'list_field_packets', {}))['count'] == 1
                asyncio.run(run())
    finally:
        service.stop()


def test_host_applies_codex_config_to_real_cli(tmp_path, monkeypatch):
    import shutil

    from host_tools_harness import publish
    from workflow_orchestrator.host_contracts import load_config
    from workflow_orchestrator.launch_host import LaunchHost
    codex = shutil.which('codex')
    assert codex and codex.lower().endswith('.exe')
    with running_service(tmp_path / 'queue') as service:
        tools = ['get_task', 'reply_task', 'list_task_replies']
        profile = service.profile(tools=tools, principal='worker')
        with http_mcp(service, profile, service.tokens['worker'], service.path) as (base, _):
            monkeypatch.setenv('HOST_TEST_CALLER', 'synthetic-caller')
            monkeypatch.setenv('HOST_TEST_QUEUE', service.tokens['worker'])
            monkeypatch.setenv('HOST_TEST_MCP', 'synthetic-secret')
            principal = {'principal_id': 'caller', 'token_env': 'HOST_TEST_CALLER',
                         'actions': ['launch', 'query', 'status'], 'role_profiles': ['experimenter'], 'connections': ['queue']}
            cfg = {'database_path': str(tmp_path / 'host.sqlite'), 'runtime_path': str(tmp_path / 'host-runtime'),
                   'listen': {'host': '127.0.0.1', 'port': 0}, 'max_active_runs': 1, 'principals': [principal],
                   'connections': {'queue': {'endpoint': service.endpoint, 'token_env': 'HOST_TEST_QUEUE'}},
                   'model_profiles': {'codex': {'command': [codex, 'mcp', 'list', '--json'], 'cwd': str(tmp_path), 'adapter': 'codex'}},
                   'role_profiles': {'experimenter': {'role': 'experimenter', 'model_profile': 'codex', 'prompt': 'Inspect.',
                        'catalog': {'role_name': 'Experimenter', 'responsibility': 'Inspect', 'profile_name': 'Codex',
                                    'purpose': 'HTTP MCP test', 'model_description': 'Codex', 'queue_consumer': True},
                        'mcp': [{'surface': 'queue', 'connection': 'queue', 'tools': tools, 'http_url': base + '/mcp',
                                 'http_token_env': 'HOST_TEST_MCP'}]}}}
            file = tmp_path / 'host.json'
            file.write_text(json.dumps(cfg), encoding='utf-8')
            host = LaunchHost(load_config(file))
            task = publish(service)
            request = {'request_id': 'test-codex', 'rule_id': 'manual', 'role_profile': 'experimenter',
                'source': {'connection': 'queue', 'kind': 'queue.task', 'item_id': task, 'issue_id': 'A', 'service_id': service.service_id}}
            result = host.launch(principal, request)
            run = result['run']
            assert run['process'] and run['process']['identity'], run
            child = host.children[result['run_id']]
            try:
                child.wait(timeout=30)
                host.observe_one(host.records.lookup('test-codex', run['request'] and __import__('workflow_orchestrator.host_contracts', fromlist=['principal_binding']).principal_binding(principal)))
                assert child.returncode == 0
                session = tmp_path / 'host-runtime' / 'sessions' / result['run_id']
                outputs = json.loads((session / 'stdout.log').read_text(encoding='utf-8'))
                queue = next(row for row in outputs if row['name'] == 'queue')
                assert queue['transport']['url'] == base + '/sessions/' + result['run_id'] + '-queue/mcp', queue
                assert queue['transport']['bearer_token_env_var'] == 'HOST_TEST_MCP'
            finally:
                if child.poll() is None:
                    child.terminate()
                    child.wait(timeout=10)


def test_codex_app_server_connects_http_mcp_without_model(tmp_path):
    import shutil
    with running_service(tmp_path / 'queue') as service:
        tools = ['list_tasks']
        profile = service.profile(tools=tools)
        with http_mcp(service, profile, service.tokens['manager'], service.path) as (base, _):
            command = [shutil.which('codex'), 'app-server', '-c',
                'mcp_servers.queue={url="' + base + '/mcp",bearer_token_env_var="MCP_HTTP_TOKEN"}']
            _, env = command_env({'MCP_HTTP_TOKEN': 'synthetic-secret'})
            process = ManagedProcess(command, tmp_path, env, 'codex-app-server')
            try:
                def send(value):
                    process.process.stdin.write(json.dumps(value) + '\n')
                    process.process.stdin.flush()
                def response(identity):
                    while True:
                        value = json.loads(process.line())
                        if value.get('id') == identity:
                            assert 'error' not in value, value
                            return value['result']
                send({'method': 'initialize', 'id': 1, 'params': {'clientInfo': {'name': 'synthetic-test', 'version': '1'}}})
                response(1)
                send({'method': 'initialized', 'params': {}})
                send({'method': 'mcpServerStatus/list', 'id': 2, 'params': {'serverName': 'queue'}})
                status = response(2)
                queue = next(row for row in status['data'] if row['name'] == 'queue')
                assert 'list_tasks' in queue['tools'], queue
                assert queue.get('toolsError') is None, queue
            finally:
                process.close()


def test_queue_default_task_is_per_session(tmp_path):
    from host_tools_harness import publish
    with running_service(tmp_path / 'queue') as service:
        tasks = [publish(service), publish(service)]
        tools = ['reply_task', 'list_task_replies']
        profile = service.profile(tools=tools)
        with http_mcp(service, profile, service.tokens['manager'], service.path) as (base, _):
            for index, task in enumerate(tasks):
                register(base, 'run-' + str(index), 'A', tools, task)
            async def run():
                for index in range(2):
                    sid = 'run-' + str(index)
                    async with client(base + '/sessions/' + sid + '/mcp', session_token('synthetic-secret', sid)) as m:
                        result = await call(m, 'reply_task', {'text': 'reply ' + str(index)})
                        assert result.get('reply', {}).get('reply_id'), result
                        items = (await call(m, 'list_task_replies', {}))['items']
                        assert len(items) == 1 and items[0]['text'] == 'reply ' + str(index)
            asyncio.run(run())


def test_registered_session_recovers_original_after_mcp_restart(tmp_path):
    from queue_tools_harness import DropProxy
    with running_service(tmp_path / 'queue') as service, DropProxy(service.endpoint) as proxy:
        profile = service.profile(tools=['publish_task', 'list_tasks'], connection={
            'endpoint': proxy.endpoint, 'token_env': 'MCP_QUEUE_TOKEN'})
        sid = 'restart-session'
        token = session_token('synthetic-secret', sid)
        with http_mcp(service, profile, service.tokens['manager'], service.path) as (base, _):
            register(base, sid, 'A', ['publish_task', 'list_tasks'])
            async def first():
                async with client(base + '/sessions/' + sid + '/mcp', token) as m:
                    proxy.drop = 1
                    result = await call(m, 'publish_task', {'instructions': 'original lost reply', 'experimenter_profile': 'worker'})
                    assert result['error']['effect'] == 'unknown', result
                    return result['error']['operation_id']
            original = asyncio.run(first())
            assert service.counts()['tasks'] == 1
        with http_mcp(service, profile, service.tokens['manager'], service.path) as (base, _):
            async def second():
                async with client(base + '/sessions/' + sid + '/mcp', token) as m:
                    assert len((await call(m, 'list_tasks', {}))['items']) == 1
            asyncio.run(second())
        session_journals = list(service.path.glob('mcp-sessions-*/*-actions.json'))
        assert len(session_journals) == 1
        journal = json.loads(session_journals[0].read_text(encoding='utf-8'))
        assert journal['actions'][original]['state'] != 'pending'
        assert service.counts()['tasks'] == 1


def test_host_session_recovery_command(tmp_path):
    from queue_tools_harness import DropProxy
    with running_service(tmp_path / 'queue') as service, DropProxy(service.endpoint) as proxy:
        profile = service.profile(tools=['publish_task'], connection={
            'endpoint': proxy.endpoint, 'token_env': 'MCP_QUEUE_TOKEN'})
        sid = 'command-session'
        with http_mcp(service, profile, service.tokens['manager'], service.path) as (base, _):
            register(base, sid, 'A', ['publish_task'])
            async def send():
                async with client(base + '/sessions/' + sid + '/mcp', session_token('synthetic-secret', sid)) as m:
                    proxy.drop = 1
                    result = await call(m, 'publish_task', {'instructions': 'recover via CLI', 'experimenter_profile': 'worker'})
                    assert result['error']['effect'] == 'unknown'
                    return result['error']['operation_id']
            operation = asyncio.run(send())
            command, env = command_env({'MCP_QUEUE_TOKEN': service.tokens['manager'], 'MCP_HTTP_TOKEN': 'synthetic-secret'})
            process = ManagedProcess(command + ['recover', '--profile', str(profile), '--operation-id', operation,
                '--registry', str(service.path / 'registry.json'), '--session-id', sid, '--token-env', 'MCP_HTTP_TOKEN'],
                service.path, env, 'recover-session')
            try:
                receipt = json.loads(process.line())
                assert receipt['operation_id'] == operation
                assert service.counts()['tasks'] == 1
            finally:
                process.close()


def test_host_launches_codex_app_server_with_live_session_tools(tmp_path, monkeypatch):
    import shutil

    import websockets
    from host_tools_harness import publish
    from workflow_orchestrator.host_contracts import load_config, principal_binding
    from workflow_orchestrator.launch_host import LaunchHost
    with running_service(tmp_path / 'queue') as service:
        tools = ['get_task', 'reply_task', 'list_task_replies']
        profile = service.profile(tools=tools, principal='worker')
        with http_mcp(service, profile, service.tokens['worker'], service.path) as (base, _):
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            monkeypatch.setenv('HOST_TEST_CALLER', 'synthetic-caller')
            monkeypatch.setenv('HOST_TEST_QUEUE', service.tokens['worker'])
            monkeypatch.setenv('HOST_TEST_MCP', 'synthetic-secret')
            principal = {'principal_id': 'caller', 'token_env': 'HOST_TEST_CALLER',
                         'actions': ['launch', 'query', 'status'], 'role_profiles': ['experimenter'], 'connections': ['queue']}
            cfg = {'database_path': str(tmp_path / 'host.sqlite'), 'runtime_path': str(tmp_path / 'host-runtime'),
                   'listen': {'host': '127.0.0.1', 'port': 0}, 'max_active_runs': 1, 'principals': [principal],
                   'connections': {'queue': {'endpoint': service.endpoint, 'token_env': 'HOST_TEST_QUEUE'}},
                   'model_profiles': {'codex': {'command': [shutil.which('codex'), 'app-server', '--listen', f'ws://127.0.0.1:{port}'],
                                                'cwd': str(tmp_path), 'adapter': 'codex'}},
                   'role_profiles': {'experimenter': {'role': 'experimenter', 'model_profile': 'codex', 'prompt': 'Inspect.',
                        'catalog': {'role_name': 'Experimenter', 'responsibility': 'Inspect', 'profile_name': 'Codex',
                                    'purpose': 'HTTP MCP test', 'model_description': 'Codex', 'queue_consumer': True},
                        'mcp': [{'surface': 'queue', 'connection': 'queue', 'tools': tools, 'http_url': base + '/mcp',
                                 'http_token_env': 'HOST_TEST_MCP'}]}}}
            file = tmp_path / 'host.json'
            file.write_text(json.dumps(cfg), encoding='utf-8')
            host = LaunchHost(load_config(file))
            task = publish(service)
            request = {'request_id': 'live-codex', 'rule_id': 'manual', 'role_profile': 'experimenter',
                'source': {'connection': 'queue', 'kind': 'queue.task', 'item_id': task, 'issue_id': 'A', 'service_id': service.service_id}}
            result = host.launch(principal, request)
            run = result['run']
            assert run['process'] and run['process']['identity'], run
            child = host.children[result['run_id']]
            try:
                async def verify():
                    for _ in range(100):
                        try:
                            ws = await websockets.connect(f'ws://127.0.0.1:{port}', open_timeout=1)
                            break
                        except OSError:
                            assert child.poll() is None
                            await asyncio.sleep(.1)
                    else:
                        raise AssertionError('Codex app-server did not listen')
                    async with ws:
                        async def rpc(identity, method, params):
                            await ws.send(json.dumps({'id': identity, 'method': method, 'params': params}))
                            while True:
                                message = json.loads(await asyncio.wait_for(ws.recv(), 30))
                                if message.get('id') == identity:
                                    assert 'error' not in message, message
                                    return message['result']
                        await rpc(1, 'initialize', {'clientInfo': {'name': 'host-integration', 'version': '1'}})
                        await ws.send(json.dumps({'method': 'initialized', 'params': {}}))
                        thread = await rpc(2, 'thread/start', {'ephemeral': True, 'cwd': str(tmp_path)})
                        status = await rpc(3, 'mcpServerStatus/list', {
                            'serverName': 'queue', 'threadId': thread['thread']['id']})
                        queue = next(row for row in status['data'] if row['name'] == 'queue')
                        assert set(queue['tools']) == set(tools), queue
                        assert queue.get('toolsError') is None, queue
                asyncio.run(verify())
            finally:
                from queue_tools_harness import WindowsDescendant, child_process_snapshot
                descendants = []
                for pid, parent, image in child_process_snapshot():
                    if parent == child.pid:
                        try:
                            descendants.append(WindowsDescendant(pid, parent, image, 'host-codex'))
                        except ProcessLookupError:
                            pass
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=10)
                for descendant in descendants:
                    descendant.close()
                host.observe_one(host.records.lookup('live-codex', principal_binding(principal)))
