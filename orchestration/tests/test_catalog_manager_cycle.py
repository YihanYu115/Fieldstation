"""One synthetic manager session, multiple bound Hosts, and real Queue/Trigger/Host paths."""
import asyncio
import json
from contextlib import ExitStack
from copy import deepcopy

import pytest
from board_tools_harness import BoardService
from host_tools_harness import Host, wait_for
from queue_tools_harness import Service, raw
from test_http_mcp_core import call, client, http_mcp
from test_python_trigger import configuration
from workflow_orchestrator.host_contracts import load_config
from workflow_orchestrator.mcp_sessions import session_token
from workflow_orchestrator.tools_contracts import ToolError
from workflow_orchestrator.trigger_tools import TriggerTools


def test_manager_two_hosts_two_tasks_and_trigger(tmp_path, monkeypatch):
    with ExitStack() as stack:
        queue = Service(tmp_path / 'queue')
        stack.callback(queue.stop)
        board = BoardService(tmp_path / 'board')
        stack.callback(board.stop)
        def target_config(config):
            for principal in config['principals']:
                principal['actions'].append('catalog')
            config['model_profiles']['alternate'] = deepcopy(config['model_profiles']['synthetic'])
            config['role_profiles']['scientist']['role'] = 'experimenter'
            config['role_profiles']['scientist']['model_profile'] = 'alternate'
        first = stack.enter_context(Host(tmp_path / 'target-a', queue, config_mutator=target_config))
        second = stack.enter_context(Host(tmp_path / 'target-b', queue, config_mutator=target_config))
        monkeypatch.setenv('TARGET_A', first.tokens['caller'])
        monkeypatch.setenv('TARGET_B', second.tokens['caller'])
        monkeypatch.setenv('MANAGER_QUEUE', queue.tokens['manager'])
        for name in ('ACCESS_A', 'ACCESS_B', 'ACCESS_MANAGER_QUEUE'):
            monkeypatch.setenv(name, 'synthetic-secret')
        entries = []
        for name, target, token in [('catalog_a', first, first.tokens['caller']), ('catalog_b', second, second.tokens['caller'])]:
            directory = tmp_path / ('mcp-' + name)
            directory.mkdir()
            profile = {'surface': 'host', 'connection': {'endpoint': target.endpoint, 'token_env': 'MCP_QUEUE_TOKEN'},
                       'tools': ['list_host_catalog'], 'journal_path': str(directory / 'unused.json')}
            base, _ = stack.enter_context(http_mcp(None, profile, token, directory))
            entries.append({'surface': 'host', 'name': name, 'connection': name, 'tools': ['list_host_catalog'],
                            'http_url': base + '/mcp', 'http_token_env': 'ACCESS_A' if name.endswith('a') else 'ACCESS_B'})
        directory = tmp_path / 'mcp-manager-queue'
        directory.mkdir()
        profile = queue.profile(tools=['publish_task'], principal='manager')
        base, _ = stack.enter_context(http_mcp(queue, profile, queue.tokens['manager'], directory))
        entries.append({'surface': 'queue', 'connection': 'manager_queue', 'tools': ['publish_task'],
                        'http_url': base + '/mcp', 'http_token_env': 'ACCESS_MANAGER_QUEUE'})
        def manager_config(config):
            config['connections'].update(catalog_a={'endpoint': first.endpoint, 'token_env': 'TARGET_A'},
                                         catalog_b={'endpoint': second.endpoint, 'token_env': 'TARGET_B'},
                                         manager_queue={'endpoint': queue.endpoint, 'token_env': 'MANAGER_QUEUE'})
            config['role_profiles']['manager']['mcp'] = entries
        with Host(tmp_path / 'manager', queue, board=board, mode='catalog_cycle', config_mutator=manager_config) as manager:
            for invalid_name in ('catalog_a', 'bad.name', 'bad]name'):
                invalid = deepcopy(manager.config)
                invalid['role_profiles']['manager']['mcp'][1]['name'] = invalid_name
                config_file = tmp_path / 'invalid-host.json'
                config_file.write_text(json.dumps(invalid), encoding='utf-8')
                with pytest.raises(ToolError, match='MCP server names'):
                    load_config(config_file)
            status, message = raw(board.endpoint, board.tokens['manager'], 'POST', '/v1/board/messages',
                                  {'operation_id': 'manager-input', 'issue_id': 'A', 'text': 'Coordinate work.'})
            assert status == 200, message
            request = manager.request(board, message['message']['message_id'], kind='board.message', role='manager')
            receipt = manager.client().launch(request)
            assert receipt['outcome'] == 'accepted', receipt
            session = manager.session(receipt)
            wait_for(lambda: (session / 'results.json').exists())
            results = json.loads((session / 'results.json').read_text(encoding='utf-8'))
            catalogs = [r for r in results if 'catalog_result' in r]
            assert {r['name'] for r in catalogs} == {'catalog_a', 'catalog_b'}
            assert {r['catalog_result']['service_id'] for r in catalogs} == {first.service_id, second.service_id}
            assert all(len(r['catalog_result']['items']) >= 3 for r in catalogs)
            tasks = [r['published']['task_id'] for r in results if 'published' in r]
            assert len(tasks) == 2 and queue.counts()['claims'] == 0
            context = json.loads((session / 'input.json').read_text(encoding='utf-8'))
            assert {m.get('name') for m in context['mcp'] if m['surface'] == 'host'} == {'catalog_a', 'catalog_b'}
            second.stop()
            async def verify_partial_failure():
                surfaces = {m['name']: m for m in context['mcp'] if m['surface'] == 'host'}
                for name in ('catalog_a', 'catalog_b'):
                    token = session_token('synthetic-secret', receipt['run_id'] + '-' + name)
                    async with client(surfaces[name]['url'], token) as session_client:
                        result = await call(session_client, 'list_host_catalog', {})
                    if name == 'catalog_a':
                        assert result['service_id'] == first.service_id
                    else:
                        assert result['error']['code'] == 'transport_unknown'
            asyncio.run(verify_partial_failure())
            monkeypatch.setenv('HOST_CALLER', first.tokens['caller'])
            config = configuration(tmp_path, monkeypatch, {'queue': queue}, first)
            trigger = TriggerTools(config, tmp_path / 'trigger')
            trigger.listen('queue', kind='queue.task', connection='queue', issue_id='A')
            trigger.scan_once()
            candidates = list(trigger.pending('queue'))
            assert {c['record']['experimenter_profile'] for c in candidates} == {'experimenter', 'scientist'}
            launches = [trigger.activate(c, host='host') for c in candidates]
            assert all(r['outcome'] == 'accepted' for r in launches), launches
            wait_for(lambda: len(first.starts()) == 2)
            assert {s['context']['model_profile'] for s in first.starts()} == {'synthetic', 'alternate'}
            assert queue.counts()['claims'] == 2
