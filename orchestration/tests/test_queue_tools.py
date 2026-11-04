"""First-step business acceptance through actual HTTP and installed-capable stdio."""
from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from queue_tools_harness import (
    MCP,
    DropProxy,
    ManagedProcess,
    command_env,
    evidence,
    raw,
    running_service,
)
from workflow_orchestrator.tools_client import ToolsClient
from workflow_orchestrator.tools_contracts import ACTIONS, ToolError


@pytest.fixture
def service(tmp_path):
    with running_service(tmp_path / 'service') as value:
        yield value


def client(service, name='manager', suffix=''):
    return ToolsClient(service.endpoint, service.tokens[name], service.path / (name + suffix + '.json'))


def publish(current, issue='A', instructions='Measure the unresolved frequency shift; save failures too.'):
    return current.write('publish_task', issue_id=issue, instructions=instructions,
                         input_refs=['im:observation:seed'], experimenter_profile='experimenter')


def test_independent_business_http_and_read_only(service):
    manager, worker = client(service), client(service, 'worker')
    receipt = publish(manager)
    task_id = receipt['task_id']
    original = manager.read('get_task', task_id=task_id)
    assert original['author'] == 'manager' and original['claim'] is None
    assert original['input_refs'] == ['im:observation:seed']
    before_reads = service.counts()
    assert manager.read('list_tasks', issue_id='A', claimed=False)['items'] == [original]
    assert manager.read('list_task_replies', task_id=task_id)['items'] == []
    assert service.counts() == before_reads
    claim = worker.write('claim_task', task_id=task_id)
    reply = worker.write('reply_task', task_id=task_id, text='The measurement failed; raw trace preserved.',
                         refs=['file:failed-trace.csv'])
    saved = manager.read('get_task', task_id=task_id)
    assert saved['claim'] == claim['claim'] and saved['instructions'] == original['instructions']
    assert reply['reply']['author'] == 'worker'
    assert manager.read('list_task_replies', task_id=task_id)['items'] == [reply['reply']]
    assert not ({'status', 'completed', 'acceptance', 'attempt', 'lease', 'run_id'} & saved.keys())
    identity = raw(service.endpoint, service.tokens['manager'], 'GET', '/v1/identity')[1]
    assert identity['modules'] == ['queue']
    evidence('http-business', {'identity': identity, 'publish': receipt, 'claim': claim, 'reply': reply,
                               'read_back': saved, 'counts': service.counts()})


def test_atomic_claim_and_restart_original_replay(service):
    manager = client(service)
    task_id = publish(manager)['task_id']
    workers = [client(service, name) for name in ('worker', 'worker2')]

    def claim(current):
        try:
            return current, current.write('claim_task', task_id=task_id)
        except ToolError as error:
            return current, error.result()

    with ThreadPoolExecutor(max_workers=2) as pool:
        attempts = list(pool.map(claim, workers))
    winners = [(current, result) for current, result in attempts if 'error' not in result]
    assert len(winners) == 1
    winner, receipt = winners[0]
    loser = [result for _, result in attempts if 'error' in result][0]
    assert loser['error']['code'] == 'already_claimed'
    assert loser['error']['effect'] == 'not_committed'
    original_service_id = service.service_id
    service.stop()
    service.start()
    assert service.service_id == original_service_id
    recovered = winner.recover(receipt['operation_id'])
    assert recovered['claim'] == receipt['claim']
    # Force the HTTP replay too, even when the local receipt is already durable.
    name = receipt['claim']['claimant']
    status, replay = raw(service.endpoint, service.tokens[name], 'POST',
                         '/v1/queue/tasks/' + task_id + '/claim', {'operation_id': receipt['operation_id']})
    assert status == 200 and replay['replayed'] and replay['claim'] == receipt['claim']
    with pytest.raises(ToolError, match='already has a claimant'):
        winner.write('claim_task', task_id=task_id)
    other = 'worker2' if name == 'worker' else 'worker'
    status, conflict = raw(service.endpoint, service.tokens[other], 'POST',
                          '/v1/queue/tasks/' + task_id + '/claim', {'operation_id': receipt['operation_id']})
    assert status == 409 and conflict['error']['code'] == 'idempotency_conflict'
    assert service.counts()['claims'] == 1
    evidence('claim-concurrency-restart', {'receipt': receipt, 'replayed': replay, 'loser': loser,
                                         'different_principal': conflict, 'counts': service.counts()})


def test_pagination_binds_filters_principal_service_and_detects_mutation(service):
    current = client(service)
    ids = [publish(current)['task_id'] for _ in range(23)]
    assert len(current.read('list_tasks')['items']) == 20
    first = current.read('list_tasks', issue_id='A', claimed=False, limit=10)
    second = current.read('list_tasks', issue_id='A', claimed=False, limit=10, cursor=first['next_cursor'])
    third = current.read('list_tasks', issue_id='A', claimed=False, limit=10, cursor=second['next_cursor'])
    assert [item['task_id'] for page in (first, second, third) for item in page['items']] == ids
    for kwargs in ({'issue_id': 'B', 'claimed': False}, {'issue_id': 'A', 'claimed': True}):
        with pytest.raises(ToolError) as bad:
            current.read('list_tasks', cursor=first['next_cursor'], **kwargs)
        assert bad.value.code == 'invalid_cursor'
    with pytest.raises(ToolError) as bad:
        client(service, 'worker').read('list_tasks', issue_id='A', claimed=False, cursor=first['next_cursor'])
    assert bad.value.code == 'invalid_cursor'
    for limit in (0, 51, -1, True):
        with pytest.raises(ToolError):
            current.read('list_tasks', limit=limit)
    with pytest.raises(ToolError) as bad:
        current.read('list_tasks', cursor='not-base64!')
    assert bad.value.code == 'invalid_cursor'
    current.write('claim_task', task_id=ids[0])
    with pytest.raises(ToolError) as changed:
        current.read('list_tasks', issue_id='A', claimed=False, cursor=first['next_cursor'])
    assert changed.value.code == 'snapshot_changed'
    for index in range(22):
        current.write('reply_task', task_id=ids[0], text=f'Observation {index}')
    replies = current.read('list_task_replies', task_id=ids[0])
    tail = current.read('list_task_replies', task_id=ids[0], cursor=replies['next_cursor'])
    assert len(replies['items']) == 20 and len(tail['items']) == 2
    assert tail['next_cursor'] is None
    with pytest.raises(ToolError):
        current.read('list_task_replies', task_id=ids[1], cursor=replies['next_cursor'])
    evidence('pagination', {'task_ids': ids, 'page_lengths': [len(p['items']) for p in (first, second, third)],
                            'reply_lengths': [len(replies['items']), len(tail['items'])],
                            'mutation_error': changed.value.result()})


@pytest.mark.parametrize('action', ['publish_task', 'claim_task', 'reply_task'])
def test_committed_lost_response_reconstructed_original_action(service, action):
    manager = client(service)
    task_id = publish(manager)['task_id']
    with DropProxy(service.endpoint) as proxy:
        journal = service.path / ('lost-' + action + '.json')
        current = ToolsClient(proxy.endpoint, service.tokens['worker'], journal)
        proxy.drop = 1
        args = {'task_id': task_id}
        if action == 'publish_task':
            args = {'issue_id': 'B', 'instructions': 'Same new contribution', 'experimenter_profile': 'experimenter'}
        elif action == 'reply_task':
            args['text'] = 'Partial result, original operation'
        before = service.counts()
        with pytest.raises(ToolError) as lost:
            current.write(action, **args)
        assert lost.value.effect == 'unknown'
        operation_id = lost.value.operation_id
        assert operation_id and len(proxy.committed) == 1
        committed = service.counts()
        # An unknown action does not block a genuine independent contribution of the same text.
        independent = None
        if action == 'publish_task':
            independent = current.write(action, **args)
            assert service.counts()['tasks'] == before['tasks'] + 2
        rebuilt = ToolsClient(proxy.endpoint, service.tokens['worker'], journal)
        recovered = rebuilt.recover(operation_id)
        assert recovered['operation_id'] == operation_id and recovered['replayed'] is True
        assert recovered == {**proxy.committed[0], 'replayed': True}
        expected = service.counts()
        assert rebuilt.recover(operation_id) == recovered and service.counts() == expected
        if independent:
            assert independent['task_id'] != recovered['task_id']
        else:
            assert expected == committed
        evidence('lost-response-' + action, {'lost': lost.value.result(), 'before': before,
                                            'after_server_commit': committed, 'recovered': recovered,
                                            'independent': independent, 'final_counts': expected})


def test_authority_validation_and_idempotency_no_partial_writes(service):
    current = client(service)
    original = publish(current)
    other_task = publish(current, 'B')['task_id']
    token = service.tokens['manager']
    before = service.counts()
    failures = []
    cases = [
        ('bad-token', 'POST', '/v1/queue/tasks', {'operation_id': 'bad', 'issue_id': 'A',
          'instructions': 'x', 'experimenter_profile': 'worker'}, 401, 'unauthorized'),
        (service.tokens['reader'], 'POST', '/v1/queue/tasks/' + original['task_id'] + '/claim',
          {'operation_id': 'denied-readonly'}, 403, 'forbidden'),
        (token, 'POST', '/v1/queue/tasks', {'operation_id': 'forged-author', 'issue_id': 'A',
          'instructions': 'x', 'experimenter_profile': 'worker', 'actor': 'admin'}, 400, 'invalid_input'),
        (token, 'POST', '/v1/queue/tasks', {'operation_id': 'bad-profile', 'issue_id': 'A',
          'instructions': 'x', 'experimenter_profile': 'cmd /c run.exe'}, 400, 'invalid_input'),
        (token, 'POST', '/v1/queue/tasks/' + original['task_id'] + '/replies',
          {'operation_id': 'huge', 'text': 'x' * 2001}, 400, 'invalid_input'),
        (token, 'GET', '/v1/queue/tasks?claimed=maybe', None, 400, 'invalid_input'),
        (token, 'GET', '/v1/queue/tasks?limit=10&limit=20', None, 400, 'invalid_input'),
        (token, 'POST', '/v1/queue/tasks', {'operation_id': original['operation_id'], 'issue_id': 'B',
          'instructions': 'changed', 'experimenter_profile': 'worker'}, 409, 'idempotency_conflict'),
    ]
    for bearer, method, path, body, expected_status, code in cases:
        status, value = raw(service.endpoint, bearer, method, path, body)
        assert status == expected_status and value['error']['code'] == code, value
        assert value['error']['effect'] == 'not_committed'
        failures.append({'path': path, 'status': status, 'response': value})
    status, wrong_identity = raw(service.endpoint, token, 'POST', '/v1/queue/tasks',
                                {'operation_id': 'wrong-service', 'issue_id': 'A',
                                 'instructions': 'x', 'experimenter_profile': 'worker'},
                                {'X-Workflow-Service-ID': 'another-service'})
    assert status == 409 and wrong_identity['error']['code'] == 'service_identity_changed'
    assert service.counts() == before
    # Original claim operation cannot be repurposed for a different existing task or action.
    claimed = current.write('claim_task', task_id=original['task_id'])
    baseline = service.counts()
    for path, body in [('/v1/queue/tasks/' + other_task + '/claim', {'operation_id': claimed['operation_id']}),
                       ('/v1/queue/tasks/' + original['task_id'] + '/replies',
                        {'operation_id': claimed['operation_id'], 'text': 'changed operation'})]:
        status, changed = raw(service.endpoint, token, 'POST', path, body)
        assert status == 409 and changed['error']['code'] == 'idempotency_conflict'
        assert service.counts() == baseline
    evidence('authority-refusals', {'failures': failures, 'wrong_identity': wrong_identity,
                                    'before': before, 'after_refusals': before,
                                    'target_action_conflict': changed, 'counts_after_claim': baseline})


def test_journal_fails_before_send_and_after_commit_without_duplicate(service, monkeypatch):
    current = client(service)
    before = service.counts()
    save = current.journal.save

    def fail_save(value):
        raise OSError('synthetic journal disk failure')

    monkeypatch.setattr(current.journal, 'save', fail_save)
    with pytest.raises(ToolError) as not_sent:
        publish(current)
    assert not_sent.value.code == 'journal_write_failed'
    assert not_sent.value.effect == 'not_committed' and service.counts() == before

    def fail_receipt(value):
        if any(action['state'] == 'confirmed' for action in value['actions'].values()):
            raise OSError('synthetic receipt persistence failure')
        save(value)

    monkeypatch.setattr(current.journal, 'save', fail_receipt)
    with pytest.raises(ToolError) as committed:
        publish(current)
    assert committed.value.effect == 'unknown'
    assert service.counts()['tasks'] == before['tasks'] + 1
    rebuilt = client(service)
    recovered = rebuilt.recover(committed.value.operation_id)
    assert recovered['replayed'] and service.counts()['tasks'] == before['tasks'] + 1
    evidence('journal-failure', {'before_send': not_sent.value.result(),
                                'after_commit': committed.value.result(), 'recovered': recovered})


def test_recovery_rejects_changed_service_endpoint_and_principal(service, tmp_path):
    with DropProxy(service.endpoint) as proxy:
        path = service.path / 'identity-journal.json'
        current = ToolsClient(proxy.endpoint, service.tokens['manager'], path)
        proxy.drop = 1
        with pytest.raises(ToolError) as unknown:
            publish(current)
        with pytest.raises(ToolError) as principal:
            ToolsClient(proxy.endpoint, service.tokens['worker'], path)
        assert principal.value.code == 'recovery_binding_changed'
        with running_service(tmp_path / 'replacement') as replacement:
            replacement.stop()
            replacement.tokens = service.tokens.copy()
            replacement.start()
            with pytest.raises(ToolError) as endpoint:
                ToolsClient(replacement.endpoint, service.tokens['manager'], path)
            assert endpoint.value.code == 'recovery_binding_changed'
            proxy.upstream = replacement.endpoint
            with pytest.raises(ToolError) as changed:
                ToolsClient(proxy.endpoint, service.tokens['manager'], path)
            assert changed.value.code == 'recovery_binding_changed'
            with pytest.raises(ToolError) as changed_existing:
                current.recover(unknown.value.operation_id)
            assert changed_existing.value.code == 'service_identity_changed'
            assert replacement.counts() == {'tasks': 0, 'claims': 0, 'replies': 0, 'receipts': 0}
        proxy.upstream = service.endpoint
        recovered = ToolsClient(proxy.endpoint, service.tokens['manager'], path).recover(unknown.value.operation_id)
        assert recovered['replayed'] and service.counts()['tasks'] == 1
        evidence('recovery-identity-refusals', {'original_unknown': unknown.value.result(),
                                              'principal': principal.value.result(),
                                              'endpoint': endpoint.value.result(),
                                              'replacement_service': changed.value.result(),
                                              'original_recovered': recovered})


def test_real_stdio_mcp_six_tools_defaults_cross_issue_and_profile(service):
    with MCP(service) as mcp:
        listed = mcp.rpc('tools/list', {})
        assert {item['name'] for item in listed['tools']} == ACTIONS
        for item in listed['tools']:
            assert not ({'operation_id', 'actor'} & item['inputSchema']['properties'].keys())
        created = mcp.call('publish_task', {'instructions': 'Default A; inspect the unresolved signal.',
                                           'experimenter_profile': 'scientist'})
        assert created['task']['issue_id'] == 'A'
        task_id = created['task_id']
        second = mcp.call('publish_task', {'issue_id': 'B', 'instructions': 'Independent B.',
                                          'experimenter_profile': 'experimenter'})
        assert second['task']['issue_id'] == 'B'
        created_c = mcp.call('publish_task', {'issue_id': 'C', 'instructions': 'New C.', 'experimenter_profile': 'worker'})
        assert created_c['task']['issue_id'] == 'C'
        default_list = mcp.call('list_tasks', {})
        explicit_b = mcp.call('list_tasks', {'issue_id': 'B'})
        assert [item['task_id'] for item in default_list['items']] == [task_id]
        assert [item['task_id'] for item in explicit_b['items']] == [second['task_id']]
        read = mcp.call('get_task', {'task_id': task_id})
        claim = mcp.call('claim_task', {'task_id': task_id})
        reply = mcp.call('reply_task', {'task_id': task_id, 'text': 'Saved a negative observation.'})
        replies = mcp.call('list_task_replies', {'task_id': task_id})
        assert replies['items'] == [reply['reply']]
        forged = mcp.call('reply_task', {'task_id': task_id, 'text': 'spoof', 'actor': 'someone'})
        assert forged['error']['code'] == 'invalid_input'
        bad_limit = mcp.call('list_tasks', {'limit': True})
        assert bad_limit['error']['code'] == 'invalid_input'
        same = mcp.call('publish_task', {'instructions': 'Default A; inspect the unresolved signal.',
                                        'experimenter_profile': 'scientist'})
        assert same['task_id'] != task_id
    profile = service.profile(tools=['get_task'])
    with MCP(service, profile=profile) as restricted:
        assert [item['name'] for item in restricted.rpc('tools/list', {})['tools']] == ['get_task']
        assert restricted.call('list_tasks', {})['error']['code'] == 'tool_not_enabled'
    profile = service.profile(tools=['reply_task', 'list_task_replies'], default_task_id=task_id)
    with MCP(service, profile=profile) as default_task:
        assert default_task.call('reply_task', {'text': 'Default task reply.'})['task_id'] == task_id
        assert len(default_task.call('list_task_replies', {})['items']) == 2
    evidence('stdio-mcp', {'tools': listed, 'default_A': created, 'explicit_B': second, 'created_C': created_c,
                           'read': read, 'claim': claim, 'reply': reply, 'replies': replies, 'forged': forged,
                           'same_text_new_action': same})


def test_mcp_next_read_preserves_default_and_filters(service):
    with MCP(service) as mcp:
        for index in range(3):
            mcp.call('publish_task', {'instructions': f'item {index}', 'experimenter_profile': 'worker'})
        first = mcp.call('list_tasks', {'claimed': False, 'limit': 1})
        continuation = first['next_read']
        assert continuation['arguments']['issue_id'] == 'A'
        assert continuation['arguments']['claimed'] is False
        assert continuation['arguments']['limit'] == 1
        second = mcp.call(continuation['tool'], continuation['arguments'])
        third = mcp.call(second['next_read']['tool'], second['next_read']['arguments'])
        assert third['next_read'] is None
        assert len({first['items'][0]['task_id'], second['items'][0]['task_id'], third['items'][0]['task_id']}) == 3
        changed = dict(continuation['arguments'], claimed=True)
        assert 'error' in mcp.call('list_tasks', changed)
        task = first['items'][0]['task_id']
        for index in range(2):
            mcp.call('reply_task', {'task_id': task, 'text': f'reply {index}'})
        replies = mcp.call('list_task_replies', {'task_id': task, 'limit': 1})
        assert replies['next_read']['arguments']['task_id'] == task
        last = mcp.call('list_task_replies', replies['next_read']['arguments'])
        assert last['next_read'] is None
        stale = mcp.call('list_tasks', {'claimed': False, 'limit': 1})
        mcp.call('publish_task', {'instructions': 'later', 'experimenter_profile': 'worker'})
        assert mcp.call('list_tasks', stale['next_read']['arguments'])['error']['code'] == 'snapshot_changed'


def test_mcp_unscoped_cursor_survives_default_change(service):
    with MCP(service) as mcp:
        for issue in ('A', 'B'):
            mcp.call('publish_task', {'issue_id': issue, 'instructions': issue, 'experimenter_profile': 'worker'})
    profile = service.profile()
    value = json.loads(profile.read_text(encoding='utf-8'))
    value.pop('default_issue_id')
    profile.write_text(json.dumps(value), encoding='utf-8')
    with MCP(service, profile=profile) as mcp:
        first = mcp.call('list_tasks', {'limit': 1})
        assert first['next_read']['arguments']['issue_id'] is None
    value['default_issue_id'] = 'A'
    profile.write_text(json.dumps(value), encoding='utf-8')
    with MCP(service, profile=profile) as mcp:
        second = mcp.call('list_tasks', first['next_read']['arguments'])
        assert {first['items'][0]['issue_id'], second['items'][0]['issue_id']} == {'A', 'B'}


def test_stdio_restart_recovers_pending_without_turning_new_call_into_replay(service):
    with DropProxy(service.endpoint) as proxy:
        journal = service.path / 'pending-mcp.json'
        current = ToolsClient(proxy.endpoint, service.tokens['manager'], journal)
        proxy.drop = 1
        with pytest.raises(ToolError) as dropped:
            publish(current)
        profile = service.profile(journal_path=str(journal), connection={'endpoint': proxy.endpoint,
                                                                        'token_env': 'MCP_QUEUE_TOKEN'})
        with MCP(service, profile=profile) as mcp:
            tasks = mcp.call('list_tasks', {})
            assert len(tasks['items']) == 1
            recovered_journal = json.loads(journal.read_text(encoding='utf-8'))
            saved = recovered_journal['actions'][dropped.value.operation_id]
            assert saved['state'] == 'confirmed' and saved['receipt']['replayed']
            new = mcp.call('publish_task', {'instructions': 'New genuine call', 'experimenter_profile': 'scientist'})
            assert new['operation_id'] != dropped.value.operation_id
        assert service.counts()['tasks'] == 2
        evidence('stdio-startup-recovery', {'recovered': saved['receipt'], 'new': new})


def test_console_help_and_transitive_dependency_boundary(service):
    command, env = command_env()
    source_python = os.environ.get('WORKFLOW_TEST_PYTHON', sys.executable)
    code = """
import json, sys
import workflow_orchestrator.tools_cli
import workflow_orchestrator.tools_http
import workflow_orchestrator.tools_mcp
import workflow_orchestrator.tools_client
for name in sys.modules:
    assert not name.startswith('issue_manager'), name
    if name.startswith('workflow_orchestrator.'):
        short = name.rsplit('.', 1)[-1]
        assert short not in {'queue_service','queue_store','queue_contracts','workflow_composition',
                              'registered_settlement','source_settlement'}, name
        assert not short.startswith('trigger'), name
print(json.dumps({'package_file': workflow_orchestrator.tools_cli.__file__,
                  'loaded': sorted(name for name in sys.modules if name.startswith('workflow_orchestrator')),
                  'source_pythonpath': __import__('os').environ.get('PYTHONPATH')}))
"""
    child = ManagedProcess([source_python, '-B', '-c', code], service.path, env, 'dependency-audit')
    try:
        result = json.loads(child.line())
        child.process.wait(timeout=10)
    finally:
        child.close()
    assert child.process.returncode == 0
    if os.environ.get('WORKFLOW_TEST_CLI'):
        assert 'site-packages' in result['package_file'].lower()
        assert result['source_pythonpath'] is None
    child = ManagedProcess(command + ['--help'], service.path, env, 'console-help')
    try:
        help_line = child.line()
        assert 'workflow-tools' in help_line
        child.process.wait(timeout=10)
    finally:
        child.close()
    evidence('entry-dependencies-' + ('installed' if os.environ.get('WORKFLOW_TEST_CLI') else 'source'), result)


def test_malformed_http_and_hidden_write_paths_leave_no_partial_rows(service):
    import http.client
    from urllib.parse import urlsplit
    remote = urlsplit(service.endpoint)
    before = service.counts()
    rejected = []
    for payload in (
        b'{"operation_id":"x","operation_id":"y"}',
        b'{"operation_id":"x","issue_id":"A","instructions":NaN,"experimenter_profile":"worker"}',
        b'[]', b'{"bad":"\\ud800"}', b'{"unterminated":',
    ):
        conn = http.client.HTTPConnection(remote.hostname, remote.port, timeout=8)
        try:
            conn.request('POST', '/v1/queue/tasks', body=payload,
                         headers={'Authorization': 'Bearer ' + service.tokens['manager'],
                                  'Content-Type': 'application/json'})
            response = conn.getresponse()
            value = json.loads(response.read())
            assert response.status == 400 and value['error']['effect'] == 'not_committed'
            rejected.append(value)
        finally:
            conn.close()
    assert service.counts() == before
    task = publish(client(service))['task_id']
    status, no_edit = raw(service.endpoint, service.tokens['manager'], 'POST', '/v1/queue/tasks/' + task,
                          {'operation_id': 'edit', 'instructions': 'replaced'})
    assert status == 404 and service.counts()['tasks'] == 1
    # Explicit C reads remain possible irrespective of the default Issue.
    c_task = publish(client(service, 'c'), issue='C')['task_id']
    for path in ('/v1/queue/tasks/' + c_task, '/v1/queue/tasks/' + c_task + '/replies'):
        status, read_c = raw(service.endpoint, service.tokens['manager'], 'GET', path)
        assert status == 200
    assert any(item['issue_id'] == 'C' for item in client(service).read('list_tasks')['items'])
    evidence('malformed-http', {'rejections': rejected, 'no_edit': no_edit, 'cross_issue_read': read_c})


def test_service_never_initializes_or_migrates_unrelated_existing_database(service):
    import hashlib
    import sqlite3
    unrelated = service.path / 'unrelated.sqlite'
    with sqlite3.connect(unrelated) as db:
        db.execute('CREATE TABLE historical_marker(value TEXT)')
        db.execute("INSERT INTO historical_marker VALUES ('preserve')")
        db.commit()
    original = hashlib.sha256(unrelated.read_bytes()).hexdigest()
    config = {**service.config, 'database_path': str(unrelated), 'listen': {'host': '127.0.0.1', 'port': 0}}
    config_path = service.path / 'unrelated-config.json'
    config_path.write_text(json.dumps(config), encoding='utf-8')
    command, env = command_env({'TEST_QUEUE_' + name.upper(): token for name, token in service.tokens.items()})
    child = ManagedProcess(command + ['serve', '--services', 'queue', '--config', str(config_path)],
                           service.path, env, 'unrelated-store-refusal')
    try:
        child.process.wait(timeout=15)
    finally:
        child.close()
    assert child.process.returncode == 1
    assert hashlib.sha256(unrelated.read_bytes()).hexdigest() == original
    result = json.loads(child.log.read_text(encoding='utf-8'))
    assert result['error']['code'] == 'schema_mismatch'
    evidence('no-migration', {'database_sha256_before_after': original, 'result': result})


def test_finite_client_reads_a_full_page_of_large_references(service):
    current = client(service)
    refs = [str(index) + ':' + 'x' * 1990 for index in range(30)]
    tasks = [current.write('publish_task', issue_id='A', instructions='Large material references',
                           input_refs=refs, experimenter_profile='worker') for _ in range(5)]
    page = current.read('list_tasks', issue_id='A')
    assert len(page['items']) == 5 and all(item['input_refs'] == refs for item in page['items'])
    for index in range(5):
        current.write('reply_task', task_id=tasks[0]['task_id'], text=str(index), refs=refs)
    replies = current.read('list_task_replies', task_id=tasks[0]['task_id'])
    assert len(replies['items']) == 5 and all(item['refs'] == refs for item in replies['items'])
    evidence('large-finite-pages', {'task_count': len(page['items']), 'reply_count': len(replies['items']),
                                   'serialized_task_bytes': len(json.dumps(page).encode()),
                                   'serialized_reply_bytes': len(json.dumps(replies).encode())})
