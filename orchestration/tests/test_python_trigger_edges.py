"""Actual refusal, identity and original-send failure boundaries for Python tools."""
from __future__ import annotations

import json
import os
import sys

import pytest
from host_tools_harness import Host, publish, wait_for
from queue_tools_harness import evidence
from test_python_trigger import configuration, drain, run_policy, script, services
from workflow_orchestrator.listener import Listener
from workflow_orchestrator.tools_contracts import ToolError
from workflow_orchestrator.tools_journal import ActionJournal
from workflow_orchestrator.trigger_tools import TriggerTools


def test_initial_history_and_declaration_changes(tmp_path, monkeypatch):
    from test_python_trigger import board_write
    with services(tmp_path, 'board', 'queue') as src:
        old = board_write(src['board'])
        config = configuration(tmp_path, monkeypatch, src)
        t = Listener(config, tmp_path / 'state')
        t.listen('b', kind='board.message', connection='board', issue_id='A')
        drain(t)
        assert not list(t.pending('b'))
        new = board_write(src['board'])
        drain(t)
        assert [c['source']['item_id'] for c in t.pending('b')] == [new]
        t.listen('history', kind='board.message', connection='board', issue_id='A', initial='from_start')
        drain(t)
        assert {c['source']['item_id'] for c in t.pending('history')} == {old, new}
        with pytest.raises(ToolError, match='Queue requires'):
            t.listen('q', kind='queue.task', connection='queue', issue_id='A', initial='new_only')
        with pytest.raises(ToolError) as changed:
            t.listen('b', kind='board.message', connection='board', issue_id='B')
        assert changed.value.code == 'watch_binding_changed'
        monkeypatch.setenv('LISTENER_BOARD', src['board'].tokens['manager'])
        with pytest.raises(ToolError) as subject:
            t.listen('b', kind='board.message', connection='board', issue_id='A')
        assert subject.value.code == 'watch_binding_changed'
        evidence('trigger-initial-binding', {'old': old, 'new': new,
            'changed_issue': changed.value.result(), 'changed_subject': subject.value.result()})


def test_source_and_host_new_store_refuse_same_address(tmp_path, monkeypatch):
    with services(tmp_path, 'queue') as src:
        q = src['queue']
        publish(q)
        with Host(tmp_path / 'host', q, maximum=1, mode='hold') as host:
            config = configuration(tmp_path, monkeypatch, src, host)
            t = TriggerTools(config, tmp_path / 'state')
            t.listen('q', kind='queue.task', connection='queue', issue_id='A')
            drain(t)
            candidate = next(t.pending('q'))
            accepted = t.activate(candidate, host='host')
            assert accepted['outcome'] == 'accepted'
            host.finish(accepted)
            original_host = host.service_id
            host.stop()
            host.config['database_path'] = str(host.path / 'replacement.sqlite')
            host.config['runtime_path'] = str(host.path / 'replacement-sessions')
            host.start()
            refused_host = t.activate(candidate, host='host')
            assert refused_host['outcome'] == 'rejected'
            assert refused_host['error']['code'] in {'recovery_binding_changed', 'host_binding_changed'}
            assert host.service_id != original_host
            original_source = q.service_id
            q.stop()
            q.config['database_path'] = str(q.path / 'replacement.sqlite')
            q.start()
            failed_scan = t.scan_once()
            assert q.service_id != original_source
            assert any(r.get('error', {}).get('code') == 'recovery_binding_changed' for r in failed_scan)
            assert len(t.state.associations()) == 1
            evidence('trigger-replacement-refusals', {'accepted': accepted, 'host_refusal': refused_host,
                'source_refusal': failed_scan, 'original_host': original_host, 'replacement_host': host.service_id,
                'original_queue': original_source, 'replacement_queue': q.service_id})


def test_permissions_bad_issue_profile_and_frozen_action(tmp_path, monkeypatch):
    with services(tmp_path, 'queue') as src:
        q = src['queue']
        task = publish(q)
        with Host(tmp_path / 'host', q, mode='hold') as host:
            config = configuration(tmp_path, monkeypatch, src, host)
            t = TriggerTools(config, tmp_path / 'state')
            t.listen('denied', kind='queue.task', connection='queue', issue_id='C')
            scans = t.scan_once()
            assert scans[1]['watch_key'] == 'denied' and scans[1]['complete'] and scans[1]['saved'] == 0
            t.listen('q', kind='queue.task', connection='queue', issue_id='A')
            t.scan_once()
            c = next(t.pending('q'))
            with pytest.raises(ToolError) as missing_profile:
                t.activate(c, host='host', role_profile='unconfigured')
            assert missing_profile.value.code == 'invalid_input' and q.counts()['claims'] == 0
            assert t.scan_once()[0]['recoveries'] == []  # clear rejection is not automatic choice
            with pytest.raises(ToolError) as changed:
                t.activate(c, host='host', role_profile='experimenter')
            assert changed.value.code == 'invalid_input'
            allowed = t.activate(c, host='host', action_key='actual-independent-choice')
            assert allowed['outcome'] == 'accepted'
            assert len(list(t.pending('q'))) == 1  # independent action does not consume the default association
            assert not list(t.pending('q', action_key='actual-independent-choice'))
            host.finish(allowed)
            assert q.counts()['claims'] == 1
            evidence('trigger-permissions-and-frozen-action', {'task': task, 'scan_denied': scans,
                'profile_denied': missing_profile.value.result(), 'changed_body': changed.value.result(), 'allowed_explicit_action': allowed})


def test_receipt_disk_failure_and_initial_offline_are_recoverable(tmp_path, monkeypatch):
    with services(tmp_path, 'queue') as src:
        q = src['queue']
        publish(q)
        config = configuration(tmp_path, monkeypatch, src)
        t = TriggerTools(config, tmp_path / 'state')
        t.listen('q', kind='queue.task', connection='queue', issue_id='A')
        drain(t)
        c = next(t.pending('q'))
        monkeypatch.setenv('HOST_CALLER', 'synthetic-not-a-real-key')
        offline = t.activate(c, host='host')
        assert offline['outcome'] == 'rejected' and offline['request_id'] is None
        assert not t.state.associations() and len(list(t.pending('q'))) == 1
        with Host(tmp_path / 'host', q, mode='hold') as host:
            config = configuration(tmp_path, monkeypatch, src, host)
            t = TriggerTools(config, tmp_path / 'state')
            original_save = ActionJournal.save
            fired = []

            def fail_once(journal, value):
                if journal.path.parent.name == 'hosts' and not fired and any(
                        v.get('receipt', {}).get('outcome') == 'accepted' for v in value['actions'].values()):
                    fired.append(str(journal.path))
                    raise OSError('synthetic receipt disk failure')
                return original_save(journal, value)

            monkeypatch.setattr(ActionJournal, 'save', fail_once)
            unknown = t.activate(c, host='host')
            assert unknown['outcome'] == 'unknown' and fired
            restored = TriggerTools(config, tmp_path / 'state')
            recovered = restored.scan_once()[0]['recoveries'][0]
            assert recovered['outcome'] == 'accepted' and recovered['request_id'] == unknown['request_id']
            wait_for(lambda: len(host.starts()) == 1)
            assert q.counts()['claims'] == 1 and not list(restored.pending('q'))
            host.finish(recovered)
            evidence('trigger-receipt-write-failure', {'before_host': offline, 'after_real_admission': unknown,
                'recovered_no_watch': recovered, 'starts': host.starts(), 'queue_counts': q.counts()})


@pytest.mark.parametrize('mode', ['absent', 'utf8'])
def test_file_errors(tmp_path, mode):
    file = tmp_path / 'absent.py'
    if mode == 'utf8':
        file.write_bytes(b'\xff\xfe\x80')
    config = tmp_path / 'connections.json'
    config.write_text('{"connections":{}}', encoding='utf-8')
    _, error = run_policy(tmp_path, file, config, tmp_path / 'state', expected=1)
    assert str(file) in error
    assert ('UnicodeDecodeError' if mode == 'utf8' else 'FileNotFoundError') in error


def test_host_profile_permission_and_independent_board_actions(tmp_path, monkeypatch):
    from test_python_trigger import board_write
    with services(tmp_path, 'board', 'queue') as src:
        status, result = __import__('queue_tools_harness').raw(src['queue'].endpoint, src['queue'].tokens['manager'],
            'POST', '/v1/queue/tasks', {'operation_id': 'op-b', 'issue_id': 'B',
            'instructions': 'actual B source', 'experimenter_profile': 'manager'})
        assert status == 200, result
        status, denied_task = __import__('queue_tools_harness').raw(src['queue'].endpoint, src['queue'].tokens['manager'],
            'POST', '/v1/queue/tasks', {'operation_id': 'op-b-denied', 'issue_id': 'B',
            'instructions': 'profile not granted to caller', 'experimenter_profile': 'experimenter'})
        assert status == 200, denied_task
        with Host(tmp_path / 'host', **src, maximum=4, mode='zero') as host:
            config = configuration(tmp_path, monkeypatch, src, host)
            # Issue B is not an authorization boundary; this caller only has the manager profile.
            content = json.loads(config.read_text(encoding='utf-8'))
            content['connections']['host']['token_env'] = 'HOST_LIMITED'
            limited = TriggerTools(content, tmp_path / 'limited')
            limited.listen('b-task', kind='queue.task', connection='queue', issue_id='B')
            drain(limited)
            candidates = {c['record']['experimenter_profile']: c for c in limited.pending('b-task')}
            refused = limited.activate(candidates['experimenter'], host='host')
            assert refused['outcome'] == 'rejected' and refused['error']['code'] == 'forbidden'
            assert src['queue'].counts()['claims'] == 0 and not host.starts()
            allowed = limited.activate(candidates['manager'], host='host')
            assert allowed['outcome'] == 'accepted', allowed
            wait_for(lambda: len(host.starts()) == 1)
            assert host.starts()[0]['context']['source']['item_id'] == result['task_id']
            assert src['queue'].counts()['claims'] == 1
            message = board_write(src['board'])
            t = TriggerTools(config, tmp_path / 'state')
            t.listen('b', kind='board.message', connection='board', issue_id='A', initial='from_start')
            drain(t)
            c = next(t.pending('b'))
            with pytest.raises(ToolError, match='requires role_profile'):
                t.activate(c, host='host')
            first = t.activate(c, host='host', role_profile='manager')
            second = t.activate(c, host='host', role_profile='scientist', action_key='independent-scientist')
            assert first['outcome'] == second['outcome'] == 'accepted'
            assert first['run_id'] != second['run_id']
            wait_for(lambda: len(host.starts()) == 3)
            assert {row['context']['role_profile'] for row in host.starts()
                    if row['context']['source']['item_id'] == message} == {'manager', 'scientist'}
            assert not list(t.pending('b')) and not list(t.pending('b', action_key='independent-scientist'))
            assert t.activate(c, host='host', role_profile='manager')['run_id'] == first['run_id']
            assert src['queue'].counts()['claims'] == 1
            evidence('trigger-independent-actions-profile-permission', {'forbidden': refused, 'allowed_b': allowed,
                'message': message, 'manager': first, 'scientist': second, 'starts': host.starts()})


def test_lazy_listener_has_no_host_or_policy_dependencies(tmp_path):
    file = script(tmp_path, '''
import json,sys
from workflow_orchestrator.listener import Listener
t=Listener({'connections':{'host':{'token_env':'NOT_SET','endpoint':'http://127.0.0.1:1'}}},sys.argv[1])
print(json.dumps({'modules':sorted(m for m in sys.modules if m.startswith('workflow_orchestrator.'))}),flush=True)
''')
    # Use the actual selected Python installation without a workflow CLI to inspect imports.
    from queue_tools_harness import ManagedProcess
    env = os.environ.copy()
    command = [os.environ.get('WORKFLOW_TEST_PYTHON', sys.executable), '-B', str(file), str(tmp_path / 'state')]
    p = ManagedProcess(command, tmp_path, env, 'lazy-listener-audit')
    try:
        modules = json.loads(p.line())['modules']
        p.process.wait(10)
        forbidden = {'host_client', 'launch_host', 'trigger_tools', 'trigger_script', 'trigger_runner', 'workflow_composition', 'registered_workflow_host'}
        assert not {m.rsplit('.', 1)[-1] for m in modules} & forbidden
        evidence('trigger-lazy-listener-imports', {'modules': modules})
    finally:
        p.close()
