"""Additional bounded host failures, source authority and OS observation classification."""
from __future__ import annotations

import ctypes
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

import pytest
from board_tools_harness import BoardService
from host_tools_harness import Host, publish, wait_for
from queue_tools_harness import Service, evidence, raw
from workflow_orchestrator.host_process import observe
from workflow_orchestrator.tools_contracts import ToolError


@pytest.fixture
def queue(tmp_path):
    service = Service(tmp_path / 'queue')
    try:
        yield service
    finally:
        service.stop()


@pytest.mark.parametrize('point,mode,claims', [('before_admission', 'disk', 0),
    ('after_claim_intent', 'send_marker_disk', 0), ('before_spawn_intent', 'intent_disk', 1)])
def test_durable_failure_before_mechanical_effect(queue, tmp_path, point, mode, claims):
    with Host(tmp_path / 'host', queue, mode='hold', fault={'point': point, 'mode': mode}) as host:
        request = host.request(queue, publish(queue))
        first = host.client().launch(request)
        assert queue.counts()['claims'] == claims and host.starts() == []
        with sqlite3.connect(host.config['database_path']) as db:
            rows = [json.loads(r[0]) for r in db.execute('SELECT record FROM host_requests WHERE record IS NOT NULL')]
        if point == 'before_admission':
            assert not rows and first['outcome'] == 'unknown'
        elif point == 'after_claim_intent':
            assert rows[0]['claim']['sent'] is False
        else:
            assert rows[0]['spawn_intent'] is None
        restored = host.client().launch(request)
        assert restored['outcome'] == 'accepted'
        wait_for(lambda: len(host.starts()) == 1)
        assert queue.counts()['claims'] == 1
        host.finish(restored)
        evidence('host-durable-' + point, {'first': first, 'persisted_before_replay': rows, 'restored': restored, 'starts': host.starts()})


def test_known_createprocess_failure_retains_claim_no_redispatch(queue, tmp_path):
    with Host(tmp_path / 'host', queue, mode='hold', fault={'point': 'before_create', 'mode': 'create_failed'}) as host:
        request = host.request(queue, publish(queue))
        first = host.client().launch(request)
        assert first['outcome'] == 'accepted' and first['run']['state'] == 'failed'
        assert first['run']['phase'] == 'create_failed' and queue.counts()['claims'] == 1
        assert host.starts() == [] and host.client().status()['active_runs'] == 0
        replay = host.client().launch(request)
        assert replay['run_id'] == first['run_id'] and replay['run']['state'] == 'failed'
        assert queue.counts()['claims'] == 1
        evidence('host-known-create-failed', {'admitted_failed': first, 'same_original': replay})


def test_other_claim_same_actor_is_not_original_run(queue, tmp_path):
    task = publish(queue)
    status, claimed = raw(queue.endpoint, queue.tokens['worker'], 'POST', '/v1/queue/tasks/' + task + '/claim', {'operation_id': 'op-other-actual-claim'})
    assert status == 200
    with Host(tmp_path / 'host', queue) as host:
        request = host.request(queue, task)
        failed = host.client().launch(request)
        assert failed['outcome'] == 'accepted' and failed['run']['state'] == 'failed'
        assert failed['run']['error']['code'] == 'already_claimed'
        assert failed['run']['claim']['body']['operation_id'] != claimed['operation_id']
        assert host.starts() == [] and queue.counts()['claims'] == 1
        evidence('host-no-same-actor-takeover', {'prior': claimed, 'new_original_run': failed})


def test_source_actual_permissions_and_finite_input(queue, tmp_path):
    status, task = raw(queue.endpoint, queue.tokens['c'], 'POST', '/v1/queue/tasks', {'operation_id': 'op-outside',
        'issue_id': 'C', 'instructions': 'Outside actual source authorization.', 'experimenter_profile': 'experimenter'})
    assert status == 200
    with Host(tmp_path / 'host', queue) as host:
        denied = host.client().launch(host.request(queue, task['task_id']))
        assert denied['outcome'] == 'rejected' and denied['error']['code'] == 'source_mismatch'
        ordinary = host.request(queue, publish(queue))
        results = []
        for extra in [{'argv': ['cmd.exe']}, {'operation': 'arbitrary'}, {'conditions': {'max_active_runs': 100}}]:
            request = {**ordinary, **extra}
            status, response = raw(host.endpoint, host.tokens['caller'], 'POST', '/v1/launches', request)
            assert status == 400 and response['outcome'] == 'rejected'
            results.append(response)
        assert queue.counts()['claims'] == 0
        evidence('host-source-authority-finite', {'denied_by_source': denied, 'finite_rejections': results})


def test_unknown_os_keeps_slot_and_other_record_services_work(queue, tmp_path):
    board = BoardService(tmp_path / 'board')
    try:
        with Host(tmp_path / 'host', queue, board=board, maximum=1, mode='hold',
                  fault={'point': 'before_process_save', 'mode': 'os_unknown'}) as host:
            request = host.request(queue, publish(queue))
            accepted = host.client().launch(request)
            wait_for(lambda: len(host.starts()) == 1)
            current = wait_for(lambda: (r if (r := host.client().by_request(request['request_id']))['run']['state'] == 'unknown' else None))
            status = host.client().status()
            busy = host.client().launch(host.request(queue, publish(queue)))
            assert busy['outcome'] == 'busy' and status['active_runs'] == 1 and queue.counts()['claims'] == 1
            code, ordinary = raw(board.endpoint, board.tokens['manager'], 'POST', '/v1/board/messages',
                                  {'operation_id': 'op-unrelated-write', 'issue_id': 'A', 'text': 'Unrelated normal Board write remains available.'})
            assert code == 200
            real_identity = host.starts()[0]['identity']
            real_os = observe(real_identity['pid'], real_identity)
            assert real_os['state'] == 'running'
            evidence('host-injected-os-unknown', {'accepted': accepted, 'injected_observation': current,
                'real_os_separate': real_os, 'status': status, 'busy': busy, 'unrelated_board': ordinary})
    finally:
        board.stop()


def test_os_observation_denial_and_pid_reuse_classification(monkeypatch):
    real = observe(os.getpid())
    assert real['state'] == 'running' and real['identity']['pid'] == os.getpid()
    class Function:
        def __init__(self, fn):
            self.fn = fn
        def __call__(self, *args):
            return self.fn(*args)
    class Kernel:
        def __init__(self, denied=False):
            def open_process(*args):
                ctypes.set_last_error(5)
                return 0 if denied else 123
            def times(handle, created, *rest):
                created._obj.value = real['identity']['creation_filetime'] + 1
                return 1
            self.OpenProcess = Function(open_process)
            self.GetProcessTimes = Function(times)
            self.GetExitCodeProcess = Function(lambda *args: 1)
            self.WaitForSingleObject = Function(lambda *args: 258)
            self.CloseHandle = Function(lambda *args: 1)
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *args, **kw: Kernel(True))
    denied = observe(os.getpid(), real['identity'])
    assert denied == {'state': 'unknown', 'reason': 'open_process_failed', 'os_error': 5}
    monkeypatch.setattr(ctypes, 'WinDLL', lambda *args, **kw: Kernel())
    reused = observe(os.getpid(), real['identity'])
    assert reused['state'] == 'exited' and reused['reason'] == 'pid_reused' and reused['exit_code_known'] is False
    evidence('host-os-classification-injection', {'real_os': real, 'injected_error5': denied, 'injected_reuse': reused})


def test_host_store_replaced_and_caller_binding_changes_refused(queue, tmp_path):
    with Host(tmp_path / 'host', queue) as host:
        client = host.client()
        request = host.request(queue, publish(queue))
        first = client.launch(request)
        wait_for(lambda: len(host.starts()) == 1)
        host.stop()
        original_store = host.config['database_path']
        host.config['database_path'] = str(host.path / 'replacement.sqlite')
        host.start()
        with pytest.raises(ToolError) as changed:
            client.by_request(request['request_id'])
        assert changed.value.code == 'host_binding_changed'
        replayed = client.replay(request['request_id'])
        assert replayed['outcome'] == 'unknown' and len(host.starts()) == 1
        host.stop()
        host.config['database_path'] = original_store
        host.start()
        restored = client.by_request(request['request_id'])
        host.stop()
        original_actions = host.config['principals'][0]['actions']
        host.config['principals'][0]['actions'] = ['query']
        with pytest.raises(AssertionError):
            host.start()
        host.config['principals'][0]['actions'] = original_actions
        host.start()
        assert host.service_id == client.binding['service_id']
        evidence('host-persistent-store-and-caller-binding', {'first': first, 'replacement_query_error': changed.value.result(),
            'replacement_replay': replayed, 'restored': restored})


def test_source_store_replacement_after_lost_claim_not_adopted(queue, tmp_path):
    with Host(tmp_path / 'host', queue, mode='hold', fault={'point': 'after_claim_send', 'mode': 'crash'}) as host:
        request = host.request(queue, publish(queue))
        first = host.client().launch(request)
        wait_for(lambda: (host.path / 'fault-ready').exists())
        assert queue.counts()['claims'] == 1
        host.stop()
        queue.stop()
        original_path = queue.config['database_path']
        queue.config['database_path'] = str(queue.path / 'replacement.sqlite')
        queue.start()
        host.fault = None
        host.start()
        replayed = host.client().launch(request)
        assert replayed['outcome'] == 'accepted' and replayed['run']['state'] == 'unknown'
        assert queue.counts()['claims'] == 0 and host.starts() == [] and host.client().status()['active_runs'] == 1
        evidence('host-source-replaced-after-claim-loss', {'first': first, 'replay': replayed, 'replacement_queue': queue.counts()})
        host.stop()
        queue.stop()
        queue.config['database_path'] = original_path
        queue.start()


def test_start_conditions_rechecked_after_admission(queue, tmp_path):
    with Host(tmp_path / 'host', queue, maximum=4, mode='hold', fault={'point': 'before_spawn_intent', 'mode': 'pause'}) as host:
        request = host.request(queue, publish(queue), conditions={'idle_roles': ['scientist']})
        with ThreadPoolExecutor(2) as pool:
            future = pool.submit(host.client().launch, request)
            wait_for(lambda: (host.path / 'fault-ready').exists())
            other = host.client(suffix='-other').launch(host.request(queue, publish(queue, experimenter_profile='scientist'), role='scientist'))
            assert other['outcome'] == 'accepted'
            (host.path / 'fault-release').touch()
            waiting = future.result(15)
        assert waiting['outcome'] == 'accepted' and waiting['run']['phase'] == 'waiting_conditions'
        assert waiting['run']['spawn_intent'] is None
        assert len(host.starts()) <= 1
        host.finish(other)
        resumed = host.client().launch(request)
        assert resumed['run_id'] == waiting['run_id']
        host.finish(resumed)
        evidence('host-start-condition-recheck', {'waiting': waiting, 'intervening_scientist': other, 'same_run_later': resumed})


def test_network_refusal_preserves_original_request(queue, tmp_path):
    with Host(tmp_path / 'host', queue, mode='hold') as host:
        client = host.client()
        request = host.request(queue, publish(queue))
        # Host identity was already verified; no server during first actual request.
        host.stop()
        refused = client.launch(request)
        assert refused['outcome'] == 'rejected'  # verification GET proved no POST was sent by this call
        host.start()
        restored = client.replay(request['request_id'])
        assert restored['outcome'] == 'accepted'
        host.finish(restored)
        evidence('host-network-refusal', {'refused_before_send': refused, 'same_original_later': restored})


@pytest.mark.parametrize('failed_save', [1, 2, 3])
def test_host_client_original_local_persistence_windows(queue, tmp_path, monkeypatch, failed_save):
    with Host(tmp_path / 'host', queue, mode='hold') as host:
        request = host.request(queue, publish(queue))
        client = host.client()
        actual_save = client.journal.save
        calls = 0
        def save(value):
            nonlocal calls
            calls += 1
            if calls == failed_save:
                raise OSError('synthetic caller journal failure')
            return actual_save(value)
        monkeypatch.setattr(client.journal, 'save', save)
        if failed_save == 1:
            with pytest.raises(ToolError) as error:
                client.launch(request)
            first = error.value.result()
            assert error.value.code == 'journal_write_failed' and error.value.effect == 'not_committed'
        else:
            first = client.launch(request)
            assert first['outcome'] == 'unknown'
        if failed_save <= 2:
            assert queue.counts()['claims'] == 0 and host.starts() == []
        else:
            wait_for(lambda: len(host.starts()) == 1)
            assert queue.counts()['claims'] == 1
        monkeypatch.setattr(client.journal, 'save', actual_save)
        restored = client.launch(request)
        assert restored['outcome'] == 'accepted'
        wait_for(lambda: len(host.starts()) == 1)
        assert queue.counts()['claims'] == 1
        changed = deepcopy(request)
        changed['rule_id'] = 'changed-original-body'
        from_other_local_journal = host.client(suffix='-changed').launch(changed)
        assert from_other_local_journal['outcome'] == 'rejected'
        assert from_other_local_journal['error']['code'] == 'idempotency_conflict'
        host.finish(restored)
        evidence('host-client-disk-' + str(failed_save), {'first': first, 'same_original': restored,
                 'server_rejected_changed_original': from_other_local_journal, 'starts': host.starts()})
