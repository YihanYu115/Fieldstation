"""Installed/public HTTP discovery and real synthetic foreground launch evidence."""
from __future__ import annotations

import json
import os
import time
from contextlib import ExitStack, contextmanager

import pytest
from board_tools_harness import BoardService
from host_repair_proxy import FaultProxy
from host_tools_harness import Host, publish, wait_for
from im_tools_harness import IMService
from queue_tools_harness import ManagedProcess, Service, command_env, evidence, raw
from workflow_orchestrator.board_client import BoardClient
from workflow_orchestrator.listener import Listener
from workflow_orchestrator.trigger_tools import TriggerTools


@contextmanager
def services(path, *names, trace=False):
    with ExitStack() as stack:
        result = {}
        for name in names:
            service = {'queue': Service, 'board': BoardService, 'im': IMService}[name](path / name)
            stack.callback(service.stop)
            if trace:
                service.gateway = stack.enter_context(FaultProxy(service))
                service.endpoint = service.gateway.endpoint
            result[name] = service
        yield result


def configuration(path, monkeypatch, sources, host=None, board_actor='worker'):
    config = {'connections': {}}
    for name, source in sources.items():
        actor = 'reader' if name in {'queue', 'im'} else board_actor
        env = 'LISTENER_' + name.upper()
        monkeypatch.setenv(env, source.tokens[actor])
        config['connections'][name] = {'endpoint': source.endpoint, 'token_env': env}
    config['connections']['host'] = {'endpoint': host.endpoint if host else 'http://127.0.0.1:1',
                                     'token_env': 'HOST_CALLER'}
    file = path / 'connections.json'
    file.write_text(json.dumps(config), encoding='utf-8')
    return file


def board_write(service, text='New information', actor='manager', recipient=None):
    status, result = raw(service.endpoint, service.tokens[actor], 'POST',
                         '/v1/board/handoffs' if recipient else '/v1/board/messages',
                         {'operation_id': 'op-' + os.urandom(12).hex(), 'issue_id': 'A', 'text': text,
                          **({'recipient': recipient} if recipient else {})})
    assert status == 200, result
    return result['message']['message_id']


def cli(path, args, *, expected=0):
    command, env = command_env()
    process = ManagedProcess(command + args, path, env, 'user-cli-' + os.urandom(4).hex())
    try:
        deadline = time.monotonic() + 40
        while process.process.poll() is None and time.monotonic() < deadline:
            process.capture_descendants()
            time.sleep(.02)
        process.process.wait(1)
        process.reader.join(5)
        output = ''.join(list(process.lines.queue))
        error = process.log.read_text(encoding='utf-8')
        assert process.process.returncode == expected, (output, error)
        return output, error
    finally:
        process.close()


def script(path, body):
    file = path / 'policy.py'
    file.write_text(body, encoding='utf-8')
    return file


def run_policy(path, file, connections, state, **kwargs):
    return cli(path, ['trigger', '--script', str(file), '--connections', str(connections), '--state', str(state)], **kwargs)


def drain(listener, limit=100):
    results = []
    for _ in range(limit):
        scans = listener.scan_once()
        results.extend(scans)
        assert not any('error' in r for r in scans), scans
        if all(r.get('complete', True) for r in scans):
            return results
    raise AssertionError('finite continuation did not finish')


def test_discover_without_host_script_and_source_writes(tmp_path, monkeypatch):
    with services(tmp_path, 'queue', 'board', 'im') as src:
        task = publish(src['queue'])
        msg = board_write(src['board'])
        packet = src['im'].tools().call('submit_field_packet', {'content': 'Negative trace; no fit.'})
        config = configuration(tmp_path, monkeypatch, src)
        monkeypatch.delenv('HOST_CALLER', raising=False)
        script(tmp_path, "raise RuntimeError('must never be imported')")
        before = {'queue': src['queue'].counts(), 'board': src['board'].counts(),
                  'packet': src['im'].client('reader').field_packet(packet['packet_id'])}
        outputs = []
        for name, kind in [('queue', 'queue.task'), ('board', 'board.message'), ('im', 'inbox.packet')]:
            outputs.append(cli(tmp_path, ['discover', '--once', '--connections', str(config),
                '--state', str(tmp_path / 'state'), '--watch', name, '--kind', kind,
                '--connection', name, '--issue', 'A', '--initial', 'from_start'])[0])
        after = {'queue': src['queue'].counts(), 'board': src['board'].counts(),
                 'packet': src['im'].client('reader').field_packet(packet['packet_id'])}
        assert before == after
        assert task in outputs[0] and msg in outputs[1] and packet['packet_id'] in outputs[2]
        evidence('trigger-discover-independent', {'before': before, 'after': after, 'outputs': outputs})


def test_queue_board_pagination_snapshot_and_recipient(tmp_path, monkeypatch):
    with services(tmp_path, 'queue', 'board', trace=True) as src:
        tasks = {publish(src['queue']) for _ in range(111)}
        messages = {board_write(src['board'], text=f'information {n}') for n in range(61)}
        incoming = board_write(src['board'], recipient='scientist')
        outgoing = board_write(src['board'], actor='worker', recipient='manager')
        config = configuration(tmp_path, monkeypatch, src)
        t = Listener(config, tmp_path / 'state', page_size=10, max_pages=1)
        for watch, kind, connection in [('q', 'queue.task', 'queue'), ('b', 'board.message', 'board'), ('h', 'board.handoff', 'board')]:
            t.listen(watch, kind=kind, connection=connection, issue_id='A', initial='from_start')
        first = t.scan_once()
        tasks.add(publish(src['queue']))  # invalidate opaque Queue snapshot
        messages.add(board_write(src['board']))  # invalidate Board snapshot
        rest = drain(t)
        assert {c['source']['item_id'] for c in t.pending('q')} == tasks
        assert {c['source']['item_id'] for c in t.pending('b')} == messages
        assert {c['source']['item_id'] for c in t.pending('h')} == {incoming}
        assert outgoing not in {c['source']['item_id'] for c in t.pending('h')}
        assert len(list(t.pending('q'))) == 112
        # Restart/redeclare must not reset cursors or forget unselected history.
        rebuilt = Listener(config, tmp_path / 'state')
        rebuilt.listen('b', kind='board.message', connection='board', issue_id='A', initial='new_only')
        drain(rebuilt)
        assert len(list(rebuilt.pending('b'))) == 62
        http = {name: source.gateway.events() for name, source in src.items()}
        assert all(any(e.get('upstream_status') == 409 for e in events) for events in http.values())
        evidence('trigger-queue-board-pages', {'first': first, 'continuations': rest,
            'queue': sorted(tasks), 'board': sorted(messages), 'incoming': incoming, 'excluded_outgoing': outgoing,
            'source_counts': {k: v.counts() for k, v in src.items()}, 'http': http})


def test_new_only_empty_baseline_and_inbox_failed_partial_crawl(tmp_path, monkeypatch):
    with services(tmp_path, 'board', 'im') as src:
        config = configuration(tmp_path, monkeypatch, src)
        t = Listener(config, tmp_path / 'state', page_size=7, max_pages=1)
        t.listen('b', kind='board.message', connection='board', issue_id='A')
        t.listen('i', kind='inbox.packet', connection='im', issue_id='A')
        drain(t)  # empty initialized baseline must survive restart
        packet_ids = {src['im'].tools().call('submit_field_packet', {'content': f'partial result {n}'})['packet_id'] for n in range(9)}
        message = board_write(src['board'])
        first = t.scan_once()
        assert len(list(t.pending('i'))) == 7
        src['im'].stop()
        failed = t.scan_once()
        assert any('error' in r and r.get('watch_key') == 'i' for r in failed)
        # The other test exercises restart through a stable public gateway.
        evidence('trigger-inbox-offline-retained', {'first': first, 'failed': failed,
            'saved_before_failure': list(t.pending('i')), 'expected_packets': sorted(packet_ids), 'message': message})


def test_inbox_multi_page_restart_review_is_not_new(tmp_path, monkeypatch):
    with services(tmp_path, 'im') as src:
        im = src['im']
        with FaultProxy(im) as proxy:
            original = im.endpoint
            im.endpoint = proxy.endpoint
            try:
                config = configuration(tmp_path, monkeypatch, src)
                t = Listener(config, tmp_path / 'state', page_size=8, max_pages=1)
                t.listen('i', kind='inbox.packet', connection='im', issue_id='A')
                drain(t)
                expected = {im.tools().call('submit_field_packet', {'content': f'negative trace {n}'})['packet_id'] for n in range(63)}
                first = t.scan_once()
                head_before = t.state.watch('i')['progress'].get('head')
                proxy.inject('before', method='GET', html=True)
                failure = t.scan_once()
                assert any('error' in r for r in failure)
                assert t.state.watch('i')['progress'].get('head') == head_before
                rebuilt = Listener(config, tmp_path / 'state', page_size=8, max_pages=1)
                rebuilt.listen('i', kind='inbox.packet', connection='im', issue_id='A')
                expected.add(im.tools().call('submit_field_packet', {'content': 'arrival during crawl'})['packet_id'])
                drain(rebuilt)
                drain(rebuilt)  # latest arrival after prior crawl is included
                found = list(rebuilt.pending('i'))
                assert {c['source']['item_id'] for c in found} == expected
                pid = found[0]['source']['item_id']
                review = im.tools('curator').call('record_field_review', {'packet_id': pid, 'handled_fact_refs': [], 'reason': 'still unresolved'})
                drain(rebuilt)
                assert len(list(rebuilt.pending('i'))) == len(expected)
                evidence('trigger-inbox-pages-restart-review', {'first': first, 'failed': failure,
                    'head_before_complete': head_before, 'found': found, 'review': review, 'http': proxy.events()})
            finally:
                im.endpoint = original


POLICY = '''
import json
def run(t):
    t.listen('q',kind='queue.task',connection='queue',issue_id='A')
    print(json.dumps(t.scan_once()),flush=True)
    for candidate in t.pending('q'):
        print(json.dumps(t.activate(candidate,host='host')),flush=True)
'''


def test_actual_python_branch_fault_restart_and_all_source_launches(tmp_path, monkeypatch):
    with services(tmp_path, 'queue', 'board', 'im', trace=True) as src:
        with Host(tmp_path / 'host', **src, mode='zero', maximum=5) as host:
            task = publish(src['queue'])
            message = board_write(src['board'])
            incoming = board_write(src['board'], recipient='scientist')
            pid = src['im'].tools().call('submit_field_packet', {'content': 'Unresolved raw trace.'})['packet_id']
            config = configuration(tmp_path, monkeypatch, src, host)
            helper = tmp_path / 'helper.py'
            helper.write_text('def choose(items, enabled):\n    return sorted(items,key=lambda c:c["source"]["item_id"]) if enabled else []\n', encoding='utf-8')
            state = tmp_path / 'state'
            policy = script(tmp_path, '''
import json
from helper import choose
def run(t):
    t.listen('q',kind='queue.task',connection='queue',issue_id='A')
    t.listen('b',kind='board.message',connection='board',issue_id='A',initial='from_start')
    t.listen('h',kind='board.handoff',connection='board',issue_id='A',initial='from_start')
    t.listen('i',kind='inbox.packet',connection='im',issue_id='A',initial='from_start')
    for scans in t.poll(every=.05):
        print(json.dumps(scans),flush=True)
        for c in choose(list(t.pending('q')), False):
            t.activate(c,host='host')
        status=t.host_status('host')
        if list(t.pending('i')) and all(status['by_role'][r]==0 for r in ('experimenter','scientist')):
            for c in choose(list(t.pending('b')), True):
                print(json.dumps(t.activate(c,host='host',role_profile='manager',conditions={'idle_roles':['experimenter','scientist']})),flush=True)
        break
''')
            first = run_policy(tmp_path, policy, config, state)[0]
            assert src['queue'].counts()['claims'] == 0
            wait_for(lambda: len(host.starts()) == 1)
            # Change ordinary Python: pending old Queue remains selectable, and partial
            # successful activation survives an unrelated script exception.
            policy.write_text(POLICY + "    raise RuntimeError('after admission')\n", encoding='utf-8')
            fault_output, fault_error = run_policy(tmp_path, policy, config, state, expected=1)
            assert 'after admission' in fault_error
            policy.write_text(POLICY + '''
    for name,kind,role in [('h','board.handoff','scientist'),('i','inbox.packet','curator')]:
        t.listen(name,kind=kind,connection='im' if name=='i' else 'board',issue_id='A',initial='from_start')
        t.scan_once()
        for candidate in t.pending(name):
            print(json.dumps(t.activate(candidate,host='host',role_profile=role)),flush=True)
''', encoding='utf-8')
            restarted = run_policy(tmp_path, policy, config, state)[0]
            wait_for(lambda: len(host.starts()) == 4)
            host.capture_workers()
            assert src['queue'].counts()['claims'] == 1
            board_reader = BoardClient(src['board'].endpoint, src['board'].tokens['worker'], tmp_path / 'check-board.json')
            assert board_reader.read('get_message', message_id=message)['purpose'] == 'information'
            assert board_reader.read('get_handoff', message_id=incoming)['status'] == 'pending'
            assert src['im'].client('reader').field_packet(pid)['curation_version'] == 0
            assert {s['context']['source']['item_id'] for s in host.starts()} == {task, message, incoming, pid}
            evidence('trigger-python-real-sources', {'first_false_branch': first, 'fault_output': fault_output,
                'fault_error': fault_error, 'restart': restarted, 'starts': host.starts(),
                'queue_counts': src['queue'].counts(), 'board_counts': src['board'].counts(),
                'source_http': {k: v.gateway.events() for k, v in src.items()}})


def test_unknown_recovers_without_selecting_and_busy_does_not(tmp_path, monkeypatch):
    with services(tmp_path, 'queue') as src:
        queue = src['queue']
        with Host(tmp_path / 'host', queue, maximum=1, mode='hold') as host:
            with FaultProxy(host) as proxy:
                direct = host.endpoint
                host.endpoint = proxy.endpoint
                try:
                    config = configuration(tmp_path, monkeypatch, src, host)
                    state = tmp_path / 'state'
                    first_task = publish(queue)
                    policy = script(tmp_path, POLICY)
                    proxy.inject('drop')
                    unknown_output = run_policy(tmp_path, policy, config, state)[0]
                    assert 'unknown' in unknown_output
                    policy.write_text('import json\ndef run(t):\n    print(json.dumps(t.scan_once()),flush=True)\n', encoding='utf-8')
                    recovered_output = run_policy(tmp_path, policy, config, state)[0]
                    t = TriggerTools(config, state)
                    original_action = t.state.associations()[0]
                    intent = t._intent(original_action)
                    assert intent['receipt']['outcome'] == 'accepted'
                    receipt = intent['receipt']
                    wait_for(lambda: len(host.starts()) == 1)
                    second_task = publish(queue)
                    policy.write_text(POLICY, encoding='utf-8')
                    busy_output = run_policy(tmp_path, policy, config, state)[0]
                    assert 'busy' in busy_output
                    host.finish(receipt)
                    policy.write_text('import json\ndef run(t):\n    print(json.dumps(t.scan_once()),flush=True)\n', encoding='utf-8')
                    false_output = run_policy(tmp_path, policy, config, state)[0]
                    assert queue.counts()['claims'] == 1 and len(host.starts()) == 1
                    policy.write_text(POLICY, encoding='utf-8')
                    selected_again = run_policy(tmp_path, policy, config, state)[0]
                    assert 'accepted' in selected_again
                    second = next(t._intent(a)['receipt'] for a in t.state.associations() if a['request_id'] != original_action['request_id'])
                    host.finish(second)
                    assert queue.counts()['claims'] == 2 and len(host.starts()) == 2
                    posts = [e for e in proxy.events() if e['method'] == 'POST']
                    assert len([e for e in posts if e['body']['request_id'] == original_action['request_id']]) == 1
                    evidence('trigger-unknown-vs-busy', {'unknown': unknown_output, 'recovered_no_watch': recovered_output,
                        'busy': busy_output, 'false_branch': false_output, 'selected_again': selected_again,
                        'tasks': [first_task, second_task], 'actions': t.state.associations(), 'http': proxy.events(),
                        'starts': host.starts(), 'queue_counts': queue.counts()})
                finally:
                    host.endpoint = direct


@pytest.mark.parametrize('body,needle', [('', 'callable run'), ('def run(:', 'SyntaxError'),
    ('import no_such_policy_dependency', 'ModuleNotFoundError'),
    ("def run(t):\n    raise RuntimeError('actual failure')", 'actual failure')])
def test_script_errors_are_not_no_work(tmp_path, body, needle):
    config = tmp_path / 'connections.json'
    config.write_text('{"connections":{}}', encoding='utf-8')
    file = script(tmp_path, body)
    _, error = run_policy(tmp_path, file, config, tmp_path / 'state', expected=1)
    assert str(file) in error and needle in error


def test_same_state_two_script_processes_one_actual_worker(tmp_path, monkeypatch):
    with services(tmp_path, 'queue') as src:
        with Host(tmp_path / 'host', src['queue'], mode='hold') as host:
            publish(src['queue'])
            config = configuration(tmp_path, monkeypatch, src, host)
            policy = script(tmp_path, POLICY)
            command, env = command_env()
            args = ['trigger', '--script', str(policy), '--connections', str(config), '--state', str(tmp_path / 'state')]
            owned = []
            try:
                for n in range(2):
                    owned.append(ManagedProcess(command + args, tmp_path, env, 'racing-script-' + str(n)))
                for p in owned:
                    while p.process.poll() is None:
                        p.capture_descendants()
                        time.sleep(.02)
                    assert p.process.returncode == 0, p.log.read_text(encoding='utf-8')
                wait_for(lambda: len(host.starts()) == 1)
                host.capture_workers()
                t = TriggerTools(config, tmp_path / 'state')
                receipt = t._intent(t.state.associations()[0])['receipt']
                assert src['queue'].counts()['claims'] == 1
                host.finish(receipt)
                evidence('trigger-two-process-one-worker', {'receipt': receipt, 'starts': host.starts(),
                    'queue_counts': src['queue'].counts(), 'script_identities': [p.identity for p in owned]})
            finally:
                for p in owned:
                    p.close()


def test_busy_retry_lost_response_removes_stale_receipt(tmp_path):
    queue = Service(tmp_path / 'queue')
    try:
        with Host(tmp_path / 'host', queue, maximum=1, mode='hold') as host:
            first = host.client().launch(host.request(queue, publish(queue)))
            with FaultProxy(host) as proxy:
                from workflow_orchestrator.host_client import HostClient
                client = HostClient({'endpoint': proxy.endpoint, 'token_env': 'HOST_CALLER'}, host.path / 'retry.json')
                request = host.request(queue, publish(queue))
                assert client.launch(request)['outcome'] == 'busy'
                host.finish(first)
                proxy.inject('drop')
                result = client.replay(request['request_id'])
                assert result['outcome'] == 'unknown'
                journal = client.journal.load()['actions'][request['request_id']]
                evidence('trigger-busy-retry-window', {'unknown': result, 'intent': journal, 'http': proxy.events()})
                assert not journal.get('receipt'), 'old busy receipt hides the second possibly admitted POST'
                accepted = client.by_request(request['request_id'])
                host.finish(accepted)
                assert len(host.starts()) == 2 and queue.counts()['claims'] == 2
    finally:
        queue.stop()
