"""Step 04 business and failure-window evidence through real HTTP and OS processes."""
from __future__ import annotations

import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

import pytest
from board_tools_harness import BoardService
from board_transport_harness import FaultProxy
from host_tools_harness import Host, publish, wait_for
from im_tools_harness import IMService
from queue_tools_harness import Service, evidence, raw
from workflow_orchestrator.host_client import HostClient
from workflow_orchestrator.host_process import observe
from workflow_orchestrator.tools_contracts import ToolError


@pytest.fixture
def queue(tmp_path):
    current = Service(tmp_path / 'queue')
    try:
        yield current
    finally:
        current.stop()


def exited(host, request):
    return wait_for(lambda: (r if (r := host.client().by_request(request['request_id']))['run']['state'] == 'exited' else None))


def test_queue_session_real_mcp_and_independent_im(queue, tmp_path):
    im = IMService(tmp_path / 'im')
    try:
        with Host(tmp_path / 'host', queue, im=im, mode='business') as host:
            task = publish(queue)
            request = host.request(queue, task)
            result = host.client().launch(request)
            assert result['outcome'] == 'accepted', result
            done = exited(host, request)
            session = host.session(result)
            outputs = json.loads((session / 'results.json').read_text(encoding='utf-8'))
            context = host.starts()[0]['context']
            assert context['task_id'] == task and context['default_issue_id'] == 'A'
            assert context['source_input']['instructions'].startswith('Measure')
            registry = json.loads((host.path / 'queue-base-owner.json').read_text(encoding='utf-8'))
            registration = registry['actions'][result['run_id'] + '-queue']['request']
            assert registration['default_task_id'] == task
            replies = raw(queue.endpoint, queue.tokens['manager'], 'GET', '/v1/queue/tasks/' + task + '/replies')[1]
            assert len(replies['items']) == 1 and replies['items'][0]['author'] == 'worker'
            assert im.tools().call('list_field_packets', {})['count'] == 1
            assert im.tools().call('list_field_packets', {'issue_id': 'B'})['count'] == 1
            assert any(r.get('error', {}).get('code') == 'permission_denied' for r in outputs)
            assert queue.counts()['claims'] == 1
            assert done['run']['observation']['exit_code'] == 0
            assert host.client().status()['active_runs'] == 0
            assert len(host.starts()) == 1
            all_bytes = b''.join(p.read_bytes() for p in session.glob('*.json'))
            assert all(token.encode() not in all_bytes for token in list(host.tokens.values()) + list(queue.tokens.values()) + list(im.tokens.values()))
            evidence('host-queue-mcp-im', {'request': request, 'accepted': result, 'exited': done, 'context': context,
                                          'outputs': outputs, 'replies': replies, 'counts': queue.counts()})
    finally:
        im.stop()


def test_replay_concurrent_original_owner_and_reconstructed_client(queue, tmp_path):
    with Host(tmp_path / 'host', queue, mode='hold') as host:
        request = host.request(queue, publish(queue))
        clients = [host.client(suffix='-' + str(n)) for n in range(6)]
        with ThreadPoolExecutor(6) as pool:
            results = list(pool.map(lambda c: c.launch(request), clients))
        evidence('host-replay-race-diagnostics', results)
        assert {r['outcome'] for r in results} == {'accepted'}, results
        assert len({r['run_id'] for r in results}) == 1
        wait_for(lambda: len(host.starts()) == 1)
        rebuilt = host.client().launch(request)
        assert rebuilt['run_id'] == results[0]['run_id']
        with pytest.raises(ToolError) as conflict:
            host.client().launch({**request, 'rule_id': 'changed'})
        assert conflict.value.code == 'idempotency_conflict'
        other = host.client('other').launch(request)
        assert other['outcome'] == 'rejected' and other['error']['code'] == 'idempotency_conflict'
        with pytest.raises(ToolError):
            host.client('other').by_request(request['request_id'])
        assert queue.counts()['claims'] == 1 and len(host.starts()) == 1
        finished = host.finish(results[0])
        evidence('host-concurrent-replay', {'request': request, 'results': results, 'rebuilt': rebuilt, 'other': other, 'exited': finished})


def test_busy_same_request_retry_and_actual_idle_roles(queue, tmp_path):
    with Host(tmp_path / 'host', queue, maximum=1, mode='hold') as host:
        first = host.request(queue, publish(queue))
        second = host.request(queue, publish(queue))
        result = host.client().launch(first)
        busy = host.client().launch(second)
        assert busy['outcome'] == 'busy' and queue.counts()['claims'] == 1
        with pytest.raises(ToolError):
            host.client().by_request(second['request_id'])
        host.finish(result)
        accepted = host.client().replay(second['request_id'])
        assert accepted['outcome'] == 'accepted' and queue.counts()['claims'] == 2
        host.finish(accepted)
        evidence('host-busy-original-retry', {'first': result, 'busy': busy, 'same_original_later': accepted})
    with Host(tmp_path / 'idle-host', queue, maximum=4, mode='hold') as host:
        scientific = publish(queue, experimenter_profile='scientist')
        first = host.request(queue, scientific, role='scientist')
        active = host.client().launch(first)
        second = host.request(queue, publish(queue), conditions={'idle_roles': ['scientist']})
        busy = host.client().launch(second)
        assert busy['outcome'] == 'busy'
        without = host.request(queue, publish(queue))
        allowed = host.client().launch(without)
        assert allowed['outcome'] == 'accepted'
        assert host.client().status()['by_role']['scientist'] == 1
        host.finish(active)
        retry = host.client().replay(second['request_id'])
        assert retry['outcome'] == 'accepted'
        host.finish(retry)
        host.finish(allowed)
        evidence('host-idle-roles', {'first': active, 'conditional_busy': busy, 'optional_no_condition': allowed, 'later': retry})


def test_capacity_transaction_race(queue, tmp_path):
    with Host(tmp_path / 'host', queue, maximum=1, mode='hold') as host:
        requests = [host.request(queue, publish(queue)) for _ in range(5)]
        clients = [host.client(suffix='-' + str(n)) for n in range(5)]
        with ThreadPoolExecutor(5) as pool:
            results = list(pool.map(lambda pair: pair[0].launch(pair[1]), zip(clients, requests)))
        evidence('host-capacity-race-diagnostics', results)
        winners = [r for r in results if r['outcome'] == 'accepted']
        assert len(winners) == 1 and sum(r['outcome'] == 'busy' for r in results) == 4
        wait_for(lambda: len(host.starts()) == 1)
        assert queue.counts()['claims'] == 1
        host.finish(winners[0])
        evidence('host-capacity-race', results)


def test_real_host_restart_keeps_same_original_worker(queue, tmp_path):
    with Host(tmp_path / 'host', queue, mode='hold') as host:
        request = host.request(queue, publish(queue))
        result = host.client().launch(request)
        wait_for(lambda: len(host.starts()) == 1)
        host.capture_workers()
        before = host.client().by_request(request['request_id'])
        identity = before['run']['process']['identity']
        assert observe(identity['pid'], identity)['state'] == 'running'
        host.stop()  # Deliberately preserves the real worker, including the installed launcher case.
        still = observe(identity['pid'], identity)
        assert still['state'] == 'running', still
        host.start()
        after = host.client().by_request(request['request_id'])
        assert after['run']['process']['identity'] == identity and after['run']['state'] == 'running'
        replayed = host.client().launch(request)
        assert replayed['run_id'] == result['run_id'] and len(host.starts()) == 1
        done = host.finish(result)
        assert done['run']['observation']['state'] == 'exited'
        evidence('host-real-restart-live-worker', {'before': before, 'while_host_stopped': still, 'after': after, 'done': done, 'starts': host.starts()})


@pytest.mark.parametrize('point,mode,expected_claims,expected_starts,recoverable', [
    ('before_claim_intent', 'disk', 0, 0, True),
    ('after_claim_intent', 'crash', 0, 0, True),
    ('after_claim_send', 'crash', 1, 0, True),
    ('before_claim_receipt', 'disk', 1, 0, True),
    ('before_spawn_intent', 'crash', 1, 0, True),
    ('after_spawn_intent', 'crash', 1, 0, False),
    ('after_create', 'crash', 1, 1, False),
    ('before_process_save', 'disk', 1, 1, False),
])
def test_real_claim_and_spawn_failure_windows(queue, tmp_path, point, mode, expected_claims, expected_starts, recoverable):
    with Host(tmp_path / 'host', queue, mode='hold', fault={'point': point, 'mode': mode}) as host:
        request = host.request(queue, publish(queue))
        result = host.client().launch(request)
        wait_for(lambda: (host.path / 'fault-ready').exists())
        assert queue.counts()['claims'] == expected_claims
        if expected_starts:
            wait_for(lambda: len(host.starts()) == expected_starts)
        assert len(host.starts()) == expected_starts
        with sqlite3.connect(host.config['database_path']) as db:
            before = json.loads(db.execute('SELECT record FROM host_requests WHERE record IS NOT NULL').fetchone()[0])
        claim_id = before['claim']['body']['operation_id'] if before['claim'] else None
        host.stop()
        host.fault = None
        host.start()
        restored = host.client().launch(request)
        assert restored['outcome'] == 'accepted' and restored['run_id'] == before['run_id']
        if recoverable:
            wait_for(lambda: len(host.starts()) == 1)
            assert queue.counts()['claims'] == 1
            current = host.client().by_request(request['request_id'])
            assert current['run']['state'] == 'running'
            if claim_id:
                assert current['run']['claim']['body']['operation_id'] == claim_id
            host.finish(restored)
        else:
            current = host.client().by_request(request['request_id'])
            assert current['run']['state'] == 'unknown'
            assert host.client().status()['active_runs'] == 1
            assert len(host.starts()) == expected_starts
            # No PID recovery by guessing the synthetic worker's self-report: product remains conservative.
        evidence('host-window-' + point, {'request': request, 'first_response': result, 'before': before, 'restored': restored,
                                          'current': current, 'starts': host.starts(), 'counts': queue.counts()})


def test_actual_claim_response_loss_original_operation(queue, tmp_path):
    with FaultProxy(queue) as proxy:
        queue_endpoint = queue.endpoint
        queue.endpoint = proxy.endpoint
        try:
            with Host(tmp_path / 'proxy-host', queue, mode='hold',
                      fault={'point': 'never', 'mode': 'pause', 'background_barrier': True}) as host:
                task = publish(queue)
                request = host.request(queue, task)
                client = host.client()
                proxy.inject('drop')
                result = client.launch(request)
                assert result['outcome'] == 'accepted' and result['run']['state'] == 'unknown'
                assert queue.counts()['claims'] == 1 and host.starts() == []
                original = result['run']['claim']['body']['operation_id']
                proxy.inject('invalid_auth')
                lost_auth = host.client().launch(request)
                assert lost_auth['run']['state'] == 'unknown' and queue.counts()['claims'] == 1
                proxy.inject('before', 503, html=True)
                temporary = host.client().launch(request)
                assert temporary['run']['state'] == 'unknown' and host.starts() == []
                recovered = host.client().launch(request)
                wait_for(lambda: len(host.starts()) == 1)
                assert recovered['run']['claim']['body']['operation_id'] == original
                assert recovered['run']['claim']['receipt']['replayed'] is True
                assert queue.counts()['claims'] == 1
                host.finish(recovered)
                posts = [e for e in proxy.events() if e['method'] == 'POST' and e['path'].endswith('/claim')]
                assert len(posts) == 4 and {p['body']['operation_id'] for p in posts} == {original}
                evidence('host-claim-http-loss', {'first': result, 'auth_after_lost_send': lost_auth, 'html503': temporary, 'restored': recovered, 'posts': posts})
        finally:
            queue.endpoint = queue_endpoint


def test_host_admission_response_loss_and_transient_client(queue, tmp_path):
    with Host(tmp_path / 'host', queue, mode='hold') as host:
        with FaultProxy(host) as proxy:
            os.environ['PROXY_HOST_TOKEN'] = host.tokens['caller']
            connection = {'endpoint': proxy.endpoint, 'token_env': 'PROXY_HOST_TOKEN'}
            client = HostClient(connection, host.path / 'proxy-client.json')
            request = host.request(queue, publish(queue))
            proxy.inject('drop')
            lost = client.launch(request)
            assert lost['outcome'] == 'unknown'
            observed = client.by_request(request['request_id'])
            proxy.inject('before', 429, html=True)
            transient = HostClient(connection, host.path / 'proxy-client.json').replay(request['request_id'])
            assert transient['outcome'] == 'unknown'
            proxy.inject('before', 503, html=True)
            html503 = client.replay(request['request_id'])
            assert html503['outcome'] == 'unknown'
            proxy.inject('invalid_auth')
            lost_auth = client.replay(request['request_id'])
            assert lost_auth['outcome'] == 'unknown'
            original = client.replay(request['request_id'])
            assert original['outcome'] == 'accepted' and original['run_id'] == observed['run_id']
            wait_for(lambda: len(host.starts()) == 1)
            assert queue.counts()['claims'] == 1
            host.finish(original)
            evidence('host-admission-response-loss', {'lost': lost, 'query': observed, 'temporary': transient, 'html503': html503, 'auth_after_lost_send': lost_auth, 'replayed': original, 'events': proxy.events()})


def test_actual_sources_and_host_authority(queue, tmp_path):
    board = BoardService(tmp_path / 'board')
    im = IMService(tmp_path / 'im')
    try:
        status, message = raw(board.endpoint, board.tokens['manager'], 'POST', '/v1/board/messages',
                              {'operation_id': 'op-note', 'issue_id': 'A', 'text': 'Ordinary unresolved information.'})
        assert status == 200
        status, handoff = raw(board.endpoint, board.tokens['manager'], 'POST', '/v1/board/handoffs',
                              {'operation_id': 'op-request', 'issue_id': 'A', 'text': 'Please inspect uncertainty.', 'recipient': 'scientist'})
        assert status == 200
        packet = im.tools().call('submit_field_packet', {'content': 'Failed source packet.'})
        before = board.counts()
        with Host(tmp_path / 'host', queue, board=board, im=im) as host:
            requests = [host.request(board, message['message']['message_id'], kind='board.message', role='manager'),
                        host.request(board, handoff['message']['message_id'], kind='board.handoff', role='scientist'),
                        host.request(im, packet['packet_id'], kind='inbox.packet', role='curator')]
            accepted = []
            for request in requests:
                response = host.client().launch(request)
                assert response['outcome'] == 'accepted', response
                accepted.append(exited(host, request))
            assert board.counts() == before
            assert im.tools().call('read_field_packet', {'packet_id': packet['packet_id']})['curation_version'] == 0
            denied = host.client('limited').launch(host.request(queue, publish(queue)))
            assert denied['outcome'] == 'rejected' and denied['error']['code'] == 'forbidden'
            wrong_issue = deepcopy(requests[0])
            wrong_issue['request_id'] = 'req-wrong-issue'
            wrong_issue['source']['issue_id'] = 'B'
            mismatch = host.client().launch(wrong_issue)
            assert mismatch['outcome'] == 'rejected' and mismatch['error']['code'] == 'source_mismatch'
            wrong_kind = deepcopy(requests[0])
            wrong_kind['request_id'] = 'req-wrong-kind'
            wrong_kind['source']['kind'] = 'board.handoff'
            kind = host.client().launch(wrong_kind)
            assert kind['outcome'] == 'rejected'
            task = publish(queue)
            mismatch_profile = host.client().launch(host.request(queue, task, role='scientist'))
            assert mismatch_profile['outcome'] == 'rejected' and mismatch_profile['error']['code'] == 'profile_mismatch'
            evidence('host-source-types-permissions', {'accepted': accepted, 'denied': denied, 'issue': mismatch,
                'kind': kind, 'profile': mismatch_profile, 'board_counts': before, 'queue': queue.counts()})
    finally:
        board.stop()
        im.stop()


@pytest.mark.parametrize('mode,expected_code', [('zero', 0), ('readonly', 0), ('failure', 3), ('omit', 0)])
def test_foreground_legal_exits_without_completion(queue, tmp_path, mode, expected_code):
    with Host(tmp_path / 'host', queue, mode=mode) as host:
        request = host.request(queue, publish(queue))
        result = host.client().launch(request)
        done = exited(host, request)
        assert done['run']['observation']['exit_code'] == expected_code
        assert host.client().status()['active_runs'] == 0 and len(host.starts()) == 1
        assert queue.counts()['claims'] == 1
        if mode in {'zero', 'readonly'}:
            assert queue.counts()['replies'] == 0
        assert 'completed' not in raw(queue.endpoint, queue.tokens['manager'], 'GET', '/v1/queue/tasks/' + request['source']['item_id'])[1]
        evidence('host-legal-exit-' + mode, {'admitted': result, 'exited': done, 'counts': queue.counts()})
