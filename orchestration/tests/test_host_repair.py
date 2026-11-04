"""R4 regressions: real accepted preparations progress without another activation POST."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import workflow_orchestrator.host_client as client_implementation
import workflow_orchestrator.host_http as host_implementation
from host_repair_proxy import FaultProxy
from host_tools_harness import Host, publish, wait_for
from queue_tools_harness import Service
from queue_tools_harness import evidence as save_evidence
from workflow_orchestrator.host_client import HostClient
from workflow_orchestrator.host_process import observe
from workflow_orchestrator.tools_contracts import ToolError


def evidence(name, value):
    save_evidence(name, {**value, 'client_implementation': client_implementation.__file__,
                        'host_implementation': host_implementation.__file__})


@pytest.fixture
def queue(tmp_path):
    service = Service(tmp_path / 'queue')
    try:
        yield service
    finally:
        service.stop()


def starts_for(host, run_id):
    return [row for row in host.starts() if row['context']['run_id'] == run_id]


def posts_for(proxy, request_id):
    return [row for row in proxy.events() if row['method'] == 'POST'
            and (row.get('body') or {}).get('request_id') == request_id]


def test_condition_clear_continues_without_another_host_call(queue, tmp_path):
    with Host(tmp_path / 'host', queue, maximum=4, mode='hold',
              fault={'point': 'before_spawn_intent', 'mode': 'pause'}) as host:
        direct_endpoint = host.endpoint
        with FaultProxy(host) as gateway:
            host.endpoint = gateway.endpoint
            try:
                request = host.request(queue, publish(queue), conditions={'idle_roles': ['scientist']})
                with ThreadPoolExecutor(2) as pool:
                    pending = pool.submit(host.client().launch, request)
                    wait_for(lambda: (host.path / 'fault-ready').exists())
                    other = host.client(suffix='-scientist').launch(
                        host.request(queue, publish(queue, experimenter_profile='scientist'), role='scientist'))
                    wait_for(lambda: len(starts_for(host, other['run_id'])) == 1)
                    (host.path / 'fault-release').touch()
                    accepted = pending.result(30)
                assert accepted['outcome'] == 'accepted' and accepted['run']['phase'] == 'waiting_conditions'
                assert accepted['run']['spawn_intent'] is None
                original_claim = accepted['run']['claim']['body']['operation_id']
                host.capture_workers()
                scientist_identity = starts_for(host, other['run_id'])[0]['identity']
                assert observe(scientist_identity['pid'], scientist_identity)['state'] == 'running'
                (host.session(other) / 'exit.flag').touch()
                wait_for(lambda: observe(scientist_identity['pid'], scientist_identity)['state'] == 'exited')
                # No host HTTP at all between the actual scientist exit and the next worker start.
                wait_for(lambda: len(starts_for(host, accepted['run_id'])) == 1, seconds=12)
                current = host.client().by_request(request['request_id'])
                assert current['run_id'] == accepted['run_id']
                assert current['run']['claim']['body']['operation_id'] == original_claim
                assert len(posts_for(gateway, request['request_id'])) == 1
                ended = host.finish(current)
                evidence('r4-condition-auto-continue', {'request': request, 'accepted_waiting': accepted,
                    'intervening_role_identity': scientist_identity, 'automatic_current': current, 'exited': ended,
                    'host_events': gateway.events(), 'queue_counts': queue.counts(),
                    'original_starts': starts_for(host, accepted['run_id']),
                    'no_host_http_between_condition_clear_and_worker_start': True})
            finally:
                host.endpoint = direct_endpoint


def test_claim_loss_auth_and_html_recover_automatically_original_operation(queue, tmp_path):
    original_endpoint = queue.endpoint
    with FaultProxy(queue) as source_gateway:
        queue.endpoint = source_gateway.endpoint
        try:
            with Host(tmp_path / 'host', queue, mode='hold',
                      fault={'point': 'never', 'mode': 'pause', 'background_barrier': True}) as host:
                direct_endpoint = host.endpoint
                with FaultProxy(host) as host_gateway:
                    host.endpoint = host_gateway.endpoint
                    try:
                        request = host.request(queue, publish(queue))
                        source_gateway.inject('drop')
                        accepted = host.client().launch(request)
                        assert accepted['outcome'] == 'accepted' and accepted['run']['state'] == 'unknown'
                        assert accepted['run']['claim']['receipt'] is None
                        assert queue.counts()['claims'] == 1 and not host.starts()
                        operation_id = accepted['run']['claim']['body']['operation_id']
                        source_gateway.inject('invalid_auth', repeat=True)
                        (host.path / 'background-release').touch()
                        wait_for(lambda: any(e.get('upstream_status') == 401 for e in source_gateway.events()))
                        auth_unknown = host.client().by_request(request['request_id'])
                        assert auth_unknown['run']['state'] == 'unknown' and not host.starts()
                        assert auth_unknown['run']['claim']['body']['operation_id'] == operation_id
                        source_gateway.inject('before', 503, html=True, repeat=True)
                        wait_for(lambda: any(e.get('returned_status') == 503 for e in source_gateway.events()))
                        html_unknown = host.client().by_request(request['request_id'])
                        assert html_unknown['run']['state'] == 'unknown' and not host.starts()
                        source_gateway.release()  # Source transport recovers; no activation POST follows.
                        wait_for(lambda: len(starts_for(host, accepted['run_id'])) == 1, seconds=12)
                        current = host.client().by_request(request['request_id'])
                        assert current['run_id'] == accepted['run_id']
                        assert current['run']['claim']['receipt']['replayed'] is True
                        assert current['run']['claim']['body']['operation_id'] == operation_id
                        claim_posts = [e for e in source_gateway.events() if e['method'] == 'POST' and e['path'].endswith('/claim')]
                        assert {e['body']['operation_id'] for e in claim_posts} == {operation_id}
                        assert len(posts_for(host_gateway, request['request_id'])) == 1
                        assert queue.counts()['claims'] == 1
                        ended = host.finish(current)
                        evidence('r4-claim-auto-continue', {'request': request, 'accepted_after_lost_response': accepted,
                            'auth_unknown': auth_unknown, 'html_unknown': html_unknown, 'automatic_current': current,
                            'exited': ended, 'claim_posts': claim_posts, 'host_events': host_gateway.events(),
                            'queue_counts': queue.counts(), 'starts': host.starts()})
                    finally:
                        host.endpoint = direct_endpoint
        finally:
            queue.endpoint = original_endpoint


@pytest.mark.parametrize('verification_failure', ['offline', 'drop', 'html503', 'bad_json', 'unauthorized'])
def test_prior_admission_unknown_stays_unknown_on_verification_failure(queue, tmp_path, verification_failure):
    with Host(tmp_path / 'host', queue, mode='hold') as host:
        with FaultProxy(host) as gateway:
            client = HostClient({'endpoint': gateway.endpoint, 'token_env': 'HOST_CALLER'},
                                host.path / 'original-activation.json', timeout=30)
            request = host.request(queue, publish(queue))
            gateway.inject('drop')
            first = client.launch(request)
            assert first['outcome'] == 'unknown'
            accepted = client.by_request(request['request_id'])
            wait_for(lambda: len(host.starts()) == 1)
            host.capture_workers()
            identity = accepted['run']['process']['identity']
            assert observe(identity['pid'], identity)['state'] == 'running'
            if verification_failure == 'offline':
                host.stop()
            elif verification_failure == 'drop':
                gateway.inject('drop', method='GET')
            elif verification_failure == 'html503':
                gateway.inject('before', 503, html=True, method='GET')
            elif verification_failure == 'bad_json':
                gateway.inject('after', 200, payload='not finite JSON', method='GET')
            else:
                gateway.inject('invalid_auth', method='GET')
            before = len(posts_for(gateway, request['request_id']))
            retry = client.replay(request['request_id'])
            assert retry['outcome'] == 'unknown' and retry['error']['effect'] == 'unknown', retry
            assert len(posts_for(gateway, request['request_id'])) == before
            disk = client.journal.load()['actions'][request['request_id']]
            assert disk['sent'] is True and disk['state'] == 'pending'
            assert observe(identity['pid'], identity)['state'] == 'running'
            if verification_failure == 'offline':
                host.start()
            current = client.by_request(request['request_id'])
            recovered = client.replay(request['request_id'])
            assert current['run_id'] == recovered['run_id'] == accepted['run_id']
            assert recovered['run']['process']['identity'] == identity
            assert queue.counts()['claims'] == 1 and len(host.starts()) == 1
            ended = host.finish(recovered)
            evidence('r4-verify-unknown-' + verification_failure, {'request': request, 'first': first,
                'actual_accepted_before_verification_failure': accepted, 'verification_retry': retry,
                'original_pending_journal': disk, 'current': current, 'recovered': recovered, 'exited': ended,
                'worker_identity': identity, 'host_events': gateway.events(), 'queue_counts': queue.counts()})


def test_busy_is_not_background_admitted_and_terminal_is_not_restarted(queue, tmp_path):
    with Host(tmp_path / 'host', queue, maximum=1, mode='hold') as host:
        first = host.client().launch(host.request(queue, publish(queue)))
        request = host.request(queue, publish(queue))
        busy = host.client().launch(request)
        assert busy['outcome'] == 'busy' and queue.counts()['claims'] == 1
        host.finish(first)
        time.sleep(1.5)  # Several bounded background passes; no new source/run is admitted.
        with pytest.raises(ToolError) as missing:
            host.client().by_request(request['request_id'])
        assert missing.value.code == 'not_found'
        assert queue.counts()['claims'] == 1 and len(host.starts()) == 1
        later = host.client().replay(request['request_id'])
        assert later['outcome'] == 'accepted'
        host.finish(later)
        assert len(starts_for(host, first['run_id'])) == 1
        evidence('r4-busy-and-terminal-boundaries', {'busy': busy, 'later_explicit_acceptance': later,
            'starts': host.starts(), 'queue_counts': queue.counts()})


def test_background_explicit_replays_queries_and_restart_share_original(queue, tmp_path):
    with Host(tmp_path / 'host', queue, mode='hold',
              fault={'point': 'before_claim_intent', 'mode': 'disk'}) as host:
        request = host.request(queue, publish(queue))
        accepted = host.client().launch(request)
        wait_for(lambda: (host.path / 'fault-ready').exists())
        assert accepted['outcome'] == 'accepted' and queue.counts()['claims'] == 0 and not host.starts()
        (host.path / 'fault-release').touch()
        with ThreadPoolExecutor(5) as pool:
            clients = [host.client(suffix='-race-' + str(n)) for n in range(5)]
            results = list(pool.map(lambda c: c.launch(request), clients))
        assert all(r['outcome'] == 'accepted' and r['run_id'] == accepted['run_id'] for r in results)
        wait_for(lambda: len(host.starts()) == 1)
        current = host.client().by_request(request['request_id'])
        identity = current['run']['process']['identity']
        operation = current['run']['claim']['body']['operation_id']
        host.stop()
        still = observe(identity['pid'], identity)
        assert still['state'] == 'running'
        host.start()
        after = host.client().by_request(request['request_id'])
        assert after['run']['process']['identity'] == identity
        assert after['run']['claim']['body']['operation_id'] == operation
        assert queue.counts()['claims'] == 1 and len(host.starts()) == 1
        ended = host.finish(after)
        evidence('r4-background-replay-restart', {'accepted': accepted, 'racing_replays': results,
            'before_restart': current, 'real_worker_while_host_stopped': still, 'after_restart': after,
            'exited': ended, 'starts': host.starts(), 'queue_counts': queue.counts()})


def test_definitive_post_rejection_is_not_changed_to_unknown(queue, tmp_path):
    with Host(tmp_path / 'host', queue) as host:
        request = host.request(queue, publish(queue), model_profile='unconfigured-model')
        client = host.client()
        first = client.launch(request)
        replay = client.replay(request['request_id'])
        assert first['outcome'] == replay['outcome'] == 'rejected'
        assert first['error']['code'] == replay['error']['code'] == 'profile_mismatch'
        assert first['error']['effect'] == replay['error']['effect'] == 'not_committed'
        assert queue.counts()['claims'] == 0 and not host.starts()
        evidence('r4-definitive-post-rejection', {'first': first, 'original_replay': replay, 'queue_counts': queue.counts()})
