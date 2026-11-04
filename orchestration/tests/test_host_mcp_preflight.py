"""Host checks the independently managed MCP binding before a Queue claim."""
from __future__ import annotations

import json
import socket
from urllib.parse import urlsplit

import pytest
from host_repair_proxy import FaultProxy
from host_tools_harness import Host, publish, wait_for
from queue_tools_harness import ManagedProcess, Service, command_env, evidence, raw


@pytest.fixture
def queue(tmp_path):
    service = Service(tmp_path / 'queue')
    try:
        yield service
    finally:
        service.stop()


def stop_mcp(host):
    process = host.mcp_processes.pop(0)
    args = list(process.process.args)
    process.close()
    return args


def restart_mcp(host, args):
    _, env = command_env(host.injected)
    process = ManagedProcess(args, host.path, env, 'service-mcp-restarted')
    host.mcp_processes.append(process)
    address = urlsplit(host.config['role_profiles']['experimenter']['mcp'][0]['http_url'])
    def ready():
        try:
            with socket.create_connection((address.hostname, address.port), timeout=.2):
                return True
        except OSError:
            if process.process.poll() is not None:
                raise AssertionError('restarted MCP exited')
            return False
    wait_for(ready)


@pytest.mark.parametrize('mismatch', ['endpoint', 'credential', 'tools', 'surface'])
def test_mcp_binding_mismatch_does_not_claim(queue, tmp_path, mismatch):
    other = Service(tmp_path / 'other') if mismatch == 'endpoint' else None
    try:
        def mutate(surface, profile, injected):
            if surface != 'queue':
                return profile
            profile = {**profile, 'connection': dict(profile['connection'])}
            if mismatch == 'endpoint':
                profile['connection']['endpoint'] = other.endpoint
            elif mismatch == 'credential':
                profile['connection']['token_env'] = 'MISMATCH_QUEUE_TOKEN'
                injected['MISMATCH_QUEUE_TOKEN'] = queue.tokens['worker2']
            elif mismatch == 'tools':
                profile['tools'] = ['get_task']
            else:
                profile.update(surface='board', tools=['get_message'])
            return profile
        with Host(tmp_path / 'host', queue, mode='hold', mcp_profile_mutator=mutate) as host:
            task = publish(queue)
            request = host.request(queue, task)
            result = host.client().launch(request)
            assert result['outcome'] == 'accepted', result
            expected = ('failed', 'mcp_binding_changed') if mismatch in {'endpoint', 'credential'} else ('unknown', 'mcp_unavailable')
            assert (result['run']['state'], result['run']['error']['code']) == expected, result
            assert result['run']['claim'] is None
            assert queue.counts()['claims'] == 0
            status, actual = raw(queue.endpoint, queue.tokens['manager'], 'GET', '/v1/queue/tasks/' + task)
            assert status == 200 and actual['claim'] is None
            assert not host.starts()
            evidence('preclaim-mcp-mismatch-' + mismatch, {'run': result, 'counts': queue.counts()})
    finally:
        if other:
            other.stop()


def test_matching_mcp_claims_and_starts(queue, tmp_path):
    with Host(tmp_path / 'host', queue, mode='hold') as host:
        request = host.request(queue, publish(queue))
        result = host.client().launch(request)
        wait_for(lambda: len(host.starts()) == 1)
        assert result['outcome'] == 'accepted'
        assert result['run']['claim']['receipt']
        assert queue.counts()['claims'] == 1
        status, actual = raw(queue.endpoint, queue.tokens['manager'], 'GET',
                             '/v1/queue/tasks/' + request['source']['item_id'])
        assert status == 200 and actual['claim']['claimant'] == 'worker'
        assert host.starts()[0]['context']['run_id'] == result['run_id']
        ended = host.finish(result)
        evidence('preclaim-mcp-matching', {'run': result, 'ended': ended, 'counts': queue.counts()})


def test_unavailable_mcp_continues_original_run_without_reclaim(queue, tmp_path):
    with Host(tmp_path / 'host', queue, mode='hold') as host:
        args = stop_mcp(host)
        request = host.request(queue, publish(queue))
        accepted = host.client().launch(request)
        assert accepted['outcome'] == 'accepted'
        assert accepted['run']['state'] == 'unknown'
        assert accepted['run']['error']['code'] == 'mcp_unavailable'
        assert accepted['run']['claim'] is None
        assert queue.counts()['claims'] == 0 and not host.starts()
        restart_mcp(host, args)
        wait_for(lambda: len(host.starts()) == 1, seconds=20)
        current = host.client().by_request(request['request_id'])
        assert current['run_id'] == accepted['run_id']
        assert current['run']['claim']['receipt']
        assert queue.counts()['claims'] == 1 and len(host.starts()) == 1
        ended = host.finish(current)
        evidence('preclaim-mcp-unavailable-continue', {'accepted': accepted, 'current': current,
                 'ended': ended, 'counts': queue.counts()})


def test_pending_original_claim_stays_unknown_during_mcp_binding_mismatch(queue, tmp_path):
    original_endpoint = queue.endpoint
    with FaultProxy(queue) as gateway:
        queue.endpoint = gateway.endpoint
        try:
            with Host(tmp_path / 'host', queue, mode='hold',
                      fault={'point': 'never', 'mode': 'pause', 'background_barrier': True}) as host:
                request = host.request(queue, publish(queue))
                gateway.inject('drop')
                accepted = host.client().launch(request)
                assert accepted['run']['state'] == 'unknown'
                claim = accepted['run']['claim']
                assert claim['sent'] and claim['receipt'] is None
                original_id = claim['body']['operation_id']
                assert queue.counts()['claims'] == 1 and not host.starts()
                args = stop_mcp(host)
                original_profile = host.path / 'queue-base-profile.json'
                wrong_profile = json.loads(original_profile.read_text(encoding='utf-8'))
                wrong_profile['connection']['endpoint'] = 'http://127.0.0.1:1'
                wrong_file = host.path / 'wrong-mcp-profile.json'
                wrong_file.write_text(json.dumps(wrong_profile), encoding='utf-8')
                wrong_args = list(args)
                wrong_args[wrong_args.index('--profile') + 1] = str(wrong_file)
                wrong_args[wrong_args.index('--registry') + 1] = str(host.path / 'wrong-registry.json')
                restart_mcp(host, wrong_args)
                (host.path / 'background-release').touch()
                current = wait_for(lambda: (v if ((v := host.client().by_request(request['request_id']))['run'].get('error') or {}).get('code') == 'mcp_binding_changed' else None))
                assert current['run']['state'] == 'unknown'
                assert current['run']['claim']['body']['operation_id'] == original_id
                assert current['run']['claim']['receipt'] is None
                stop_mcp(host)
                restart_mcp(host, args)
                wait_for(lambda: len(host.starts()) == 1, seconds=20)
                resumed = host.client().by_request(request['request_id'])
                assert resumed['run_id'] == accepted['run_id']
                assert resumed['run']['claim']['body']['operation_id'] == original_id
                assert resumed['run']['claim']['receipt']['replayed'] is True
                assert queue.counts()['claims'] == 1 and len(host.starts()) == 1
                ended = host.finish(resumed)
                evidence('preclaim-pending-claim-remains-unknown', {'accepted': accepted, 'mcp_down': current,
                         'resumed': resumed, 'ended': ended, 'counts': queue.counts()})
        finally:
            queue.endpoint = original_endpoint
