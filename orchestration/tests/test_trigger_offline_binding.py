"""R5-1: verified original admissions keep the binding and authority boundaries."""
from __future__ import annotations

from copy import deepcopy

import pytest
from host_repair_proxy import FaultProxy
from host_tools_harness import Host, publish, wait_for
from queue_tools_harness import evidence
from test_python_trigger import configuration, drain, services
from workflow_orchestrator.host_process import observe
from workflow_orchestrator.tools_contracts import ToolError
from workflow_orchestrator.trigger_tools import TriggerTools


@pytest.mark.parametrize('offline', ['host', 'source'])
def test_offline_repeat_preserves_receipt_and_changed_inputs_are_refused(tmp_path, monkeypatch, offline):
    with services(tmp_path, 'queue') as src:
        q = src['queue']
        with Host(tmp_path / 'host', q, mode='hold') as host:
            with FaultProxy(host) as gateway:
                direct = host.endpoint
                host.endpoint = gateway.endpoint
                try:
                    publish(q)
                    config = configuration(tmp_path, monkeypatch, src, host)
                    t = TriggerTools(config, tmp_path / 'state', timeout=30)
                    t.listen('q', kind='queue.task', connection='queue', issue_id='A')
                    drain(t)
                    c = next(t.pending('q'))
                    accepted = t.activate(c, host='host')
                    assert accepted['outcome'] == 'accepted'
                    wait_for(lambda: len(host.starts()) == 1)
                    original = host.client().by_request(accepted['request_id'])
                    identity = original['run']['process']['identity']
                    host.capture_workers()
                    assert observe(identity['pid'], identity)['state'] == 'running'
                    if offline == 'host':
                        host.stop()
                    else:
                        q.stop()
                    outcomes = []
                    try:
                        repeated = t.activate(c, host='host')
                        still = observe(identity['pid'], identity)
                        assert still['state'] == 'running'
                        assert repeated['outcome'] == 'accepted' and repeated['run_id'] == accepted['run_id']
                        assert repeated['request_id'] == accepted['request_id']
                        assert repeated['current_state_verified'] is False
                        assert any(e['surface'] == offline for e in repeated['verification_errors'])
                        assert t._intent(t.state.associations()[0])['receipt'] == accepted
                        for kwargs in ({'host': 'different-host'}, {'host': 'host', 'role_profile': 'manager'},
                                       {'host': 'host', 'model_profile': 'different-model'},
                                       {'host': 'host', 'conditions': {'idle_roles': ['scientist']}}):
                            with pytest.raises(ToolError) as changed:
                                t.activate(c, **kwargs)
                            assert changed.value.code == ('invalid_input' if 'role_profile' in kwargs or 'model_profile' in kwargs else 'activation_binding_changed')
                            outcomes.append(changed.value.result())
                        altered = deepcopy(c)
                        altered['source']['item_id'] = 'different-source'
                        with pytest.raises(ToolError) as changed_source:
                            t.activate(altered, host='host')
                        outcomes.append(changed_source.value.result())
                        for connection, field, value in [('queue', 'endpoint', 'http://127.0.0.1:1'),
                                                          ('queue', 'token_env', 'ALTERNATE_QUEUE_TOKEN'),
                                                          ('host', 'endpoint', 'http://127.0.0.1:1'),
                                                          ('host', 'token_env', 'ALTERNATE_HOST_TOKEN')]:
                            with monkeypatch.context() as patch:
                                if field == 'token_env':
                                    patch.setenv(value, 'synthetic-alternate')
                                patch.setitem(t.connections[connection], field, value)
                                refusal = t.activate(c, host='host')
                                assert refusal['outcome'] == 'rejected'
                                assert refusal['original_receipt']['run_id'] == accepted['run_id']
                                outcomes.append(refusal)
                        for env_name in ('LISTENER_QUEUE', 'HOST_CALLER'):
                            with monkeypatch.context() as patch:
                                patch.setenv(env_name, 'synthetic-changed-credential')
                                refusal = t.activate(c, host='host')
                                assert refusal['outcome'] == 'rejected'
                                assert refusal['original_receipt']['run_id'] == accepted['run_id']
                                outcomes.append(refusal)
                    finally:
                        if offline == 'host':
                            host.start()
                            host.endpoint = gateway.endpoint
                        else:
                            q.start()
                    restored = host.client().by_request(accepted['request_id'])
                    assert restored['run_id'] == accepted['run_id']
                    assert restored['run']['process']['identity'] == identity
                    ended = host.finish(restored)
                    posts = [e for e in gateway.events() if e['method'] == 'POST']
                    assert len(posts) == 1 and posts[0]['body']['request_id'] == accepted['request_id']
                    assert q.counts()['claims'] == 1 and len(host.starts()) == 1
                    evidence('repair-offline-input-' + offline, {'accepted': accepted, 'identity': identity,
                        'repeat': repeated, 'worker_during_offline': still, 'refusals': outcomes, 'restored': restored, 'exited': ended,
                        'http': gateway.events(), 'starts': host.starts(), 'queue_counts': q.counts()})
                finally:
                    host.endpoint = direct


@pytest.mark.parametrize('offline', ['host', 'source'])
def test_offline_check_does_not_hide_other_service_store_replacement(tmp_path, monkeypatch, offline):
    with services(tmp_path, 'queue') as src:
        q = src['queue']
        with Host(tmp_path / 'host', q, mode='hold') as host:
            publish(q)
            config = configuration(tmp_path, monkeypatch, src, host)
            t = TriggerTools(config, tmp_path / 'state', timeout=30)
            t.listen('q', kind='queue.task', connection='queue', issue_id='A')
            drain(t)
            c = next(t.pending('q'))
            accepted = t.activate(c, host='host')
            assert accepted['outcome'] == 'accepted'
            wait_for(lambda: len(host.starts()) == 1)
            host.capture_workers()
            old_queue_db = q.config['database_path']
            old_host_db, old_host_runtime = host.config['database_path'], host.config['runtime_path']
            old_source_id, old_host_id = q.service_id, host.service_id
            try:
                if offline == 'host':
                    host.stop()
                    q.stop()
                    q.config['database_path'] = str(q.path / 'replacement.sqlite')
                    q.start()
                    assert q.service_id != old_source_id
                else:
                    q.stop()
                    host.stop()
                    host.config['database_path'] = str(host.path / 'replacement.sqlite')
                    host.config['runtime_path'] = str(host.path / 'replacement-sessions')
                    host.start()
                    assert host.service_id != old_host_id
                refusal = t.activate(c, host='host')
                assert refusal['outcome'] == 'rejected'
                assert refusal['error']['code'] in {'recovery_binding_changed', 'host_binding_changed'}
                assert refusal['original_receipt']['run_id'] == accepted['run_id']
            finally:
                if offline == 'host':
                    q.stop()
                    q.config['database_path'] = old_queue_db
                    q.start()
                    host.start()
                else:
                    host.stop()
                    host.config['database_path'], host.config['runtime_path'] = old_host_db, old_host_runtime
                    host.start()
                    q.start()
            original = host.client().by_request(accepted['request_id'])
            ended = host.finish(original)
            assert len(host.starts()) == 1 and q.counts()['claims'] == 1
            evidence('repair-offline-replacement-' + offline, {'accepted': accepted, 'refusal': refusal,
                'original_after_restore': original, 'exited': ended, 'starts': host.starts(), 'queue_counts': q.counts()})


@pytest.mark.parametrize('fault', ['html503', 'malformed200', 'unauthorized', 'html403'])
def test_temporary_host_http_failure_preserves_original(tmp_path, monkeypatch, fault):
    with services(tmp_path, 'queue') as src:
        with Host(tmp_path / 'host', src['queue'], mode='hold') as host:
            with FaultProxy(host) as gateway:
                direct = host.endpoint
                host.endpoint = gateway.endpoint
                try:
                    publish(src['queue'])
                    config = configuration(tmp_path, monkeypatch, src, host)
                    t = TriggerTools(config, tmp_path / 'state', timeout=30)
                    t.listen('q', kind='queue.task', connection='queue', issue_id='A')
                    drain(t)
                    candidate = next(t.pending('q'))
                    accepted = t.activate(candidate, host='host')
                    assert accepted['outcome'] == 'accepted'
                    wait_for(lambda: len(host.starts()) == 1)
                    if fault == 'html503':
                        gateway.inject('before', 503, html=True, method='GET')
                    elif fault == 'malformed200':
                        gateway.inject('after', 200, payload='not JSON', method='GET')
                    elif fault == 'unauthorized':
                        gateway.inject('invalid_auth', method='GET')
                    else:
                        gateway.inject('before', 403, html=True, method='GET')
                    repeated = t.activate(candidate, host='host')
                    if fault in {'unauthorized', 'html403'}:
                        assert repeated['outcome'] == 'rejected'
                        assert repeated['error']['code'] == ('unauthorized' if fault == 'unauthorized' else 'invalid_response')
                        assert repeated['original_receipt']['run_id'] == accepted['run_id']
                    else:
                        assert repeated['outcome'] == 'accepted' and repeated['run_id'] == accepted['run_id']
                        assert repeated['verification_errors'][0]['error']['code'] == 'invalid_response'
                    assert repeated['current_state_verified'] is False
                    assert len([e for e in gateway.events() if e['method'] == 'POST']) == 1
                    host.finish(accepted)
                    evidence('repair-temporary-http-' + fault, {'accepted': accepted, 'repeat': repeated,
                        'http': gateway.events(), 'starts': host.starts(), 'queue_counts': src['queue'].counts()})
                finally:
                    host.endpoint = direct


def test_same_credential_reassigned_to_different_source_principal(tmp_path, monkeypatch):
    with services(tmp_path, 'queue') as src:
        q = src['queue']
        with Host(tmp_path / 'host', q, mode='hold') as host:
            publish(q)
            config = configuration(tmp_path, monkeypatch, src, host)
            t = TriggerTools(config, tmp_path / 'state', timeout=30)
            t.listen('q', kind='queue.task', connection='queue', issue_id='A')
            drain(t)
            candidate = next(t.pending('q'))
            accepted = t.activate(candidate, host='host')
            assert accepted['outcome'] == 'accepted'
            wait_for(lambda: len(host.starts()) == 1)
            host.capture_workers()
            principal = next(p for p in q.config['principals'] if p['principal_id'] == 'reader')
            original_id = q.service_id
            host.stop()
            q.stop()
            try:
                principal['principal_id'] = 'different-reader'
                q.start()
                assert q.service_id == original_id
                refused = t.activate(candidate, host='host')
                assert refused['outcome'] == 'rejected'
                assert refused['error']['code'] == 'recovery_binding_changed'
                assert refused['original_receipt']['run_id'] == accepted['run_id']
            finally:
                q.stop()
                principal['principal_id'] = 'reader'
                q.start()
                host.start()
            original = host.client().by_request(accepted['request_id'])
            ended = host.finish(original)
            assert len(host.starts()) == 1 and q.counts()['claims'] == 1
            evidence('repair-source-principal-reassigned', {'accepted': accepted, 'refusal': refused,
                'original_after_restore': original, 'exited': ended, 'starts': host.starts(),
                'queue_counts': q.counts(), 'service_id': original_id})


@pytest.mark.parametrize('fault', ['html503', 'malformed200'])
def test_temporary_source_http_failure_preserves_original(tmp_path, monkeypatch, fault):
    with services(tmp_path, 'queue', trace=True) as src:
        q = src['queue']
        with Host(tmp_path / 'host', q, mode='hold') as host:
            publish(q)
            config = configuration(tmp_path, monkeypatch, src, host)
            t = TriggerTools(config, tmp_path / 'state', timeout=30)
            t.listen('q', kind='queue.task', connection='queue', issue_id='A')
            drain(t)
            candidate = next(t.pending('q'))
            accepted = t.activate(candidate, host='host')
            assert accepted['outcome'] == 'accepted'
            wait_for(lambda: len(host.starts()) == 1)
            if fault == 'html503':
                q.gateway.inject('before', 503, html=True, method='GET')
            else:
                q.gateway.inject('after', 200, payload='not JSON', method='GET')
            repeated = t.activate(candidate, host='host')
            assert repeated['outcome'] == 'accepted' and repeated['run_id'] == accepted['run_id'], repeated
            assert repeated['current_state_verified'] is False
            assert repeated['verification_errors'][0]['surface'] == 'source'
            assert repeated['verification_errors'][0]['error']['code'] in {'invalid_input', 'invalid_response'}
            host.finish(accepted)
            assert q.counts()['claims'] == 1 and len(host.starts()) == 1
            evidence('repair-source-http-' + fault, {'accepted': accepted, 'repeat': repeated,
                'source_http': q.gateway.events(), 'starts': host.starts(), 'queue_counts': q.counts()})
