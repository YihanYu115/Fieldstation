"""R1: actual IM commits survive temporary/invalid HTTP responses with the original identity."""
from __future__ import annotations

from copy import deepcopy

import pytest
from im_tools_harness import IMMCP, IMService
from im_transport_harness import FaultProxy
from queue_tools_harness import evidence
from workflow_orchestrator.tools_contracts import ToolError


@pytest.fixture
def service(tmp_path):
    current = IMService(tmp_path / 'r1-im')
    try:
        yield current
    finally:
        current.stop()


def failed(fn):
    with pytest.raises(ToolError) as raised:
        fn()
    error = raised.value
    return error, {'http_status': error.status, **error.result()}


def submit(tools, **changes):
    return tools.call('submit_field_packet', {'content': 'Failed measurement at 20 mK. No fitted result.', **changes})


def original(client, oid):
    return deepcopy(client.status(oid)['requests'])


def verify_recovery(service, proxy, tools, oid, saved):
    rebuilt = service.tools(endpoint=proxy.endpoint)
    recovered = rebuilt.client.recover(oid)
    assert recovered['idempotent_replay'] is True
    assert rebuilt.client.status(oid)['state'] == 'confirmed'
    assert original(rebuilt.client, oid) == saved
    assert rebuilt.client.recover(oid) == recovered
    packets = rebuilt.call('list_field_packets', {})
    assert packets['count'] == 1 and packets['items'][0]['packet_id'] == recovered['packet_id']
    events = proxy.events()
    expected = saved[0]
    start = next(index for index, event in enumerate(events) if event['request_id'] == expected['request_id'])
    attempts = [event for event in events[start:] if event['method'] == 'POST'
                and event['path'] == expected['path'] and event['body'] == expected['body']]
    assert len(attempts) >= 2
    assert all(event['request_id'] == expected['request_id']
               and event['idempotency_key'] == expected['idempotency_key'] for event in attempts)
    return {'receipt': recovered, 'state': rebuilt.client.status(oid), 'packets': packets, 'events': events}


@pytest.mark.parametrize('status', [408, 425, 429, 502, 503])
def test_committed_then_transient_http_remains_recoverable(service, status):
    with FaultProxy(service) as proxy:
        tools = service.tools(endpoint=proxy.endpoint)
        proxy.inject('after', status, html=status == 503)
        error, diagnostic = failed(lambda: submit(tools))
        oid = error.operation_id
        saved = original(tools.client, oid)
        state = tools.client.status(oid)
        events = proxy.events()
        assert events[-1]['forwarded'] and events[-1]['upstream_status'] == 200
        evidence('r1-committed-' + str(status) + '-initial', {'error': diagnostic, 'state': state, 'events': events})
        assert error.effect == 'unknown' and state['state'] == 'pending'
        assert error.code != 'invalid_input'
        result = verify_recovery(service, proxy, tools, oid, saved)
        evidence('r1-committed-' + str(status), {'initial': diagnostic, **result})


@pytest.mark.parametrize('status', [408, 425, 429, 503])
def test_prior_unknown_then_gateway_before_retry_keeps_original(service, status):
    with FaultProxy(service) as proxy:
        tools = service.tools(endpoint=proxy.endpoint)
        proxy.inject('drop')
        first, first_diagnostic = failed(lambda: submit(tools))
        oid = first.operation_id
        saved = original(tools.client, oid)
        rebuilt = service.tools(endpoint=proxy.endpoint)
        proxy.inject('before', status, html=status == 503)
        retry, retry_diagnostic = failed(lambda: rebuilt.client.recover(oid))
        state = rebuilt.client.status(oid)
        events = proxy.events()
        evidence('r1-prior-unknown-' + str(status) + '-initial', {
            'first': first_diagnostic, 'retry': retry_diagnostic, 'state': state, 'events': events})
        assert events[-1]['forwarded'] is False
        assert retry.effect == 'unknown' and retry.code != 'invalid_input' and state['state'] == 'pending'
        assert retry.operation_id == oid and original(rebuilt.client, oid) == saved
        result = verify_recovery(service, proxy, rebuilt, oid, saved)
        evidence('r1-prior-unknown-' + str(status), {'first': first_diagnostic, 'retry': retry_diagnostic, **result})


@pytest.mark.parametrize(('tool', 'status', 'html'), [('curate_field_item', 429, False), ('record_field_review', 503, True)])
def test_curation_review_unknown_transient_recovery_is_unique(service, tool, status, html):
    with FaultProxy(service) as proxy:
        pid = submit(service.tools(endpoint=proxy.endpoint))['packet_id']
        curator = service.tools('curator', endpoint=proxy.endpoint)
        arguments = {'packet_id': pid, 'kind': 'observation', 'description': 'The failed measurement has no fitted result.',
                     'origin': {'type': 'packet_text', 'quoted_text': 'No fitted result.'}, 'reason': 'Keep the negative result.'}
        if tool == 'record_field_review':
            fact = curator.call('curate_field_item', arguments)
            arguments = {'packet_id': pid, 'handled_fact_refs': [fact['fact_ref']], 'unresolved': [],
                         'reason': 'Reviewed only this actual synthetic fact.'}
        proxy.inject('drop')
        first, first_diag = failed(lambda: curator.call(tool, arguments))
        oid = first.operation_id
        saved = original(curator.client, oid)
        proxy.inject('before', status, html=html)
        rebuilt = service.tools('curator', endpoint=proxy.endpoint)
        retry, retry_diag = failed(lambda: rebuilt.client.recover(oid))
        assert retry.effect == 'unknown' and rebuilt.client.status(oid)['state'] == 'pending'
        recovered = rebuilt.client.recover(oid)
        assert original(rebuilt.client, oid) == saved
        assert recovered['idempotent_replay'] is True and rebuilt.client.recover(oid) == recovered
        facts = rebuilt.call('list_curated_field_items', {'packet_id': pid})
        reviews = rebuilt.call('list_field_reviews', {'packet_id': pid})
        assert len(facts['items']) == 1
        assert len(reviews['items']) == (1 if tool == 'record_field_review' else 0)
        fact_read = rebuilt.call('read_field_fact', {'packet_id': pid, 'fact_ref': facts['items'][0]['fact_ref']})
        assert fact_read['mapping']['evidence_id'] == facts['items'][0]['mapping']['evidence_id']
        evidence('r1-' + tool, {'first': first_diag, 'retry': retry_diag, 'original_requests': saved,
            'recovered': recovered, 'facts': facts, 'reviews': reviews, 'fact': fact_read, 'events': proxy.events()})


def test_first_authority_refusals_remain_definitive_and_prior_auth_unknown(service):
    with FaultProxy(service) as proxy:
        denied = service.tools('reader', endpoint=proxy.endpoint)
        permission, permission_diag = failed(lambda: submit(denied))
        assert permission.code == 'permission_denied' and permission.effect == 'not_committed'
        assert denied.client.status(permission.operation_id)['state'] == 'rejected'
        good = service.tools(endpoint=proxy.endpoint)
        oid = good.client.begin('submit_field_packet', '/v1/field-packets', {'issue_id': 'A', 'content': ''})
        validation, validation_diag = failed(lambda: good.client.recover(oid))
        assert validation.code == 'validation_error' and validation.effect == 'not_committed'
        assert good.client.status(oid)['state'] == 'rejected'
        cached, cached_diag = failed(lambda: good.client.recover(oid))
        assert cached.code == validation.code and cached.effect == 'not_committed'
        assert cached_diag['error']['details'] == validation_diag['error']['details']
        assert good.call('list_field_packets', {})['count'] == 0
        proxy.inject('drop')
        lost, lost_diag = failed(lambda: submit(good))
        saved = original(good.client, lost.operation_id)
        # Corrupt only this test gateway's retry header; real IM rejects its authentication.
        # The original product endpoint/credential binding and journal are unchanged.
        proxy.inject('invalid_auth', 403)
        auth, auth_diag = failed(lambda: good.client.recover(lost.operation_id))
        assert auth.effect == 'unknown' and auth.code == 'permission_denied'
        assert good.client.status(lost.operation_id)['state'] == 'pending'
        recovered = verify_recovery(service, proxy, good, lost.operation_id, saved)
        evidence('r1-authority-refusals', {'permission': permission_diag, 'validation': validation_diag,
            'lost': lost_diag, 'authority_auth_403': auth_diag, **recovered})


@pytest.mark.parametrize('status', [408, 425, 429, 503])
def test_get_gateway_failure_does_not_create_write_intent(service, status):
    with FaultProxy(service) as proxy:
        tools = service.tools(endpoint=proxy.endpoint)
        before = tools.client.journal.load()
        proxy.inject('before', status, html=status == 503, method='GET')
        error, diagnostic = failed(lambda: tools.call('list_field_packets', {}))
        assert error.effect == 'not_committed' and error.code != 'invalid_input'
        assert tools.client.journal.load() == before
        evidence('r1-read-' + str(status), {'error': diagnostic, 'events': proxy.events(), 'actions': before['actions']})


def test_mcp_rebuild_temp_failure_and_new_independent_calls(service):
    with FaultProxy(service) as proxy:
        profile = service.profile(endpoint=proxy.endpoint)
        with IMMCP(service, profile=profile) as first:
            proxy.inject('drop')
            unknown = first.call('submit_field_packet', {'content': 'Same text can be a new contribution.'})
            oid = unknown['error']['operation_id']
        proxy.inject('before', 429)
        with IMMCP(service, profile=profile) as rebuilt:
            state = rebuilt.call('get_delivery_status', {'delivery_id': oid})
            assert state['state'] == 'pending'
            b = rebuilt.call('submit_field_packet', {'issue_id': 'B', 'content': 'Independent B while A is unknown.'})
            recovered = rebuilt.call('recover_delivery', {'delivery_id': oid})
            fresh = rebuilt.call('submit_field_packet', {'content': 'Same text can be a new contribution.'})
            assert b['packet_id'] != recovered['packet_id'] != fresh['packet_id']
            assert rebuilt.call('list_field_packets', {})['count'] == 2
            assert rebuilt.call('list_field_packets', {'issue_id': 'B'})['count'] == 1
            assert rebuilt.call('get_delivery_status', {'delivery_id': oid})['requests'] == state['requests']
        evidence('r1-mcp-rebuild', {'unknown': unknown, 'state_after_startup_429': state,
            'b': b, 'recovered': recovered, 'fresh': fresh, 'events': proxy.events(),
            'client_module': __import__('workflow_orchestrator.im_client', fromlist=['']).__file__})



@pytest.mark.parametrize(('status', 'payload'), [
    (400, '[]'), (400, '{"error": 42, "message": "Gateway response"}'),
    (400, '{"error": "gateway_without_message"}'),
    (200, '<html>Invalid success response</html>'), (200, '{"result": null}'),
])
def test_unrecognized_responses_cannot_close_a_committed_action(service, status, payload):
    with FaultProxy(service) as proxy:
        tools = service.tools(endpoint=proxy.endpoint)
        proxy.inject('after', status, payload=payload)
        error, diagnostic = failed(lambda: submit(tools))
        oid = error.operation_id
        assert error.code == 'invalid_response' and error.effect == 'unknown'
        assert tools.client.status(oid)['state'] == 'pending'
        result = verify_recovery(service, proxy, tools, oid, original(tools.client, oid))
        evidence('r1-unrecognized-' + str(status) + '-' + str(len(payload)), {'error': diagnostic, **result})
