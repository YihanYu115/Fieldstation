"""Direct split through a real Streamable HTTP MCP and public IM HTTP."""
import asyncio
import json

import pytest
from im_tools_harness import IMService
from queue_tools_harness import DropProxy
from test_http_mcp_core import call, client, http_mcp, register
from workflow_orchestrator.im_client import IMClient
from workflow_orchestrator.mcp_sessions import session_token
from workflow_orchestrator.tools_contracts import ToolError

from issue_manager import IssueManager


def test_direct_split_http_mcp_and_formal_origin(tmp_path):
    service = IMService(tmp_path / 'im')
    try:
        sender = service.tools('experimenter')
        packet = sender.call('submit_field_packet', {'content': 'Count 13 and method result.'})
        tools = service.tools('curator')
        fact = tools.call('curate_field_item', {'packet_id': packet['packet_id'], 'kind': 'observation',
            'description': 'Count 13 and method result.', 'origin': {'type': 'packet_text',
            'quoted_text': 'Count 13 and method result.'}, 'reason': 'Synthetic source.'})
        correction = tools.call('save_contribution', {'kind': 'observation', 'source': 'urn:correction',
            'text': 'Count is 14', 'reason': 'Synthetic correction.'})
        provider = tools.call('save_contribution', {'kind': 'observation', 'source': 'urn:method-input',
            'text': 'Method input', 'reason': 'Synthetic input.'})['evidence']['evidence_id']
        old = tools.call('create_relation', {'source_evidence_id': correction['evidence']['evidence_id'],
            'target_evidence_id': fact['evidence_id'], 'relation_type': 'refutes', 'rationale': 'Count only.'})
        names = ['split_evidence', 'read_split_origins', 'read_evidence_neighbors']
        profile = service.profile('curator', tools=names, suffix='-direct-http')
        with http_mcp(service, profile, service.tokens['curator'], service.path) as (base, _):
            async def run():
                async with client(base + '/mcp') as mcp:
                    assert {tool.name for tool in (await mcp.list_tools()).tools} == set(names)
                    result = await call(mcp, 'split_evidence', {'source_evidence_id': fact['evidence_id'],
                        'parts': [{'issue_id': 'A', 'kind': 'observation', 'text': 'Count 13'},
                                  {'issue_id': 'A', 'kind': 'interpretation', 'text': 'Method result'}],
                        'relation_decisions': [{'relation_id': old['relation_id'], 'action': 'replace',
                                                'part_index': 0, 'reason': 'Count only'}],
                        'new_relations': [{'issue_id': 'A', 'source': {'part_index': 1},
                            'target': {'evidence_id': provider}, 'relation_type': 'depends_on',
                            'rationale': 'The method result needs this input.'}]})
                    assert len(result['parts']) == 2, result
                    assert result['relations_created'][0]['target_evidence_id'] == result['parts'][0]['evidence_id']
                    assert result['relations_created'][1]['target_evidence_id'] == provider
                    child = await call(mcp, 'read_split_origins', {'evidence_id': result['parts'][0]['evidence_id']})
                    assert child['items'][0]['evidence_id'] == fact['evidence_id']
                    assert child['items'][0]['source_binding']['evidence_id'] == fact['evidence_id']
                    assert child['items'][0]['source_binding_current'] is True
                    parent = await call(mcp, 'read_split_origins', {'evidence_id': fact['evidence_id']})
                    mapping = next(item for item in parent['items'] if item['kind'] == 'field_mapping')
                    assert (mapping['packet_id'], mapping['fact_ref']) == (packet['packet_id'], fact['fact_ref'])
            asyncio.run(run())
    finally:
        service.stop()


def test_lost_split_response_recovers_same_action(tmp_path):
    service = IMService(tmp_path / 'im')
    try:
        with DropProxy(service.endpoint) as proxy:
            tools = service.tools('curator', endpoint=proxy.endpoint)
            source = tools.call('save_contribution', {'kind': 'observation', 'source': 'urn:split:lost',
                'text': 'Two independent facts', 'reason': 'Synthetic'})['evidence']['evidence_id']
            args = {'source_evidence_id': source, 'parts': [
                {'issue_id': 'A', 'kind': 'observation', 'text': 'First'},
                {'issue_id': 'B', 'kind': 'interpretation', 'text': 'Second'}]}
            proxy.drop = 1
            try:
                tools.call('split_evidence', args)
            except ToolError as exc:
                assert exc.effect == 'unknown'
                delivery = exc.operation_id
            else:
                raise AssertionError('Expected lost response')
            other = tools.call('save_contribution', {'kind': 'observation', 'source': 'urn:unrelated',
                'text': 'Independent', 'reason': 'Synthetic'})
            recovered = service.tools('curator', endpoint=proxy.endpoint).client.recover(delivery)
            assert recovered['idempotent_replay'] is True
            assert len(recovered['parts']) == 2 and other['evidence']['evidence_id'] != source
    finally:
        service.stop()


def test_split_permissions_no_default_and_currentness(tmp_path):
    service = IMService(tmp_path / 'im')
    try:
        curator = service.tools('curator')
        source = curator.call('save_contribution', {'kind': 'observation', 'source': 'urn:currentness',
            'text': 'First and second', 'reason': 'Synthetic'})['evidence']['evidence_id']
        provider = curator.call('save_contribution', {'kind': 'observation', 'source': 'urn:required-input',
            'text': 'Required input', 'reason': 'Synthetic'})['evidence']['evidence_id']
        dependency = curator.call('create_relation', {'source_evidence_id': source,
            'target_evidence_id': provider, 'relation_type': 'depends_on', 'rationale': 'Necessary input'})
        conclusion = curator.call('save_working_conclusion', {'statement': 'Synthetic conclusion',
            'evidence_ids': [source], 'reason': 'Observed source', 'confidence': 'low'})
        assert conclusion['conclusion_id']
        args = {'source_evidence_id': source, 'parts': [
            {'issue_id': 'A', 'kind': 'observation', 'text': 'First'},
            {'issue_id': 'B', 'kind': 'observation', 'text': 'Second'}],
            'relation_decisions': [{'relation_id': dependency['relation_id'], 'action': 'replace',
                                    'part_index': 0, 'reason': 'Only the first part requires the input'}]}
        with pytest.raises(ToolError) as denied:
            service.tools('reader').call('split_evidence', args)
        assert denied.value.code == 'permission_denied'
        with pytest.raises(ToolError) as denied_relation:
            service.tools('no-relations').call('split_evidence', args)
        assert denied_relation.value.code == 'permission_denied'
        profile = service.profile('curator', tools=['split_evidence', 'inspect_issue'], suffix='-no-default')
        profile.pop('default_issue_id')
        with http_mcp(service, profile, service.tokens['curator'], service.path) as (base, _):
            async def run():
                async with client(base + '/mcp') as mcp:
                    unchanged = await call(mcp, 'split_evidence', {**args, 'relation_decisions': []})
                    assert len(unchanged['parts']) == 2, unchanged
                    before_change = await call(mcp, 'inspect_issue', {'issue_id': 'A'})
                    assert before_change['current_conclusion']['currentness']['currentness'] == 'current'
                    result = await call(mcp, 'split_evidence', args)
                    assert len(result['parts']) == 2, result
                    inspected = await call(mcp, 'inspect_issue', {'issue_id': 'A'})
                    assert inspected['issue']['current_conclusion_id'] == conclusion['conclusion_id']
                    assert inspected['current_conclusion']['currentness']['currentness'] == 'needs_update', inspected
            asyncio.run(run())
    finally:
        service.stop()


def test_split_receipt_journal_failure_recovers_frozen_original(tmp_path, monkeypatch):
    service = IMService(tmp_path / 'im')
    try:
        source = service.tools('curator').call('save_contribution', {
            'kind': 'observation', 'source': 'urn:journal-split', 'text': 'Two findings',
            'reason': 'Synthetic'})['evidence']['evidence_id']
        tools = service.tools('curator', suffix='-split-journal')
        real_save = tools.client.journal.save
        def fail_receipt(value):
            if any('result' in step for action in value['actions'].values() for step in action['steps']):
                raise OSError('synthetic receipt write failure')
            real_save(value)
        monkeypatch.setattr(tools.client.journal, 'save', fail_receipt)
        with pytest.raises(ToolError) as lost:
            tools.call('split_evidence', {'source_evidence_id': source, 'parts': [
                {'issue_id': 'A', 'kind': 'observation', 'text': 'One'},
                {'issue_id': 'B', 'kind': 'interpretation', 'text': 'Two'}]})
        assert lost.value.effect == 'unknown'
        delivery = lost.value.operation_id
        monkeypatch.setattr(tools.client.journal, 'save', real_save)
        old = tools.client.status(delivery)
        with pytest.raises(ToolError) as changed:
            IMClient(service.endpoint, service.tokens['reader'], tools.client.journal.path,
                     token_env='MCP_QUEUE_TOKEN')
        assert changed.value.code == 'recovery_binding_changed'
        restarted = service.tools('curator', suffix='-split-journal')
        recovered = restarted.client.recover(delivery)
        assert recovered['idempotent_replay'] is True
        assert restarted.client.status(delivery)['requests'] == old['requests']
        assert len(recovered['parts']) == 2
    finally:
        service.stop()


def test_platform_mcp_cannot_learn_unreadable_neighbor_identity(tmp_path):
    service = IMService(tmp_path / 'im')
    service.stop()
    manager = IssueManager(service.ledger)
    try:
        maintenance = manager.credentials.path_for('maintenance-agent')
        manager.evidence.register_platform('external-split', display_name='External', capabilities=['manifest'],
                                           credential=maintenance)
        manager.credentials.issue_actor(actor_id='external-split-agent', actor_kind='experiment_agent',
            platform_id='external-split', capabilities={'context.read', 'evidence.write', 'evidence.relation.write',
                                                       'evidence.manifest.submit'}, maintenance_credential=maintenance)
        token = json.loads(manager.credentials.path_for('external-split-agent').read_text(encoding='utf-8'))['token']
        source = manager.add_evidence(kind='external', locator='urn:external:visible', issue_id='A')['evidence_id']
        visible = manager.add_evidence(kind='external', locator='urn:external:visible-middle', issue_id='A')['evidence_id']
        hidden = manager.add_evidence(kind='external', locator='urn:external:hidden', issue_id='A')['evidence_id']
        with manager.store.transaction() as conn:
            conn.execute("UPDATE evidence_source_bindings SET source_platform_id='external-split',"
                         "binding_state='inferred' WHERE evidence_id=?", (source,))
            conn.execute("UPDATE evidence_source_bindings SET source_platform_id='external-split',"
                         "binding_state='inferred' WHERE evidence_id=?", (visible,))
        auth = manager.credentials.resolve(manager.credentials.path_for('organizer-agent'))
        relation_service = manager.scoped_evidence_relations
        relation = relation_service.create(scope_issue_id='A', source_evidence_id=source,
            target_evidence_id=hidden, relation_type='depends_on', rationale='Synthetic', auth=auth,
            expected_source_token=relation_service.binding(source, auth=auth)['token'],
            expected_target_token=relation_service.binding(hidden, auth=auth)['token'], idempotency_key='private-edge')
        for start, end, kind, key in ((source, visible, 'supports', 'visible-edge'),
                                      (visible, hidden, 'depends_on', 'unrelated-private-edge')):
            relation_service.create(scope_issue_id='A', source_evidence_id=start, target_evidence_id=end,
                relation_type=kind, rationale='Synthetic', auth=auth,
                expected_source_token=relation_service.binding(start, auth=auth)['token'],
                expected_target_token=relation_service.binding(end, auth=auth)['token'], idempotency_key=key)
        foreign = manager.direct_splits.split({'source_evidence_id': source,
            'expected_snapshot': manager.direct_splits.boundary(source, auth=auth)['snapshot'],
            'parts': [{'issue_id': 'A', 'kind': 'observation', 'text': 'Foreign one'},
                      {'issue_id': 'A', 'kind': 'interpretation', 'text': 'Foreign two'}],
            'relation_decisions': [], 'new_relations': []}, auth=auth, idempotency_key='foreign-split')
    finally:
        manager.close()
    try:
        service.start()
        names = ['read_evidence_neighbors', 'read_split_origins', 'split_evidence']
        profile = service.profile('external-split-agent', tools=names, suffix='-private')
        with http_mcp(service, profile, token, service.path) as (base, _):
            async def run():
                async with client(base + '/mcp') as mcp:
                    neighbors = await call(mcp, 'read_evidence_neighbors', {'evidence_id': source})
                    assert any(item.get('restricted') for item in neighbors['items'])
                    assert hidden not in json.dumps(neighbors) and relation['relation_id'] not in json.dumps(neighbors)
                    result = await call(mcp, 'split_evidence', {'source_evidence_id': source, 'parts': [
                        {'issue_id': 'A', 'kind': 'observation', 'text': 'One'},
                        {'issue_id': 'A', 'kind': 'interpretation', 'text': 'Two'}]})
                    assert len(result['parts']) == 2
                    assert hidden not in json.dumps(result) and relation['relation_id'] not in json.dumps(result)
                    origins = await call(mcp, 'read_split_origins', {'evidence_id': source})
                    assert {item['evidence_id'] for item in origins['items'] if not item.get('restricted')} == {
                        item['evidence_id'] for item in result['parts']}
                    assert any(item.get('restricted') for item in origins['items'])
                    assert all(item['evidence_id'] not in json.dumps(origins) for item in foreign['parts'])
                    denied = await call(mcp, 'split_evidence', {'source_evidence_id': source, 'parts': [
                        {'issue_id': 'A', 'kind': 'observation', 'text': 'One'},
                        {'issue_id': 'A', 'kind': 'interpretation', 'text': 'Two'}],
                        'relation_decisions': [{'relation_id': relation['relation_id'], 'action': 'withdraw',
                                                'part_index': None, 'reason': 'Unauthorized guess'}]})
                    assert denied['error']['code'] == 'permission_denied', denied
                    assert hidden not in json.dumps(denied)
            asyncio.run(run())
    finally:
        service.stop()


def test_split_keeps_historical_and_current_conclusion_currentness_readable(tmp_path):
    service = IMService(tmp_path / 'history-im')
    try:
        tools = service.tools('curator')
        source = tools.call('save_contribution', {'kind': 'observation', 'source': 'urn:history:source',
            'text': 'Mixed input', 'reason': 'Synthetic'})['evidence']['evidence_id']
        provider = tools.call('save_contribution', {'kind': 'observation', 'source': 'urn:history:provider',
            'text': 'Required input', 'reason': 'Synthetic'})['evidence']['evidence_id']
        relation = tools.call('create_relation', {'source_evidence_id': source, 'target_evidence_id': provider,
            'relation_type': 'depends_on', 'rationale': 'Synthetic prerequisite'})
        statements = []
        for statement in ('First conclusion', 'Second conclusion'):
            statements.append(tools.call('save_working_conclusion', {'statement': statement,
                'evidence_ids': [source], 'reason': 'Synthetic', 'confidence': 'low'}))
        profile = service.profile('curator', tools=['split_evidence', 'list_conclusion_history'], suffix='-history')
        with http_mcp(service, profile, service.tokens['curator'], service.path) as (base, _):
            async def run():
                async with client(base + '/mcp') as mcp:
                    result = await call(mcp, 'split_evidence', {'source_evidence_id': source,
                        'parts': [{'issue_id': 'A', 'kind': 'observation', 'text': 'First'},
                                  {'issue_id': 'A', 'kind': 'interpretation', 'text': 'Second'}],
                        'relation_decisions': [{'relation_id': relation['relation_id'], 'action': 'replace',
                                                'part_index': 0, 'reason': 'Only first needs input'}]})
                    assert len(result['parts']) == 2, result
                    history = await call(mcp, 'list_conclusion_history', {'issue_id': 'A'})
                    versions = {item['conclusion_id']: item for item in history['items']}
                    assert all(item['conclusion_id'] in versions for item in statements)
                    assert all(versions[item['conclusion_id']]['currentness']['currentness'] == 'needs_update'
                               for item in statements)
                    assert all(source in versions[item['conclusion_id']]['evidence_refs'] for item in statements)
            asyncio.run(run())
        assert tools.call('inspect_issue', {'issue_id': 'A'})['issue']['current_conclusion_id'] == statements[-1]['conclusion_id']
    finally:
        service.stop()


def test_multiple_splits_have_bounded_origin_pages(tmp_path):
    service = IMService(tmp_path / 'pages-im')
    try:
        source = service.tools('curator').call('save_contribution', {'kind': 'observation',
            'source': 'urn:pages', 'text': 'Composite', 'reason': 'Synthetic'})['evidence']['evidence_id']
        profile = service.profile('curator', tools=['split_evidence', 'read_split_origins'], suffix='-pages')
        with http_mcp(service, profile, service.tokens['curator'], service.path) as (base, _):
            async def run():
                async with client(base + '/mcp') as mcp:
                    expected = set()
                    for _ in range(5):
                        result = await call(mcp, 'split_evidence', {'source_evidence_id': source,
                            'parts': [{'issue_id': 'A', 'kind': 'observation', 'text': 'One'},
                                      {'issue_id': 'B', 'kind': 'interpretation', 'text': 'Two'}]})
                        expected.update(part['evidence_id'] for part in result['parts'])
                    arguments = {'evidence_id': source, 'limit': 3}
                    actual = []
                    while True:
                        page = await call(mcp, 'read_split_origins', arguments)
                        assert len(page['items']) <= 3
                        actual.extend(item['evidence_id'] for item in page['items'] if item['kind'] == 'split_child')
                        if not page.get('next_read'):
                            break
                        arguments = page['next_read']['arguments']
                    assert len(actual) == 10 and set(actual) == expected
            asyncio.run(run())
    finally:
        service.stop()


def test_observed_relation_revision_is_not_refreshed_before_split(tmp_path):
    service = IMService(tmp_path / 'observation-im')
    try:
        other = service.tools('curator', suffix='-other')
        source = other.call('save_contribution', {'kind': 'observation', 'source': 'urn:observed-source',
            'text': 'Two findings', 'reason': 'Synthetic'})['evidence']['evidence_id']
        peer = other.call('save_contribution', {'kind': 'observation', 'source': 'urn:observed-peer',
            'text': 'Correction', 'reason': 'Synthetic'})['evidence']['evidence_id']
        relation = other.call('create_relation', {'source_evidence_id': peer, 'target_evidence_id': source,
            'relation_type': 'refutes', 'rationale': 'Original judgment'})
        names = ['read_evidence', 'read_evidence_neighbors', 'split_evidence']
        profile = service.profile('curator', tools=names, suffix='-observed')
        with http_mcp(service, profile, service.tokens['curator'], service.path) as (base, _):
            async def run():
                async with client(base + '/mcp') as mcp:
                    page = await call(mcp, 'read_evidence_neighbors', {'evidence_id': source})
                    assert page['items'][0]['version_id'] == relation['version_id']
                    other.call('withdraw_relation', {'relation_id': relation['relation_id'], 'reason': 'Changed'})
                    other.call('restore_relation', {'relation_id': relation['relation_id'], 'reason': 'Reconsidered'})
                    # A later detail read must not overwrite the relation version that was actually shown.
                    await call(mcp, 'read_evidence', {'evidence_id': source})
                    args = {'source_evidence_id': source, 'parts': [
                        {'issue_id': 'A', 'kind': 'observation', 'text': 'One'},
                        {'issue_id': 'A', 'kind': 'interpretation', 'text': 'Two'}],
                        'relation_decisions': [{'relation_id': relation['relation_id'], 'action': 'replace',
                                                'part_index': 0, 'reason': 'Observed correction'}]}
                    result = await call(mcp, 'split_evidence', args)
                    assert result['error']['code'] == 'conflict', result
                    assert not (await call(mcp, 'read_evidence_neighbors', {'evidence_id': source}))['items'][0].get('restricted')
                    fresh = await call(mcp, 'split_evidence', args)
                    assert len(fresh['parts']) == 2, fresh
            asyncio.run(run())
    finally:
        service.stop()


def test_reading_survives_oversized_split_boundary_without_refreshing_decision(tmp_path):
    service = IMService(tmp_path / 'large-boundary-im')
    service.stop()
    manager = IssueManager(service.ledger)
    try:
        auth = manager.credentials.resolve(manager.credentials.path_for('organizer-agent'))
        source = manager.add_evidence(kind='external', locator='urn:large:source', issue_id='A',
                                      description='Readable source')['evidence_id']
        peers = []
        for index in range(2):
            peer = manager.add_evidence(kind='external', locator=f'urn:large:peer:{index}', issue_id='A',
                                        description='x' * 550_000)['evidence_id']
            peers.append(peer)
            relations = manager.scoped_evidence_relations
            relations.create(scope_issue_id='A', source_evidence_id=source, target_evidence_id=peer,
                relation_type='supports', rationale='Synthetic', auth=auth,
                expected_source_token=relations.binding(source, auth=auth)['token'],
                expected_target_token=relations.binding(peer, auth=auth)['token'], idempotency_key=f'large-{index}')
    finally:
        manager.close()
    try:
        service.start()
        names = ['read_evidence', 'read_evidence_neighbors', 'split_evidence']
        profile = service.profile('curator', tools=names, suffix='-large-boundary')
        with http_mcp(service, profile, service.tokens['curator'], service.path) as (base, _):
            register(base, 'large-observer', 'A', names)
            register(base, 'independent-observer', 'A', names)
            async def run():
                url = base + '/sessions/large-observer/mcp'
                async with client(url, session_token('synthetic-secret', 'large-observer')) as mcp:
                    detail = await call(mcp, 'read_evidence', {'evidence_id': source})
                    assert detail['evidence']['evidence_id'] == source
                    assert detail['split_observation_notice']['code'] == 'split_boundary_too_large'
                    neighbors = await call(mcp, 'read_evidence_neighbors', {'evidence_id': source})
                    assert len(neighbors['items']) == 2
                    assert neighbors['split_observation_notice']['code'] == 'split_boundary_too_large'
                    args = {'source_evidence_id': source, 'parts': [
                        {'issue_id': 'A', 'kind': 'observation', 'text': 'One'},
                        {'issue_id': 'A', 'kind': 'interpretation', 'text': 'Two'}]}
                    denied = await call(mcp, 'split_evidence', args)
                    assert denied['error']['code'] == 'split_boundary_too_large', denied
                    assert denied['error']['effect'] == 'not_committed'
                    # Once the synthetic graph becomes smaller, the old unavailable
                    # observation must not be silently replaced at submission.
                    instance = IssueManager(service.ledger)
                    try:
                        with instance.store.transaction() as conn:
                            for peer in peers:
                                conn.execute('UPDATE evidence_refs SET short_description=? WHERE evidence_id=?',
                                             ('bounded', peer))
                    finally:
                        instance.close()
                    denied = await call(mcp, 'split_evidence', args)
                    assert denied['error']['code'] == 'split_boundary_too_large', denied
                    async with client(base + '/sessions/independent-observer/mcp',
                                      session_token('synthetic-secret', 'independent-observer')) as other:
                        independent = await call(other, 'split_evidence', args)
                        assert len(independent['parts']) == 2, independent
                    fresh = await call(mcp, 'read_evidence', {'evidence_id': source})
                    assert 'split_observation_notice' not in fresh
                    result = await call(mcp, 'split_evidence', args)
                    assert len(result['parts']) == 2, result
            asyncio.run(run())
    finally:
        service.stop()
