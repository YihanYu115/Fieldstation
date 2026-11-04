"""Step-02 acceptance using real IM HTTP, process isolation and stdio MCP."""
from __future__ import annotations

import json
from copy import deepcopy

import pytest
from im_tools_harness import IMMCP, IMService
from queue_tools_harness import DropProxy, evidence, raw
from workflow_orchestrator.im_client import IMClient
from workflow_orchestrator.im_tools import SPECS, definitions
from workflow_orchestrator.mcp_contract import ContractError
from workflow_orchestrator.tools_contracts import ToolError
from workflow_orchestrator.tools_mcp import load_profile


@pytest.fixture
def service(tmp_path):
    current = IMService(tmp_path / 'isolated-im')
    try:
        yield current
    finally:
        current.stop()


def packet(tools, **changes):
    return tools.call('submit_field_packet', {'content': 'Measurement failed at 20 mK. No fitted result; repeat is unresolved.',
        'sources': [{'locator': 'urn:synthetic:failed-log', 'provided_text': 'No fitted result.'}],
        'attachment_refs': ['urn:synthetic:trace.csv', 'urn:synthetic:script:v1'], **changes})


def curate(tools, packet_id, **changes):
    return tools.call('curate_field_item', {'packet_id': packet_id, 'kind': 'observation',
        'description': 'The synthetic measurement failed at 20 mK; no fit was obtained.',
        'origin': {'type': 'packet_text', 'quoted_text': 'Measurement failed at 20 mK.'},
        'reason': 'Preserve the negative result with conditions.', **changes})


def expect_error(code, fn):
    with pytest.raises(ToolError) as result:
        fn()
    assert result.value.code == code
    return result.value


@pytest.mark.parametrize('default_issue', [True, False])
def test_mcp_descriptions_remain_specific_to_each_field(service, default_issue):
    profile = service.profile('curator', suffix=f'-schema-{default_issue}')
    if not default_issue:
        profile.pop('default_issue_id')
    with IMMCP(service, actor='curator', profile=profile) as mcp:
        tools = {item['name']: item['inputSchema'] for item in mcp.rpc('tools/list', {})['tools']}
    read = tools['read_original_access']
    assert '冻结原件绑定' in read['properties']['evidence_id']['description']
    assert 'revision' in read['properties']['contract_id']['description']
    assert 'evidence_id' in read['oneOf'][0]['required']
    assert ('issue_id' in read['required']) is not default_issue
    discover = tools['discover_original_access']['properties']
    assert discover['contract_id'].get('description') != discover['issue_id'].get('description')
    assert '关系' not in discover['cursor'].get('description', '')
    contribution = tools['save_contribution']['properties']
    assert '真实来源定位' in contribution['source']['description']
    assert '观察或解释' in contribution['text']['description']
    assert '实际理由' in contribution['reason']['description']
    related = contribution['related_evidence']['items']['properties']
    assert 'target end' in related['provider_evidence_id']['description']
    assert 'target end' not in read['properties']['contract_id']['description']
    assert contribution['source']['maxLength'] == 512
    assert contribution['text']['maxLength'] == 8000
    assert tools['save_working_conclusion']['properties']['structured_outputs']['type'] == 'object'
    assert definitions() == SPECS


def test_original_contract_reminder_respects_enabled_tools(service):
    profile = service.profile('experimenter', tools=['submit_field_packet'], suffix='-no-original')
    with IMMCP(service, 'experimenter', profile=profile) as mcp:
        tool = next(t for t in mcp.rpc('tools/list', {})['tools'] if t['name'] == 'submit_field_packet')
        assert '工作区' in tool['description'] and '可信宿主' in tool['description']
        assert 'discover_original_access' not in tool['description']
        assert mcp.call('submit_field_packet', {'content': 'Temporary result; archive unavailable.'})['status'] == 'received'
    profile = service.profile('experimenter', tools=['submit_field_packet', 'discover_original_access'], suffix='-original')
    with IMMCP(service, 'experimenter', profile=profile) as mcp:
        tool = next(t for t in mcp.rpc('tools/list', {})['tools'] if t['name'] == 'submit_field_packet')
        assert 'discover_original_access' in tool['description']


def test_independent_mcp_multiple_and_cross_issue(service):
    with IMMCP(service) as mcp:
        listed = mcp.rpc('tools/list', {})['tools']
        assert {item['name'] for item in listed} == set(SPECS)
        assert all('operation_id' not in item['inputSchema']['properties'] for item in listed)
        args = {'content': 'Failed scan; raw trace retained.', 'attachment_refs': ['urn:synthetic:failed.csv']}
        receipts = [mcp.call('submit_field_packet', args),
                    mcp.call('submit_field_packet', {'content': 'Partial scan; temperature unknown.'}),
                    mcp.call('submit_field_packet', args),
                    mcp.call('submit_field_packet', {**args, 'issue_id': 'B'})]
        assert all(row['status'] == 'received' for row in receipts), receipts
        assert len({row['packet_id'] for row in receipts}) == 4
        assert len({row['delivery_id'] for row in receipts}) == 4
        a = mcp.call('list_field_packets', {})
        b = mcp.call('list_field_packets', {'issue_id': 'B'})
        assert a['count'] == 3 and b['count'] == 1
        read = mcp.call('read_field_source', {'packet_id': receipts[0]['packet_id']})
        assert read['content_utf8'] == args['content']
        original = mcp.call('read_field_packet', {'packet_id': receipts[0]['packet_id']})
        assert original['created_by'] == 'experimenter'
        assert original['attachment_refs'] == args['attachment_refs']
        assert original['curation_version'] == 0
        denied = mcp.call('save_contribution', {'kind': 'observation', 'source': 'urn:synthetic:x', 'text': 'x', 'reason': 'x'})
        assert denied['error']['code'] == 'permission_denied'
        invalid = mcp.call('submit_field_packet', {'content': 'x', 'task_id': 'not-a-required-field'})
        assert 'error' in invalid
        evidence('im-independent-mcp', {'receipts': receipts, 'a': a, 'b': b, 'source': read,
            'packet': original, 'denied': denied, 'catalog': listed})


def test_pagination_partial_curation_restart_and_sources(service):
    submit = service.tools()
    receipts = [packet(submit, content='Measurement failed at 20 mK. No fitted result; repeat is unresolved.' + ' 多字节来源' * 1500) for _ in range(3)]
    curator = service.tools('curator')
    page = curator.call('list_field_packets', {'limit': 1})
    ids = [page['items'][0]['packet_id']]
    while page.get('next_read'):
        step = page['next_read']
        page = curator.call(step['tool'], step['arguments'])
        ids.extend(row['packet_id'] for row in page['items'])
    assert len(set(ids)) == 3
    pid = receipts[0]['packet_id']
    read = curator.call('read_field_source', {'packet_id': pid, 'max_bytes': 256})
    collected = read['content_utf8']
    pages = 1
    while read.get('next_read'):
        step = read['next_read']
        read = curator.call(step['tool'], step['arguments'])
        collected += read['content_utf8']
        pages += 1
    assert collected.endswith(' 多字节来源' * 1500) and pages > 10
    source = curator.call('read_field_source', {'packet_id': pid, 'source_index': 0})
    assert source['content_utf8'] == 'No fitted result.'
    first = curate(curator, pid)
    restarted = service.tools('curator', suffix='-new-session')
    known = restarted.call('list_curated_field_items', {'packet_id': pid})
    assert known['items'][0]['fact_ref'] == first['fact_ref']
    second = curate(restarted, pid, kind='interpretation', description='The failed fit leaves the inferred parameter unresolved.',
        origin={'type': 'source_text', 'source_index': 0, 'quoted_text': 'No fitted result.'},
        related_evidence=[{'target_kind': 'fact_ref', 'target_ref': first['fact_ref'],
                          'relation_type': 'depends_on', 'rationale': 'The unresolved inference requires the failed observation.'}])
    assert second['atomic'] is True and second['curation_version'] == 2 and len(second['relation_ids']) == 1
    mappings = restarted.call('list_curated_field_items', {'packet_id': pid, 'limit': 1})
    assert mappings.get('next_read')
    next_page = restarted.call(**{'name': mappings['next_read']['tool'], 'arguments': mappings['next_read']['arguments']})
    assert len(next_page['items']) == 1
    fact = restarted.call('read_field_fact', {'packet_id': pid, 'fact_ref': second['fact_ref']})
    neighbors = restarted.call('read_evidence_neighbors', {'evidence_id': second['evidence_id']})
    assert restarted.call('get_field_summary', {'packet_id': pid})['curation_version'] == 2
    assert restarted.call('list_field_reviews', {'packet_id': pid})['items'] == []
    review = restarted.call('record_field_review', {'packet_id': pid, 'handled_fact_refs': [first['fact_ref'], second['fact_ref']],
        'unresolved': [], 'reason': 'Reviewed these two synthetic statements; no claim of scientific validity.'})
    assert restarted.call('read_field_review', {'packet_id': pid, 'review_id': review['review_id']})['reason'].startswith('Reviewed')
    evidence('im-partial-curation', {'packets': receipts, 'pages': pages, 'first': first, 'second': second,
        'existing': known, 'fact': fact, 'neighbors': neighbors, 'review': review})


def test_real_http_loss_and_reconstruction(service):
    with DropProxy(service.endpoint) as proxy:
        tools = service.tools(endpoint=proxy.endpoint)
        proxy.drop = 1
        error = expect_error('transport_unknown', lambda: packet(tools))
        assert error.effect == 'unknown'
        old_id = error.operation_id
        other = packet(tools, issue_id='B')
        recovered = service.tools(endpoint=proxy.endpoint).client.recover(old_id)
        assert recovered['packet_id'] != other['packet_id']
        assert recovered['idempotent_replay'] is True
        assert tools.call('list_field_packets', {})['count'] == 1
        curator = service.tools('curator', endpoint=proxy.endpoint)
        proxy.drop = 1
        lost = expect_error('transport_unknown', lambda: curate(curator, recovered['packet_id']))
        restored = service.tools('curator', endpoint=proxy.endpoint).client.recover(lost.operation_id)
        assert restored['idempotent_replay'] is True
        assert curator.call('get_field_summary', {'packet_id': recovered['packet_id']})['curation_version'] == 1
        assert curator.call('list_field_reviews', {'packet_id': recovered['packet_id']})['items'] == []
        evidence('im-http-loss', {'submit_error': error.result(), 'restored': recovered, 'other': other,
            'curate_error': lost.result(), 'curation_restored': restored, 'proxy_received': proxy.committed})


def test_journal_failure_before_send_and_after_real_curation(service, monkeypatch):
    tools = service.tools()
    real_save = tools.client.journal.save
    monkeypatch.setattr(tools.client.journal, 'save', lambda value: (_ for _ in ()).throw(OSError('synthetic disk fault')))
    expect_error('journal_write_failed', lambda: packet(tools))
    monkeypatch.setattr(tools.client.journal, 'save', real_save)
    assert tools.call('list_field_packets', {})['count'] == 0
    pid = packet(tools)['packet_id']
    curator = service.tools('curator')
    save = curator.client.journal.save
    def fail_receipt(value):
        if any('result' in step for row in value['actions'].values() for step in row['steps']):
            raise OSError('synthetic receipt fault')
        save(value)
    monkeypatch.setattr(curator.client.journal, 'save', fail_receipt)
    lost = expect_error('journal_write_failed', lambda: curate(curator, pid))
    assert lost.effect == 'unknown'
    recovered = service.tools('curator').client.recover(lost.operation_id)
    assert recovered['idempotent_replay'] is True
    assert service.tools('curator').call('get_field_summary', {'packet_id': pid})['curation_version'] == 1
    evidence('im-journal-fault', {'error': lost.result(), 'recovered': recovered})


def test_original_binding_and_intent_tamper_refused(service):
    tools = service.tools()
    row = packet(tools)
    path = tools.client.journal.path
    expect_error('recovery_binding_changed', lambda: IMClient('http://127.0.0.1:1', service.tokens['experimenter'], path, token_env='MCP_QUEUE_TOKEN'))
    expect_error('recovery_binding_changed', lambda: IMClient(service.endpoint, service.tokens['reader'], path, token_env='MCP_QUEUE_TOKEN'))
    expect_error('recovery_binding_changed', lambda: IMClient(service.endpoint, service.tokens['experimenter'], path, token_env='OTHER_ENV'))
    original = json.loads(path.read_text(encoding='utf-8'))
    errors = []
    for field, changed in [('path', '/v1/field-packets/changed'), ('body', {'issue_id': 'B', 'content': 'changed'}),
                           ('request_id', 'changed-request'), ('idempotency_key', 'changed-key')]:
        modified = deepcopy(original)
        modified['actions'][row['delivery_id']]['steps'][0][field] = changed
        path.write_text(json.dumps(modified), encoding='utf-8')
        errors.append(expect_error('intent_conflict', lambda: tools.client.recover(row['delivery_id'])).result())
    path.write_text(json.dumps(original), encoding='utf-8')
    assert tools.client.recover(row['delivery_id'])['packet_id'] == row['packet_id']
    evidence('im-binding-refusals', {'delivery_id': row['delivery_id'], 'tamper_errors': errors})


def test_authoritative_permissions_cas_atomic_rejection(service):
    pid = packet(service.tools())['packet_id']
    good = curate(service.tools('curator'), pid)
    no_relation = service.tools('no-relations')
    error = expect_error('permission_denied', lambda: curate(no_relation, pid, kind='interpretation',
        related_evidence=[{'target_kind': 'fact_ref', 'target_ref': good['fact_ref'],
                          'relation_type': 'depends_on', 'rationale': 'Necessary premise'}]))
    curator = service.tools('curator')
    packet_body = {'issue_id': 'A', 'expected_curation_version': 0, 'kind': 'observation',
        'description': 'stale competing curation', 'origin': {'type': 'packet_text', 'quoted_text': 'Measurement failed at 20 mK.'},
        'reason': 'Use the captured version', 'related_evidence': []}
    oid = curator.client.begin('curate_field_item', f'/v1/field-packets/{pid}/curated-items', packet_body)
    conflict = expect_error('conflict', lambda: curator.client.recover(oid))
    assert curator.client.status(oid)['state'] == 'rejected'
    broken = expect_error('not_found', lambda: curate(curator, pid, related_evidence=[{
        'target_kind': 'evidence_id', 'target_ref': 'absent-evidence', 'relation_type': 'depends_on', 'rationale': 'Invalid premise'}]))
    assert curator.call('get_field_summary', {'packet_id': pid})['curation_version'] == 1
    assert len(curator.call('list_curated_field_items', {'packet_id': pid})['items']) == 1
    assert curator.call('read_field_fact', {'packet_id': pid, 'fact_ref': good['fact_ref']})['mapping']['evidence_id'] == good['evidence_id']
    with pytest.raises(ContractError):
        packet(service.tools(), sources=[{'locator': 'x', 'provided_text': ''}])
    expect_error('permission_denied', lambda: packet(service.tools('reader')))
    expect_error('permission_denied', lambda: service.tools('submit-only').call('list_field_packets', {}))
    evidence('im-atomic-refusals', {'good': good, 'permission': error.result(), 'cas': conflict.result(), 'source': broken.result()})


def test_general_contribution_relation_conclusion_and_browse(service):
    current = service.tools('curator')
    status, registered = raw(service.endpoint, service.tokens['curator'], 'POST', '/v1/original-access', {
        'root_issue_id': 'P', 'contract_id': 'synthetic', 'expected_revision': 0,
        'document': {'reference_prefix': 'urn:synthetic:', 'summary': 'Synthetic source reading instruction',
            'capability': 'synthetic.read', 'parameters': 'reference', 'example': 'reference=urn:synthetic:root',
            'semantics': 'Returns synthetic test text only.', 'failures': 'missing_binding or missing',
            'change_impact': 'initial', 'impact_note': 'Synthetic fixture.'}, 'reason': 'Register synthetic source instructions.'},
        extra_headers={'X-Request-ID': 'original-fixture', 'Idempotency-Key': 'original-fixture'})
    assert status == 200, registered
    contribution = current.call('save_contribution' , {'kind': 'observation', 'source': 'urn:synthetic:root',
        'text': 'Synthetic independent observation at 20 mK.', 'reason': 'Preserve an independent source.'})
    eid = contribution['evidence']['evidence_id']
    dependent = current.call('save_contribution', {'issue_id': 'B', 'kind': 'interpretation',
        'source': 'urn:synthetic:analysis', 'text': 'Synthetic derived inference remains uncertain.',
        'reason': 'Explicitly retain necessary dependency.', 'related_evidence': [{
            'provider_evidence_id': eid, 'relation_type': 'depends_on', 'rationale': 'Requires the measured observation.'}]})
    did = dependent['evidence']['evidence_id']
    relations = current.call('create_relation', {'issue_id': 'B', 'source_evidence_id': did,
        'target_evidence_id': eid, 'relation_type': 'challenges', 'rationale': 'Synthetic uncertainty challenges applicability.'})
    relation_id = relations['relation_id']
    withdrawn = current.call('withdraw_relation', {'relation_id': relation_id, 'reason': 'Synthetic relation reconsidered.'})
    restored = current.call('restore_relation', {'relation_id': relation_id, 'reason': 'Synthetic relation reasserted.'})
    conclusion = current.call('save_working_conclusion', {'statement': 'Synthetic observation recorded; no physical validation.',
        'evidence_ids': [eid], 'reason': 'Initial bounded working statement.', 'confidence': 'low',
        'limitations': ['Synthetic inputs only.']})
    with IMMCP(service, 'curator', profile=service.profile('curator', suffix='-browse')) as fresh:
        read = fresh.call('read_evidence', {'evidence_id': eid})
        neighbors = fresh.call('read_evidence_neighbors', {'evidence_id': did})
        overview = fresh.call('inspect_issue', {})
        assert overview['issue']['issue_type_snapshot']['definition']['conclusion']['structured_outputs_schema']['type'] == 'object'
        children = fresh.call('list_child_issues', {'issue_id': 'P', 'limit': 1})
        assert overview['issue']['parent_issue_id'] == 'P'
        assert fresh.call('inspect_issue', {'issue_id': 'P'})['issue']['parent_issue_id'] is None
        assert fresh.call('inspect_issue', {'issue_id': 'B'})['issue']['parent_issue_id'] == 'P'
        assert fresh.call('inspect_issue', {'issue_id': 'OUT'})['issue']['parent_issue_id'] is None
        tail = fresh.call('list_child_issues', {'issue_id': 'P', 'limit': 1, 'cursor': children['next_cursor']})
        assert {children['items'][0]['issue_id'], tail['items'][0]['issue_id']} == {'A', 'B'}
        originals = fresh.call('discover_original_access', {'reference': 'urn:synthetic:root'})
        original_detail = fresh.call('read_original_access', {'evidence_id': eid})
        assert children['items'][0]['read']['arguments']['issue_id'] == children['items'][0]['issue_id']
        assert fresh.call(children['next_read']['tool'], children['next_read']['arguments'])['items'] == tail['items']
        assert any(row.get('source_read') and row.get('target_read') for row in neighbors['items'] if not row.get('restricted'))
        evidence_page = fresh.call('list_issue_evidence', {'issue_id': 'A'})
        assert any(row.get('read', {}).get('arguments', {}).get('evidence_id') == eid for row in evidence_page['items'])
        assert original_detail['complete'] is True and original_detail['external_binding'] == 'host_required'
        assert 'error' not in read and 'error' not in neighbors and 'error' not in overview
        assert 'error' not in children and 'error' not in originals
    with IMMCP(service, 'submit-only') as limited:
        assert limited.call('inspect_issue', {'issue_id': 'P'})['error']['code'] == 'permission_denied'
    invalid_source = current.client.begin('save_contribution', '/v1/scoped-evidence-contributions', {
        'issue_id': 'A', 'kind': 'observation', 'source': '', 'description': 'Missing source.',
        'reason': 'Verify actual source validation.', 'related_evidence': []})
    expect_error('validation_error', lambda: current.client.recover(invalid_source))
    evidence('im-general-work', {'contribution': contribution, 'dependent': dependent, 'relation': relations,
        'withdrawn': withdrawn, 'restored': restored, 'conclusion': conclusion,
        'fresh_read': read, 'neighbors': neighbors, 'overview': overview, 'children': children, 'originals': originals})


def test_profile_selection_no_queue_and_trim(service):
    file = service.path / 'trim-profile.json'
    profile = service.profile(tools=['submit_field_packet', 'read_field_source'])
    file.write_text(json.dumps(profile), encoding='utf-8')
    assert load_profile(file)['surface'] == 'im'
    with IMMCP(service, profile=profile) as mcp:
        assert {item['name'] for item in mcp.rpc('tools/list', {})['tools']} == set(profile['tools'])
        assert mcp.call('list_tasks', {})['error']['code'] == 'tool_not_enabled'
        assert mcp.call('submit_field_packet', {'content': 'Failure without workflow services.'})['status'] == 'received'
    for bad in ({**profile, 'surface': 'arbitrary'}, {**profile, 'tools': ['publish_task']}):
        file.write_text(json.dumps(bad), encoding='utf-8')
        with pytest.raises(ToolError):
            load_profile(file)


def test_mcp_rebuild_recovers_original_and_new_same_text_is_new(service):
    with DropProxy(service.endpoint) as proxy:
        profile = service.profile(endpoint=proxy.endpoint, suffix='-rebuild')
        with IMMCP(service, profile=profile) as first:
            proxy.drop = 1
            unknown = first.call('submit_field_packet', {'content': 'Failed run; retain unknown response.'})
            assert unknown['error']['effect'] == 'unknown'
            oid = unknown['error']['operation_id']
        with IMMCP(service, profile=profile) as rebuilt:
            recovered = rebuilt.call('get_delivery_status', {'delivery_id': oid})
            assert recovered['state'] == 'confirmed'
            original = recovered['receipt']
            new = rebuilt.call('submit_field_packet', {'content': 'Failed run; retain unknown response.'})
            assert new['packet_id'] != original['packet_id']
            assert rebuilt.call('list_field_packets', {})['count'] == 2
        evidence('im-mcp-rebuild', {'unknown': unknown, 'recovered': recovered, 'new_same_content': new})


def test_review_response_loss_and_original_unknown_auth_offline(service):
    pid = packet(service.tools())['packet_id']
    with DropProxy(service.endpoint) as proxy:
        current = service.tools('curator', endpoint=proxy.endpoint)
        first = curate(current, pid)
        proxy.drop = 1
        lost = expect_error('transport_unknown', lambda: current.call('record_field_review', {
            'packet_id': pid, 'handled_fact_refs': [first['fact_ref']], 'reason': 'Actually reviewed this item.'}))
        saved_token = current.client.token
        current.client.token = service.tokens['reader']
        expect_error('recovery_binding_changed', lambda: current.client.recover(lost.operation_id))
        current.client.token = saved_token
        assert current.client.status(lost.operation_id)['state'] == 'pending'
        recovered = service.tools('curator', endpoint=proxy.endpoint).client.recover(lost.operation_id)
        assert recovered['idempotent_replay'] is True
        reviews = current.call('list_field_reviews', {'packet_id': pid})
        assert len(reviews['items']) == 1
        proxy.drop = 1
        submit = service.tools(endpoint=proxy.endpoint, suffix='-offline')
        lost_submit = expect_error('transport_unknown', lambda: packet(submit))
        service.stop()
        offline = expect_error('transport_unknown', lambda: submit.client.recover(lost_submit.operation_id))
        assert offline.effect == 'unknown' and submit.client.status(lost_submit.operation_id)['state'] == 'pending'
        evidence('im-review-loss-offline', {'review_error': lost.result(), 'recovered': recovered,
            'reviews': reviews, 'submit_error': lost_submit.result(), 'offline': offline.result()})


def test_relation_and_conclusion_cas_keep_original_versions(service):
    current = service.tools('curator')
    first = current.call('save_contribution', {'kind': 'observation', 'source': 'urn:synthetic:cas-1',
        'text': 'First synthetic root.', 'reason': 'Root source.'})['evidence']['evidence_id']
    second = current.call('save_contribution', {'kind': 'observation', 'source': 'urn:synthetic:cas-2',
        'text': 'Second synthetic root.', 'reason': 'Root source.'})['evidence']['evidence_id']
    rel = current.call('create_relation', {'source_evidence_id': second, 'target_evidence_id': first,
        'relation_type': 'challenges', 'rationale': 'Synthetic relation for stale version test.'})
    rid = rel['relation_id']
    head = current.client.scoped_relation(rid)
    stale_relation = current.client.begin('withdraw_relation', f'/v1/scoped-evidence-relations/{rid}/deactivate',
        {'expected_version_id': head['version_id'], 'reason': 'Captured original relation version.'})
    current.call('withdraw_relation', {'relation_id': rid, 'reason': 'Actual competing relation decision.'})
    expect_error('conflict', lambda: current.client.recover(stale_relation))
    old_head = current.client.inspect_issue('A')['issue']
    original = current.client.begin('save_working_conclusion', '/v1/currentness/prepare',
        {'issue_id': 'A', 'evidence_ids': [first]}, continuation={'evidence_ids': [first], 'body': {
            'issue_id': 'A', 'expected_current_conclusion_id': old_head.get('current_conclusion_id'),
            'expected_conclusion_revision': old_head['conclusion_revision'], 'statement': 'Original decision.',
            'confidence': 'low', 'reason': 'Captured head before competition.'}})
    competing = current.call('save_working_conclusion', {'statement': 'New actual working conclusion.',
        'evidence_ids': [first], 'confidence': 'low', 'reason': 'Independent competing judgment.'})
    conflict = expect_error('conflict', lambda: current.client.recover(original))
    assert current.client.status(original)['state'] == 'rejected'
    expect_error('conflict', lambda: current.client.recover(original))
    assert current.call('read_evidence', {'evidence_id': first})
    evidence('im-domain-cas', {'relation': rel, 'original_relation': stale_relation,
        'original_conclusion': original, 'competing': competing, 'conflict': conflict.result()})



def test_browse_other_project_and_explicit_packet_target_refusal(service):
    submit = service.tools()
    a = packet(submit)
    b = packet(submit, issue_id='B')
    current = service.tools('curator')
    outside = current.call('inspect_issue', {'issue_id': 'OUT'})
    assert outside['issue']['issue_id'] == 'OUT'
    mismatch = expect_error('scope_mismatch', lambda: curate(current, b['packet_id'], issue_id='A'))
    assert current.call('get_field_summary', {'packet_id': b['packet_id']})['curation_version'] == 0
    saved = curate(current, b['packet_id'])
    assert current.call('get_field_summary', {'packet_id': a['packet_id']})['curation_version'] == 0
    evidence('im-root-target-refusals', {'outside_root': outside, 'target_mismatch': mismatch.result(),
        'a_packet': a, 'b_packet': b, 'b_curation': saved})


@pytest.mark.parametrize('operation', ['curate_field_item', 'record_field_review'])
def test_attachment_origin_roundtrip_over_real_mcp(service, operation):
    reference = r'D:\synthetic\not-mounted.csv'
    with IMMCP(service, 'experimenter') as sender:
        receipt = sender.call('submit_field_packet', {'content': 'Synthetic observation.', 'attachment_refs': [reference]})
    packet_id = receipt['packet_id']
    origin = {'type': 'attachment', 'attachment_ref': reference, 'part_locator': 'rows 2-3'}
    with IMMCP(service, 'curator') as curator:
        args = {'packet_id': packet_id, 'reason': 'Preserve original attachment reference.'}
        if operation == 'curate_field_item':
            args.update(kind='observation', description='Partial observation', origin=origin)
            saved = curator.call(operation, args)
            read = curator.call('read_field_fact', {'packet_id': packet_id, 'fact_ref': saved['fact_ref']})
            assert read['origin'] == {**origin, 'local_position_verified': False}
            assert read['source_locator'] == reference
        else:
            args.update(handled_fact_refs=[], unresolved=[{'origin': origin, 'reason': 'Attachment not mounted.'}])
            saved = curator.call(operation, args)
            read = curator.call('read_field_review', {'packet_id': packet_id, 'review_id': saved['review_id']})
            assert read['unresolved'][0]['origin'] == {**origin, 'local_position_verified': False}


ATTACHMENT_REFERENCES = [
    r"D:\实验记录\run 01\原始数据.csv", "D:/实验记录/run 01/原始数据.csv",
    r"\\Lab-Share\项目\run 01\原始数据.csv", "/mnt/lab/run 01/原始数据.csv",
    "results/run-01/原始数据.csv", "file:///D:/run%2001/%E6%95%B0%E6%8D%AE.csv",
    "https://files.example.invalid/run/a.csv?version=2#sheet-1",
    "s3://test-bucket/run/a.csv?versionId=v2", "project-record:run-17/raw-data",
    "dv://sample/run/42", "sha256:" + "a" * 64, "project-code:analysis@r2",
    "archive:run-17.zip#raw/data.csv", " e\u0301/中文😀  𠮷/ ", " é/中文😀  𠮷/ ",
    "project:A%2F+B/", "project:A%2f%20B/", "project:a%2F+B/",
    "https://files.example.invalid/a?q=1#x", "https://files.example.invalid/a?q=2#x",
    "https://files.example.invalid/a?q=1#y", "project:tab\there", "x" * 2048,
]


def test_attachment_references_remain_exact_over_real_mcp(service):
    with IMMCP(service, 'experimenter') as sender:
        for offset in range(0, len(ATTACHMENT_REFERENCES), 16):
            original = ATTACHMENT_REFERENCES[offset:offset + 16]
            receipt = sender.call('submit_field_packet', {'content': 'Retain actual references.', 'attachment_refs': original})
            packet = sender.call('read_field_packet', {'packet_id': receipt['packet_id']})
            assert packet['attachment_refs'] == original


def test_many_long_packet_references_are_readable_over_real_mcp(service):
    original = [f'urn:synthetic:{i:03d}:' + 'x' * 1200 for i in range(128)]
    sources = [{'locator': f'urn:source:{i:02d}:' + 'y' * 1800, 'provided_text': f'excerpt {i}'} for i in range(16)]
    with IMMCP(service, 'experimenter') as sender:
        receipt = sender.call('submit_field_packet', {'content': 'Many actual references.', 'attachment_refs': original, 'sources': sources})
        args = {'packet_id': receipt['packet_id']}
        attachments, bindings, found_sources = [], [], []
        while True:
            result = sender.call('read_field_packet', args)
            attachments.extend(result['attachment_refs'])
            bindings.extend(result['original_access'])
            found_sources.extend(result['sources'])
            next_read = result.get('next_read')
            if not next_read:
                break
            assert next_read['tool'] == 'read_field_packet'
            args = next_read['arguments']
        assert attachments == original
        assert [source['locator'] for source in found_sources] == [source['locator'] for source in sources]
        assert {binding['reference'] for binding in bindings} == set(original) | {source['locator'] for source in sources}
        assert len(bindings) == len(original) + len(sources)
        args = {'packet_id': receipt['packet_id']}
        summary_attachments, summary_bindings = [], []
        while True:
            result = sender.call('get_field_summary', args)
            summary_attachments.extend(result['attachment_refs'])
            summary_bindings.extend(result['original_access'])
            next_read = result.get('next_read')
            if not next_read:
                break
            assert next_read['tool'] == 'get_field_summary'
            args = next_read['arguments']
        assert summary_attachments == original
        assert {binding['reference'] for binding in summary_bindings} == set(original) | {source['locator'] for source in sources}


def test_host_reads_original_attachment_separately_from_im(service, tmp_path):
    original = tmp_path / '项目原件.csv'
    original.write_bytes('value,unit\r\n12,ns\r\n'.encode('utf-8'))
    quoted = original.read_bytes().decode('utf-8')
    with IMMCP(service, 'experimenter') as sender:
        receipt = sender.call('submit_field_packet', {'content': 'Host read original.', 'attachment_refs': [str(original)]})
    origin = {'type': 'attachment', 'attachment_ref': str(original), 'part_locator': 'row 2', 'quoted_text': quoted}
    with IMMCP(service, 'curator') as curator:
        saved = curator.call('curate_field_item', {'packet_id': receipt['packet_id'], 'kind': 'observation',
            'description': 'Host reported 12 ns.', 'origin': origin, 'reason': 'Keep the source as reported.'})
        read = curator.call('read_field_fact', {'packet_id': receipt['packet_id'], 'fact_ref': saved['fact_ref']})
        assert read['origin'] == {**origin, 'local_position_verified': False}


def test_unicode_source_page_replay_and_hash_guard_over_mcp(service):
    import hashlib
    from pathlib import Path
    content = '测量😀𠮷\r\n' * 400
    digest = hashlib.sha256(content.encode('utf-8')).hexdigest()
    with IMMCP(service, 'experimenter') as sender:
        receipt = sender.call('submit_field_packet', {'content': content})
    profile = service.profile('curator', suffix='-source-read')
    with IMMCP(service, 'curator', profile=profile) as reader:
        journal = Path(profile['journal_path'])
        before = journal.read_bytes()
        assert json.loads(before)['actions'] == {}
        args = {'packet_id': receipt['packet_id'], 'max_bytes': 256}
        parts = []
        while True:
            page = reader.call('read_field_source', args)
            assert page['content_sha256'] == digest
            assert len(page['content_utf8'].encode('utf-8')) <= 256
            assert reader.call('read_field_source', args) == page
            parts.append(page['content_utf8'])
            if not page.get('next_read'):
                break
            args = page['next_read']['arguments']
        assert ''.join(parts) == content
        wrong = reader.call('read_field_source', {**args, 'content_sha256': '0' * 64})
        assert 'error' in wrong
    assert journal.read_bytes() == before


def test_ambiguous_origin_requires_exact_unicode_position_over_mcp(service):
    content = 'prefix 😀unique e\u0301 phrase. repeated phrase. repeated phrase.'
    with IMMCP(service, 'experimenter') as sender:
        receipt = sender.call('submit_field_packet', {'content': content})
    with IMMCP(service, 'curator') as curator:
        base = {'packet_id': receipt['packet_id'], 'kind': 'observation', 'description': 'Observation', 'reason': 'Exact origin.'}
        wrong = curator.call('curate_field_item', {**base, 'origin': {'type': 'packet_text', 'quoted_text': 'unique e\u0301 phrase.', 'start': 0}})
        assert wrong['error']['code'] == 'invalid_origin'
        ambiguous = curator.call('curate_field_item', {**base, 'origin': {'type': 'packet_text', 'quoted_text': 'repeated phrase.'}})
        assert ambiguous['error']['code'] == 'invalid_origin'
        located = curator.call('locate_field_excerpt', {'packet_id': receipt['packet_id'], 'quoted_text': 'repeated phrase.'})
        assert len(located['matches']) == 2
        assert len({item['origin']['start'] for item in located['matches']}) == 2
        good = curator.call('curate_field_item', {**base, 'origin': {'type': 'packet_text', 'quoted_text': 'unique e\u0301 phrase.', 'start': content.index('unique e\u0301 phrase.')}})
        assert good['origin']['start'] == content.index('unique e\u0301 phrase.')
        assert curator.call('get_field_summary', {'packet_id': receipt['packet_id']})['curation_version'] == 1


def test_conclusion_commit_lost_response_recovers_original_over_real_mcp(service):
    from im_transport_harness import FaultProxy
    root = service.tools('curator').call('save_contribution', {
        'kind': 'observation', 'source': 'urn:synthetic:conclusion-root',
        'text': 'Observed synthetic root.', 'reason': 'Preserve root.'})['evidence']['evidence_id']
    with FaultProxy(service) as proxy:
        profile = service.profile('curator', endpoint=proxy.endpoint, suffix='-conclusion-recovery')
        with IMMCP(service, 'curator', profile=profile) as first:
            proxy.inject('drop', path_suffix='/working-conclusion')
            unknown = first.call('save_working_conclusion', {'statement': 'Bounded synthetic conclusion.',
                'evidence_ids': [root], 'reason': 'Use the observed root.', 'confidence': 'low',
                'structured_outputs': {'status': 'partial', 'parameters': {'count': 2}}})
            assert unknown['error']['effect'] == 'unknown'
            operation = unknown['error']['operation_id']
            sent = [e for e in proxy.events() if e['path'].endswith('/working-conclusion')]
            assert len(sent) == 1 and sent[0]['upstream_status'] == 200 and sent[0]['returned_status'] == 'dropped'
        proxy.inject('invalid_auth', path_suffix='/working-conclusion')
        with IMMCP(service, 'curator', profile=profile) as rebuilt:
            pending = rebuilt.call('get_delivery_status', {'delivery_id': operation})
            assert pending['state'] == 'pending'
            recovered = rebuilt.call('recover_delivery', {'delivery_id': operation})
            assert recovered['delivery_id'] == operation
            assert rebuilt.call('get_delivery_status', {'delivery_id': operation})['state'] == 'confirmed'
        attempts = [e for e in proxy.events() if e['path'].endswith('/working-conclusion')]
        assert len(attempts) == 3 and attempts[1]['upstream_status'] == 403
        for attempt in attempts[1:]:
            for field in ('request_id', 'idempotency_key', 'body', 'path'):
                assert attempts[0][field] == attempt[field]
        verified = service.tools('curator', suffix='-verify').call('inspect_issue', {})
        assert verified['issue']['conclusion_revision'] == 1
        assert verified['current_conclusion']['structured_outputs'] == {'status': 'partial', 'parameters': {'count': 2}}
