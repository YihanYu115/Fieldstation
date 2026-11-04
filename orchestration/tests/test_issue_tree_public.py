"""Public HTTP and actual MCP tree creation, including failed and replayed writes."""
from concurrent.futures import ThreadPoolExecutor

import pytest
from im_tools_harness import IMMCP, IMService
from queue_tools_harness import DropProxy, raw
from workflow_orchestrator.tools_contracts import ToolError


@pytest.fixture
def service(tmp_path):
    host = IMService(tmp_path / 'tree')
    try:
        yield host
    finally:
        host.stop()


def post(service, actor, body, key):
    return raw(service.endpoint, service.tokens[actor], 'POST', '/v1/issues', body,
               {'X-Request-ID': 'request-' + key, 'Idempotency-Key': key})


def test_http_tree_auth_validation_and_atomic_replay(service):
    root = {'issue_id': 'ROOT2', 'issue_type': 'sample', 'title': 'Root', 'scope': {'sample': 'x'}}
    child = {'issue_id': 'CHILD2', 'issue_type': 'qubit', 'title': 'Child', 'parent_issue_id': 'ROOT2'}
    assert post(service, 'curator', root, 'root')[0] == 200
    first = post(service, 'curator', child, 'child')
    assert first[0] == 200
    assert post(service, 'curator', child, 'child') == first
    assert post(service, 'curator', {**child, 'title': 'changed'}, 'child')[0] == 409
    assert post(service, 'reader', {**child, 'issue_id': 'DENIED'}, 'denied')[0] == 403
    assert post(service, 'curator', {**child, 'issue_id': 'MISSING', 'parent_issue_id': 'absent'}, 'missing')[0] == 404
    bad_type = {**child, 'issue_id': 'BADTYPE', 'issue_type': 'sample'}
    rejected = post(service, 'curator', bad_type, 'badtype')
    assert rejected[0] == 400 and post(service, 'curator', bad_type, 'badtype') == rejected
    assert post(service, 'curator', {**child, 'issue_id': 'BADFIELD', 'unknown': True}, 'badfield')[0] == 400
    assert post(service, 'curator', {**child, 'issue_id': 'BADPARENT', 'parent_issue_id': ''}, 'badparent')[0] == 400
    assert post(service, 'curator', {**child, 'issue_id': 'BADSCOPE', 'scope': []}, 'badscope')[0] == 400
    assert post(service, 'curator', {**child, 'issue_id': 'BADREG', 'issue_type_registration_id': 'missing'}, 'badreg')[0] == 404
    status, result = raw(service.endpoint, service.tokens['curator'], 'GET', '/v1/browse/children?id=ROOT2')
    assert status == 200
    assert [row['issue_id'] for row in result['result']['items']] == ['CHILD2']
    status, result = raw(service.endpoint, service.tokens['curator'], 'GET', '/v1/browse/issue?id=CHILD2')
    assert status == 200 and result['result']['issue']['parent_issue_id'] == 'ROOT2'
    for issue in ('DENIED', 'MISSING', 'BADTYPE', 'BADFIELD', 'BADPARENT', 'BADSCOPE', 'BADREG'):
        assert raw(service.endpoint, service.tokens['curator'], 'GET', '/v1/browse/issue?id=' + issue)[0] == 404
    concurrent = {'issue_id': 'RACE', 'issue_type': 'qubit', 'title': 'Race', 'parent_issue_id': 'ROOT2'}
    with ThreadPoolExecutor(max_workers=2) as pool:
        replies = list(pool.map(lambda _: post(service, 'curator', concurrent, 'race'), range(2)))
    assert replies[0] == replies[1] and replies[0][0] == 200


def test_real_mcp_schema_and_creation(service):
    with IMMCP(service, actor='curator') as mcp:
        specs = {item['name']: item['inputSchema'] for item in mcp.rpc('tools/list', {})['tools']}
        schema = specs['create_issue']
        assert set(schema['required']) == {'issue_id', 'issue_type', 'title'}
        assert 'parent_issue_id' in schema['properties'] and schema['additionalProperties'] is False
        root = mcp.call('create_issue', {'issue_id': 'MROOT', 'issue_type': 'sample', 'title': 'Root'})
        assert root['issue_id'] == 'MROOT' and root['parent_issue_id'] is None
        child = mcp.call('create_issue', {'issue_id': 'MCHILD', 'issue_type': 'qubit', 'title': 'Child', 'parent_issue_id': 'MROOT'})
        assert child['parent_issue_id'] == 'MROOT'
        assert mcp.call('inspect_issue', {'issue_id': 'MCHILD'})['issue']['parent_issue_id'] == 'MROOT'
        assert [row['issue_id'] for row in mcp.call('list_child_issues', {'issue_id': 'MROOT'})['items']] == ['MCHILD']
        assert mcp.call('recover_delivery', {'delivery_id': child['delivery_id']}) == child
    with IMMCP(service, actor='reader') as mcp:
        denied = mcp.call('create_issue', {'issue_id': 'MNO', 'issue_type': 'sample', 'title': 'No'})
        assert denied['error']['code'] == 'permission_denied'


def test_unknown_response_recovers_original(service):
    proxy = DropProxy(service.endpoint)
    try:
        tools = service.tools('curator', suffix='-dropped', endpoint=proxy.endpoint)
        proxy.drop = 1
        with pytest.raises(ToolError) as exc:
            tools.call('create_issue', {'issue_id': 'RECOVER', 'issue_type': 'qubit', 'title': 'Recovered', 'parent_issue_id': 'P'})
        assert exc.value.effect == 'unknown'
        recovered = tools.call('recover_delivery', {'delivery_id': exc.value.operation_id})
        assert recovered['issue_id'] == 'RECOVER' and recovered['parent_issue_id'] == 'P'
        assert len([x for x in tools.call('list_child_issues', {'issue_id': 'P'})['items'] if x['issue_id'] == 'RECOVER']) == 1
    finally:
        proxy.close()
