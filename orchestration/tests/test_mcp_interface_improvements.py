"""Real HTTP and MCP checks for optional MCP entrances and diagnostics."""
from board_tools_harness import BoardMCP, running_board
from im_tools_harness import IMMCP, IMService
from queue_tools_harness import MCP, running_service


def test_queue_read_continuation_and_errors(tmp_path):
    with running_service(tmp_path / 'queue') as service:
        with MCP(service) as mcp:
            for text in ('first', 'second'):
                mcp.call('publish_task', {'instructions': text, 'experimenter_profile': 'worker'})
            result = mcp.call('list_tasks', {'limit': 1})
            step = result['items'][0]['read']
            task = mcp.call(step['tool'], step['arguments'])
            assert task['reply']['arguments']['task_id'] == step['arguments']['task_id']
            assert task['replies_read']['tool'] == 'list_task_replies'
            assert mcp.call(result['next_read']['tool'], result['next_read']['arguments'])['items']
            missing = mcp.call('publish_task', {'instructions': 'sensitive'})
            assert missing['error']['fields'][0]['missing'] == ['experimenter_profile']
            assert 'sensitive' not in str(missing)
            unknown = mcp.call('list_tasks', {'oops': 'secret'})
            assert unknown['error']['fields'][0]['unknown'] == ['oops']
            assert 'secret' not in str(unknown)


def test_board_reply_draft_and_permissions(tmp_path):
    with running_board(tmp_path / 'board') as service:
        with BoardMCP(service, profile=service.profile()) as mcp:
            definitions = {item['name']: item for item in mcp.rpc('tools/list', {})['tools']}
            for name in ('list_messages', 'list_handoffs'):
                assert '1..50' in definitions[name]['description']
                assert 'next_read' in definitions[name]['inputSchema']['properties']['limit']['description']
            original = mcp.call('post_message', {'issue_id': 'B', 'text': 'original'})
            message_id = original['message_id']
            for item in (mcp.call('get_message', {'message_id': message_id}),
                         mcp.call('list_messages', {'issue_id': 'B'})['items'][0]):
                draft = item['reply']
                assert draft['arguments'] == {'issue_id': 'B', 'reply_to': message_id}
                result = mcp.call(draft['tool'], {**draft['arguments'], 'text': 'reply'})
                assert mcp.call('get_message', {'message_id': result['message_id']})['issue_id'] == 'B'
            cross = mcp.call('post_message', {'issue_id': 'A', 'reply_to': message_id, 'text': 'cross'})
            cross_read = mcp.call('get_message', {'message_id': cross['message_id']})
            assert cross_read['issue_id'] == 'A' and cross_read['parent_read']['arguments']['message_id'] == message_id
            handoff = mcp.call('post_handoff', {'text': 'request', 'recipient': 'scientist'})
            assert 'reply' not in mcp.call('get_handoff', {'message_id': handoff['message_id']})
            bad = mcp.call('list_messages', {'limit': 51})
            assert bad['error']['fields'][0]['expected_limit'] == 50
        with BoardMCP(service, principal='reader', profile=service.profile(principal='reader')) as reader:
            draft = reader.call('get_message', {'message_id': message_id})['reply']
            assert reader.call('post_message', {**draft['arguments'], 'text': 'denied'})['error']['code'] == 'forbidden'
        with BoardMCP(service, profile=service.profile(tools=['get_message'])) as limited:
            assert 'reply' not in limited.call('get_message', {'message_id': message_id})
        with BoardMCP(service, profile=service.profile(tools=['list_messages', 'post_message'])) as limited:
            replies = limited.call('list_messages', {'issue_id': 'A'})['items']
            assert all('parent_read' not in item for item in replies)


def test_im_navigation_and_origin_diagnostics(tmp_path):
    service = IMService(tmp_path / 'im')
    try:
        with IMMCP(service, actor='curator') as mcp:
            definitions = {item['name']: item for item in mcp.rpc('tools/list', {})['tools']}
            related = definitions['save_contribution']['inputSchema']['properties']['related_evidence']
            assert '实际工具返回的 Evidence ID' in related['description']
            issue = mcp.call('inspect_issue', {'issue_id': 'A'})
            assert issue['parent_read']['arguments']['issue_id'] == 'P'
            page = mcp.call('list_child_issues', {'issue_id': 'P', 'limit': 1})
            assert page['items'][0]['read']['tool'] == 'inspect_issue'
            step = page['next_read']
            assert step['arguments']['expected_snapshot'] == page['snapshot']
            assert mcp.call(step['tool'], step['arguments'])['items']
            error = mcp.call('curate_field_item', {'packet_id': 'p', 'kind': 'observation', 'description': 'x',
                'reason': 'x', 'origin': {'type': 'source_text', 'quoted_text': 'secret'}})
            assert any(f['path'].endswith('/source_index') for f in error['error']['fields'])
            assert 'secret' not in str(error)
            error = mcp.call('curate_field_item', {'packet_id': 'p', 'kind': 'observation', 'description': 'x',
                'reason': 'x', 'origin': {'type': 'attachment', 'attachment_ref': 'secret'}})
            assert any(f['path'].endswith('/part_locator') for f in error['error']['fields'])
            unknown = mcp.call('curate_field_item', {'packet_id': 'p', 'kind': 'observation', 'description': 'x',
                'reason': 'x', 'origin': {'type': 'invalid'}})
            assert any(f.get('allowed') == ['packet_text', 'source_text', 'attachment'] for f in unknown['error']['fields'])
            mixed = mcp.call('read_original_access', {'evidence_id': 'e', 'contract_id': 'c', 'revision': 1})
            assert mixed['error']['code'] == 'invalid_arguments'
        limited_profile = service.profile('curator', tools=['list_child_issues'], suffix='-limited')
        with IMMCP(service, actor='curator', profile=limited_profile) as limited:
            page = limited.call('list_child_issues', {'issue_id': 'P'})
            assert all('read' not in item for item in page['items'])
    finally:
        service.stop()
