"""Actual Streamable HTTP negotiation for per-surface server instructions and selected tools."""

from board_tools_harness import running_board
from im_tools_harness import IMMCP, IMService
from queue_tools_harness import MCP, running_service


class CaptureInitialize:
    def rpc(self, method, params):
        result = super().rpc(method, params)
        if method == 'initialize':
            self.initialize_result = result
        return result


class CaptureMCP(CaptureInitialize, MCP):
    pass


class CaptureIMMCP(CaptureInitialize, IMMCP):
    pass


def check(mcp, selected, required, absent):
    info = mcp.initialize_result
    assert info['protocolVersion']
    instructions = info['instructions']
    for fragment in required:
        assert fragment in instructions
    for fragment in absent:
        assert fragment not in instructions
    assert {t['name'] for t in mcp.rpc('tools/list', {})['tools']} == set(selected)


def test_queue_instructions_with_restricted_profile(tmp_path):
    with running_service(tmp_path / 'queue') as service:
        selected = ['list_tasks']
        with CaptureMCP(service, profile=service.profile(tools=selected)) as mcp:
            check(mcp, selected, ['Queue', '领取只表示', '不授予权限', '后续会话能够接续'], ['Inbox 用来', 'Board 用于'])
            assert 'items' in mcp.call('list_tasks', {})


def test_board_instructions_with_restricted_profile(tmp_path):
    with running_board(tmp_path / 'board') as service:
        selected = ['list_messages']
        with CaptureMCP(service, profile=service.profile(tools=selected)) as mcp:
            check(mcp, selected, ['Board', '普通留言只是交流', '不自动派工'], ['Inbox 用来', 'Queue 用来'])
            assert 'items' in mcp.call('list_messages', {})


def test_im_instructions_with_read_only_profile(tmp_path):
    service = IMService(tmp_path / 'im')
    try:
        selected = ['inspect_issue', 'read_evidence', 'save_working_conclusion', 'submit_field_packet']
        profile = service.profile('reader', tools=selected, suffix='-instructions')
        with CaptureIMMCP(service, actor='reader', profile=profile) as mcp:
            check(mcp, selected, ['Inbox', 'IM', '来源说明', '必要依据', '保存新材料不自动替代',
                                  '不需要提交前拆成 Evidence', 'verification_level=declared', 'quality_status=unknown',
                                  '不等于无效或必须先经整理员审核'], ['Queue 用来', 'Board 用于'])
            assert mcp.call('inspect_issue', {'issue_id': 'A'})['issue']['issue_id'] == 'A'
            tools = {item['name']: item for item in mcp.rpc('tools/list', {})['tools']}
            assert '无需预先拆成 Evidence' in tools['submit_field_packet']['description']
            assert 'verification_level=declared' in tools['read_evidence']['description']
            assert '不等于无效或必须先经整理员审核' in tools['save_working_conclusion']['description']
            assert mcp.call('create_issue', {})['error']['code'] == 'tool_not_enabled'
    finally:
        service.stop()
