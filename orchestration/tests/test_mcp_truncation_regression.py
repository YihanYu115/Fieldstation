"""Truncation and restricted navigation over independent HTTP and Streamable HTTP MCP."""
import json
from pathlib import Path

from board_tools_harness import BoardMCP, running_board
from im_tools_harness import IMMCP, IMService
from queue_tools_harness import MCP, running_service

from issue_manager import IssueManager


def check_errors(mcp, name, valid, many):
    secret = 'private-value-must-not-appear'
    for count, truncated in ((1, False), (8, False), (9, True)):
        args = {**valid, **{f'unknown_{i:02}': secret for i in range(count)}}
        result = mcp.call(name, args)['error']
        assert result['fields_truncated'] is truncated
        field = next(f for f in result['fields'] if f['rule'] == 'additionalProperties')
        assert len(field['unknown']) == min(count, 8)
        assert secret not in json.dumps(result)
        assert result['effect'] == 'not_committed'
    for count, truncated in ((1, False), (8, False), (9, True)):
        result = mcp.call(name, {**valid, **many(count)})['error']
        assert result['fields_truncated'] is truncated
        assert len(result['fields']) == min(count, 8)
        assert result['effect'] == 'not_committed'


def test_queue_truncation_http(tmp_path):
    with running_service(tmp_path / 'queue') as service:
        with MCP(service) as mcp:
            check_errors(mcp, 'publish_task', {'instructions': 'text', 'experimenter_profile': 'worker'},
                         lambda n: {'input_refs': [''] * n})
            error = mcp.call('list_tasks', {'limit': 51})['error']
            assert error['fields_truncated'] is False
            assert error['fields'][0]['expected_limit'] == 50
            assert mcp.call('list_tasks', {'limit': True})['error']['fields'][0]['expected_type'] == 'integer'
            assert service.counts()['tasks'] == 0


def test_board_truncation_http(tmp_path):
    with running_board(tmp_path / 'board') as service:
        with BoardMCP(service) as mcp:
            check_errors(mcp, 'answer_handoff', {'message_id': 'id', 'answer': 'yes', 'reason': 'why'},
                         lambda n: {'result_refs': [''] * n})
            error = mcp.call('list_messages', {'limit': 51})['error']
            assert error['fields_truncated'] is False and error['fields'][0]['actual'] == 51
            assert service.counts()['messages'] == 0


def test_im_truncation_http(tmp_path):
    service = IMService(tmp_path / 'im')
    try:
        with IMMCP(service, actor='curator') as mcp:
            check_errors(mcp, 'save_working_conclusion', {'statement': 'text', 'evidence_ids': ['e'],
                         'reason': 'why', 'confidence': 'low'}, lambda n: {'limitations': [''] * n})
            error = mcp.call('read_evidence_neighbors', {'evidence_id': 'e', 'limit': 51})['error']
            assert error['fields_truncated'] is False and error['fields'][0]['expected_limit'] == 50
            assert mcp.call('save_working_conclusion', {'statement': 'x'})['error']['fields']
    finally:
        service.stop()


def test_restricted_evidence_mcp_navigation(tmp_path):
    service = IMService(tmp_path / 'im')
    try:
        service.stop()
        manager = IssueManager(service.ledger)
        try:
            evidence_id = manager.add_evidence(kind='external', locator='urn:restricted:test', issue_id='A')['evidence_id']
            credential = manager.credentials.path_for('maintenance-agent')
            manager.evidence.register_platform('other-platform', display_name='Other', capabilities=['manifest'], credential=credential)
            issued = manager.credentials.issue_actor(actor_id='platform-reader', actor_kind='maintenance_agent',
                capabilities={'context.read', 'evidence.manifest.submit'}, profiles={'platform-evidence-executor'},
                principal_kind='service', platform_id='other-platform', maintenance_credential=credential)
            service.tokens['platform-reader'] = json.loads(Path(issued['credential_path']).read_text(encoding='utf-8'))['token']
        finally:
            manager.close()
        service.start()
        with IMMCP(service, actor='platform-reader') as mcp:
            page = mcp.call('list_issue_evidence', {'issue_id': 'A'})
            row = next(item for item in page['items'] if item['evidence_id'] == evidence_id)
            assert row['restricted'] is True and 'read' not in row
            assert 'error' in mcp.call('read_evidence', {'evidence_id': evidence_id})
    finally:
        service.stop()
