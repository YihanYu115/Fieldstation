"""Finite public HTTP source reads and a pre-persisted original Queue claim."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .host_contracts import KINDS, connection_binding, digest
from .host_transport import exchange
from .tools_contracts import ToolError, fail


class Sources:
    def __init__(self, connections: dict[str, Any], runtime: Path):
        self.connections, self.runtime = connections, runtime

    def client(self, source: dict[str, Any]) -> Any:
        name = source['connection']
        if name not in self.connections:
            fail('invalid_configuration', 'unknown source connection')
        conn = self.connections[name]
        path = self.runtime / 'source-bindings' / (digest(name) + '.json')
        if KINDS[source['kind']] == 'queue':
            from .tools_client import ToolsClient
            return ToolsClient.from_connection(conn, path)
        if KINDS[source['kind']] == 'board':
            from .board_client import BoardClient
            return BoardClient.from_connection(conn, path)
        from .im_client import IMClient
        return IMClient.from_connection(conn, path)

    def read(self, source: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        client = self.client(source)
        binding = {**connection_binding(self.connections[source['connection']]), **client.binding}
        if source['kind'] != 'inbox.packet' and source['service_id'] != binding['service_id']:
            fail('source_identity_changed', 'source store differs from original service_id', status=409)
        if source['kind'] == 'queue.task':
            item = client.read('get_task', task_id=source['item_id'])
            actual_id = item.get('task_id')
        elif source['kind'] in {'board.message', 'board.handoff'}:
            action = 'get_message' if source['kind'] == 'board.message' else 'get_handoff'
            item = client.read(action, message_id=source['item_id'])
            actual_id = item.get('message_id')
        else:
            item = client.field_packet(source['item_id'])
            actual_id = item.get('packet_id')
        if actual_id != source['item_id'] or item.get('issue_id') != source['issue_id']:
            fail('source_mismatch', 'actual source ID or Issue differs', status=409)
        if 'revision' in source and source['revision'] != item.get('revision'):
            fail('source_revision_changed', 'original requested revision differs', status=409)
        return item, binding

    @staticmethod
    def content_digest(item: dict[str, Any]) -> str:
        # Queue claim is the one expected mechanical mutation; all input content stays fixed.
        return digest({k: v for k, v in item.items() if k != 'claim'})

    def claim(self, source: dict[str, Any], intent: dict[str, Any]) -> dict[str, Any]:
        connection = self.connections[source['connection']]
        client = self.client(source)
        actual = {**connection_binding(connection), **client.binding}
        if actual != intent['binding']:
            raise ToolError('source_identity_changed', 'original claim connection/subject differs', effect='unknown')
        headers = {'X-Workflow-Service-ID': actual['service_id'],
                   'X-Workflow-Principal-ID': actual['principal_id']}
        result = exchange(connection['endpoint'], os.environ[connection['token_env']], 'POST',
                          intent['path'], intent['body'], expected=headers)
        claim = result.get('claim')
        if (result.get('operation_id') != intent['body']['operation_id']
                or result.get('service_id') != source['service_id']
                or not isinstance(claim, dict) or result.get('task_id') != source['item_id']
                or claim.get('claimant') != actual['principal_id'] or type(result.get('replayed')) is not bool):
            raise ToolError('invalid_response', 'original claim receipt is incomplete', effect='unknown')
        return result
