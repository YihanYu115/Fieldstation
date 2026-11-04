"""Finite MCP surfaces: natural business arguments and journal-owned action identities."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Any

from mcp import types
from mcp.server import Server

from .tools_client import ToolsClient
from .tools_contracts import (
    ACTIONS,
    WRITES,
    ToolError,
    canonical,
    decode,
    fail,
    fields,
    identifier,
    outside_path,
    references,
    text,
)

STRING = {'type': 'string', 'minLength': 1, 'maxLength': 128}
ISSUE = {'type': 'string', 'minLength': 1, 'maxLength': 200}
REFS = {'type': 'array', 'maxItems': 30,
        'items': {'type': 'string', 'minLength': 1, 'maxLength': 2048}}
PAGE = {'cursor': {'type': 'string', 'minLength': 1, 'maxLength': 8192},
        'limit': {'type': 'integer', 'minimum': 1, 'maximum': 50, 'default': 20}}
IM_WRITES = {'create_issue', 'submit_field_packet', 'curate_field_item', 'record_field_review',
             'save_contribution', 'create_relation', 'withdraw_relation', 'restore_relation', 'split_evidence',
             'save_working_conclusion', 'recover_delivery', 'set_conclusion_rule'}
SPECS: dict[str, tuple[str, dict[str, Any], set[str]]] = {
    'publish_task': ('Publish an immutable work instruction; it is not a completion record.',
                     {'issue_id': ISSUE, 'instructions': {'type': 'string', 'minLength': 1, 'maxLength': 16000},
                      'input_refs': {**REFS, 'description': 'References to actual input material.'}, 'experimenter_profile': {**STRING, 'description': 'Selected Queue-capable experimenter configuration; checked by the target Host before claiming.'}},
                     {'instructions', 'experimenter_profile'}),
    'list_tasks': ('Read tasks, optionally filtered by whether they have a claimant. Page limit 1..50.',
                   {'issue_id': {**ISSUE, 'type': ['string', 'null'], 'description': 'Omitted uses the host default; null queries all Issues.'}, 'claimed': {'type': 'boolean', 'description': 'Filter by actual claim; claiming does not mean completion.'}, **PAGE}, set()),
    'get_task': ('Read a task instruction, materials, profiles and actual claim.',
                 {'task_id': STRING}, {'task_id'}),
    'claim_task': ('Atomically claim once as your authenticated principal. A new claim cannot take over.',
                   {'task_id': STRING}, {'task_id'}),
    'reply_task': ('Append a short factual reply; this does not mark completion or release anything.',
                   {'task_id': {**STRING, 'description': '要回复的实际 task_id；省略时使用宿主绑定的默认任务。'}, 'text': {'type': 'string', 'minLength': 1, 'maxLength': 2000, 'description': '实际的简短回复；不表示任务完成。'},
                    'refs': {**REFS, 'description': '可选的真实结果或材料引用。'}}, {'text'}),
    'list_task_replies': ('Read append-only replies in pages. Page limit 1..50.',
                          {'task_id': {**STRING, 'description': '要读取回复的实际 task_id；省略时使用宿主绑定的默认任务。'}, **PAGE}, set()),
}


def load_profile(path: str | Path) -> dict[str, Any]:
    value = fields(decode(Path(path).read_text(encoding='utf-8')),
                   {'connection', 'tools', 'journal_path'}, {'default_issue_id', 'default_task_id', 'surface', 'tree_connection'})
    fields(value['connection'], {'endpoint', 'token_env'})
    surface = value.get('surface', 'queue')
    if surface not in {'queue', 'im', 'board', 'host'}:
        fail('invalid_configuration', 'surface must be queue, im, board or host')
    if 'tree_connection' in value:
        if surface != 'board':
            fail('invalid_configuration', 'tree_connection is only valid for Board')
        fields(value['tree_connection'], {'endpoint', 'token_env'})
    if surface == 'host':
        allowed = {'list_host_catalog'}
        if 'default_task_id' in value:
            fail('invalid_configuration', 'Host profile has no default_task_id')
    elif surface == 'im':
        from .im_tools import SPECS as im_specs
        allowed = set(im_specs)
        if 'default_task_id' in value:
            fail('invalid_configuration', 'IM profile has no default_task_id')
    elif surface == 'board':
        from .board_facade import SPECS as board_specs
        allowed = set(board_specs)
        if 'default_task_id' in value:
            fail('invalid_configuration', 'Board profile has no task default')
    else:
        allowed = set(ACTIONS)
    if (not isinstance(value['tools'], list) or not value['tools']
            or any(not isinstance(name, str) or name not in allowed for name in value['tools'])
            or len(set(value['tools'])) != len(value['tools'])):
        fail('invalid_configuration', 'tools must be a nonempty unique subset of the selected surface tools')
    outside_path(value['journal_path'])
    if 'default_issue_id' in value:
        text(value['default_issue_id'], 'default_issue_id')
    if 'default_task_id' in value:
        identifier(value['default_task_id'], 'default_task_id')
    return value


class HostCatalogTools:
    def __init__(self, profile: dict[str, Any]):
        self.profile = profile

    def definitions(self) -> list[dict[str, Any]]:
        return [{'name': 'list_host_catalog',
                 'description': 'Read configurations visible to this caller on the configured Host; visibility does not grant launch or IM permissions.',
                 'inputSchema': {'type': 'object', 'properties': {'queue_only': {'type': 'boolean'}},
                                 'additionalProperties': False}}]

    def call(self, name: str, arguments: Any) -> dict[str, Any]:
        if name != 'list_host_catalog' or name not in self.profile['tools']:
            fail('tool_not_enabled', 'tool is not enabled in the host profile')
        fields(arguments, set(), {'queue_only'})
        from .host_catalog import read_catalog
        return read_catalog(self.profile['connection'], queue_only=arguments.get('queue_only', False))


class QueueTools:
    def __init__(self, client: ToolsClient, profile: dict[str, Any]):
        self.client, self.profile = client, profile

    def definitions(self) -> list[dict[str, Any]]:
        definitions = []
        for name in self.profile['tools']:
            description, properties, required = SPECS[name]
            required = set(required)
            if name in {'publish_task', 'list_tasks'} and not self.profile.get('default_issue_id'):
                if name == 'publish_task':
                    required.add('issue_id')
            if name in {'reply_task', 'list_task_replies'} and not self.profile.get('default_task_id'):
                required.add('task_id')
            definitions.append({'name': name, 'description': description,
                                'inputSchema': {'type': 'object', 'properties': properties,
                                                'required': sorted(required), 'additionalProperties': False}})
        return definitions

    def call(self, name: str, arguments: Any) -> dict[str, Any]:
        if name not in self.profile['tools']:
            fail('tool_not_enabled', 'tool is not enabled in the host profile')
        spec = next(item for item in self.definitions() if item['name'] == name)['inputSchema']
        from .mcp_contract import ContractError
        from .mcp_contract import validate as validate_schema_arguments
        try:
            validate_schema_arguments(self.definitions(), name, arguments)
        except ContractError as exc:
            raise ToolError('invalid_input', str(exc), fields=exc.fields,
                            fields_truncated=exc.fields_truncated) from exc
        arguments = fields(arguments, set(spec['required']), set(spec['properties']))
        arguments = dict(arguments)
        for key, value in arguments.items():
            rule = spec['properties'][key]
            kind = rule['type']
            if name == 'list_tasks' and key == 'issue_id' and value is None:
                continue
            if kind == 'string' or (name == 'list_tasks' and key == 'issue_id'):
                if isinstance(value, str) and not value.strip():
                    raise ToolError('invalid_input', key + ' must contain non-whitespace text',
                                    fields=[{'path': '/' + key, 'rule': 'nonWhitespace'}])
                text(value, key, rule['maxLength'])
            elif kind == 'array':
                for index, item in enumerate(value):
                    if isinstance(item, str) and not item.strip():
                        raise ToolError('invalid_input', key + ' items must contain non-whitespace text',
                                        fields=[{'path': '/' + key + '/' + str(index), 'rule': 'nonWhitespace'}])
                references(value)
            elif kind == 'boolean' and type(value) is not bool:
                fail('invalid_input', key + ' must be boolean')
            elif kind == 'integer' and (type(value) is not int or not 1 <= value <= 50):
                fail('invalid_input', 'limit must be 1..50')
        if name in {'publish_task', 'list_tasks'} and 'issue_id' not in arguments:
            if self.profile.get('default_issue_id') is not None:
                arguments['issue_id'] = self.profile['default_issue_id']
            elif name == 'list_tasks':
                arguments['issue_id'] = None
        if name in {'reply_task', 'list_task_replies'} and 'task_id' not in arguments:
            arguments['task_id'] = self.profile['default_task_id']
        if name in WRITES:
            return self.client.write(name, **arguments)
        result = self.client.read(name, **arguments)
        if name == 'list_tasks' and 'get_task' in self.profile['tools']:
            for item in result.get('items', []):
                if isinstance(item.get('task_id'), str) and item['task_id']:
                    item['read'] = {'tool': 'get_task', 'arguments': {'task_id': item['task_id']}}
        if name == 'get_task':
            task_id = result.get('task_id')
            if isinstance(task_id, str) and task_id:
                if 'list_task_replies' in self.profile['tools']:
                    result['replies_read'] = {'tool': 'list_task_replies', 'arguments': {'task_id': task_id}}
                if 'reply_task' in self.profile['tools']:
                    result['reply'] = {'tool': 'reply_task', 'arguments': {'task_id': task_id}, 'required_arguments': ['text']}
        if name in {'list_tasks', 'list_task_replies'}:
            cursor = result.get('next_cursor')
            result['next_read'] = ({'tool': name, 'arguments': {**arguments, 'cursor': cursor}}
                                   if cursor else None)
        return result


def create_server(profile: dict[str, Any]) -> Server:
    client: Any
    facade: Any
    if profile.get('surface') == 'host':
        client = None
        facade = HostCatalogTools(profile)
    elif profile.get('surface', 'queue') == 'im':
        from .im_client import IMClient
        from .im_tools import IMTools
        client = IMClient.from_connection(profile['connection'], profile['journal_path'])
        facade = IMTools(client, profile)
    elif profile.get('surface') == 'board':
        from .board_client import BoardClient
        from .board_facade import BoardTools
        client = BoardClient.from_connection(profile['connection'], profile['journal_path'])
        facade = BoardTools(client, profile)
    else:
        client = ToolsClient.from_connection(profile['connection'], profile['journal_path'])
        facade = QueueTools(client, profile)
    # Recovery uses saved original POSTs, before accepting genuinely new tool calls.
    # A single unresolved action does not prevent independent legal contributions.
    for result in client.recover_pending() if client is not None else []:
        summary = result.get('error', {})
        print(canonical({'recovered_operation_id': result.get('operation_id', result.get('delivery_id', summary.get('operation_id'))),
                         'code': summary.get('code', 'confirmed')}), file=sys.stderr)
    from .module_instructions import MODULE_INSTRUCTIONS
    surface = profile.get('surface', 'queue')
    server = Server('workflow-tools', version='1', instructions=MODULE_INSTRUCTIONS.get(surface, 'Read the configured Host catalog. Visibility does not grant launch or IM permissions.'))
    lock = asyncio.Lock()

    @server.list_tools()
    async def list_tools():
        return [types.Tool(**value) for value in facade.definitions()]

    async def execute_tool(name, arguments):
        async with lock:
            surface = profile.get('surface', 'queue')
            if surface == 'board':
                from .board_contracts import BOARD_WRITES
                is_read = name in profile['tools'] and name not in BOARD_WRITES
            elif surface == 'im':
                is_read = name in profile['tools'] and name not in IM_WRITES
            else:
                is_read = name in profile['tools'] and name not in WRITES
            try:
                result = await asyncio.to_thread(facade.call, name, arguments)
            except ToolError as exc:
                result = exc.result()
                if exc.effect == 'unknown' and surface in {'queue', 'board'}:
                    result['error']['guidance'] = 'Use host recovery for the original operation; do not submit a new action.'
                elif 'snapshot_changed' in exc.code:
                    result['error']['guidance'] = 'Restart reading from the first page with the same filters.'
            except ValueError as exc:
                from .mcp_contract import ContractError
                if isinstance(exc, ContractError):
                    result = ToolError(exc.code, str(exc)).result()
                    result['error']['fields'] = exc.fields
                    result['error']['fields_truncated'] = exc.fields_truncated
                    for key in ('budget', 'guidance', 'origin_candidates', 'next_step'):
                        if hasattr(exc, key):
                            result['error'][key] = getattr(exc, key)
                else:
                    result = (ToolError('read_error', 'Read failed; retry the same read').result() if is_read
                              else ToolError('tool_error', 'Write outcome could not be confirmed', effect='unknown').result())
                    if not is_read and surface in {'queue', 'board'}:
                        result['error']['guidance'] = 'Use host recovery for the original operation; do not submit a new action.'
            except Exception:
                result = (ToolError('read_error', 'Read failed; retry the same read').result() if is_read
                          else ToolError('tool_error', 'Write outcome could not be confirmed; recover the original action', effect='unknown').result())
                if not is_read and surface in {'queue', 'board'}:
                    result['error']['guidance'] = 'Use host recovery for the original operation; do not submit a new action.'
            return types.CallToolResult(isError=result.get('error') is not None, structuredContent=result,
                                        content=[types.TextContent(type='text', text=canonical(result))])

    tasks: set[asyncio.Task] = set()

    @server.call_tool(validate_input=False)
    async def call_tool(name, arguments):
        # The downstream journal owns the action even if the HTTP caller disconnects.
        task = asyncio.create_task(execute_tool(name, arguments))
        tasks.add(task)
        task.add_done_callback(tasks.discard)
        return await asyncio.shield(task)

    setattr(server, 'workflow_tasks', tasks)

    return server
