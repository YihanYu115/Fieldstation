"""Test-only direct foreground CLI. Never contacts a real model or instrument."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

# The test host copies the existing process helper into this isolated runtime directory.
from synthetic_process_helper import creation_identity


def main():
    mode = sys.argv[1]
    source = Path(os.environ['WORKFLOW_SESSION_INPUT'])
    context = json.loads(source.read_text(encoding='utf-8'))
    session = source.parent
    identity = creation_identity(type('Self', (), {'pid': os.getpid(), '_handle': __import__('ctypes').windll.kernel32.GetCurrentProcess()})())
    with (session / 'starts.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'identity': identity, 'context': context}) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    if mode == 'hold':
        deadline = time.monotonic() + 180
        while not (session / 'exit.flag').exists() and time.monotonic() < deadline:
            time.sleep(.05)
    results = []
    for surface in context['mcp'] if mode in {'readonly', 'business', 'failure', 'omit', 'catalog_cycle'} else []:
        next_id = 0
        def rpc(method, params):
            nonlocal next_id
            next_id += 1
            body = json.dumps({'jsonrpc': '2.0', 'id': next_id, 'method': method, 'params': params}).encode('utf-8')
            request = Request(surface['url'], body, headers={'Content-Type': 'application/json',
                'Accept': 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-03-26',
                'Authorization': 'Bearer ' + os.environ[surface['bearer_token_env']]})
            with urlopen(request, timeout=20) as response:
                value = json.load(response)
            assert 'error' not in value, value
            return value['result']
        def call(name, arguments):
            result = rpc('tools/call', {'name': name, 'arguments': arguments})
            return json.loads(result['content'][0]['text'])
        try:
            rpc('initialize', {'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'synthetic-host-cli', 'version': '1'}})
            catalog = rpc('tools/list', {})
            results.append({'surface': surface['surface'], 'name': surface.get('name', surface['surface']), 'catalog': catalog})
            if mode == 'catalog_cycle':
                if surface['surface'] == 'host':
                    results.append({'name': surface.get('name', 'host'), 'catalog_result': call('list_host_catalog', {'queue_only': True})})
                elif surface['surface'] == 'queue':
                    for profile in ('experimenter', 'scientist'):
                        results.append({'published': call('publish_task', {'instructions': 'Synthetic work', 'experimenter_profile': profile})})
                continue
            if surface['surface'] == 'queue':
                results.append(call('get_task', {'task_id': context['task_id']}))
                if mode != 'readonly':
                    results.append(call('reply_task', {'text': 'Synthetic scan failed; raw trace is retained.'}))
                results.append(call('list_task_replies', {}))
                results.append(call('get_task', {'task_id': 'not-permitted-or-missing'}))
            if surface['surface'] == 'im':
                results.append(call('list_field_packets', {}))
                if mode != 'readonly':
                    results.extend([call('submit_field_packet', {'content': 'Failed synthetic scan; no fit.'}),
                                    call('submit_field_packet', {'content': 'Partial synthetic trace; temperature unknown.', 'issue_id': 'B'}),
                                    call('save_contribution', {'kind': 'observation', 'source': 'urn:synthetic:failed', 'text': 'denied', 'reason': 'actual permission check'})])
            if surface['surface'] == 'board':
                results.append(call('get_message', {'message_id': context['source']['item_id']}))
        finally:
            pass
    (session / 'results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
    return 3 if mode == 'failure' else 0


if __name__ == '__main__':
    raise SystemExit(main())
