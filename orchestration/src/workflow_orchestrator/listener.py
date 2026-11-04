"""Independent read-only HTTP discovery. No scripts, host connection or source writes."""
from __future__ import annotations

import math
import os
import time
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

from .listener_state import ListenerState, digest
from .run_lock import exclusive
from .tools_contracts import ToolError, decode, fail, fields, identifier, text

KINDS = {'queue.task', 'board.message', 'board.handoff', 'inbox.packet'}


def load_connections(value: dict[str, Any] | str | Path) -> dict[str, Any]:
    if isinstance(value, (str, Path)):
        value = decode(Path(value).read_text(encoding='utf-8'))
    config = fields(value, {'connections'})
    if not isinstance(config['connections'], dict):
        fail('invalid_configuration', 'connections must be a map')
    # Only an actually used connection resolves its authentication environment.
    return dict(config['connections'])


def local_binding(value: Any) -> dict[str, str]:
    fields(value, {'endpoint', 'token_env'})
    endpoint = text(value['endpoint'], 'endpoint', 2048).rstrip('/')
    url = urlsplit(endpoint)
    if (url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password
            or url.path or url.query or url.fragment):
        fail('invalid_configuration', 'connection must be a fixed HTTP(S) origin')
    name = identifier(value['token_env'], 'token_env')
    token = os.environ.get(name, '')
    if not token or not token.isascii() or any(c.isspace() for c in token):
        fail('invalid_configuration', 'host must inject the used connection token: ' + name)
    return {'endpoint': endpoint, 'token_env': name, 'credential_sha256': digest(token)}


class Listener:
    def __init__(self, connections: dict[str, Any] | str | Path, state: str | Path, *,
                 page_size: int = 50, max_pages: int = 20, timeout: float = 5):
        self.connections = load_connections(connections)
        self.state = ListenerState(state)
        if type(page_size) is not int or not 1 <= page_size <= 50:
            fail('invalid_configuration', 'page_size must be 1..50')
        if type(max_pages) is not int or not 1 <= max_pages <= 100:
            fail('invalid_configuration', 'max_pages must be 1..100 per watch per scan')
        if not 0 < timeout <= 60:
            fail('invalid_configuration', 'timeout must be in (0,60] seconds')
        self.page_size, self.max_pages, self.timeout = page_size, max_pages, timeout
        self.watches: list[str] = []

    def listen(self, watch_key: str, *, kind: str, connection: str, issue_id: str,
               initial: str | None = None) -> None:
        identifier(watch_key, 'watch_key')
        identifier(connection, 'connection')
        text(issue_id, 'issue_id')
        if kind not in KINDS or connection not in self.connections:
            fail('invalid_configuration', 'unknown listener kind or connection')
        initial = initial or ('from_start' if kind == 'queue.task' else 'new_only')
        if initial not in {'new_only', 'from_start'} or (kind == 'queue.task' and initial != 'from_start'):
            fail('invalid_configuration', 'Queue requires from_start; Board/Inbox accept new_only or from_start')
        self.state.declare(watch_key, {'kind': kind, 'connection': connection, 'issue_id': issue_id,
                                     'local': local_binding(self.connections[connection])}, initial)
        if watch_key not in self.watches:
            self.watches.append(watch_key)

    def _client(self, name: str, watch: dict[str, Any]) -> Any:
        d = watch['declaration']
        config = self.connections[d['connection']]
        if local_binding(config) != d['local']:
            fail('watch_binding_changed', 'original source connection or credential differs', status=409)
        path = self.state.root / 'sources' / (digest(name) + '.json')
        args = (d['local']['endpoint'], os.environ[d['local']['token_env']], path)
        client: Any
        if d['kind'] == 'queue.task':
            from .tools_client import ToolsClient
            client = ToolsClient(*args, timeout=self.timeout)
        elif d['kind'].startswith('board.'):
            from .board_client import BoardClient
            client = BoardClient(*args, token_env=d['local']['token_env'], timeout=self.timeout)
        else:
            from .im_client import IMClient
            client = IMClient(*args, token_env=d['local']['token_env'], timeout=self.timeout)
        self.state.bind(name, client.binding)
        return client

    @staticmethod
    def _candidate(name: str, d: dict[str, Any], binding: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
        key = 'task_id' if d['kind'] == 'queue.task' else 'packet_id' if d['kind'] == 'inbox.packet' else 'message_id'
        item = identifier(record.get(key), key)
        if record.get('issue_id') != d['issue_id']:
            fail('invalid_response', 'source returned a record outside the requested Issue')
        source = {k: d[k] for k in ('kind', 'connection', 'issue_id')}
        source['item_id'] = item
        if d['kind'] != 'inbox.packet':
            source['service_id'] = binding['service_id']
        return {'watch_key': name, 'source': source, 'record': record}

    def _scan(self, name: str) -> dict[str, Any]:
        with exclusive(self.state.root / 'locks' / ('watch-' + digest(name)), wait_seconds=5):
            watch = self.state.watch(name)
            client = self._client(name, watch)
            d, p = watch['declaration'], watch['progress']
            kind = d['kind']
            found = 0
            for page_number in range(self.max_pages):
                try:
                    if kind == 'queue.task':
                        page = client.read('list_tasks', issue_id=d['issue_id'], claimed=False,
                                           limit=self.page_size, cursor=p.get('cursor'))
                    elif kind.startswith('board.'):
                        page = client.read('list_handoffs' if kind == 'board.handoff' else 'list_messages',
                                           issue_id=d['issue_id'], after_sequence=p.get('page_after', p.get('after', 0)),
                                           limit=self.page_size, cursor=p.get('cursor'),
                                           **({'status': 'pending'} if kind == 'board.handoff' else {}))
                    else:
                        page = client.list_field_packets(d['issue_id'], limit=self.page_size,
                                                         after_packet_id=p.get('cursor'))
                except ToolError as exc:
                    if exc.code == 'snapshot_changed' and kind != 'inbox.packet':
                        p.pop('cursor', None)
                        p.pop('page_after', None)
                        self.state.save_page(name, p, [])
                        continue
                    raise
                rows = page.get('items')
                if ('next_cursor' not in page or not isinstance(rows, list)
                        or any(not isinstance(r, dict) for r in rows) or len(rows) > self.page_size):
                    fail('invalid_response', 'source returned an invalid finite page')
                candidates = []
                if kind == 'inbox.packet':
                    # IM puts Issue context on the page envelope, not each index row.
                    if page.get('issue_id') != d['issue_id']:
                        fail('invalid_response', 'Inbox page belongs to another Issue')
                    rows = [{**row, 'issue_id': page['issue_id']} for row in rows]
                    if not p['initialized'] and watch['initial'] == 'new_only':
                        for row in rows:
                            self._candidate(name, d, client.binding, row)
                        p.update(initialized=True, head=rows[0]['packet_id'] if rows else None)
                        self.state.save_page(name, p, [])
                        return {'watch_key': name, 'pages': page_number + 1, 'saved': 0, 'complete': True}
                    if 'crawl_head' not in p:
                        p['crawl_head'] = rows[0]['packet_id'] if rows else p.get('head')
                    reached = False
                    for row in rows:
                        if row.get('packet_id') == p.get('head'):
                            reached = True
                            break
                        candidates.append(self._candidate(name, d, client.binding, row))
                    cursor = None if reached else page.get('next_cursor')
                    if not cursor:
                        p.update(initialized=True, head=p.pop('crawl_head'))
                else:
                    baseline = not p['initialized'] and watch['initial'] == 'new_only'
                    for row in rows:
                        candidate = self._candidate(name, d, client.binding, row)
                        if not baseline and (kind != 'board.handoff' or row.get('recipient') == client.binding['recipient']):
                            candidates.append(candidate)
                    cursor = page.get('next_cursor')
                    if kind.startswith('board.'):
                        p.setdefault('page_after', p.get('after', 0))
                        sequence = page.get('next_sequence')
                        if type(sequence) is not int or sequence < p.get('after', 0):
                            fail('invalid_response', 'Board sequence regressed')
                        p['after'] = sequence
                    if not cursor:
                        p['initialized'] = True
                        p.pop('page_after', None)
                if cursor is not None and (not isinstance(cursor, str) or not cursor or cursor == p.get('cursor')):
                    fail('invalid_response', 'source cursor did not advance')
                p['cursor'] = cursor
                self.state.save_page(name, p, candidates)
                found += len(candidates)
                if not cursor:
                    return {'watch_key': name, 'pages': page_number + 1, 'saved': found, 'complete': True}
            return {'watch_key': name, 'pages': self.max_pages, 'saved': found, 'complete': False}

    def scan_once(self) -> list[dict[str, Any]]:
        results = []
        for name in self.watches:
            try:
                results.append(self._scan(name))
            except ToolError as exc:
                results.append({'watch_key': name, **exc.result()})
        return results

    def pending(self, watch_key: str, action_key: str | None = None) -> Iterator[dict[str, Any]]:
        self.state.watch(watch_key)
        after = 0
        while True:
            with self.state.transaction() as db:
                rows = db.execute('SELECT id,source,record FROM candidates WHERE watch=? AND id>? ORDER BY id LIMIT 100',
                                  (watch_key, after)).fetchall()
            if not rows:
                return
            for key, source, record in rows:
                after = key
                yield {'watch_key': watch_key, 'source': decode(source), 'record': decode(record)}

    def poll(self, every: float = 5) -> Iterator[Any]:
        if isinstance(every, bool) or not isinstance(every, (int, float)) or not math.isfinite(every) or not .05 <= every <= 3600:
            fail('invalid_configuration', 'poll interval must be .05..3600 seconds')
        while True:
            yield self.scan_once()
            time.sleep(every)

    def close(self) -> None:
        """Connections and OS locks are scoped to calls; no background workers are owned."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
