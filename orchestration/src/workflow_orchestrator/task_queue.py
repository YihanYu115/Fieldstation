"""Independent immutable task Queue. Only this boundary opens its own SQLite."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Iterator

from .tools_contracts import (
    Principal,
    ToolError,
    canonical,
    decode,
    fail,
    fields,
    identifier,
    now,
    outside_path,
    references,
    text,
)

DDL = """
CREATE TABLE tool_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE tasks(sequence INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT UNIQUE NOT NULL,
 issue_id TEXT NOT NULL, instructions TEXT NOT NULL, input_refs TEXT NOT NULL,
 experimenter_profile TEXT NOT NULL, author TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE claims(task_id TEXT PRIMARY KEY REFERENCES tasks(task_id), claim_id TEXT UNIQUE NOT NULL,
 claimant TEXT NOT NULL, claimed_at TEXT NOT NULL);
CREATE TABLE replies(sequence INTEGER PRIMARY KEY AUTOINCREMENT, reply_id TEXT UNIQUE NOT NULL,
 task_id TEXT NOT NULL REFERENCES tasks(task_id), text TEXT NOT NULL, refs TEXT NOT NULL,
 author TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX replies_task ON replies(task_id, sequence);
CREATE INDEX tasks_issue ON tasks(issue_id, sequence);
CREATE TABLE receipts(operation_id TEXT PRIMARY KEY, principal_id TEXT NOT NULL,
 action TEXT NOT NULL, target TEXT NOT NULL, body TEXT NOT NULL, receipt TEXT NOT NULL);
"""
SCHEMA = 'workflow-tools-queue-3'


class TaskQueue:
    def __init__(self, path: str | Path):
        self.path = outside_path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
            with closing(sqlite3.connect(self.path, isolation_level=None)) as db:
                db.execute('PRAGMA journal_mode=WAL')
                db.executescript('BEGIN IMMEDIATE;\n' + DDL)
                db.executemany('INSERT INTO tool_meta VALUES (?,?)', [
                    ('schema', SCHEMA), ('service_id', str(uuid.uuid4())),
                    ('cursor_key', uuid.uuid4().hex + uuid.uuid4().hex),
                ])
                db.commit()
        try:
            with closing(sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True)) as db:
                meta = dict(db.execute('SELECT key,value FROM tool_meta'))
                if meta.get('schema') != SCHEMA:
                    fail('schema_mismatch', 'requires an independent current Queue; no migration')
                self.service_id = str(uuid.UUID(meta['service_id']))
                self._cursor_key = bytes.fromhex(meta['cursor_key'])
                self._inventory = self._schema(db)
                with closing(sqlite3.connect(':memory:')) as expected:
                    expected.executescript(DDL)
                    if self._inventory != self._schema(expected):
                        fail('schema_mismatch', 'unexpected Queue tables, indexes or triggers')
        except (sqlite3.Error, KeyError, ValueError) as exc:
            raise ToolError('schema_mismatch', 'Queue is not current; no initialization or repair') from exc

    @staticmethod
    def _schema(db: sqlite3.Connection) -> list[Any]:
        return db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master "
                          "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()

    @contextmanager
    def transaction(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True,
                             timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
            meta = dict(db.execute('SELECT key,value FROM tool_meta'))
            if meta.get('service_id') != self.service_id or meta.get('schema') != SCHEMA:
                fail('service_identity_changed', 'original Queue binding changed', status=409)
            # Opening an existing store never migrates, initializes or repairs it.
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def identity(self, principal: Principal) -> dict[str, Any]:
        with self.transaction():
            return {'service_id': self.service_id, 'modules': ['queue'], 'schema': SCHEMA,
                    'principal_id': principal.principal_id}

    @staticmethod
    def _task(db: sqlite3.Connection, task_id: str) -> dict[str, Any]:
        row = db.execute('SELECT * FROM tasks WHERE task_id=?', (task_id,)).fetchone()
        if row is None:
            fail('not_found', 'task not found', status=404)
        item = dict(row)
        item.pop('sequence')
        item['input_refs'] = json.loads(item['input_refs'])
        claim = db.execute('SELECT * FROM claims WHERE task_id=?', (task_id,)).fetchone()
        item['claim'] = dict(claim) if claim else None
        return item

    def write(self, principal: Principal, action: str, target: str,
              body: dict[str, Any]) -> dict[str, Any]:
        if action == 'publish_task':
            fields(body, {'operation_id', 'issue_id', 'instructions', 'experimenter_profile'},
                   {'input_refs'})
            issue = text(body['issue_id'], 'issue_id')
            normalized = {'operation_id': identifier(body['operation_id'], 'operation_id'),
                          'issue_id': issue, 'instructions': text(body['instructions'], 'instructions', 16000),
                          'experimenter_profile': identifier(body['experimenter_profile'], 'experimenter_profile'),
                          'input_refs': references(body.get('input_refs', []))}
        elif action in {'claim_task', 'reply_task'}:
            identifier(target, 'task_id')
            fields(body, {'operation_id'} | ({'text'} if action == 'reply_task' else set()),
                   {'refs'} if action == 'reply_task' else set())
            normalized = {'operation_id': identifier(body['operation_id'], 'operation_id')}
            if action == 'reply_task':
                normalized.update(text=text(body['text'], 'text', 2000),
                                  refs=references(body.get('refs', [])))
            issue = None
        else:
            fail('invalid_input', 'unsupported Queue write')
        operation_id = normalized['operation_id']
        encoded = canonical(normalized)
        principal.require(action, issue)
        with self.transaction(write=True) as db:
            if action != 'publish_task':
                issue = self._task(db, target)['issue_id']
                principal.require(action, issue)
            old = db.execute('SELECT * FROM receipts WHERE operation_id=?', (operation_id,)).fetchone()
            if old:
                if (old['principal_id'], old['action'], old['target'], old['body']) != (
                        principal.principal_id, action, target, encoded):
                    fail('idempotency_conflict', 'original operation identity, target or content differs',
                         status=409)
                return {**json.loads(old['receipt']), 'replayed': True}
            if action == 'publish_task':
                task_id = 'task-' + uuid.uuid4().hex
                db.execute('INSERT INTO tasks(task_id,issue_id,instructions,input_refs,experimenter_profile,'
                           'author,created_at) VALUES (?,?,?,?,?,?,?)',
                           (task_id, issue, normalized['instructions'], canonical(normalized['input_refs']),
                            normalized['experimenter_profile'],
                            principal.principal_id, now()))
                receipt: dict[str, Any] = {'task': self._task(db, task_id), 'task_id': task_id,
                           'read_path': '/v1/queue/tasks/' + task_id}
            elif action == 'claim_task':
                if db.execute('SELECT 1 FROM claims WHERE task_id=?', (target,)).fetchone():
                    fail('already_claimed', 'task already has a claimant; no takeover', status=409)
                claim = {'task_id': target, 'claim_id': 'claim-' + uuid.uuid4().hex,
                         'claimant': principal.principal_id, 'claimed_at': now()}
                db.execute('INSERT INTO claims VALUES (?,?,?,?)', tuple(claim.values()))
                receipt = {'task_id': target, 'claim': claim,
                           'read_path': '/v1/queue/tasks/' + target}
            else:
                reply = {'reply_id': 'reply-' + uuid.uuid4().hex, 'task_id': target,
                         'text': normalized['text'], 'refs': normalized['refs'],
                         'author': principal.principal_id, 'created_at': now()}
                db.execute('INSERT INTO replies(reply_id,task_id,text,refs,author,created_at) '
                           'VALUES (?,?,?,?,?,?)', (reply['reply_id'], target, reply['text'],
                                                    canonical(reply['refs']), reply['author'],
                                                    reply['created_at']))
                receipt = {'task_id': target, 'reply': reply,
                           'read_path': '/v1/queue/tasks/' + target + '/replies'}
            receipt.update(operation_id=operation_id, service_id=self.service_id, replayed=False)
            db.execute('INSERT INTO receipts VALUES (?,?,?,?,?,?)',
                       (operation_id, principal.principal_id, action, target, encoded, canonical(receipt)))
            return receipt

    def get(self, principal: Principal, task_id: str) -> dict[str, Any]:
        principal.require('get_task')
        identifier(task_id, 'task_id')
        with self.transaction() as db:
            item = self._task(db, task_id)
            principal.require('get_task', item['issue_id'])
            return item

    def _cursor(self, value: dict[str, Any]) -> str:
        payload = canonical(value).encode()
        signature = hmac.new(self._cursor_key, payload, hashlib.sha256).hexdigest().encode()
        return base64.urlsafe_b64encode(signature + b'.' + payload).decode()

    def _page(self, cursor: str | None, context: dict[str, Any], watermark: Any) -> int:
        if cursor is None:
            return 0
        try:
            signature, payload = base64.b64decode(cursor, altchars=b'-_', validate=True).split(b'.', 1)
            expected = hmac.new(self._cursor_key, payload, hashlib.sha256).hexdigest().encode()
            value = decode(payload)
            if not hmac.compare_digest(signature, expected) or value['context'] != context:
                raise ValueError()
            if value['watermark'] != watermark:
                fail('snapshot_changed', 'collection changed; restart pagination', status=409)
            if type(value['after']) is not int or value['after'] < 0:
                raise ValueError()
            return int(value['after'])
        except (ValueError, KeyError, TypeError):
            fail('invalid_cursor', 'cursor does not match this service, principal or query')

    def list(self, principal: Principal, *, issue_id: str | None = None,
             claimed: bool | None = None, task_id: str | None = None,
             cursor: str | None = None, limit: int = 20) -> dict[str, Any]:
        action = 'list_task_replies' if task_id else 'list_tasks'
        principal.require(action, issue_id)
        if type(limit) is not int or not 1 <= limit <= 50 or type(claimed) not in {bool, type(None)}:
            fail('invalid_input', 'limit must be 1..50 and claimed must be true/false')
        if cursor is not None:
            text(cursor, 'cursor', 8192)
        context = {'service_id': self.service_id, 'principal': principal.principal_id,
                   'action': action, 'issue_id': issue_id,
                   'claimed': claimed, 'task_id': task_id}
        with self.transaction() as db:
            if task_id:
                principal.require(action, self._task(db, identifier(task_id, 'task_id'))['issue_id'])
                watermark = db.execute('SELECT COALESCE(MAX(sequence),0) FROM replies WHERE task_id=?',
                                       (task_id,)).fetchone()[0]
                after = self._page(cursor, context, watermark)
                rows = db.execute('SELECT * FROM replies WHERE task_id=? AND sequence>? '
                                  'ORDER BY sequence LIMIT ?', (task_id, after, limit + 1)).fetchall()
                items = []
                for row in rows[:limit]:
                    item = dict(row)
                    item.pop('sequence')
                    item['refs'] = json.loads(item['refs'])
                    items.append(item)
            else:
                watermark = list(db.execute('SELECT (SELECT COALESCE(MAX(sequence),0) FROM tasks),'
                                            '(SELECT COUNT(*) FROM claims)').fetchone())
                after = self._page(cursor, context, watermark)
                where = 't.sequence>?'
                values: list[Any] = [after]
                if issue_id is not None:
                    where += ' AND t.issue_id=?'
                    values.append(issue_id)
                if claimed is not None:
                    where += ' AND c.task_id IS ' + ('NOT NULL' if claimed else 'NULL')
                rows = db.execute('SELECT t.* FROM tasks t LEFT JOIN claims c USING(task_id) WHERE '
                                  + where + ' ORDER BY t.sequence LIMIT ?',
                                  (*values, limit + 1)).fetchall()
                items = [self._task(db, row['task_id']) for row in rows[:limit]]
            next_cursor = None
            if len(rows) > limit:
                next_cursor = self._cursor({'context': context, 'watermark': watermark,
                                            'after': rows[limit - 1]['sequence']})
            return {'items': items, 'limit': limit, 'next_cursor': next_cursor,
                    'service_id': self.service_id}
