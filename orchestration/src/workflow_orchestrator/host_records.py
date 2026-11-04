"""Host-owned technical admission/claim/start records. No business lifecycle."""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Iterator

from .host_contracts import ACTIVE, digest
from .run_lock import exclusive
from .tools_contracts import canonical, fail, now, outside_path

DDL = """
CREATE TABLE host_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE host_requests(request_id TEXT PRIMARY KEY, owner TEXT NOT NULL,
 body TEXT NOT NULL, run_id TEXT UNIQUE, record TEXT);
"""
SCHEMA = 'workflow-tools-host-2'


class HostRecords:
    def __init__(self, path: str | Path, binding: dict[str, Any]):
        self.path = outside_path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.binding = digest(binding)
        with exclusive(self.path.with_suffix('.init.lock'), wait_seconds=5):
            if not self.path.exists():
                with closing(sqlite3.connect(self.path, isolation_level=None)) as db:
                    db.execute('PRAGMA journal_mode=WAL')
                    db.executescript('BEGIN IMMEDIATE;\n' + DDL)
                    db.executemany('INSERT INTO host_meta VALUES (?,?)', [
                        ('schema', SCHEMA), ('service_id', str(uuid.uuid4())), ('binding', self.binding)])
                    db.commit()
            try:
                with closing(sqlite3.connect(self.path.as_uri() + '?mode=ro', uri=True)) as db:
                    meta = dict(db.execute('SELECT key,value FROM host_meta'))
                    self.service_id = str(uuid.UUID(meta['service_id']))
                    with closing(sqlite3.connect(':memory:')) as expected:
                        expected.executescript(DDL)
                        if self.inventory(db) != self.inventory(expected):
                            fail('schema_mismatch', 'unexpected host schema; no migration')
                    if meta.get('schema') != SCHEMA or meta.get('binding') != self.binding:
                        fail('host_binding_changed', 'original host configuration/authorization binding differs', status=409)
            except (sqlite3.Error, KeyError, ValueError):
                fail('schema_mismatch', 'requires original current host store; no repair')

    @staticmethod
    def inventory(db: sqlite3.Connection) -> list[Any]:
        return db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()

    @contextmanager
    def transaction(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True, isolation_level=None, timeout=5)
        try:
            db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
            meta = dict(db.execute('SELECT key,value FROM host_meta'))
            if meta != {'schema': SCHEMA, 'service_id': self.service_id, 'binding': self.binding}:
                fail('host_binding_changed', 'original host store identity changed', status=409)
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def lookup(self, request_id: str, owner: str, body: dict[str, Any] | None = None) -> dict[str, Any] | None:
        with self.transaction() as db:
            row = db.execute('SELECT owner,body,record FROM host_requests WHERE request_id=?', (request_id,)).fetchone()
        if row is None:
            return None
        if row[0] != owner or (body is not None and row[1] != canonical(body)):
            fail('idempotency_conflict', 'original request, caller, target, profiles or conditions differ', status=409)
        return json.loads(row[2]) if row[2] else None

    @staticmethod
    def records(db: sqlite3.Connection) -> list[dict[str, Any]]:
        return [json.loads(row[0]) for row in db.execute('SELECT record FROM host_requests WHERE record IS NOT NULL')]

    @staticmethod
    def busy(records: list[dict[str, Any]], maximum: int, idle_roles: list[str], exclude: str | None = None) -> bool:
        active = [r for r in records if r['state'] in ACTIVE and r['run_id'] != exclude]
        return len(active) >= maximum or any(r['role'] in idle_roles for r in active)

    def admit(self, owner: str, body: dict[str, Any], prepared: dict[str, Any], maximum: int) -> tuple[dict[str, Any] | None, bool]:
        with self.transaction(write=True) as db:
            row = db.execute('SELECT owner,body,record FROM host_requests WHERE request_id=?', (body['request_id'],)).fetchone()
            if row:
                if row[0] != owner or row[1] != canonical(body):
                    fail('idempotency_conflict', 'original request or caller differs', status=409)
                if row[2]:
                    return json.loads(row[2]), True
            else:
                db.execute('INSERT INTO host_requests VALUES (?,?,?,NULL,NULL)', (body['request_id'], owner, canonical(body)))
            if self.busy(self.records(db), maximum, body['conditions']['idle_roles']):
                return None, False
            record = {**prepared, 'request': body, 'run_id': 'run-' + uuid.uuid4().hex,
                      'owner': owner, 'state': 'accepted', 'phase': 'prepared', 'accepted_at': now(),
                      'claim': None, 'spawn_intent': None, 'process': None}
            db.execute('UPDATE host_requests SET run_id=?,record=? WHERE request_id=?',
                       (record['run_id'], canonical(record), body['request_id']))
            return record, False

    def save(self, record: dict[str, Any]) -> None:
        with self.transaction(write=True) as db:
            row = db.execute('SELECT run_id FROM host_requests WHERE request_id=?', (record['request']['request_id'],)).fetchone()
            if row != (record['run_id'],):
                fail('host_binding_changed', 'original run is absent', status=409)
            db.execute('UPDATE host_requests SET record=? WHERE request_id=?', (canonical(record), record['request']['request_id']))

    def start_intent(self, record: dict[str, Any], maximum: int) -> bool:
        with self.transaction(write=True) as db:
            current = json.loads(db.execute('SELECT record FROM host_requests WHERE run_id=?', (record['run_id'],)).fetchone()[0])
            if current['spawn_intent'] is not None:
                return False
            if self.busy(self.records(db), maximum, record['request']['conditions']['idle_roles'], record['run_id']):
                record.update(phase='waiting_conditions')
                db.execute('UPDATE host_requests SET record=? WHERE run_id=?', (canonical(record), record['run_id']))
                return False
            record.update(spawn_intent={'intent_id': 'spawn-' + uuid.uuid4().hex, 'created_at': now()}, phase='spawn_intent')
            db.execute('UPDATE host_requests SET record=? WHERE run_id=?', (canonical(record), record['run_id']))
            return True

    def all(self) -> list[dict[str, Any]]:
        with self.transaction() as db:
            return self.records(db)
