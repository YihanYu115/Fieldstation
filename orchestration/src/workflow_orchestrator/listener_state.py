"""Local discovery cursors and candidate/action associations, never source authority."""
from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .tools_contracts import canonical, decode, fail, outside_path


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


class ListenerState:
    def __init__(self, path: str | Path):
        self.root = outside_path(path)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / 'listener.sqlite'
        with self.transaction() as db:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if tables and tables != {'metadata', 'watches', 'candidates', 'actions'}:
                fail('state_invalid', 'state directory contains an unrelated database')
            if not tables:
                db.execute('CREATE TABLE metadata (format TEXT NOT NULL)')
                db.execute("INSERT INTO metadata VALUES ('workflow-listener-2')")
                db.execute('CREATE TABLE watches (name TEXT PRIMARY KEY, declaration TEXT NOT NULL, '
                           'binding TEXT, initial TEXT NOT NULL, progress TEXT NOT NULL)')
                db.execute('CREATE TABLE candidates (id INTEGER PRIMARY KEY, watch TEXT NOT NULL, '
                           'item TEXT NOT NULL, source TEXT NOT NULL, record TEXT NOT NULL, UNIQUE(watch,item))')
                db.execute('CREATE TABLE actions (candidate INTEGER NOT NULL, name TEXT NOT NULL, '
                           'host TEXT NOT NULL, request_id TEXT NOT NULL UNIQUE, selection TEXT NOT NULL, '
                           'PRIMARY KEY(candidate,name))')
            if db.execute('SELECT format FROM metadata').fetchall() != [('workflow-listener-2',)]:
                fail('state_invalid', 'unsupported discovery state; never recreate it')

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        try:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def watch(self, name: str) -> dict[str, Any]:
        with self.transaction() as db:
            row = db.execute('SELECT declaration,binding,initial,progress FROM watches WHERE name=?', (name,)).fetchone()
        if row is None:
            fail('not_found', 'watch has not been declared')
        return {'declaration': decode(row[0]), 'binding': decode(row[1]) if row[1] else None,
                'initial': row[2], 'progress': decode(row[3])}

    def declare(self, name: str, declaration: dict[str, Any], initial: str) -> None:
        with self.transaction() as db:
            row = db.execute('SELECT declaration FROM watches WHERE name=?', (name,)).fetchone()
            if row and row[0] != canonical(declaration):
                fail('watch_binding_changed', 'watch source/filter/connection/credential differs; use a new watch name', status=409)
            db.execute('INSERT OR IGNORE INTO watches VALUES (?,?,NULL,?,?)',
                       (name, canonical(declaration), initial, canonical({'initialized': False})))

    def bind(self, name: str, binding: dict[str, Any]) -> None:
        with self.transaction() as db:
            original = db.execute('SELECT binding FROM watches WHERE name=?', (name,)).fetchone()[0]
            if original and original != canonical(binding):
                fail('watch_binding_changed', 'actual source service or subject differs', status=409)
            db.execute('UPDATE watches SET binding=? WHERE name=?', (canonical(binding), name))

    def save_page(self, name: str, progress: dict[str, Any], candidates: list[dict[str, Any]]) -> None:
        # Candidate insertion and cursor advancement commit together, including empty baselines.
        with self.transaction() as db:
            for candidate in candidates:
                db.execute('INSERT OR IGNORE INTO candidates(watch,item,source,record) VALUES (?,?,?,?)',
                           (name, candidate['source']['item_id'], canonical(candidate['source']), canonical(candidate['record'])))
            db.execute('UPDATE watches SET progress=? WHERE name=?', (canonical(progress), name))

    def associations(self, candidate: int | None = None) -> list[dict[str, Any]]:
        with self.transaction() as db:
            sql = 'SELECT candidate,name,host,request_id,selection FROM actions'
            rows = db.execute(sql if candidate is None else sql + ' WHERE candidate=?',
                              () if candidate is None else (candidate,)).fetchall()
        return [dict(zip(('candidate', 'name', 'host', 'request_id', 'selection'), row)) for row in rows]
