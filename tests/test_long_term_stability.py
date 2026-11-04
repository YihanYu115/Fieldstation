from __future__ import annotations

import sqlite3
from pathlib import Path

from issue_manager.store import Store


def pragma_value(connection: sqlite3.Connection, name: str) -> object:
    return connection.execute(f"PRAGMA {name}").fetchone()[0]


def test_product_connections_use_wal_and_full_synchronous(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    store = Store.initialize(root)
    second = Store(root)
    try:
        for connection in (store.conn, second.conn):
            assert str(pragma_value(connection, "journal_mode")).lower() == "wal"
            assert pragma_value(connection, "synchronous") == 2
            assert pragma_value(connection, "foreign_keys") == 1
            assert pragma_value(connection, "busy_timeout") == 5000
    finally:
        second.close()
        store.close()


def test_fresh_initialization_and_backup_target_are_full_synchronous(tmp_path: Path) -> None:
    root = tmp_path / "ledger"
    Store.initialize(root).close()
    with sqlite3.connect(root / "issue_ledger.sqlite") as connection:
        assert pragma_value(connection, "synchronous") == 2

    backup = Store.create_backup(root, label="stability-test", mode="metadata")
    backup_db = root / "backups" / backup["backup_id"] / "issue_ledger.sqlite"
    with sqlite3.connect(backup_db) as connection:
        assert pragma_value(connection, "synchronous") == 2
