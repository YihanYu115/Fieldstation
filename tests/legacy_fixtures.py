"""Explicit historical ledgers for migration regression tests.

These helpers intentionally bypass ``Store.initialize``.  Product fresh
initialization is current-schema-only; migration tests still need a way to
construct an old-format fixture without making that format a supported fresh
initialization target.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from issue_manager import IssueManager
from issue_manager import store as store_module
from issue_manager.default_policy import default_policy_text
from issue_manager.store import Store


def _prepare_root(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for relative in (
        "backups",
        "exports/issues",
        "credentials",
        "artifacts/objects/sha256",
        "artifacts/manifests",
        "runtime",
        "reports",
    ):
        (root / relative).mkdir(parents=True, exist_ok=True)
    policy = root / "policy.yaml"
    if not policy.exists():
        policy.write_text(default_policy_text(), encoding="utf-8", newline="\n")


def initialize_legacy_store(root: str | Path, version: int) -> Store:
    """Build and open a historical schema fixture at ``version``."""

    target = Path(root).resolve()
    _prepare_root(target)
    conn = sqlite3.connect(target / "issue_ledger.sqlite")
    try:
        original = store_module.LATEST_SCHEMA_VERSION
        store_module.LATEST_SCHEMA_VERSION = version
        try:
            Store._apply_pending(conn)
            conn.commit()
            return Store(target)
        finally:
            store_module.LATEST_SCHEMA_VERSION = original
    finally:
        conn.close()


def initialize_legacy_manager(root: str | Path, version: int) -> IssueManager:
    store = initialize_legacy_store(root, version)
    manager = IssueManager.__new__(IssueManager)
    manager.store = store
    manager.policy = store.policy
    manager._wire_services()
    return manager
