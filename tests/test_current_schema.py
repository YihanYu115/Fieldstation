from __future__ import annotations

import hashlib
import sqlite3
from unittest.mock import patch

import pytest

from issue_manager import IssueManager
from issue_manager.errors import ValidationError
from issue_manager.schema import SCHEMA_VERSION
from issue_manager.store import Store


def test_fresh_init_has_one_schema_identity_and_one_runtime(tmp_path):
    ledger = tmp_path / "ledger"
    manager = IssueManager.initialize(ledger)
    try:
        assert SCHEMA_VERSION == 10
        assert Store._schema_version(manager.store.conn) == 10
        tables = {
            row[0]
            for row in manager.store.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert "schema_identity" in tables
        assert "schema_migrations" not in tables
        assert "schema_versions" not in tables
        assert {
            "field_packets", "field_facts", "field_packet_curation_heads", "field_packet_reviews",
            "field_fact_mapping_versions", "field_fact_mapping_heads",
        } <= tables
        assert "field_fact_references" not in tables
        assert "field_relation_claims" not in tables
        assert "field_relation_claim_decisions" not in tables
        assert "declared_source_locator" in {
            row[1] for row in manager.store.conn.execute("PRAGMA table_info(evidence_refs)")
        }
        assert len(manager.store.rows("SELECT * FROM context_rule_versions")) == 1
        assert manager.context_rules.active()["rule_id"].startswith(
            "context-currentness/scoped-v2:"
        )
    finally:
        manager.close()


@pytest.mark.parametrize("version", [1, 6, 8, 9])
def test_incompatible_schema_identity_is_rejected_without_mutation(tmp_path, version):
    ledger = tmp_path / "ledger"
    manager = IssueManager.initialize(ledger)
    manager.close()
    database = ledger / "issue_ledger.sqlite"
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA ignore_check_constraints=ON")
    connection.execute("UPDATE schema_identity SET version=? WHERE singleton=1", (version,))
    connection.commit()
    connection.close()
    before = hashlib.sha256(database.read_bytes()).digest()
    with pytest.raises(ValidationError, match="accepts only fresh schema 10"):
        Store(ledger)
    assert hashlib.sha256(database.read_bytes()).digest() == before


def test_declared_source_is_immutable_and_part_of_context_input_history(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    try:
        manager.create_issue("scope", "investigation", "Scope")
        auth = manager.credentials.resolve(
            manager.credentials.path_for("organizer-agent"), "evidence.write"
        )
        saved = manager.add_scoped_evidence_contribution(
            issue_id="scope", kind="observation", locator="  来源🙂  ",
            description="a contribution", related_evidence=[], actor=auth.actor_id,
            auth=auth, reason="test", idempotency_key="declared-source",
        )
        evidence_id = saved["evidence"]["evidence_id"]
        assert saved["evidence"]["declared_source_locator"] == "  来源🙂  "
        event = manager.store.row(
            "SELECT after_json FROM context_input_events WHERE object_kind='evidence_refs' "
            "AND json_extract(object_id,'$[0]')=? ORDER BY revision DESC LIMIT 1",
            (evidence_id,),
        )
        assert '"declared_source_locator":"  来源🙂  "' in event["after_json"]
        with pytest.raises(sqlite3.IntegrityError, match="declared source locator is immutable"):
            manager.store.conn.execute(
                "UPDATE evidence_refs SET declared_source_locator='changed' WHERE evidence_id=?",
                (evidence_id,),
            )
        ordinary = manager.add_evidence(kind="external", locator="urn:ordinary")
        assert manager.store.row(
            "SELECT declared_source_locator FROM evidence_refs WHERE evidence_id=?",
            (ordinary["evidence_id"],),
        )["declared_source_locator"] is None
        manager.evidence.register_platform(
            "platform-source-test", display_name="Source test", capabilities=["manifest"],
            credential=manager.credentials.path_for("maintenance-agent"),
        )
        with pytest.raises(ValidationError, match="declared only"):
            manager.evidence.preview_source_migration(
                evidence_id, "platform-source-test", reason="must reject"
            )
        with pytest.raises(ValidationError, match="declared only"):
            with manager.store.transaction() as conn:
                manager.evidence._bind_source(conn, evidence_id, "platform-source-test", auth)
        assert manager.store.row(
            "SELECT identity_namespace,declared_source_locator FROM evidence_refs WHERE evidence_id=?",
            (evidence_id,),
        ) == {"identity_namespace": "legacy", "declared_source_locator": "  来源🙂  "}
    finally:
        manager.close()


def test_v3_backup_is_refused_instead_of_restored_as_v6(tmp_path):
    with patch.object(Store, "verify_backup", return_value={"ok": True, "schema_version": 3}):
        with pytest.raises(ValidationError, match="Backup schema v3 must be migrated explicitly"):
            Store.restore_backup(tmp_path / "ledger", "synthetic-v3")


def test_failed_current_schema_init_leaves_no_database(tmp_path):
    ledger = tmp_path / "ledger"
    with patch("issue_manager.store.CURRENT_SCHEMA_SQL", "CREATE TABLE broken("):
        with pytest.raises(ValidationError):
            Store.initialize(ledger)
    assert not (ledger / "issue_ledger.sqlite").exists()
    assert not (ledger / "issue_ledger.sqlite.initializing").exists()


def test_sql_script_accepts_trailing_comments_and_whitespace():
    connection = sqlite3.connect(":memory:")
    try:
        Store._execute_sql_script(
            connection,
            "CREATE TABLE sample(id INTEGER);\n\n-- trailing line comment\n/* trailing block comment */\n",
        )
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='sample'"
        ).fetchone() == ("sample",)
    finally:
        connection.close()
