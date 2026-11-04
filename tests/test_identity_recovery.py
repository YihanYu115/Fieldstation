from __future__ import annotations

import json

import pytest

from issue_manager.cli import main
from issue_manager.errors import PermissionError, ValidationError
from issue_manager.service import IssueManager


def test_recover_bootstrap_credential_preserves_grant_and_audits(tmp_path, capsys):
    ledger = tmp_path / "ledger"
    manager = IssueManager.initialize(ledger)
    credential_path = manager.store.ledger_dir / "credentials" / "maintenance-agent.token"
    before_capabilities = {
        row["capability"]
        for row in manager.store.rows(
            "SELECT capability FROM actor_capabilities WHERE actor_id='maintenance-agent'"
        )
    }
    credential_path.unlink()
    manager.close()

    assert main(
        [
            "--ledger",
            str(ledger),
            "recover-bootstrap-credential",
            "--reason",
            "restore delegated pilot test access",
        ]
    ) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["actor_id"] == "maintenance-agent"
    assert result["credential_path"] == str(credential_path)
    assert "token" not in result

    manager = IssueManager(ledger)
    try:
        auth = manager.credentials.resolve(credential_path, "identity.manage")
        assert auth.actor_id == "maintenance-agent"
        after_capabilities = {
            row["capability"]
            for row in manager.store.rows(
                "SELECT capability FROM actor_capabilities WHERE actor_id='maintenance-agent'"
            )
        }
        assert after_capabilities == before_capabilities
        event = manager.store.row(
            "SELECT actor,action,reason,payload_json FROM audit_events "
            "WHERE action='identity.recover_bootstrap_credential'"
        )
        assert event["actor"] == "trusted-host:issuectl"
        assert event["reason"] == "restore delegated pilot test access"
        assert json.loads(event["payload_json"]) == {
            "grant_changed": False,
            "run_id": auth.run_id,
        }
    finally:
        manager.close()


def test_recovery_refuses_existing_credential(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    try:
        with pytest.raises(ValidationError, match="already exists"):
            manager.credentials.recover_bootstrap_maintenance_credential(
                reason="test refusal"
            )
    finally:
        manager.close()


def test_recovery_refuses_modified_bootstrap_grant(tmp_path):
    manager = IssueManager.initialize(tmp_path / "ledger")
    credential_path = manager.store.ledger_dir / "credentials" / "maintenance-agent.token"
    credential_path.unlink()
    with manager.store.transaction() as conn:
        conn.execute(
            "DELETE FROM actor_capabilities WHERE actor_id='maintenance-agent' "
            "AND capability='identity.manage'"
        )
    try:
        with pytest.raises(PermissionError, match="grant does not match policy"):
            manager.credentials.recover_bootstrap_maintenance_credential(
                reason="test refusal"
            )
    finally:
        manager.close()
