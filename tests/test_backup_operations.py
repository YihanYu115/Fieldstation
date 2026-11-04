from __future__ import annotations

import json
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

from issue_manager import IssueManager
from issue_manager.errors import NotFoundError, ValidationError
from issue_manager.schema import SCHEMA_VERSION
from issue_manager.store import Store


def _cli(root: Path, *arguments: str) -> dict:
    result = subprocess.run(
        [sys.executable, "-X", "utf8", "-m", "issue_manager", "--ledger", str(root),
         "backup", *arguments],
        capture_output=True, text=True, encoding="utf-8", check=True,
    )
    return json.loads(result.stdout)


def _ledger_with_artifact(tmp_path: Path) -> tuple[Path, dict]:
    root = tmp_path / "账本"
    source = tmp_path / "观察.txt"
    source.write_text("可复验的观察\n", encoding="utf-8")
    with closing(IssueManager.initialize(root)) as manager:
        manager.create_issue("before", "episode", "备份前的问题")
        artifact = manager.artifacts.add(
            source, role="frozen", credential=manager.credentials.path_for("maintenance-agent")
        )
        assert manager.doctor()["ok"]
    return root, artifact


@pytest.mark.parametrize("mode", ["metadata", "full"])
def test_backup_cli_roundtrip_preserves_artifact_history_and_current_schema(tmp_path, mode):
    root, artifact = _ledger_with_artifact(tmp_path)
    original = (root / artifact["storage_uri"]).read_bytes()
    backup = _cli(root, "create", "--mode", mode, "--label", "中文往返")
    backup_id = backup["backup_id"]
    assert any(item["backup_id"] == backup_id for item in _cli(root, "list"))
    verified = _cli(root, "verify", backup_id)
    assert verified["ok"] and verified["schema_version"] == SCHEMA_VERSION
    assert verified["mode"] == mode
    with closing(IssueManager(root)) as manager:
        manager.create_issue("after", "episode", "备份后的问题")
        epoch = manager.store.manager_metadata()["token_epoch"]
    if mode == "full":
        (root / artifact["storage_uri"]).unlink()
    restored = _cli(root, "restore", backup_id)
    assert restored["doctor"]["ok"]
    assert restored["token_epoch"] > epoch
    assert restored["pre_restore_backup_degraded"] == (mode == "full")
    assert (root / artifact["storage_uri"]).read_bytes() == original
    with closing(IssueManager(root)) as manager:
        assert manager.show_issue("before")["title"] == "备份前的问题"
        with pytest.raises(NotFoundError):
            manager.show_issue("after")
        assert manager.doctor()["ok"]
        assert manager.store.row(
            "SELECT COUNT(*) AS n FROM audit_events WHERE action='backup.restore'"
        )["n"] == 1


def test_full_backup_skips_corrupt_same_size_previous_object(tmp_path):
    root, artifact = _ledger_with_artifact(tmp_path)
    first = Store.create_backup(root, mode="full")
    previous = root / "backups" / first["backup_id"] / artifact["storage_uri"]
    previous.write_bytes(b"x" * artifact["size"])
    assert not Store.verify_backup(root, first["backup_id"])["ok"]
    second = Store.create_backup(root, mode="full")
    assert Store.verify_backup(root, second["backup_id"])["ok"]
    backed = root / "backups" / second["backup_id"] / artifact["storage_uri"]
    assert backed.read_bytes() == (root / artifact["storage_uri"]).read_bytes()


def test_metadata_restore_requires_live_objects_and_preserves_later_state(tmp_path):
    root, artifact = _ledger_with_artifact(tmp_path)
    backup = Store.create_backup(root, mode="metadata")
    with closing(IssueManager(root)) as manager:
        manager.create_issue("after", "episode", "不可因恢复失败而丢失")
    (root / artifact["storage_uri"]).unlink()
    assert Store.verify_backup(root, backup["backup_id"])["ok"]
    with pytest.raises(ValidationError, match="missing Artifact"):
        Store.restore_backup(root, backup["backup_id"])
    with closing(IssueManager(root)) as manager:
        assert manager.show_issue("after")["title"] == "不可因恢复失败而丢失"
        assert not manager.store.manager_metadata()["maintenance_mode"]


def test_restore_switch_failure_rolls_back_to_original_live_state(tmp_path, monkeypatch):
    root, _ = _ledger_with_artifact(tmp_path)
    backup = Store.create_backup(root, mode="full")
    with closing(IssueManager(root)) as manager:
        manager.create_issue("after", "episode", "故障后应保留")
    activate = Store._activate_restore_stage
    calls = []

    def fail_after_first_switch(cls, ledger, stage):
        activate(ledger, stage)
        calls.append(stage)
        if len(calls) == 1:
            raise OSError("synthetic switch interruption")

    monkeypatch.setattr(Store, "_activate_restore_stage", classmethod(fail_after_first_switch))
    with pytest.raises(OSError, match="synthetic switch interruption"):
        Store.restore_backup(root, backup["backup_id"])
    assert len(calls) == 2
    with closing(IssueManager(root)) as manager:
        assert manager.show_issue("after")["title"] == "故障后应保留"
        assert manager.doctor()["ok"]
    journal = json.loads((root / "runtime/restore_journal.json").read_text(encoding="utf-8"))
    assert journal["phase"] == "rolled_back"
