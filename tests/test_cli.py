from __future__ import annotations

import json
import subprocess
import sys


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-X", "utf8", "-m", "issue_manager.cli", *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_cli_initializes_and_reports_fixed_runtime(tmp_path):
    ledger = tmp_path / "ledger"
    initialized = _run("--ledger", str(ledger), "init")
    assert initialized.returncode == 0, initialized.stderr
    assert json.loads(initialized.stdout)["schema_version"] == 10

    status = _run("--ledger", str(ledger), "status")
    assert status.returncode == 0, status.stderr
    result = json.loads(status.stdout)
    assert result["runtime"] == "scoped-v2"
    assert result["schema_version"] == 10


def test_cli_does_not_expose_retired_commands(tmp_path):
    rejected = _run("--ledger", str(tmp_path / "ledger"), "migrate")
    assert rejected.returncode == 2
    assert "invalid choice" in rejected.stderr
