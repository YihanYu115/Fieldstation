from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_workflow_boundary", ROOT / "scripts" / "check_workflow_boundary.py"
)
assert SPEC is not None and SPEC.loader is not None
BOUNDARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOUNDARY)


def test_reviewed_orchestration_runtime_imports_are_file_scoped() -> None:
    for name in ("listener_state.py", "host_records.py", "board_records.py", "task_queue.py"):
        assert BOUNDARY.allowed_orchestrator_import(Path(name), "sqlite3")
    assert BOUNDARY.allowed_orchestrator_import(Path("tools_mcp.py"), "mcp.server.stdio")
    for module in ("mcp.server.streamable_http_manager", "starlette.routing", "uvicorn"):
        assert BOUNDARY.allowed_orchestrator_import(Path("mcp_http.py"), module)
        assert not BOUNDARY.allowed_orchestrator_import(Path("client.py"), module)
    assert not BOUNDARY.allowed_orchestrator_import(Path("tools_mcp.py"), "uvicorn")
    for name in ("tools_mcp.py", "client.py", "queue_store.py"):
        assert not BOUNDARY.allowed_orchestrator_import(Path(name), "sqlite3")
    assert not BOUNDARY.allowed_orchestrator_import(Path("client.py"), "mcp.server")
    assert not BOUNDARY.allowed_orchestrator_import(Path("client.py"), "requests")
    assert not BOUNDARY.allowed_orchestrator_import(Path("tools_mcp.py"), "issue_manager")


def test_kernel_import_direction_remains_rejected() -> None:
    assert BOUNDARY.violates_kernel_import("workflow_orchestrator.queue_store")
    assert not BOUNDARY.violates_kernel_import("issue_manager.service")


def test_current_repository_obeys_boundary() -> None:
    assert BOUNDARY.findings(ROOT) == []


def test_boundary_scan_reports_both_forbidden_import_directions(tmp_path: Path) -> None:
    kernel = tmp_path / "issue_manager"
    orchestration = tmp_path / "orchestration" / "src" / "workflow_orchestrator"
    kernel.mkdir(parents=True)
    orchestration.mkdir(parents=True)
    for name in (
        "agent_workflow_service.py", "agent_workflow_results.py", "agent_workflow_contracts.py",
        "agent_workflow_assessments.py", "agent_workflow_coverage.py", "agent_workflow_proposals.py",
    ):
        (kernel / name).write_text("", encoding="utf-8")
    (kernel / "bad_direction.py").write_text("import workflow_orchestrator.queue_store\n", encoding="utf-8")
    (orchestration / "bad_direction.py").write_text("import issue_manager.service\n", encoding="utf-8")
    findings = BOUNDARY.findings(tmp_path)
    assert any("kernel imports orchestration" in item for item in findings)
    assert any("forbidden runtime import issue_manager.service" in item for item in findings)


def test_boundary_checks_new_mcp_modules_and_listener(tmp_path: Path) -> None:
    kernel = tmp_path / "issue_manager"
    orchestration = tmp_path / "orchestration" / "src" / "workflow_orchestrator"
    kernel.mkdir(parents=True)
    orchestration.mkdir(parents=True)
    for name in (
        "agent_workflow_service.py", "agent_workflow_results.py", "agent_workflow_contracts.py",
        "agent_workflow_assessments.py", "agent_workflow_coverage.py", "agent_workflow_proposals.py",
    ):
        (kernel / name).write_text("", encoding="utf-8")
    (orchestration / "mcp_http.py").write_text(
        "import sqlite3\nfrom .retired_workflow import something\n", encoding="utf-8"
    )
    (orchestration / "client.py").write_text("import uvicorn\n", encoding="utf-8")
    (orchestration / "listener.py").write_text(
        "from .trigger_tools import TriggerTools\ndef probe(host):\n    host.launch()\n", encoding="utf-8"
    )
    results = BOUNDARY.findings(tmp_path)
    for message in (
        "forbidden runtime import sqlite3", "new tools import old workflow retired_workflow",
        "forbidden runtime import uvicorn", "listener imports activation/policy",
        "listener calls a mutating surface",
    ):
        assert any(message in item for item in results), (message, results)
