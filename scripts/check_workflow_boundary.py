"""Architecture regression gate; run without importing either runtime package."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ORCHESTRATOR_SQLITE_FILES = {"listener_state.py", "host_records.py", "board_records.py", "task_queue.py"}
ORCHESTRATOR_MCP_FILES = {"tools_mcp.py", "mcp_http.py"}


# The current entry must not acquire a dependency on retired workflow modules.
TOOL_MODULES = {'listener', 'listener_state', 'trigger_tools', 'trigger_script', 'host_contracts', 'host_transport', 'host_process', 'host_records', 'host_sources', 'launch_host', 'host_http', 'host_client', 'board_records', 'board_contracts', 'board_http', 'board_client', 'board_facade', 'tools_cli', 'tools_contracts', 'tools_http', 'tools_client',
                'tools_journal', 'tools_mcp', 'task_queue', 'run_lock',
                'im_client', 'im_contracts', 'im_tools', 'client', 'mcp_contract',
                'packet_contract', 'relation_contract', 'mcp_sessions', 'mcp_http',
                'module_instructions', 'host_catalog'}


def allowed_orchestrator_import(path: Path, module: str) -> bool:
    """Allow reviewed persistence and MCP server dependencies only where used."""
    filename = path.name
    top = module.split(".")[0]
    if module == "sqlite3":
        return filename in ORCHESTRATOR_SQLITE_FILES
    if top == "mcp":
        return filename in ORCHESTRATOR_MCP_FILES
    if top in {"starlette", "uvicorn"}:
        return filename == "mcp_http.py"
    if top == "jsonschema":
        return filename == "mcp_contract.py"
    return top in sys.stdlib_module_names or top == "workflow_orchestrator"


def violates_kernel_import(module: str) -> bool:
    return module.split(".")[0] == "workflow_orchestrator"


def findings(root: Path) -> list[str]:
    errors = []
    areas = {
        "kernel": root / "issue_manager",
        "orchestrator": root / "orchestration/src/workflow_orchestrator",
    }
    generic = {"workflow_composition.py", "registered_workflow_host.py", "registered_settlement.py",
               "source_settlement.py", "continuation_records.py", "workflow_continuations.py", "installed_runtime.py"}
    shims = {"request_completion", "material_review", "workflow_policies", "runtime_controller", "runtime_store"}
    for area, directory in areas.items():
        for path in directory.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if area == 'orchestrator' and path.name == 'listener.py':
                    if isinstance(node, ast.ImportFrom) and (node.module or '').split('.')[-1].startswith(('host_', 'trigger_')):
                        errors.append(f'{path.relative_to(root)}: listener imports activation/policy')
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {
                        'write', 'begin', 'launch', 'claim', 'answer_handoff', 'curate_field_item'
                    }:
                        errors.append(f'{path.relative_to(root)}: listener calls a mutating surface')
                if area == "orchestrator" and path.name in generic and isinstance(node, ast.ImportFrom):
                    parts = (node.module or "").split(".")
                    if "five_role_workflow" in parts or any(part in shims for part in parts):
                        errors.append(f"{path.relative_to(root)}: registered core imports professional/legacy policy")
                if area == "orchestrator" and path.stem in TOOL_MODULES:
                    if isinstance(node, ast.ImportFrom):
                        module = node.module or ""
                        if node.level or module.startswith("workflow_orchestrator."):
                            if module.split(".")[-1] not in TOOL_MODULES:
                                errors.append(f"{path.relative_to(root)}: new tools import old workflow {module}")
                    elif isinstance(node, ast.Import):
                        for alias in node.names:
                            if alias.name.startswith("workflow_orchestrator.") and alias.name.split(".")[-1] not in TOOL_MODULES:
                                errors.append(f"{path.relative_to(root)}: new tools import old workflow {alias.name}")
                imports = []
                if isinstance(node, ast.Import):
                    imports = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and not node.level:
                    imports = [node.module or ""]
                for module in imports:
                    if area == "kernel" and violates_kernel_import(module):
                        errors.append(f"{path.relative_to(root)}: kernel imports orchestration")
                    if area == "orchestrator" and not allowed_orchestrator_import(path, module):
                        errors.append(f"{path.relative_to(root)}: forbidden runtime import {module}")
    for path in areas["kernel"].glob("*curator*"):
        errors.append(f"{path.relative_to(root)}: role-specific asset in kernel")
    for name in ("agent_workflow_service.py",
                 "agent_workflow_results.py", "agent_workflow_contracts.py",
                 "agent_workflow_assessments.py", "agent_workflow_coverage.py",
                 "agent_workflow_proposals.py"):
        tree = ast.parse((areas["kernel"] / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare) and any(
                isinstance(value, ast.Constant) and value.value in {"material_curator", "conclusion_maintainer"}
                for value in ast.walk(node)
            ):
                errors.append(f"{name}:{node.lineno}: role-specific kernel branch")
    return errors


if __name__ == "__main__":
    violations = findings(Path(__file__).resolve().parents[1])
    if violations:
        raise SystemExit("\n".join(violations))
    print("workflow API boundary check passed")
