"""Check local links, UTF-8 and version identities in current documentation."""
from __future__ import annotations

import ast
import json
import re
import tomllib
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"\]\((<[^>\n]+>|[^\s)]+)")
REFERENCE = re.compile(r"^\s*\[[^\]\n]+\]:\s*(<[^>\n]+>|\S+)", re.MULTILINE)


def current_documents(root: Path) -> list[Path]:
    documents = list(root.glob("*.md"))
    for folder in ("docs", "orchestration", "scripts"):
        documents.extend(
            path for path in (root / folder).rglob("*.md")
            if not {"build", "dist", "node_modules", "__pycache__"}.intersection(path.parts)
        )
    return sorted(set(documents))


def findings(root: Path) -> list[str]:
    errors = []
    for name in ("archive", "docs/archive"):
        if (root / name).exists():
            errors.append(f"{name}: retired source belongs in Git history")
    for path in current_documents(root):
        relative = path.relative_to(root)
        raw = path.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            errors.append(f"{relative}: UTF-8 BOM")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{relative}: not UTF-8")
            continue
        # Code examples can contain illustrative Markdown paths and are not links.
        text = re.sub(r"(?ms)^```[^\n]*\n.*?^```[^\n]*$", "", text)
        targets = [match[1] for pattern in (LINK, REFERENCE) for match in pattern.finditer(text)]
        for target in targets:
            target = target.strip("<>")
            if re.match(r"^[A-Za-z]:[/\\]", target):
                errors.append(f"{relative}: non-portable local link {target}")
                continue
            if target.startswith(("#", "/", "\\")) or re.match(r"^[\w+.-]+:", target):
                continue
            local = re.split(r"[?#]", target, maxsplit=1)[0]
            if local and not (path.parent / unquote(local)).exists():
                errors.append(f"{relative}: missing local link {target}")

    core = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    orchestration = tomllib.loads(
        (root / "orchestration/pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    tree = ast.parse((root / "issue_manager/schema.py").read_text(encoding="utf-8"))
    schema = next(
        node.value.value for node in tree.body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        and any(isinstance(target, ast.Name) and target.id == "SCHEMA_VERSION" for target in node.targets)
    )
    if (root / "LICENSE").read_bytes() != (root / "orchestration/LICENSE").read_bytes():
        errors.append("orchestration/LICENSE: differs from repository license")
    contracts = json.loads((root / "project_package/contracts.json").read_text(encoding="utf-8"))
    component = contracts["$defs"]["imComponentManifest"]["properties"]
    manifest = contracts["$defs"]["projectManifest"]["properties"]["components"]["properties"]
    if component["schema_version"]["const"] != schema or manifest["im"]["properties"]["schema_version"]["const"] != schema:
        errors.append("project_package/contracts.json: IM schema differs from current kernel")
    package = tomllib.loads((root / "orchestration/pyproject.toml").read_text(encoding="utf-8"))
    if package["project"].get("scripts") != {"workflow-tools": "workflow_orchestrator.tools_cli:main"}:
        errors.append("orchestration/pyproject.toml: expected the single workflow-tools console")
    extra = package["project"].get("optional-dependencies", {}).get("mcp", [])
    if "mcp==1.30.0" not in extra or "jsonschema>=4.20,<5" not in extra:
        errors.append("orchestration/pyproject.toml: missing actual MCP dependencies")
    resources = package["tool"]["setuptools"].get("data-files", {})
    expected = {
        "share/issue-workflow-orchestrator": {"README.md", "QUEUE_TOOLS.md", "BOARD_TOOLS.md", "IM_TOOLS.md", "HOST_TOOLS.md", "HTTP_MCP.md", "PYTHON_TRIGGER.md", "ROLE_USAGE.md", "CONCLUSION_RULES.md", "DESIGN.md"},
        "share/issue-workflow-orchestrator/examples": {"examples/python_queue_inbox.py", "examples/python_board_combination.py", "examples/python_connections.json", "examples/python_role_events.py", "examples/host_role_guidance.json", "examples/dynamic_project_scheduler.py"},
    }
    for destination, paths in expected.items():
        if set(resources.get(destination, [])) != paths:
            errors.append(f"orchestration/pyproject.toml: incorrect resources for {destination}")
        for name in paths:
            if not (root / "orchestration" / name).is_file():
                errors.append(f"orchestration/{name}: missing installed resource")
    for name in ("README.md", "docs/README.md", "docs/START_HERE.md",
                 "docs/WORKFLOW_ARCHITECTURE.md",
                 "docs/OPERATIONS.md", "docs/WORKFLOW_PROJECT_PACKAGE_USAGE.md"):
        text = (root / name).read_text(encoding="utf-8")
        if core not in text or orchestration not in text:
            errors.append(f"{name}: missing current package version {core}/{orchestration}")
        normalized = text.replace("*", "").replace("`", "")
        if not re.search(rf"schema\s*v?\s*{schema}\b", normalized, re.IGNORECASE):
            errors.append(f"{name}: missing current IM schema {schema}")
    return errors


if __name__ == "__main__":
    problems = findings(ROOT)
    if problems:
        raise SystemExit("\n".join(problems))
    print(f"current documentation check passed ({len(current_documents(ROOT))} files)")
