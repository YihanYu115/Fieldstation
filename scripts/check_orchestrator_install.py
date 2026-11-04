"""Verify the current orchestration wheel in an isolated environment over HTTP."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path

PROBE = r'''import importlib.metadata, json, os, sys, threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen
import workflow_orchestrator
from workflow_orchestrator.tools_client import ToolsClient
from workflow_orchestrator.tools_http import ToolsHTTPServer, load_service

root = Path(sys.argv[1])
module = Path(workflow_orchestrator.__file__).resolve()
assert Path(sys.prefix).resolve() in module.parents, module
assert importlib.metadata.version("issue-workflow-orchestrator") == "0.13.8"
os.environ["FIELDSTATION_SMOKE_TOKEN"] = "synthetic-wheel-check"
config = {"database_path": str(root / "queue.sqlite"),
          "listen": {"host": "127.0.0.1", "port": 0},
          "principals": [{"principal_id": "manager", "token_env": "FIELDSTATION_SMOKE_TOKEN",
                          "actions": ["publish_task", "list_tasks", "get_task"]}]}
path = root / "queue.json"
path.write_text(json.dumps(config), encoding="utf-8")
queue, bindings, address = load_service(path)
with ToolsHTTPServer(address, queue, bindings) as server:
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
    thread.start()
    try:
        endpoint = "http://127.0.0.1:%d" % server.server_address[1]
        try:
            urlopen(endpoint + "/v1/identity", timeout=5)
            raise AssertionError("unauthenticated request was accepted")
        except HTTPError as error:
            assert error.code == 401
        client = ToolsClient(endpoint, os.environ["FIELDSTATION_SMOKE_TOKEN"], root / "journal.json")
        receipt = client.write("publish_task", issue_id="smoke", instructions="Record an observation",
                               input_refs=["synthetic:observation"], experimenter_profile="experimenter")
        task = client.read("get_task", task_id=receipt["task_id"])
        assert task["issue_id"] == "smoke" and task["instructions"] == "Record an observation"
        assert client.read("list_tasks", issue_id="smoke")["items"] == [task]
        assert task["claim"] is None
    finally:
        server.shutdown()
        thread.join(timeout=5)
        assert not thread.is_alive()
print(json.dumps({"version": importlib.metadata.version("issue-workflow-orchestrator"),
                  "module_path": str(module), "http_queue_verified": True,
                  "unauthenticated_request_rejected": True}))
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--receipt-out", type=Path)
    args = parser.parse_args()
    wheel = args.wheel.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="orchestration-wheel-") as directory:
        root = Path(directory)
        venv.EnvBuilder(with_pip=True).create(root / "venv")
        python = root / "venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        subprocess.run([str(python), "-m", "pip", "install", "--no-deps", str(wheel)],
                       cwd=root, check=True, capture_output=True)
        result = subprocess.run([str(python), "-I", "-X", "utf8", "-c", PROBE, str(root)],
                                cwd=root, capture_output=True, text=True, encoding="utf-8")
        if result.returncode:
            raise RuntimeError(result.stderr)
        receipt = json.loads(result.stdout)
        package = Path(receipt["module_path"]).parent
        with zipfile.ZipFile(wheel) as archive:
            modules = [name for name in archive.namelist()
                       if name.startswith("workflow_orchestrator/") and name.endswith(".py")]
            if not modules:
                raise RuntimeError("wheel has no orchestration Python modules")
            for name in modules:
                installed = package.parent / name
                if not installed.is_file() or installed.read_bytes() != archive.read(name):
                    raise RuntimeError(f"installed module differs from wheel: {name}")
        executable = root / "venv" / ("Scripts/workflow-tools.exe" if sys.platform == "win32"
                                      else "bin/workflow-tools")
        help_result = subprocess.run([str(executable), "--help"], cwd=root, check=True,
                                     capture_output=True, text=True, encoding="utf-8")
        assert all(command in help_result.stdout for command in ("serve", "mcp", "host", "discover"))
        receipt.update(wheel=wheel.name, wheel_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
                       installed_modules_compared=len(modules), installed_console_verified=True)
        output = json.dumps(receipt, ensure_ascii=False, indent=2) + "\n"
        if args.receipt_out:
            args.receipt_out.parent.mkdir(parents=True, exist_ok=True)
            args.receipt_out.write_text(output, encoding="utf-8")
        print(output, end="")


if __name__ == "__main__":
    main()
