"""Budget-count and audit JSON-RPC tools/call traffic for a live trial MCP."""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import time
from pathlib import Path
from typing import Any


def append_jsonl(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")
        stream.flush()


def take_budget_slot(path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path, timeout=30) as db:
        db.execute("CREATE TABLE IF NOT EXISTS tool_budget (id INTEGER PRIMARY KEY CHECK(id=1), used INTEGER NOT NULL)")
        db.execute("INSERT OR IGNORE INTO tool_budget(id, used) VALUES(1, 0)")
        db.execute("UPDATE tool_budget SET used=used+1 WHERE id=1")
        return int(db.execute("SELECT used FROM tool_budget WHERE id=1").fetchone()[0])


async def run() -> int:
    separator = sys.argv.index("--") if "--" in sys.argv else -1
    if separator < 0 or separator + 1 == len(sys.argv):
        raise SystemExit("usage: python mcp_budget_proxy.py -- command args...")
    limit = int(os.environ["BOARD_TRIAL_TOOL_LIMIT"])
    trace_path = Path(os.environ["BOARD_TRIAL_TOOL_TRACE"])
    budget_path = Path(os.environ["BOARD_TRIAL_BUDGET_DB"])
    server_name = os.environ["BOARD_TRIAL_SERVER_NAME"]
    process = await asyncio.create_subprocess_exec(
        *sys.argv[separator + 1 :],
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=os.environ.copy(),
    )
    assert process.stdin and process.stdout and process.stderr
    pending: dict[str, dict[str, Any]] = {}

    async def forward_responses() -> None:
        while line := await process.stdout.readline():
            try:
                row = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
                continue
            request_id = row.get("id")
            meta = pending.pop(str(request_id), None) if request_id is not None else None
            if meta:
                append_jsonl(trace_path, meta | {
                    "response_at_ns": time.time_ns(),
                    "response": row.get("result", row.get("error")),
                    "jsonrpc_error": "error" in row,
                })
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()

    async def forward_stderr() -> None:
        while chunk := await process.stderr.read(4096):
            sys.stderr.buffer.write(chunk)
            sys.stderr.buffer.flush()

    response_task = asyncio.create_task(forward_responses())
    stderr_task = asyncio.create_task(forward_stderr())
    try:
        while line := await asyncio.to_thread(sys.stdin.buffer.readline):
            try:
                row = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                process.stdin.write(line)
                await process.stdin.drain()
                continue
            method = row.get("method")
            request_id = row.get("id")
            if method == "tools/call" and request_id is not None:
                operation_count = take_budget_slot(budget_path)
                params = row.get("params") or {}
                request_meta = {
                    "server_name": server_name,
                    "sequence": operation_count,
                    "request_id": request_id,
                    "tool": params.get("name"),
                    "arguments": params.get("arguments", {}),
                    "request_at_ns": time.time_ns(),
                    "active_limits": {"tool_call_limit": limit},
                    "counter_source": "shared_host_budget_db",
                    "counter_unit": "tools_call_attempts",
                }
                if operation_count > limit:
                    append_jsonl(trace_path, request_meta | {
                        "response_at_ns": time.time_ns(),
                        "response": {"isError": True, "content": [{
                            "type": "text", "text": "Live trial tool-call budget reached; no operation was forwarded."
                        }]},
                        "budget_blocked": True,
                        "forwarded": False,
                    })
                    blocked = {"jsonrpc": "2.0", "id": request_id, "result": {
                        "content": [{"type": "text", "text": "Live trial tool-call budget reached; no operation was forwarded."}],
                        "isError": True,
                    }}
                    sys.stdout.buffer.write((json.dumps(blocked, separators=(",", ":")) + "\n").encode())
                    sys.stdout.buffer.flush()
                    continue
                pending[str(request_id)] = request_meta | {"forwarded": True}
            process.stdin.write(line)
            await process.stdin.drain()
    finally:
        if process.returncode is None:
            process.terminate()
        await process.wait()
        await asyncio.gather(response_task, stderr_task, return_exceptions=True)
    return process.returncode or 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
