"""Real standalone Board process host; all synthetic tokens stay in child environment."""

from __future__ import annotations

import json
import secrets
import sqlite3
from contextlib import contextmanager

from queue_tools_harness import MCP, ManagedProcess, command_env
from workflow_orchestrator.board_contracts import BOARD_ACTIONS, BOARD_WRITES


class BoardService:
    def __init__(self, path):
        self.path = path
        path.mkdir(parents=True, exist_ok=True)
        names = (
            "manager",
            "worker",
            "worker2",
            "human",
            "human_no",
            "foreign",
            "c",
            "reader",
            "writer",
        )
        self.tokens = {name: secrets.token_urlsafe(24) for name in names}
        principals = []
        for name in names:
            actions = set(BOARD_ACTIONS)
            if name == "reader":
                actions -= BOARD_WRITES
            if name == "writer":
                actions = {"post_message"}
            if name == "human_no":
                actions -= {"create_board_instruction", "revoke_board_instruction"}
            principals.append(
                {
                    "principal_id": name,
                    "token_env": "TEST_BOARD_" + name.upper(),
                    "kind": "human" if name.startswith("human") else "service",
                    "recipient": "scientist" if name.startswith("worker") else name,
                    "actions": sorted(actions),
                    "allowed_recipients": ["scientist", "manager"],
                }
            )
        self.config = {
            "database_path": str(path / "board.sqlite"),
            "listen": {"host": "127.0.0.1", "port": 0},
            "principals": principals,
        }
        self.process = None
        self.start()

    def start(self):
        path = self.path / "service.json"
        path.write_text(json.dumps(self.config), encoding="utf-8")
        command, env = command_env({"TEST_BOARD_" + k.upper(): v for k, v in self.tokens.items()})
        self.process = ManagedProcess(
            command + ["serve", "--services", "board", "--config", str(path)],
            self.path,
            env,
            "board-service",
        )
        try:
            value = json.loads(self.process.line())
            assert value["modules"] == ["board"]
            self.endpoint = "http://127.0.0.1:" + str(value["listening"][1])
            self.config["listen"]["port"] = value["listening"][1]
            self.service_id = value["service_id"]
        except BaseException:
            self.stop()
            raise

    def stop(self):
        if self.process:
            self.process.close()
            self.process = None

    def counts(self):
        with sqlite3.connect(self.config["database_path"]) as db:
            return {
                name: db.execute("SELECT COUNT(*) FROM " + name).fetchone()[0]
                for name in (
                    "messages",
                    "handoffs",
                    "instructions",
                    "instruction_events",
                    "receipts",
                )
            }

    def profile(self, tools=None, principal="manager", **extra):
        value = {
            "surface": "board",
            "connection": {"endpoint": self.endpoint, "token_env": "MCP_QUEUE_TOKEN"},
            "default_issue_id": "A",
            "tools": tools or sorted(BOARD_ACTIONS),
            "journal_path": str(self.path / ("mcp-" + principal + ".json")),
        }
        value.update(extra)
        path = self.path / ("profile-" + principal + ".json")
        path.write_text(json.dumps(value), encoding="utf-8")
        return path


@contextmanager
def running_board(path):
    service = BoardService(path)
    try:
        yield service
    finally:
        service.stop()


BoardMCP = MCP
