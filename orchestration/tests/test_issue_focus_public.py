import json
import os
import threading
from pathlib import Path

import workflow_orchestrator
from im_tools_harness import IMMCP, IMService
from queue_tools_harness import MCP, raw
from workflow_orchestrator.board_client import BoardClient
from workflow_orchestrator.board_http import BoardHTTPServer, load_board_service
from workflow_orchestrator.tools_http import ToolsHTTPServer, load_service


def test_issue_scope_public_mcp_and_pagination(tmp_path, monkeypatch):
    if os.environ.get("WORKFLOW_EXPECT_PACKAGE_ROOT"):
        assert (
            Path(workflow_orchestrator.__file__)
            .resolve()
            .is_relative_to(Path(os.environ["WORKFLOW_EXPECT_PACKAGE_ROOT"]).resolve())
        )
    root = tmp_path
    im = None
    servers = []

    def service(kind):
        token = "board-test" if kind == "board" else "queue-test"
        key = kind.upper() + "_TOKEN"
        monkeypatch.setenv(key, token)
        actions = (
            ["post_message", "list_messages", "get_message"]
            if kind == "board"
            else ["publish_task", "list_tasks"]
        )
        principal = {"principal_id": "manager", "token_env": key, "actions": actions}
        if kind == "board":
            principal.update(kind="service", recipient="manager", allowed_recipients=[])
        cfg = {
            "database_path": str(root / (kind + ".sqlite")),
            "listen": {"host": "127.0.0.1", "port": 0},
            "principals": [principal],
        }
        f = root / (kind + ".json")
        f.write_text(json.dumps(cfg), encoding="utf-8")
        records, bindings, address = (load_board_service if kind == "board" else load_service)(f)
        server = (BoardHTTPServer if kind == "board" else ToolsHTTPServer)(
            address, records, bindings
        )
        th = threading.Thread(target=server.serve_forever)
        th.start()
        servers.append((server, th))

        class S:
            pass

        s = S()
        s.path = root / kind
        s.path.mkdir()
        s.tokens = {"manager": token}
        s.endpoint = "http://127.0.0.1:" + str(server.server_address[1])
        return s

    try:
        im = IMService(root / "im")
        board = service("board")
        queue = service("queue")
        monkeypatch.setenv("TREE_TOKEN", im.tokens["reader"])
        with IMMCP(im, actor="curator") as m:
            x = m.call(
                "create_issue",
                {
                    "issue_id": "CHILDNEW",
                    "issue_type": "qubit",
                    "title": "New",
                    "parent_issue_id": "P",
                },
            )
            assert x.get("issue_id") == "CHILDNEW", x
        queue_profile = {
            "connection": {"endpoint": queue.endpoint, "token_env": "MCP_QUEUE_TOKEN"},
            "default_issue_id": "P",
            "tools": ["publish_task", "list_tasks"],
            "journal_path": str(root / "queue-mcp-actions.json"),
        }
        queue_profile_file = root / "queue-profile.json"
        queue_profile_file.write_text(json.dumps(queue_profile), encoding="utf-8")
        with MCP(queue, profile=queue_profile_file) as m:
            task = m.call(
                "publish_task",
                {"issue_id": "CHILDNEW", "instructions": "Work", "experimenter_profile": "role"},
            )
            assert task["task"]["issue_id"] == "CHILDNEW", task
            assert task["task"]["experimenter_profile"] == "role", task
        bc = BoardClient(board.endpoint, board.tokens["manager"], root / "board-actions.json")
        for issue in ["P", "OUT", "CHILDNEW", "A"]:
            bc.write("post_message", issue_id=issue, text=issue)
        profile = {
            "surface": "board",
            "connection": {"endpoint": board.endpoint, "token_env": "MCP_QUEUE_TOKEN"},
            "tree_connection": {"endpoint": im.endpoint, "token_env": "TREE_TOKEN"},
            "default_issue_id": "P",
            "tools": ["list_messages", "get_message"],
            "journal_path": str(root / "board-mcp-actions.json"),
        }
        f = root / "board-profile.json"
        f.write_text(json.dumps(profile), encoding="utf-8")
        with MCP(board, profile=f) as m:
            definitions = {item["name"]: item for item in m.rpc("tools/list", {})["tools"]}
            schema = definitions["list_messages"]["inputSchema"]["properties"]
            assert "128" in schema["include_descendants"]["description"]
            assert "next_read" in schema["include_descendants"]["description"]
            assert "expected_tree_snapshot" in schema
            one = m.call("list_messages", {})
            assert [x["issue_id"] for x in one["items"]] == ["P"], one
            allrows = m.call("list_messages", {"all_issues": True})
            assert len(allrows["items"]) == 4, allrows
            args = {"issue_id": "P", "include_descendants": True, "limit": 1}
            got = []
            while args:
                page = m.call("list_messages", args)
                assert "error" not in page, page
                got.extend(x["issue_id"] for x in page["items"])
                args = page["next_read"]["arguments"] if page["next_read"] else None
            assert got == ["P", "CHILDNEW", "A"], got
            first = m.call(
                "list_messages", {"issue_id": "P", "include_descendants": True, "limit": 1}
            )
            with IMMCP(im, actor="curator") as other:
                y = other.call(
                    "create_issue",
                    {
                        "issue_id": "LATER",
                        "issue_type": "qubit",
                        "title": "Later",
                        "parent_issue_id": "P",
                    },
                )
                assert y.get("issue_id") == "LATER", y
            changed = m.call("list_messages", first["next_read"]["arguments"])
            assert changed["error"]["code"] == "snapshot_changed", changed
            first = m.call(
                "list_messages", {"issue_id": "P", "include_descendants": True, "limit": 1}
            )
            bc.write("post_message", issue_id="P", text="new")
            changed = m.call("list_messages", first["next_read"]["arguments"])
            assert changed["error"]["code"] == "snapshot_changed", changed
            monkeypatch.setenv("TREE_DENIED", im.tokens["submit-only"])
            denied_profile = {
                **profile,
                "tree_connection": {"endpoint": im.endpoint, "token_env": "TREE_DENIED"},
                "journal_path": str(root / "denied-board-actions.json"),
            }
            denied_file = root / "denied-board-profile.json"
            denied_file.write_text(json.dumps(denied_profile), encoding="utf-8")
            with MCP(board, profile=denied_file) as denied:
                failure = denied.call(
                    "list_messages", {"issue_id": "P", "include_descendants": True}
                )
                assert failure["error"]["code"] == "permission_denied", failure
            im.stop()
            assert m.call("list_messages", {"issue_id": "P"})["items"]
            assert m.call("list_messages", {"all_issues": True})["items"]
            assert (
                m.call("list_messages", {"issue_id": "P", "include_descendants": True})["error"][
                    "code"
                ]
                == "transport_unknown"
            )
        print("real IM and Board HTTP/MCP integration passed")
    finally:
        for server, th in reversed(servers):
            server.shutdown()
            server.server_close()
            th.join()
        if im:
            im.stop()


def test_public_im_overview_rejects_more_than_128_nodes(tmp_path):
    im = IMService(tmp_path / "im-limit")
    try:
        for number in range(126):
            key = f"limit-{number}"
            status, body = raw(
                im.endpoint,
                im.tokens["curator"],
                "POST",
                "/v1/issues",
                {
                    "issue_id": f"LIMIT{number}",
                    "issue_type": "qubit",
                    "title": "Limit test",
                    "parent_issue_id": "P",
                },
                {"X-Request-ID": key, "Idempotency-Key": key},
            )
            assert status == 200, body
            if number == 124:
                status, overview = raw(
                    im.endpoint, im.tokens["reader"], "GET", "/v1/issues/overview?root=P"
                )
                assert status == 200 and overview["result"]["complete"] is True
                assert len(overview["result"]["nodes"]) == 128
        status, error = raw(im.endpoint, im.tokens["reader"], "GET", "/v1/issues/overview?root=P")
        assert status == 409 and error["error"] == "overview_too_large"
    finally:
        im.stop()
