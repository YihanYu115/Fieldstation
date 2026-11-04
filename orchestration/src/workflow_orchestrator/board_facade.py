"""Natural Board business tools; technical write identity and CAS stay internal."""

from __future__ import annotations

import hashlib
from typing import Any

from .board_client import BoardClient
from .board_contracts import BOARD_WRITES
from .mcp_contract import ContractError
from .mcp_contract import validate as validate_schema_arguments
from .tools_contracts import ToolError, canonical, fail, fields, text

ID = {"type": "string", "minLength": 1, "maxLength": 128}
ISSUE = {"type": "string", "minLength": 1, "maxLength": 200}
TEXT = {"type": "string", "minLength": 1, "maxLength": 16000}
REASON = {"type": "string", "minLength": 1, "maxLength": 8192}
PAGE = {
    "cursor": {"type": "string", "minLength": 1, "maxLength": 8192},
    "after_sequence": {"type": "integer", "minimum": 0, "maximum": 9223372036854775807},
    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 20,
              "description": "Page size 1..50; default 20. Use the returned next_read for later pages."},
}
ALL_ISSUES = {"type": "boolean", "description": "Query all Issues; cannot be combined with issue_id."}
LISTS = {"list_messages", "list_handoffs", "list_board_instructions", "list_board_instruction_events"}
SPECS: dict[str, tuple[str, dict[str, Any], set[str]]] = {
    "post_message": (
        "Save ordinary information or an ordinary reply. Creates no handling request.",
        {"issue_id": {**ISSUE, "description": "Actual write Issue; omitted uses the host default. Replies require the corresponding Board action permissions."}, "text": TEXT, "reply_to": {**ID, "description": "Actual ordinary message ID; requests use answer_handoff."}},
        {"text"},
    ),
    "get_message": (
        "Read complete ordinary information; does not mark read or handle anything.",
        {"message_id": ID},
        {"message_id"},
    ),
    "list_messages": (
        "Read ordinary information in pages of 1..50; use next_read for later pages. Truncated text has a full read entrance.",
        {"issue_id": ISSUE, "all_issues": ALL_ISSUES,
         "include_descendants": {"type": "boolean", "description": "Include the IM Issue subtree; requires a configured IM tree connection. IM overview is limited to 128 nodes and 256 KiB. A page may be empty while next_read is present."},
         "expected_tree_snapshot": {"type": "string", "minLength": 64, "maxLength": 64, "description": "Tree snapshot from next_read; required with a subtree cursor."}, **PAGE},
        set(),
    ),
    "post_handoff": (
        "Save an explicit request to a host-allowed recipient. Does not activate a role.",
        {"issue_id": ISSUE, "text": TEXT, "recipient": {**ID, "description": "Actual recipient allowed by the host and service."}},
        {"text", "recipient"},
    ),
    "get_handoff": (
        "Read the original request and its exact answer as sender or bound recipient.",
        {"message_id": ID},
        {"message_id"},
    ),
    "list_handoffs": (
        "Read sender/recipient requests in pages of 1..50; use next_read for later pages. Does not handle requests; negative answers remain factual.",
        {"issue_id": ISSUE, "all_issues": ALL_ISSUES, "status": {"type": "string", "enum": ["pending", "handled"], "description": "按请求状态筛选：pending 尚未回答，handled 已记录答复。"}, **PAGE},
        set(),
    ),
    "answer_handoff": (
        "Record an exact answer and reason as the bound recipient. Handled is not scientific success.",
        {
            "message_id": {**ID, "description": "要回答的明确请求的 message_id。"},
            "answer": {**REASON, "description": "对请求的实际回答；未解决或否定的结果也如实写明。"},
            "reason": {**REASON, "description": "说明该回答的依据或原因。"},
            "result_refs": {
                "description": "可选的真实结果或材料引用；不代表已核验或采纳。",
                "type": "array",
                "maxItems": 30,
                "items": {"type": "string", "minLength": 1, "maxLength": 2048},
            },
        },
        {"message_id", "answer", "reason"},
    ),
    "create_board_instruction": (
        "Authenticated humans only: publish an explicit instruction from a readable human information message.",
        {
            "source_message_id": {**ID, "description": "可读取的真实人类普通留言 ID。"},
            "kind": {"type": "string", "enum": ["priority", "scope", "budget", "constraint"], "description": "指令类别：优先级、范围、预算或约束。"},
            "payload": {"type": "object", "description": "由真实人提供的指令内容对象；不会自动执行。"},
        },
        {"source_message_id", "kind", "payload"},
    ),
    "get_board_instruction": (
        "Read the complete instruction and actual revision/revocation history fields.",
        {"instruction_id": ID},
        {"instruction_id"},
    ),
    "list_board_instructions": (
        "Read active instructions; explicitly include revoked history if needed. Does not execute requirements.",
        {"issue_id": ISSUE, "all_issues": ALL_ISSUES, "include_revoked": {"type": "boolean"}, **PAGE},
        set(),
    ),
    "revoke_board_instruction": (
        "Authenticated humans only: revoke this instruction with a real reason, preserving original content and CAS history.",
        {"instruction_id": ID, "reason": REASON},
        {"instruction_id", "reason"},
    ),
    "list_board_instruction_events": (
        "Read immutable creation/revocation events in bounded pages.",
        {"issue_id": ISSUE, "all_issues": ALL_ISSUES, "instruction_id": ID, **PAGE},
        set(),
    ),
}


def validate(value: Any, rule: dict[str, Any], key: str) -> None:
    kind = rule["type"]
    if kind == "string":
        if isinstance(value, str) and not value.strip():
            raise ToolError("invalid_input", key + " must contain non-whitespace text",
                            fields=[{"path": "/" + key, "rule": "nonWhitespace"}])
        text(value, key, rule.get("maxLength", 200))
    elif kind == "integer":
        if type(value) is not int or not rule["minimum"] <= value <= rule["maximum"]:
            fail("invalid_input", key + " is outside its finite integer bounds")
    elif kind == "boolean":
        if type(value) is not bool:
            fail("invalid_input", key + " must be boolean")
    elif kind == "object":
        if not isinstance(value, dict) or len(canonical(value).encode()) > 8192:
            fail("invalid_input", key + " must be an object of at most 8192 bytes")
    elif kind == "array":
        if not isinstance(value, list) or len(value) > rule["maxItems"]:
            fail("invalid_input", key + " must be a finite array")
        for index, item in enumerate(value):
            validate(item, rule["items"], key + "/" + str(index))
    if "enum" in rule and value not in rule["enum"]:
        fail("invalid_input", key + " must be one of " + ", ".join(rule["enum"]))


class BoardTools:
    def __init__(self, client: BoardClient, profile: dict[str, Any]):
        self.client, self.profile = client, profile

    def definitions(self) -> list[dict[str, Any]]:
        definitions = []
        for name in self.profile["tools"]:
            description, properties, required = SPECS[name]
            required = set(required)
            if name in {"post_message", "post_handoff"} and not self.profile.get(
                "default_issue_id"
            ):
                required.add("issue_id")
            definitions.append(
                {
                    "name": name,
                    "description": description,
                    "inputSchema": {
                        "type": "object",
                        "properties": properties,
                        "required": sorted(required),
                        "additionalProperties": False,
                    },
                }
            )
        return definitions

    def call(self, name: str, arguments: Any) -> dict[str, Any]:
        if name not in self.profile["tools"]:
            fail("tool_not_enabled", "tool is not enabled by the host")
        spec = next(item for item in self.definitions() if item["name"] == name)["inputSchema"]
        try:
            validate_schema_arguments(self.definitions(), name, arguments)
        except ContractError as exc:
            raise ToolError("invalid_input", str(exc), fields=exc.fields,
                            fields_truncated=exc.fields_truncated) from exc
        arguments = dict(fields(arguments, set(spec["required"]), set(spec["properties"])))
        for key, value in arguments.items():
            validate(value, spec["properties"][key], key)
        all_issues = arguments.pop("all_issues", False)
        subtree = arguments.pop("include_descendants", False)
        expected_tree = arguments.pop("expected_tree_snapshot", None)
        if all_issues and "issue_id" in arguments:
            fail("invalid_input", "all_issues cannot be combined with issue_id")
        if (subtree and all_issues) or (expected_tree is not None and not subtree):
            fail("invalid_input", "subtree and all-Issue scopes are incompatible")
        if (
            name
            in {
                "post_message",
                "post_handoff",
                "list_messages",
                "list_handoffs",
                "list_board_instructions",
                "list_board_instruction_events",
            }
            and "issue_id" not in arguments
            and not all_issues
            and self.profile.get("default_issue_id") is not None
        ):
            arguments["issue_id"] = self.profile["default_issue_id"]
        if subtree:
            if name != "list_messages" or not arguments.get("issue_id"):
                fail("invalid_input", "subtree requires an Issue")
            return self._subtree_messages(arguments, expected_tree)
        if name in BOARD_WRITES:
            return self.client.write(name, **arguments)
        result = self.client.read(name, **arguments)
        if name == "get_message":
            self._message_entrances(result)
        elif name == "list_messages":
            for item in result.get("items", []):
                self._message_entrances(item)
        if name in LISTS:
            issue = arguments.get("issue_id")
            result["query_scope"] = ({"mode": "issue", "issue_id": issue} if issue is not None
                                     else {"mode": "all_issues"})
            if issue is None and result.get("next_read"):
                result["next_read"]["arguments"]["all_issues"] = True
        return result

    def _subtree_messages(self, arguments: dict[str, Any], expected: str | None) -> dict[str, Any]:
        from .client import WorkflowAPIError
        from .im_client import IMClient

        connection = self.profile.get("tree_connection")
        if not connection:
            fail("invalid_configuration", "subtree queries require tree_connection")
        if bool(arguments.get("cursor")) != (expected is not None):
            fail("invalid_input", "subtree cursor and expected_tree_snapshot must be supplied together")
        tree = IMClient.from_connection(connection, str(self.profile["journal_path"]) + ".tree.json")
        root = arguments["issue_id"]
        try:
            overview = tree.get_issue_overview(root)
        except WorkflowAPIError as exc:
            raise ToolError(exc.code, str(exc), status=exc.status) from exc
        snapshot = overview["snapshot"]["content_sha256"]
        if expected is not None and expected != snapshot:
            fail("snapshot_changed", "IM tree changed; restart pagination", status=409)
        ids = {node["issue_id"] for node in overview["nodes"]}
        scope_tag = hashlib.sha256(canonical({"root": root, "snapshot": snapshot,
            "endpoint": connection["endpoint"]}).encode("utf-8")).hexdigest()
        query = {k: v for k, v in arguments.items() if k != "issue_id"}
        result = self.client.read("list_messages", **query, scope_tag=scope_tag)
        try:
            after = tree.get_issue_overview(root)["snapshot"]["content_sha256"]
        except WorkflowAPIError as exc:
            raise ToolError(exc.code, str(exc), status=exc.status) from exc
        if after != snapshot:
            fail("snapshot_changed", "IM tree changed during query; restart pagination", status=409)
        result["items"] = [item for item in result["items"] if item["issue_id"] in ids]
        for item in result["items"]:
            self._message_entrances(item)
        result["query_scope"] = {"mode": "subtree", "issue_id": root, "tree_snapshot": snapshot}
        result["next_read"] = ({"tool": "list_messages", "arguments": {**arguments,
            "include_descendants": True, "expected_tree_snapshot": snapshot,
            "cursor": result["next_cursor"]}} if result.get("next_cursor") else None)
        return result

    def _message_entrances(self, item: dict[str, Any]) -> None:
        if item.get("purpose") != "information":
            return
        message_id, issue_id = item.get("message_id"), item.get("issue_id")
        if ("post_message" in self.profile["tools"] and isinstance(message_id, str)
                and message_id and isinstance(issue_id, str) and issue_id):
            item["reply"] = {"tool": "post_message", "arguments": {
                "reply_to": message_id, "issue_id": issue_id}, "required_arguments": ["text"]}
        if "get_message" in self.profile["tools"] and isinstance(item.get("reply_to"), str) and item["reply_to"]:
            item["parent_read"] = {"tool": "get_message", "arguments": {"message_id": item["reply_to"]}}
