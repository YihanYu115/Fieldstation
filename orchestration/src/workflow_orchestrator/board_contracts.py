"""Finite Board permissions and host-bound human/recipient identity."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .tools_contracts import Principal, canonical, fail, fields, identifier, references, text

BOARD_WRITES = frozenset(
    {
        "post_message",
        "post_handoff",
        "answer_handoff",
        "create_board_instruction",
        "revoke_board_instruction",
    }
)
BOARD_ACTIONS = BOARD_WRITES | frozenset(
    {
        "get_message",
        "list_messages",
        "get_handoff",
        "list_handoffs",
        "get_board_instruction",
        "list_board_instructions",
        "list_board_instruction_events",
    }
)
MAX_REPLY_DEPTH = 16
KINDS = frozenset({"priority", "scope", "budget", "constraint"})


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class BoardPrincipal(Principal):
    kind: str
    recipient: str
    allowed_recipients: frozenset[str]

    @property
    def binding_id(self) -> str:
        return digest(
            {
                "principal_id": self.principal_id,
                "kind": self.kind,
                "recipient": self.recipient,
                "actions": sorted(self.actions),
                "allowed_recipients": sorted(self.allowed_recipients),
            }
        )

    def human(self) -> None:
        if self.kind != "human":
            fail("forbidden", "a host-authenticated human is required", status=403)


def normalize(action: str, body: Any) -> dict[str, Any]:
    required = {"operation_id"}
    optional: set[str] = set()
    if action in {"post_message", "post_handoff"}:
        required |= {"issue_id", "text"}
        if action == "post_handoff":
            required.add("recipient")
        else:
            optional.add("reply_to")
    elif action == "answer_handoff":
        required |= {"expected_revision", "answer", "reason"}
        optional.add("result_refs")
    elif action == "create_board_instruction":
        required |= {"source_message_id", "kind", "payload"}
    elif action == "revoke_board_instruction":
        required |= {"expected_revision", "reason"}
    else:
        fail("invalid_input", "unsupported Board write")
    fields(body, required, optional)
    value = dict(body)
    identifier(value["operation_id"], "operation_id")
    if "issue_id" in value:
        text(value["issue_id"], "issue_id")
        text(value["text"], "text", 16000)
    for key in ("reply_to", "recipient", "source_message_id"):
        if key in value and value[key] is not None:
            identifier(value[key], key)
    if "recipient" in value and value["recipient"] is None:
        fail("invalid_input", "recipient must be a finite name")
    if action == "post_message":
        value.setdefault("reply_to", None)
    if "expected_revision" in value:
        if type(value["expected_revision"]) is not int or value["expected_revision"] < 1:
            fail("invalid_input", "expected_revision must be a positive integer")
        text(value["reason"], "reason", 8192)
    if action == "answer_handoff":
        text(value["answer"], "answer", 8192)
        value["result_refs"] = references(value.get("result_refs", []))
    if action == "create_board_instruction":
        if not isinstance(value["kind"], str) or value["kind"] not in KINDS:
            fail("invalid_input", "kind must be priority, scope, budget or constraint")
        if (
            not isinstance(value["payload"], dict)
            or len(canonical(value["payload"]).encode()) > 8192
        ):
            fail("invalid_input", "payload must be a finite JSON object of at most 8192 bytes")
    return value
