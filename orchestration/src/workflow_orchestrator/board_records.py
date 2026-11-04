"""Independent Board records. This boundary opens only its own SQLite store."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Iterator

from .board_contracts import MAX_REPLY_DEPTH, BoardPrincipal, normalize
from .tools_contracts import ToolError, canonical, decode, fail, identifier, now, outside_path, text

DDL = """
CREATE TABLE board_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE messages(sequence INTEGER PRIMARY KEY AUTOINCREMENT, message_id TEXT UNIQUE NOT NULL,
 issue_id TEXT NOT NULL, text TEXT NOT NULL, reply_to TEXT REFERENCES messages(message_id),
 purpose TEXT NOT NULL CHECK(purpose IN ('information','request')),
 author TEXT NOT NULL, author_kind TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX messages_issue ON messages(issue_id,sequence);
CREATE TABLE handoffs(message_id TEXT PRIMARY KEY REFERENCES messages(message_id),
 sender_recipient TEXT NOT NULL, recipient TEXT NOT NULL, status TEXT NOT NULL,
 revision INTEGER NOT NULL, answer TEXT, reason TEXT, result_refs TEXT,
 answered_by TEXT, answered_kind TEXT, answered_at TEXT);
CREATE TABLE instructions(sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 instruction_id TEXT UNIQUE NOT NULL, source_message_id TEXT NOT NULL REFERENCES messages(message_id),
 issue_id TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, revision INTEGER NOT NULL,
 created_by TEXT NOT NULL, created_at TEXT NOT NULL, revoked_by TEXT, revoked_at TEXT, revoke_reason TEXT);
CREATE INDEX instructions_issue ON instructions(issue_id,sequence);
CREATE TABLE instruction_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 instruction_id TEXT NOT NULL REFERENCES instructions(instruction_id), issue_id TEXT NOT NULL,
 event_type TEXT NOT NULL, revision INTEGER NOT NULL, author TEXT NOT NULL,
 author_kind TEXT NOT NULL, created_at TEXT NOT NULL, payload TEXT NOT NULL);
CREATE TABLE receipts(operation_id TEXT PRIMARY KEY, principal_binding TEXT NOT NULL,
 action TEXT NOT NULL, target TEXT NOT NULL, body TEXT NOT NULL, receipt TEXT NOT NULL);
"""
SCHEMA = "workflow-tools-board-2"


class BoardRecords:
    def __init__(self, path: str | Path):
        self.path = outside_path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
            with closing(sqlite3.connect(self.path, isolation_level=None)) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.executescript("BEGIN IMMEDIATE;\n" + DDL)
                db.executemany(
                    "INSERT INTO board_meta VALUES (?,?)",
                    [
                        ("schema", SCHEMA),
                        ("service_id", str(uuid.uuid4())),
                        ("cursor_key", uuid.uuid4().hex + uuid.uuid4().hex),
                    ],
                )
                db.commit()
        try:
            with closing(sqlite3.connect(self.path.as_uri() + "?mode=ro", uri=True)) as db:
                meta = dict(db.execute("SELECT key,value FROM board_meta"))
                if meta.get("schema") != SCHEMA:
                    fail("schema_mismatch", "requires an independent current Board; no migration")
                self.service_id = str(uuid.UUID(meta["service_id"]))
                self._cursor_key = bytes.fromhex(meta["cursor_key"])
                self._inventory = self._schema(db)
                with closing(sqlite3.connect(":memory:")) as expected:
                    expected.executescript(DDL)
                    if self._inventory != self._schema(expected):
                        fail("schema_mismatch", "unexpected Board tables, indexes or triggers")
        except (sqlite3.Error, KeyError, ValueError) as exc:
            raise ToolError(
                "schema_mismatch", "Board is not current; no initialization or repair"
            ) from exc

    @staticmethod
    def _schema(db: sqlite3.Connection) -> list[Any]:
        return db.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        ).fetchall()

    @contextmanager
    def transaction(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        db = sqlite3.connect(
            self.path.as_uri() + "?mode=rw", uri=True, timeout=5, isolation_level=None
        )
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            meta = dict(db.execute("SELECT key,value FROM board_meta"))
            if meta.get("service_id") != self.service_id or meta.get("schema") != SCHEMA:
                fail("service_identity_changed", "original Board binding changed", status=409)
            # Opening an existing store never migrates, initializes or repairs it.
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def identity(self, principal: BoardPrincipal) -> dict[str, Any]:
        with self.transaction():
            return {
                "service_id": self.service_id,
                "modules": ["board"],
                "principal_id": principal.principal_id,
                "kind": principal.kind,
                "recipient": principal.recipient,
                "principal_binding": principal.binding_id,
            }

    @staticmethod
    def _message(db: sqlite3.Connection, message_id: str) -> dict[str, Any]:
        row = db.execute("SELECT * FROM messages WHERE message_id=?", (message_id,)).fetchone()
        if row is None:
            fail("not_found", "message not found", status=404)
        return dict(row)

    @classmethod
    def _handoff(cls, db: sqlite3.Connection, message_id: str) -> dict[str, Any]:
        item = cls._message(db, message_id)
        row = db.execute("SELECT * FROM handoffs WHERE message_id=?", (message_id,)).fetchone()
        if row is None:
            fail("invalid_transition", "message is not an explicit request")
        item.update(dict(row))
        item["result_refs"] = json.loads(item["result_refs"]) if item["result_refs"] else []
        return item

    @staticmethod
    def _instruction(db: sqlite3.Connection, instruction_id: str) -> dict[str, Any]:
        row = db.execute(
            "SELECT * FROM instructions WHERE instruction_id=?", (instruction_id,)
        ).fetchone()
        if row is None:
            fail("not_found", "instruction not found", status=404)
        item = dict(row)
        item["payload"] = json.loads(item["payload"])
        item["status"] = "revoked" if item["revoked_at"] else "active"
        return item

    @staticmethod
    def _participant(principal: BoardPrincipal, item: dict[str, Any]) -> None:
        if not (
            (item["author"], item["author_kind"], item["sender_recipient"])
            == (principal.principal_id, principal.kind, principal.recipient)
            or item["recipient"] == principal.recipient
        ):
            fail(
                "forbidden", "request is visible only to its sender and bound recipient", status=403
            )

    def get(self, principal: BoardPrincipal, action: str, target: str) -> dict[str, Any]:
        principal.require(action)
        identifier(target, "target")
        with self.transaction() as db:
            if action == "get_message":
                item = self._message(db, target)
                principal.require(action, item["issue_id"])
                if item["purpose"] != "information":
                    fail("invalid_transition", "use get_handoff for an explicit request")
            elif action == "get_handoff":
                item = self._handoff(db, target)
                principal.require(action, item["issue_id"])
                self._participant(principal, item)
            elif action == "get_board_instruction":
                item = self._instruction(db, target)
                principal.require(action, item["issue_id"])
            else:
                fail("invalid_input", "unsupported Board read")
            return item

    def _reply(self, db: sqlite3.Connection, principal: BoardPrincipal, reply_to: str) -> None:
        seen: set[str] = set()
        current: str | None = reply_to
        while current is not None:
            if current in seen or len(seen) >= MAX_REPLY_DEPTH:
                fail("invalid_input", "reply chain exceeds maximum depth 16 or is inconsistent")
            seen.add(current)
            parent = self._message(db, current)
            principal.require("get_message", parent["issue_id"])
            if parent["purpose"] != "information":
                fail("invalid_transition", "ordinary replies require ordinary readable information")
            current = parent["reply_to"]

    def write(
        self, principal: BoardPrincipal, action: str, target: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        normalized = normalize(action, body)
        operation_id = normalized["operation_id"]
        encoded = canonical(normalized)
        principal.require(action, normalized.get("issue_id"))
        if action in {"create_board_instruction", "revoke_board_instruction"}:
            principal.human()
        if target:
            identifier(target, "target")
        with self.transaction(write=True) as db:
            # Permissions and actual target are checked even for a replay. Revision checks
            # follow the original receipt lookup so the winning operation remains replayable.
            item: dict[str, Any] = {}
            if action == "answer_handoff":
                item = self._handoff(db, target)
                principal.require(action, item["issue_id"])
                if item["recipient"] != principal.recipient:
                    fail("forbidden", "only the host-bound recipient may answer", status=403)
            elif action == "revoke_board_instruction":
                item = self._instruction(db, target)
                principal.require(action, item["issue_id"])
            elif action == "create_board_instruction":
                item = self._message(db, normalized["source_message_id"])
                principal.require("get_message", item["issue_id"])
                principal.require(action, item["issue_id"])
                if item["author_kind"] != "human" or item["purpose"] != "information":
                    fail(
                        "invalid_transition",
                        "instruction source must be a readable human information message",
                    )
            elif action == "post_message" and normalized["reply_to"] is not None:
                self._reply(db, principal, normalized["reply_to"])
            elif (
                action == "post_handoff"
                and normalized["recipient"] not in principal.allowed_recipients
            ):
                fail("forbidden", "recipient is outside the host-allowed targets", status=403)
            old = db.execute(
                "SELECT * FROM receipts WHERE operation_id=?", (operation_id,)
            ).fetchone()
            if old:
                if (old["principal_binding"], old["action"], old["target"], old["body"]) != (
                    principal.binding_id,
                    action,
                    target,
                    encoded,
                ):
                    fail(
                        "idempotency_conflict",
                        "original operation identity, target or content differs",
                        status=409,
                    )
                return {**json.loads(old["receipt"]), "replayed": True}
            if action in {"post_message", "post_handoff"}:
                message_id = "msg-" + uuid.uuid4().hex
                db.execute(
                    "INSERT INTO messages(message_id,issue_id,text,reply_to,purpose,author,author_kind,created_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (
                        message_id,
                        normalized["issue_id"],
                        normalized["text"],
                        normalized.get("reply_to"),
                        "information" if action == "post_message" else "request",
                        principal.principal_id,
                        principal.kind,
                        now(),
                    ),
                )
                if action == "post_handoff":
                    db.execute(
                        "INSERT INTO handoffs(message_id,sender_recipient,recipient,status,revision) "
                        "VALUES (?,?,?,'pending',1)",
                        (message_id, principal.recipient, normalized["recipient"]),
                    )
                item = (
                    self._message(db, message_id)
                    if action == "post_message"
                    else self._handoff(db, message_id)
                )
                receipt: dict[str, Any] = {
                    "message_id": message_id,
                    "message": item,
                    "read_path": "/v1/board/"
                    + ("messages/" if action == "post_message" else "handoffs/")
                    + message_id,
                }
            elif action == "answer_handoff":
                if item["revision"] != normalized["expected_revision"]:
                    fail("stale_revision", "request revision changed", status=409)
                if item["status"] != "pending":
                    fail("invalid_transition", "request already has an answer", status=409)
                db.execute(
                    "UPDATE handoffs SET status='handled',revision=2,answer=?,reason=?,result_refs=?,"
                    "answered_by=?,answered_kind=?,answered_at=? WHERE message_id=? AND revision=?",
                    (
                        normalized["answer"],
                        normalized["reason"],
                        canonical(normalized["result_refs"]),
                        principal.principal_id,
                        principal.kind,
                        now(),
                        target,
                        normalized["expected_revision"],
                    ),
                )
                receipt = {
                    "message_id": target,
                    "handoff": self._handoff(db, target),
                    "read_path": "/v1/board/handoffs/" + target,
                }
            elif action == "create_board_instruction":
                instruction_id = "ins-" + uuid.uuid4().hex
                created = now()
                db.execute(
                    "INSERT INTO instructions(instruction_id,source_message_id,issue_id,kind,payload,"
                    "revision,created_by,created_at) VALUES (?,?,?,?,?,1,?,?)",
                    (
                        instruction_id,
                        normalized["source_message_id"],
                        item["issue_id"],
                        normalized["kind"],
                        canonical(normalized["payload"]),
                        principal.principal_id,
                        created,
                    ),
                )
                self._event(
                    db,
                    instruction_id,
                    item["issue_id"],
                    "created",
                    1,
                    principal,
                    created,
                    {k: normalized[k] for k in ("source_message_id", "kind", "payload")},
                )
                receipt = {
                    "instruction_id": instruction_id,
                    "instruction": self._instruction(db, instruction_id),
                    "read_path": "/v1/board/instructions/" + instruction_id,
                }
            else:
                if item["revision"] != normalized["expected_revision"]:
                    fail("stale_revision", "instruction revision changed", status=409)
                if item["revoked_at"] is not None:
                    fail("invalid_transition", "instruction already revoked", status=409)
                revoked = now()
                db.execute(
                    "UPDATE instructions SET revision=2,revoked_at=?,revoked_by=?,revoke_reason=? "
                    "WHERE instruction_id=? AND revision=?",
                    (
                        revoked,
                        principal.principal_id,
                        normalized["reason"],
                        target,
                        normalized["expected_revision"],
                    ),
                )
                self._event(
                    db,
                    target,
                    item["issue_id"],
                    "revoked",
                    2,
                    principal,
                    revoked,
                    {"reason": normalized["reason"]},
                )
                receipt = {
                    "instruction_id": target,
                    "instruction": self._instruction(db, target),
                    "read_path": "/v1/board/instructions/" + target,
                }
            receipt.update(operation_id=operation_id, service_id=self.service_id, replayed=False)
            db.execute(
                "INSERT INTO receipts VALUES (?,?,?,?,?,?)",
                (operation_id, principal.binding_id, action, target, encoded, canonical(receipt)),
            )
            return receipt

    @staticmethod
    def _event(
        db: sqlite3.Connection,
        target: str,
        issue: str,
        event: str,
        revision: int,
        principal: BoardPrincipal,
        at: str,
        payload: dict[str, Any],
    ) -> None:
        db.execute(
            "INSERT INTO instruction_events(instruction_id,issue_id,event_type,revision,author,"
            "author_kind,created_at,payload) VALUES (?,?,?,?,?,?,?,?)",
            (
                target,
                issue,
                event,
                revision,
                principal.principal_id,
                principal.kind,
                at,
                canonical(payload),
            ),
        )

    def _cursor(self, value: dict[str, Any]) -> str:
        payload = canonical(value).encode()
        signature = hmac.new(self._cursor_key, payload, hashlib.sha256).hexdigest().encode()
        return base64.urlsafe_b64encode(signature + b"." + payload).decode()

    def list(self, principal: BoardPrincipal, action: str, **params: Any) -> dict[str, Any]:
        principal.require(action, params.get("issue_id"))
        limit = params.get("limit", 20)
        if type(limit) is not int or not 1 <= limit <= 50:
            fail("invalid_input", "limit must be 1..50")
        after_sequence = params.get("after_sequence", 0)
        if type(after_sequence) is not int or not 0 <= after_sequence <= 9223372036854775807:
            fail("invalid_input", "after_sequence must be a nonnegative 64-bit integer")
        cursor = params.get("cursor")
        context = {
            "service_id": self.service_id,
            "principal_binding": principal.binding_id,
            "action": action,
            "filters": {k: v for k, v in params.items() if k not in {"limit", "cursor"}},
        }
        with self.transaction() as db:
            if action == "list_messages":
                table, alias = "messages", "m"
                select = "m.*"
                extra = " AND m.purpose='information'"
            elif action == "list_handoffs":
                table, alias = "messages", "m"
                select = "m.*"
                extra = (
                    " AND m.purpose='request' AND (h.recipient=? OR "
                    "(m.author=? AND m.author_kind=? AND h.sender_recipient=?))"
                )
            elif action == "list_board_instructions":
                table, alias, select = "instructions", "i", "i.*"
                extra = "" if params.get("include_revoked", False) else " AND i.revoked_at IS NULL"
            elif action == "list_board_instruction_events":
                table, alias, select, extra = "instruction_events", "e", "e.*", ""
            else:
                fail("invalid_input", "unsupported Board list")
            where = "1=1"
            values: list[Any] = []
            if params.get("issue_id") is not None:
                where += " AND " + alias + ".issue_id=?"
                values.append(params["issue_id"])
            where += extra
            join = ""
            if action == "list_handoffs":
                join = " JOIN handoffs h USING(message_id)"
                values.extend(
                    [
                        principal.recipient,
                        principal.principal_id,
                        principal.kind,
                        principal.recipient,
                    ]
                )
                if params.get("status") is not None:
                    if params["status"] not in {"pending", "handled"}:
                        fail("invalid_input", "status must be pending or handled")
                    where += " AND h.status=?"
                    values.append(params["status"])
            if params.get("instruction_id") is not None:
                if action != "list_board_instruction_events":
                    fail("invalid_input", "instruction_id filter requires event list")
                item = self._instruction(db, identifier(params["instruction_id"], "instruction_id"))
                principal.require(action, item["issue_id"])
                where += " AND e.instruction_id=?"
                values.append(params["instruction_id"])
            # Bind paging to the actual query and the current record history. Ordinary
            # incremental scans start anew with after_sequence; a cursor is a snapshot page.
            watermark = [
                db.execute("SELECT COALESCE(MAX(sequence),0) FROM messages").fetchone()[0],
                db.execute("SELECT COUNT(*) FROM handoffs WHERE revision=2").fetchone()[0],
                db.execute("SELECT COALESCE(MAX(sequence),0) FROM instruction_events").fetchone()[
                    0
                ],
            ]
            after = after_sequence
            if cursor is not None:
                text(cursor, "cursor", 8192)
                try:
                    signature, payload = base64.b64decode(
                        cursor, altchars=b"-_", validate=True
                    ).split(b".", 1)
                    expected = (
                        hmac.new(self._cursor_key, payload, hashlib.sha256).hexdigest().encode()
                    )
                    saved = decode(payload)
                    if not hmac.compare_digest(signature, expected) or saved["context"] != context:
                        raise ValueError()
                    if saved["watermark"] != watermark:
                        fail(
                            "snapshot_changed", "collection changed; restart pagination", status=409
                        )
                    if type(saved["after"]) is not int or saved["after"] < after_sequence:
                        raise ValueError()
                    after = saved["after"]
                except (ValueError, KeyError, TypeError):
                    fail("invalid_cursor", "cursor does not match this service, principal or query")
            rows = db.execute(
                "SELECT "
                + select
                + " FROM "
                + table
                + " "
                + alias
                + join
                + " WHERE "
                + where
                + " AND "
                + alias
                + ".sequence>? ORDER BY "
                + alias
                + ".sequence LIMIT ?",
                (*values, after, limit + 1),
            ).fetchall()
            items = []
            for row in rows[:limit]:
                if action == "list_handoffs":
                    item = self._handoff(db, row["message_id"])
                elif action == "list_board_instructions":
                    item = self._instruction(db, row["instruction_id"])
                else:
                    item = dict(row)
                    if action == "list_board_instruction_events":
                        item["payload"] = json.loads(item["payload"])
                if action in {"list_messages", "list_handoffs"}:
                    item["read"] = {
                        "tool": "get_message" if action == "list_messages" else "get_handoff",
                        "arguments": {"message_id": item["message_id"]},
                    }
                    item["text_complete"] = len(item["text"]) <= 1024
                    item["text"] = item["text"][:1024]
                items.append(item)
            next_cursor = (
                self._cursor(
                    {
                        "context": context,
                        "watermark": watermark,
                        "after": rows[limit - 1]["sequence"],
                    }
                )
                if len(rows) > limit
                else None
            )
            return {
                "items": items,
                "limit": limit,
                "next_cursor": next_cursor,
                "next_sequence": rows[min(limit, len(rows)) - 1]["sequence"]
                if rows
                else after_sequence,
                "has_more": next_cursor is not None,
                "service_id": self.service_id,
                "next_read": {"tool": action, "arguments": {**params, "cursor": next_cursor}}
                if next_cursor
                else None,
            }
