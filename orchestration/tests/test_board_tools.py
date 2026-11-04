"""Step-3 business acceptance over real standalone HTTP, CLI and stdio processes."""

from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from board_tools_harness import BoardMCP, running_board
from board_transport_harness import FaultProxy
from queue_tools_harness import ManagedProcess, command_env, evidence, raw
from workflow_orchestrator.board_client import BoardClient
from workflow_orchestrator.board_contracts import BOARD_ACTIONS
from workflow_orchestrator.tools_contracts import ToolError


@pytest.fixture
def service(tmp_path):
    with running_board(tmp_path / "board") as value:
        yield value


def client(service, name="manager", suffix="", endpoint=None):
    return BoardClient(
        endpoint or service.endpoint, service.tokens[name], service.path / (name + suffix + ".json")
    )


def post(c, text="Partial and negative findings are preserved.", issue="A", **extra):
    return c.write("post_message", issue_id=issue, text=text, **extra)


def request(c, **extra):
    return c.write(
        "post_handoff",
        issue_id="A",
        text="What remains unresolved?",
        recipient="scientist",
        **extra,
    )


def instruction(c, source):
    return c.write(
        "create_board_instruction",
        source_message_id=source,
        kind="constraint",
        payload={"text": "Keep the sample cold; no new measurement is authorized."},
    )


def refusal(code, call):
    with pytest.raises(ToolError) as caught:
        call()
    assert caught.value.code == code, caught.value.result()
    return caught.value.result()


def test_mcp_all_authorized_issue_scope_and_pagination(service):
    post(client(service), issue="A", text="A")
    post(client(service), issue="B", text="B")
    post(client(service, "c"), issue="C", text="C")
    with BoardMCP(service, profile=service.profile()) as mcp:
        assert [x["issue_id"] for x in mcp.call("list_messages", {})["items"]] == ["A"]
        page = mcp.call("list_messages", {"all_issues": True, "limit": 1})
        assert page["query_scope"] == {"mode": "all_issues"}
        assert page["next_read"]["arguments"]["all_issues"] is True
        tail = mcp.call(**{"name": page["next_read"]["tool"], "arguments": page["next_read"]["arguments"]})
        assert {page["items"][0]["issue_id"], tail["items"][0]["issue_id"]} == {"A", "B"}
        assert mcp.call("list_messages", {"all_issues": True, "issue_id": "B"})["error"]["code"] == "invalid_input"
        assert mcp.call("list_messages", {"issue_id": "B"})["query_scope"] == {"mode": "issue", "issue_id": "B"}


@pytest.mark.parametrize("name,filters", [
    ("list_handoffs", {"status": "pending"}),
    ("list_board_instructions", {"include_revoked": True}),
    ("list_board_instruction_events", {}),
])
def test_all_issue_other_lists_continue_with_filters(service, name, filters):
    manager, human = client(service), client(service, "human")
    for issue in ("A", "B"):
        manager.write("post_handoff", issue_id=issue, text="Question", recipient="scientist")
        source = post(human, issue=issue)["message_id"]
        instruction(human, source)
    with BoardMCP(service, profile=service.profile()) as mcp:
        first = mcp.call(name, {"all_issues": True, "limit": 1, **filters})
        continuation = first["next_read"]["arguments"]
        assert continuation["all_issues"] is True and "issue_id" not in continuation
        assert all(continuation[k] == v for k, v in filters.items())
        second = mcp.call(name, continuation)
        assert {first["items"][0]["issue_id"], second["items"][0]["issue_id"]} == {"A", "B"}
        assert second["next_read"] is None


def test_ordinary_mcp_replies_and_new_process_reads(service):
    profile = service.profile()
    with BoardMCP(service, profile=profile) as mcp:
        definitions = mcp.rpc("tools/list", {})["tools"]
        assert {v["name"] for v in definitions} == BOARD_ACTIONS
        for item in definitions:
            assert (
                not {"actor", "operation_id", "expected_revision"}
                & item["inputSchema"]["properties"].keys()
            )
        first = mcp.call("post_message", {"text": "A reminder is ordinary information."})
        second = mcp.call("post_message", {"text": "A reminder is ordinary information."})
        reply = mcp.call(
            "post_message",
            {"text": "Read and recorded a negative result.", "reply_to": first["message_id"]},
        )
        assert first["message_id"] != second["message_id"]
    with BoardMCP(service, profile=profile) as fresh:
        saved = fresh.call("get_message", {"message_id": first["message_id"]})
        saved_reply = fresh.call("get_message", {"message_id": reply["message_id"]})
        assert saved["author"] == "manager" and saved["author_kind"] == "service"
        assert (
            saved_reply["reply_to"] == first["message_id"]
            and saved_reply["purpose"] == "information"
        )
        assert fresh.call("list_handoffs", {})["items"] == []
        assert fresh.call("list_board_instructions", {})["items"] == []
        spoof = fresh.call("post_message", {"text": "spoof", "actor": "human"})
        assert spoof["error"]["code"] == "invalid_input"
    assert service.counts() == dict(
        messages=3, handoffs=0, instructions=0, instruction_events=0, receipts=3
    )
    evidence(
        "board-ordinary-mcp",
        {
            "definitions": definitions,
            "first": first,
            "second": second,
            "reply": saved_reply,
            "fresh_read": saved,
            "counts": service.counts(),
        },
    )


def test_reply_authority_type_depth_and_read_only(service):
    manager = client(service)
    source = post(manager, text="正文原样保留。" + "z" * 7000)["message_id"]
    handoff = request(manager)["message_id"]
    before = service.counts()
    errors = []
    for action in [
        lambda: post(manager, reply_to="msg-absent"),
        lambda: post(manager, reply_to=handoff),
        lambda: post(client(service, "writer"), reply_to=source),
    ]:
        with pytest.raises(ToolError) as caught:
            action()
        assert caught.value.effect == "not_committed"
        errors.append(caught.value.result())
    assert service.counts() == before
    assert post(manager, issue="C", reply_to=source)["message"]["issue_id"] == "C"
    before = service.counts()
    page = manager.read("list_messages", issue_id="A", limit=1)
    assert not page["items"][0]["text_complete"] and len(page["items"][0]["text"]) == 1024
    assert manager.read("get_message", message_id=source)["text"] == "正文原样保留。" + "z" * 7000
    assert manager.read("get_handoff", message_id=handoff)["status"] == "pending"
    assert service.counts() == before
    tail = source
    for _ in range(16):
        tail = post(manager, reply_to=tail)["message_id"]
    deep = refusal("invalid_input", lambda: post(manager, reply_to=tail))
    assert service.counts()["handoffs"] == 1
    assert manager.read("get_handoff", message_id=handoff)["status"] == "pending"
    evidence(
        "board-reply-refusals",
        {"errors": errors, "page": page, "depth_refusal": deep, "counts": service.counts()},
    )


def test_handoff_recipient_and_exact_negative_answer(service):
    sender, receiver = client(service), client(service, "worker")
    posted = request(sender)
    target = posted["message_id"]
    before = service.counts()
    assert (
        receiver.read("list_handoffs", issue_id="A", status="pending")["items"][0]["message_id"]
        == target
    )
    assert receiver.read("get_handoff", message_id=target)["status"] == "pending"
    assert service.counts() == before
    errors = [
        refusal(
            "forbidden", lambda: client(service, "foreign").read("get_handoff", message_id=target)
        ),
        refusal("forbidden", lambda: client(service, "c").read("get_handoff", message_id=target)),
        refusal(
            "forbidden",
            lambda: sender.write(
                "answer_handoff", message_id=target, answer="no", reason="not recipient"
            ),
        ),
        refusal(
            "forbidden",
            lambda: sender.write(
                "post_handoff", issue_id="A", text="not allowed", recipient="foreign"
            ),
        ),
    ]
    assert client(service, "foreign").read("list_handoffs")["items"] == []
    answer = receiver.write(
        "answer_handoff",
        message_id=target,
        answer="No measurement was obtained; the fault remains unresolved.",
        reason="The trace is incomplete.",
        result_refs=["archive:failed-trace"],
    )
    saved = sender.read("get_handoff", message_id=target)
    assert saved["answer"] == answer["handoff"]["answer"] and saved["answered_by"] == "worker"
    assert saved["status"] == "handled" and saved["revision"] == 2
    assert service.counts()["handoffs"] == 1 and service.counts()["messages"] == 1
    evidence(
        "board-exact-answer",
        {
            "request": posted,
            "answer": answer,
            "sender_read": saved,
            "refusals": errors,
            "counts": service.counts(),
        },
    )


def test_competing_answers_and_original_winner_replay(service):
    target = request(client(service))["message_id"]

    def answer(name):
        return raw(
            service.endpoint,
            service.tokens[name],
            "POST",
            "/v1/board/handoffs/" + target + "/answer",
            {
                "operation_id": "race-" + name,
                "expected_revision": 1,
                "answer": "Actual " + name + " answer",
                "reason": "same original revision",
            },
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(answer, ["worker", "worker2"]))
    assert sorted(v[0] for v in results) == [200, 409]
    winner = next(v[1] for v in results if v[0] == 200)
    name = winner["handoff"]["answered_by"]
    replay = answer(name)
    assert replay[0] == 200 and replay[1]["replayed"] and replay[1]["handoff"] == winner["handoff"]
    saved = client(service).read("get_handoff", message_id=target)
    assert saved["answer"] == winner["handoff"]["answer"] and service.counts()["receipts"] == 2
    evidence(
        "board-answer-race",
        {"attempts": results, "replay": replay, "read": saved, "counts": service.counts()},
    )


def test_human_instructions_source_permissions_cas_and_history(service):
    human, manager = client(service, "human"), client(service)
    source = post(human, text="Explicit human boundary, no automatic execution.")["message_id"]
    service_source = post(manager, text="Just a reminder.")["message_id"]
    errors = [
        refusal("forbidden", lambda: instruction(manager, source)),
        refusal("forbidden", lambda: instruction(client(service, "human_no"), source)),
        refusal("invalid_transition", lambda: instruction(human, service_source)),
    ]
    remote = post(human, issue="C")["message_id"]
    assert manager.read("get_message", message_id=remote)["issue_id"] == "C"
    status, spoof = raw(
        service.endpoint,
        service.tokens["manager"],
        "POST",
        "/v1/board/instructions",
        {
            "operation_id": "spoof",
            "source_message_id": source,
            "kind": "constraint",
            "payload": {},
            "actor": {"kind": "human"},
        },
    )
    assert status == 400 and spoof["error"]["code"] == "invalid_input"
    assert manager.read("list_board_instructions")["items"] == []
    created = instruction(human, source)
    target = created["instruction_id"]

    def revoke(name):
        return raw(
            service.endpoint,
            service.tokens["human"],
            "POST",
            "/v1/board/instructions/" + target + "/revoke",
            {
                "operation_id": "revoke-" + name,
                "expected_revision": 1,
                "reason": "Actual revocation " + name,
            },
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        attempts = list(pool.map(revoke, ["one", "two"]))
    assert sorted(r[0] for r in attempts) == [200, 409]
    winner = next(r[1] for r in attempts if r[0] == 200)
    name = winner["instruction"]["revoke_reason"].split()[-1]
    assert revoke(name)[1]["replayed"]
    assert manager.read("list_board_instructions")["items"] == []
    history = manager.read("list_board_instructions", include_revoked=True)["items"]
    assert (
        history[0]["payload"] == created["instruction"]["payload"] and history[0]["revision"] == 2
    )
    events = manager.read("list_board_instruction_events", instruction_id=target, limit=1)
    second = manager.read(events["next_read"]["tool"], **events["next_read"]["arguments"])
    assert [events["items"][0]["event_type"], second["items"][0]["event_type"]] == [
        "created",
        "revoked",
    ]
    assert service.counts()["instruction_events"] == 2
    evidence(
        "board-human-history",
        {
            "created": created,
            "refusals": errors,
            "attempts": attempts,
            "history": history,
            "event_pages": [events, second],
            "counts": service.counts(),
        },
    )


def test_all_list_pages_filter_and_cursor_boundaries(service):
    manager = client(service)
    human = client(service, "human")
    for index in range(3):
        source = post(human, text="human " + str(index))["message_id"]
        instruction(human, source)
        request(manager)
    post(manager, issue="B")
    pages = {}
    for action in (
        "list_messages",
        "list_handoffs",
        "list_board_instructions",
        "list_board_instruction_events",
    ):
        before = service.counts()
        page = manager.read(action, issue_id="A", after_sequence=0, limit=1)
        values = []
        chain = []
        while True:
            chain.append(page)
            values += page["items"]
            if not page["next_read"]:
                break
            next_read = page["next_read"]
            page = manager.read(next_read["tool"], **next_read["arguments"])
        assert len(values) == 3 and len(chain) == 3 and all(v["issue_id"] == "A" for v in values)
        assert service.counts() == before
        initial = chain[0]
        refusal(
            "invalid_cursor",
            lambda: manager.read(
                action, issue_id="B", after_sequence=0, limit=1, cursor=initial["next_cursor"]
            ),
        )
        refusal(
            "invalid_cursor",
            lambda: client(service, "worker").read(
                action, issue_id="A", after_sequence=0, limit=1, cursor=initial["next_cursor"]
            ),
        )
        pages[action] = chain
    messages = manager.read("list_messages", issue_id="A")["items"]
    sequence = messages[0]["sequence"]
    increment = manager.read("list_messages", issue_id="A", after_sequence=sequence)
    assert (
        all(v["sequence"] > sequence for v in increment["items"]) and len(increment["items"]) == 2
    )
    initial = manager.read("list_handoffs", issue_id="A", status="pending", limit=1)
    first = initial["items"][0]["message_id"]
    client(service, "worker").write(
        "answer_handoff", message_id=first, answer="still unresolved", reason="no data"
    )
    refusal(
        "snapshot_changed",
        lambda: manager.read(
            "list_handoffs", issue_id="A", status="pending", limit=1, cursor=initial["next_cursor"]
        ),
    )
    evidence(
        "board-all-pages", {"pages": pages, "incremental": increment, "counts": service.counts()}
    )


@pytest.mark.parametrize(
    "action",
    [
        "post_message",
        "reply",
        "answer_handoff",
        "create_board_instruction",
        "revoke_board_instruction",
    ],
)
def test_lost_response_transient_errors_and_original_recovery(service, action):
    direct = client(service)
    human = client(service, "human")
    target = None
    if action == "reply":
        target = post(direct)["message_id"]
    elif action == "answer_handoff":
        target = request(direct)["message_id"]
    elif action in {"create_board_instruction", "revoke_board_instruction"}:
        target = post(human)["message_id"]
        if action == "revoke_board_instruction":
            target = instruction(human, target)["instruction_id"]
    name = (
        "human"
        if "instruction" in action
        else "worker"
        if action == "answer_handoff"
        else "manager"
    )
    with FaultProxy(service) as proxy:
        current = client(service, name, "-lost-" + action, proxy.endpoint)
        proxy.inject("drop")

        def write():
            if action == "reply":
                return post(current, reply_to=target)
            if action == "post_message":
                return post(current)
            if action == "answer_handoff":
                return current.write(
                    action,
                    message_id=target,
                    answer="No valid result exists yet.",
                    reason="Negative evidence preserved.",
                )
            if action == "create_board_instruction":
                return instruction(current, target)
            return current.write(
                action, instruction_id=target, reason="Human ended this requirement."
            )

        with pytest.raises(ToolError) as caught:
            write()
        original = caught.value.operation_id
        assert original and caught.value.effect == "unknown"
        counts = service.counts()
        rebuilt = BoardClient(proxy.endpoint, service.tokens[name], current.journal.path)
        errors = [caught.value.result()]
        for status, html in [(429, False), (503, True)]:
            proxy.inject("before", status, html=html)
            with pytest.raises(ToolError) as uncertain:
                rebuilt.recover(original)
            assert uncertain.value.effect == "unknown"
            assert rebuilt.journal.load()["actions"][original]["state"] == "pending"
            errors.append(uncertain.value.result())
        # Unknown protects one action only; an unrelated legal message still succeeds.
        independent = post(direct, issue="B", text="Independent message during unknown action.")
        recovered = rebuilt.recover(original)
        assert recovered["replayed"] and recovered["operation_id"] == original
        assert rebuilt.recover(original) == recovered
        assert service.counts()["receipts"] == counts["receipts"] + 1
        posts = [e for e in proxy.events() if e["method"] == "POST"]
        assert (
            len(posts) == 4
            and posts[0]["forwarded"]
            and not posts[1]["forwarded"]
            and not posts[2]["forwarded"]
        )
        assert all(e["body"] == posts[0]["body"] and e["path"] == posts[0]["path"] for e in posts)
        evidence(
            "board-loss-" + action,
            {
                "original_id": original,
                "errors": errors,
                "recovered": recovered,
                "independent": independent,
                "events": proxy.events(),
                "counts": service.counts(),
            },
        )


@pytest.mark.parametrize("status", [408, 425, 429, 502, 503])
def test_committed_then_temporary_http_does_not_reject(service, status):
    with FaultProxy(service) as proxy:
        current = client(service, suffix="-http" + str(status), endpoint=proxy.endpoint)
        # A forged not_committed gateway envelope is still temporary HTTP.
        proxy.inject(
            "after",
            status,
            html=status == 503,
            payload=None
            if status == 503
            else json.dumps(
                {"error": {"code": "gateway_busy", "message": "retry", "effect": "not_committed"}}
            ),
        )
        with pytest.raises(ToolError) as caught:
            post(current)
        assert caught.value.effect == "unknown"
        result = current.recover(caught.value.operation_id)
        assert result["replayed"] and service.counts()["messages"] == 1
        evidence(
            "board-transient-" + str(status),
            {"error": caught.value.result(), "recovered": result, "events": proxy.events()},
        )


@pytest.mark.parametrize("payload", ["<html>bad 200</html>", "[]", "{}", '{"message":{}}'])
def test_unrecognized_success_is_unknown(service, payload):
    with FaultProxy(service) as proxy:
        current = client(service, suffix="-malformed", endpoint=proxy.endpoint)
        proxy.inject("after", 200, payload=payload)
        with pytest.raises(ToolError) as caught:
            post(current)
        assert caught.value.code == "invalid_response" and caught.value.effect == "unknown"
        assert current.recover(caught.value.operation_id)["replayed"]
        assert service.counts()["messages"] == 1


@pytest.mark.parametrize("stage", ["before", "after"])
def test_journal_failure_no_send_or_original_receipt_recovery(service, stage):
    current = client(service)
    save = current.journal.save

    def fail(value):
        intents = value["actions"].values()
        if (stage == "before" and any(not v["sent"] for v in intents)) or (
            stage == "after" and any(v["state"] == "confirmed" for v in intents)
        ):
            raise OSError("synthetic journal failure")
        save(value)

    current.journal.save = fail
    with pytest.raises(ToolError) as caught:
        post(current)
    assert caught.value.code == "journal_write_failed"
    if stage == "before":
        assert caught.value.effect == "not_committed" and service.counts()["messages"] == 0
    else:
        assert caught.value.effect == "unknown" and service.counts()["messages"] == 1
        rebuilt = client(service)
        assert rebuilt.recover(caught.value.operation_id)["replayed"]
    evidence("board-journal-" + stage, {"error": caught.value.result(), "counts": service.counts()})


def test_cas_recovery_never_refreshes_captured_revision(service):
    target = request(client(service))["message_id"]
    with FaultProxy(service) as proxy:
        receiver = client(service, "worker", "-stale", proxy.endpoint)
        proxy.inject("before", 503, html=True)
        with pytest.raises(ToolError) as caught:
            receiver.write(
                "answer_handoff",
                message_id=target,
                answer="Original answer",
                reason="Original frozen revision",
            )
        original = caught.value.operation_id
        winner = client(service, "worker2").write(
            "answer_handoff",
            message_id=target,
            answer="Concurrent real answer",
            reason="New independent action",
        )
        denied = refusal("stale_revision", lambda: receiver.recover(original))
        assert denied["error"]["effect"] == "not_committed"
        assert receiver.journal.load()["actions"][original]["body"]["expected_revision"] == 1
        assert (
            client(service).read("get_handoff", message_id=target)["answer"]
            == winner["handoff"]["answer"]
        )
        evidence(
            "board-cas-original",
            {
                "refusal": denied,
                "winner": winner,
                "events": proxy.events(),
                "counts": service.counts(),
            },
        )


def test_restart_store_and_host_binding_changes_refuse_original(service):
    current = client(service)
    saved = post(current)
    old = service.service_id
    service.stop()
    service.start()
    assert service.service_id == old and current.recover(saved["operation_id"]) == saved
    # Same URL, another new synthetic store; original journal stays untouched.
    service.stop()
    service.config["database_path"] = str(service.path / "replacement.sqlite")
    service.start()
    assert service.service_id != old
    changed = refusal("recovery_binding_changed", lambda: client(service))
    assert service.counts()["messages"] == 0
    service.stop()
    service.config["database_path"] = str(service.path / "board.sqlite")
    service.start()
    # An unchanged credential cannot silently change kind, recipient or permissions.
    original = service.config["principals"][0].copy()
    for key, new in [("kind", "human"), ("recipient", "different"), ("actions", ["list_messages"])]:
        service.stop()
        service.config["principals"][0][key] = new
        service.start()
        refusal("recovery_binding_changed", lambda: client(service))
        service.stop()
        service.config["principals"][0] = original.copy()
        service.start()
    assert client(service).recover(saved["operation_id"]) == saved
    evidence(
        "board-binding-changes",
        {"saved": saved, "replaced_store_error": changed, "restored": service.service_id},
    )


@pytest.mark.parametrize(
    "field", ["text", "issue_id", "operation_id", "path", "action", "expected_revision"]
)
def test_tampered_original_intent_refused_before_post(service, field):
    target = request(client(service))["message_id"]
    with FaultProxy(service) as proxy:
        receiver = client(service, "worker", "-tamper", proxy.endpoint)
        proxy.inject("drop")
        with pytest.raises(ToolError) as caught:
            receiver.write(
                "answer_handoff", message_id=target, answer="Saved answer", reason="No overwrite"
            )
        original = caught.value.operation_id
        data = receiver.journal.load()
        intent = data["actions"][original]
        if field in {"path", "action"}:
            intent[field] = "changed"
        else:
            intent["body"][field] = "changed"
        receiver.journal.save(data)
        before = len(proxy.events())
        counts = service.counts()
        refusal("intent_conflict", lambda: receiver.recover(original))
        assert len(proxy.events()) == before and service.counts() == counts
        evidence(
            "board-intent-" + field,
            {"error": "intent_conflict", "original_id": original, "counts": counts},
        )


def test_mcp_restart_unknown_cli_recover_and_selected_catalog(service):
    with FaultProxy(service) as proxy:
        profile = service.profile(
            tools=["post_message", "get_message"],
            connection={"endpoint": proxy.endpoint, "token_env": "MCP_QUEUE_TOKEN"},
        )
        with BoardMCP(service, profile=profile) as mcp:
            assert len(mcp.rpc("tools/list", {})["tools"]) == 2
            proxy.inject("drop")
            error = mcp.call("post_message", {"text": "Preserve the exact original message."})
            original = error["error"]["operation_id"]
            assert error["error"]["effect"] == "unknown"
            assert mcp.call("list_handoffs", {})["error"]["code"] == "tool_not_enabled"
        proxy.inject("before", 429)
        with BoardMCP(service, profile=profile) as mcp:
            new = mcp.call("post_message", {"text": "Another independent legitimate message."})
            assert "message_id" in new
        command, env = command_env({"MCP_QUEUE_TOKEN": service.tokens["manager"]})
        proc = ManagedProcess(
            command + ["recover", "--profile", str(profile), "--operation-id", original],
            service.path,
            env,
            "board-cli-recover",
        )
        try:
            recovered = json.loads(proc.line())
            proc.process.wait(15)
            assert proc.process.returncode == 0
        finally:
            proc.close()
        assert recovered["replayed"] and service.counts()["messages"] == 2
        evidence(
            "board-mcp-unknown-cli",
            {"first_error": error, "new": new, "recovered": recovered, "events": proxy.events()},
        )


def test_finite_http_and_permissions_reject_without_side_effects(service):
    c = client(service)
    before = service.counts()
    bodies = [
        {"operation_id": "bad", "issue_id": "A", "text": "x", "author": "human"},
        {"operation_id": "bad", "issue_id": "A", "text": "x", "kind": "human"},
    ]
    results = [
        raw(service.endpoint, service.tokens["manager"], "POST", "/v1/board/messages", body)
        for body in bodies
    ]
    assert [r[0] for r in results] == [400, 400]
    refusal("forbidden", lambda: post(client(service, "reader")))
    for args in ({"limit": 0}, {"limit": 51}, {"after_sequence": -1}, {"include_revoked": True}):
        refusal("invalid_input", lambda: c.read("list_messages", **args))
    for path in [
        "/v1/queue/tasks",
        "/v1/board/messages/missing/edit",
        "/v1/board/handoffs/missing/forward",
    ]:
        status, value = raw(
            service.endpoint,
            service.tokens["manager"],
            "POST",
            path,
            {"operation_id": "forbidden-route"},
        )
        assert status == 404
    assert service.counts() == before
    evidence("board-finite-refusals", {"results": results, "counts": service.counts()})


def test_installed_loading_and_offline_catalog(service):
    command, env = command_env()
    python = os.environ.get("WORKFLOW_TEST_PYTHON", sys.executable)
    source = 'import json,sys; from workflow_orchestrator import board_facade; print(json.dumps({"file":board_facade.__file__,"tools":sorted(board_facade.SPECS),"modules":sorted(sys.modules)}))'
    proc = ManagedProcess([python, "-B", "-c", source], service.path, env, "board-import-audit")
    try:
        value = json.loads(proc.line())
        proc.process.wait(15)
        assert proc.process.returncode == 0
    finally:
        proc.close()
    forbidden = {
        "queue_service",
        "queue_store",
        "board",
        "board_tools",
        "message_dispatch",
        "trigger_service",
        "workflow_composition",
        "registered_settlement",
        "source_settlement",
        "action_fence",
        "im_client",
    }
    assert not any("workflow_orchestrator." + v in value["modules"] for v in forbidden)
    assert set(value["tools"]) == BOARD_ACTIONS
    if os.environ.get("WORKFLOW_TEST_CLI"):
        assert "site-packages" in value["file"] and "orchestration/src" not in value[
            "file"
        ].replace("\\", "/")
    evidence("board-import-audit", value)


def test_authority_rejection_and_previous_send_auth_unknown(service):
    with FaultProxy(service) as proxy:
        current = client(service, suffix="-authority", endpoint=proxy.endpoint)
        proxy.inject("invalid_auth")
        with pytest.raises(ToolError) as first:
            post(current)
        assert first.value.code == "unauthorized" and first.value.effect == "not_committed"
        assert current.journal.load()["actions"][first.value.operation_id]["state"] == "rejected"
        assert service.counts()["messages"] == 0
        proxy.inject("drop")
        with pytest.raises(ToolError) as lost:
            post(current)
        original = lost.value.operation_id
        proxy.inject("invalid_auth")
        with pytest.raises(ToolError) as retry:
            current.recover(original)
        assert retry.value.effect == "unknown"
        assert current.journal.load()["actions"][original]["state"] == "pending"
        assert current.recover(original)["replayed"] and service.counts()["messages"] == 1
        evidence(
            "board-authority-refusals",
            {
                "first": first.value.result(),
                "prior_unknown_auth": retry.value.result(),
                "events": proxy.events(),
                "counts": service.counts(),
            },
        )


def test_unrelated_store_is_not_initialized_or_repaired(tmp_path):
    import hashlib
    import sqlite3

    from workflow_orchestrator.board_records import BoardRecords

    path = tmp_path / "unrelated.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE unrelated(value TEXT)")
        db.execute("INSERT INTO unrelated VALUES (?)", ("preserve exactly",))
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    refusal("schema_mismatch", lambda: BoardRecords(path))
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before
    evidence("board-unrelated-store", {"path": str(path), "sha256_unchanged": before})


def test_pending_original_rejects_connection_and_recipient_rebinding(service):
    with FaultProxy(service) as proxy:
        current = client(service, suffix="-pending-binding", endpoint=proxy.endpoint)
        proxy.inject("drop")
        with pytest.raises(ToolError) as caught:
            post(current)
        original = caught.value.operation_id
        errors = []
        for endpoint, token, token_env in [
            (service.endpoint, service.tokens["manager"], "BOARD_TOKEN"),
            (proxy.endpoint, service.tokens["worker"], "BOARD_TOKEN"),
            (proxy.endpoint, service.tokens["manager"], "DIFFERENT_ENV"),
        ]:
            error = refusal(
                "recovery_binding_changed",
                lambda: BoardClient(endpoint, token, current.journal.path, token_env=token_env),
            )
            assert error["error"]["effect"] == "unknown"
            errors.append(error)
        principal = service.config["principals"][0].copy()
        for field, value in [("kind", "human"), ("recipient", "changed-mailbox")]:
            service.stop()
            service.config["principals"][0][field] = value
            service.start()
            error = refusal("recovery_binding_changed", lambda: current.recover(original))
            assert error["error"]["effect"] == "unknown"
            errors.append(error)
            service.stop()
            service.config["principals"][0] = principal.copy()
            service.start()
        oldpath = service.config["database_path"]
        service.stop()
        service.config["database_path"] = str(service.path / "pending-replacement.sqlite")
        service.start()
        errors.append(
            refusal(
                "recovery_binding_changed",
                lambda: BoardClient(
                    proxy.endpoint, service.tokens["manager"], current.journal.path
                ),
            )
        )
        assert service.counts()["messages"] == 0
        service.stop()
        service.config["database_path"] = oldpath
        service.start()
        recovered = current.recover(original)
        assert recovered["replayed"] and service.counts()["messages"] == 1
        evidence(
            "board-pending-binding",
            {
                "errors": errors,
                "recovered": recovered,
                "events": proxy.events(),
                "counts": service.counts(),
            },
        )
