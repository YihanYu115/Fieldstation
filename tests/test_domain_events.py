"""Real HTTP fact replay, authorization, rollback and idempotency; no model."""
import json
import sqlite3
from contextlib import closing

import pytest
from workflow_orchestrator.client import WorkflowAPIError, WorkflowClient

from issue_manager import IssueManager
from issue_manager.manager_api import ManagerService


def test_http_events_survive_offline_consumer_and_replay(tmp_path):
    ledger = tmp_path / "im"
    with closing(IssueManager.initialize(ledger)) as im:
        for issue in ("one", "two"):
            im.create_issue(issue, "investigation", issue)
        token = json.loads(im.credentials.path_for("organizer-agent").read_text(encoding="utf-8"))["token"]
        im.credentials.issue_actor(actor_id="submit-only", actor_kind="experiment_agent",
            capabilities={"intake.submit"}, maintenance_credential=im.credentials.path_for("maintenance-agent"))
        submit_token = json.loads(im.credentials.path_for("submit-only").read_text(encoding="utf-8"))["token"]
    with ManagerService(ledger, port=0) as server:
        c = WorkflowClient("http://%s:%s" % server.address, token)
        beginning = c.domain_events("one", start_now=True)
        packets = []
        for i in range(3):
            body = {"issue_id": "one", "content": "外部讨论贡献 " + str(i)}
            a = c.submit_field_packet(body, request_id=str(i), idempotency_key=str(i))
            b = c.submit_field_packet(body, request_id=str(i), idempotency_key=str(i))
            assert a["packet_id"] == b["packet_id"]
            packets.append(a["packet_id"])
        c.submit_field_packet({"issue_id": "two", "content": "Other scope"},
                              request_id="other", idempotency_key="other")
        first = c.domain_events("one", limit=1, stream_id=beginning["stream_id"])
        assert first["has_more"] and len(first["items"]) == 1
        with pytest.raises(WorkflowAPIError) as denied:
            WorkflowClient(c.base_url, "invalid").domain_events("one")
        assert denied.value.status == 403
        with pytest.raises(WorkflowAPIError) as denied:
            WorkflowClient(c.base_url, submit_token).domain_events("one")
        assert denied.value.status == 403
        with pytest.raises(WorkflowAPIError) as conflict:
            c.submit_field_packet({"issue_id": "one", "content": "changed"}, request_id="0", idempotency_key="changed")
        assert conflict.value.status == 409
        for kwargs in ({"after": 999}, {"stream_id": "different"}):
            with pytest.raises(WorkflowAPIError) as conflict:
                c.domain_events("one", **kwargs)
            assert conflict.value.status == 409
    # Both HTTP service and consumer restart; original IDs and position remain.
    with ManagerService(ledger, port=0) as server:
        c = WorkflowClient("http://%s:%s" % server.address, token)
        rest = c.domain_events("one", after=first["next_after"], stream_id=first["stream_id"])
        all_events = first["items"] + rest["items"]
        assert [e["object_id"] for e in all_events] == packets
        assert len({e["event_id"] for e in all_events}) == 3
        assert all(e["issue_id"] == "one" and "content" not in e for e in all_events)
        assert not c.domain_events("one", after=rest["next_after"])["items"]


def test_same_transaction_and_append_only_fact_history(tmp_path):
    with closing(IssueManager.initialize(tmp_path / "im")) as im:
        im.create_issue("one", "investigation", "One")
        with pytest.raises(RuntimeError):
            with im.store.transaction() as db:
                db.execute("INSERT INTO field_packets VALUES(?,?,?,?,?,?,?,?,?,?)",
                           ("packet", "req", "one", "body", "sha", "sha", "[]", "[]", "now", "organizer-agent"))
                assert db.execute("SELECT COUNT(*) FROM domain_events").fetchone()[0] == 1
                raise RuntimeError("rollback before domain commit")
        assert im.store.row("SELECT COUNT(*) AS n FROM field_packets")["n"] == 0
        assert im.store.row("SELECT COUNT(*) AS n FROM domain_events")["n"] == 0
        with im.store.transaction() as db:
            db.execute("INSERT INTO field_packets VALUES(?,?,?,?,?,?,?,?,?,?)",
                       ("packet", "req", "one", "body", "sha", "sha", "[]", "[]", "now", "organizer-agent"))
        for sql in ("DELETE FROM domain_events", "UPDATE domain_events SET object_version=2"):
            with pytest.raises(sqlite3.IntegrityError, match="append-only"):
                im.store.conn.execute(sql)
