from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from issue_manager import IssueManager
from issue_manager.manager_api import ManagerService
from issue_manager.store import Store
from tests.scoped_test_support import prepare_explicit


class TestFieldInboxHttp:
    def setup_method(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = Path(self.temp.name) / "ledger"
        manager = IssueManager.initialize(self.ledger)
        manager.create_issue("scope", "investigation", "Scope")
        prepare_explicit(manager, "scope")
        manager.credentials.issue_actor(actor_id="field-only-test", actor_kind="experiment_agent",
            capabilities={"intake.submit"}, maintenance_credential=manager.credentials.path_for("maintenance-agent"))
        manager.credentials.issue_actor(actor_id="reader-only-test", actor_kind="experiment_agent",
            capabilities={"context.read"}, maintenance_credential=manager.credentials.path_for("maintenance-agent"))
        manager.credentials.issue_actor(actor_id="curator-only-test", actor_kind="organizer_agent",
            capabilities={"context.read", "evidence.write", "evidence.relation.write"},
            maintenance_credential=manager.credentials.path_for("maintenance-agent"))
        manager.credentials.issue_actor(actor_id="curator-no-relation-test", actor_kind="organizer_agent",
            capabilities={"context.read", "evidence.write"},
            maintenance_credential=manager.credentials.path_for("maintenance-agent"))
        self.field_credential = self.ledger / "credentials" / "field-only-test.token"
        self.read_credential = self.ledger / "credentials" / "reader-only-test.token"
        self.curator_credential = self.ledger / "credentials" / "curator-only-test.token"
        self.curator_no_relation_credential = self.ledger / "credentials" / "curator-no-relation-test.token"
        manager.close()
        self.service = ManagerService(self.ledger, port=0)
        host, port = self.service.start()
        self.base = f"http://{host}:{port}"

    def teardown_method(self):
        self.service.close()
        self.temp.cleanup()

    def request(self, method, path, body=None, key=None, request_id=None, credential=None):
        req = urllib.request.Request(self.base + path, method=method)
        token = json.loads(Path(credential or self.field_credential).read_text(encoding="utf-8"))["token"]
        req.add_header("Authorization", "Bearer " + token)
        req.add_header("X-Request-ID", request_id or ("request-" + (key or "read")))
        if key:
            req.add_header("Idempotency-Key", key)
        if body is not None:
            req.data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def packet(self, **overrides):
        value = {"issue_id": "scope",
            "content": "曲线 A 出现平台。按本次参数得到加载计算 B=2.50 s。我怀疑输入负载影响了判断 H，但目前只能提出疑问。",
            "sources": [{"locator": "run://P1/curve-A", "provided_text": "曲线 A 出现平台。"}],
            "attachment_refs": ["sha256:abc"]}
        value.update(overrides)
        return value

    def submit(self, body=None, request_id="receive-1", key="receive-1", credential=None):
        return self.request("POST", "/v1/field-packets", body or self.packet(), key, request_id, credential)

    def domain_snapshot(self):
        connection = sqlite3.connect(self.ledger / "issue_ledger.sqlite")
        try:
            counts = tuple(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in (
                "issue_evidence", "scoped_evidence_relation_versions", "field_facts",
                "field_fact_mapping_versions", "field_packet_reviews", "conclusion_currentness"))
            issue = connection.execute("SELECT freshness,current_conclusion_id,conclusion_revision FROM issues WHERE issue_id='scope'").fetchone()
            return counts + (issue,)
        finally:
            connection.close()

    def curate(self, packet_id, **overrides):
        request_id = overrides.pop("request_id", "curate-1")
        credential = overrides.pop("credential", self.curator_credential)
        body = {"issue_id": "scope", "expected_curation_version": 0,
                "description": "曲线 A 在本次测量中出现平台", "kind": "observation",
                "origin": {"type": "packet_text", "quoted_text": "曲线 A 出现平台。"},
                "reason": "按现场原文拆出可独立核查的观察", "related_evidence": []}
        body.update(overrides)
        return self.request("POST", f"/v1/field-packets/{packet_id}/curated-items", body,
                            request_id, request_id, credential)

    def test_raw_receipt_is_minimal_immutable_and_replayable(self):
        before = self.request("GET", "/v1/health", credential=self.read_credential)[1]["result"]
        domain_before = self.domain_snapshot()
        raw_body = {"issue_id": "scope", "content": "现场原文，不附来源或拆分字段。"}
        status, response = self.submit(raw_body)
        receipt = response["result"]
        assert status == 200
        assert set(receipt) == {"status", "packet_id", "content_sha256", "idempotent_replay"}
        assert receipt["status"] == "received" and receipt["idempotent_replay"] is False
        status, replay = self.submit(raw_body, request_id="receive-1", key="receive-1")
        assert status == 200 and replay["result"] == {**receipt, "idempotent_replay": True}
        status, conflict = self.submit({**raw_body, "content": "changed"}, request_id="receive-1", key="receive-1")
        assert status == 409 and conflict["error"] == "idempotency_conflict"
        status, invalid = self.submit(self.packet(facts=[]), "v3-request", "v3-key")
        assert status == 400 and invalid["error"] == "validation_error"
        status, detail = self.request("GET", f"/v1/field-packets/{receipt['packet_id']}",
                                      credential=self.read_credential)
        assert status == 200
        assert detail["result"]["created_by"] == "field-only-test"
        assert detail["result"]["curation_version"] == 0
        assert detail["result"]["curated_item_count"] == 0
        assert detail["result"]["sources"] == [] and detail["result"]["attachment_refs"] == []
        assert before["schema_version"] == 10
        assert self.domain_snapshot() == domain_before

    def test_curated_item_creates_fact_evidence_mapping_atomically_and_cas(self):
        _, received = self.submit()
        packet_id = received["result"]["packet_id"]
        status, curated = self.curate(packet_id)
        result = curated["result"]
        assert status == 200 and result["atomic"] is True
        assert result["source_locator"] == f"im-field-packet:{packet_id}#content"
        assert result["curation_version"] == 1 and result["relation_ids"] == []
        status, items = self.request("GET", f"/v1/field-packets/{packet_id}/curated-items?limit=10",
                                     credential=self.read_credential)
        assert status == 200 and items["result"]["items"][0]["origin"]["quoted_text"] == "曲线 A 出现平台。"
        status, fact = self.request("GET", f"/v1/field-facts/{result['fact_ref']}", credential=self.read_credential)
        assert status == 200 and fact["result"]["mapping"]["evidence_id"] == result["evidence_id"]
        second_body = {"issue_id": "scope", "expected_curation_version": 1,
            "description": "现场对 H 只能提出疑问，不能确定影响方向。", "kind": "interpretation",
            "origin": {"type": "packet_text", "quoted_text": "我怀疑输入负载影响了判断 H，但目前只能提出疑问。"},
            "reason": "保留现场不确定措辞", "related_evidence": [{"target_kind": "fact_ref",
                "target_ref": result["fact_ref"], "relation_type": "challenges", "rationale": "现场只提出疑问"}]}
        status, second = self.request("POST", f"/v1/field-packets/{packet_id}/curated-items", second_body,
                                      "curate-2", "curate-2", self.curator_credential)
        assert status == 200 and second["result"]["curation_version"] == 2
        connection = sqlite3.connect(self.ledger / "issue_ledger.sqlite")
        try:
            relation = connection.execute(
                "SELECT source_evidence_id,target_evidence_id,relation_type FROM scoped_evidence_relation_versions WHERE relation_id=?",
                (second["result"]["relation_ids"][0],)).fetchone()
        finally:
            connection.close()
        assert relation == (second["result"]["evidence_id"], result["evidence_id"], "challenges")
        source_body = {"issue_id": "scope", "expected_curation_version": 2,
            "description": "可定位的来源摘录", "kind": "observation",
            "origin": {"type": "source_text", "source_index": 0, "quoted_text": "曲线 A"},
            "reason": "复核来源 locator", "related_evidence": []}
        status, source_item = self.request("POST", f"/v1/field-packets/{packet_id}/curated-items", source_body,
            "curate-source", "curate-source", self.curator_credential)
        assert status == 200 and source_item["result"]["source_locator"] == "run://P1/curve-A"
        status, stale = self.curate(packet_id, description="陈旧版本写入", request_id="curate-stale")
        assert status == 409 and stale["error"] == "conflict"
        assert "curation version" in stale["message"]

    def test_single_source_relation_pages_are_authorized_and_snapshot_bound(self):
        raw = "First excerpt. Second excerpt. Third excerpt."
        _, received = self.submit(self.packet(content=raw, sources=[], attachment_refs=[]),
                                  request_id="relations-receive", key="relations-receive")
        packet_id = received["result"]["packet_id"]
        first = {"issue_id": "scope", "expected_curation_version": 0,
            "description": "First", "kind": "observation",
            "origin": {"type": "packet_text", "quoted_text": "First excerpt."},
            "reason": "first origin", "related_evidence": []}
        status, first_result = self.request("POST", f"/v1/field-packets/{packet_id}/curated-items",
            first, "relations-first", "relations-first", self.curator_credential)
        assert status == 200
        second = {**first, "expected_curation_version": 1, "description": "Second",
            "origin": {"type": "packet_text", "quoted_text": "Second excerpt."}}
        status, second_result = self.request("POST", f"/v1/field-packets/{packet_id}/curated-items",
            second, "relations-second", "relations-second", self.curator_credential)
        assert status == 200
        third = {**first, "expected_curation_version": 2, "description": "Third",
            "origin": {"type": "packet_text", "quoted_text": "Third excerpt."},
            "related_evidence": [
                {"target_kind": "fact_ref", "target_ref": first_result["result"]["fact_ref"],
                 "relation_type": "depends_on", "rationale": "first is required"},
                {"target_kind": "fact_ref", "target_ref": second_result["result"]["fact_ref"],
                 "relation_type": "derived_from", "rationale": "second is an input source"},
            ]}
        status, third_result = self.request("POST", f"/v1/field-packets/{packet_id}/curated-items",
            third, "relations-third", "relations-third", self.curator_credential)
        assert status == 200 and third_result["result"]["atomic"] is True
        source_evidence_id = third_result["result"]["evidence_id"]
        query = urllib.parse.urlencode({"scope_issue_id": "scope", "source_evidence_id": source_evidence_id,
                                        "limit": 1, "max_bytes": 16384})
        status, first_page = self.request("GET", "/v1/scoped-evidence-relations?" + query,
                                          credential=self.read_credential)
        result = first_page["result"]
        assert status == 200 and len(result["items"]) == 1
        assert result["items"][0]["active"] is True
        assert result["items"][0]["revision"] == 1
        assert result["items"][0]["binding_current"] is True
        assert result["items"][0]["rationale"] in {"first is required", "second is an input source"}
        assert result["complete"] is False and result["next_cursor"]
        snapshot = result["snapshot"]["token"]
        query = urllib.parse.urlencode({"scope_issue_id": "scope", "source_evidence_id": source_evidence_id,
            "limit": 1, "max_bytes": 16384, "cursor": result["next_cursor"],
            "expected_snapshot": snapshot})
        status, second_page = self.request("GET", "/v1/scoped-evidence-relations?" + query,
                                           credential=self.read_credential)
        assert status == 200 and len(second_page["result"]["items"]) == 1
        assert second_page["result"]["items"][0]["relation_id"] != result["items"][0]["relation_id"]
        assert second_page["result"]["complete"] is True

        relation = result["items"][0]
        status, deactivated = self.request("POST",
            f"/v1/scoped-evidence-relations/{relation['relation_id']}/deactivate",
            {"expected_version_id": relation["current_version_id"], "reason": "snapshot mutation"},
            "relation-deactivate", "relation-deactivate", self.curator_credential)
        assert status == 200 and deactivated["result"]["active"] is False
        one_relation = urllib.parse.urlencode({"scope_issue_id": "scope",
            "source_evidence_id": source_evidence_id, "relation_id": relation["relation_id"],
            "max_bytes": 16384})
        status, inactive = self.request("GET", "/v1/scoped-evidence-relations?" + one_relation,
                                        credential=self.read_credential)
        assert status == 200 and len(inactive["result"]["items"]) == 1
        inactive_head = inactive["result"]["items"][0]
        assert inactive_head["active"] is False and inactive_head["revision"] == 2
        assert inactive_head["binding_current"] is True
        stale_query = urllib.parse.urlencode({"scope_issue_id": "scope", "source_evidence_id": source_evidence_id,
            "limit": 1, "max_bytes": 16384, "cursor": result["next_cursor"],
            "expected_snapshot": snapshot})
        status, stale = self.request("GET", "/v1/scoped-evidence-relations?" + stale_query,
                                     credential=self.read_credential)
        assert status == 409 and stale["error"] == "conflict"

        status, denied = self.request("GET", "/v1/scoped-evidence-relations?" + stale_query,
                                      credential=self.field_credential)
        assert status == 403 and denied["error"] == "permission_denied"
        oversized = urllib.parse.urlencode({"scope_issue_id": "scope", "source_evidence_id": source_evidence_id,
                                            "max_bytes": 20000})
        status, invalid = self.request("GET", "/v1/scoped-evidence-relations?" + oversized,
                                       credential=self.read_credential)
        assert status == 400 and invalid["error"] == "validation_error"

    def test_two_curators_racing_same_curation_version_have_one_winner(self):
        _, received = self.submit()
        packet_id = received["result"]["packet_id"]
        barrier = threading.Barrier(2)
        def submit_race(index):
            body = {"issue_id": "scope", "expected_curation_version": 0,
                "description": f"独立条目 {index}", "kind": "observation",
                "origin": {"type": "packet_text", "quoted_text": "曲线 A 出现平台。"},
                "reason": f"curator {index}", "related_evidence": []}
            barrier.wait()
            request_id = f"race-{index}"
            return self.request("POST", f"/v1/field-packets/{packet_id}/curated-items", body,
                                request_id, request_id, self.curator_credential)
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(submit_race, (1, 2)))
        assert sorted(status for status, _ in responses) == [200, 409]
        detail = self.request("GET", f"/v1/field-packets/{packet_id}", credential=self.read_credential)[1]["result"]
        assert detail["curation_version"] == 1 and detail["curated_item_count"] == 1

    def test_origin_validation_relation_permissions_and_cross_issue_rejection(self):
        _, received = self.submit()
        packet_id = received["result"]["packet_id"]
        ambiguous_packet = self.packet(content="重复摘录。重复摘录。")
        _, second = self.submit(ambiguous_packet, "receive-2", "receive-2")
        invalid = {"type": "packet_text", "quoted_text": "重复摘录。"}
        status, response = self.curate(second["result"]["packet_id"], origin=invalid, request_id="ambiguous-origin")
        assert status == 400 and response["error"] == "validation_error"
        bad_origins = [
            {"type": "packet_text", "quoted_text": "not in packet"},
            {"type": "source_text", "source_index": 4, "quoted_text": "quote"},
            {"type": "source_text", "source_index": 0, "quoted_text": "not in source"},
            {"type": "attachment", "attachment_ref": "sha256:not-registered", "part_locator": "sheet-1"},
        ]
        counts_before = self.domain_snapshot()
        for index, origin in enumerate(bad_origins):
            status, error = self.curate(packet_id, origin=origin, request_id=f"bad-origin-{index}")
            assert status == 400 and error["error"] == "validation_error"
        assert self.domain_snapshot() == counts_before
        status, denied = self.curate(packet_id, related_evidence=[{"target_kind": "evidence_id",
            "target_ref": "missing", "relation_type": "depends_on", "rationale": "explicit"}], request_id="missing-target")
        assert status == 404
        body = {"issue_id": "scope", "expected_curation_version": 0, "description": "Q", "kind": "interpretation",
                "origin": {"type": "packet_text", "quoted_text": "曲线 A 出现平台。"}, "reason": "R",
                "related_evidence": [{"target_kind": "evidence_id", "target_ref": "not-found",
                                      "relation_type": "depends_on", "rationale": "needed"}]}
        status, denied = self.request("POST", f"/v1/field-packets/{packet_id}/curated-items", body,
            "relation-deny", "relation-deny", self.curator_no_relation_credential)
        assert status == 403
        assert denied["error"] == "permission_denied"
        status, denied = self.request("POST", f"/v1/field-packets/{packet_id}/curated-items", body,
            "field-deny", "field-deny", self.field_credential)
        assert status == 403

    def test_repeated_source_quote_requires_exact_position_and_bad_pages_are_400(self):
        body = self.packet(sources=[{"locator": "run://repeat", "provided_text": "重复。重复。"}])
        _, received = self.submit(body)
        packet_id = received["result"]["packet_id"]
        repeated = {"type": "source_text", "source_index": 0, "quoted_text": "重复。"}
        status, error = self.curate(packet_id, origin=repeated, request_id="repeat-ambiguous")
        assert status == 400 and error["error"] == "validation_error"
        status, result = self.curate(packet_id, origin={**repeated, "start": 3}, request_id="repeat-position")
        assert status == 200 and result["result"]["origin"]["start"] == 3
        status, error = self.request("GET", f"/v1/field-packets/{packet_id}/curated-items?limit=bad",
                                     credential=self.read_credential)
        assert status == 400 and error["error"] == "validation_error"
        status, error = self.request("GET", f"/v1/field-packets/{packet_id}/curated-items?after_fact_ref=missing",
                                     credential=self.read_credential)
        assert status == 404 and error["error"] == "not_found"
        status, error = self.request("GET", f"/v1/field-facts/{result['result']['fact_ref']}/mappings?limit=bad",
                                     credential=self.read_credential)
        assert status == 400 and error["error"] == "validation_error"

    def test_review_appends_handoff_and_does_not_require_all_text_resolved(self):
        _, received = self.submit()
        packet_id = received["result"]["packet_id"]
        _, curated = self.curate(packet_id)
        fact_ref = curated["result"]["fact_ref"]
        body = {"issue_id": "scope", "expected_curation_version": 1, "handled_fact_refs": [fact_ref],
            "unresolved": [{"origin": {"type": "packet_text", "quoted_text": "我怀疑输入负载影响了判断 H"},
                            "reason": "现场未给出可唯一定位的 H 身份"}], "reason": "交接整理缺口"}
        status, review = self.request("POST", f"/v1/field-packets/{packet_id}/reviews", body,
            "review-1", "review-1", self.curator_credential)
        assert status == 200 and review["result"]["curation_version"] == 2
        status, detail = self.request("GET", f"/v1/field-packets/{packet_id}", credential=self.read_credential)
        assert status == 200 and detail["result"]["latest_review"]["unresolved"][0]["reason"].startswith("现场未")
        status, history = self.request("GET", f"/v1/field-packets/{packet_id}/reviews?limit=10",
                                       credential=self.read_credential)
        assert status == 200 and history["result"]["items"][0]["review_id"] == review["result"]["review_id"]

    def test_source_pages_preserve_unicode_crlf_and_find_overlapping_full_source_matches(self):
        source_text = "x" * 254 + "😀needle\r\nababa"
        _, received = self.submit(self.packet(content="packet\r\ntext", sources=[
            {"locator": "run://unicode", "provided_text": source_text}]))
        packet_id = received["result"]["packet_id"]
        status, first = self.request("GET", f"/v1/field-packets/{packet_id}/text?source_index=0&start=0&max_bytes=256",
                                     credential=self.read_credential)
        assert status == 200 and first["result"]["content_utf8"].endswith("x")
        assert first["result"]["next_cursor"] == 254
        status, second = self.request("GET", f"/v1/field-packets/{packet_id}/text?source_index=0&start=254&max_bytes=256&content_sha256={first['result']['content_sha256']}",
                                      credential=self.read_credential)
        assert status == 200 and second["result"]["content_utf8"] == "😀needle\r\nababa"
        assert second["result"]["complete"] is True
        status, first_match = self.request("GET", f"/v1/field-packets/{packet_id}/locate?source_index=0&quoted_text=aba&limit=1",
                                           credential=self.read_credential)
        assert status == 200 and first_match["result"]["matches"][0]["origin"]["start"] == source_text.index("aba")
        assert first_match["result"]["unique"] is False and first_match["result"]["complete"] is False
        cursor = first_match["result"]["next_cursor"]
        status, second_match = self.request("GET", f"/v1/field-packets/{packet_id}/locate?source_index=0&quoted_text=aba&limit=1&after_start={cursor}",
                                            credential=self.read_credential)
        assert status == 200 and second_match["result"]["matches"][0]["origin"]["start"] == source_text.index("aba") + 2
        assert second_match["result"]["complete"] is True and second_match["result"]["unique"] is False
        status, conflict = self.request("GET", f"/v1/field-packets/{packet_id}/text?source_index=0&content_sha256={'0' * 64}",
                                        credential=self.read_credential)
        assert status == 409 and conflict["error"] == "conflict"

    def test_authoritative_review_statistics_are_versioned_and_review_detail_is_paged(self):
        body = self.packet(content=" ".join(f"fact-{index}" for index in range(19)), sources=[])
        _, received = self.submit(body)
        packet_id = received["result"]["packet_id"]
        refs = []
        for index in range(19):
            kind = "observation" if index < 12 else "interpretation"
            status, result = self.curate(packet_id, request_id=f"fact-{index}",
                expected_curation_version=index,
                description=f"Fact {index}", kind=kind,
                origin={"type": "packet_text", "quoted_text": f"fact-{index}",
                        "start": body["content"].index(f"fact-{index}")})
            assert status == 200, result
            refs.append(result["result"]["fact_ref"])
        review_body = {"issue_id": "scope", "expected_curation_version": 19,
            "handled_fact_refs": refs, "unresolved": [], "reason": "19 selected items counted from the returned receipts."}
        status, review = self.request("POST", f"/v1/field-packets/{packet_id}/reviews", review_body,
            "review-19", "review-19", self.curator_credential)
        assert status == 200
        review_id = review["result"]["review_id"]
        status, summary = self.request("GET", f"/v1/field-packets/{packet_id}/summary?review_id={review_id}",
                                       credential=self.read_credential)
        stats = summary["result"]
        assert status == 200 and stats["fact_count"] == 19
        assert stats["kind_counts"] == {"interpretation": 7, "observation": 12}
        assert stats["mapped_item_count"] == 19 and stats["statistics_complete"] is True
        assert stats["review"]["handled_count"] == stats["review"]["handled_unique_count"] == 19
        assert stats["review"]["handled_kind_counts"] == {"interpretation": 7, "observation": 12}
        assert stats["review"]["unresolved_count"] == 0
        status, page = self.request("GET", f"/v1/field-packets/{packet_id}/review?review_id={review_id}&max_bytes=512&expected_curation_version=20",
                                   credential=self.read_credential)
        assert status == 200 and len(page["result"]["handled_fact_refs"]) < 19
        assert page["result"]["handled_next_cursor"] is not None
        status, new_fact = self.curate(packet_id, request_id="fact-after-review",
            expected_curation_version=20, description="Additional fact after review",
            kind="observation", origin={"type": "packet_text", "quoted_text": "fact-18",
                                        "start": body["content"].index("fact-18")})
        assert status == 200
        status, stale_page = self.request("GET", f"/v1/field-packets/{packet_id}/review?review_id={review_id}&after_handled={page['result']['handled_next_cursor']}&expected_curation_version=20",
                                          credential=self.read_credential)
        assert status == 409 and stale_page["error"] == "conflict"
        status, fact = self.request("GET", f"/v1/field-packets/{packet_id}/facts/{refs[0]}",
                                    credential=self.read_credential)
        assert status == 200 and fact["result"]["packet_id"] == packet_id
        status, global_fact = self.request("GET", f"/v1/field-packets/{packet_id}/facts/not-in-this-packet",
                                           credential=self.read_credential)
        assert status == 404 and global_fact["error"] == "not_found"

    def test_internal_write_failure_rolls_back_then_same_identity_can_recover(self, monkeypatch):
        _, received = self.submit()
        packet_id = received["result"]["packet_id"]
        body = {"issue_id": "scope", "expected_curation_version": 0,
            "description": "曲线 A 出现平台", "kind": "observation",
            "origin": {"type": "packet_text", "quoted_text": "曲线 A 出现平台。"},
            "reason": "recovery", "related_evidence": []}
        original = Store.fault
        failed = False
        def fail_once(store, point):
            nonlocal failed
            if point == "field_curate.after_mapping" and not failed:
                failed = True
                raise RuntimeError("injected temporary failure")
            original(store, point)
        monkeypatch.setattr(Store, "fault", fail_once)
        request_id = "recover-same-identity"
        status, first = self.request("POST", f"/v1/field-packets/{packet_id}/curated-items", body,
                                     request_id, request_id, self.curator_credential)
        assert status == 500 and first["error"] == "internal_error"
        assert self.domain_snapshot()[2:4] == (0, 0)
        status, wrong_identity = self.request("POST", f"/v1/field-packets/{packet_id}/curated-items", body,
                                              request_id, "different-request-id", self.curator_credential)
        assert status == 409 and wrong_identity["error"] == "idempotency_conflict"
        status, recovered = self.request("POST", f"/v1/field-packets/{packet_id}/curated-items", body,
                                         request_id, request_id, self.curator_credential)
        assert status == 200 and recovered["result"]["atomic"] is True
        assert self.domain_snapshot()[2:4] == (1, 1)

    def test_intake_and_read_capabilities_are_separate(self):
        status, denied = self.request("GET", "/v1/field-packets?issue_id=scope", credential=self.field_credential)
        assert status == 403 and denied["error"] == "permission_denied"
        status, denied = self.request("POST", "/v1/field-packets", self.packet(), "reader-write", "reader-write",
                                      self.read_credential)
        assert status == 403
        status, denied = self.request("POST", "/v1/field-packets", self.packet(), "curator-intake-deny",
                                      "curator-intake-deny", self.curator_credential)
        assert status == 403
        status, received = self.submit()
        assert status == 200
        packet_id = received["result"]["packet_id"]
        status, denied = self.curate(packet_id, credential=self.field_credential, request_id="field-curate-deny")
        assert status == 403

    @pytest.mark.parametrize("state", [False, True, 0, None])
    def test_attachment_public_state_is_rejected_for_contribution_and_review(self, state):
        _, packet = self.submit()
        packet_id = packet["result"]["packet_id"]
        before = self.domain_snapshot()
        origin = {"type": "attachment", "attachment_ref": "sha256:abc", "part_locator": "row 2",
                  "local_position_verified": state}
        status, error = self.curate(packet_id, origin=origin, request_id="forged-contribution")
        assert status == 400 and error["details"]["fields"] == [{"path": "/origin", "rule": "additionalProperties"}]
        status, error = self.request("POST", f"/v1/field-packets/{packet_id}/reviews", {
            "issue_id": "scope", "expected_curation_version": 0, "handled_fact_refs": [],
            "unresolved": [{"origin": origin, "reason": "gap"}], "reason": "handoff"},
            "forged-review", "forged-review", self.curator_credential)
        assert status == 400 and error["details"]["fields"][0]["path"] == "/unresolved/0/origin"
        assert self.domain_snapshot() == before

    def test_attachment_same_version_concurrency_and_authoritative_denials(self):
        _, received = self.submit()
        packet_id = received["result"]["packet_id"]
        origin = {"type": "attachment", "attachment_ref": "sha256:abc", "part_locator": "row 2"}
        before = self.domain_snapshot()
        for index, credential in enumerate((self.field_credential, self.read_credential)):
            status, _ = self.curate(packet_id, origin=origin, credential=credential, request_id=f"deny-item-{index}")
            assert status == 403
            status, _ = self.request("POST", f"/v1/field-packets/{packet_id}/reviews", {
                "issue_id": "scope", "expected_curation_version": 0, "handled_fact_refs": [],
                "unresolved": [{"origin": origin, "reason": "gap"}], "reason": "handoff"},
                f"deny-review-{index}", f"deny-review-{index}", credential)
            assert status == 403
        status, _ = self.curate(packet_id, origin=origin, credential=self.curator_no_relation_credential,
            related_evidence=[{"target_kind": "evidence_id", "target_ref": "missing", "relation_type": "depends_on",
                               "rationale": "required"}], request_id="deny-attachment-relation")
        assert status == 403 and self.domain_snapshot() == before
        barrier = threading.Barrier(2)
        def race(index):
            barrier.wait()
            return self.curate(packet_id, origin={**origin, "part_locator": f"row {index}"},
                               description=f"fragment {index}", request_id=f"attachment-race-{index}")
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(race, (1, 2)))
        assert sorted(status for status, _ in responses) == [200, 409]
        detail = self.request("GET", f"/v1/field-packets/{packet_id}", credential=self.read_credential)[1]["result"]
        assert detail["curated_item_count"] == detail["curation_version"] == 1

    def test_attachment_cross_packet_issue_exact_matching_and_unsafe_input(self):
        _, received = self.submit()
        packet_id = received["result"]["packet_id"]
        _, other = self.submit(self.packet(attachment_refs=["project:other"]), "other-packet", "other-packet")
        assert other["result"]["packet_id"] != packet_id
        origin = {"type": "attachment", "attachment_ref": "sha256:abc", "part_locator": "row 2"}
        before = self.domain_snapshot()
        invalid = [
            {**origin, "attachment_ref": "project:other"}, {**origin, "attachment_ref": "SHA256:abc"},
            {**origin, "attachment_ref": " sha256:abc"}, {**origin, "attachment_ref": "sha256:abc/"},
            {**origin, "attachment_ref": "https://example.invalid/a?secret=do-not-echo"},
            {**origin, "attachment_ref": 1}, {**origin, "attachment_ref": " "},
            {**origin, "part_locator": ""}, {**origin, "part_locator": " "},
            {**origin, "part_locator": "x" * 2049}, {**origin, "part_locator": "a\nrow"},
            {**origin, "part_locator": "a\x00row"}, {**origin, "part_locator": 2},
            {**origin, "quoted_text": ""}, {**origin, "quoted_text": " "},
            {**origin, "quoted_text": "x" * 4001}, {**origin, "quoted_text": False},
            {**origin, "unexpected": "secret"}, {"type": "attachment", "attachment_ref": "sha256:abc"},
        ]
        for index, anchor in enumerate(invalid):
            status, error = self.curate(packet_id, origin=anchor, request_id=f"attachment-bad-{index}")
            assert status == 400, error
            assert error["details"]["origin_contract"] == "field-origin/v1"
            assert "do-not-echo" not in json.dumps(error)
            status, error = self.request("POST", f"/v1/field-packets/{packet_id}/reviews", {
                "issue_id": "scope", "expected_curation_version": 0, "handled_fact_refs": [],
                "unresolved": [{"origin": anchor, "reason": "gap"}], "reason": "handoff"},
                f"bad-review-{index}", f"bad-review-{index}", self.curator_credential)
            assert status == 400
        status, _ = self.curate(packet_id, origin=origin, issue_id="other", request_id="attachment-wrong-issue")
        assert status == 400 and self.domain_snapshot() == before

    def test_attachment_intake_lossless_limits_and_control_character_consistency(self):
        for index, ref in enumerate(("x" * 2049, " ", "a\x00b", "a\nb", "a\rb", "a\x7fb", 3)):
            status, _ = self.submit(self.packet(attachment_refs=[ref]), f"invalid-ref-{index}", f"invalid-ref-{index}")
            assert status == 400
        for index, ref in enumerate(("x" * 2048, "project:tab\there", " /a//中文😀  e\u0301/ ")):
            status, result = self.submit(self.packet(attachment_refs=[ref]), f"valid-ref-{index}", f"valid-ref-{index}")
            assert status == 200
            packet_id = result["result"]["packet_id"]
            origin = {"type": "attachment", "attachment_ref": ref, "part_locator": "x" * 2048,
                      "quoted_text": "x" * 3997 + "😀\r\n"}
            status, result = self.curate(packet_id, origin=origin, request_id=f"valid-item-{index}")
            assert status == 200 and result["result"]["source_locator"] == ref
            assert result["result"]["origin"] == {**origin, "local_position_verified": False}
        status, _ = self.submit(self.packet(attachment_refs=[f"p:{i}" for i in range(17)]), "refs17", "refs17")
        assert status == 200
        status, _ = self.submit(self.packet(attachment_refs=[f"p:{i}" for i in range(128)]), "refs128", "refs128")
        assert status == 200
        status, _ = self.submit(self.packet(attachment_refs=[f"p:{i}" for i in range(129)]), "refs129", "refs129")
        assert status == 400

    def test_attachment_http_invalid_unicode_and_structure_leave_no_business_writes(self):
        before = self.domain_snapshot()
        # ASCII JSON escapes can carry an unpaired surrogate to the actual HTTP
        # parser; Python's UTF-8 serializer must not reject it before the request.
        token = json.loads(self.field_credential.read_text(encoding="utf-8"))["token"]
        request = urllib.request.Request(self.base + "/v1/field-packets", method="POST",
            data=json.dumps(self.packet(attachment_refs=["project:\ud800"]), ensure_ascii=True).encode("ascii"),
            headers={"Authorization": "Bearer " + token, "X-Request-ID": "invalid-unicode",
                     "Idempotency-Key": "invalid-unicode", "Content-Type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request)
        assert caught.value.code == 400
        for index, raw in enumerate((b'{"issue_id":"scope","content":"x","attachment_refs":["\xff"]}',
                                     json.dumps(self.packet()).encode("utf-16"))):
            request = urllib.request.Request(self.base + "/v1/field-packets", method="POST", data=raw,
                headers={"Authorization": "Bearer " + token, "X-Request-ID": f"invalid-byte-encoding-{index}",
                         "Idempotency-Key": f"invalid-byte-encoding-{index}", "Content-Type": "application/json"})
            with pytest.raises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(request)
            assert caught.value.code == 400
        _, received = self.submit()
        packet_id = received["result"]["packet_id"]
        for index, origin in enumerate((None, [], 0, "attachment", {}, {"type": []})):
            status, _ = self.curate(packet_id, origin=origin, request_id=f"invalid-structure-{index}")
            assert status == 400
        assert self.domain_snapshot() == before
