from __future__ import annotations

import json
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from issue_manager import IssueManager, scoped_evidence_relation_api
from issue_manager.errors import ValidationError
from issue_manager.manager_api import ManagerService


class ScopedEvidenceRelationApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        ledger = Path(self.temp.name) / "ledger"
        manager = IssueManager.initialize(ledger)
        manager.create_issue("scope", "investigation", "Scope")
        self.a = manager.add_evidence(kind="external", locator="urn:api:a", issue_id="scope")["evidence_id"]
        self.b = manager.add_evidence(kind="external", locator="urn:api:b")["evidence_id"]
        self.credential = manager.credentials.path_for("organizer-agent")
        auth = manager.credentials.resolve(self.credential, "context.read")
        self.source_token = manager.scoped_evidence_relations.binding(self.a, auth=auth)["token"]
        self.target_token = manager.scoped_evidence_relations.binding(self.b, auth=auth)["token"]
        manager.close()
        self.service = ManagerService(ledger, port=0)
        self.base = f"http://{self.service.start()[0]}:{self.service.address[1]}"

    def tearDown(self) -> None:
        self.service.close()
        self.temp.cleanup()

    def request(self, method: str, path: str, body: dict | None = None, key: str | None = None) -> tuple[int, dict]:
        request = urllib.request.Request(self.base + path, method=method)
        credential = json.loads(Path(self.credential).read_text(encoding="utf-8"))["token"]
        request.add_header("Authorization", "Bearer " + credential)
        request.add_header("X-Request-ID", "req-" + (key or "read"))
        if key:
            request.add_header("Idempotency-Key", key)
        if body is not None:
            request.data = json.dumps(body).encode()
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def test_http_lifecycle_preview_and_history(self) -> None:
        status, binding = self.request("GET", f"/v1/scoped-evidence-relations/bindings/{self.a}")
        self.assertEqual(status, 200)
        self.assertEqual(binding["result"]["token"], self.source_token)
        status, created = self.request("POST", "/v1/scoped-evidence-relations", {
            "scope_issue_id": "scope", "source_evidence_id": self.a, "target_evidence_id": self.b,
            "relation_type": "refutes", "rationale": "api reason",
            "expected_source_token": self.source_token, "expected_target_token": self.target_token,
        }, "create-api")
        self.assertEqual(status, 200, created)
        relation = created["result"]
        status, preview = self.request("POST", "/v1/scoped-evidence-relations/preview-selection", {
            "scope_issue_id": "scope", "seed_evidence_ids": [self.a], "maximum_nodes": 10, "maximum_relations": 10,
        }, "preview-api")
        self.assertEqual(status, 200, preview)
        self.assertEqual(preview["result"]["selection"]["rule_id"], "context-currentness/scoped-v2")
        status, changed = self.request("POST", f"/v1/scoped-evidence-relations/{relation['relation_id']}/deactivate", {
            "expected_version_id": relation["version_id"], "reason": "api withdraw",
        }, "deactivate-api")
        self.assertEqual(status, 200, changed)
        status, revised = self.request("POST", f"/v1/scoped-evidence-relations/{relation['relation_id']}/revise", {
            "expected_version_id": changed["result"]["version_id"], "rationale": "api revise",
            "rebind": False,
        }, "revise-api")
        self.assertEqual(status, 200, revised)
        status, naked = self.request("POST", f"/v1/scoped-evidence-relations/{relation['relation_id']}", {
            "expected_version_id": revised["result"]["version_id"], "rationale": "wrong route",
        }, "naked-api")
        self.assertEqual(status, 400, naked)
        status, history = self.request("GET", f"/v1/scoped-evidence-relations/{relation['relation_id']}/history?limit=1")
        self.assertEqual(status, 200)
        self.assertEqual(len(history["result"]["items"]), 1)
        self.assertIsNotNone(history["result"]["next_cursor"])

    def test_dispatch_rejects_unknown_fields_and_api_replay_is_identity_scoped(self) -> None:
        manager = IssueManager.initialize(Path(self.temp.name) / "direct")
        try:
            auth = manager.credentials.resolve(manager.credentials.path_for("organizer-agent"), "evidence.relation.write")
            with self.assertRaises(ValidationError):
                scoped_evidence_relation_api.dispatch(manager, "POST", ["v1", "scoped-evidence-relations"], {"extra": 1}, auth, "k")
        finally:
            manager.close()

    def test_preview_over_limit_returns_no_partial_result(self) -> None:
        status, payload = self.request("POST", "/v1/scoped-evidence-relations/preview-selection", {
            "scope_issue_id": "scope", "seed_evidence_ids": [self.a], "maximum_nodes": 0, "maximum_relations": 10,
        }, "limit-api")
        self.assertEqual(status, 400)
        self.assertNotIn("result", payload)

    def test_api_rejects_coercions_and_bad_history_queries(self) -> None:
        invalid_requests = [
            ({"scope_issue_id": "scope", "seed_evidence_ids": [self.a], "maximum_nodes": True,
              "maximum_relations": 10}, "bad-bool"),
            ({"scope_issue_id": "scope", "seed_evidence_ids": [self.a], "maximum_nodes": 1001,
              "maximum_relations": 10}, "too-many"),
        ]
        for body, key in invalid_requests:
            status, payload = self.request("POST", "/v1/scoped-evidence-relations/preview-selection" if "seed_evidence_ids" in body else "/v1/scoped-evidence-relations", body, key)
            self.assertEqual(status, 400, payload)
        status, created = self.request("POST", "/v1/scoped-evidence-relations", {
            "scope_issue_id": "scope", "source_evidence_id": self.a, "target_evidence_id": self.b,
            "relation_type": "refutes", "rationale": "setup", "expected_source_token": self.source_token,
            "expected_target_token": self.target_token,
        }, "setup-invalid-rebind")
        self.assertEqual(status, 200, created)
        status, payload = self.request("POST", f"/v1/scoped-evidence-relations/{created['result']['relation_id']}/revise", {
            "expected_version_id": created["result"]["version_id"], "rebind": "false",
        }, "bad-rebind")
        self.assertEqual(status, 400, payload)
        status, payload = self.request("GET", "/v1/scoped-evidence-relations/missing/history?limit=x")
        self.assertEqual(status, 400, payload)
        status, payload = self.request("GET", "/v1/scoped-evidence-relations/missing/history?limit=1&limit=2")
        self.assertEqual(status, 400, payload)
        status, payload = self.request("GET", "/v1/scoped-evidence-relations/missing/history?unknown=1")
        self.assertEqual(status, 400, payload)

    def test_http_surface_rejects_legacy_role_fields_routes_and_arbitrary_proxies(self) -> None:
        status, payload = self.request("POST", "/v1/issues", {
            "issue_id": "role-shaped", "issue_type": "investigation", "title": "legacy",
            "reason": "test", "role": "reviewer", "work_item_id": "old-item",
        }, "legacy-issue-fields")
        self.assertEqual(status, 400, payload)
        self.assertEqual(payload["error"], "validation_error")
        status, payload = self.request("GET", "/v1/issues/role-shaped")
        self.assertEqual(status, 404, payload)

        status, payload = self.request("POST", "/v1/work-items", {"issue_id": "scope"}, "legacy-route")
        self.assertEqual(status, 404, payload)
        status, payload = self.request("POST", "/v1/http", {
            "method": "POST", "path": "/anything", "body": {},
        }, "http-proxy")
        self.assertEqual(status, 404, payload)
        status, payload = self.request("POST", "/v1/sql", {"query": "SELECT 1"}, "sql-proxy")
        self.assertEqual(status, 404, payload)
        status, payload = self.request("GET", "/v1/context?issue=scope&role=reviewer")
        self.assertEqual(status, 400, payload)

        status, payload = self.request("POST", "/v1/scoped-evidence-contributions", {
            "issue_id": "scope", "kind": "observation", "source": "urn:legacy",
            "description": "must not save", "reason": "legacy payload", "role": "reviewer",
        }, "legacy-contribution-fields")
        self.assertEqual(status, 400, payload)
        manager = IssueManager(Path(self.temp.name) / "ledger")
        try:
            self.assertEqual(manager.store.row("SELECT COUNT(*) AS n FROM evidence_refs")["n"], 2)
            self.assertEqual(manager.store.row(
                "SELECT COUNT(*) AS n FROM issues WHERE issue_id='role-shaped'"
            )["n"], 0)
        finally:
            manager.close()


if __name__ == "__main__":
    unittest.main()
