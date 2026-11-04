import json
import tempfile
import urllib.parse
import urllib.request

from issue_manager import IssueManager
from issue_manager.manager_api import ManagerService


def test_fresh_scoped_v2_http_catalog_1000_candidates():
    budget = 4096
    with tempfile.TemporaryDirectory(prefix="issue-manager-s3-http-1000-") as temporary:
        manager = IssueManager.initialize(temporary + "/ledger", context_rule="scoped-v2")
        try:
            manager.create_issue("scope", "investigation", "1000-candidate HTTP check")
            expected = {
                manager.add_evidence(
                    kind="external", locator=f"urn:s3-http-1000:{index}", issue_id="scope"
                )["evidence_id"]
                for index in range(1000)
            }
            token = json.loads(
                manager.credentials.path_for("organizer-agent").read_text(encoding="utf-8")
            )["token"]

            def request(base, method, path, body=None, key=None):
                encoded = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
                headers = {
                    "Authorization": f"Bearer {token}",
                    "X-Request-ID": key or "s3-http-1000-read",
                }
                if encoded is not None:
                    headers["Content-Type"] = "application/json"
                if key:
                    headers["Idempotency-Key"] = key
                request_obj = urllib.request.Request(base + path, data=encoded, headers=headers, method=method)
                with urllib.request.urlopen(request_obj) as response:
                    raw = response.read()
                    return json.loads(raw)["result"], len(raw)

            with ManagerService(manager.store.ledger_dir, port=0) as server:
                base = f"http://{server.address[0]}:{server.address[1]}"
                package, prepare_bytes = request(
                    base, "POST", "/v1/currentness/prepare",
                    {"issue_id": "scope", "evidence_ids": sorted(expected)}, "s3-http-1000-prepare",
                )
                assert prepare_bytes > 0
                view, create_view_bytes = request(
                    base, "POST", f"/v1/currentness/packages/{package['package_id']}/views",
                    {"budget_bytes": budget}, "s3-http-1000-view",
                )
                assert create_view_bytes <= budget
                cursor = None
                seen = []
                pages = 0
                max_response_bytes = 0
                while True:
                    path = f"/v1/currentness/views/{view['view_id']}"
                    if cursor is not None:
                        path += "?cursor=" + urllib.parse.quote(str(cursor), safe="")
                    page, response_bytes = request(base, "GET", path)
                    pages += 1
                    max_response_bytes = max(max_response_bytes, response_bytes)
                    assert response_bytes <= budget
                    summary = page["summary"]
                    seen.extend(
                        entry["id"]
                        for entry in summary["catalog"]
                        if entry["kind"] == "evidence"
                    )
                    next_cursor = summary["next_cursor"]
                    if next_cursor is None:
                        break
                    assert next_cursor != cursor
                    cursor = next_cursor

            assert pages > 1
            assert len(seen) == 1000
            assert set(seen) == expected
            assert len(seen) == len(set(seen))
            result = {
                "candidates": len(expected),
                "pages": pages,
                "max_http_response_bytes": max_response_bytes,
                "budget_bytes": budget,
                "cursor_terminated": True,
                "exact_once": True,
                "no_omissions": True,
            }
            print("S3_HTTP_1000_RESULT=" + json.dumps(result, sort_keys=True))
        finally:
            manager.close()
