"""Small public-HTTP client; no kernel imports, credential files or database access."""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any
from urllib.parse import urlencode
from uuid import uuid4


class WorkflowAPIError(RuntimeError):
    def __init__(self, status, code, message, details=None):
        super().__init__(f"Workflow API ({status}): {code}: {message}")
        self.status = status
        self.code = code
        self.details = details if isinstance(details, dict) else {}
        self.retryable = status >= 500 or status in {408, 425, 429}


class WorkflowClient:
    """Only operations needed by the execution adapter, not a public HTTP proxy tool."""

    def __init__(self, base_url: str, token: str, *, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, method, route, body=None, *, idempotency_key=None, request_id=None):
        headers = {"Accept": "application/json", "Authorization": f"Bearer {self.token}",
                   "X-Request-ID": request_id or str(uuid4())}
        data = None
        if method != "GET":
            if not idempotency_key:
                raise ValueError("A durable idempotency key is required")
            headers["Idempotency-Key"] = idempotency_key
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        request = urllib.request.Request(self.base_url + route, data=data,
                                         headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                envelope = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                error = json.loads(exc.read().decode("utf-8"))
            except (ValueError, UnicodeError):
                error = {}
            raise WorkflowAPIError(exc.code, error.get("error", "http_error"),
                                   error.get("message", str(exc)), error.get("details")) from exc
        return envelope["result"]

    def submit_field_packet(self, request: dict, *, request_id: str, idempotency_key: str):
        return self._request("POST", "/v1/field-packets", request,
                             request_id=request_id, idempotency_key=idempotency_key)

    def domain_events(self, issue_id: str, *, after: int = 0, limit: int = 50,
                      stream_id: str | None = None, start_now: bool = False):
        params: dict[str, str | int] = {"issue_id": issue_id, "limit": limit}
        if start_now:
            params["start"] = "now"
        else:
            params["after"] = after
        if stream_id is not None:
            params["stream_id"] = stream_id
        return self._request("GET", "/v1/events?" + urlencode(params))

    def list_field_packets(self, issue_id: str, *, limit: int = 50,
                           after_packet_id: str | None = None):
        params = {"issue_id": issue_id, "limit": limit}
        if after_packet_id is not None:
            params["after_packet_id"] = after_packet_id
        return self._request("GET", "/v1/field-packets?" + urllib.parse.urlencode(params))

    def field_packet(self, packet_id: str):
        return self._request("GET", "/v1/field-packets/" + urllib.parse.quote(packet_id, safe=""))

    def field_packet_summary(self, packet_id: str, *, review_id: str | None = None):
        query = "?" + urllib.parse.urlencode({"review_id": review_id}) if review_id else ""
        route = "/v1/field-packets/" + urllib.parse.quote(packet_id, safe="") + "/summary" + query
        return self._request("GET", route)

    def field_source(self, packet_id: str, *, source_index: int | None = None, start: int = 0,
                     max_bytes: int = 8192, content_sha256: str | None = None):
        params: dict[str, str | int] = {"start": start, "max_bytes": max_bytes}
        if source_index is not None:
            params["source_index"] = source_index
        if content_sha256 is not None:
            params["content_sha256"] = content_sha256
        route = "/v1/field-packets/" + urllib.parse.quote(packet_id, safe="") + "/text?"
        return self._request("GET", route + urllib.parse.urlencode(params))

    def locate_field_excerpt(self, packet_id: str, *, source_index: int | None = None,
                             quoted_text: str, after_start: int = 0, limit: int = 3):
        params: dict[str, str | int] = {"quoted_text": quoted_text, "after_start": after_start, "limit": limit}
        if source_index is not None:
            params["source_index"] = source_index
        route = "/v1/field-packets/" + urllib.parse.quote(packet_id, safe="") + "/locate?"
        return self._request("GET", route + urllib.parse.urlencode(params))

    def field_review(self, packet_id: str, review_id: str, *, after_handled: int = 0,
                     after_unresolved: int = 0, max_bytes: int = 8192,
                     expected_curation_version: int | None = None):
        params: dict[str, str | int] = {"review_id": review_id, "after_handled": after_handled,
                                        "after_unresolved": after_unresolved, "max_bytes": max_bytes}
        if expected_curation_version is not None:
            params["expected_curation_version"] = expected_curation_version
        route = "/v1/field-packets/" + urllib.parse.quote(packet_id, safe="") + "/review?"
        return self._request("GET", route + urllib.parse.urlencode(params))

    def field_packet_fact(self, packet_id: str, fact_ref: str):
        route = ("/v1/field-packets/" + urllib.parse.quote(packet_id, safe="") + "/facts/" +
                 urllib.parse.quote(fact_ref, safe=""))
        return self._request("GET", route)

    def curated_field_items(self, packet_id: str, *, limit: int = 20, after_fact_ref: str | None = None,
                            expected_curation_version: int | None = None, max_bytes: int = 8192):
        params: dict[str, str | int] = {"limit": limit, "max_bytes": max_bytes}
        if after_fact_ref is not None:
            params["after_fact_ref"] = after_fact_ref
        if expected_curation_version is not None:
            params["expected_curation_version"] = expected_curation_version
        route = "/v1/field-packets/" + urllib.parse.quote(packet_id, safe="") + "/curated-items?"
        return self._request("GET", route + urllib.parse.urlencode(params))

    def field_reviews(self, packet_id: str, *, limit: int = 20, before_version: int | None = None,
                      expected_curation_version: int | None = None):
        params: dict[str, str | int] = {"limit": limit}
        if before_version is not None:
            params["before_version"] = before_version
        if expected_curation_version is not None:
            params["expected_curation_version"] = expected_curation_version
        route = "/v1/field-packets/" + urllib.parse.quote(packet_id, safe="") + "/reviews?"
        return self._request("GET", route + urllib.parse.urlencode(params))

    def field_fact(self, fact_ref: str):
        return self._request("GET", "/v1/field-facts/" + urllib.parse.quote(fact_ref, safe=""))

    def curate_field_item(self, packet_id: str, request: dict, *, request_id: str,
                          idempotency_key: str):
        route = "/v1/field-packets/" + urllib.parse.quote(packet_id, safe="") + "/curated-items"
        return self._request("POST", route, request, request_id=request_id,
                             idempotency_key=idempotency_key)

    def record_field_review(self, packet_id: str, request: dict, *, request_id: str,
                            idempotency_key: str):
        route = "/v1/field-packets/" + urllib.parse.quote(packet_id, safe="") + "/reviews"
        return self._request("POST", route, request, request_id=request_id,
                             idempotency_key=idempotency_key)

    def create_issue(self, issue_id: str, issue_type: str, title: str, *, idempotency_key: str,
                     parent_issue_id: str | None = None, scope: dict | None = None,
                     issue_type_registration_id: str | None = None, request_id: str | None = None):
        body: dict[str, Any] = {
            "issue_id": issue_id, "issue_type": issue_type, "title": title,
            "reason": "Create direct-use Issue Manager target",
        }
        for key, value in (("parent_issue_id", parent_issue_id), ("scope", scope),
                           ("issue_type_registration_id", issue_type_registration_id)):
            if value is not None:
                body[key] = value
        return self._request("POST", "/v1/issues", body, idempotency_key=idempotency_key,
                             request_id=request_id)

    def browse_issue(self, issue_id: str):
        return self._request("GET", "/v1/browse/issue?" + urlencode({"id": issue_id}))

    def list_issue_types(self, **page):
        query = "?" + urlencode(page) if page else ""
        return self._request("GET", "/v1/conclusion-rules/types" + query)

    def conclusion_rule(self, issue_id: str, *, revision: int | None = None):
        route = "/v1/conclusion-rules/issue/" + urllib.parse.quote(issue_id, safe="")
        if revision is not None:
            route += "?" + urlencode({"revision": revision})
        return self._request("GET", route)

    def set_conclusion_rule(self, issue_id: str, request: dict, *, request_id: str,
                            idempotency_key: str):
        route = "/v1/conclusion-rules/issue/" + urllib.parse.quote(issue_id, safe="")
        return self._request("POST", route, request, request_id=request_id,
                             idempotency_key=idempotency_key)

    def discover_original_access(self, issue_id: str, **query):
        return self._request("GET", "/v1/original-access/discover?" + urlencode({
            "issue_id": issue_id, **query}))

    def read_original_access(self, issue_id: str, contract_id: str | None = None,
                             revision: int | None = None, *, max_bytes: int = 65536,
                             evidence_id: str | None = None, reference: str | None = None):
        query = {"issue_id": issue_id, "max_bytes": max_bytes,
                 "contract_id": contract_id, "revision": revision,
                 "evidence_id": evidence_id, "reference": reference}
        return self._request("GET", "/v1/original-access/read?" + urlencode({
            k: v for k, v in query.items() if v is not None}))

    def register_original_access(self, request: dict, *, request_id: str, idempotency_key: str):
        return self._request("POST", "/v1/original-access", request,
                             request_id=request_id, idempotency_key=idempotency_key)

    def browse_children(self, issue_id: str, **page):
        return self._request("GET", "/v1/browse/children?" + urlencode({"id": issue_id, **page}))

    def browse_conclusions(self, issue_id: str, **page):
        return self._request("GET", "/v1/browse/conclusions?" + urlencode({"id": issue_id, **page}))

    def browse_evidence(self, issue_id: str, **page):
        return self._request("GET", "/v1/browse/evidence?" + urlencode({"id": issue_id, **page}))

    def browse_evidence_detail(self, evidence_id: str, **options):
        return self._request("GET", "/v1/browse/detail?" + urlencode({"id": evidence_id, **options}))

    def browse_neighbors(self, evidence_id: str, **page):
        return self._request("GET", "/v1/browse/neighbors?" + urlencode({"id": evidence_id, **page}))

    def inspect_issue(self, issue_id: str, *, intent: str = "handoff"):
        query = urllib.parse.urlencode({"issue": issue_id, "intent": intent})
        return self._request("GET", "/v1/context?" + query)

    def get_issue_overview(self, root_issue_id: str):
        """Fetch and validate one complete bounded Issue subtree over public HTTP."""
        if not isinstance(root_issue_id, str) or not root_issue_id.strip():
            raise ValueError("root_issue_id must be a non-empty string")
        query = urllib.parse.urlencode({"root": root_issue_id.strip()})
        result = self._request("GET", "/v1/issues/overview?" + query)
        if not isinstance(result, dict) or result.get("protocol_version") != 1:
            raise WorkflowAPIError(502, "overview_protocol_invalid",
                                   "Issue overview protocol version is unsupported")
        nodes = result.get("nodes")
        if result.get("complete") is not True or not isinstance(nodes, list) or len(nodes) > 128:
            raise WorkflowAPIError(502, "overview_incomplete",
                                   "Issue overview is incomplete or exceeds the node limit")
        snapshot = result.get("snapshot")
        content_hash = snapshot.get("content_sha256") if isinstance(snapshot, dict) else None
        if not isinstance(content_hash, str) or len(content_hash) != 64:
            raise WorkflowAPIError(502, "overview_hash_invalid",
                                   "Issue overview content hash is missing or malformed")
        assert isinstance(snapshot, dict)
        hash_input = dict(result)
        hash_snapshot = dict(snapshot)
        hash_snapshot.pop("content_sha256", None)
        hash_input["snapshot"] = hash_snapshot
        expected_hash = hashlib.sha256(json.dumps(
            hash_input, ensure_ascii=False, allow_nan=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        if expected_hash != content_hash:
            raise WorkflowAPIError(502, "overview_hash_mismatch",
                                   "Issue overview content hash does not match its body")
        if len(json.dumps(result, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":")).encode("utf-8")) > 256 * 1024:
            raise WorkflowAPIError(502, "overview_too_large",
                                   "Issue overview response exceeds 256 KiB")
        return result

    def scoped_contribution(self, request: dict, *, idempotency_key: str):
        return self._request("POST", "/v1/scoped-evidence-contributions", request,
                             idempotency_key=idempotency_key)

    def scoped_relation(self, relation_id: str):
        return self._request("GET", "/v1/scoped-evidence-relations/" +
                             urllib.parse.quote(relation_id, safe=""))

    def scoped_relation_binding(self, evidence_id: str):
        return self._request("GET", "/v1/scoped-evidence-relations/bindings/" +
                             urllib.parse.quote(evidence_id, safe=""))

    def create_scoped_relation(self, request: dict, *, idempotency_key: str):
        return self._request("POST", "/v1/scoped-evidence-relations", request,
                             idempotency_key=idempotency_key)

    def scoped_relations_for_source(self, scope_issue_id: str, source_evidence_id: str, *,
                                    limit: int = 8, max_bytes: int = 16_384,
                                    cursor: str | None = None,
                                    expected_snapshot: str | None = None,
                                    relation_id: str | None = None):
        params: dict[str, str | int] = {
            "scope_issue_id": scope_issue_id,
            "source_evidence_id": source_evidence_id,
            "limit": limit,
            "max_bytes": max_bytes,
        }
        if cursor is not None:
            params["cursor"] = cursor
        if expected_snapshot is not None:
            params["expected_snapshot"] = expected_snapshot
        if relation_id is not None:
            params["relation_id"] = relation_id
        return self._request("GET", "/v1/scoped-evidence-relations?" +
                             urllib.parse.urlencode(params))

    def scoped_relation_transition(self, relation_id: str, action: str, reason: str, *,
                                   expected_version_id: str, idempotency_key: str):
        if action not in {"deactivate", "reactivate"}:
            raise ValueError("Unsupported scoped relation transition")
        return self._request(
            "POST", "/v1/scoped-evidence-relations/" + urllib.parse.quote(relation_id, safe="") +
            "/" + action,
            {"expected_version_id": expected_version_id, "reason": reason},
            idempotency_key=idempotency_key,
        )

    def prepare_materials(self, issue_id: str, evidence_ids: list[str] | None = None, *, idempotency_key: str):
        body: dict[str, str | list[str]] = {"issue_id": issue_id}
        if evidence_ids is None:
            body["basis_mode"] = "current-basis"
        else:
            body["evidence_ids"] = list(evidence_ids)
        return self._request("POST", "/v1/currentness/prepare", body, idempotency_key=idempotency_key)

    def create_view(self, package_id: str, *, idempotency_key: str):
        return self._request("POST", "/v1/currentness/packages/" +
                             urllib.parse.quote(package_id, safe="") + "/views", {},
                             idempotency_key=idempotency_key)

    def currentness_package(self, package_id: str):
        return self._request("GET", "/v1/currentness/packages/" +
                             urllib.parse.quote(package_id, safe=""))

    def view(self, view_id: str, *, cursor: int | None = None):
        route = "/v1/currentness/views/" + urllib.parse.quote(view_id, safe="")
        if cursor is not None:
            route += "?cursor=" + urllib.parse.quote(str(cursor), safe="")
        return self._request("GET", route)

    def view_entry(self, view_id: str, kind: str, entry_id: str, *, cursor: str | None = None):
        route = ("/v1/currentness/views/" + urllib.parse.quote(view_id, safe="") + "/entries/"
                 + urllib.parse.quote(kind, safe="") + "/" + urllib.parse.quote(entry_id, safe=""))
        return self._request("GET", route + (("?cursor=" + urllib.parse.quote(cursor, safe="")) if cursor else ""))

    def material(self, view_id: str, evidence_id: str, *, mode: str = "selected", cursor: str | None = None):
        route = ("/v1/currentness/views/" + urllib.parse.quote(view_id, safe="") + "/materials/"
                 + urllib.parse.quote(evidence_id, safe="") + "?mode=" + urllib.parse.quote(mode, safe=""))
        if cursor:
            route += "&cursor=" + urllib.parse.quote(cursor, safe="")
        return self._request("GET", route)

    def record_working_conclusion(self, request: dict, *, idempotency_key: str):
        return self._request("POST", "/v1/issues/" + urllib.parse.quote(request["issue_id"], safe="") +
                             "/working-conclusion", request, idempotency_key=idempotency_key)
