"""Direct split domain operation. All mutations are one IM transaction."""
from __future__ import annotations

from typing import Any

from .direct_split_boundary import snapshot
from .errors import ConflictError, PermissionError, ValidationError
from .store import canonical_json, new_id, now


class DirectSplitService:
    def __init__(self, manager: Any):
        self.manager = manager
        self.store = manager.store

    def boundary(self, source: str, *, auth: Any) -> dict[str, Any]:
        with self.store.read_transaction():
            return snapshot(self.manager, source, auth=auth)

    def split(self, request: dict[str, Any], *, auth: Any, idempotency_key: str) -> dict[str, Any]:
        auth.require("context.read")
        auth.require("evidence.write")
        if not isinstance(idempotency_key, str) or not idempotency_key.strip():
            raise ValidationError("Direct split requires an idempotency key")
        required = {"source_evidence_id", "expected_snapshot", "parts", "relation_decisions", "new_relations"}
        if not isinstance(request, dict) or not required <= set(request) or set(request) - required - {"extra_snapshots", "observed_relation_versions"}:
            raise ValidationError("Invalid direct split request fields")
        source = request["source_evidence_id"]
        expected = request["expected_snapshot"]
        parts = request["parts"]
        decisions = request["relation_decisions"]
        additions = request["new_relations"]
        extra_snapshots = request.get("extra_snapshots", {})
        observed_versions = request.get("observed_relation_versions", {})
        if not isinstance(source, str) or not source or not isinstance(expected, str) or not expected:
            raise ValidationError("Source and expected boundary snapshot are required")
        if not isinstance(parts, list) or not 2 <= len(parts) <= 16:
            raise ValidationError("A split needs between 2 and 16 parts")
        for part in parts:
            if (not isinstance(part, dict) or set(part) != {"issue_id", "kind", "text"}
                    or not all(isinstance(part.get(k), str) and part[k].strip() for k in part)
                    or part["kind"] not in {"observation", "interpretation"}
                    or len(part["text"]) > 8000):
                raise ValidationError("Each part needs an Issue, observation/interpretation, and text")
        if not isinstance(decisions, list) or len(decisions) > 16 or not isinstance(additions, list) or len(additions) > 16:
            raise ValidationError("Relation choices must be bounded arrays")
        if (not isinstance(extra_snapshots, dict) or len(extra_snapshots) > 128 or any(
                not isinstance(k, str) or not k or not isinstance(v, str) or not v for k, v in extra_snapshots.items())):
            raise ValidationError("Extra Evidence snapshots must be a bounded map")
        if (not isinstance(observed_versions, dict) or len(observed_versions) > 16 or any(
                not isinstance(k, str) or not k or not isinstance(v, str) or not v
                for k, v in observed_versions.items())):
            raise ValidationError("Observed relation versions must be a bounded map")
        if decisions or additions:
            auth.require("evidence.relation.write")
        operation = f"direct_split:{auth.actor_id}:{auth.run_id}:{auth.platform_id or ''}"
        with self.store.transaction() as conn:
            self.manager.evidence.require_read_access(source, auth)
            replay = self.store.idempotency_lookup(operation, idempotency_key, request)
            if replay is not None:
                for child in replay["parts"]:
                    self.manager.evidence.require_read_access(child["evidence_id"], auth)
                return {**replay, "idempotent_replay": True}
            before = snapshot(self.manager, source, auth=auth)
            if before["snapshot"] != expected:
                raise ConflictError("Split boundary changed; inspect it and make a new decision",
                                    details={"code": "split_boundary_changed"})
            relation_map = {r["relation_id"]: r for r in before["scoped_relations"]}
            seen: set[str] = set()
            for decision in decisions:
                if not isinstance(decision, dict) or set(decision) != {"relation_id", "action", "part_index", "reason"}:
                    raise ValidationError("Each relation choice requires relation_id, action, part_index and reason")
                rid, action, index, reason = (decision[k] for k in ("relation_id", "action", "part_index", "reason"))
                if not isinstance(rid, str) or rid in seen or rid not in relation_map:
                    raise ValidationError("Relation choice must identify a distinct relation in the boundary")
                seen.add(rid)
                relation = relation_map[rid]
                try:
                    for endpoint in (relation["source_evidence_id"], relation["target_evidence_id"]):
                        self.manager.evidence.require_read_access(endpoint, auth)
                except PermissionError:
                    raise PermissionError("Selected relation contains inaccessible Evidence") from None
                if rid in observed_versions and relation["version_id"] != observed_versions[rid]:
                    raise ConflictError("An observed relation changed; inspect it and make a new decision",
                                        details={"code": "split_boundary_changed"})
                if (not relation["active"] or source not in (relation["source_evidence_id"], relation["target_evidence_id"])
                        or relation["source_evidence_id"] == relation["target_evidence_id"]):
                    raise ValidationError("Only active non-self relations directly involving the source can be changed")
                if not isinstance(action, str) or action not in {"withdraw", "replace"} or not isinstance(reason, str) or not reason.strip():
                    raise ValidationError("Relation choice needs withdraw/replace and a reason")
                if (action == "withdraw" and index is not None) or (action == "replace" and
                        (type(index) is not int or not 0 <= index < len(parts))):
                    raise ValidationError("Replacement requires a valid part index")
            # New edges may reference parts or existing nodes whose complete
            # scoped boundary was fixed before the write.
            known = {source}
            for identity, expected_extra in extra_snapshots.items():
                actual = snapshot(self.manager, identity, auth=auth)["snapshot"]
                if actual != expected_extra:
                    raise ConflictError("A selected Evidence boundary changed; make a new decision")
                known.add(identity)
            for edge in additions:
                if not isinstance(edge, dict) or set(edge) != {"issue_id", "source", "target", "relation_type", "rationale"}:
                    raise ValidationError("Invalid new relation fields")
                if any(not isinstance(edge[k], str) or not edge[k].strip() for k in ("issue_id", "relation_type", "rationale")):
                    raise ValidationError("New relation needs an Issue, type and rationale")
                for endpoint in (edge["source"], edge["target"]):
                    if not isinstance(endpoint, dict) or len(endpoint) != 1:
                        raise ValidationError("Relation endpoints identify one part or Evidence")
                    if "part_index" in endpoint:
                        n = endpoint["part_index"]
                        if type(n) is not int or not 0 <= n < len(parts):
                            raise ValidationError("Invalid relation part index")
                    elif "evidence_id" in endpoint:
                        if not isinstance(endpoint["evidence_id"], str) or endpoint["evidence_id"] not in known:
                            raise ValidationError("Relation Evidence is outside the frozen boundary")
                    else:
                        raise ValidationError("Invalid relation endpoint")
            split_id = new_id("direct_split")
            source_binding, source_binding_token = self.manager.scoped_evidence_relations._binding(
                self.manager.scoped_evidence_relations._evidence(conn, source))
            children = []
            for index, part in enumerate(parts):
                locator = "im-internal:direct-split:" + new_id("src")
                result = self.manager.add_evidence(
                    kind="report", locator=locator, issue_id=part["issue_id"],
                    description=part["text"], actor=auth.actor_id, reason="direct split",
                    _declared_source_locator="issue-manager:evidence:" + source, _conn=conn,
                )
                if result.get("existing"):
                    raise ConflictError("Split child identity collision")
                child_id = result["evidence_id"]
                self.store.fault("direct_split.after_child")
                conn.execute("INSERT INTO direct_split_origins "
                             "(child_evidence_id,source_evidence_id,split_id,part_index,content_kind,"
                             "source_binding_json,source_binding_token,actor_id,platform_id,created_at) "
                             "VALUES (?,?,?,?,?,?,?,?,?,?)",
                             (child_id, source, split_id, index, part["kind"], canonical_json(source_binding),
                              source_binding_token, auth.actor_id, auth.platform_id, now()))
                children.append({"evidence_id": child_id, "issue_id": part["issue_id"], "kind": part["kind"]})
                self.store.fault("direct_split.after_origin")
            created = []
            for index, decision in enumerate(decisions):
                relation = relation_map[decision["relation_id"]]
                self.manager.scoped_evidence_relations.deactivate(
                    decision["relation_id"], expected_version_id=relation["version_id"],
                    reason=decision["reason"], auth=auth, idempotency_key=f"{idempotency_key}:withdraw:{index}")
                if decision["action"] == "replace":
                    child = children[decision["part_index"]]["evidence_id"]
                    start = child if relation["source_evidence_id"] == source else relation["source_evidence_id"]
                    end = child if relation["target_evidence_id"] == source else relation["target_evidence_id"]
                    created.append(self._create(conn, relation["scope_issue_id"], start, end,
                                                relation["relation_type"], decision["reason"], auth,
                                                f"{idempotency_key}:replace:{index}", relation["impact_policy"]))
                self.store.fault("direct_split.after_relation")
            for index, edge in enumerate(additions):
                def endpoint(value: dict[str, Any]) -> str:
                    return children[value["part_index"]]["evidence_id"] if "part_index" in value else value["evidence_id"]
                created.append(self._create(conn, edge["issue_id"], endpoint(edge["source"]), endpoint(edge["target"]),
                                            edge["relation_type"], edge["rationale"], auth,
                                            f"{idempotency_key}:new:{index}", None))
                self.store.fault("direct_split.after_relation")
            self.manager.context_maintenance.flush()
            revision = conn.execute("SELECT revision FROM context_input_clock WHERE singleton=1").fetchone()[0]
            if conn.execute(
                "SELECT 1 FROM conclusion_currentness c WHERE c.computed_revision=? "
                "AND EXISTS (SELECT 1 FROM json_each(c.reason_json) r "
                "WHERE json_extract(r.value,'$.code')='context_resolution_failed') LIMIT 1", (revision,),
            ).fetchone():
                raise ConflictError("Split impact could not be resolved; the original action was not committed",
                                    details={"code": "split_impact_unresolved"})
            self.store.fault("direct_split.after_currentness")
            compact_relations = [{key: relation[key] for key in ("relation_id", "version_id", "scope_issue_id",
                                  "source_evidence_id", "target_evidence_id", "relation_type", "impact_policy")}
                                 for relation in created]
            compact_decisions = [{key: decision[key] for key in ("relation_id", "action", "part_index")}
                                 for decision in decisions]
            result = {"split_id": split_id, "source_evidence_id": source, "parts": children,
                      "relations_created": compact_relations, "relation_decisions": compact_decisions,
                      "currentness": "maintained", "scientific_validity": "not_assessed"}
            self.store.idempotency_record(conn, operation, idempotency_key, request, result)
            self.store.fault("direct_split.after_receipt")
            return result

    def _create(self, conn: Any, issue: str, source: str, target: str, kind: str, rationale: str,
                auth: Any, key: str, impact: str | None) -> dict[str, Any]:
        service = self.manager.scoped_evidence_relations
        source_token = service._binding(service._evidence(conn, source))[1]
        target_token = service._binding(service._evidence(conn, target))[1]
        return service.create(scope_issue_id=issue, source_evidence_id=source, target_evidence_id=target,
                              relation_type=kind, rationale=rationale, impact_policy=impact, auth=auth,
                              expected_source_token=source_token, expected_target_token=target_token,
                              idempotency_key=key, conn=conn)
