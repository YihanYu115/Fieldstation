from __future__ import annotations

import json
import re
import sqlite3
from typing import TYPE_CHECKING, Any, Iterable

from .errors import ConflictError, NotFoundError, ValidationError
from .integrity import digest
from .migration_planner import plan_legacy_policy_migration
from .registry_service import (
    _semver,
    _version_matches,
    build_issue_type_semantics,
    finalize_prepared_references,
    install_prepared_bundle,
    prepare_bundle,
)
from .store import canonical_json, new_id, now
from .strict_json import require_strict_json

if TYPE_CHECKING:
    from .store import Store


POLICY_FINDING_CODES = frozenset(
    {
        "legacy_policy_profile_invalid",
        "legacy_policy_semantics_not_declaratively_convertible",
        "legacy_policy_bundle_prepare_invalid",
        "legacy_policy_snapshot_invalid",
        "legacy_policy_json_invalid",
        "migration_policy_mapping_proof_insufficient",
    }
)


def _row(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...]) -> dict[str, Any] | None:
    found = conn.execute(sql, params).fetchone()
    return dict(found) if found else None


def _rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [dict(item) for item in conn.execute(sql, params).fetchall()]


def load_policy_subject(
    conn: sqlite3.Connection, finding: dict[str, Any]
) -> dict[str, Any]:
    details = finding.get("details")
    if not isinstance(details, dict):
        try:
            details = json.loads(finding.get("details_json") or "{}")
        except (json.JSONDecodeError, TypeError):
            details = {}
    bundle_id = str(details.get("bundle_id", finding.get("object_id", "")))
    legacy_finding_id = details.get("legacy_finding_id")
    if legacy_finding_id and finding.get("code") == "migration_policy_mapping_proof_insufficient":
        legacy = _row(
            conn,
            "SELECT object_id,details_json FROM migration_findings WHERE finding_id=?",
            (legacy_finding_id,),
        )
        if legacy:
            legacy_details = json.loads(legacy.get("details_json") or "{}")
            bundle_id = str(legacy_details.get("bundle_id", legacy["object_id"]))
    bundle = _row(
        conn,
        "SELECT bundle_id,namespace,name,version,content_hash,state FROM extension_bundles "
        "WHERE bundle_id=?",
        (bundle_id,),
    )
    entries = _rows(
        conn,
        "SELECT registration_id,bundle_id,namespace,kind,name,version,api_version,"
        "content_hash,state,definition_json FROM registry_entries WHERE bundle_id=? "
        "ORDER BY registration_id",
        (bundle_id,),
    )
    routing = next(
        (
            item
            for item in entries
            if item["kind"] == "routing_profile" and item["name"] == "legacy-policy-snapshot"
        ),
        None,
    )
    policy: Any = None
    policy_hash: str | None = None
    if routing:
        try:
            definition = json.loads(routing["definition_json"])
            policy = definition["policy_snapshot"]
            policy_hash = digest(policy)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            pass
    affected_issues = _rows(
        conn,
        "SELECT issue_id,issue_type,issue_type_registration_id,issue_type_content_hash "
        "FROM issues WHERE issue_type_registration_id IN "
        "(SELECT registration_id FROM registry_entries WHERE bundle_id=? AND kind='issue_type') "
        "ORDER BY issue_id",
        (bundle_id,),
    )
    return {
        "bundle": bundle,
        "entries": entries,
        "routing_registration_id": routing["registration_id"] if routing else None,
        "policy": policy,
        "policy_hash": policy_hash,
        "affected_issues": affected_issues,
        "load_error": None if bundle and routing and policy_hash else "policy_subject_missing",
    }


def finding_fingerprint(
    finding: dict[str, Any], subject: dict[str, Any]
) -> dict[str, Any]:
    details = finding.get("details")
    if not isinstance(details, dict):
        try:
            details = json.loads(finding.get("details_json") or "{}")
        except (json.JSONDecodeError, TypeError):
            details = {}
    semantic_code = details.get("semantic_code")
    pointer = details.get("json_pointer", details.get("pointer", ""))
    if not semantic_code or not pointer:
        policy = subject.get("policy")
        if policy is not None:
            current_plan = plan_legacy_policy_migration(
                policy,
                existing_registry_entries=subject.get("entries", []),
                target_namespace="local.compat.v13.audit",
            )
            matching = next(
                (
                    item
                    for item in current_plan["blocking_findings"]
                    if item.get("code") == finding.get("code")
                    or (
                        finding.get("code")
                        in {
                            "legacy_policy_semantics_not_declaratively_convertible",
                            "migration_policy_mapping_proof_insufficient",
                        }
                        and item.get("semantic_code")
                    )
                ),
                None,
            )
            if matching:
                semantic_code = semantic_code or matching.get("semantic_code")
                pointer = pointer or matching.get("subject", {}).get("json_pointer", "")
    bundle = subject.get("bundle") or {}
    return {
        "classification": finding.get("classification"),
        "code": finding.get("code"),
        "semantic_code": semantic_code or "unspecified_policy_semantic",
        "json_pointer": pointer or "",
        "source_policy_hash": subject.get("policy_hash"),
        "source_bundle_id": bundle.get("bundle_id"),
        "source_bundle_hash": bundle.get("content_hash"),
    }


def _resolve_dependencies(
    conn: sqlite3.Connection, dependencies: Iterable[Any]
) -> list[dict[str, Any]]:
    locks: list[dict[str, Any]] = []
    for raw in dependencies:
        if isinstance(raw, str):
            match = re.fullmatch(r"([^/]+)/([^@]+)@(.+)", raw)
            if not match:
                raise ValidationError(f"Invalid bundle dependency: {raw!r}")
            namespace, name, version_range = match.groups()
        elif isinstance(raw, dict):
            namespace = str(raw.get("namespace", ""))
            name = str(raw.get("name", ""))
            version_range = str(raw.get("version", raw.get("version_range", "*")))
        else:
            raise ValidationError("Bundle dependency must be a string or object")
        candidates = _rows(
            conn,
            "SELECT bundle_id,version,content_hash,state FROM extension_bundles "
            "WHERE namespace=? AND name=? AND state IN ('installed','active','deprecated')",
            (namespace, name),
        )
        compatible = [item for item in candidates if _version_matches(item["version"], version_range)]
        if not compatible:
            raise ValidationError(f"Unresolved bundle dependency {namespace}/{name}@{version_range}")
        selected = max(compatible, key=lambda item: _semver(item["version"]))
        locks.append(
            {
                "namespace": namespace,
                "name": name,
                "declared_range": version_range,
                "resolved_bundle_id": selected["bundle_id"],
                "resolved_version": selected["version"],
                "resolved_content_hash": selected["content_hash"],
            }
        )
    return sorted(locks, key=lambda item: (item["namespace"], item["name"]))


def _prepare_feature_bundle(
    conn: sqlite3.Connection, bundle: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    prepared = prepare_bundle(bundle, trusted_local=False)
    dependency_locks = _resolve_dependencies(
        conn, prepared["manifest"].get("dependencies", [])
    )
    external: list[dict[str, Any]] = []
    for lock in dependency_locks:
        external.extend(
            _rows(
                conn,
                "SELECT * FROM registry_entries WHERE bundle_id=? ORDER BY registration_id",
                (lock["resolved_bundle_id"],),
            )
        )
    prepared, reference_locks = finalize_prepared_references(
        prepared, external, dependency_locks
    )
    return prepared, dependency_locks, reference_locks


def _auto_binding_map(
    subject: dict[str, Any], prepared: dict[str, Any]
) -> dict[str, str]:
    old_by_name = {
        item["name"]: item["registration_id"]
        for item in subject.get("entries", [])
        if item["kind"] == "issue_type"
    }
    new_by_name = {
        item["name"]: item["registration_id"]
        for item in prepared.get("entries", [])
        if item["kind"] == "issue_type"
    }
    return {
        old_registration: new_by_name[name]
        for name, old_registration in old_by_name.items()
        if name in new_by_name
    }


def _candidate_plan(
    *,
    mode: str,
    fingerprint: dict[str, Any],
    prepared: dict[str, Any],
    dependency_locks: list[dict[str, Any]],
    reference_locks: list[dict[str, Any]],
    issue_binding_map: dict[str, str],
    affected_issues: list[dict[str, Any]],
    replacement_policy_plan: dict[str, Any] | None,
    registry_environment: list[dict[str, Any]],
) -> dict[str, Any]:
    required_old = sorted(
        {
            str(item["issue_type_registration_id"])
            for item in affected_issues
            if item.get("issue_type_registration_id")
        }
    )
    target_entries = {
        item["registration_id"]: item
        for item in prepared.get("entries", [])
        if item["kind"] == "issue_type"
    }
    residual: list[dict[str, Any]] = []
    if replacement_policy_plan:
        residual.extend(replacement_policy_plan.get("blocking_findings", []))
    missing = sorted(set(required_old) - set(issue_binding_map))
    if missing:
        residual.append({"code": "policy_repair_issue_binding_missing", "registrations": missing})
    invalid_targets = sorted(
        target
        for target in issue_binding_map.values()
        if target not in target_entries
    )
    if invalid_targets:
        residual.append(
            {"code": "policy_repair_issue_binding_target_invalid", "registrations": invalid_targets}
        )
    plan: dict[str, Any] = {
        "format": "migration-policy-repair-plan/v1",
        "repair_mode": mode,
        "fingerprint": fingerprint,
        "prepared_bundle_id": prepared.get("bundle_id"),
        "prepared_bundle_hash": prepared.get("content_hash"),
        "dependency_locks": dependency_locks,
        "reference_locks_hash": digest(reference_locks),
        "issue_binding_map": issue_binding_map,
        "affected_issue_ids": [item["issue_id"] for item in affected_issues],
        "covered_findings": [fingerprint],
        "residual_findings": residual,
        "registry_environment_hash": digest(registry_environment),
        "safe_to_apply": not residual,
    }
    plan["plan_hash"] = digest(plan)
    return plan


def create_policy_repair(
    store: Store,
    finding_id: str,
    *,
    replacement_policy: dict[str, Any] | None = None,
    replacement_bundle: dict[str, Any] | None = None,
    issue_binding_map: dict[str, str] | None = None,
    actor: str,
) -> dict[str, Any]:
    if (replacement_policy is None) == (replacement_bundle is None):
        raise ValidationError(
            "Supply exactly one replacement Policy or replacement Feature Bundle"
        )
    require_strict_json(
        replacement_policy if replacement_policy is not None else replacement_bundle,
        path="$.replacement",
    )
    require_strict_json(issue_binding_map or {}, path="$.issue_binding_map")
    with store.transaction() as conn:
        finding = _row(
            conn,
            "SELECT * FROM migration_findings WHERE finding_id=?",
            (finding_id,),
        )
        if not finding:
            raise NotFoundError(f"Migration finding not found: {finding_id}")
        if finding["state"] != "open":
            raise ConflictError("Policy repair candidate requires an open finding")
        if finding["code"] not in POLICY_FINDING_CODES:
            raise ValidationError("Finding does not use the trusted Policy repair handler")
        finding["details"] = json.loads(finding.get("details_json") or "{}")
        subject = load_policy_subject(conn, finding)
        if subject.get("load_error"):
            raise ValidationError("Policy repair source is unavailable", details=subject)
        fingerprint = finding_fingerprint(finding, subject)
        # Reference finalization needs the full registry identity, while the
        # migration planner itself reduces this to a stable hash snapshot.
        registry_environment = _rows(
            conn,
            "SELECT * FROM registry_entries ORDER BY registration_id",
            (),
        )
        replacement_policy_plan: dict[str, Any] | None = None
        dependency_locks: list[dict[str, Any]] = []
        if replacement_policy is not None:
            mode = "replacement_policy_snapshot"
            replacement_policy_plan = plan_legacy_policy_migration(
                replacement_policy,
                existing_registry_entries=registry_environment,
                target_namespace="local.compat.v13",
            )
            prepared = replacement_policy_plan.get("prepared_bundle") or {
                "bundle_id": "",
                "content_hash": "",
                "entries": [],
                "manifest": {},
            }
            reference_locks = replacement_policy_plan.get("reference_locks", [])
        else:
            mode = "replacement_feature_bundle"
            assert replacement_bundle is not None
            prepared, dependency_locks, reference_locks = _prepare_feature_bundle(
                conn, replacement_bundle
            )
        bindings = dict(issue_binding_map or _auto_binding_map(subject, prepared))
        plan = _candidate_plan(
            mode=mode,
            fingerprint=fingerprint,
            prepared=prepared,
            dependency_locks=dependency_locks,
            reference_locks=reference_locks,
            issue_binding_map=bindings,
            affected_issues=subject["affected_issues"],
            replacement_policy_plan=replacement_policy_plan,
            registry_environment=registry_environment,
        )
        repair_id = new_id("policy_repair")
        timestamp = now()
        replacement_policy_json = (
            canonical_json(replacement_policy) if replacement_policy is not None else None
        )
        replacement_bundle_json = (
            canonical_json(replacement_bundle) if replacement_bundle is not None else None
        )
        conn.execute(
            "INSERT INTO migration_policy_repairs VALUES ("
            + ",".join("?" for _ in range(26))
            + ")",
            (
                repair_id,
                finding_id,
                subject["bundle"]["bundle_id"],
                subject["bundle"]["content_hash"],
                subject["policy_hash"],
                canonical_json(fingerprint),
                digest(fingerprint),
                mode,
                replacement_policy_json,
                digest(replacement_policy) if replacement_policy is not None else None,
                replacement_bundle_json,
                digest(replacement_bundle) if replacement_bundle is not None else None,
                canonical_json(prepared),
                str(prepared.get("content_hash", "")),
                canonical_json(reference_locks),
                digest(reference_locks),
                canonical_json(bindings),
                digest(bindings),
                canonical_json(plan),
                plan["plan_hash"],
                "draft",
                timestamp,
                actor,
                None,
                None,
                None,
            ),
        )
        return show_policy_repair(store, repair_id)


def _decode_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    result = dict(candidate)
    for column in (
        "finding_fingerprint_json",
        "replacement_policy_json",
        "replacement_bundle_json",
        "prepared_bundle_json",
        "reference_locks_json",
        "issue_binding_map_json",
        "plan_json",
    ):
        value = result.pop(column)
        result[column.removesuffix("_json")] = json.loads(value) if value is not None else None
    return result


def show_policy_repair(store: Store, repair_id: str) -> dict[str, Any]:
    candidate = store.row(
        "SELECT * FROM migration_policy_repairs WHERE repair_id=?",
        (repair_id,),
    )
    if not candidate:
        raise NotFoundError(f"Migration Policy repair not found: {repair_id}")
    return _decode_candidate(candidate)


def _revalidate_candidate(
    conn: sqlite3.Connection, candidate: dict[str, Any]
) -> dict[str, Any]:
    finding = _row(
        conn,
        "SELECT * FROM migration_findings WHERE finding_id=?",
        (candidate["finding_id"],),
    )
    if not finding:
        return {"valid": False, "code": "policy_repair_finding_missing"}
    finding["details"] = json.loads(finding.get("details_json") or "{}")
    subject = load_policy_subject(conn, finding)
    fingerprint = finding_fingerprint(finding, subject)
    stale: list[str] = []
    bundle = subject.get("bundle") or {}
    if finding["state"] != "open":
        stale.append("finding_state")
    if bundle.get("content_hash") != candidate["source_bundle_hash"]:
        stale.append("source_bundle_hash")
    if subject.get("policy_hash") != candidate["source_policy_hash"]:
        stale.append("source_policy_hash")
    if digest(fingerprint) != candidate["finding_fingerprint_hash"]:
        stale.append("finding_fingerprint")
    registry_environment = _rows(
        conn,
        "SELECT * FROM registry_entries ORDER BY registration_id",
        (),
    )
    replacement_policy_plan: dict[str, Any] | None = None
    dependency_locks: list[dict[str, Any]] = []
    try:
        if candidate["repair_mode"] == "replacement_policy_snapshot":
            replacement_policy_plan = plan_legacy_policy_migration(
                candidate["replacement_policy"],
                existing_registry_entries=registry_environment,
                target_namespace="local.compat.v13",
            )
            prepared = replacement_policy_plan.get("prepared_bundle") or {}
            reference_locks = replacement_policy_plan.get("reference_locks", [])
        else:
            prepared, dependency_locks, reference_locks = _prepare_feature_bundle(
                conn, candidate["replacement_bundle"]
            )
    except (ValidationError, ConflictError, PermissionError, KeyError, TypeError) as exc:
        return {
            "valid": False,
            "code": "policy_repair_prepare_failed",
            "message": str(exc),
            "stale_fields": stale,
        }
    plan = _candidate_plan(
        mode=candidate["repair_mode"],
        fingerprint=fingerprint,
        prepared=prepared,
        dependency_locks=dependency_locks,
        reference_locks=reference_locks,
        issue_binding_map=candidate["issue_binding_map"],
        affected_issues=subject.get("affected_issues", []),
        replacement_policy_plan=replacement_policy_plan,
        registry_environment=registry_environment,
    )
    exact_hashes = {
        "prepared_bundle_hash": str(prepared.get("content_hash", "")),
        "reference_locks_hash": digest(reference_locks),
        "issue_binding_map_hash": digest(candidate["issue_binding_map"]),
        "plan_hash": plan["plan_hash"],
    }
    for column, current in exact_hashes.items():
        if current != candidate[column]:
            stale.append(column)
    valid = not stale and plan["safe_to_apply"]
    return {
        "valid": valid,
        "code": "policy_repair_valid" if valid else "policy_repair_stale_or_invalid",
        "stale_fields": sorted(stale),
        "residual_findings": plan["residual_findings"],
        "covered_findings": plan["covered_findings"],
        "affected_issue_count": len(subject.get("affected_issues", [])),
        "plan_hash": plan["plan_hash"],
        "prepared_bundle_hash": prepared.get("content_hash"),
        "prepared_bundle": prepared,
        "reference_locks": reference_locks,
        "dependency_locks": dependency_locks,
    }


def validate_policy_repair(store: Store, repair_id: str) -> dict[str, Any]:
    with store.transaction() as conn:
        raw = _row(
            conn,
            "SELECT * FROM migration_policy_repairs WHERE repair_id=?",
            (repair_id,),
        )
        if not raw:
            raise NotFoundError(f"Migration Policy repair not found: {repair_id}")
        candidate = _decode_candidate(raw)
        if candidate["state"] in {"applied", "rejected", "superseded"}:
            raise ConflictError(f"Policy repair cannot be validated from {candidate['state']}")
        validation = _revalidate_candidate(conn, candidate)
        target_state = "validated" if validation["valid"] else "stale"
        conn.execute(
            "UPDATE migration_policy_repairs SET state=?,validated_at=? WHERE repair_id=?",
            (target_state, now() if validation["valid"] else None, repair_id),
        )
        return {**candidate, "state": target_state, "validation": validation}


def policy_repair_dependency(
    conn: sqlite3.Connection, repair_id: str
) -> list[dict[str, Any]]:
    from .integrity import load_dependency

    candidate = load_dependency(conn, "policy_repair_candidate", repair_id)
    if not candidate:
        return []
    raw = _row(
        conn,
        "SELECT prepared_bundle_json FROM migration_policy_repairs WHERE repair_id=?",
        (repair_id,),
    )
    prepared = json.loads(raw["prepared_bundle_json"]) if raw else {}
    bundle = load_dependency(conn, "extension_bundle", str(prepared.get("bundle_id", "")))
    dependencies = [candidate]
    if bundle:
        bundle["required_states"] = ["active"]
        dependencies.append(bundle)
    for entry in prepared.get("entries", []):
        registration = load_dependency(
            conn, "registry_registration", str(entry.get("registration_id", ""))
        )
        if registration:
            registration["required_states"] = ["active"]
            dependencies.append(registration)
    return sorted(
        dependencies,
        key=lambda item: (item["dependency_type"], item["dependency_id"]),
    )


def apply_policy_repair_mutation(
    conn: sqlite3.Connection,
    candidate: dict[str, Any],
    *,
    actor: str,
) -> list[dict[str, Any]]:
    validation = _revalidate_candidate(conn, candidate)
    if not validation["valid"] or candidate["state"] != "validated":
        conn.execute(
            "UPDATE migration_policy_repairs SET state='stale' WHERE repair_id=?",
            (candidate["repair_id"],),
        )
        raise ConflictError("Policy repair candidate is stale", details=validation)
    prepared = validation["prepared_bundle"]
    dependency_locks = validation["dependency_locks"]
    reference_locks = validation["reference_locks"]
    install = install_prepared_bundle(
        conn,
        prepared,
        actor=actor,
        state="active",
        lock_snapshot=dependency_locks,
    )
    if not install.get("idempotent_replay"):
        for lock in dependency_locks:
            conn.execute(
                "INSERT INTO registry_dependencies VALUES (?,?,?,?,?,?,?,?)",
                (
                    new_id("dependency"),
                    prepared["bundle_id"],
                    lock["namespace"],
                    lock["name"],
                    lock["declared_range"],
                    lock["resolved_bundle_id"],
                    lock["resolved_version"],
                    lock["resolved_content_hash"],
                ),
            )
        for lock in reference_locks:
            conn.execute(
                "INSERT INTO registry_reference_locks VALUES (?,?,?,?,?,?,?)",
                (
                    lock["owner_registration_id"],
                    lock["json_pointer"],
                    lock["target_registration_id"],
                    lock["target_kind"],
                    lock["target_content_hash"],
                    lock["resolution_source"],
                    now(),
                ),
            )
    entries = {item["registration_id"]: item for item in prepared["entries"]}
    result_objects: list[dict[str, Any]] = [
        {
            "object_type": "extension_bundle",
            "object_id": prepared["bundle_id"],
            "content_hash": prepared["content_hash"],
        }
    ]
    for old_id, new_id_value in sorted(candidate["issue_binding_map"].items()):
        entry = entries[new_id_value]
        semantics = build_issue_type_semantics(
            entry["name"], entry["api_version"], entry["definition"]
        )
        semantic_snapshot = {
            "registration_id": entry["registration_id"],
            "registration_content_hash": entry["content_hash"],
            "api_version": "issue-type/v2",
            "definition": semantics,
        }
        semantic_hash = digest(semantic_snapshot)
        issues = _rows(
            conn,
            "SELECT issue_id FROM issues WHERE issue_type_registration_id=? ORDER BY issue_id",
            (old_id,),
        )
        conn.execute(
            "UPDATE issues SET issue_type_registration_id=?,issue_type_content_hash=?,"
            "issue_type_snapshot_json=?,issue_type_semantic_hash=?,updated_at=? "
            "WHERE issue_type_registration_id=?",
            (
                entry["registration_id"],
                entry["content_hash"],
                canonical_json(semantic_snapshot),
                semantic_hash,
                now(),
                old_id,
            ),
        )
        result_objects.extend(
            {
                "object_type": "issue",
                "object_id": issue["issue_id"],
                "content_hash": semantic_hash,
            }
            for issue in issues
        )
    conn.execute(
        "UPDATE migration_policy_repairs SET state='applied',applied_at=? WHERE repair_id=?",
        (now(), candidate["repair_id"]),
    )
    return result_objects


def load_candidate(conn: sqlite3.Connection, repair_id: str) -> dict[str, Any]:
    raw = _row(
        conn,
        "SELECT * FROM migration_policy_repairs WHERE repair_id=?",
        (repair_id,),
    )
    if not raw:
        raise NotFoundError(f"Migration Policy repair not found: {repair_id}")
    return _decode_candidate(raw)
