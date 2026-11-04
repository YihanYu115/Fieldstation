from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import nullcontext
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import (
    AttestationManifestStaleError,
    AttestationPlatformMismatchError,
    BindingReviewRequiredError,
    ConflictError,
    CrossPlatformSupersedeForbiddenError,
    EvidenceBindingConflictError,
    EvidenceIdentityConflictError,
    EvidenceIdentityInvariantError,
    EvidencePlatformMismatchError,
    EvidenceSourceUnboundError,
    ManifestPlatformMismatchError,
    ManifestRevisionStaleError,
    NotFoundError,
    PermissionError,
    PrivateResourceForbiddenError,
    ValidationError,
)
from .evidence_identity import (
    IDENTITY_ALGORITHM,
    LOCATOR_IDENTITY_VERSION,
    conflict_identity_key,
    identity_locator,
    platform_identity_key,
    search_normalize_locator,
)
from .evidence_semantics import semantic_manifest_fingerprint, semantic_manifest_parts
from .security import AuthContext, CredentialResolver
from .store import canonical_json, new_id, now

if TYPE_CHECKING:
    from .service import IssueManager


def normalize_quality_status(status: str) -> str:
    """Shared reassessment semantics for execution and staged state."""
    if status not in {"unknown", "usable", "questionable", "invalid", "unusable_for_purpose"}:
        raise ValidationError(f"Unknown evidence quality status: {status}")
    return "unusable_for_purpose" if status == "invalid" else status


VERIFICATION_LEVELS = (
    "declared",
    "source_verified",
    "snapshot_verified",
    "reproduced",
)
VERIFICATION_STATES = {
    "active",
    "verification_requested",
    "conflict",
    "unavailable",
    "superseded",
}
ATTESTATION_TYPES = {"existence", "metadata", "content", "snapshot", "reproduction"}
ATTESTATION_STATES = {"valid", "conflict", "superseded", "revoked"}
ATTESTATION_ROLES = {"source", "independent", "resolution"}
MANIFEST_LIMIT_BYTES = 256 * 1024


def _json(value: str | None, fallback: Any) -> Any:
    return json.loads(value) if value is not None else fallback


class EvidenceService:
    """Append-only evidence manifests, attestations, and Manager-derived verification."""

    MANIFEST_FIELDS = {
        "manifest_version",
        "platform_id",
        "observed_at",
        "sample_session_ref",
        "content_identity",
        "data_profile",
        "execution",
        "summary",
        "preview_artifact_ids",
        "mutable_source",
        "adapter",
        "extensions",
    }

    def __init__(self, manager: "IssueManager"):
        self.manager = manager
        self.store = manager.store
        self.credentials = CredentialResolver(self.store)

    def register_platform(
        self,
        platform_id: str,
        *,
        display_name: str,
        capabilities: list[str],
        metadata: dict[str, Any] | None = None,
        credential: str | Path,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "identity.manage")
        if not platform_id or any(char.isspace() for char in platform_id):
            raise ValidationError("platform_id must be a non-empty token without whitespace")
        if not display_name.strip():
            raise ValidationError("Platform display_name cannot be empty")
        allowed = {"manifest", "metadata", "existence", "preview", "statistics", "reanalysis"}
        unknown = set(capabilities) - allowed
        if unknown:
            raise ValidationError(f"Unknown platform capabilities: {sorted(unknown)}")
        if self.store.row("SELECT 1 FROM platform_sources WHERE platform_id=?", (platform_id,)):
            raise ConflictError(f"Platform source already exists: {platform_id}")
        result = {
            "platform_id": platform_id,
            "display_name": display_name.strip(),
            "status": "active",
            "capabilities": sorted(set(capabilities)),
            "metadata": metadata or {},
        }
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO platform_sources VALUES (?,?,?,?,?,?,?)",
                (
                    platform_id,
                    result["display_name"],
                    "active",
                    canonical_json(result["capabilities"]),
                    canonical_json(result["metadata"]),
                    now(),
                    auth.actor_id,
                ),
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="platform.register",
                object_type="platform_source",
                object_id=platform_id,
                before_revision=None,
                after_revision=1,
                reason="",
                payload=result,
            )
            self._activity(
                conn,
                "platform.registered",
                "platform_source",
                platform_id,
                [],
                result,
                platform_id=platform_id,
            )
        return result

    def list_platforms(self) -> list[dict[str, Any]]:
        result = []
        for row in self.store.rows("SELECT * FROM platform_sources ORDER BY platform_id"):
            row["capabilities"] = _json(row.pop("capabilities_json"), [])
            row["metadata"] = _json(row.pop("metadata_json"), {})
            result.append(row)
        return result

    @staticmethod
    def _source_key(platform_id: str, kind: str, locator: str) -> str:
        return platform_identity_key(platform_id, kind, locator)

    @staticmethod
    def normalize_locator(locator: str) -> str:
        return search_normalize_locator(locator)

    def identity_for(self, platform_id: str, kind: str, locator: str) -> dict[str, Any]:
        exact = identity_locator(locator)
        search = search_normalize_locator(locator)
        return {
            "identity_algorithm": IDENTITY_ALGORITHM,
            "locator_identity_version": LOCATOR_IDENTITY_VERSION,
            "identity_locator": exact,
            "search_locator": search,
            "normalized_locator": search,
            "identity_namespace": "platform",
            "identity_key": platform_identity_key(platform_id, kind, exact),
        }

    def source_binding(self, evidence_id: str) -> dict[str, Any]:
        row = self.store.row(
            "SELECT * FROM evidence_source_bindings WHERE evidence_id=?", (evidence_id,)
        )
        if not row:
            raise EvidenceSourceUnboundError(
                "Evidence has no source binding record", details={"evidence_id": evidence_id}
            )
        return row

    def require_read_access(self, evidence_id: str, auth: AuthContext) -> None:
        if not auth.platform_id:
            return
        current = evidence_id
        seen: set[str] = set()
        while current not in seen and len(seen) < 1000:
            seen.add(current)
            allowed = self.store.row(
                "SELECT 1 FROM evidence_source_bindings WHERE evidence_id=? "
                "AND source_platform_id=? UNION SELECT 1 FROM evidence_requests "
                "WHERE evidence_id=? AND platform_id=? UNION SELECT 1 FROM evidence_attestations "
                "WHERE evidence_id=? AND platform_id=? LIMIT 1",
                (current, auth.platform_id, current, auth.platform_id, current, auth.platform_id),
            )
            if allowed:
                return
            origin = self.store.row(
                "SELECT source_evidence_id FROM direct_split_origins "
                "WHERE child_evidence_id=? AND platform_id=?", (current, auth.platform_id),
            )
            if origin is None:
                break
            current = origin["source_evidence_id"]
        raise PrivateResourceForbiddenError(
            "Evidence is outside this platform's authorized scope",
            details={"evidence_id": evidence_id},
        )

    def _bind_source(
        self,
        conn: sqlite3.Connection,
        evidence_id: str,
        platform_id: str,
        auth: AuthContext,
    ) -> dict[str, Any]:
        evidence_value = conn.execute(
            "SELECT kind,locator,declared_source_locator,normalized_locator,identity_locator,search_locator,"
            "locator_identity_version,identity_key,identity_namespace "
            "FROM evidence_refs WHERE evidence_id=?",
            (evidence_id,),
        ).fetchone()
        if not evidence_value:
            raise NotFoundError(f"Evidence not found: {evidence_id}")
        evidence = dict(evidence_value)
        if evidence.get("declared_source_locator") is not None:
            raise ValidationError(
                "Scoped contribution source is declared only; its internal identity cannot be platform-bound",
                details={"evidence_id": evidence_id},
            )
        value = conn.execute(
            "SELECT * FROM evidence_source_bindings WHERE evidence_id=?", (evidence_id,)
        ).fetchone()
        binding = dict(value) if value else None
        if binding and binding["binding_state"] == "binding_conflict":
            raise EvidenceBindingConflictError(
                "Evidence source binding is in conflict",
                details={"evidence_id": evidence_id},
            )
        if binding and binding["binding_state"] in {"bound", "inferred"}:
            if binding["source_platform_id"] != platform_id:
                raise EvidencePlatformMismatchError(
                    "Evidence is owned by another source platform",
                    details={
                        "evidence_id": evidence_id,
                        "expected_platform": binding["source_platform_id"],
                        "actual_platform": platform_id,
                    },
                )
            expected_key = self._source_key(platform_id, evidence["kind"], evidence["locator"])
            if (
                evidence["identity_namespace"] != "platform"
                or evidence["identity_key"] != expected_key
                or binding.get("source_key") != expected_key
            ):
                raise EvidenceIdentityInvariantError(
                    "Evidence identity and source binding are inconsistent",
                    details={"evidence_id": evidence_id},
                )
            return binding
        if binding and binding["binding_state"] == "retired":
            raise EvidenceSourceUnboundError(
                "Evidence source binding is retired", details={"evidence_id": evidence_id}
            )
        target_key = self._source_key(platform_id, evidence["kind"], evidence["locator"])
        occupied = conn.execute(
            "SELECT evidence_id FROM evidence_refs WHERE identity_key=? AND evidence_id<>?",
            (target_key, evidence_id),
        ).fetchone()
        if occupied:
            raise EvidenceIdentityConflictError(
                "The platform Evidence identity is already occupied",
                details={
                    "evidence_id": evidence_id,
                    "conflicting_evidence_id": occupied["evidence_id"],
                    "identity_key": target_key,
                },
            )
        review_reasons: list[str] = []
        published = conn.execute(
            "SELECT i.issue_id,c.conclusion_id,c.status,i.issue_type "
            "FROM issues i JOIN conclusion_revisions c "
            "ON c.conclusion_id=i.current_conclusion_id "
            "JOIN conclusion_evidence_uses u ON u.conclusion_id=c.conclusion_id "
            "WHERE u.evidence_id=? AND (c.status IN ('accepted','canonical') "
            "OR i.issue_type='report_scope') LIMIT 1",
            (evidence_id,),
        ).fetchone()
        if published:
            review_reasons.append("published_use")
        unresolved = conn.execute(
            "SELECT 1 FROM conclusion_evidence_uses u JOIN evidence_proofs p "
            "ON p.proof_id=u.proof_id WHERE u.evidence_id=? "
            "AND EXISTS (SELECT 1 FROM json_each(p.reason_codes_json) "
            "WHERE value='legacy_unresolved') LIMIT 1",
            (evidence_id,),
        ).fetchone()
        if unresolved:
            review_reasons.append("legacy_unresolved_proof")
        if review_reasons:
            raise BindingReviewRequiredError(
                "Legacy Evidence source binding requires a reviewed T3 ChangeSet",
                details={"evidence_id": evidence_id, "reason_codes": review_reasons},
            )
        before = binding or {}
        revision = int(binding["binding_revision"]) + 1 if binding else 1
        after = {
            "evidence_id": evidence_id,
            "source_platform_id": platform_id,
            "binding_state": "bound",
            "source_key": target_key,
            "binding_revision": revision,
        }
        if binding:
            conn.execute(
                "UPDATE evidence_source_bindings SET source_platform_id=?,binding_state='bound',"
                "source_key=?,binding_revision=?,reviewed_at=NULL,reviewed_by=NULL,reason=? "
                "WHERE evidence_id=?",
                (
                    platform_id,
                    after["source_key"],
                    revision,
                    "low-risk authenticated Legacy source claim",
                    evidence_id,
                ),
            )
        else:
            conn.execute(
                "INSERT INTO evidence_source_bindings("
                "evidence_id,source_platform_id,binding_state,source_key,binding_revision,"
                "created_at,created_by,reviewed_at,reviewed_by,reason) "
                "VALUES (?,?,'bound',?,?,?, ?,NULL,NULL,?)",
                (
                    evidence_id,
                    platform_id,
                    after["source_key"],
                    revision,
                    now(),
                    auth.actor_id,
                    "first authenticated Manifest submission",
                ),
            )
        conn.execute(
            "UPDATE evidence_refs SET normalized_locator=?,identity_locator=?,search_locator=?,"
            "locator_identity_version=?,identity_namespace='platform',identity_key=? "
            "WHERE evidence_id=?",
            (
                search_normalize_locator(evidence["locator"]),
                identity_locator(evidence["locator"]),
                search_normalize_locator(evidence["locator"]),
                LOCATOR_IDENTITY_VERSION,
                target_key,
                evidence_id,
            ),
        )
        conn.execute(
            "INSERT INTO evidence_source_binding_events("
            "binding_event_id,evidence_id,before_json,after_json,event_type,reason,actor_id,"
            "run_id,created_at,reviewed_changeset_id,review_ids_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,NULL,'[]')",
            (
                new_id("binding_event"),
                evidence_id,
                canonical_json(before),
                canonical_json(after),
                "legacy_source_claimed",
                "low-risk authenticated Legacy source claim",
                auth.actor_id,
                auth.run_id,
                now(),
            ),
        )
        return after

    @staticmethod
    def _semantic_parts(manifest: dict[str, Any]) -> dict[str, Any]:
        return semantic_manifest_parts(manifest)

    def _manifest_change_class(
        self, previous: dict[str, Any] | None, current: dict[str, Any]
    ) -> tuple[str, str]:
        fingerprint = semantic_manifest_fingerprint(current)
        if previous is None:
            return "initial", fingerprint
        old = _json(previous["manifest_json"], {})
        if (
            old.get("content_identity", {}) != current.get("content_identity", {})
            or bool(old.get("mutable_source", False))
            != bool(current.get("mutable_source", False))
        ):
            return "content_changed", fingerprint
        if any(
            old.get(field) != current.get(field)
            for field in (
                "observed_at",
                "sample_session_ref",
                "data_profile",
                "execution",
                "adapter",
            )
        ):
            return "provenance_changed", fingerprint
        if any(
            old.get(field) != current.get(field)
            for field in ("preview_artifact_ids", "extensions")
        ):
            return "metadata_changed", fingerprint
        old_namespaced = {str(key): value for key, value in old.items() if ":" in str(key)}
        current_namespaced = {
            str(key): value for key, value in current.items() if ":" in str(key)
        }
        if old_namespaced != current_namespaced:
            return "metadata_changed", fingerprint
        return "summary_only", fingerprint

    @staticmethod
    def _classify_proof_transition(
        before: dict[str, str], after: dict[str, str]
    ) -> tuple[str, str, list[str]]:
        level_rank = {name: index for index, name in enumerate(VERIFICATION_LEVELS)}
        if after["state"] in {"conflict", "unavailable", "superseded"}:
            return (
                f"state_{after['state']}",
                "blocked",
                [f"verification_state_{after['state']}"],
            )
        if level_rank[after["level"]] < level_rank.get(before["level"], 0):
            return "level_downgraded", "stale", ["verification_downgrade"]
        if level_rank[after["level"]] > level_rank.get(before["level"], 0):
            return "level_upgraded", "notify", ["verification_upgrade"]
        if after["state"] != before["state"]:
            return "state_changed", "impact_review", ["verification_state_changed"]
        return "unchanged", "none", []

    @staticmethod
    def _manifest_default_impact(change_class: str | None) -> tuple[str, list[str]]:
        if change_class == "content_changed":
            return "stale", ["manifest_content_changed"]
        if change_class in {"provenance_changed", "metadata_changed", "initial"}:
            return "impact_review", [f"manifest_{change_class}"]
        if change_class == "summary_only":
            return "notify", ["manifest_summary_changed"]
        return "none", []

    @staticmethod
    def _check_bounded(value: Any, *, path: str = "manifest") -> None:
        if isinstance(value, list):
            if len(value) > 4096:
                raise ValidationError(f"{path} contains an oversized array")
            for index, item in enumerate(value):
                EvidenceService._check_bounded(item, path=f"{path}[{index}]")
        elif isinstance(value, dict):
            for key, item in value.items():
                EvidenceService._check_bounded(item, path=f"{path}.{key}")
        elif isinstance(value, str):
            lowered = value.lstrip().lower()
            if lowered.startswith("data:") and ";base64," in lowered:
                raise ValidationError("Manifest previews must be registered Artifacts, not base64")
            if len(value.encode("utf-8")) > 64 * 1024:
                raise ValidationError(f"{path} contains an oversized string")

    def validate_manifest(self, manifest: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(manifest, dict):
            raise ValidationError("Evidence Manifest must be an object")
        raw = canonical_json(manifest)
        if len(raw.encode("utf-8")) > MANIFEST_LIMIT_BYTES:
            raise ValidationError(f"Evidence Manifest exceeds {MANIFEST_LIMIT_BYTES} bytes")
        self._check_bounded(manifest)
        if manifest.get("manifest_version") != 1:
            raise ValidationError("Only Evidence Manifest version 1 is supported")
        platform_id = manifest.get("platform_id")
        if not isinstance(platform_id, str) or not platform_id:
            raise ValidationError("Evidence Manifest requires platform_id")
        unknown = set(manifest) - self.MANIFEST_FIELDS
        unnamespaced = {key for key in unknown if ":" not in str(key)}
        if unnamespaced:
            raise ValidationError(
                f"Unrecognized Manifest fields must be namespaced or placed in extensions: "
                f"{sorted(unnamespaced)}"
            )
        for field in ("content_identity", "data_profile", "execution", "summary"):
            if not isinstance(manifest.get(field, {}), dict):
                raise ValidationError(f"Manifest {field} must be an object")
        previews = manifest.get("preview_artifact_ids", [])
        if not isinstance(previews, list) or any(not isinstance(item, str) for item in previews):
            raise ValidationError("preview_artifact_ids must be a list of Artifact IDs")
        identity = manifest.get("content_identity", {})
        immutable = bool(identity.get("digest") or identity.get("immutable_revision"))
        mutable = bool(manifest.get("mutable_source", False))
        if not immutable and not mutable:
            raise ValidationError(
                "A mutable locator must set mutable_source=true when no digest or immutable_revision exists"
            )
        return json.loads(raw)

    @staticmethod
    def _enforce_platform(auth: AuthContext, platform_id: str) -> None:
        if auth.platform_id is None:
            raise PermissionError("Evidence Manifest operations require a platform-scoped principal")
        if auth.platform_id != platform_id:
            raise PermissionError(
                f"Principal is scoped to platform {auth.platform_id!r}, not {platform_id!r}"
            )

    def submit_manifest(
        self,
        evidence_id: str,
        manifest: dict[str, Any],
        *,
        credential: str | Path,
        source_packet_id: str | None = None,
        supersedes_manifest_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "evidence.manifest.submit")
        return self._submit_manifest_auth(
            evidence_id,
            manifest,
            auth=auth,
            source_packet_id=source_packet_id,
            supersedes_manifest_id=supersedes_manifest_id,
            idempotency_key=idempotency_key,
        )

    def _submit_manifest_auth(
        self,
        evidence_id: str,
        manifest: dict[str, Any],
        *,
        auth: AuthContext,
        source_packet_id: str | None = None,
        supersedes_manifest_id: str | None = None,
        idempotency_key: str | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        auth.require("evidence.manifest.submit")
        normalized = self.validate_manifest(manifest)
        platform_id = normalized["platform_id"]
        self._enforce_platform(auth, platform_id)
        if not self.store.row(
            "SELECT 1 FROM platform_sources WHERE platform_id=? AND status='active'",
            (platform_id,),
        ):
            raise ValidationError(f"Active platform source not found: {platform_id}")
        platform = self.store.row(
            "SELECT capabilities_json FROM platform_sources WHERE platform_id=?", (platform_id,)
        )
        if not platform or "manifest" not in set(_json(platform["capabilities_json"], [])):
            raise PermissionError("Platform does not advertise Manifest submission capability")
        for artifact_id in normalized.get("preview_artifact_ids", []):
            if not self.store.row(
                "SELECT 1 FROM artifacts WHERE artifact_id=?", (artifact_id,)
            ):
                raise ValidationError(f"Manifest preview Artifact not found: {artifact_id}")
            self.manager.artifacts.require_platform_artifact(artifact_id, platform_id)
        evidence = self.store.row(
            "SELECT evidence_id,identity_namespace,identity_key,normalized_locator,"
            "identity_locator,search_locator,locator_identity_version "
            "FROM evidence_refs WHERE evidence_id=? AND lifecycle_status='active'",
            (evidence_id,),
        )
        if not evidence:
            raise NotFoundError(f"Active evidence not found: {evidence_id}")
        manifest_hash = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
        operation_payload = {
            "evidence_id": evidence_id,
            "manifest_hash": manifest_hash,
            "source_packet_id": source_packet_id,
            "supersedes_manifest_id": supersedes_manifest_id,
            "actor_id": auth.actor_id,
            "run_id": auth.run_id,
        }
        replay = self.store.idempotency_lookup(
            "evidence.manifest.submit", idempotency_key, operation_payload
        )
        if replay:
            return {**replay, "idempotent_replay": True}
        transaction = self.store.transaction() if conn is None else nullcontext(conn)
        with transaction as active:
            source_binding = self._bind_source(active, evidence_id, platform_id, auth)
            existing_value = active.execute(
                "SELECT manifest_id,manifest_revision,change_class FROM evidence_manifests "
                "WHERE evidence_id=? AND manifest_hash=?",
                (evidence_id, manifest_hash),
            ).fetchone()
            if existing_value:
                existing = dict(existing_value)
                current = active.execute(
                    "SELECT semantic_revision,current_proof_id FROM evidence_refs "
                    "WHERE evidence_id=?",
                    (evidence_id,),
                ).fetchone()
                binding = active.execute(
                    "SELECT source_platform_id,binding_state,source_key "
                    "FROM evidence_source_bindings "
                    "WHERE evidence_id=?",
                    (evidence_id,),
                ).fetchone()
                return {
                    **existing,
                    "evidence_id": evidence_id,
                    "semantic_revision": int(current["semantic_revision"]),
                    "current_proof_id": current["current_proof_id"],
                    "source_binding": dict(binding) if binding else None,
                    "identity_namespace": evidence["identity_namespace"],
                    "identity_key": evidence["identity_key"],
                    "normalized_locator": evidence["normalized_locator"],
                    "identity_locator": evidence["identity_locator"],
                    "search_locator": evidence["search_locator"],
                    "locator_identity_version": evidence["locator_identity_version"],
                    "identity_algorithm": IDENTITY_ALGORITHM,
                    "existing": True,
                }
            latest_value = active.execute(
                "SELECT * FROM evidence_manifests WHERE evidence_id=? "
                "ORDER BY manifest_revision DESC LIMIT 1",
                (evidence_id,),
            ).fetchone()
            latest = dict(latest_value) if latest_value else None
            reviewed_source_migration = str(source_binding.get("reason", "")).startswith(
                "reviewed source migration:"
            )
            if (
                latest
                and latest["platform_id"] != platform_id
                and not reviewed_source_migration
            ):
                raise ManifestPlatformMismatchError(
                    "Current Manifest belongs to another source platform",
                    details={
                        "evidence_id": evidence_id,
                        "expected_platform": latest["platform_id"],
                        "actual_platform": platform_id,
                    },
                )
            if latest and supersedes_manifest_id != latest["manifest_id"]:
                raise ManifestRevisionStaleError(
                    "A new Manifest revision must explicitly supersede the current Manifest",
                    details={
                        "evidence_id": evidence_id,
                        "current_manifest_id": latest["manifest_id"],
                        "supersedes_manifest_id": supersedes_manifest_id,
                    },
                )
            if not latest and supersedes_manifest_id:
                raise ValidationError("The first Manifest revision cannot supersede another Manifest")
            revision = int(latest["manifest_revision"]) + 1 if latest else 1
            manifest_id = new_id("manifest")
            change_class, semantic_fingerprint = self._manifest_change_class(latest, normalized)
            result = {
                "manifest_id": manifest_id,
                "evidence_id": evidence_id,
                "manifest_revision": revision,
                "manifest_version": 1,
                "platform_id": platform_id,
                "manifest_hash": manifest_hash,
                "semantic_fingerprint": semantic_fingerprint,
                "change_class": change_class,
                "supersedes_manifest_id": supersedes_manifest_id,
            }
            timestamp = now()
            if latest:
                active.execute(
                    "UPDATE evidence_manifests SET superseded_at=? WHERE manifest_id=?",
                    (timestamp, latest["manifest_id"]),
                )
            active.execute(
                "INSERT INTO evidence_manifests("
                "manifest_id,evidence_id,manifest_revision,manifest_version,platform_id,"
                "source_packet_id,source_actor_id,source_run_id,observed_at,sample_session_ref,"
                "content_identity_json,data_profile_json,execution_json,summary_json,manifest_json,"
                "manifest_hash,created_at,supersedes_manifest_id,semantic_fingerprint,change_class,"
                "superseded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
                (
                    manifest_id,
                    evidence_id,
                    revision,
                    1,
                    platform_id,
                    source_packet_id,
                    auth.actor_id,
                    auth.run_id,
                    normalized.get("observed_at"),
                    normalized.get("sample_session_ref"),
                    canonical_json(normalized.get("content_identity", {})),
                    canonical_json(normalized.get("data_profile", {})),
                    canonical_json(normalized.get("execution", {})),
                    canonical_json(normalized.get("summary", {})),
                    canonical_json(normalized),
                    manifest_hash,
                    timestamp,
                    supersedes_manifest_id,
                    semantic_fingerprint,
                    change_class,
                ),
            )
            active.execute(
                "UPDATE evidence_refs SET mutable_source=?,current_manifest_id=?,"
                "semantic_revision=semantic_revision+1 WHERE evidence_id=?",
                (1 if normalized.get("mutable_source") else 0, manifest_id, evidence_id),
            )
            active.execute(
                "UPDATE evidence_attestations SET proof_eligible=0,invalidated_at=?,"
                "invalidation_reason='Manifest revision superseded' WHERE evidence_id=? "
                "AND proof_eligible=1 AND qualified_manifest_id IS NOT NULL "
                "AND qualified_manifest_id<>?",
                (timestamp, evidence_id, manifest_id),
            )
            active.execute(
                "UPDATE evidence_requests SET state='expired',lease_until=NULL,updated_at=?,"
                "last_error='requested Manifest superseded' WHERE evidence_id=? "
                "AND state IN ('pending','claimed','running') AND requested_manifest_id IS NOT NULL "
                "AND requested_manifest_id<>?",
                (timestamp, evidence_id, manifest_id),
            )
            verification = self.recalculate(
                evidence_id,
                trigger_object_type="evidence_manifest",
                trigger_object_id=manifest_id,
                reason=f"Manifest {change_class}",
                auth=auth,
                conn=active,
                semantic_change_class=change_class,
            )
            result["verification"] = verification
            current = active.execute(
                "SELECT semantic_revision,current_proof_id FROM evidence_refs WHERE evidence_id=?",
                (evidence_id,),
            ).fetchone()
            result["semantic_revision"] = int(current["semantic_revision"])
            result["proof_id"] = current["current_proof_id"]
            result["current_proof_id"] = current["current_proof_id"]
            source_binding = active.execute(
                "SELECT source_platform_id,binding_state,source_key "
                "FROM evidence_source_bindings "
                "WHERE evidence_id=?",
                (evidence_id,),
            ).fetchone()
            result["source_binding"] = dict(source_binding) if source_binding else None
            identity = active.execute(
                "SELECT identity_namespace,identity_key,normalized_locator,identity_locator,"
                "search_locator,locator_identity_version "
                "FROM evidence_refs WHERE evidence_id=?",
                (evidence_id,),
            ).fetchone()
            result.update(dict(identity))
            result["identity_algorithm"] = IDENTITY_ALGORITHM
            publication_impact = self.manager._evidence_publication_impact(
                evidence_id, include_working=True
            )
            result["publication_impact"] = [
                item["issue_id"] for item in (publication_impact or {}).get("issues", [])
            ]
            self.store.idempotency_record(
                active,
                "evidence.manifest.submit",
                idempotency_key,
                operation_payload,
                result,
            )
            self.store.audit(
                active,
                actor=auth.actor_id,
                action="evidence.manifest.submit",
                object_type="evidence_manifest",
                object_id=manifest_id,
                before_revision=revision - 1 or None,
                after_revision=revision,
                reason="",
                payload=result,
            )
            issue_ids = self._issue_ids(evidence_id, active)
            self._activity(
                active,
                "evidence.manifest.submitted",
                "evidence_manifest",
                manifest_id,
                issue_ids,
                result,
                platform_id=platform_id,
            )
        return result

    def attest(
        self,
        evidence_id: str,
        *,
        attestation_type: str,
        method: str,
        input_snapshot: dict[str, Any],
        result: dict[str, Any],
        credential: str | Path,
        manifest_id: str | None = None,
        artifact_ids: list[str] | None = None,
        analysis_run_id: str | None = None,
        state: str = "valid",
        attestation_role: str | None = None,
        qualified_manifest_hash: str | None = None,
        supersedes_attestation_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        if attestation_role == "resolution":
            raise PermissionError(
                "Resolution Attestations must be created by an applied reviewed ChangeSet"
            )
        auth = self.credentials.resolve(credential, "evidence.attest")
        return self._attest_auth(
            evidence_id,
            attestation_type=attestation_type,
            method=method,
            input_snapshot=input_snapshot,
            result=result,
            auth=auth,
            manifest_id=manifest_id,
            artifact_ids=artifact_ids,
            analysis_run_id=analysis_run_id,
            state=state,
            attestation_role=attestation_role,
            qualified_manifest_hash=qualified_manifest_hash,
            supersedes_attestation_id=supersedes_attestation_id,
            idempotency_key=idempotency_key,
        )

    def _attest_auth(
        self,
        evidence_id: str,
        *,
        attestation_type: str,
        method: str,
        input_snapshot: dict[str, Any],
        result: dict[str, Any],
        auth: AuthContext,
        manifest_id: str | None = None,
        artifact_ids: list[str] | None = None,
        analysis_run_id: str | None = None,
        state: str = "valid",
        attestation_role: str | None = None,
        qualified_manifest_hash: str | None = None,
        supersedes_attestation_id: str | None = None,
        idempotency_key: str | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        auth.require("evidence.attest")
        if attestation_type not in ATTESTATION_TYPES:
            raise ValidationError(f"Unknown attestation type: {attestation_type}")
        if state not in ATTESTATION_STATES:
            raise ValidationError(f"Unknown attestation state: {state}")
        if not method.strip():
            raise ValidationError("Attestation method cannot be empty")
        if not isinstance(input_snapshot, dict) or not isinstance(result, dict):
            raise ValidationError("Attestation input_snapshot and result must be objects")
        if not auth.platform_id:
            raise PermissionError("Evidence attestations require a platform-scoped principal")
        platform_id = auth.platform_id
        required_capability = {
            "existence": "existence",
            "metadata": "metadata",
            "content": "metadata",
            "snapshot": "preview",
            "reproduction": "reanalysis",
        }[attestation_type]
        evidence = self.store.row(
            "SELECT lifecycle_status,current_manifest_id FROM evidence_refs WHERE evidence_id=?",
            (evidence_id,),
        )
        if not evidence or evidence["lifecycle_status"] != "active":
            raise NotFoundError(f"Active evidence not found: {evidence_id}")
        binding = self.source_binding(evidence_id)
        if binding["binding_state"] == "binding_conflict":
            raise EvidenceBindingConflictError(
                "Evidence source binding is in conflict", details={"evidence_id": evidence_id}
            )
        binding_active = binding["binding_state"] in {"bound", "inferred"}
        role = attestation_role or "source"
        if role not in ATTESTATION_ROLES:
            raise ValidationError(f"Unknown attestation role: {role}")
        if role == "resolution":
            raise PermissionError(
                "Resolution Attestations must be created by an applied reviewed ChangeSet"
            )
        platform = self.store.row(
            "SELECT capabilities_json,status FROM platform_sources WHERE platform_id=?",
            (platform_id,),
        )
        if (
            not platform
            or platform["status"] != "active"
            or required_capability not in set(_json(platform["capabilities_json"], []))
        ):
            raise PermissionError(
                f"Platform does not advertise {required_capability!r} attestation capability"
            )
        if role == "source" and binding_active and binding["source_platform_id"] != platform_id:
            raise AttestationPlatformMismatchError(
                "Source Attestation must come from the Evidence source platform",
                details={
                    "evidence_id": evidence_id,
                    "expected_platform": binding["source_platform_id"],
                    "actual_platform": platform_id,
                },
            )
        manifest = None
        if manifest_id:
            manifest = self.store.row(
                "SELECT evidence_id,platform_id,manifest_hash FROM evidence_manifests "
                "WHERE manifest_id=?",
                (manifest_id,),
            )
            if not manifest or manifest["evidence_id"] != evidence_id:
                raise ValidationError("Attestation Manifest does not belong to the evidence")
            if manifest_id != evidence.get("current_manifest_id"):
                raise AttestationManifestStaleError(
                    "Attestation must qualify the current Manifest revision",
                    details={
                        "evidence_id": evidence_id,
                        "current_manifest_id": evidence.get("current_manifest_id"),
                        "qualified_manifest_id": manifest_id,
                    },
                )
            if binding_active and manifest["platform_id"] != binding["source_platform_id"]:
                raise ManifestPlatformMismatchError(
                    "Qualified Manifest does not belong to the Evidence source platform"
                )
            if qualified_manifest_hash and qualified_manifest_hash != manifest["manifest_hash"]:
                raise AttestationManifestStaleError(
                    "Qualified Manifest hash does not match the current Manifest",
                    details={
                        "manifest_id": manifest_id,
                        "expected_hash": manifest["manifest_hash"],
                        "actual_hash": qualified_manifest_hash,
                    },
                )
        elif role == "independent":
            raise ValidationError(
                f"{role.capitalize()} Attestation requires a current Manifest ID/hash"
            )
        artifacts = sorted(set(artifact_ids or []))
        for artifact_id in artifacts:
            if not self.store.row(
                "SELECT 1 FROM artifacts WHERE artifact_id=?", (artifact_id,)
            ):
                raise ValidationError(f"Attestation Artifact not found: {artifact_id}")
            self.manager.artifacts.require_platform_artifact(artifact_id, platform_id)
        if attestation_type == "reproduction" and not analysis_run_id:
            raise ValidationError("A reproduction attestation requires analysis_run_id")
        if analysis_run_id:
            run = self.manager.artifacts.require_platform_analysis_run(
                analysis_run_id, platform_id, frozen=attestation_type == "reproduction"
            )
            if manifest:
                snapshots = _json(run.get("input_manifest_hashes_json"), {})
                pinned = snapshots.get(evidence_id, {})
                if pinned.get("manifest_id") != manifest_id or pinned.get(
                    "manifest_hash"
                ) != manifest["manifest_hash"]:
                    raise AttestationManifestStaleError(
                        "AnalysisRun does not pin the qualified Manifest ID/hash",
                        details={
                            "analysis_run_id": analysis_run_id,
                            "manifest_id": manifest_id,
                        },
                    )
        result_hash = hashlib.sha256(canonical_json(result).encode("utf-8")).hexdigest()
        operation_payload = {
            "evidence_id": evidence_id,
            "attestation_type": attestation_type,
            "method": method,
            "input_snapshot": input_snapshot,
            "result_hash": result_hash,
            "artifact_ids": artifacts,
            "analysis_run_id": analysis_run_id,
            "state": state,
            "attestation_role": role,
            "qualified_manifest_id": manifest_id,
            "qualified_manifest_hash": manifest["manifest_hash"] if manifest else None,
            "actor_id": auth.actor_id,
            "run_id": auth.run_id,
        }
        replay = self.store.idempotency_lookup(
            "evidence.attest", idempotency_key, operation_payload
        )
        if replay:
            return {**replay, "idempotent_replay": True}
        if supersedes_attestation_id:
            previous = self.store.row(
                "SELECT evidence_id,state,platform_id,attestation_role FROM evidence_attestations "
                "WHERE attestation_id=?",
                (supersedes_attestation_id,),
            )
            if not previous or previous["evidence_id"] != evidence_id:
                raise ValidationError("Superseded attestation does not belong to the evidence")
            if previous["state"] in {"superseded", "revoked"}:
                raise ConflictError("Attestation was already superseded or revoked")
            if previous["platform_id"] != platform_id or previous["attestation_role"] != role:
                raise CrossPlatformSupersedeForbiddenError(
                    "An Attestation can only supersede the same platform and role",
                    details={
                        "attestation_id": supersedes_attestation_id,
                        "expected_platform": previous["platform_id"],
                        "actual_platform": platform_id,
                    },
                )
        attestation_id = new_id("attestation")
        response = {
            "attestation_id": attestation_id,
            "evidence_id": evidence_id,
            "attestation_type": attestation_type,
            "platform_id": platform_id,
            "attestation_role": role,
            "qualified_manifest_id": manifest_id,
            "qualified_manifest_hash": manifest["manifest_hash"] if manifest else None,
            "state": state,
            "result_hash": result_hash,
        }
        transaction = self.store.transaction() if conn is None else nullcontext(conn)
        with transaction as active:
            if supersedes_attestation_id:
                active.execute(
                    "UPDATE evidence_attestations SET state='superseded',proof_eligible=0,"
                    "invalidated_at=?,invalidation_reason='explicitly superseded' "
                    "WHERE attestation_id=? AND state IN ('valid','conflict')",
                    (now(), supersedes_attestation_id),
                )
            proof_eligible = int(
                bool(manifest)
                and manifest_id == evidence.get("current_manifest_id")
                and state in {"valid", "conflict"}
            )
            active.execute(
                "INSERT INTO evidence_attestations("
                "attestation_id,evidence_id,manifest_id,attestation_type,platform_id,actor_id,"
                "run_id,method,input_snapshot_json,result_json,result_hash,artifact_ids_json,"
                "analysis_run_id,state,created_at,supersedes_attestation_id,attestation_role,"
                "qualified_manifest_id,qualified_manifest_hash,proof_eligible,invalidated_at,"
                "invalidation_reason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL)",
                (
                    attestation_id,
                    evidence_id,
                    manifest_id,
                    attestation_type,
                    platform_id,
                    auth.actor_id,
                    auth.run_id,
                    method.strip(),
                    canonical_json(input_snapshot),
                    canonical_json(result),
                    result_hash,
                    canonical_json(artifacts),
                    analysis_run_id,
                    state,
                    now(),
                    supersedes_attestation_id,
                    role,
                    manifest_id,
                    manifest["manifest_hash"] if manifest else None,
                    proof_eligible,
                ),
            )
            self.store.idempotency_record(
                active,
                "evidence.attest",
                idempotency_key,
                operation_payload,
                response,
            )
            self.store.audit(
                active,
                actor=auth.actor_id,
                action="evidence.attest",
                object_type="evidence_attestation",
                object_id=attestation_id,
                before_revision=None,
                after_revision=1,
                reason="",
                payload=response,
            )
            verification = self.recalculate(
                evidence_id,
                trigger_object_type="evidence_attestation",
                trigger_object_id=attestation_id,
                reason="attestation appended",
                auth=auth,
                conn=active,
            )
            self._activity(
                active,
                "evidence.attested",
                "evidence_attestation",
                attestation_id,
                self._issue_ids(evidence_id, active),
                {**response, "verification": verification},
                platform_id=platform_id,
            )
        return {**response, "verification": verification}

    def revoke_attestation(
        self,
        attestation_id: str,
        *,
        reason: str,
        credential: str | Path,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "evidence.attest")
        row = self.store.row(
            "SELECT * FROM evidence_attestations WHERE attestation_id=?", (attestation_id,)
        )
        if not row:
            raise NotFoundError(f"Attestation not found: {attestation_id}")
        if auth.platform_id != row["platform_id"]:
            raise CrossPlatformSupersedeForbiddenError(
                "A platform cannot revoke another platform's Attestation",
                details={
                    "attestation_id": attestation_id,
                    "expected_platform": row["platform_id"],
                    "actual_platform": auth.platform_id,
                },
            )
        if row["state"] == "revoked":
            return {"attestation_id": attestation_id, "state": "revoked", "existing": True}
        if not reason.strip():
            raise ValidationError("Revoking an attestation requires a reason")
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE evidence_attestations SET state='revoked',proof_eligible=0,"
                "invalidated_at=?,invalidation_reason=? WHERE attestation_id=?",
                (now(), reason.strip(), attestation_id),
            )
            verification = self.recalculate(
                row["evidence_id"],
                trigger_object_type="evidence_attestation",
                trigger_object_id=attestation_id,
                reason=reason,
                auth=auth,
                conn=conn,
            )
        return {"attestation_id": attestation_id, "state": "revoked", "verification": verification}

    def preview_source_migration(self, evidence_id, new_platform_id, *, reason, state_view=None):
        if not reason.strip():
            raise ValidationError("Reviewed source migration requires a reason")
        if not self.store.row("SELECT 1 FROM platform_sources WHERE platform_id=? AND status='active'", (new_platform_id,)):
            raise ValidationError(f"Active platform source not found: {new_platform_id}")
        evidence = state_view.evidence(evidence_id) if state_view is not None else self.store.row(
            "SELECT * FROM evidence_refs WHERE evidence_id=?", (evidence_id,))
        if not evidence:
            raise NotFoundError(f"Evidence not found: {evidence_id}")
        if evidence.get("declared_source_locator") is not None:
            raise ValidationError(
                "Scoped contribution source is declared only; reviewed source migration is unsupported",
                details={"evidence_id": evidence_id},
            )
        binding_rows = state_view.context_rows("evidence_source_bindings", "evidence_id", evidence_id) if state_view is not None else []
        binding = binding_rows[0] if binding_rows else self.source_binding(evidence_id)
        existing = binding.get("source_platform_id") == new_platform_id and binding["binding_state"] == "bound"
        after = {"evidence_id": evidence_id, "source_platform_id": new_platform_id, "binding_state": "bound",
                 "source_key": self._source_key(new_platform_id, evidence["kind"], evidence["locator"]),
                 "binding_revision": int(binding["binding_revision"]) + int(not existing), "reason": reason.strip()}
        occupied = state_view.context_rows("evidence_refs", "identity_key", after["source_key"]) if state_view is not None else self.store.rows(
            "SELECT evidence_id FROM evidence_refs WHERE identity_key=?", (after["source_key"],))
        conflict = next((row for row in occupied if row["evidence_id"] != evidence_id), None)
        if conflict and not existing:
            raise EvidenceIdentityConflictError("Reviewed binding target identity is occupied by another Evidence",
                                               details={"evidence_id": evidence_id, "conflicting_evidence_id": conflict["evidence_id"],
                                                        "identity_key": after["source_key"]})
        return {"binding": binding, "evidence": evidence, "after": after, "existing": existing}

    def _reviewed_migrate_source(
        self,
        evidence_id: str,
        new_platform_id: str,
        *,
        reason: str,
        auth: AuthContext,
        changeset_id: str | None = None,
        review_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        auth.require("evidence.resolve")
        preview = self.preview_source_migration(evidence_id, new_platform_id, reason=reason)
        binding, evidence, after = preview["binding"], preview["evidence"], preview["after"]
        if preview["existing"]:
            return {**binding, "existing": True}
        revision = after["binding_revision"]
        timestamp = now()
        with self.store.transaction() as conn:
            occupied = conn.execute(
                "SELECT evidence_id FROM evidence_refs WHERE identity_key=? AND evidence_id<>?",
                (after["source_key"], evidence_id),
            ).fetchone()
            if occupied:
                raise EvidenceIdentityConflictError(
                    "Reviewed binding target identity is occupied by another Evidence",
                    details={
                        "evidence_id": evidence_id,
                        "conflicting_evidence_id": occupied["evidence_id"],
                        "identity_key": after["source_key"],
                    },
                )
            conn.execute(
                "UPDATE evidence_source_bindings SET source_platform_id=?,binding_state='bound',"
                "source_key=?,binding_revision=?,reviewed_at=?,reviewed_by=?,reason=? "
                "WHERE evidence_id=?",
                (
                    new_platform_id,
                    after["source_key"],
                    revision,
                    timestamp,
                    auth.actor_id,
                    f"reviewed source migration: {reason.strip()}",
                    evidence_id,
                ),
            )
            conn.execute(
                "UPDATE evidence_refs SET normalized_locator=?,identity_locator=?,search_locator=?,"
                "locator_identity_version=?,identity_namespace='platform',identity_key=? "
                "WHERE evidence_id=?",
                (
                    search_normalize_locator(evidence["locator"]),
                    identity_locator(evidence["locator"]),
                    search_normalize_locator(evidence["locator"]),
                    LOCATOR_IDENTITY_VERSION,
                    after["source_key"],
                    evidence_id,
                ),
            )
            conn.execute(
                "INSERT INTO evidence_source_binding_events("
                "binding_event_id,evidence_id,before_json,after_json,event_type,reason,actor_id,"
                "run_id,created_at,reviewed_changeset_id,review_ids_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    new_id("binding_event"),
                    evidence_id,
                    canonical_json(binding),
                    canonical_json(after),
                    "source_migrated",
                    reason.strip(),
                    auth.actor_id,
                    auth.run_id,
                    timestamp,
                    changeset_id,
                    canonical_json(sorted(review_ids or [])),
                ),
            )
            conn.execute(
                "UPDATE evidence_attestations SET proof_eligible=0,invalidated_at=?,"
                "invalidation_reason='source platform migrated' WHERE evidence_id=? "
                "AND proof_eligible=1",
                (timestamp, evidence_id),
            )
            conn.execute(
                "UPDATE evidence_requests SET state='expired',lease_until=NULL,updated_at=?,"
                "last_error='source platform migrated' WHERE evidence_id=? "
                "AND state IN ('pending','claimed','running')",
                (timestamp, evidence_id),
            )
            conn.execute(
                "UPDATE evidence_refs SET semantic_revision=semantic_revision+1 WHERE evidence_id=?",
                (evidence_id,),
            )
            verification = self.recalculate(
                evidence_id,
                trigger_object_type="evidence_source_binding",
                trigger_object_id=evidence_id,
                reason=reason.strip(),
                auth=auth,
                conn=conn,
                semantic_change_class="provenance_changed",
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="evidence.source.migrate",
                object_type="evidence_source_binding",
                object_id=evidence_id,
                before_revision=int(binding["binding_revision"]),
                after_revision=revision,
                reason=reason.strip(),
                payload=after,
            )
        return {**after, "verification": verification}

    def preview_identity_resolution(self, operation, *, state_view=None):
        rows = state_view.context_rows("evidence_identity_ambiguities", "ambiguity_id", operation["ambiguity_id"]) if state_view is not None else self.store.rows(
            "SELECT * FROM evidence_identity_ambiguities WHERE ambiguity_id=?", (operation["ambiguity_id"],))
        ambiguity = rows[0] if rows else None
        if not ambiguity:
            raise NotFoundError(f"Evidence identity ambiguity not found: {operation['ambiguity_id']}")
        if ambiguity["state"] != "open":
            return {"ambiguity": ambiguity, "existing": True}
        decision, platform = operation["decision"], operation.get("platform_id")
        evidence_id = ambiguity["evidence_id"]
        evidence = state_view.evidence(evidence_id) if state_view is not None else self.store.row(
            "SELECT * FROM evidence_refs WHERE evidence_id=?", (evidence_id,))
        if not evidence:
            raise NotFoundError(f"Evidence not found: {evidence_id}")
        if evidence.get("declared_source_locator") is not None and decision in {
            "bind_existing_to_platform", "confirm_same_object", "split_future_identity"
        }:
            raise ValidationError(
                "Scoped contribution source is declared only; platform identity resolution is unsupported",
                details={"evidence_id": evidence_id},
            )
        rationale = operation.get("rationale", "")
        if not rationale.strip():
            raise ValidationError("Identity ambiguity resolution requires a rationale")
        if decision == "waive_migration_blocker":
            in_use = state_view.has_current_evidence_use(evidence_id) if state_view is not None else bool(
                self.manager._evidence_publication_impact(evidence_id, include_working=True))
            if in_use:
                raise ValidationError("A published identity ambiguity cannot be waived; resolve its source or future identity")
        result = {"ambiguity": ambiguity, "evidence": evidence, "existing": False}
        if decision in {"bind_existing_to_platform", "confirm_same_object"} and platform:
            result["migration"] = self.preview_source_migration(
                evidence_id, platform, reason=f"identity ambiguity {operation['ambiguity_id']}: {rationale.strip()}", state_view=state_view)
        elif decision == "bind_existing_to_platform":
            raise ValidationError("bind_existing_to_platform requires platform_id")
        elif decision == "split_future_identity":
            locator = operation.get("locator")
            if not platform or locator is None:
                raise ValidationError("split_future_identity requires platform_id and locator")
            if not self.store.row("SELECT 1 FROM platform_sources WHERE platform_id=? AND status='active'", (platform,)):
                raise ValidationError(f"Active platform source not found: {platform}")
            try:
                exact = identity_locator(locator)
                future_key = platform_identity_key(platform, evidence["kind"], exact)
            except (TypeError, ValueError) as exc:
                raise ValidationError(str(exc)) from exc
            occupied = state_view.context_rows("evidence_refs", "identity_key", future_key) if state_view is not None else self.store.rows(
                "SELECT evidence_id FROM evidence_refs WHERE identity_key=?", (future_key,))
            if occupied:
                raise EvidenceIdentityConflictError("Future platform identity is already occupied",
                                                   details={"identity_key": future_key, "conflicting_evidence_id": occupied[0]["evidence_id"]})
            result["future_identity_key"] = future_key
        elif decision == "void_incorrect_reference" and evidence["lifecycle_status"] != "void":
            raise ValidationError("void_incorrect_reference requires the existing void/detach operation first")
        elif decision not in {"confirm_same_object", "void_incorrect_reference", "waive_migration_blocker"}:
            raise ValidationError(f"Unsupported identity ambiguity decision: {decision}")
        return result

    def _reviewed_resolve_identity_ambiguity(
        self,
        ambiguity_id: str,
        *,
        decision: str,
        rationale: str,
        platform_id: str | None,
        locator: str | None,
        auth: AuthContext,
        changeset_id: str,
        review_ids: list[str],
    ) -> dict[str, Any]:
        auth.require("evidence.resolve")
        allowed = {
            "confirm_same_object",
            "bind_existing_to_platform",
            "split_future_identity",
            "void_incorrect_reference",
            "waive_migration_blocker",
        }
        if decision not in allowed:
            raise ValidationError(f"Unsupported identity ambiguity decision: {decision}")
        if not rationale.strip():
            raise ValidationError("Identity ambiguity resolution requires a rationale")
        if len(set(review_ids)) < 2:
            raise PermissionError(
                "Identity ambiguity resolution requires two independent passing reviews"
            )
        self.preview_identity_resolution({"ambiguity_id": ambiguity_id, "decision": decision,
                                          "rationale": rationale, "platform_id": platform_id, "locator": locator})
        ambiguity = self.store.row(
            "SELECT * FROM evidence_identity_ambiguities WHERE ambiguity_id=?",
            (ambiguity_id,),
        )
        if not ambiguity:
            raise NotFoundError(f"Evidence identity ambiguity not found: {ambiguity_id}")
        if ambiguity["state"] != "open":
            return {**ambiguity, "existing": True}
        evidence_id = ambiguity["evidence_id"]
        evidence = self.store.row(
            "SELECT * FROM evidence_refs WHERE evidence_id=?", (evidence_id,)
        )
        if not evidence:
            raise NotFoundError(f"Evidence not found: {evidence_id}")
        publication_impact = self.manager._evidence_publication_impact(
            evidence_id, include_working=True
        )
        if decision == "waive_migration_blocker" and publication_impact:
            raise ValidationError(
                "A published identity ambiguity cannot be waived; resolve its source or future identity"
            )

        action_result: dict[str, Any] = {}
        if decision in {"bind_existing_to_platform", "confirm_same_object"} and platform_id:
            action_result = self._reviewed_migrate_source(
                evidence_id,
                platform_id,
                reason=f"identity ambiguity {ambiguity_id}: {rationale.strip()}",
                auth=auth,
                changeset_id=changeset_id,
                review_ids=review_ids,
            )
        elif decision == "bind_existing_to_platform":
            raise ValidationError("bind_existing_to_platform requires platform_id")
        elif decision == "split_future_identity":
            if not platform_id or locator is None:
                raise ValidationError("split_future_identity requires platform_id and locator")
            if not self.store.row(
                "SELECT 1 FROM platform_sources WHERE platform_id=? AND status='active'",
                (platform_id,),
            ):
                raise ValidationError(f"Active platform source not found: {platform_id}")
            try:
                exact = identity_locator(locator)
                search = search_normalize_locator(locator)
            except (TypeError, ValueError) as exc:
                raise ValidationError(str(exc)) from exc
            future_key = platform_identity_key(platform_id, evidence["kind"], exact)
            occupied = self.store.row(
                "SELECT evidence_id FROM evidence_refs WHERE identity_key=?", (future_key,)
            )
            if occupied:
                raise EvidenceIdentityConflictError(
                    "Future platform identity is already occupied",
                    details={
                        "identity_key": future_key,
                        "conflicting_evidence_id": occupied["evidence_id"],
                    },
                )
            new_evidence_id = new_id("ev")
            timestamp = now()
            with self.store.transaction() as conn:
                binding_value = conn.execute(
                    "SELECT * FROM evidence_source_bindings WHERE evidence_id=?",
                    (evidence_id,),
                ).fetchone()
                binding = dict(binding_value) if binding_value else {}
                conn.execute(
                    "UPDATE evidence_refs SET identity_namespace='conflict',identity_key=?,"
                    "semantic_revision=semantic_revision+1,verification_state='conflict' "
                    "WHERE evidence_id=?",
                    (conflict_identity_key(evidence_id), evidence_id),
                )
                if binding:
                    conn.execute(
                        "UPDATE evidence_source_bindings SET binding_state='binding_conflict',"
                        "source_key=NULL,binding_revision=binding_revision+1,reviewed_at=?,"
                        "reviewed_by=?,reason=? WHERE evidence_id=?",
                        (
                            timestamp,
                            auth.actor_id,
                            f"future identity split: {rationale.strip()}",
                            evidence_id,
                        ),
                    )
                conn.execute(
                    "INSERT INTO evidence_refs("
                    "evidence_id,kind,locator,normalized_locator,identity_locator,search_locator,"
                    "locator_identity_version,identity_key,identity_namespace,target_scope,"
                    "short_description,quality_status,content_hash,lifecycle_status,created_at,"
                    "created_by,verification_level,verification_state,mutable_source,"
                    "semantic_revision,current_manifest_id,current_proof_id) "
                    "VALUES (?,?,?,?,?,?,?,?,'platform',?,?, 'unknown',NULL,'active',?,?,"
                    "'declared','active',0,0,NULL,NULL)",
                    (
                        new_evidence_id,
                        evidence["kind"],
                        locator,
                        search,
                        exact,
                        search,
                        LOCATOR_IDENTITY_VERSION,
                        future_key,
                        evidence.get("target_scope"),
                        f"future identity split from {evidence_id}",
                        timestamp,
                        auth.actor_id,
                    ),
                )
                conn.execute(
                    "INSERT INTO evidence_source_bindings("
                    "evidence_id,source_platform_id,binding_state,source_key,binding_revision,"
                    "created_at,created_by,reviewed_at,reviewed_by,reason) "
                    "VALUES (?,?,'bound',?,1,?,?,?,?,?)",
                    (
                        new_evidence_id,
                        platform_id,
                        future_key,
                        timestamp,
                        auth.actor_id,
                        timestamp,
                        auth.actor_id,
                        f"reviewed future identity split: {rationale.strip()}",
                    ),
                )
                conn.execute(
                    "INSERT INTO evidence_source_binding_events("
                    "binding_event_id,evidence_id,before_json,after_json,event_type,reason,"
                    "actor_id,run_id,created_at,reviewed_changeset_id,review_ids_json) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        new_id("binding_event"),
                        new_evidence_id,
                        canonical_json({}),
                        canonical_json(
                            {
                                "evidence_id": new_evidence_id,
                                "source_platform_id": platform_id,
                                "binding_state": "bound",
                                "source_key": future_key,
                                "binding_revision": 1,
                            }
                        ),
                        "source_declared",
                        rationale.strip(),
                        auth.actor_id,
                        auth.run_id,
                        timestamp,
                        changeset_id,
                        canonical_json(sorted(set(review_ids))),
                    ),
                )
                self.recalculate(
                    evidence_id,
                    trigger_object_type="evidence_identity_ambiguity",
                    trigger_object_id=ambiguity_id,
                    reason=rationale.strip(),
                    auth=auth,
                    conn=conn,
                    semantic_change_class="provenance_changed",
                )
                self.recalculate(
                    new_evidence_id,
                    trigger_object_type="evidence_identity_ambiguity",
                    trigger_object_id=ambiguity_id,
                    reason="initial declared future identity proof",
                    auth=auth,
                    conn=conn,
                    semantic_change_class="initial",
                )
            action_result = {
                "historical_evidence_id": evidence_id,
                "future_evidence_id": new_evidence_id,
                "future_identity_key": future_key,
            }
        elif decision == "void_incorrect_reference" and evidence["lifecycle_status"] != "void":
            raise ValidationError(
                "void_incorrect_reference requires the existing void/detach operation first"
            )

        state = "waived" if decision == "waive_migration_blocker" else "resolved"
        timestamp = now()
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE evidence_identity_ambiguities SET state=?,rationale=?,resolved_at=?,"
                "resolved_by=?,reviewed_changeset_id=?,review_ids_json=? "
                "WHERE ambiguity_id=? AND state='open'",
                (
                    state,
                    rationale.strip(),
                    timestamp,
                    auth.actor_id,
                    changeset_id,
                    canonical_json(sorted(set(review_ids))),
                    ambiguity_id,
                ),
            )
            result = {
                "ambiguity_id": ambiguity_id,
                "evidence_id": evidence_id,
                "decision": decision,
                "state": state,
                "rationale": rationale.strip(),
                "reviewed_changeset_id": changeset_id,
                "review_ids": sorted(set(review_ids)),
                "action": action_result,
            }
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="evidence.identity_ambiguity.resolve",
                object_type="evidence_identity_ambiguity",
                object_id=ambiguity_id,
                before_revision=0,
                after_revision=1,
                reason=rationale.strip(),
                payload=result,
            )
        return result

    def preview_conflict_resolution(
        self,
        evidence_id: str,
        *,
        accepted_attestation_ids: list[str],
        retained_attestation_ids: list[str],
        rejected_attestation_ids: list[str],
        rationale: str,
        state_view=None,
    ) -> dict[str, Any]:
        if not rationale.strip():
            raise ValidationError("Conflict resolution requires reviewer rationale")
        evidence = state_view.evidence(evidence_id) if state_view is not None else self.store.row(
            "SELECT current_manifest_id FROM evidence_refs WHERE evidence_id=?",
            (evidence_id,),
        )
        binding_rows = state_view.context_rows("evidence_source_bindings", "evidence_id", evidence_id) if state_view is not None else []
        binding = binding_rows[0] if binding_rows else self.source_binding(evidence_id)
        if not evidence or not evidence.get("current_manifest_id") or not binding.get(
            "source_platform_id"
        ):
            raise ValidationError("Conflict resolution requires a bound current Manifest")
        manifest = self.store.row(
            "SELECT manifest_hash FROM evidence_manifests WHERE manifest_id=?",
            (evidence["current_manifest_id"],),
        )
        if not manifest:
            raise ValidationError("Conflict resolution current Manifest is missing")
        referenced = sorted(
            set(accepted_attestation_ids)
            | set(retained_attestation_ids)
            | set(rejected_attestation_ids)
        )
        if not referenced:
            raise ValidationError("Conflict resolution must reference Attestation IDs")
        placeholders = ",".join("?" for _ in referenced)
        rows = [row for row in state_view.context_rows("evidence_attestations", "evidence_id", evidence_id)
                if row["attestation_id"] in referenced] if state_view is not None else self.store.rows(
            f"SELECT attestation_id,state FROM evidence_attestations WHERE evidence_id=? "
            f"AND attestation_id IN ({placeholders})",
            (evidence_id, *referenced),
        )
        if {row["attestation_id"] for row in rows} != set(referenced):
            raise ValidationError("Conflict resolution references an Attestation from another Evidence")
        if not any(row["state"] == "conflict" for row in rows):
            raise ValidationError("Conflict resolution must include a conflict Attestation")
        result = {
            "accepted_attestation_ids": sorted(set(accepted_attestation_ids)),
            "retained_attestation_ids": sorted(set(retained_attestation_ids)),
            "rejected_attestation_ids": sorted(set(rejected_attestation_ids)),
            "resolved_attestation_ids": referenced,
            "rationale": rationale.strip(),
        }
        result_hash = hashlib.sha256(canonical_json(result).encode("utf-8")).hexdigest()
        return {"evidence": evidence, "binding": binding, "manifest": manifest, "referenced": referenced,
                "result": result, "result_hash": result_hash}

    def _reviewed_resolve_conflict(
        self, evidence_id: str, *, accepted_attestation_ids: list[str], retained_attestation_ids: list[str],
        rejected_attestation_ids: list[str], rationale: str, auth: AuthContext,
    ) -> dict[str, Any]:
        auth.require("evidence.resolve")
        preview = self.preview_conflict_resolution(
            evidence_id, accepted_attestation_ids=accepted_attestation_ids, retained_attestation_ids=retained_attestation_ids,
            rejected_attestation_ids=rejected_attestation_ids, rationale=rationale)
        evidence, binding, manifest = preview["evidence"], preview["binding"], preview["manifest"]
        referenced, result, result_hash = preview["referenced"], preview["result"], preview["result_hash"]
        attestation_id = new_id("attestation")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO evidence_attestations("
                "attestation_id,evidence_id,manifest_id,attestation_type,platform_id,actor_id,"
                "run_id,method,input_snapshot_json,result_json,result_hash,artifact_ids_json,"
                "analysis_run_id,state,created_at,supersedes_attestation_id,attestation_role,"
                "qualified_manifest_id,qualified_manifest_hash,proof_eligible,invalidated_at,"
                "invalidation_reason) VALUES (?,?,?,'metadata',?,?,?,'reviewed-resolution',"
                "?,?,?,?,NULL,'valid',?,NULL,'resolution',?,?,1,NULL,NULL)",
                (
                    attestation_id,
                    evidence_id,
                    evidence["current_manifest_id"],
                    binding["source_platform_id"],
                    auth.actor_id,
                    auth.run_id,
                    canonical_json({"resolved_attestation_ids": referenced}),
                    canonical_json(result),
                    result_hash,
                    canonical_json([]),
                    now(),
                    evidence["current_manifest_id"],
                    manifest["manifest_hash"],
                ),
            )
            verification = self.recalculate(
                evidence_id,
                trigger_object_type="evidence_attestation",
                trigger_object_id=attestation_id,
                reason=rationale.strip(),
                auth=auth,
                conn=conn,
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="evidence.conflict.resolve",
                object_type="evidence_attestation",
                object_id=attestation_id,
                before_revision=None,
                after_revision=1,
                reason=rationale.strip(),
                payload=result,
            )
        return {
            "attestation_id": attestation_id,
            "attestation_role": "resolution",
            "result_hash": result_hash,
            "verification": verification,
        }

    def _valid_reproduction(
        self, row: dict[str, Any], manifest: dict[str, Any] | None = None
    ) -> bool:
        analysis_run_id = row.get("analysis_run_id")
        if not analysis_run_id:
            return False
        run = self.store.row(
            "SELECT * FROM analysis_runs WHERE analysis_run_id=?", (analysis_run_id,)
        )
        if (
            not run
            or run["state"] != "frozen"
            or run.get("platform_id") != row.get("platform_id")
        ):
            return False
        if manifest:
            pinned = _json(run.get("input_manifest_hashes_json"), {}).get(
                row["evidence_id"], {}
            )
            if (
                pinned.get("manifest_id") != manifest["manifest_id"]
                or pinned.get("manifest_hash") != manifest["manifest_hash"]
            ):
                return False
        inputs = self.store.rows(
            "SELECT input_type,input_id FROM analysis_inputs WHERE analysis_run_id=?",
            (analysis_run_id,),
        )
        if not any(
            item["input_type"] == "evidence" and item["input_id"] == row["evidence_id"]
            for item in inputs
        ):
            return False
        method = self.store.row(
            "SELECT * FROM analysis_methods WHERE method_id=?", (run["method_id"],)
        )
        if not method or method.get("platform_id") != run.get("platform_id"):
            return False
        try:
            script = self.manager.artifacts.require_platform_artifact(
                method["script_artifact_id"], run["platform_id"]
            )
        except (ValidationError, PermissionError, NotFoundError):
            return False
        if script["sha256"] != method["source_hash"]:
            return False
        outputs = self.store.rows(
            "SELECT a.artifact_id,a.role FROM analysis_outputs o JOIN artifacts a "
            "ON a.artifact_id=o.artifact_id WHERE o.analysis_run_id=?",
            (analysis_run_id,),
        )
        return bool(outputs) and all(
            output["role"] == "frozen"
            and self.manager.artifacts.verify(output["artifact_id"])["ok"]
            and run["platform_id"]
            in self.manager.artifacts.artifact_platforms(output["artifact_id"])
            for output in outputs
        )

    def _proof_snapshot(
        self, evidence_id: str, *, evidence: dict[str, Any] | None = None, binding: dict[str, Any] | None = None,
        state_view=None,
    ) -> dict[str, Any]:
        evidence = evidence or (state_view.evidence(evidence_id) if state_view is not None else None) or self.store.row(
            "SELECT * FROM evidence_refs WHERE evidence_id=?", (evidence_id,)
        )
        if not evidence:
            raise NotFoundError(f"Evidence not found: {evidence_id}")
        binding_rows = state_view.context_rows("evidence_source_bindings", "evidence_id", evidence_id) if state_view is not None else []
        binding = binding if binding is not None else (binding_rows[0] if binding_rows else self.store.row(
            "SELECT * FROM evidence_source_bindings WHERE evidence_id=?", (evidence_id,)
        ))
        manifest = None
        if evidence.get("current_manifest_id"):
            manifest = self.store.row(
                "SELECT * FROM evidence_manifests WHERE manifest_id=?",
                (evidence["current_manifest_id"],),
            )
        attestations = sorted(
            (row for row in state_view.context_rows("evidence_attestations", "evidence_id", evidence_id)
             if row["state"] in {"valid", "conflict"}), key=lambda row: (row["created_at"], row["attestation_id"])
        ) if state_view is not None else self.store.rows(
            "SELECT * FROM evidence_attestations WHERE evidence_id=? "
            "AND state IN ('valid','conflict') ORDER BY created_at,attestation_id",
            (evidence_id,),
        )
        current = [
            row
            for row in attestations
            if bool(row.get("proof_eligible"))
            and manifest is not None
            and row.get("qualified_manifest_id") == manifest["manifest_id"]
            and row.get("qualified_manifest_hash") == manifest["manifest_hash"]
        ]
        source_platform = binding.get("source_platform_id") if binding else None
        source_rows = [
            row
            for row in current
            if row["state"] == "valid"
            and row.get("attestation_role") == "source"
            and row["platform_id"] == source_platform
        ]
        independent_rows = [
            row
            for row in current
            if row["state"] == "valid"
            and row.get("attestation_role") == "independent"
            and row["platform_id"] != source_platform
        ]
        resolution_rows = [
            row
            for row in current
            if row["state"] == "valid" and row.get("attestation_role") == "resolution"
        ]
        resolved_attestation_ids: set[str] = set()
        for row in resolution_rows:
            resolution = _json(row["result_json"], {})
            for field in (
                "accepted_attestation_ids",
                "retained_attestation_ids",
                "rejected_attestation_ids",
                "resolved_attestation_ids",
            ):
                resolved_attestation_ids.update(str(item) for item in resolution.get(field, []))
        proof_rows = source_rows + independent_rows
        source_verified = any(
            row["attestation_type"] in ATTESTATION_TYPES
            and bool(_json(row["result_json"], {}).get("exists", True))
            for row in source_rows
        )
        immutable_identity = False
        if manifest:
            identity = _json(manifest["content_identity_json"], {})
            immutable_identity = bool(identity.get("digest") or identity.get("immutable_revision"))

        artifact_snapshots: list[dict[str, Any]] = []
        frozen_snapshot = False
        seen_artifacts: set[tuple[str, str]] = set()
        for row in proof_rows:
            for artifact_id in _json(row["artifact_ids_json"], []):
                key = (row["attestation_id"], artifact_id)
                if key in seen_artifacts:
                    continue
                seen_artifacts.add(key)
                artifact = self.store.row(
                    "SELECT artifact_id,sha256,size,role FROM artifacts WHERE artifact_id=?",
                    (artifact_id,),
                )
                owners = (
                    self.manager.artifacts.artifact_platforms(artifact_id) if artifact else []
                )
                verified = bool(artifact and self.manager.artifacts.verify(artifact_id)["ok"])
                eligible = bool(
                    artifact
                    and artifact["role"] == "frozen"
                    and verified
                    and row["platform_id"] in owners
                )
                artifact_snapshots.append(
                    {
                        "artifact_id": artifact_id,
                        "sha256": artifact.get("sha256") if artifact else None,
                        "size": artifact.get("size") if artifact else None,
                        "role": artifact.get("role") if artifact else None,
                        "platform_id": row["platform_id"],
                        "owners": owners,
                        "verified": verified,
                        "eligible": eligible,
                        "attestation_id": row["attestation_id"],
                    }
                )
                if row["attestation_type"] in {"content", "snapshot", "reproduction"}:
                    frozen_snapshot = frozen_snapshot or eligible

        analysis_snapshots: list[dict[str, Any]] = []
        reproduction = False
        for row in proof_rows:
            if row["attestation_type"] != "reproduction":
                continue
            valid = self._valid_reproduction(row, manifest)
            run = self.store.row(
                "SELECT analysis_run_id,method_id,state,platform_id,input_manifest_hashes_json "
                "FROM analysis_runs WHERE analysis_run_id=?",
                (row.get("analysis_run_id"),),
            )
            analysis_snapshots.append(
                {
                    "analysis_run_id": row.get("analysis_run_id"),
                    "method_id": run.get("method_id") if run else None,
                    "state": run.get("state") if run else None,
                    "platform_id": run.get("platform_id") if run else None,
                    "input_manifests": _json(
                        run.get("input_manifest_hashes_json") if run else None, {}
                    ),
                    "attestation_id": row["attestation_id"],
                    "eligible": valid,
                }
            )
            reproduction = reproduction or valid

        level = "declared"
        reasons: list[str] = []
        binding_active = bool(
            binding
            and binding["binding_state"] in {"bound", "inferred"}
            and source_platform
        )
        manifest_coherent = bool(
            manifest and binding_active and manifest["platform_id"] == source_platform
        )
        if not binding_active:
            reasons.append("source_binding_missing_or_inactive")
        if binding_active and not manifest_coherent:
            reasons.append("current_manifest_platform_mismatch")
        if source_verified and manifest_coherent:
            level = "source_verified"
        else:
            reasons.append("current_source_attestation_missing")
        if level == "source_verified" and (immutable_identity or frozen_snapshot):
            level = "snapshot_verified"
        elif level == "source_verified":
            reasons.append("immutable_snapshot_missing")
        if level in {"source_verified", "snapshot_verified"} and reproduction:
            level = "reproduced"

        legacy_source_conflicts = [
            row
            for row in attestations
            if row["state"] == "conflict"
            and row["platform_id"] == source_platform
            and row.get("attestation_role") == "source"
            and row.get("qualified_manifest_id") is None
        ]
        conflicts = [
            row
            for row in current
            if row["state"] == "conflict"
            and row["attestation_id"] not in resolved_attestation_ids
        ] + [
            row
            for row in legacy_source_conflicts
            if row["attestation_id"] not in resolved_attestation_ids
        ]
        unavailable = any(
            row["attestation_type"] == "existence"
            and not bool(_json(row["result_json"], {}).get("exists", True))
            for row in source_rows
        )
        request = next((row for row in state_view.context_rows("evidence_requests", "evidence_id", evidence_id)
                        if row["state"] in {"pending", "claimed", "running"}), None) if state_view is not None else self.store.row(
            "SELECT state FROM evidence_requests WHERE evidence_id=? "
            "AND state IN ('pending','claimed','running') LIMIT 1",
            (evidence_id,),
        )
        if evidence["lifecycle_status"] != "active":
            state = "superseded"
        elif conflicts:
            state = "conflict"
            reasons.append("blocking_conflict")
        elif unavailable:
            state = "unavailable"
            reasons.append("source_unavailable")
        elif request:
            state = "verification_requested"
        else:
            state = "active"
        return {
            "format": "evidence-proof-v1",
            "evidence_id": evidence_id,
            "semantic_revision": int(evidence.get("semantic_revision", 0)),
            "manifest": {
                "manifest_id": manifest.get("manifest_id") if manifest else None,
                "manifest_hash": manifest.get("manifest_hash") if manifest else None,
                "semantic_fingerprint": manifest.get("semantic_fingerprint") if manifest else None,
                "platform_id": manifest.get("platform_id") if manifest else None,
            },
            "source_binding": {
                "source_platform_id": source_platform,
                "binding_state": binding.get("binding_state") if binding else "legacy_unbound",
                "binding_revision": binding.get("binding_revision") if binding else 0,
            },
            "verification_level": level,
            "verification_state": state,
            "source_attestations": [
                {
                    "attestation_id": row["attestation_id"],
                    "result_hash": row["result_hash"],
                    "type": row["attestation_type"],
                    "role": row["attestation_role"],
                    "platform_id": row["platform_id"],
                    "manifest_id": row["qualified_manifest_id"],
                    "manifest_hash": row["qualified_manifest_hash"],
                }
                for row in source_rows
            ],
            "independent_attestations": [
                {
                    "attestation_id": row["attestation_id"],
                    "result_hash": row["result_hash"],
                    "type": row["attestation_type"],
                    "role": row["attestation_role"],
                    "platform_id": row["platform_id"],
                    "manifest_id": row["qualified_manifest_id"],
                    "manifest_hash": row["qualified_manifest_hash"],
                }
                for row in independent_rows
            ],
            "resolution_attestations": [
                {
                    "attestation_id": row["attestation_id"],
                    "result_hash": row["result_hash"],
                    "type": row["attestation_type"],
                    "role": row["attestation_role"],
                    "platform_id": row["platform_id"],
                    "manifest_id": row["qualified_manifest_id"],
                    "manifest_hash": row["qualified_manifest_hash"],
                    "resolved_attestation_ids": sorted(resolved_attestation_ids),
                }
                for row in resolution_rows
            ],
            "conflict_attestation_ids": sorted(row["attestation_id"] for row in conflicts),
            "artifact_snapshots": artifact_snapshots,
            "analysis_run_snapshots": analysis_snapshots,
            "reason_codes": sorted(set(reasons)),
            "policy_version": self.manager.policy.version,
        }

    def recalculate(
        self,
        evidence_id: str,
        *,
        trigger_object_type: str,
        trigger_object_id: str,
        reason: str,
        auth: AuthContext,
        conn: sqlite3.Connection | None = None,
        semantic_change_class: str | None = None,
        _allocated_proof_id: str | None = None,
    ) -> dict[str, str]:
        evidence = self.store.row("SELECT * FROM evidence_refs WHERE evidence_id=?", (evidence_id,))
        if not evidence:
            raise NotFoundError(f"Evidence not found: {evidence_id}")
        before = {
            "level": evidence.get("verification_level", "declared"),
            "state": evidence.get("verification_state", "active"),
        }
        snapshot = self._proof_snapshot(evidence_id, evidence=evidence)
        after = {
            "level": snapshot["verification_level"],
            "state": snapshot["verification_state"],
        }
        level = after["level"]
        state = after["state"]
        transaction = self.store.transaction() if conn is None else nullcontext(conn)
        with transaction as active:
            old_proof_id = evidence.get("current_proof_id")
            old_proof = (
                self.store.row(
                    "SELECT proof_hash FROM evidence_proofs WHERE proof_id=?", (old_proof_id,)
                )
                if old_proof_id
                else None
            )
            proof_json = canonical_json(snapshot)
            proof_hash = hashlib.sha256(proof_json.encode("utf-8")).hexdigest()
            proof_changed = not old_proof or old_proof["proof_hash"] != proof_hash
            semantic_revision = int(evidence.get("semantic_revision", 0))
            from_semantic_revision = (
                max(0, semantic_revision - 1)
                if semantic_change_class
                else semantic_revision
            )
            if proof_changed and semantic_change_class is None:
                semantic_revision += 1
                snapshot["semantic_revision"] = semantic_revision
                proof_json = canonical_json(snapshot)
                proof_hash = hashlib.sha256(proof_json.encode("utf-8")).hexdigest()
            proof_id = old_proof_id
            if proof_changed:
                proof_id = _allocated_proof_id or new_id("proof")
                active.execute(
                    "INSERT INTO evidence_proofs("
                    "proof_id,evidence_id,semantic_revision,manifest_id,manifest_hash,"
                    "source_platform_id,verification_level,verification_state,"
                    "source_attestation_ids_json,independent_attestation_ids_json,"
                    "artifact_snapshots_json,analysis_run_snapshots_json,reason_codes_json,"
                    "policy_version,proof_json,proof_hash,supersedes_proof_id,created_at,created_by) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        proof_id,
                        evidence_id,
                        semantic_revision,
                        snapshot["manifest"]["manifest_id"],
                        snapshot["manifest"]["manifest_hash"],
                        snapshot["source_binding"]["source_platform_id"],
                        level,
                        state,
                        canonical_json(
                            [row["attestation_id"] for row in snapshot["source_attestations"]]
                            + [
                                row["attestation_id"]
                                for row in snapshot["resolution_attestations"]
                            ]
                        ),
                        canonical_json(
                            [
                                row["attestation_id"]
                                for row in snapshot["independent_attestations"]
                            ]
                        ),
                        canonical_json(snapshot["artifact_snapshots"]),
                        canonical_json(snapshot["analysis_run_snapshots"]),
                        canonical_json(snapshot["reason_codes"]),
                        self.manager.policy.version,
                        proof_json,
                        proof_hash,
                        old_proof_id,
                        now(),
                        auth.actor_id,
                    ),
                )
            active.execute(
                "UPDATE evidence_refs SET verification_level=?,verification_state=?,"
                "current_proof_id=?,semantic_revision=? "
                "WHERE evidence_id=?",
                (level, state, proof_id, semantic_revision, evidence_id),
            )
            if before != after:
                active.execute(
                    "INSERT INTO evidence_verification_events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        new_id("verification_event"),
                        evidence_id,
                        "effective_verification_changed",
                        canonical_json(before),
                        canonical_json(after),
                        trigger_object_type,
                        trigger_object_id,
                        reason,
                        auth.actor_id,
                        auth.run_id,
                        now(),
                    ),
                )
            if proof_changed:
                severity = {
                    "none": 0,
                    "notify": 1,
                    "impact_review": 2,
                    "stale": 3,
                    "blocked": 4,
                }
                transition_class, proof_impact, proof_reasons = (
                    self._classify_proof_transition(before, after)
                )
                manifest_impact, manifest_reasons = self._manifest_default_impact(
                    semantic_change_class
                )
                impact_class = max(
                    (manifest_impact, proof_impact), key=lambda value: severity[value]
                )
                publication_impact = self.manager._evidence_publication_impact(
                    evidence_id,
                    include_working=True,
                    manifest_change_class=semantic_change_class,
                    before_proof=before,
                    after_proof=after,
                )
                if publication_impact and severity[publication_impact["max_impact"]] > severity[
                    impact_class
                ]:
                    impact_class = publication_impact["max_impact"]
                semantic_event_id = new_id("semantic_event")
                cause = {
                    "manifest_change_class": semantic_change_class,
                    "proof_transition": transition_class,
                    "before_level": before["level"],
                    "after_level": after["level"],
                    "before_state": before["state"],
                    "after_state": after["state"],
                    "selected_impact": impact_class,
                    "reason_codes": sorted(set(manifest_reasons + proof_reasons)),
                }
                if semantic_change_class or semantic_revision != from_semantic_revision:
                    active.execute(
                        "INSERT INTO evidence_semantic_events("
                        "semantic_event_id,evidence_id,from_semantic_revision,to_semantic_revision,"
                        "event_type,trigger_object_type,trigger_object_id,before_proof_id,"
                        "after_proof_id,impact_class,reason,created_at,cause_json) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            semantic_event_id,
                            evidence_id,
                            from_semantic_revision,
                            semantic_revision,
                            "manifest_changed"
                            if semantic_change_class
                            else "proof_changed",
                            trigger_object_type,
                            trigger_object_id,
                            old_proof_id,
                            proof_id,
                            impact_class,
                            reason,
                            now(),
                            canonical_json(cause),
                        ),
                    )
                if publication_impact:
                    if publication_impact["max_impact"] in {
                        "impact_review",
                        "stale",
                        "blocked",
                    }:
                        self.manager._mark_evidence_impact(
                            active,
                            publication_impact,
                            evidence_id,
                            impact_class="per_conclusion",
                        )
                    for item in publication_impact["issues"]:
                        active.execute(
                            "INSERT INTO evidence_publication_impacts("
                            "publication_impact_id,semantic_event_id,evidence_id,issue_id,"
                            "conclusion_id,conclusion_status,issue_type,use_role,stored_proof_id,"
                            "stored_proof_hash,current_proof_id,current_proof_hash,"
                            "selected_freshness,refresh_reason,priority,created_at) "
                            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (
                                new_id("publication_impact"),
                                semantic_event_id,
                                evidence_id,
                                item["issue_id"],
                                item["conclusion_id"],
                                item["conclusion_status"],
                                item["issue_type"],
                                item["use_role"],
                                item["stored_proof_id"],
                                item["stored_proof_hash"],
                                item["current_proof_id"],
                                item["current_proof_hash"],
                                item["selected_freshness"],
                                item.get("refresh_reason"),
                                int(item["priority"]),
                                now(),
                            ),
                        )
                self.manager.evidence_relations.propagate_change(
                    evidence_id,
                    source_event_type="evidence_semantic_change",
                    source_event_id=semantic_event_id,
                    conn=active,
                )
        return after

    def expected(
        self, evidence_id: str, *, evidence: dict[str, Any] | None = None
    ) -> dict[str, str]:
        """Compute effective verification exclusively from persisted Manager objects."""
        evidence = evidence or self.store.row(
            "SELECT * FROM evidence_refs WHERE evidence_id=?", (evidence_id,)
        )
        if not evidence:
            raise NotFoundError(f"Evidence not found: {evidence_id}")
        snapshot = self._proof_snapshot(evidence_id, evidence=evidence)
        return {
            "level": snapshot["verification_level"],
            "state": snapshot["verification_state"],
        }

    @staticmethod
    def _quality(value: str) -> str:
        return "invalid" if value == "unusable_for_purpose" else value

    def show(self, evidence_id: str, *, auth: AuthContext | None = None) -> dict[str, Any]:
        if auth is not None:
            self.require_read_access(evidence_id, auth)
        evidence = self.store.row("SELECT * FROM evidence_refs WHERE evidence_id=?", (evidence_id,))
        if not evidence:
            raise NotFoundError(f"Evidence not found: {evidence_id}")
        evidence["quality_status"] = self._quality(evidence["quality_status"])
        evidence["mutable_source"] = bool(evidence.get("mutable_source"))
        evidence["identity_algorithm"] = IDENTITY_ALGORITHM
        if evidence.get("declared_source_locator") is not None:
            evidence["source_locator"] = evidence["declared_source_locator"]
            evidence["locator_role"] = "internal_identity"
        else:
            evidence["source_locator"] = evidence["locator"]
            evidence["locator_role"] = "source"
        privileged = auth is None or (
            not auth.platform_id
            and auth.actor_kind
            in {"organizer_agent", "review_agent", "maintenance_agent"}
        )
        platform_id = auth.platform_id if auth else None
        evidence["manifests"] = self.manifests(
            evidence_id,
            platform_id=None if privileged else platform_id or "__public__",
            include_current=True,
        )
        evidence["attestations"] = self.attestations(
            evidence_id,
            platform_id=None if privileged else platform_id or "__public__",
        )
        evidence["requests"] = (
            self.manager.evidence_requests.list_for_evidence(
                evidence_id, platform_id=platform_id
            )
            if platform_id
            else (
                self.manager.evidence_requests.list_for_evidence(evidence_id)
                if privileged
                else []
            )
        )
        evidence["source_binding"] = self.store.row(
            "SELECT * FROM evidence_source_bindings WHERE evidence_id=?", (evidence_id,)
        )
        evidence["source_platform_id"] = (
            evidence["source_binding"].get("source_platform_id")
            if evidence["source_binding"]
            else None
        )
        evidence["identity_ambiguities"] = []
        if privileged:
            evidence["identity_ambiguities"] = self.store.rows(
                "SELECT * FROM evidence_identity_ambiguities WHERE evidence_id=? "
                "ORDER BY created_at,ambiguity_id",
                (evidence_id,),
            )
            for ambiguity in evidence["identity_ambiguities"]:
                ambiguity["candidate"] = _json(ambiguity.pop("candidate_json"), {})
                ambiguity["review_ids"] = _json(
                    ambiguity.pop("review_ids_json"), []
                )
        evidence["current_proof"] = (
            self.store.row(
                "SELECT proof_id,proof_hash,semantic_revision,manifest_id,manifest_hash,"
                "source_platform_id,verification_level,verification_state,reason_codes_json,"
                "policy_version,created_at FROM evidence_proofs WHERE proof_id=?",
                (evidence.get("current_proof_id"),),
            )
            if evidence.get("current_proof_id")
            else None
        )
        if evidence["current_proof"]:
            evidence["current_proof"]["reason_codes"] = _json(
                evidence["current_proof"].pop("reason_codes_json"), []
            )
        evidence["issue_ids"] = self._issue_ids(evidence_id)
        evidence["conclusion_uses"] = self.store.rows(
            "SELECT * FROM conclusion_evidence_uses WHERE evidence_id=? ORDER BY conclusion_id,use_role",
            (evidence_id,),
        )
        evidence["verification_events"] = self.store.rows(
            "SELECT * FROM evidence_verification_events WHERE evidence_id=? ORDER BY created_at",
            (evidence_id,),
        )
        evidence["semantic_events"] = self.store.rows(
            "SELECT * FROM evidence_semantic_events WHERE evidence_id=? ORDER BY created_at",
            (evidence_id,),
        )
        return evidence

    def manifests(
        self,
        evidence_id: str,
        *,
        platform_id: str | None = None,
        include_current: bool = False,
    ) -> list[dict[str, Any]]:
        where = "evidence_id=?"
        params: tuple[Any, ...] = (evidence_id,)
        if platform_id is not None:
            if include_current:
                where += (
                    " AND (platform_id=? OR manifest_id=(SELECT current_manifest_id "
                    "FROM evidence_refs WHERE evidence_id=?))"
                )
                params += (platform_id, evidence_id)
            else:
                where += " AND platform_id=?"
                params += (platform_id,)
        rows = self.store.rows(
            f"SELECT * FROM evidence_manifests WHERE {where} ORDER BY manifest_revision",
            params,
        )
        for row in rows:
            row["manifest"] = _json(row.pop("manifest_json"), {})
            for source, target in (
                ("content_identity_json", "content_identity"),
                ("data_profile_json", "data_profile"),
                ("execution_json", "execution"),
                ("summary_json", "summary"),
            ):
                row[target] = _json(row.pop(source), {})
        return rows

    def attestations(
        self, evidence_id: str, *, platform_id: str | None = None
    ) -> list[dict[str, Any]]:
        where = "evidence_id=?"
        params: tuple[Any, ...] = (evidence_id,)
        if platform_id is not None:
            where += " AND platform_id=?"
            params += (platform_id,)
        rows = self.store.rows(
            f"SELECT * FROM evidence_attestations WHERE {where} "
            "ORDER BY created_at,attestation_id",
            params,
        )
        for row in rows:
            row["input_snapshot"] = _json(row.pop("input_snapshot_json"), {})
            row["result"] = _json(row.pop("result_json"), {})
            row["artifact_ids"] = _json(row.pop("artifact_ids_json"), [])
        return rows

    def _issue_ids(
        self, evidence_id: str, conn: sqlite3.Connection | None = None
    ) -> list[str]:
        active = conn or self.store.conn
        return [
            row[0]
            for row in active.execute(
                "SELECT issue_id FROM issue_evidence WHERE evidence_id=? ORDER BY issue_id",
                (evidence_id,),
            ).fetchall()
        ]

    @staticmethod
    def _activity(
        conn: sqlite3.Connection,
        activity_type: str,
        object_type: str,
        object_id: str,
        issue_ids: list[str],
        summary: dict[str, Any],
        *,
        platform_id: str | None = None,
    ) -> int:
        cursor = conn.execute(
            "INSERT INTO activity_events(activity_type,object_type,object_id,issue_ids_json,"
            "platform_id,summary_json,created_at) VALUES (?,?,?,?,?,?,?)",
            (
                activity_type,
                object_type,
                object_id,
                canonical_json(sorted(set(issue_ids))),
                platform_id,
                canonical_json(summary),
                now(),
            ),
        )
        return int(cursor.lastrowid or 0)
