"""Simulate legacy Evidence creation without writing facts or signing proofs."""

from __future__ import annotations

import hashlib
from typing import Any

from .store import canonical_json, now


def stage_identity_resolution(view, operation):
    from .evidence_identity import conflict_identity_key

    manager = view.manager
    preview = manager.evidence.preview_identity_resolution(operation, state_view=view)
    if preview["existing"]:
        return
    ambiguity = preview["ambiguity"]
    identity = ambiguity["evidence_id"]
    decision = operation["decision"]
    if "migration" in preview:
        stage_source_migration(view, {"evidence_id": identity, "new_platform_id": operation["platform_id"],
                                      "reason": f"identity ambiguity {ambiguity['ambiguity_id']}: {operation['rationale'].strip()}"})
    elif decision == "split_future_identity":
        historical = dict(view.evidence(identity))
        historical.update(identity_namespace="conflict", identity_key=conflict_identity_key(identity),
                          semantic_revision=historical["semantic_revision"] + 1, verification_state="conflict")
        view.new_evidence[identity] = historical
        bindings = view.context_rows("evidence_source_bindings", "evidence_id", identity)
        if bindings:
            view.source_bindings[identity] = {**bindings[0], "binding_state": "binding_conflict", "source_key": None,
                                              "binding_revision": bindings[0]["binding_revision"] + 1}
        future_id = f"preflight-evidence:{len(view.new_evidence)}"
        future: dict[str, Any] = {column[1]: None for column in manager.store.conn.execute("PRAGMA table_info(evidence_refs)")}
        future.update({key: value for key, value in manager.evidence.identity_for(
            operation["platform_id"], historical["kind"], operation["locator"]).items() if key in future})
        future.update(evidence_id=future_id, kind=historical["kind"], locator=operation["locator"],
                      target_scope=historical.get("target_scope"), short_description=f"future identity split from {identity}",
                      quality_status="unknown", lifecycle_status="active", verification_level="declared",
                      verification_state="active", mutable_source=0, semantic_revision=0, created_at=now())
        view.new_evidence[future_id] = future
        view.source_bindings[future_id] = {"evidence_id": future_id, "source_platform_id": operation["platform_id"],
                                          "binding_state": "bound", "source_key": preview["future_identity_key"], "binding_revision": 1}
        for row in (historical, future):
            stage_proof(view, row, manager.evidence._proof_snapshot(row["evidence_id"], state_view=view))
    view.identity_ambiguities[ambiguity["ambiguity_id"]] = {
        **ambiguity, "state": "waived" if decision == "waive_migration_blocker" else "resolved",
        "rationale": operation["rationale"].strip()}


def stage_source_migration(view, operation):
    manager = view.manager
    identity = operation["evidence_id"]
    preview = manager.evidence.preview_source_migration(
        identity, operation["new_platform_id"], reason=operation.get("reason", "reviewed ChangeSet"), state_view=view)
    if preview["existing"]:
        return
    row = dict(preview["evidence"])
    row.update({key: value for key, value in manager.evidence.identity_for(
        operation["new_platform_id"], row["kind"], row["locator"]).items() if key in row})
    row["semantic_revision"] += 1
    view.new_evidence[identity] = row
    view.source_bindings[identity] = {**preview["binding"], **preview["after"],
                                      "reason": "reviewed source migration: " + operation.get("reason", "reviewed ChangeSet").strip()}
    for attestation in view.context_rows("evidence_attestations", "evidence_id", identity):
        if attestation["proof_eligible"]:
            view.attestations[attestation["attestation_id"]] = {
                **attestation, "proof_eligible": 0, "invalidated_at": None, "invalidation_reason": "source platform migrated"}
    for request in view.context_rows("evidence_requests", "evidence_id", identity):
        if request["state"] in {"pending", "claimed", "running"}:
            view.evidence_requests[request["evidence_request_id"]] = {
                **request, "state": "expired", "lease_until": None, "last_error": "source platform migrated"}
    snapshot = manager.evidence._proof_snapshot(identity, state_view=view)
    stage_proof(view, row, snapshot)


def stage_conflict_resolution(view, operation):
    manager = view.manager
    identity = operation["evidence_id"]
    preview = manager.evidence.preview_conflict_resolution(
        identity, accepted_attestation_ids=operation.get("accepted_attestation_ids", []),
        retained_attestation_ids=operation.get("retained_attestation_ids", []),
        rejected_attestation_ids=operation.get("rejected_attestation_ids", []),
        rationale=operation.get("rationale", ""), state_view=view)
    attestation_id = f"preflight-resolution:{len(view.attestations)}"
    attestation: dict[str, Any] = {column[1]: None for column in manager.store.conn.execute("PRAGMA table_info(evidence_attestations)")}
    attestation.update({"attestation_id": attestation_id, "evidence_id": identity,
                        "manifest_id": preview["evidence"]["current_manifest_id"], "attestation_type": "metadata",
                        "platform_id": preview["binding"]["source_platform_id"], "method": "reviewed-resolution",
                        "input_snapshot_json": canonical_json({"resolved_attestation_ids": preview["referenced"]}),
                        "result_json": canonical_json(preview["result"]), "result_hash": preview["result_hash"],
                        "artifact_ids_json": "[]", "state": "valid", "created_at": now(), "attestation_role": "resolution",
                        "qualified_manifest_id": preview["evidence"]["current_manifest_id"],
                        "qualified_manifest_hash": preview["manifest"]["manifest_hash"], "proof_eligible": 1})
    view.attestations[attestation_id] = attestation
    row = dict(view.evidence(identity))
    row["semantic_revision"] += 1
    view.new_evidence[identity] = row
    stage_proof(view, row, manager.evidence._proof_snapshot(identity, state_view=view))


def stage_proof(view, row, snapshot):
    manager = view.manager
    identity = row["evidence_id"]
    encoded = canonical_json(snapshot)
    proof_id = f"preflight-proof:{len(view.new_proofs)}"
    proof: dict[str, Any] = {column[1]: None for column in manager.store.conn.execute("PRAGMA table_info(evidence_proofs)")}
    proof.update(proof_id=proof_id, evidence_id=identity, semantic_revision=snapshot["semantic_revision"],
                 manifest_id=snapshot["manifest"]["manifest_id"], manifest_hash=snapshot["manifest"]["manifest_hash"],
                 source_platform_id=snapshot["source_binding"]["source_platform_id"],
                 verification_level=snapshot["verification_level"], verification_state=snapshot["verification_state"],
                 source_attestation_ids_json=canonical_json([item["attestation_id"] for item in
                                                             snapshot["source_attestations"] + snapshot["resolution_attestations"]]),
                 independent_attestation_ids_json=canonical_json([item["attestation_id"] for item in snapshot["independent_attestations"]]),
                 artifact_snapshots_json=canonical_json(snapshot["artifact_snapshots"]),
                 analysis_run_snapshots_json=canonical_json(snapshot["analysis_run_snapshots"]),
                 reason_codes_json=canonical_json(snapshot["reason_codes"]), policy_version=manager.policy.version,
                 proof_json=encoded, proof_hash=hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
                 supersedes_proof_id=row.get("current_proof_id"))
    row.update(current_proof_id=proof_id, verification_level=snapshot["verification_level"], verification_state=snapshot["verification_state"])
    view.new_proofs[proof_id] = proof


def stage_evidence(view, declaration, *, allocated_id=None):
    manager = view.manager
    preview = manager.add_evidence(kind=declaration["kind"], locator=declaration["locator"],
                                   description=declaration.get("description", ""),
                                   quality_status=declaration.get("quality_status", "unknown"), dry_run=True)
    for row in view.new_evidence.values():
        if row["identity_key"] == preview["identity_key"]:
            return row["evidence_id"]
    if manager.store.row("SELECT 1 FROM evidence_refs WHERE evidence_id=?", (preview["evidence_id"],)):
        return preview["evidence_id"]
    identity = allocated_id or f"preflight-evidence:{len(view.new_evidence)}"
    row = {column[1]: (manager.store.conn.execute("SELECT " + column[4]).fetchone()[0]
                       if column[4] is not None else None)
           for column in manager.store.conn.execute("PRAGMA table_info(evidence_refs)")}
    row.update({key: value for key, value in preview.items() if key in row})
    quality = declaration.get("quality_status", "unknown")
    row.update(evidence_id=identity, short_description=declaration.get("description", ""),
               quality_status="unusable_for_purpose" if quality == "invalid" else quality, lifecycle_status="active")
    snapshot = manager.evidence._proof_snapshot(identity, evidence=row, binding={
        "source_platform_id": None, "binding_state": "legacy_unbound", "binding_revision": 1})
    encoded = canonical_json(snapshot)
    proof_id = ("split-proof:" + identity) if allocated_id else f"preflight-proof:{len(view.new_proofs)}"
    proof: dict[str, Any] = {column[1]: None for column in manager.store.conn.execute("PRAGMA table_info(evidence_proofs)")}
    proof.update(proof_id=proof_id, evidence_id=identity, semantic_revision=snapshot["semantic_revision"],
                 verification_level=snapshot["verification_level"], verification_state=snapshot["verification_state"],
                 source_attestation_ids_json="[]", independent_attestation_ids_json="[]",
                 artifact_snapshots_json=canonical_json(snapshot["artifact_snapshots"]),
                 analysis_run_snapshots_json=canonical_json(snapshot["analysis_run_snapshots"]),
                 reason_codes_json=canonical_json(snapshot["reason_codes"]), policy_version=manager.policy.version,
                 proof_json=encoded, proof_hash=hashlib.sha256(encoded.encode("utf-8")).hexdigest())
    row.update(current_proof_id=proof_id, verification_level=snapshot["verification_level"],
               verification_state=snapshot["verification_state"])
    view.new_evidence[identity] = row
    view.new_proofs[proof_id] = proof
    return identity
