from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import (
    ConflictError,
    LeaseExpiredError,
    NotFoundError,
    PermissionError,
    ValidationError,
)
from .security import AuthContext, CredentialResolver
from .store import canonical_json, new_id, now

if TYPE_CHECKING:
    from .service import IssueManager


class ProposalService:
    def __init__(self, manager: "IssueManager"):
        self.manager = manager
        self.store = manager.store
        self.credentials = CredentialResolver(self.store)

    def _encode_snapshot(self, snapshot: dict[str, Any]) -> str:
        raw = canonical_json(snapshot).encode("utf-8")
        payload = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        signature = hmac.new(self.store.secret, raw, hashlib.sha256).hexdigest()
        return f"{payload}.{signature}"

    def _decode_snapshot(self, token: str) -> dict[str, Any]:
        try:
            payload, signature = token.rsplit(".", 1)
            padding = "=" * (-len(payload) % 4)
            raw = base64.urlsafe_b64decode(payload + padding)
            expected = hmac.new(self.store.secret, raw, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise ValidationError("basis_snapshot_token signature is invalid")
            value = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("basis_snapshot_token is malformed") from exc
        if not isinstance(value, dict):
            raise ValidationError("basis_snapshot_token payload must be an object")
        return value

    def make_snapshot_token(
        self,
        issue_id: str,
        expected_revision: int,
        basis: list[dict[str, Any]],
        evidence_refs: list[str] | None = None,
        context_package_id: str | None = None,
    ) -> str:
        providers: list[dict[str, Any]] = []
        for item in basis:
            provider = self.manager._issue(str(item["issue_id"]), active=False)
            providers.append(
                {
                    "issue_id": provider["issue_id"],
                    "captured_revision": provider["conclusion_revision"],
                    "captured_conclusion_id": provider["current_conclusion_id"],
                    "captured_freshness": provider["freshness"],
                    "requested_revision": item.get("conclusion_revision"),
                    "basis_mode": item.get("basis_mode", "current"),
                }
            )
        evidence_proofs: list[dict[str, Any]] = []
        for evidence_id in sorted(set(evidence_refs or [])):
            evidence = self.store.row(
                "SELECT current_proof_id,semantic_revision FROM evidence_refs WHERE evidence_id=?",
                (evidence_id,),
            )
            proof = (
                self.store.row(
                    "SELECT proof_hash,manifest_id,manifest_hash FROM evidence_proofs "
                    "WHERE proof_id=?",
                    (evidence.get("current_proof_id"),),
                )
                if evidence and evidence.get("current_proof_id")
                else None
            )
            evidence_proofs.append(
                {
                    "evidence_id": evidence_id,
                    "proof_id": evidence.get("current_proof_id") if evidence else None,
                    "proof_hash": proof.get("proof_hash") if proof else None,
                    "semantic_revision": int(evidence.get("semantic_revision", 0))
                    if evidence
                    else None,
                    "manifest_id": proof.get("manifest_id") if proof else None,
                    "manifest_hash": proof.get("manifest_hash") if proof else None,
                }
            )
        snapshot = {
            "version": 2,
            "issue_id": issue_id,
            "expected_conclusion_revision": expected_revision,
            "providers": sorted(providers, key=lambda row: row["issue_id"]),
            "evidence_proofs": evidence_proofs,
            "policy_version": self.manager.policy.version,
        }
        from .conclusion_rule_service import ConclusionRuleService
        snapshot["conclusion_rule_revision"] = ConclusionRuleService(self.manager).current(issue_id)["revision"]
        if context_package_id is not None:
            snapshot["context_package_id"] = context_package_id
        return self._encode_snapshot(snapshot)

    def verify_snapshot(
        self, token: str, proposal: dict[str, Any], *, require_current: bool = True, state_view=None
    ) -> dict[str, Any]:
        snapshot = self._decode_snapshot(token)
        if require_current and snapshot.get("context_package_id"):
            self.manager.context_maintenance.verify_package(
                snapshot["context_package_id"], str(proposal.get("issue_id")), state_view=state_view
            )
        if snapshot.get("issue_id") != proposal.get("issue_id"):
            raise ConflictError("Basis snapshot belongs to another issue")
        if snapshot.get("expected_conclusion_revision") != proposal.get(
            "expected_conclusion_revision"
        ):
            raise ConflictError("Basis snapshot does not match the proposal revision")
        if snapshot.get("policy_version") != self.manager.policy.version:
            raise ConflictError("Policy changed after proposal preparation; prepare again")
        if require_current:
            from .conclusion_rule_service import ConclusionRuleService
            issue_id = str(proposal.get("issue_id"))
            issue = state_view.issue(issue_id) if state_view is not None else None
            if ConclusionRuleService(self.manager).current(issue_id, issue=issue)["revision"] != snapshot.get("conclusion_rule_revision"):
                raise ConflictError("Conclusion rule changed after proposal preparation; prepare again")
        requested = {str(item.get("issue_id")): item for item in proposal.get("basis", [])}
        captured = {item["issue_id"]: item for item in snapshot.get("providers", [])}
        if set(requested) != set(captured):
            raise ConflictError("Proposal basis changed after its signed snapshot was created")
        for provider_id, item in requested.items():
            snap = captured[provider_id]
            mode = item.get("basis_mode", "current")
            if mode != snap.get("basis_mode"):
                raise ConflictError(f"Basis mode changed for {provider_id}")
            if item.get("conclusion_revision") != snap.get("requested_revision"):
                raise ConflictError(f"Basis revision changed for {provider_id}")
            if require_current and mode == "current":
                provider = state_view.issue(provider_id) if state_view is not None else self.manager._issue(provider_id, active=False)
                if provider["conclusion_revision"] != snap.get("captured_revision") or provider[
                    "current_conclusion_id"
                ] != snap.get("captured_conclusion_id"):
                    raise ConflictError(
                        f"Provider {provider_id} changed after prepare; prepare again"
                    )
        captured_evidence = {
            item["evidence_id"]: item for item in snapshot.get("evidence_proofs", [])
        }
        if captured_evidence:
            requested_evidence = set(str(item) for item in proposal.get("evidence_refs", []))
            if requested_evidence != set(captured_evidence):
                raise ConflictError("Proposal Evidence set changed after prepare")
            for evidence_id, captured_proof in captured_evidence.items():
                current = self.store.row(
                    "SELECT current_proof_id,semantic_revision FROM evidence_refs "
                    "WHERE evidence_id=?",
                    (evidence_id,),
                )
                proof = (
                    self.store.row(
                        "SELECT proof_hash FROM evidence_proofs WHERE proof_id=?",
                        (current.get("current_proof_id"),),
                    )
                    if current and current.get("current_proof_id")
                    else None
                )
                if (
                    not current
                    or current.get("current_proof_id") != captured_proof.get("proof_id")
                    or int(current.get("semantic_revision", -1))
                    != int(captured_proof.get("semantic_revision", -2))
                    or not proof
                    or proof.get("proof_hash") != captured_proof.get("proof_hash")
                ):
                    raise ConflictError(
                        f"Evidence {evidence_id} proof changed after prepare; prepare again"
                    )
        return snapshot

    def create(
        self,
        proposal: dict[str, Any],
        *,
        credential: str | Path,
        idempotency_key: str | None = None,
        source_changeset_id: str | None = None,
        risk_tier: str | None = None,
        risk_reasons: list[str] | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "conclusion.propose")
        return self._create(proposal, auth=auth, idempotency_key=idempotency_key,
                            source_changeset_id=source_changeset_id, risk_tier=risk_tier,
                            risk_reasons=risk_reasons)

    def _create(self, proposal, *, auth, idempotency_key=None, source_changeset_id=None,
                risk_tier=None, risk_reasons=None):
        """Internal authenticated entry, also usable inside a workflow transaction."""
        auth.require("conclusion.propose")
        issue_id = proposal.get("issue_id")
        expected = proposal.get("expected_conclusion_revision")
        if not issue_id or not isinstance(expected, int):
            raise ValidationError(
                "Proposal needs issue_id and integer expected_conclusion_revision"
            )
        issue = self.manager._issue(issue_id)
        if "revision_of" in proposal:
            parent = proposal["revision_of"]
            if (not isinstance(parent, dict) or set(parent) != {"proposal_id", "proposal_hash"}
                    or any(not isinstance(v, str) or not v for v in parent.values())):
                raise ValidationError("revision_of needs proposal_id and proposal_hash")
            previous = self.store.row("SELECT issue_id,proposal_hash FROM proposals WHERE proposal_id=?",
                                      (parent["proposal_id"],))
            if not previous or previous["issue_id"] != issue_id or previous["proposal_hash"] != parent["proposal_hash"]:
                raise ConflictError("Revision source must match an existing proposal on this Issue")
        if expected != issue["conclusion_revision"]:
            raise ConflictError(
                f"Optimistic lock failed for {issue_id}: expected {expected}, current {issue['conclusion_revision']}"
            )
        payload = json.loads(canonical_json(proposal))
        token = payload.get("basis_snapshot_token") or self.make_snapshot_token(
            issue_id,
            expected,
            payload.get("basis", []),
            [str(item) for item in payload.get("evidence_refs", [])],
        )
        payload["basis_snapshot_token"] = token
        operation_payload = {"proposal": payload, "actor_id": auth.actor_id, "run_id": auth.run_id}
        replay = self.store.idempotency_lookup(
            "proposal.create", idempotency_key, operation_payload
        )
        if replay:
            return {**replay, "idempotent_replay": True}
        proposal_json = canonical_json(payload)
        proposal_hash = hashlib.sha256(proposal_json.encode("utf-8")).hexdigest()
        proposal_id = new_id("proposal")
        target_status = str(payload.get("status", "provisional"))
        quorum = int(
            self.manager.issue_publication_profile(issue, target_status).get(
                "review_quorum", 0
            )
        )
        effective_risk = risk_tier or (
            "T3"
            if self.manager.issue_report_facing(issue) or target_status == "canonical"
            else ("T2" if quorum else "T1")
        )
        if effective_risk == "T3":
            quorum = max(quorum, 2)
        elif effective_risk == "T2":
            quorum = max(quorum, 1)
        result = {
            "proposal_id": proposal_id,
            "issue_id": issue_id,
            "state": "draft",
            "target_status": target_status,
            "proposal_hash": proposal_hash,
            "basis_snapshot_token": token,
            "required_reviews": quorum,
            "source_changeset_id": source_changeset_id,
            "risk_tier": effective_risk,
            "risk_reasons": risk_reasons or [],
        }
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO proposals("
                "proposal_id,issue_id,target_status,state,proposal_json,proposal_hash,basis_snapshot_token,"
                "proposer_actor_id,proposer_run_id,required_reviews,created_at,updated_at,"
                "source_changeset_id,risk_tier,risk_reasons_json"
                ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    proposal_id,
                    issue_id,
                    target_status,
                    "draft",
                    proposal_json,
                    proposal_hash,
                    token,
                    auth.actor_id,
                    auth.run_id,
                    quorum,
                    now(),
                    now(),
                    source_changeset_id,
                    effective_risk,
                    canonical_json(risk_reasons or []),
                ),
            )
            self.store.idempotency_record(
                conn, "proposal.create", idempotency_key, operation_payload, result
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="proposal.create",
                object_type="proposal",
                object_id=proposal_id,
                before_revision=None,
                after_revision=0,
                reason="",
                payload=result,
            )
        return result

    def show(self, proposal_id: str) -> dict[str, Any]:
        row = self.store.row("SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,))
        if not row:
            raise NotFoundError(f"Proposal not found: {proposal_id}")
        row["proposal"] = json.loads(row.pop("proposal_json"))
        row["basis"] = self.store.rows(
            "SELECT * FROM proposal_basis WHERE proposal_id=? ORDER BY provider_issue_id",
            (proposal_id,),
        )
        row["reviews"] = self.store.rows(
            "SELECT * FROM review_decisions WHERE proposal_id=? ORDER BY created_at,review_id",
            (proposal_id,),
        )
        return row

    def list(self, state: str | None = None) -> list[dict[str, Any]]:
        if state:
            return self.store.rows(
                "SELECT proposal_id,issue_id,target_status,state,required_reviews,created_at,updated_at "
                "FROM proposals WHERE state=? ORDER BY created_at",
                (state,),
            )
        return self.store.rows(
            "SELECT proposal_id,issue_id,target_status,state,required_reviews,created_at,updated_at "
            "FROM proposals ORDER BY created_at"
        )

    def validate(self, proposal_id: str, *, credential: str | Path) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "conclusion.propose")
        row = self.store.row("SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,))
        if not row:
            raise NotFoundError(f"Proposal not found: {proposal_id}")
        if row["state"] in {"review_rejected", "applied", "expired"}:
            raise ConflictError(f"Proposal {proposal_id} is already {row['state']}")
        proposal = json.loads(row["proposal_json"])
        actual_hash = hashlib.sha256(canonical_json(proposal).encode("utf-8")).hexdigest()
        if actual_hash != row["proposal_hash"]:
            raise ConflictError("Stored proposal content hash mismatch")
        self.verify_snapshot(row["basis_snapshot_token"], proposal, require_current=True)
        validation = self.manager.validate_proposal(proposal, refresh=True)
        target_state = "validated" if row["required_reviews"] == 0 else "under_review"
        with self.store.transaction() as conn:
            conn.execute("DELETE FROM proposal_basis WHERE proposal_id=?", (proposal_id,))
            for item in validation["normalized_basis"]:
                conn.execute(
                    "INSERT INTO proposal_basis VALUES (?,?,?,?,?,?)",
                    (
                        proposal_id,
                        item["issue_id"],
                        item["conclusion_revision"],
                        item["conclusion_id"],
                        item.get("basis_mode", "current"),
                        item.get("historical_reason"),
                    ),
                )
            conn.execute(
                "UPDATE proposals SET state=?,updated_at=? WHERE proposal_id=?",
                (target_state, now(), proposal_id),
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="proposal.validate",
                object_type="proposal",
                object_id=proposal_id,
                before_revision=None,
                after_revision=None,
                reason="",
                payload={"state": target_state, "required_reviews": row["required_reviews"]},
            )
        return {
            "proposal_id": proposal_id,
            "valid": True,
            "state": target_state,
            "required_reviews": row["required_reviews"],
            "validation": validation,
        }

    def claim_review(
        self,
        proposal_id: str,
        *,
        credential: str | Path,
        lease_until: str | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "proposal.review")
        row = self.store.row("SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,))
        if not row:
            raise NotFoundError(f"Proposal not found: {proposal_id}")
        if row["state"] != "under_review":
            raise ConflictError(
                f"Proposal {proposal_id} is {row['state']}, not claimable for review"
            )
        self._check_independence(row, auth)
        lease_until = lease_until or (
            datetime.now().astimezone() + timedelta(minutes=15)
        ).isoformat(timespec="seconds")
        try:
            lease_expiry = datetime.fromisoformat(lease_until)
        except ValueError as exc:
            raise ValidationError("Review lease_until must be an ISO-8601 timestamp") from exc
        if lease_expiry.tzinfo is None:
            raise ValidationError("Review lease_until must include a timezone")
        if lease_expiry <= datetime.now().astimezone():
            raise ValidationError("Review lease must expire in the future")
        assignment_id = new_id("review_assignment")
        with self.store.transaction() as conn:
            existing = conn.execute(
                "SELECT * FROM review_assignments WHERE proposal_id=? AND reviewer_run_id=?",
                (proposal_id, auth.run_id),
            ).fetchone()
            if (
                existing
                and existing["state"] == "assigned"
                and (not existing["lease_until"] or existing["lease_until"] > now())
            ):
                return {**dict(existing), "idempotent_replay": True}
            if existing and existing["state"] == "submitted":
                raise ConflictError("Review was already completed by this reviewer run")
            if existing:
                conn.execute(
                    "UPDATE review_assignments SET state='assigned',claimed_at=?,lease_until=?,"
                    "heartbeat_at=?,attempt_count=attempt_count+1,"
                    "lease_generation=lease_generation+1,released_at=NULL,last_error=NULL "
                    "WHERE assignment_id=?",
                    (now(), lease_until, now(), existing["assignment_id"]),
                )
                assignment_id = existing["assignment_id"]
            else:
                conn.execute(
                    "INSERT INTO review_assignments(assignment_id,proposal_id,reviewer_actor_id,"
                    "reviewer_run_id,state,claimed_at,lease_until,heartbeat_at,attempt_count,last_error) "
                    "VALUES (?,?,?,?,'assigned',?,?,?,1,NULL)",
                    (
                        assignment_id,
                        proposal_id,
                        auth.actor_id,
                        auth.run_id,
                        now(),
                        lease_until,
                        now(),
                    ),
                )
        return {
            "assignment_id": assignment_id,
            "proposal_id": proposal_id,
            "reviewer_actor_id": auth.actor_id,
            "reviewer_run_id": auth.run_id,
            "lease_until": lease_until,
        }

    def _check_independence(self, proposal: dict[str, Any], auth: AuthContext) -> None:
        if auth.actor_id == proposal["proposer_actor_id"]:
            raise PermissionError("A proposer cannot review its own proposal")
        if auth.run_id == proposal["proposer_run_id"]:
            raise PermissionError("A proposer run cannot review its own proposal")
        proposer_run = self.store.row(
            "SELECT lineage_json FROM agent_runs WHERE run_id=?", (proposal["proposer_run_id"],)
        )
        proposer_lineage = set(json.loads((proposer_run or {}).get("lineage_json", "[]")))
        proposer_lineage.add(proposal["proposer_run_id"])
        if auth.run_id in proposer_lineage or proposal["proposer_run_id"] in auth.lineage:
            raise PermissionError("Reviewer is in the proposer's delegation lineage")
        duplicate_actor = self.store.row(
            "SELECT review_id FROM review_decisions WHERE proposal_id=? AND reviewer_actor_id=?",
            (proposal["proposal_id"], auth.actor_id),
        )
        if duplicate_actor:
            raise ConflictError("Each proposal review must come from a distinct actor")

    def heartbeat_review(
        self,
        proposal_id: str,
        *,
        credential: str | Path,
        lease_minutes: int = 15,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "proposal.review")
        assignment = self.store.row(
            "SELECT * FROM review_assignments WHERE proposal_id=? AND reviewer_actor_id=? "
            "AND reviewer_run_id=? AND state='assigned'",
            (proposal_id, auth.actor_id, auth.run_id),
        )
        if not assignment:
            raise ConflictError("No active review assignment exists for this run")
        if assignment["lease_until"] and assignment["lease_until"] <= now():
            raise LeaseExpiredError("Review assignment lease expired; claim it again")
        lease_until = (
            datetime.now().astimezone() + timedelta(minutes=max(1, lease_minutes))
        ).isoformat(timespec="seconds")
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE review_assignments SET lease_until=?,heartbeat_at=? WHERE assignment_id=?",
                (lease_until, now(), assignment["assignment_id"]),
            )
        return {
            "assignment_id": assignment["assignment_id"],
            "proposal_id": proposal_id,
            "lease_until": lease_until,
        }

    def release_review(
        self, proposal_id: str, *, credential: str | Path
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "proposal.review")
        with self.store.transaction() as conn:
            assignment = conn.execute(
                "SELECT * FROM review_assignments WHERE proposal_id=? AND reviewer_actor_id=? "
                "AND reviewer_run_id=?",
                (proposal_id, auth.actor_id, auth.run_id),
            ).fetchone()
            if not assignment:
                raise ConflictError("No proposal review assignment exists for this run")
            if assignment["state"] == "submitted":
                raise ConflictError("A completed review cannot be released")
            released_at = assignment["released_at"] or now()
            replay = assignment["state"] == "released"
            if not replay:
                conn.execute(
                    "UPDATE review_assignments SET state='released',released_at=? "
                    "WHERE assignment_id=?",
                    (released_at, assignment["assignment_id"]),
                )
        return {
            "assignment_id": assignment["assignment_id"],
            "proposal_id": proposal_id,
            "state": "released",
            "released_at": released_at,
            "idempotent_replay": replay,
        }

    def submit_review(
        self,
        proposal_id: str,
        *,
        decision: str,
        rationale: str,
        evidence_sufficiency: str,
        credential: str | Path,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "proposal.review")
        proposal = self.store.row("SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,))
        if not proposal:
            raise NotFoundError(f"Proposal not found: {proposal_id}")
        if decision not in {"pass", "reject"}:
            raise ValidationError("Review decision must be 'pass' or 'reject'")
        if not rationale.strip() or not evidence_sufficiency.strip():
            raise ValidationError("Review rationale and evidence_sufficiency are required")
        assignment = self.store.row(
            "SELECT * FROM review_assignments WHERE proposal_id=? AND reviewer_actor_id=? "
            "AND reviewer_run_id=?",
            (proposal_id, auth.actor_id, auth.run_id),
        )
        request_payload = {
            "proposal_id": proposal_id,
            "proposal_hash": proposal["proposal_hash"],
            "decision": decision,
            "rationale": rationale,
            "evidence_sufficiency": evidence_sufficiency,
            "actor_id": auth.actor_id,
            "run_id": auth.run_id,
            "assignment_id": assignment["assignment_id"] if assignment else None,
        }
        replay = self.store.idempotency_lookup("review.submit", idempotency_key, request_payload)
        if replay:
            return {**replay, "idempotent_replay": True}
        if proposal["state"] not in {"under_review", "validated"}:
            raise ConflictError(f"Proposal {proposal_id} is {proposal['state']}, not reviewable")
        self._check_independence(proposal, auth)
        if not assignment or assignment["state"] != "assigned":
            raise PermissionError(
                "Review submission requires an active assignment claimed by this run"
            )
        if assignment["lease_until"] and assignment["lease_until"] <= now():
            raise LeaseExpiredError("Review assignment lease has expired; claim it again")
        snapshot = self._decode_snapshot(proposal["basis_snapshot_token"])
        review_id = new_id("review")
        count_row = self.store.row(
            "SELECT COUNT(*) AS n FROM review_decisions WHERE proposal_id=? AND decision='pass'",
            (proposal_id,),
        )
        pass_count = int((count_row or {"n": 0})["n"]) + (1 if decision == "pass" else 0)
        if decision == "reject":
            state = "review_rejected"
        elif pass_count >= proposal["required_reviews"]:
            state = "review_passed"
        else:
            state = "under_review"
        result = {
            "review_id": review_id,
            "proposal_id": proposal_id,
            "decision": decision,
            "reviewer_actor_id": auth.actor_id,
            "reviewer_run_id": auth.run_id,
            "pass_count": pass_count,
            "required_reviews": proposal["required_reviews"],
            "proposal_state": state,
        }
        with self.store.transaction() as conn:
            locked_value = conn.execute(
                "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone()
            if not locked_value:
                raise NotFoundError(f"Proposal not found: {proposal_id}")
            locked_proposal = dict(locked_value)
            if locked_proposal["state"] not in {"under_review", "validated"}:
                raise ConflictError(
                    f"Proposal {proposal_id} is {locked_proposal['state']}, not reviewable"
                )
            self._check_independence(locked_proposal, auth)
            locked_assignment = conn.execute(
                "SELECT * FROM review_assignments WHERE proposal_id=? AND reviewer_actor_id=? "
                "AND reviewer_run_id=? AND state='assigned'",
                (proposal_id, auth.actor_id, auth.run_id),
            ).fetchone()
            if not locked_assignment or (
                locked_assignment["lease_until"] and locked_assignment["lease_until"] <= now()
            ):
                raise LeaseExpiredError("Review submission requires a current assignment lease")
            locked_count = conn.execute(
                "SELECT COUNT(*) FROM review_decisions WHERE proposal_id=? AND decision='pass'",
                (proposal_id,),
            ).fetchone()[0]
            pass_count = int(locked_count) + (1 if decision == "pass" else 0)
            if decision == "reject":
                state = "review_rejected"
            elif pass_count >= locked_proposal["required_reviews"]:
                state = "review_passed"
            else:
                state = "under_review"
            result["pass_count"] = pass_count
            result["proposal_state"] = state
            conn.execute(
                "INSERT INTO review_decisions(review_id,proposal_id,reviewer_actor_id,reviewer_run_id,"
                "decision,rationale,evidence_sufficiency,proposal_hash,basis_snapshot_json,created_at,"
                "changeset_hash,policy_risk_snapshot) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    review_id,
                    proposal_id,
                    auth.actor_id,
                    auth.run_id,
                    decision,
                    rationale,
                    evidence_sufficiency,
                    proposal["proposal_hash"],
                    canonical_json(snapshot),
                    now(),
                    None,
                    canonical_json(
                        {
                            "risk_tier": proposal.get("risk_tier", "T1"),
                            "risk_reasons": json.loads(proposal.get("risk_reasons_json", "[]")),
                            "policy_version": self.manager.policy.version,
                        }
                    ),
                ),
            )
            conn.execute(
                "UPDATE review_assignments SET state='submitted' "
                "WHERE proposal_id=? AND reviewer_run_id=? AND state='assigned'",
                (proposal_id, auth.run_id),
            )
            conn.execute(
                "UPDATE proposals SET state=?,updated_at=?,rejection_reason=? WHERE proposal_id=?",
                (state, now(), rationale if decision == "reject" else None, proposal_id),
            )
            self.store.idempotency_record(
                conn, "review.submit", idempotency_key, request_payload, result
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="review.submit",
                object_type="proposal",
                object_id=proposal_id,
                before_revision=None,
                after_revision=None,
                reason=rationale,
                payload=result,
            )
        return result

    def apply(
        self,
        proposal_id: str,
        *,
        credential: str | Path,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "proposal.apply")
        with self.store.transaction() as conn:
            row_value = conn.execute(
                "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone()
            if not row_value:
                raise NotFoundError(f"Proposal not found: {proposal_id}")
            row = dict(row_value)
            from .integrity import assert_not_quarantined

            current_conclusion = conn.execute(
                "SELECT current_conclusion_id FROM issues WHERE issue_id=?",
                (row["issue_id"],),
            ).fetchone()
            if current_conclusion and current_conclusion["current_conclusion_id"]:
                assert_not_quarantined(
                    conn,
                    "conclusion_revision",
                    str(current_conclusion["current_conclusion_id"]),
                    "block_publication",
                )
            for basis in conn.execute(
                "SELECT provider_conclusion_id FROM proposal_basis WHERE proposal_id=?",
                (proposal_id,),
            ).fetchall():
                assert_not_quarantined(
                    conn,
                    "conclusion_revision",
                    str(basis["provider_conclusion_id"]),
                    "block_publication",
                )
            existing = conn.execute(
                "SELECT conclusion_id,revision_number FROM conclusion_revisions WHERE proposal_id=?",
                (proposal_id,),
            ).fetchone()
            if row["state"] == "applied" or existing:
                conclusion_id = row["applied_conclusion_id"] or existing["conclusion_id"]
                if row["state"] != "applied":
                    conn.execute(
                        "UPDATE proposals SET state='applied',applied_conclusion_id=?,updated_at=? "
                        "WHERE proposal_id=?",
                        (conclusion_id, now(), proposal_id),
                    )
                return {
                    "proposal_id": proposal_id,
                    "state": "applied",
                    "conclusion_id": conclusion_id,
                    "idempotent_replay": True,
                }
            if row["state"] == "draft":
                self.validate(proposal_id, credential=credential)
                row = dict(
                    conn.execute(
                        "SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,)
                    ).fetchone()
                )
            permitted = "validated" if row["required_reviews"] == 0 else "review_passed"
            if row["state"] != permitted:
                raise PermissionError(
                    f"Proposal requires state {permitted!r} before apply; current state is {row['state']!r}"
                )
            payload = json.loads(row["proposal_json"])
            actual_hash = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
            if actual_hash != row["proposal_hash"]:
                raise ConflictError("Stored proposal content hash mismatch")
            self.verify_snapshot(row["basis_snapshot_token"], payload, require_current=True)
            pass_count = conn.execute(
                "SELECT COUNT(DISTINCT reviewer_actor_id) FROM review_decisions "
                "WHERE proposal_id=? AND decision='pass' AND proposal_hash=?",
                (proposal_id, row["proposal_hash"]),
            ).fetchone()[0]
            if pass_count < row["required_reviews"]:
                raise PermissionError(
                    f"Proposal has {pass_count} valid independent reviews; {row['required_reviews']} required"
                )
            request_payload = {"proposal_id": proposal_id, "proposal_hash": row["proposal_hash"]}
            replay = self.store.idempotency_lookup(
                "proposal.apply", idempotency_key, request_payload
            )
            if replay:
                return {**replay, "idempotent_replay": True}
            self.store.fault("proposal.before_conclusion")
            result = self.manager.publish_conclusion(
                payload,
                actor=auth.actor_id,
                reason=f"apply persistent proposal {proposal_id}",
                refresh=True,
                proposal_id=proposal_id,
                _auth_context=auth,
                _conn=conn,
            )
            self.store.fault("proposal.after_conclusion")
            response = {"proposal_id": proposal_id, "state": "applied", **result}
            cursor = conn.execute(
                "UPDATE proposals SET state='applied',applied_conclusion_id=?,updated_at=? "
                "WHERE proposal_id=? AND state=?",
                (result["conclusion_id"], now(), proposal_id, permitted),
            )
            if cursor.rowcount != 1:
                raise ConflictError("Proposal state changed concurrently during apply")
            self.store.fault("proposal.after_state_update")
            self.store.idempotency_record(
                conn, "proposal.apply", idempotency_key, request_payload, response
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="proposal.apply",
                object_type="proposal",
                object_id=proposal_id,
                before_revision=None,
                after_revision=result["revision_number"],
                reason="",
                payload={"conclusion_id": result["conclusion_id"]},
            )
            self.store.fault("proposal.after_audit")
        return response

    def reconcile(self, *, credential: str | Path) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "maintenance")
        repaired: list[dict[str, str]] = []
        with self.store.transaction() as conn:
            rows = conn.execute(
                "SELECT p.proposal_id,p.state,p.applied_conclusion_id,c.conclusion_id "
                "FROM proposals p LEFT JOIN conclusion_revisions c ON c.proposal_id=p.proposal_id "
                "WHERE (c.conclusion_id IS NOT NULL AND (p.state<>'applied' OR p.applied_conclusion_id IS NULL)) "
                "OR (p.state='applied' AND c.conclusion_id IS NULL)"
            ).fetchall()
            for row in rows:
                if row["conclusion_id"]:
                    conn.execute(
                        "UPDATE proposals SET state='applied',applied_conclusion_id=?,updated_at=? "
                        "WHERE proposal_id=?",
                        (row["conclusion_id"], now(), row["proposal_id"]),
                    )
                    repaired.append({"proposal_id": row["proposal_id"], "action": "linked"})
            if repaired:
                self.store.audit(
                    conn,
                    actor=auth.actor_id,
                    action="proposal.reconcile",
                    object_type="ledger",
                    object_id=str(self.store.ledger_dir),
                    before_revision=None,
                    after_revision=None,
                    reason="repair proposal/conclusion apply pointers",
                    payload={"repaired": repaired},
                )
        return {"repaired": repaired, "count": len(repaired)}

    def create_waiver(
        self,
        *,
        issue_id: str,
        scope: str,
        reason: str,
        credential: str | Path,
        source_changeset_id: str | None = None,
        proposal_id: str | None = None,
    ) -> dict[str, Any]:
        auth = self.credentials.resolve(credential, "conclusion.propose")
        self.manager._issue(issue_id)
        if not scope.strip() or not reason.strip():
            raise ValidationError("Publication waiver requires a scope and reason")
        if bool(source_changeset_id) == bool(proposal_id):
            raise ValidationError("Waiver requires exactly one reviewed ChangeSet or Proposal")
        review_basis: dict[str, Any]
        if source_changeset_id:
            source = self.store.row(
                "SELECT * FROM changesets WHERE changeset_id=?", (source_changeset_id,)
            )
            if not source or source["state"] != "applied" or source["risk_tier"] != "T3":
                raise PermissionError("Waiver source ChangeSet must be an applied T3 decision")
            source_payload = json.loads(source["changeset_json"])
            if not any(
                operation.get("op") == "mark_needs_review"
                and operation.get("issue_id") == issue_id
                for operation in source_payload.get("operations", [])
            ):
                raise PermissionError(
                    "Waiver source ChangeSet must explicitly review this Issue's waiver"
                )
            reviews = self.store.rows(
                "SELECT DISTINCT reviewer_actor_id FROM changeset_review_decisions "
                "WHERE changeset_id=? AND decision='pass' AND changeset_hash=?",
                (source_changeset_id, source["changeset_hash"]),
            )
            if len(reviews) < 2:
                raise PermissionError("Waiver source ChangeSet lacks two independent reviews")
            review_basis = {
                "source_changeset_id": source_changeset_id,
                "reviewers": [row["reviewer_actor_id"] for row in reviews],
            }
        else:
            source = self.store.row("SELECT * FROM proposals WHERE proposal_id=?", (proposal_id,))
            if not source or source["state"] != "applied" or source["required_reviews"] < 2:
                raise PermissionError(
                    "Waiver source Proposal must be applied with a two-review quorum"
                )
            if source["issue_id"] != issue_id:
                raise PermissionError("Waiver source Proposal belongs to another Issue")
            reviews = self.store.rows(
                "SELECT DISTINCT reviewer_actor_id FROM review_decisions "
                "WHERE proposal_id=? AND decision='pass' AND proposal_hash=?",
                (proposal_id, source["proposal_hash"]),
            )
            if len(reviews) < 2:
                raise PermissionError("Waiver source Proposal lacks two independent reviews")
            review_basis = {
                "proposal_id": proposal_id,
                "reviewers": [row["reviewer_actor_id"] for row in reviews],
            }
        waiver_id = new_id("waiver")
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO publication_waivers VALUES (?,?,?,?,?,?,?,?)",
                (
                    waiver_id,
                    issue_id,
                    scope,
                    reason,
                    proposal_id,
                    source_changeset_id,
                    auth.actor_id,
                    now(),
                ),
            )
            self.store.audit(
                conn,
                actor=auth.actor_id,
                action="publication.waiver_create",
                object_type="publication_waiver",
                object_id=waiver_id,
                before_revision=None,
                after_revision=1,
                reason=reason,
                payload={"issue_id": issue_id, "scope": scope, **review_basis},
            )
        return {
            "waiver_id": waiver_id,
            "issue_id": issue_id,
            "scope": scope,
            "reason": reason,
            **review_basis,
        }
