from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .errors import PermissionError, ValidationError
from .store import canonical_json, new_id, now

if TYPE_CHECKING:
    from .store import Store


DESKTOP_EDITOR_CAPABILITIES = {
    "context.read",
    "issue.write",
    "evidence.write",
    "intake.submit",
    "evidence.relation.write",
    "work.write",
    "workflow.read",
    "workflow.manage",
    "workflow.commit",
}

ALL_WRITE_CAPABILITIES = {
    "context.read",
    "issue.write",
    "relation.write",
    "evidence.write",
    "work.write",
    "conclusion.propose",
    "conclusion.record",
    "question.write",
    "question.answer",
    "evidence.relation.write",
    "rollup.configure",
    "proposal.apply",
    "proposal.review",
    "intake.submit",
    "triage.manage",
    "refresh.manage",
    "artifact.manage",
    "maintenance",
    "backup.manage",
    "identity.manage",
    "changeset.submit",
    "activity.read",
    "evidence.manifest.submit",
    "evidence.attest",
    "evidence.request.create",
    "evidence.request.execute",
    "evidence.request.review",
    "evidence.resolve",
    "evidence.applicability.write",
    "triage.disposition",
    "artifact.manage-scoped",
    "analysis.register-scoped",
    "registry.read",
    "registry.install",
    "registry.activate",
    "registry.deprecate",
    "registry.disable",
    "registry.bind",
    "import.inspect",
    "import.stage",
    "import.review",
    "import.apply",
    "field_bundle.submit",
    "field_bundle.read_own",
    "field_bundle.triage",
    "field_bundle.apply",
    "record.create",
    "record.revise",
    "record.publish",
    "report.prepare",
    "report.build",
    "report.publish",
    "workflow.read",
    "workflow.manage",
    "workflow.execute",
    "workflow.commit",
}

CAPABILITY_PROFILES: dict[str, set[str]] = {
    "field-maintainer": {
        "context.read",
        "intake.submit",
        "triage.manage",
        "changeset.submit",
        "issue.write",
        "relation.write",
        "evidence.write",
        "work.write",
        "conclusion.propose",
        "conclusion.record",
        "question.write",
        "question.answer",
        "evidence.relation.write",
        "proposal.apply",
        "refresh.manage",
        "activity.read",
        "evidence.request.create",
        "triage.disposition",
        "registry.read",
        "import.inspect",
        "import.stage",
        "field_bundle.submit",
        "field_bundle.read_own",
        "field_bundle.apply",
        "record.create",
        "record.revise",
        "report.prepare",
        "report.build",
        "workflow.read",
        "workflow.execute",
        "workflow.commit",
    },
    "experiment-capture": {
        "context.read",
        "activity.read",
        "intake.submit",
        "evidence.manifest.submit",
    },
    "platform-evidence-executor": {
        "context.read",
        "activity.read",
        "evidence.manifest.submit",
        "evidence.attest",
        "evidence.request.execute",
        "artifact.manage-scoped",
        "analysis.register-scoped",
    },
    "reviewer": {
        "context.read",
        "activity.read",
        "proposal.review",
        "evidence.request.review",
        "evidence.resolve",
        "registry.read",
        "import.review",
        "record.publish",
        "report.publish",
        "workflow.read",
    },
    "maintenance-service": {
        "maintenance",
        "context.read",
        "backup.manage",
        "artifact.manage",
        "identity.manage",
        "registry.read",
        "registry.install",
        "registry.activate",
        "registry.deprecate",
        "registry.disable",
        "registry.bind",
        "rollup.configure",
        "import.inspect",
        "import.stage",
        "import.review",
        "import.apply",
        "field_bundle.triage",
        "field_bundle.apply",
        "field_bundle.read_own",
        "workflow.read",
        "workflow.manage",
    },
    "evidence-curator": {
        "context.read",
        "evidence.applicability.write",
    },
}


BOOTSTRAP_IDENTITIES: dict[str, dict[str, Any]] = {
    "experiment-agent": {
        "kind": "experiment_agent",
        "display_name": "Bootstrap experiment agent",
        "profiles": {"field-maintainer"},
        "capabilities": CAPABILITY_PROFILES["field-maintainer"],
    },
    "organizer-agent": {
        "kind": "organizer_agent",
        "display_name": "Bootstrap organizer agent",
        "profiles": {"field-maintainer"},
        "capabilities": CAPABILITY_PROFILES["field-maintainer"]
        | {"evidence.resolve", "workflow.manage"},
    },
    "review-agent-1": {
        "kind": "review_agent",
        "display_name": "Bootstrap independent review agent 1",
        "profiles": {"reviewer"},
        "capabilities": CAPABILITY_PROFILES["reviewer"],
    },
    "review-agent-2": {
        "kind": "review_agent",
        "display_name": "Bootstrap independent review agent 2",
        "profiles": {"reviewer"},
        "capabilities": CAPABILITY_PROFILES["reviewer"],
    },
    "maintenance-agent": {
        "kind": "maintenance_agent",
        "display_name": "Bootstrap maintenance agent",
        "profiles": {"maintenance-service"},
        "capabilities": CAPABILITY_PROFILES["maintenance-service"],
    },
}


def credential_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuthContext:
    actor_id: str
    actor_kind: str
    run_id: str
    capabilities: frozenset[str]
    lineage: frozenset[str]
    principal_kind: str = "ai_agent"
    platform_id: str | None = None
    token_epoch: int | None = None

    def require(self, capability: str) -> None:
        if capability not in self.capabilities:
            raise PermissionError(
                f"Actor {self.actor_id!r} does not have capability {capability!r}"
            )


class CredentialResolver:
    def __init__(self, store: "Store"):
        self.store = store

    def _read(self, credential: str | Path) -> tuple[str, str | None]:
        value = str(credential)
        candidate = Path(value)
        try:
            is_file_candidate = candidate.exists()
        except OSError as exc:
            # Long run tokens can exceed a filesystem's per-component limit.
            # Other path errors still fail rather than bypassing file validation.
            if exc.errno != errno.ENAMETOOLONG or not value.startswith("run1."):
                raise
            is_file_candidate = False
        if is_file_candidate:
            resolved = candidate.resolve()
            trusted_root = (self.store.ledger_dir / "credentials").resolve()
            try:
                resolved.relative_to(trusted_root)
            except ValueError as exc:
                raise PermissionError(
                    f"Credential files must be under the ledger credential directory: {trusted_root}"
                ) from exc
            try:
                data = json.loads(resolved.read_text(encoding="utf-8"))
                token = data["token"]
            except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
                raise ValidationError(f"Invalid credential file {resolved}: {exc}") from exc
            return str(token), data.get("run_id")
        return value, None

    def _resolve_run_token(self, token: str) -> AuthContext | None:
        if not token.startswith("run1."):
            return None
        try:
            _prefix, payload_text, signature = token.split(".", 2)
            padding = "=" * (-len(payload_text) % 4)
            raw = base64.urlsafe_b64decode(payload_text + padding)
            expected = hmac.new(self.store.secret, raw, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise PermissionError("Run token signature is invalid")
            payload = json.loads(raw.decode("utf-8"))
            if int(payload["exp"]) <= int(time.time()):
                raise PermissionError("Run token has expired")
        except (ValueError, KeyError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PermissionError("Run token is malformed") from exc
        record = self.store.row(
            "SELECT * FROM service_tokens WHERE token_id=? AND nonce=? AND revoked_at IS NULL",
            (payload.get("jti"), payload.get("nonce")),
        )
        if not record:
            raise PermissionError("Run token is unknown or revoked")
        current_epoch = int(self.store.manager_metadata()["token_epoch"])
        if (
            int(payload.get("epoch", -1)) != current_epoch
            or int(record.get("token_epoch", -1)) != current_epoch
        ):
            raise PermissionError("Run token belongs to an inactive token epoch")
        actor = self.store.row(
            "SELECT * FROM actors WHERE actor_id=? AND active=1", (payload.get("sub"),)
        )
        run = self.store.row(
            "SELECT * FROM agent_runs WHERE run_id=? AND actor_id=? AND ended_at IS NULL",
            (payload.get("run_id"), payload.get("sub")),
        )
        if not actor or not run:
            raise PermissionError("Run token principal or run is inactive")
        capabilities = frozenset(str(item) for item in payload.get("cap", []))
        stored_capabilities = set(json.loads(record["capabilities_json"]))
        if set(capabilities) != stored_capabilities:
            raise PermissionError("Run token capability claim does not match its issuance record")
        lineage = set(json.loads(run["lineage_json"] or "[]"))
        lineage.add(run["run_id"])
        platform_id = record.get("platform_id") or actor.get("platform_id")
        if payload.get("platform_id") != platform_id:
            raise PermissionError("Run token platform scope does not match its issuance record")
        return AuthContext(
            actor_id=actor["actor_id"],
            actor_kind=actor["actor_kind"],
            run_id=run["run_id"],
            capabilities=capabilities,
            lineage=frozenset(lineage),
            principal_kind=actor.get("principal_kind") or "ai_agent",
            platform_id=platform_id,
            token_epoch=current_epoch,
        )

    def resolve(self, credential: str | Path | None, capability: str | None = None) -> AuthContext:
        if not credential:
            raise PermissionError(
                "This write requires a trusted credential; use --credential or ISSUECTL_CREDENTIAL"
            )
        token, requested_run = self._read(credential)
        run_context = self._resolve_run_token(token)
        if run_context is not None:
            if capability:
                run_context.require(capability)
            return run_context
        actor = self.store.row(
            "SELECT * FROM actors WHERE credential_hash=? AND active=1",
            (credential_hash(token),),
        )
        if not actor:
            raise PermissionError("Credential is invalid or inactive")
        if requested_run:
            run = self.store.row(
                "SELECT * FROM agent_runs WHERE run_id=? AND actor_id=? AND ended_at IS NULL",
                (requested_run, actor["actor_id"]),
            )
        else:
            run = self.store.row(
                "SELECT * FROM agent_runs WHERE actor_id=? AND ended_at IS NULL "
                "ORDER BY started_at DESC,run_id DESC LIMIT 1",
                (actor["actor_id"],),
            )
        if not run:
            raise PermissionError("Credential has no active agent run")
        capabilities = frozenset(
            row["capability"]
            for row in self.store.rows(
                "SELECT capability FROM actor_capabilities WHERE actor_id=?",
                (actor["actor_id"],),
            )
        )
        lineage = set(json.loads(run["lineage_json"] or "[]"))
        lineage.add(run["run_id"])
        context = AuthContext(
            actor_id=actor["actor_id"],
            actor_kind=actor["actor_kind"],
            run_id=run["run_id"],
            capabilities=capabilities,
            lineage=frozenset(lineage),
            principal_kind=actor.get("principal_kind") or "ai_agent",
            platform_id=actor.get("platform_id"),
            token_epoch=int(self.store.manager_metadata()["token_epoch"]),
        )
        if capability:
            context.require(capability)
        return context

    def path_for(self, actor_id: str) -> Path:
        path = (self.store.ledger_dir / "credentials" / f"{actor_id}.token").resolve()
        if not path.exists():
            raise ValidationError(f"No bootstrap credential exists for actor {actor_id!r}")
        return path

    def recover_bootstrap_maintenance_credential(self, *, reason: str) -> dict[str, Any]:
        """Reissue the existing bootstrap maintenance credential from the trusted host.

        This deliberately cannot create an identity, change capabilities, or run over HTTP.
        It is a break-glass host operation for a ledger whose original credential file is lost.
        """
        reason = reason.strip()
        if not reason or len(reason) > 500:
            raise ValidationError("A recovery reason of 1 to 500 characters is required")

        actor_id = "maintenance-agent"
        credential_dir = self.store.ledger_dir / "credentials"
        credential_dir.mkdir(exist_ok=True)
        token_path = credential_dir / f"{actor_id}.token"
        staging_path = credential_dir / f".{actor_id}.token.recovery"
        if token_path.exists():
            raise ValidationError("Bootstrap maintenance credential already exists")

        actor = self.store.row("SELECT * FROM actors WHERE actor_id=?", (actor_id,))
        if (
            not actor
            or not actor["active"]
            or actor["actor_kind"] != "maintenance_agent"
            or actor.get("principal_kind") != "service"
        ):
            raise PermissionError("The existing bootstrap maintenance principal is unavailable")
        capabilities = {
            row["capability"]
            for row in self.store.rows(
                "SELECT capability FROM actor_capabilities WHERE actor_id=?", (actor_id,)
            )
        }
        profiles = {
            row["profile_name"]
            for row in self.store.rows(
                "SELECT profile_name FROM principal_profile_assignments WHERE actor_id=?",
                (actor_id,),
            )
        }
        if (
            "identity.manage" not in capabilities
            or "maintenance-service" not in profiles
        ):
            raise PermissionError("The existing bootstrap maintenance grant does not match policy")
        runs = self.store.rows(
            "SELECT run_id FROM agent_runs WHERE actor_id=? AND ended_at IS NULL",
            (actor_id,),
        )
        if len(runs) != 1:
            raise ValidationError("Exactly one active bootstrap maintenance run is required")
        run_id = str(runs[0]["run_id"])

        if staging_path.exists():
            try:
                staged = json.loads(staging_path.read_text(encoding="utf-8"))
                staged_token = str(staged["token"])
            except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
                raise ValidationError("A recovery staging file exists but is invalid") from exc
            current = self.store.row(
                "SELECT credential_hash FROM actors WHERE actor_id=?", (actor_id,)
            )
            if not current or current["credential_hash"] != credential_hash(staged_token):
                raise ValidationError("A recovery staging file does not match the ledger credential")
            if staged.get("actor_id") != actor_id or staged.get("run_id") != run_id:
                raise ValidationError("A recovery staging file does not match the active principal")
            try:
                os.replace(staging_path, token_path)
            except OSError as exc:
                raise ValidationError("Could not finalize the recovered credential file") from exc
            return {"actor_id": actor_id, "run_id": run_id, "credential_path": str(token_path)}

        token = secrets.token_urlsafe(32)
        staging = {
            "token": token,
            "actor_id": actor_id,
            "run_id": run_id,
        }
        try:
            with staging_path.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(staging, ensure_ascii=False, indent=2) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.chmod(staging_path, 0o600)
            except OSError:
                pass
            with self.store.transaction() as conn:
                current = conn.execute(
                    "SELECT credential_hash,active,actor_kind,principal_kind FROM actors "
                    "WHERE actor_id=?",
                    (actor_id,),
                ).fetchone()
                if (
                    not current
                    or not current["active"]
                    or current["actor_kind"] != "maintenance_agent"
                    or current["principal_kind"] != "service"
                    or current["credential_hash"] != actor["credential_hash"]
                ):
                    raise PermissionError("The bootstrap maintenance principal changed during recovery")
                conn.execute(
                    "UPDATE actors SET credential_hash=? WHERE actor_id=?",
                    (credential_hash(token), actor_id),
                )
                self.store.audit(
                    conn,
                    actor="trusted-host:issuectl",
                    action="identity.recover_bootstrap_credential",
                    object_type="actor",
                    object_id=actor_id,
                    before_revision=None,
                    after_revision=None,
                    reason=reason,
                    payload={"run_id": run_id, "grant_changed": False},
                )
        except Exception:
            if staging_path.exists():
                staging_path.unlink()
            raise
        try:
            os.replace(staging_path, token_path)
        except OSError as exc:
            # Keep the staged token so the same trusted-host command can finish atomically
            # after a filesystem interruption without changing the ledger a second time.
            raise ValidationError("Recovery was audited; rerun to finalize its staged credential") from exc
        return {"actor_id": actor_id, "run_id": run_id, "credential_path": str(token_path)}

    def issue_actor(
        self,
        *,
        actor_id: str,
        actor_kind: str | None = None,
        capabilities: set[str],
        profiles: set[str] | None = None,
        principal_kind: str | None = None,
        platform_id: str | None = None,
        maintenance_credential: str | Path,
    ) -> dict[str, Any]:
        issuer = self.resolve(maintenance_credential, "identity.manage")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", actor_id):
            raise ValidationError("actor_id contains unsupported characters")
        if principal_kind not in {None, "ai_agent", "service", "human"}:
            raise ValidationError(f"Unknown principal kind: {principal_kind}")
        if actor_kind is None:
            if principal_kind == "service":
                actor_kind = "maintenance_agent"
            elif profiles == {"reviewer"}:
                actor_kind = "review_agent"
            else:
                actor_kind = "organizer_agent"
        if actor_kind not in {
            "experiment_agent",
            "organizer_agent",
            "review_agent",
            "maintenance_agent",
        }:
            raise ValidationError(f"Unknown actor kind: {actor_kind}")
        profiles = profiles or set()
        unknown_profiles = profiles - set(CAPABILITY_PROFILES)
        if unknown_profiles:
            raise ValidationError(f"Unknown capability profiles: {sorted(unknown_profiles)}")
        capabilities = set(capabilities)
        for profile in profiles:
            capabilities.update(CAPABILITY_PROFILES[profile])
        if principal_kind == "human" and actor_kind != "organizer_agent":
            raise ValidationError("Human editor principals require the organizer role")
        if principal_kind == "human" and (
            not capabilities <= DESKTOP_EDITOR_CAPABILITIES or profiles or platform_id
        ):
            raise PermissionError("Human editor principals are limited to basic project editing")
        unknown = capabilities - ALL_WRITE_CAPABILITIES
        if unknown:
            raise ValidationError(f"Unknown capabilities: {sorted(unknown)}")
        if self.store.row("SELECT actor_id FROM actors WHERE actor_id=?", (actor_id,)):
            raise ValidationError(f"Actor already exists: {actor_id}")
        if platform_id:
            platform = self.store.row(
                "SELECT status FROM platform_sources WHERE platform_id=?", (platform_id,)
            )
            if not platform or platform["status"] != "active":
                raise ValidationError(f"Active platform source not found: {platform_id}")
        if profiles & {"platform-evidence-executor", "experiment-capture"} and not platform_id:
            raise ValidationError("Platform evidence principals require platform_id")
        if platform_id and not {
            "evidence.manifest.submit",
            "evidence.request.execute",
        } & capabilities:
            raise ValidationError(
                "A platform-scoped principal must have a platform evidence capability"
            )
        token = secrets.token_urlsafe(32)
        run_id = new_id("run")
        token_path = self.store.ledger_dir / "credentials" / f"{actor_id}.token"
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO actors(actor_id,actor_kind,display_name,credential_hash,active,created_at,"
                "principal_kind,metadata_json,platform_id) VALUES (?,?,?,?,1,?,?, '{}',?)",
                (
                    actor_id,
                    actor_kind,
                    actor_id,
                    credential_hash(token),
                    now(),
                    principal_kind
                    or ("service" if actor_kind == "maintenance_agent" else "ai_agent"),
                    platform_id,
                ),
            )
            conn.executemany(
                "INSERT INTO actor_capabilities VALUES (?,?,?)",
                [(actor_id, capability, now()) for capability in sorted(capabilities)],
            )
            conn.execute(
                "INSERT INTO agent_runs VALUES (?,?,NULL,'[]',?,NULL)",
                (run_id, actor_id, now()),
            )
            conn.executemany(
                "INSERT INTO principal_profile_assignments VALUES (?,?,?,?)",
                [(actor_id, profile, now(), issuer.actor_id) for profile in sorted(profiles)],
            )
            self.store.audit(
                conn,
                actor=issuer.actor_id,
                action="identity.issue",
                object_type="actor",
                object_id=actor_id,
                before_revision=None,
                after_revision=1,
                reason="",
                payload={
                    "actor_kind": actor_kind,
                    "principal_kind": principal_kind or "ai_agent",
                    "profiles": sorted(profiles),
                    "capabilities": sorted(capabilities),
                    "run_id": run_id,
                    "platform_id": platform_id,
                },
            )
        token_path.write_text(
            json.dumps({"token": token, "actor_id": actor_id, "run_id": run_id}, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        try:
            os.chmod(token_path, 0o600)
        except OSError:
            pass
        return {
            "actor_id": actor_id,
            "actor_kind": actor_kind,
            "principal_kind": principal_kind
            or ("service" if actor_kind == "maintenance_agent" else "ai_agent"),
            "profiles": sorted(profiles),
            "capabilities": sorted(capabilities),
            "run_id": run_id,
            "platform_id": platform_id,
            "credential_path": str(token_path),
        }

    def issue_run_token(
        self,
        *,
        actor_id: str,
        run_id: str,
        capabilities: set[str],
        ttl_seconds: int,
        maintenance_credential: str | Path,
    ) -> dict[str, Any]:
        issuer = self.resolve(maintenance_credential, "identity.manage")
        actor = self.store.row("SELECT * FROM actors WHERE actor_id=? AND active=1", (actor_id,))
        run = self.store.row(
            "SELECT * FROM agent_runs WHERE run_id=? AND actor_id=? AND ended_at IS NULL",
            (run_id, actor_id),
        )
        if not actor or not run:
            raise ValidationError("Run token requires an active principal and run")
        granted = {
            row["capability"]
            for row in self.store.rows(
                "SELECT capability FROM actor_capabilities WHERE actor_id=?", (actor_id,)
            )
        }
        if not capabilities or not capabilities <= granted:
            raise PermissionError(
                "Run token capabilities must be a non-empty subset of the principal grants"
            )
        ttl_seconds = max(1, min(int(ttl_seconds), 24 * 60 * 60))
        issued = int(time.time())
        token_id = new_id("token")
        nonce = secrets.token_urlsafe(18)
        token_epoch = int(self.store.manager_metadata()["token_epoch"])
        payload = {
            "v": 1,
            "jti": token_id,
            "sub": actor_id,
            "run_id": run_id,
            "cap": sorted(capabilities),
            "iat": issued,
            "exp": issued + ttl_seconds,
            "nonce": nonce,
            "epoch": token_epoch,
            "platform_id": actor.get("platform_id"),
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        signature = hmac.new(self.store.secret, raw, hashlib.sha256).hexdigest()
        token = f"run1.{encoded}.{signature}"
        with self.store.transaction() as conn:
            conn.execute(
                "INSERT INTO service_tokens(token_id,actor_id,run_id,nonce,capabilities_json,"
                "issued_at,expires_at,revoked_at,token_epoch,platform_id) "
                "VALUES (?,?,?,?,?,?,?,NULL,?,?)",
                (
                    token_id,
                    actor_id,
                    run_id,
                    nonce,
                    canonical_json(sorted(capabilities)),
                    now(),
                    datetime.fromtimestamp(issued + ttl_seconds)
                    .astimezone()
                    .isoformat(timespec="seconds"),
                    token_epoch,
                    actor.get("platform_id"),
                ),
            )
            self.store.audit(
                conn,
                actor=issuer.actor_id,
                action="identity.issue_run_token",
                object_type="service_token",
                object_id=token_id,
                before_revision=None,
                after_revision=1,
                reason="",
                payload={
                    "actor_id": actor_id,
                    "run_id": run_id,
                    "capabilities": sorted(capabilities),
                    "ttl_seconds": ttl_seconds,
                    "platform_id": actor.get("platform_id"),
                },
            )
        return {
            "token_id": token_id,
            "token": token,
            "actor_id": actor_id,
            "run_id": run_id,
            "capabilities": sorted(capabilities),
            "expires_at_epoch": issued + ttl_seconds,
            "token_epoch": token_epoch,
            "platform_id": actor.get("platform_id"),
        }

    def revoke_run_token(
        self, token_id: str, *, maintenance_credential: str | Path
    ) -> dict[str, Any]:
        issuer = self.resolve(maintenance_credential, "identity.manage")
        token = self.store.row("SELECT * FROM service_tokens WHERE token_id=?", (token_id,))
        if not token:
            raise ValidationError(f"Run token not found: {token_id}")
        if token["revoked_at"]:
            return {"token_id": token_id, "revoked_at": token["revoked_at"], "existing": True}
        revoked_at = now()
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE service_tokens SET revoked_at=? WHERE token_id=? AND revoked_at IS NULL",
                (revoked_at, token_id),
            )
            self.store.audit(
                conn,
                actor=issuer.actor_id,
                action="identity.revoke_run_token",
                object_type="service_token",
                object_id=token_id,
                before_revision=1,
                after_revision=2,
                reason="",
                payload={"actor_id": token["actor_id"], "run_id": token["run_id"]},
            )
        return {"token_id": token_id, "revoked_at": revoked_at, "existing": False}
