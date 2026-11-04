class IssueManagerError(Exception):
    """Base class for errors that are safe to show to CLI callers."""

    code = "internal_error"

    def __init__(self, message: str, *, details: dict | None = None):
        super().__init__(message)
        self.details = details or {}


class NotFoundError(IssueManagerError):
    code = "not_found"


class ValidationError(IssueManagerError):
    code = "validation_error"


class StrictJSONError(ValidationError):
    """Stable strict-JSON boundary error whose code identifies the first violation."""

    def __init__(self, message: str, *, code: str, details: dict | None = None):
        super().__init__(message, details=details)
        self.code = code


class ConflictError(IssueManagerError):
    code = "conflict"


class OverviewTooLargeError(ConflictError):
    code = "overview_too_large"


class PermissionError(IssueManagerError):
    code = "permission_denied"


class StaleRevisionError(ConflictError):
    code = "stale_revision"


class ReviewRequiredError(PermissionError):
    code = "review_required"


class LeaseExpiredError(ConflictError):
    code = "lease_expired"


class IdempotencyConflictError(ConflictError):
    code = "idempotency_conflict"


class MaintenanceModeError(ConflictError):
    code = "maintenance_mode"


class IntegrityFailureError(IssueManagerError):
    code = "integrity_failure"


class EvidencePlatformMismatchError(PermissionError):
    code = "evidence_platform_mismatch"


class EvidenceSourceUnboundError(ConflictError):
    code = "evidence_source_unbound"


class EvidenceBindingConflictError(ConflictError):
    code = "evidence_binding_conflict"


class BindingReviewRequiredError(ReviewRequiredError):
    code = "binding_review_required"


class EvidenceIdentityConflictError(ConflictError):
    code = "evidence_identity_conflict"


class EvidenceIdentityInvariantError(ConflictError):
    code = "evidence_identity_invariant_failed"


class EvidenceIdentityAmbiguityError(ConflictError):
    code = "evidence_identity_ambiguity"


class LocatorIdentityInvalidError(ValidationError):
    code = "locator_identity_invalid"


class PlatformL0IdentityConflictError(ConflictError):
    code = "platform_l0_identity_conflict"


class IdentityAlgorithmMismatchError(ConflictError):
    code = "identity_algorithm_mismatch"


class MigrationAtomicityError(ConflictError):
    code = "migration_atomicity_failed"


class MigrationResolutionError(ConflictError):
    """A migration finding could not be proven resolved."""

    code = "migration_resolution_rejected"


class MigrationResolutionStaleError(MigrationResolutionError):
    code = "migration_resolution_stale"


class ConflictBindingError(ConflictError):
    """A governed conflict operation no longer matches its frozen subject."""

    code = "conflict_changeset_binding_mismatch"


class AdapterExecutionError(ConflictError):
    """Stable, bounded failure raised by a local executable Adapter."""

    def __init__(self, message: str, *, code: str, details: dict | None = None):
        super().__init__(message, details=details)
        self.code = code


class AdapterOutputError(ValidationError):
    """Stable Adapter output/limit failure rejected at the trust boundary."""

    def __init__(self, message: str, *, code: str, details: dict | None = None):
        super().__init__(message, details=details)
        self.code = code


class RendererEnvelopeError(ValidationError):
    """Stable validation failure for a report Renderer output envelope."""

    code = "adapter_output_schema_invalid"


class ManifestPlatformMismatchError(PermissionError):
    code = "manifest_platform_mismatch"


class ManifestRevisionStaleError(ConflictError):
    code = "manifest_revision_stale"


class AttestationPlatformMismatchError(PermissionError):
    code = "attestation_platform_mismatch"


class AttestationManifestStaleError(ConflictError):
    code = "attestation_manifest_stale"


class CrossPlatformSupersedeForbiddenError(PermissionError):
    code = "cross_platform_supersede_forbidden"


class ArtifactPlatformMismatchError(ValidationError):
    code = "artifact_platform_mismatch"


class AnalysisPlatformMismatchError(ValidationError):
    code = "analysis_platform_mismatch"


class ProofIncoherentError(ConflictError):
    code = "proof_incoherent"


class PrivateResourceForbiddenError(PermissionError):
    code = "private_resource_forbidden"


class CycleError(ValidationError):
    def __init__(self, message: str, path: list[str]):
        super().__init__(message)
        self.path = path
