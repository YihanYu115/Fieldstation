from __future__ import annotations

import hashlib
import json
import unicodedata
import warnings
from typing import Any

IDENTITY_ALGORITHM = "locator-v2-exact"
LOCATOR_IDENTITY_VERSION = 2


def identity_locator(locator: str) -> str:
    """Validate and return the exact authoritative locator used for identity.

    Locator identity is deliberately lossless: no trimming, case folding, Unicode
    normalization, URL decoding, or path resolution is performed.
    """
    if not isinstance(locator, str):
        raise TypeError("Evidence locator must be a string")
    if locator == "":
        raise ValueError("Evidence locator cannot be empty")
    try:
        locator.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Evidence locator must be UTF-8 encodable") from exc
    for character in locator:
        if character == "\x00" or (
            unicodedata.category(character) == "Cc" and character != "\t"
        ):
            raise ValueError("Evidence locator contains a disallowed control character")
    return locator


def search_normalize_locator(locator: str) -> str:
    """Return a fuzzy, search-only locator; never use this value for identity."""
    identity_locator(locator)
    return " ".join(locator.strip().split())


def normalize_locator(locator: str) -> str:
    """Deprecated v7 search normalization retained for SDK compatibility."""
    warnings.warn(
        "normalize_locator() is deprecated; use identity_locator() for identity or "
        "search_normalize_locator() for search",
        DeprecationWarning,
        stacklevel=2,
    )
    return search_normalize_locator(locator)


def _digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def platform_identity_key(platform_id: str, kind: str, locator: str) -> str:
    """Build the locator-v2 platform key, also used as the binding source_key."""
    return _digest(
        {
            "identity_algorithm": IDENTITY_ALGORITHM,
            "platform_id": platform_id,
            "kind": kind,
            "identity_locator": identity_locator(locator),
        }
    )


def legacy_identity_key(kind: str, locator: str) -> str:
    return _digest(
        {
            "identity_algorithm": IDENTITY_ALGORITHM,
            "identity_namespace": "legacy",
            "kind": kind,
            "identity_locator": identity_locator(locator),
        }
    )


def conflict_identity_key(evidence_id: str) -> str:
    return _digest(
        {
            "identity_algorithm": IDENTITY_ALGORITHM,
            "identity_namespace": "conflict",
            "evidence_id": evidence_id,
        }
    )


def platform_identity_key_v1(platform_id: str, kind: str, locator: str) -> str:
    """Return the deprecated locator-v1 key for local-cache migration only."""
    return _digest(
        {
            "platform_id": platform_id,
            "kind": kind,
            "locator": search_normalize_locator(locator),
        }
    )


def resolve_intake_identity(
    *,
    platform_id: str | None,
    kind: str,
    locator: str,
    manifest_platform_id: str | None = None,
) -> dict[str, Any]:
    """Resolve Intake identity from authenticated platform scope, never body scope."""
    exact = identity_locator(locator)
    search = search_normalize_locator(locator)
    if platform_id is not None and manifest_platform_id not in {None, platform_id}:
        raise ValueError("Manifest platform does not match authenticated platform")
    namespace = "platform" if platform_id is not None else "legacy"
    key = (
        platform_identity_key(platform_id, kind, exact)
        if platform_id is not None
        else legacy_identity_key(kind, exact)
    )
    return {
        "identity_namespace": namespace,
        "source_platform_id": platform_id,
        "identity_locator": exact,
        "search_locator": search,
        "normalized_locator": search,
        "identity_algorithm": IDENTITY_ALGORITHM,
        "locator_identity_version": LOCATOR_IDENTITY_VERSION,
        "identity_key": key,
    }
