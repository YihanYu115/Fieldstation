from __future__ import annotations

import hashlib
import json
from typing import Any


def semantic_manifest_parts(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "content_identity": manifest.get("content_identity", {}),
        "mutable_source": bool(manifest.get("mutable_source", False)),
        "observed_at": manifest.get("observed_at"),
        "sample_session_ref": manifest.get("sample_session_ref"),
        "data_profile": manifest.get("data_profile", {}),
        "execution": manifest.get("execution", {}),
        "adapter": manifest.get("adapter", {}),
        "preview_artifact_ids": sorted(manifest.get("preview_artifact_ids", [])),
        "extensions": manifest.get("extensions", {}),
        "summary": manifest.get("summary", {}),
        "namespaced_fields": {
            str(key): value for key, value in manifest.items() if ":" in str(key)
        },
    }


def semantic_manifest_fingerprint(manifest: dict[str, Any]) -> str:
    canonical = json.dumps(
        semantic_manifest_parts(manifest),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
