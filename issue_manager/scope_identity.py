from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


def normalize_identity_term(value: str) -> str:
    """Normalize one human-facing scope identity component."""

    return re.sub(r"[^a-z0-9]+", "-", value.strip().casefold()).strip("-")


@dataclass(frozen=True, order=True)
class SampleKey:
    """Typed identity for the sample dimension only.

    A SampleKey must never be substituted with a complete ScopeKey: target,
    phase, and run dimensions deliberately do not participate in sample
    identity.
    """

    value: str

    @classmethod
    def from_raw(cls, value: Any) -> SampleKey | None:
        if value is None or isinstance(value, bool):
            return None
        if not isinstance(value, (str, int, float)):
            return None
        normalized = normalize_identity_term(str(value))
        return cls(normalized) if normalized else None

    @classmethod
    def from_scope(cls, scope: Mapping[str, Any] | None) -> SampleKey | None:
        return cls.from_raw(scope.get("sample")) if scope else None

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, order=True)
class ScopeKey:
    """Typed identity for the complete normalized Issue scope."""

    value: str

    @classmethod
    def from_scope(cls, scope: Mapping[str, Any] | None) -> ScopeKey | None:
        if not scope:
            return None
        ordered_keys = sorted(scope, key=lambda key: (key != "sample", key))
        parts: list[str] = []
        for key in ordered_keys:
            value = scope[key]
            if isinstance(value, list):
                if len(value) != 1:
                    continue
                value = value[0]
            if isinstance(value, (str, int, float)) and not isinstance(value, bool):
                normalized = normalize_identity_term(str(value))
                if normalized:
                    parts.append(normalized)
        return cls("/".join(parts)) if parts else None

    def __str__(self) -> str:
        return self.value
