from __future__ import annotations

from .errors import ValidationError

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "none": frozenset({"draft", "provisional"}),
    "draft": frozenset({"draft", "provisional", "retracted"}),
    "provisional": frozenset(
        {"provisional", "accepted", "canonical", "disputed", "superseded", "retracted"}
    ),
    "accepted": frozenset({"accepted", "canonical", "disputed", "superseded", "retracted"}),
    "canonical": frozenset({"canonical", "disputed", "superseded", "retracted"}),
    "disputed": frozenset({"disputed", "accepted", "superseded", "retracted"}),
    "superseded": frozenset(),
    "retracted": frozenset(),
}


def validate_transition(current: str, target: str) -> str:
    allowed = ALLOWED_TRANSITIONS.get(current)
    if allowed is None or target not in allowed:
        choices = ", ".join(sorted(allowed or ())) or "none"
        raise ValidationError(
            f"Illegal conclusion transition {current!r} -> {target!r}; allowed targets: {choices}"
        )
    if current == target:
        return "revise"
    return f"{current}_to_{target}"
