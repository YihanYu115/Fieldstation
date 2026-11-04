"""Validation of the finite schema accepted for Issue conclusion outputs.

This module contains no persistence or public API.  The caller must bind the
validated schema to an immutable rule version before using it for a write.
"""

from __future__ import annotations

import json
import math
from typing import Any

from .errors import ValidationError
from .registry_service import (
    _validate_json_schema_definition,
    validate_json_instance,
)
from .store import canonical_json
from .strict_json import require_strict_json

MAX_SCHEMA_BYTES = 32 * 1024


def validate_conclusion_rule_schema(schema: Any) -> dict[str, Any]:
    """Validate and copy a bounded object schema using the kernel's subset."""
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise ValidationError("Conclusion rule schema must have type object")
    require_strict_json(schema, path="$.schema")
    encoded = canonical_json(schema)
    if len(encoded.encode("utf-8")) > MAX_SCHEMA_BYTES:
        raise ValidationError("Conclusion rule schema exceeds 32768 UTF-8 bytes")
    _validate_json_schema_definition(schema, path="$.schema")
    _validate_bounds(schema, "$.schema")
    # Avoid retaining a caller-owned mutable reference to the rule definition.
    return json.loads(encoded)


def _validate_bounds(schema: dict[str, Any], path: str) -> None:
    """Reject bounds that the instance validator cannot safely evaluate."""
    for field in ("minimum", "maximum"):
        if field in schema:
            value = schema[field]
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or (isinstance(value, float) and not math.isfinite(value))):
                raise ValidationError(f"{path}.{field} must be a finite number")
    for field in ("minItems", "maxItems"):
        if field in schema and (type(schema[field]) is not int or schema[field] < 0):
            raise ValidationError(f"{path}.{field} must be a nonnegative integer")
    for lower, upper in (("minimum", "maximum"), ("minItems", "maxItems")):
        if lower in schema and upper in schema and schema[lower] > schema[upper]:
            raise ValidationError(f"{path}.{lower} must not exceed {upper}")
    if schema.get("type") == "object":
        for name, child in schema.get("properties", {}).items():
            _validate_bounds(child, f"{path}.properties.{name}")
    if schema.get("type") == "array":
        _validate_bounds(schema["items"], f"{path}.items")


def conclusion_rule_errors(outputs: Any, schema: dict[str, Any]) -> list[dict[str, str]]:
    """Return field-level errors without changing the rule or the outputs."""
    return validate_json_instance(outputs, schema, path="$.structured_outputs")


def bounded_rule_errors(errors: list[dict[str, str]]) -> dict[str, Any]:
    """Keep diagnostics useful and bounded without claiming they are complete."""
    fields = []
    truncated = len(errors) > 32
    for item in errors[:32]:
        path = str(item.get("path", ""))
        message = str(item.get("message", ""))
        code = str(item.get("code", ""))
        truncated |= len(path) > 512 or len(message) > 512 or len(code) > 80
        fields.append({"path": path[:512], "code": code[:80], "message": message[:512]})
    return {"field_errors": fields, "fields_truncated": truncated, "error_count": len(errors)}
