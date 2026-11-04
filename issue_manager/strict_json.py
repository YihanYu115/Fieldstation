from __future__ import annotations

import json
import math
from typing import Any

from .errors import StrictJSONError


def json_value_errors(value: Any, *, path: str = "$") -> list[dict[str, str]]:
    """Return stable findings for values that cannot be represented by strict JSON."""
    errors: list[dict[str, str]] = []
    active: set[int] = set()

    def visit(item: Any, item_path: str) -> None:
        if item is None or isinstance(item, (str, bool, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                errors.append(
                    {
                        "path": item_path,
                        "code": "non_finite_number",
                        "message": "number must be finite",
                    }
                )
            return
        if isinstance(item, (list, tuple, dict)):
            identity = id(item)
            if identity in active:
                errors.append(
                    {
                        "path": item_path,
                        "code": "cyclic_reference",
                        "message": "JSON values cannot contain cycles",
                    }
                )
                return
            active.add(identity)
            if isinstance(item, (list, tuple)):
                for index, child in enumerate(item):
                    visit(child, f"{item_path}[{index}]")
            else:
                for key, child in item.items():
                    if not isinstance(key, str):
                        errors.append(
                            {
                                "path": item_path,
                                "code": "object_key_not_string",
                                "message": "object keys must be strings",
                            }
                        )
                        continue
                    child_path = f"{item_path}.{key}" if key else f"{item_path}['']"
                    visit(child, child_path)
            active.remove(identity)
            return
        errors.append(
            {
                "path": item_path,
                "code": "json_type_invalid",
                "message": f"unsupported JSON value type: {type(item).__name__}",
            }
        )

    visit(value, path)
    return errors


def require_strict_json(value: Any, *, path: str = "$") -> None:
    errors = json_value_errors(value, path=path)
    if errors:
        raise StrictJSONError(
            "JSON value is not standards-compliant",
            code=errors[0]["code"],
            details={"errors": errors},
        )


def strict_json_dumps(
    value: Any,
    *,
    ensure_ascii: bool = False,
    sort_keys: bool = True,
    separators: tuple[str, str] | None = (",", ":"),
    indent: int | None = None,
) -> str:
    require_strict_json(value)
    return json.dumps(
        value,
        ensure_ascii=ensure_ascii,
        sort_keys=sort_keys,
        separators=separators if indent is None else None,
        indent=indent,
        allow_nan=False,
    )


def strict_json_loads(value: str | bytes | bytearray, *, path: str = "$") -> Any:
    try:
        parsed = json.loads(
            value,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant {constant}")
            ),
        )
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        message = str(exc)
        if "non-finite JSON constant" in message:
            raise StrictJSONError(
                "JSON value is not standards-compliant",
                code="non_finite_number",
                details={
                    "errors": [
                        {
                            "path": path,
                            "code": "non_finite_number",
                            "message": "number must be finite",
                        }
                    ]
                },
            ) from exc
        raise
    require_strict_json(parsed, path=path)
    return parsed
