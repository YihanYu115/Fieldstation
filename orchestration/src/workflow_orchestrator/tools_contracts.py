"""Small JSON, error and host-bound authority contracts for independent tools."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

ACTIONS = frozenset({'publish_task', 'list_tasks', 'get_task', 'claim_task',
                     'reply_task', 'list_task_replies'})
WRITES = frozenset({'publish_task', 'claim_task', 'reply_task'})


class ToolError(Exception):
    def __init__(self, code: str, message: str, *, status: int = 400,
                 effect: str = 'not_committed', operation_id: str | None = None,
                 fields: list[dict[str, Any]] | None = None,
                 fields_truncated: bool | None = None):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status
        self.effect, self.operation_id = effect, operation_id
        self.fields = fields
        self.fields_truncated = fields_truncated

    def result(self) -> dict[str, Any]:
        error: dict[str, Any] = {'code': self.code, 'message': self.message,
                                 'effect': self.effect}
        if self.operation_id is not None:
            error['operation_id'] = self.operation_id
        if self.fields is not None:
            error['fields'] = self.fields
        if self.fields_truncated is not None:
            error['fields_truncated'] = self.fields_truncated
        return {'error': error}


def fail(code: str, message: str, *, status: int = 400) -> NoReturn:
    raise ToolError(code, message, status=status)


def canonical(value: Any) -> str:
    try:
        value = json.dumps(value, sort_keys=True, ensure_ascii=False,
                           separators=(',', ':'), allow_nan=False)
        value.encode('utf-8')
        return str(value)
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError):
        fail('invalid_input', 'value must be finite UTF-8 JSON')


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            fail('invalid_input', 'duplicate JSON field')
        result[key] = value
    return result


def decode(value: str | bytes) -> Any:
    try:
        result = json.loads(value, object_pairs_hook=_pairs)
        canonical(result)
        return result
    except (ValueError, UnicodeError, RecursionError):
        fail('invalid_input', 'invalid UTF-8 JSON')


def fields(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or not required <= value.keys():
        fail('invalid_input', 'missing required fields: ' + ', '.join(sorted(required)))
    if value.keys() - required - (optional or set()):
        fail('invalid_input', 'unexpected fields')
    return value


def text(value: Any, name: str, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        fail('invalid_input', f'{name} must be nonempty text of at most {maximum} characters')
    canonical(value)
    return value


def identifier(value: Any, name: str) -> str:
    value = text(value, name, 128)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', value):
        fail('invalid_input', f'{name} must be a finite name reference')
    return str(value)


def references(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > 30:
        fail('invalid_input', 'references must be a list of at most 30 strings')
    return [text(item, 'reference', 2048) for item in value]


def outside_path(value: str | Path) -> Path:
    path = Path(value)
    checkout = Path(__file__).resolve().parents[3]
    if not path.is_absolute() or path.resolve() == checkout or checkout in path.resolve().parents:
        fail('invalid_configuration', 'runtime path must be absolute and outside the package checkout')
    return path.resolve()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


@dataclass(frozen=True)
class Principal:
    principal_id: str
    actions: frozenset[str]

    def require(self, action: str, issue_id: str | None = None) -> None:
        if action not in self.actions:
            fail('forbidden', 'principal lacks the operation permission', status=403)
