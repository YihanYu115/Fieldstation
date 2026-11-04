"""Bound finite JSON transport shared only by host client and original Queue claim."""
from __future__ import annotations

import http.client
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener

from .tools_client import NoRedirect
from .tools_contracts import ToolError, canonical, decode


def exchange(endpoint: str, token: str, method: str, path: str,
             body: dict[str, Any] | None = None, *, expected: dict[str, str] | None = None,
             timeout: float = 5) -> dict[str, Any]:
    effect = 'unknown' if method == 'POST' else 'not_committed'
    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json', **(expected or {})}
    request = Request(endpoint + path, method=method, headers=headers,
                      data=canonical(body).encode('utf-8') if body is not None else None)
    def matches(response_headers: Any) -> bool:
        return all(response_headers.get(k) == v for k, v in (expected or {}).items())
    try:
        with build_opener(NoRedirect()).open(request, timeout=timeout) as response:
            payload = response.read(2 * 1024 * 1024 + 1)
            if len(payload) > 2 * 1024 * 1024 or not matches(response.headers):
                raise ToolError('binding_or_response_changed', 'response identity or size differs', effect=effect)
            value = decode(payload)
            if not isinstance(value, dict) or 'error' in value:
                raise ToolError('invalid_response', 'unrecognized JSON response', effect=effect)
            return value
    except HTTPError as exc:
        try:
            payload = exc.read(262145)
            try:
                value = decode(payload) if len(payload) <= 262144 else None
            except ToolError:
                value = None
            error = value.get('error') if isinstance(value, dict) else None
            recognized = (isinstance(error, dict) and isinstance(error.get('code'), str)
                          and isinstance(error.get('message'), str)
                          and error.get('effect') in {'not_committed', 'unknown'})
            definitive = matches(exc.headers) and 400 <= exc.code < 500 and exc.code not in {408, 425, 429}
            if recognized and isinstance(error, dict):
                raise ToolError(error['code'], error['message'], status=exc.code,
                                effect=error['effect'] if definitive else effect) from None
            raise ToolError('invalid_response', 'unrecognized HTTP response', status=exc.code, effect=effect)
        except (OSError, http.client.HTTPException):
            raise ToolError('transport_unknown', 'HTTP response incomplete', effect=effect) from None
        finally:
            exc.close()
    except (URLError, OSError, TimeoutError, http.client.HTTPException):
        raise ToolError('transport_unknown', 'HTTP response unavailable; retain original request', effect=effect) from None
    except ToolError as exc:
        if exc.code == 'invalid_input':
            raise ToolError('invalid_response', 'response is not finite JSON', effect=effect) from None
        raise
