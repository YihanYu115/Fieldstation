"""Bound, read-only access to a single trusted Host's resource catalog."""
from __future__ import annotations

import os
from typing import Any

from .host_contracts import connection_binding
from .host_transport import exchange
from .tools_contracts import fail


def read_catalog(connection: dict[str, str], *, queue_only: bool = False,
                 timeout: float = 5) -> dict[str, Any]:
    if type(queue_only) is not bool or not 0 < timeout <= 60:
        fail('invalid_input', 'invalid catalog filter or timeout')
    binding = connection_binding(connection)
    endpoint, token = binding['endpoint'], os.environ[binding['token_env']]
    identity = exchange(endpoint, token, 'GET', '/v1/identity', timeout=timeout)
    if (identity.get('modules') != ['host'] or any(not isinstance(identity.get(k), str)
            for k in ('service_id', 'principal_id', 'principal_binding'))):
        fail('invalid_response', 'endpoint did not return a finite host identity')
    headers = {'X-Workflow-Service-ID': identity['service_id'],
               'X-Workflow-Principal-ID': identity['principal_id'],
               'X-Workflow-Host-Binding': identity['principal_binding']}
    if connection_binding(connection) != binding:
        fail('host_binding_changed', 'host connection or credential changed', status=409)
    result = exchange(endpoint, token, 'GET', '/v1/catalog/queue' if queue_only else '/v1/catalog',
                      expected=headers, timeout=timeout)
    if (result.get('service_id') != identity['service_id'] or result.get('scope') != 'this_host'
            or result.get('filter') != ('queue' if queue_only else 'all')
            or not isinstance(result.get('items'), list)):
        fail('invalid_response', 'invalid Host catalog response')
    return result
