"""Finite remote host client. Persist the caller's original request before sending."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .host_contracts import connection_binding, digest, normalize
from .host_transport import exchange
from .tools_contracts import ToolError, fail, identifier
from .tools_journal import ActionJournal


class HostClient:
    def __init__(self, connection: dict[str, str], journal_path: str | Path, *, timeout: float = 5):
        self.connection = {k: v for k, v in connection.items()}
        self.local = connection_binding(connection)
        self.endpoint, self.token = self.local['endpoint'], os.environ[self.local['token_env']]
        if not 0 < timeout <= 60:
            fail('invalid_configuration', 'timeout must be in (0,60] seconds')
        self.timeout = timeout
        self.journal = ActionJournal(journal_path)
        with self.journal.lock():
            saved = self.journal.load()['binding']
            if saved is not None and any(saved.get(k) != v for k, v in self.local.items()):
                fail('host_binding_changed', 'original host connection or credential source differs', status=409)
        identity = exchange(self.endpoint, self.token, 'GET', '/v1/identity', timeout=timeout)
        if (identity.get('modules') != ['host'] or any(not isinstance(identity.get(k), str)
                for k in ('service_id', 'principal_id', 'principal_binding'))):
            fail('invalid_response', 'endpoint did not return a finite host identity')
        self.binding = {**self.local, **identity}
        self.journal.bind(self.binding)

    @classmethod
    def from_connection(cls, connection: dict[str, str], journal_path: str | Path) -> HostClient:
        return cls(connection, journal_path)

    def _headers(self) -> dict[str, str]:
        return {'X-Workflow-Service-ID': self.binding['service_id'],
                'X-Workflow-Principal-ID': self.binding['principal_id'],
                'X-Workflow-Host-Binding': self.binding['principal_binding']}

    def _verify(self) -> None:
        if connection_binding(self.connection) != self.local:
            fail('host_binding_changed', 'original connection or credential changed', status=409)
        identity = exchange(self.endpoint, self.token, 'GET', '/v1/identity', expected=self._headers(), timeout=self.timeout)
        if {**self.local, **identity} != self.binding:
            fail('host_binding_changed', 'original host store or caller binding differs', status=409)

    def status(self) -> dict[str, Any]:
        self._verify()
        return exchange(self.endpoint, self.token, 'GET', '/v1/status', expected=self._headers(), timeout=self.timeout)

    def launch(self, request: dict[str, Any]) -> dict[str, Any]:
        request = normalize(request)
        request_id = request['request_id']
        with self.journal.lock():
            value = self.journal.load()
            if value['binding'] != self.binding:
                fail('host_binding_changed', 'journal host binding changed', status=409)
            intent = value['actions'].get(request_id)
            if intent is not None and (intent['request'] != request or intent['sha256'] != digest(request)):
                fail('idempotency_conflict', 'original request content/identity differs', status=409)
            if intent is None:
                value['actions'][request_id] = {'request': request, 'sha256': digest(request), 'state': 'pending', 'sent': False}
                try:
                    self.journal.save(value)
                except OSError:
                    raise ToolError('journal_write_failed', 'activation intent not saved; no POST sent') from None
        return self.replay(request_id)

    def replay(self, request_id: str) -> dict[str, Any]:
        request_id = identifier(request_id, 'request_id')
        with self.journal.lock():
            value = self.journal.load()
            intent = value['actions'].get(request_id)
            if value['binding'] != self.binding:
                fail('host_binding_changed', 'journal binding differs', status=409)
            if intent is None:
                fail('not_found', 'original request is absent', status=404)
            if intent['request']['request_id'] != request_id or digest(intent['request']) != intent['sha256']:
                fail('intent_conflict', 'original activation request differs', status=409)
            previous = intent['sent']
            try:
                try:
                    self._verify()
                except ToolError as exc:
                    # This GET cannot disprove any earlier original admission POST.
                    # Keep POST's own definitive errors separate from verification.
                    if previous:
                        exc.effect = 'unknown'
                    raise
                intent['sent'] = True
                # A new POST must not retain an earlier busy/rejection receipt.
                intent.pop('receipt', None)
                intent['state'] = 'pending'
                self.journal.save(value)
                result = exchange(self.endpoint, self.token, 'POST', '/v1/launches', intent['request'],
                                  expected=self._headers(), timeout=self.timeout)
                if result.get('outcome') not in {'accepted', 'busy'} or result.get('request_id') != request_id:
                    raise ToolError('invalid_response', 'unrecognized admission response', effect='unknown')
                if result['outcome'] == 'accepted' and not isinstance(result.get('run_id'), str):
                    raise ToolError('invalid_response', 'admission run identity is absent', effect='unknown')
                intent.update(state='confirmed' if result['outcome'] == 'accepted' else 'pending', receipt=result)
                self.journal.save(value)
                return result
            except ToolError as exc:
                if previous and exc.code in {'host_binding_changed', 'binding_or_response_changed', 'unauthorized', 'forbidden'}:
                    exc.effect = 'unknown'
                result = {'outcome': 'unknown' if exc.effect == 'unknown' else 'rejected',
                          'request_id': request_id, 'error': exc.result()['error']}
                if result['outcome'] == 'rejected':
                    intent['receipt'] = result
                    try:
                        self.journal.save(value)
                    except OSError:
                        return {'outcome': 'unknown', 'request_id': request_id,
                                'error': {'code': 'journal_write_failed', 'message': 'retain original request and query/replay', 'effect': 'unknown'}}
                return result
            except OSError:
                return {'outcome': 'unknown', 'request_id': request_id,
                        'error': {'code': 'journal_write_failed', 'message': 'retain original request and query/replay', 'effect': 'unknown'}}

    def by_request(self, request_id: str) -> dict[str, Any]:
        self._verify()
        return exchange(self.endpoint, self.token, 'GET', '/v1/launches/by-request/' + identifier(request_id, 'request_id'),
                        expected=self._headers(), timeout=self.timeout)
