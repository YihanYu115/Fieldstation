"""Finite HTTP client: per-action durable identity and original POST recovery."""
from __future__ import annotations

import http.client
import json
import os
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .tools_contracts import ToolError, canonical, decode, fail, identifier
from .tools_journal import ActionJournal


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ToolsClient:
    def __init__(self, endpoint: str, token: str, journal_path: str | Path, *, timeout: float = 5):
        url = urlsplit(endpoint)
        if (url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password
                or url.path not in {'', '/'} or url.query or url.fragment):
            fail('invalid_configuration', 'endpoint must be a fixed HTTP(S) service origin')
        if not token or not token.isascii() or any(c.isspace() for c in token):
            fail('invalid_configuration', 'host must inject a bearer token')
        if not 0 < timeout <= 60:
            fail('invalid_configuration', 'timeout must be greater than zero and at most 60 seconds')
        self.endpoint = endpoint.rstrip('/')
        self._token, self.timeout = token, timeout
        self.journal = ActionJournal(journal_path)
        # A persisted endpoint is checked before even contacting a replacement address.
        with self.journal.lock():
            journal_value = self.journal.load()
            saved = journal_value['binding']
            if saved is not None and saved['endpoint'] != self.endpoint:
                pending = any(action['state'] == 'pending' for action in journal_value['actions'].values())
                raise ToolError('recovery_binding_changed', 'original endpoint cannot be replaced', status=409,
                                effect='unknown' if pending else 'not_committed')
        identity = self._request('GET', '/v1/identity', bound=False)
        if (not isinstance(identity.get('service_id'), str)
                or not isinstance(identity.get('principal_id'), str) or 'queue' not in identity.get('modules', [])
                or identity.get('schema') != 'workflow-tools-queue-3'):
            fail('invalid_response', 'endpoint did not return a Queue identity')
        self.binding = {'endpoint': self.endpoint, 'service_id': identity['service_id'],
                        'principal_id': identity['principal_id'], 'schema': identity['schema']}
        self.journal.bind(self.binding)

    @classmethod
    def from_connection(cls, connection: dict[str, str], journal_path: str | Path) -> ToolsClient:
        if set(connection) != {'endpoint', 'token_env'}:
            fail('invalid_configuration', 'connection requires endpoint and token_env only')
        return cls(connection['endpoint'], os.environ.get(connection['token_env'], ''), journal_path)

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None,
                 *, bound: bool = True) -> dict[str, Any]:
        headers = {'Authorization': 'Bearer ' + self._token, 'Content-Type': 'application/json'}
        if bound:
            headers.update({'X-Workflow-Service-ID': self.binding['service_id'],
                            'X-Workflow-Principal-ID': self.binding['principal_id']})
        request = Request(self.endpoint + path, data=canonical(body).encode() if body is not None else None,
                          headers=headers, method=method)
        try:
            with build_opener(NoRedirect()).open(request, timeout=self.timeout) as response:
                payload = response.read(8 * 1024 * 1024 + 1)
                if len(payload) > 8 * 1024 * 1024:
                    fail('invalid_response', 'service response exceeds the finite page bound')
                value = decode(payload)
                if not isinstance(value, dict):
                    fail('invalid_response', 'service did not return an object')
                if bound and (response.headers.get('X-Workflow-Service-ID') != self.binding['service_id']
                              or response.headers.get('X-Workflow-Principal-ID') != self.binding['principal_id']):
                    raise ToolError('recovery_binding_changed', 'response identity differs from original binding',
                                    effect='unknown' if method == 'POST' else 'not_committed')
                return dict(value)
        except HTTPError as exc:
            try:
                error = json.loads(exc.read(262145))['error']
                raise ToolError(error['code'], error['message'], status=exc.code,
                                effect=error['effect'], operation_id=error.get('operation_id')) from None
            except (ValueError, KeyError, TypeError):
                raise ToolError('invalid_response', 'service returned an unrecognized error',
                                effect='unknown' if method == 'POST' else 'not_committed') from None
            finally:
                exc.close()
        except (URLError, TimeoutError, OSError, http.client.HTTPException):
            raise ToolError('transport_unknown', 'HTTP response unavailable; recover the original action',
                            effect='unknown' if method == 'POST' else 'not_committed') from None
        except ToolError as exc:
            if method == 'POST' and exc.code in {'invalid_response', 'invalid_input'}:
                exc.effect = 'unknown'
            raise

    def _verify(self) -> None:
        identity = self._request('GET', '/v1/identity')
        if (identity.get('service_id'), identity.get('principal_id')) != (
                self.binding['service_id'], self.binding['principal_id']):
            fail('recovery_binding_changed', 'service or principal changed', status=409)

    def read(self, action: str, **arguments: Any) -> dict[str, Any]:
        self._verify()
        if action == 'get_task':
            path = '/v1/queue/tasks/' + identifier(arguments['task_id'], 'task_id')
        elif action == 'list_tasks':
            path = '/v1/queue/tasks'
        elif action == 'list_task_replies':
            path = '/v1/queue/tasks/' + identifier(arguments.pop('task_id'), 'task_id') + '/replies'
        else:
            fail('invalid_input', 'unsupported read operation')
        if action != 'get_task':
            query = {key: str(value).lower() if isinstance(value, bool) else value
                     for key, value in arguments.items() if value is not None}
            if query:
                path += '?' + urlencode(query)
        return self._request('GET', path)

    def write(self, action: str, **arguments: Any) -> dict[str, Any]:
        if 'operation_id' in arguments or 'actor' in arguments:
            fail('invalid_input', 'operation identity and actor are managed by the host')
        if action == 'publish_task':
            path = '/v1/queue/tasks'
        elif action in {'claim_task', 'reply_task'}:
            path = '/v1/queue/tasks/' + identifier(arguments.pop('task_id'), 'task_id')
            path += '/claim' if action == 'claim_task' else '/replies'
        else:
            fail('invalid_input', 'unsupported write operation')
        self._verify()
        operation_id = 'op-' + uuid.uuid4().hex
        intent = {'action': action, 'path': path, 'body': {**arguments, 'operation_id': operation_id},
                  'state': 'pending', 'sent': False}
        with self.journal.lock():
            value = self.journal.load()
            value['actions'][operation_id] = intent
            try:
                self.journal.save(value)
            except OSError:
                raise ToolError('journal_write_failed', 'intent was not saved; no POST sent') from None
        try:
            return self.recover(operation_id)
        except ToolError as exc:
            if exc.operation_id is None:
                exc.operation_id = operation_id
            raise
        except Exception as exc:
            raise ToolError('tool_error', 'Recover the original operation', effect='unknown',
                            operation_id=operation_id) from exc

    def recover(self, operation_id: str) -> dict[str, Any]:
        # Lock protects each original action, including receipt persistence, across processes.
        with self.journal.lock():
            value = self.journal.load()
            if value['binding'] != self.binding:
                fail('recovery_binding_changed', 'journal binding changed', status=409)
            intent = value['actions'].get(operation_id)
            if intent is None:
                fail('not_found', 'original operation is absent from this journal', status=404)
            if intent['state'] == 'confirmed':
                self._verify()
                return dict(intent['receipt'])
            if intent['state'] == 'rejected':
                error = intent['error']
                raise ToolError(error['code'], error['message'], effect=error['effect'],
                                operation_id=operation_id)
            previous_send = intent.get('sent', False)
            try:
                self._verify()
                intent['sent'] = True
                try:
                    self.journal.save(value)
                except OSError:
                    raise ToolError('journal_write_failed', 'send intent was not persisted; no new POST sent',
                                    effect='unknown' if previous_send else 'not_committed') from None
                result = self._request('POST', intent['path'], intent['body'])
            except ToolError as exc:
                exc.operation_id = operation_id
                if previous_send and exc.code in {
                        'transport_unknown', 'recovery_binding_changed', 'service_identity_changed',
                        'principal_identity_changed', 'unauthorized', 'forbidden'}:
                    exc.effect = 'unknown'
                # A previous send can have committed. Identity/network failures do not close it.
                if exc.effect != 'unknown' and exc.code not in {
                        'transport_unknown', 'recovery_binding_changed', 'service_identity_changed',
                        'principal_identity_changed', 'unauthorized', 'forbidden'}:
                    intent.update(state='rejected', error=exc.result()['error'])
                    try:
                        self.journal.save(value)
                    except OSError:
                        raise ToolError('journal_write_failed', 'Rejection receipt was not saved; recover original operation',
                                        effect='unknown', operation_id=operation_id) from None
                raise
            intent.update(state='confirmed', receipt=result)
            try:
                self.journal.save(value)
            except OSError:
                raise ToolError('journal_write_failed', 'POST response received but receipt was not saved; '
                                'recover original operation', effect='unknown', operation_id=operation_id) from None
            return result

    def recover_pending(self) -> list[dict[str, Any]]:
        with self.journal.lock():
            pending = [key for key, value in self.journal.load()['actions'].items()
                       if value['state'] == 'pending']
        results = []
        for operation_id in pending:
            try:
                results.append(self.recover(operation_id))
            except ToolError as exc:
                results.append(exc.result())
        return results
