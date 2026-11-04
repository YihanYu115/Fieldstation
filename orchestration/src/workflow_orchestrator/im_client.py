"""IM-only public HTTP and per-action recovery. No Queue identity or workflow state."""
from __future__ import annotations

import hashlib
import http.client
import os
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

from .client import WorkflowClient
from .tools_contracts import ToolError, canonical, decode, fail
from .tools_journal import ActionJournal


class IMError(ToolError):
    details: dict[str, Any]

    def result(self) -> dict[str, Any]:
        value = super().result()
        value['error']['details'] = self.details
        return value


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


# These responses can come from a gateway before or after the original commit.
TEMPORARY_HTTP = frozenset({408, 425, 429})


def _http_error(status: int, payload: bytes, *, write: bool) -> IMError:
    uncertain = 'unknown' if write else 'not_committed'
    try:
        value = decode(payload) if len(payload) <= 262144 else None
    except ToolError:
        value = None
    if (not isinstance(value, dict) or not isinstance(value.get('error'), str) or not value['error']
            or not isinstance(value.get('message'), str) or not value['message']
            or not isinstance(value.get('details', {}), dict)):
        error = IMError('invalid_response', 'IM returned an unrecognized HTTP error',
                        status=status, effect=uncertain)
        error.details = {'http_status': status, 'response_kind': 'unrecognized_error'}
        return error
    definitive = 400 <= status < 500 and status not in TEMPORARY_HTTP
    error = IMError(value['error'], value['message'], status=status,
                    effect='not_committed' if definitive else uncertain)
    error.details = value.get('details', {})
    return error


class IMClient(WorkflowClient):
    """Reuse reviewed finite IM routes, hardening transport and persisting actual headers.

    IM has no public ledger UUID/subject handshake. Exact credential fingerprint +
    host authorization-source binding detects replacement, but not a swapped ledger
    at the same endpoint or a server-side reassignment of the same credential.
    """
    def __init__(self, endpoint: str, token: str, journal_path: str | Path, *,
                 token_env: str = 'IM_TOKEN', timeout: float = 8):
        url = urlsplit(endpoint)
        if (url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password
                or url.path not in {'', '/'} or url.query or url.fragment):
            fail('invalid_configuration', 'endpoint must be a fixed HTTP(S) service origin')
        if not token or not token.isascii() or any(c.isspace() for c in token):
            fail('invalid_configuration', 'host must inject a bearer token')
        if not 0 < timeout <= 60:
            fail('invalid_configuration', 'timeout must be in (0,60] seconds')
        super().__init__(endpoint.rstrip('/'), token, timeout=timeout)
        self.binding = {'surface': 'im', 'endpoint': self.base_url, 'token_env': token_env,
                        'credential_sha256': hashlib.sha256(token.encode('ascii')).hexdigest()}
        self.journal = ActionJournal(journal_path)
        self.journal.bind(self.binding)

    @classmethod
    def from_connection(cls, connection: dict[str, str], journal_path: str | Path) -> IMClient:
        if set(connection) != {'endpoint', 'token_env'}:
            fail('invalid_configuration', 'IM connection requires endpoint and token_env')
        return cls(connection['endpoint'], os.environ.get(connection['token_env'], ''), journal_path,
                   token_env=connection['token_env'])

    def _request(self, method, route, body=None, *, idempotency_key=None, request_id=None):
        headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + self.token,
                   'X-Request-ID': request_id or str(uuid4())}
        if method != 'GET':
            if not request_id or not idempotency_key:
                fail('invalid_input', 'IM writes require persisted request and idempotency identities')
            headers.update({'Idempotency-Key': idempotency_key, 'Content-Type': 'application/json'})
        request = Request(self.base_url + route, method=method, headers=headers,
                          data=None if body is None else canonical(body).encode('utf-8'))
        effect = 'unknown' if method == 'POST' else 'not_committed'
        try:
            with build_opener(NoRedirect()).open(request, timeout=self.timeout) as response:
                payload = response.read(2 * 1024 * 1024 + 1)
                if len(payload) > 2 * 1024 * 1024:
                    raise ToolError('invalid_response', 'IM response exceeds finite read bound', effect=effect)
                value = decode(payload)
                if not isinstance(value, dict) or not isinstance(value.get('result'), dict):
                    raise ToolError('invalid_response', 'IM result envelope is absent or invalid',
                                    status=response.status, effect=effect)
                return value['result']
        except HTTPError as exc:
            try:
                payload = exc.read(262145)
            except (OSError, http.client.HTTPException):
                raise ToolError('transport_unknown', 'IM HTTP error response is incomplete; recover original',
                                status=exc.code, effect=effect) from None
            finally:
                exc.close()
            # decode() raises ToolError; a sibling except cannot catch errors
            # raised inside this handler.
            raise _http_error(exc.code, payload, write=method == 'POST') from None
        except (URLError, TimeoutError, OSError, http.client.HTTPException):
            raise ToolError('transport_unknown', 'IM response unavailable; recover the original delivery', effect=effect) from None
        except ToolError as exc:
            if exc.code == 'invalid_input':
                raise ToolError('invalid_response', 'IM response is not valid JSON',
                                status=response.status, effect=effect) from None
            raise

    def begin(self, action: str, path: str, body: dict[str, Any], *,
              continuation: dict[str, Any] | None = None) -> str:
        operation_id = 'im-' + uuid4().hex
        step = self._step(path, body)
        intent = {'delivery_id': operation_id, 'action': action, 'binding': self.binding, 'steps': [step],
                  'continuation': continuation, 'state': 'pending'}
        intent['intent_sha256'] = digest({k: intent[k] for k in ('delivery_id', 'action', 'binding', 'continuation')})
        with self.journal.lock():
            value = self.journal.load()
            self._bound(value)
            value['actions'][operation_id] = intent
            try:
                self.journal.save(value)
            except OSError:
                raise ToolError('journal_write_failed', 'intent was not persisted; no POST sent') from None
        return operation_id

    @staticmethod
    def _step(path, body):
        step = {'path': path, 'body': body, 'request_id': 'req-' + uuid4().hex,
                'idempotency_key': 'key-' + uuid4().hex, 'sent': False}
        step['sha256'] = digest({k: step[k] for k in ('path', 'body', 'request_id', 'idempotency_key')})
        return step

    def _bound(self, value):
        if (value['binding'] != self.binding or self.base_url != self.binding['endpoint']
                or hashlib.sha256(self.token.encode('ascii')).hexdigest() != self.binding['credential_sha256']):
            raise ToolError('recovery_binding_changed', 'original IM connection/authorization source changed', effect='unknown')

    @staticmethod
    def _validate(intent):
        if intent['intent_sha256'] != digest({k: intent[k] for k in ('delivery_id', 'action', 'binding', 'continuation')}):
            raise ToolError('intent_conflict', 'original IM action identity changed', effect='unknown')
        for step in intent['steps']:
            if step['sha256'] != digest({k: step[k] for k in ('path', 'body', 'request_id', 'idempotency_key')}):
                raise ToolError('intent_conflict', 'original body, target or HTTP identity changed', effect='unknown')

    def status(self, operation_id):
        with self.journal.lock():
            value = self.journal.load()
            self._bound(value)
            intent = value['actions'].get(operation_id)
            if intent is None:
                fail('not_found', 'original IM delivery is absent', status=404)
            self._validate(intent)
            if intent['delivery_id'] != operation_id:
                raise ToolError('intent_conflict', 'original delivery ID changed', effect='unknown')
            return {'delivery_id': operation_id, 'state': intent['state'],
                    'action': intent['action'], 'receipt': intent.get('receipt'),
                    'error': intent.get('error'), 'current_state_verified': False,
                    'requests': [{k: row[k] for k in ('path', 'body', 'request_id', 'idempotency_key', 'sent')}
                                 for row in intent['steps']]}

    def recover(self, operation_id):
        with self.journal.lock():
            value = self.journal.load()
            self._bound(value)
            intent = value['actions'].get(operation_id)
            if intent is None:
                fail('not_found', 'original IM delivery is absent', status=404)
            self._validate(intent)
            if intent['delivery_id'] != operation_id:
                raise ToolError('intent_conflict', 'original delivery ID changed', effect='unknown')
            if intent['binding'] != self.binding:
                raise ToolError('recovery_binding_changed', 'original action binding changed', effect='unknown')
            if intent['state'] == 'confirmed':
                return dict(intent['receipt'])
            if intent['state'] == 'rejected':
                error = intent['error']
                rejection = IMError(error['code'], error['message'], effect=error['effect'], operation_id=operation_id)
                rejection.details = error.get('details', {})
                raise rejection
            while True:
                step = intent['steps'][-1]
                if 'result' not in step:
                    previously_sent = step['sent']
                    step['sent'] = True
                    try:
                        self.journal.save(value)
                    except OSError:
                        raise ToolError('journal_write_failed', 'send intent was not persisted; no new POST sent',
                                        effect='unknown' if previously_sent else 'not_committed',
                                        operation_id=operation_id) from None
                    try:
                        result = self._request('POST', step['path'], step['body'],
                                               request_id=step['request_id'], idempotency_key=step['idempotency_key'])
                    except ToolError as exc:
                        exc.operation_id = operation_id
                        if (not isinstance(exc, IMError) or exc.status in TEMPORARY_HTTP
                                or exc.status >= 500 or (previously_sent and exc.status in {401, 403})):
                            # Transport failure cannot prove rejection; current
                            # authentication failure cannot deny a previous send.
                            exc.effect = 'unknown'
                        if exc.effect != 'unknown':
                            intent.update(state='rejected', error=exc.result()['error'])
                            try:
                                self.journal.save(value)
                            except OSError:
                                pass  # Original persisted pending intent remains recoverable.
                        raise
                    step['result'] = result
                    try:
                        self.journal.save(value)
                    except OSError:
                        raise ToolError('journal_write_failed', 'IM replied but receipt was not saved; recover original',
                                        effect='unknown', operation_id=operation_id) from None
                try:
                    next_step = self._next(intent)
                except ToolError as exc:
                    exc.operation_id = operation_id
                    intent.update(state='rejected', error=exc.result()['error'])
                    self.journal.save(value)
                    raise
                except (KeyError, TypeError):
                    raise ToolError('invalid_response', 'IM continuation response is incomplete; recover original',
                                    effect='unknown', operation_id=operation_id) from None
                if next_step is not None:
                    intent['steps'].append(next_step)
                    try:
                        self.journal.save(value)
                    except OSError:
                        raise ToolError('journal_write_failed', 'continuation not persisted; recover original',
                                        effect='unknown', operation_id=operation_id) from None
                    continue
                receipt = {**step['result'], 'delivery_id': operation_id,
                           'current_state_verified': False, 'scientific_validity': 'not_assessed'}
                if intent['action'] == 'submit_field_packet':
                    receipt['packet_ref'] = 'packet:' + receipt['packet_id']
                    receipt['read'] = {'tool': 'read_field_packet', 'arguments': {'packet_id': receipt['packet_id']}}
                elif intent['action'] == 'curate_field_item':
                    receipt['read'] = {'tool': 'read_field_fact', 'arguments': {
                        'packet_id': receipt['packet_id'], 'fact_ref': receipt['fact_ref']}}
                intent.update(state='confirmed', receipt=receipt)
                try:
                    self.journal.save(value)
                except OSError:
                    raise ToolError('journal_write_failed', 'final receipt not persisted; recover original',
                                    effect='unknown', operation_id=operation_id) from None
                return receipt

    def _next(self, intent):
        """Only the finite prepare -> view -> conclusion contract has continuation writes."""
        from urllib.parse import quote
        flow = intent['continuation']
        if flow is None:
            return None
        steps = intent['steps']
        if len(steps) == 1:
            package = steps[0]['result']
            return self._step('/v1/currentness/packages/' + quote(package['package_id'], safe='') + '/views', {})
        if len(steps) == 2:
            package, view = (row['result'] for row in steps)
            roots = flow['evidence_ids']
            summary = package.get('actual_input', {}).get('summary', {})
            if (package.get('descriptor', {}).get('version') != 'context-currentness/scoped-v2'
                    or not roots or not set(roots) <= set(summary.get('support_ids', []))):
                raise ToolError('frozen_basis_unavailable', 'selected roots are not available in the original frozen package',
                                operation_id=flow['delivery_id'] if 'delivery_id' in flow else None)
            body = {**flow['body'], 'package_id': package['package_id'], 'view_id': view['view_id'],
                    'evidence_refs': roots}
            return self._step('/v1/issues/' + quote(body['issue_id'], safe='') + '/working-conclusion', body)
        return None

    def recover_pending(self):
        with self.journal.lock():
            ids = [key for key, row in self.journal.load()['actions'].items() if row['state'] == 'pending']
        results = []
        for key in ids:
            try:
                results.append(self.recover(key))
            except ToolError as exc:
                results.append(exc.result())
        return results
