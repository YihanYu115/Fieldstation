"""Thin script convenience API over Listener and the existing durable HostClient."""
from __future__ import annotations

import uuid
from typing import Any, Iterator

from .listener import Listener, local_binding
from .listener_state import digest
from .run_lock import exclusive
from .tools_contracts import ToolError, decode, fail, identifier
from .tools_journal import ActionJournal


class TriggerTools(Listener):
    def _journal(self, host: str) -> ActionJournal:
        identifier(host, 'host')
        return ActionJournal(self.state.root / 'hosts' / (digest(host) + '.json'))

    def _host(self, host: str) -> Any:
        from .host_client import HostClient
        if host not in self.connections:
            fail('invalid_configuration', 'unknown host connection: ' + host)
        return HostClient(self.connections[host], self._journal(host).path, timeout=self.timeout)

    def host_status(self, host_name: str) -> dict[str, Any]:
        result = self._host(host_name).status()
        if (result.get('scope') != 'this_host' or not isinstance(result.get('by_role'), dict)
                or type(result.get('active_runs')) is not int
                or any(type(v) is not int or v < 0 for v in result['by_role'].values())):
            fail('invalid_response', 'Host did not return actual scoped role counts')
        return dict(result)

    def _intent(self, action: dict[str, Any]) -> dict[str, Any] | None:
        journal = self._journal(action['host'])
        with journal.lock():
            return journal.load()['actions'].get(action['request_id'])

    def pending(self, watch_key: str, action_key: str | None = None) -> Iterator[dict[str, Any]]:
        action_key = identifier(action_key or watch_key, 'action_key')
        for candidate in super().pending(watch_key):
            with self.state.transaction() as db:
                row = db.execute('SELECT id FROM candidates WHERE watch=? AND item=?',
                                 (watch_key, candidate['source']['item_id'])).fetchone()
            actions = [a for a in self.state.associations(row[0]) if a['name'] == action_key]
            intent = self._intent(actions[0]) if actions else None
            if intent and intent.get('receipt', {}).get('outcome') == 'accepted':
                continue
            yield candidate

    def activate(self, candidate: dict[str, Any], *, host: str, role_profile: str | None = None,
                 model_profile: str | None = None, conditions: dict[str, Any] | None = None,
                 action_key: str | None = None) -> dict[str, Any]:
        from .host_contracts import connection_binding, normalize
        name = identifier(candidate.get('watch_key'), 'watch_key')
        action_key = identifier(action_key or name, 'action_key')
        with self.state.transaction() as db:
            row = db.execute('SELECT id,source,record FROM candidates WHERE watch=? AND item=?',
                             (name, candidate.get('source', {}).get('item_id'))).fetchone()
        if row is None or decode(row[1]) != candidate.get('source'):
            fail('invalid_input', 'activate requires an actual discovered candidate')
        key, source, record = row[0], decode(row[1]), decode(row[2])
        if source['kind'] == 'queue.task':
            if role_profile is not None or model_profile is not None:
                fail('invalid_input', 'Queue activation uses its actual experimenter configuration without overrides')
            role_profile = record.get('experimenter_profile')
        if role_profile is None:
            fail('invalid_input', 'non-Queue activation requires role_profile')
        # Validate before forming a new intent; the actual source and Host still check authority.
        request = normalize({'request_id': 'pending', 'rule_id': 'script-' + digest([name, action_key]),
                             'source': source, 'role_profile': role_profile,
                             **({'model_profile': model_profile} if model_profile is not None else {}),
                             'conditions': conditions if conditions is not None else {}})
        with exclusive(self.state.root / 'locks' / ('action-' + digest([key, action_key])), wait_seconds=5):
            existing = next((a for a in self.state.associations(key) if a['name'] == action_key), None)
            original = None
            binding = None
            if existing:
                # The persisted association and HostClient journal freeze the actual
                # parameters and Host, even when neither service can currently answer.
                journal = self._journal(existing['host'])
                with journal.lock():
                    saved = journal.load()
                binding = saved['binding']
                original = saved['actions'].get(existing['request_id'])
                if binding is None:
                    fail('intent_conflict', 'original Host binding is unavailable', status=409)
                selection = digest({'request': request, 'host_name': host, 'host_binding': binding})
                if existing['host'] != host or existing['selection'] != selection:
                    fail('activation_binding_changed', 'original Host, source, role/model or conditions differ; use an explicit new action_key', status=409)
                expected = {**request, 'request_id': existing['request_id']}
                if original and (original.get('request') != expected or original.get('sha256') != digest(expected)):
                    fail('intent_conflict', 'original activation request differs', status=409)
            receipt = original.get('receipt') if original else None
            confirmed = isinstance(receipt, dict) and receipt.get('outcome') == 'accepted'
            if confirmed:
                assert existing is not None and original is not None and isinstance(receipt, dict)
                if (original.get('state') != 'confirmed' or original.get('sent') is not True
                        or receipt.get('request_id') != existing['request_id']
                        or not isinstance(receipt.get('run_id'), str)):
                    fail('intent_conflict', 'original acceptance receipt is invalid', status=409)
            watch = self.state.watch(name)
            try:
                # Check both local bindings before any network failure can hide a change.
                d = watch['declaration']
                if local_binding(self.connections.get(d['connection'])) != d['local']:
                    fail('watch_binding_changed', 'original source connection or credential differs', status=409)
                if binding is not None:
                    host_connection = self.connections.get(host)
                    if not isinstance(host_connection, dict):
                        fail('invalid_configuration', 'original Host connection is missing')
                    local = connection_binding(host_connection)
                    if any(binding.get(k) != v for k, v in local.items()):
                        fail('host_binding_changed', 'original Host connection or credential differs', status=409)
                if confirmed:
                    assert existing is not None and isinstance(receipt, dict)
                    # Both independent checks matter: one service being offline must
                    # not hide a definite binding/authorization refusal by the other.
                    failures = []
                    for surface, check in (('source', lambda: self._client(name, watch)),
                                           ('host', lambda: self._host(host))):
                        try:
                            check()
                        except ToolError as caught:
                            failures.append((surface, caught))
                    for surface, failure in failures:
                        invalid_transport_response = (failure.code == 'invalid_response'
                                                      and 'did not return' not in failure.message)
                        invalid_source_json = (surface == 'source' and failure.code == 'invalid_input'
                                               and failure.message == 'invalid UTF-8 JSON')
                        temporary = (failure.status not in {401, 403} and
                                     (failure.code == 'transport_unknown' or invalid_transport_response or invalid_source_json or
                                     (failure.code not in {'unauthorized', 'forbidden', 'host_binding_changed',
                                                           'watch_binding_changed', 'recovery_binding_changed',
                                                           'source_identity_changed', 'principal_identity_changed',
                                                           'service_identity_changed', 'binding_or_response_changed'}
                                      and (failure.status in {408, 425, 429} or failure.status >= 500))))
                        if not temporary:
                            return {'outcome': 'rejected', 'request_id': existing['request_id'],
                                    'error': failure.result()['error'], 'original_receipt': dict(receipt),
                                    'current_state_verified': False}
                    cached: dict[str, Any] = {**receipt, 'current_state_verified': False}
                    if failures:
                        cached['verification_errors'] = [{'surface': surface, **failure.result()}
                                                         for surface, failure in failures]
                    return cached
                # A new or still-unconfirmed action requires the real authority checks.
                self._client(name, watch)
                client = self._host(host)
            except ToolError as exc:
                uncertain = original and original.get('sent') and not original.get('receipt')
                result = {'outcome': 'unknown' if uncertain else 'rejected',
                          'request_id': existing['request_id'] if existing else None,
                          'error': {**exc.result()['error'], **({'effect': 'unknown'} if uncertain else {})}}
                if confirmed:
                    assert isinstance(receipt, dict)
                    result.update(original_receipt=dict(receipt), current_state_verified=False)
                return result
            selection = digest({'request': request, 'host_name': host, 'host_binding': client.binding})
            if existing:
                if existing['host'] != host or existing['selection'] != selection:
                    fail('activation_binding_changed', 'original Host, source, role/model or conditions differ; use an explicit new action_key', status=409)
                request_id = existing['request_id']
            else:
                request_id = 'req-' + uuid.uuid4().hex
                with self.state.transaction() as db:
                    db.execute('INSERT INTO actions VALUES (?,?,?,?,?)', (key, action_key, host, request_id, selection))
            request['request_id'] = request_id
            action = {'host': host, 'request_id': request_id}
            original = self._intent(action)
            if original and original.get('receipt', {}).get('outcome') == 'accepted':
                return dict(original['receipt'])
            return dict(client.launch(request))

    def recover_unknown(self) -> list[dict[str, Any]]:
        results = []
        for action in self.state.associations():
            with exclusive(self.state.root / 'locks' / ('action-' + digest([action['candidate'], action['name']])), wait_seconds=5):
                intent = self._intent(action)
                # A stored association is not a send. Busy/rejected/accepted receipts
                # are definitive outcomes, and never authorize a new background choice.
                if not intent or not intent.get('sent') or intent.get('receipt'):
                    continue
                try:
                    client = self._host(action['host'])
                    try:
                        known = client.by_request(action['request_id'])
                    except ToolError as exc:
                        if exc.code != 'not_found':
                            raise
                    else:
                        if known.get('outcome') != 'accepted' or known.get('request_id') != action['request_id']:
                            fail('invalid_response', 'original Host query did not identify its admission')
                        # HostClient remains the only authority for original bodies/receipts.
                        with client.journal.lock():
                            value = client.journal.load()
                            value['actions'][action['request_id']].update(state='confirmed', receipt=known)
                            client.journal.save(value)
                        results.append(known)
                        continue
                    results.append(client.replay(action['request_id']))
                except (ToolError, OSError) as exc:
                    error = exc.result()['error'] if isinstance(exc, ToolError) else {
                        'code': 'journal_write_failed', 'message': 'original receipt could not be saved'}
                    results.append({'outcome': 'unknown', 'request_id': action['request_id'],
                                    'error': {**error, 'effect': 'unknown'}})
        return results

    def scan_once(self) -> list[dict[str, Any]]:
        return [{'recoveries': self.recover_unknown()}, *super().scan_once()]
