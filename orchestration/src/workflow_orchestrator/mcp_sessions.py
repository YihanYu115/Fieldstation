"""Trusted Host registration and isolated MCP session bindings."""
from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any

from .tools_contracts import ToolError, canonical, fields, identifier, text
from .tools_journal import ActionJournal


def session_token(secret: str, session_id: str) -> str:
    identifier(session_id, 'session_id')
    return hmac.new(secret.encode('ascii'), ('workflow-mcp-session-v1:' + session_id).encode('utf-8'),
                    hashlib.sha256).hexdigest()


class SessionRegistry:
    def __init__(self, profile: dict[str, Any], path: str | Path, secret: str):
        self.profile, self.secret = profile, secret
        self.registry = ActionJournal(path)
        root_key = hashlib.sha256(self.registry.path.name.encode('utf-8')).hexdigest()[:24]
        self.root = self.registry.path.parent / ('mcp-sessions-' + root_key)
        self.binding = {'format': ('mcp-sessions-3' if profile.get('surface', 'queue') == 'queue'
                                   else 'mcp-sessions-2'),
                        'profile_sha256': hashlib.sha256(canonical(profile).encode('utf-8')).hexdigest(),
                        'credential_sha256': hashlib.sha256(secret.encode('ascii')).hexdigest()}
        self.registry.bind(self.binding)

    def register(self, request: Any) -> dict[str, Any]:
        fields(request, {'session_id', 'tools', 'default_issue_id'}, {'default_task_id'})
        session_id = identifier(request['session_id'], 'session_id')
        text(request['default_issue_id'], 'default_issue_id')
        if 'default_task_id' in request:
            identifier(request['default_task_id'], 'default_task_id')
            if self.profile.get('surface', 'queue') != 'queue':
                raise ToolError('invalid_input', 'task default is only valid for Queue')
        tools = request['tools']
        if (not isinstance(tools, list) or not tools
                or any(not isinstance(x, str) or x not in self.profile['tools'] for x in tools)
                or len(tools) != len(set(tools))):
            raise ToolError('invalid_input', 'session tools exceed the service profile')
        # A session is immutable. Repeating the same registration is safe after a lost response.
        request = dict(request)
        with self.registry.lock():
            data = self.registry.load()
            if data['binding'] != self.binding:
                raise ToolError('recovery_binding_changed', 'session registry binding changed', effect='unknown')
            existing = data['actions'].get(session_id)
            fingerprint = hashlib.sha256(canonical(request).encode('utf-8')).hexdigest()
            if existing is not None and (existing['request'] != request
                                         or existing.get('request_sha256') != fingerprint):
                raise ToolError('intent_conflict', 'session binding differs from its original', effect='unknown')
            if existing is None:
                data['actions'][session_id] = {'state': 'registered', 'request': request,
                                               'request_sha256': fingerprint}
                self.registry.save(data)
        return self.profile_for(request)

    def profile_for(self, request: dict[str, Any]) -> dict[str, Any]:
        identity = identifier(request['session_id'], 'session_id')
        file_key = hashlib.sha256(identity.encode('utf-8')).hexdigest()[:32]
        profile = {**self.profile, 'tools': request['tools'], 'default_issue_id': request['default_issue_id'],
                   'journal_path': str(self.root / (file_key + '-actions.json'))}
        profile.pop('default_task_id', None)
        if 'default_task_id' in request:
            profile['default_task_id'] = request['default_task_id']
        return profile

    def all(self) -> list[dict[str, Any]]:
        with self.registry.lock():
            value = self.registry.load()
            if value['binding'] != self.binding:
                raise ToolError('recovery_binding_changed', 'session registry binding changed', effect='unknown')
            requests = []
            for identity, row in value['actions'].items():
                request = row['request']
                fingerprint = hashlib.sha256(canonical(request).encode('utf-8')).hexdigest()
                if (request.get('session_id') != identity or row.get('request_sha256') != fingerprint):
                    raise ToolError('intent_conflict', 'persisted session binding changed', effect='unknown')
                identifier(identity, 'session_id')
                requests.append(request)
            return requests
