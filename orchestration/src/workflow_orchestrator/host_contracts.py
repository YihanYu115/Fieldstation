"""Finite trusted host configuration and activation contracts."""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .tools_contracts import canonical, decode, fail, fields, identifier, outside_path, text

KINDS = {'queue.task': 'queue', 'board.message': 'board', 'board.handoff': 'board', 'inbox.packet': 'im'}
ACTIVE = {'accepted', 'running', 'unknown'}


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def names(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 64:
        fail('invalid_configuration', name + ' requires 1..64 explicit names')
    result = [identifier(v, name) for v in value]
    if len(result) != len(set(result)):
        fail('invalid_configuration', name + ' must be unique')
    return result


def connection(value: Any) -> dict[str, str]:
    fields(value, {'endpoint', 'token_env'})
    url = urlsplit(text(value['endpoint'], 'endpoint', 2048))
    if (url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password
            or url.path not in {'', '/'} or url.query or url.fragment):
        fail('invalid_configuration', 'connection must be a fixed HTTP(S) origin')
    name = identifier(value['token_env'], 'token_env')
    token = os.environ.get(name, '')
    if not token or not token.isascii() or any(c.isspace() for c in token):
        fail('invalid_configuration', 'host must inject each configured token')
    return {'endpoint': value['endpoint'].rstrip('/'), 'token_env': name}


def connection_binding(value: dict[str, str]) -> dict[str, str]:
    value = connection(value)
    return {**value, 'credential_sha256': digest(os.environ[value['token_env']])}


def normalize(value: Any) -> dict[str, Any]:
    fields(value, {'request_id', 'rule_id', 'source', 'role_profile'}, {'model_profile', 'conditions'})
    source = fields(value['source'], {'connection', 'kind', 'item_id', 'issue_id'}, {'service_id', 'revision'})
    kind = source['kind']
    if not isinstance(kind, str) or kind not in KINDS:
        fail('invalid_input', 'unsupported source kind')
    normalized: dict[str, Any] = {'connection': identifier(source['connection'], 'connection'), 'kind': kind,
                  'item_id': identifier(source['item_id'], 'item_id'),
                  'issue_id': text(source['issue_id'], 'issue_id')}
    if kind == 'inbox.packet':
        if 'service_id' in source:
            fail('invalid_input', 'IM has no public persistent service identity')
    else:
        normalized['service_id'] = identifier(source.get('service_id'), 'service_id')
    if 'revision' in source:
        if type(source['revision']) is not int or source['revision'] < 1:
            fail('invalid_input', 'revision must be a positive integer')
        normalized['revision'] = source['revision']
    conditions = fields(value.get('conditions', {}), set(), {'idle_roles'})
    idle = []
    if 'idle_roles' in conditions and conditions['idle_roles'] != []:
        idle = names(conditions['idle_roles'], 'idle_roles')
    result = {'request_id': identifier(value['request_id'], 'request_id'),
              'rule_id': identifier(value['rule_id'], 'rule_id'), 'source': normalized,
              'role_profile': identifier(value['role_profile'], 'role_profile'),
              'conditions': {'idle_roles': sorted(idle)}}
    if 'model_profile' in value:
        result['model_profile'] = identifier(value['model_profile'], 'model_profile')
    return result


def load_config(path: str | Path) -> dict[str, Any]:
    c = fields(decode(Path(path).read_text(encoding='utf-8')),
               {'database_path', 'runtime_path', 'listen', 'max_active_runs', 'principals',
                'connections', 'role_profiles', 'model_profiles'})
    c['database_path'] = str(outside_path(c['database_path']))
    c['runtime_path'] = str(outside_path(c['runtime_path']))
    fields(c['listen'], {'host', 'port'})
    text(c['listen']['host'], 'listen host')
    if type(c['listen']['port']) is not int or not 0 <= c['listen']['port'] <= 65535:
        fail('invalid_configuration', 'listen port must be 0..65535')
    if type(c['max_active_runs']) is not int or not 1 <= c['max_active_runs'] <= 64:
        fail('invalid_configuration', 'max_active_runs must be 1..64')
    for key in ('connections', 'role_profiles', 'model_profiles'):
        if not isinstance(c[key], dict) or not c[key] or len(c[key]) > 64:
            fail('invalid_configuration', key + ' requires a finite nonempty map')
        for name in c[key]:
            identifier(name, key)
    c['connections'] = {k: connection(v) for k, v in c['connections'].items()}
    for model in c['model_profiles'].values():
        fields(model, {'command', 'cwd'}, {'env_names', 'adapter'})
        if model.get('adapter') not in {None, 'codex'}:
            fail('invalid_configuration', 'adapter must be codex when present')
        command = model['command']
        if (not isinstance(command, list) or not command or len(command) > 64
                or any(not isinstance(v, str) or '\x00' in v or len(v) > 8192 for v in command)):
            fail('invalid_configuration', 'command must be a finite argument array')
        executable = Path(command[0])
        # Direct foreground executable only: no shell/batch/venv console launcher contract.
        if not executable.is_absolute() or not executable.is_file() or (os.name == 'nt' and executable.suffix.lower() != '.exe'):
            fail('invalid_configuration', 'command requires an absolute foreground executable')
        cwd = Path(model['cwd'])
        if not cwd.is_absolute() or not cwd.is_dir():
            fail('invalid_configuration', 'model cwd must be an existing absolute directory')
        if 'env_names' in model:
            names(model['env_names'], 'env_names')
    for role in c['role_profiles'].values():
        fields(role, {'role', 'model_profile', 'prompt', 'mcp', 'catalog'})
        identifier(role['role'], 'role')
        if 'catalog' in role:
            catalog = fields(role['catalog'], {'role_name', 'responsibility', 'profile_name',
                                               'purpose', 'model_description', 'queue_consumer'})
            for name in ('role_name', 'responsibility', 'profile_name', 'purpose', 'model_description'):
                text(catalog[name], name, 256)
            if type(catalog['queue_consumer']) is not bool:
                fail('invalid_configuration', 'queue_consumer must be boolean')
        if role['model_profile'] not in c['model_profiles']:
            fail('invalid_configuration', 'unknown default model')
        text(role['prompt'], 'prompt', 16000)
        if not isinstance(role['mcp'], list) or len(role['mcp']) > 8:
            fail('invalid_configuration', 'mcp must be a list of at most eight surfaces')
        if role['mcp'] and c['model_profiles'][role['model_profile']].get('adapter') != 'codex':
            fail('invalid_configuration', 'MCP profiles require the codex launch adapter')
        seen = set()
        token_envs = set()
        for mcp in role['mcp']:
            fields(mcp, {'surface', 'connection', 'tools', 'http_url', 'http_token_env'}, {'name'})
            surface = mcp['surface']
            if surface not in {'queue', 'board', 'im', 'host'}:
                fail('invalid_configuration', 'unknown MCP surface')
            name = mcp.get('name', surface)
            if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name)
                    or name in seen or ('name' in mcp and surface != 'host')):
                fail('invalid_configuration', 'MCP server names must be unique safe identifiers; aliases are for Host catalogs')
            seen.add(name)
            if mcp['connection'] not in c['connections']:
                fail('invalid_configuration', 'unknown MCP connection')
            names(mcp['tools'], 'tools')
            url = urlsplit(text(mcp['http_url'], 'http_url', 2048))
            if (url.scheme not in {'http', 'https'} or not url.hostname or url.username or url.password
                    or url.path != '/mcp' or url.query or url.fragment):
                fail('invalid_configuration', 'HTTP MCP URL must be a fixed /mcp endpoint')
            if url.scheme == 'http' and url.hostname not in {'127.0.0.1', '::1', 'localhost'}:
                fail('invalid_configuration', 'remote HTTP MCP requires HTTPS')
            name = identifier(mcp['http_token_env'], 'http_token_env')
            token = os.environ.get(name, '')
            if not token or not token.isascii() or any(ch.isspace() for ch in token):
                fail('invalid_configuration', 'host must inject the MCP access token')
            env_key = name.upper() if os.name == 'nt' else name
            if env_key in token_envs:
                fail('invalid_configuration', 'each surface needs a distinct MCP access environment name')
            token_envs.add(env_key)
    public_catalog = [{'role': role['role'], 'profile': name, 'model_profile': role['model_profile'],
                       **role['catalog']} for name, role in c['role_profiles'].items() if 'catalog' in role]
    if len(canonical(public_catalog).encode('utf-8')) > 48000:
        fail('invalid_configuration', 'catalog exceeds the finite response limit')
    if not isinstance(c['principals'], list) or not c['principals']:
        fail('invalid_configuration', 'explicit principals required')
    subjects, tokens = set(), set()
    for p in c['principals']:
        fields(p, {'principal_id', 'token_env', 'actions', 'role_profiles', 'connections'})
        identifier(p['principal_id'], 'principal_id')
        for name in ('actions', 'role_profiles', 'connections'):
            names(p[name], name)
        if set(p['actions']) - {'launch', 'query', 'status', 'catalog'}:
            fail('invalid_configuration', 'unknown host permission')
        if set(p['role_profiles']) - c['role_profiles'].keys() or set(p['connections']) - c['connections'].keys():
            fail('invalid_configuration', 'unknown allowed profile/connection')
        token = os.environ.get(identifier(p['token_env'], 'token_env'), '')
        if not token or not token.isascii() or any(ch.isspace() for ch in token):
            fail('invalid_configuration', 'host must inject each principal token')
        if p['principal_id'] in subjects or token in tokens:
            fail('invalid_configuration', 'duplicate principal/token')
        subjects.add(p['principal_id'])
        tokens.add(token)
    return c


def authority(principal: dict[str, Any], action: str, request: dict[str, Any] | None = None) -> None:
    if action not in principal['actions']:
        fail('forbidden', 'principal lacks host action permission', status=403)
    if request and (request['role_profile'] not in principal['role_profiles']
                    or request['source']['connection'] not in principal['connections']):
        fail('forbidden', 'principal lacks profile or source connection permission', status=403)


def principal_binding(principal: dict[str, Any]) -> str:
    return digest({**principal, 'credential_sha256': digest(os.environ[principal['token_env']])})
