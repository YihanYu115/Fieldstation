"""Host-managed Streamable HTTP MCP, with isolated immutable session bindings."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import os
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path

import uvicorn
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Mount

from .mcp_sessions import SessionRegistry, session_token
from .tools_contracts import ToolError, decode, identifier, outside_path
from .tools_mcp import create_server


def serve(profile: dict, registry_path: str | Path, host: str, port: int, token_env: str) -> None:
    identifier(token_env, 'token_env')
    token = os.environ.get(token_env, '')
    if not token or not token.isascii() or any(c.isspace() for c in token):
        raise ToolError('invalid_configuration', 'host must inject MCP bearer token')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ToolError('invalid_configuration', 'listen host must be a loopback IP') from None
    if not address.is_loopback or not 1 <= port <= 65535:
        raise ToolError('invalid_configuration', 'MCP must listen on a loopback IP and fixed port')
    if outside_path(registry_path) == outside_path(profile['journal_path']):
        raise ToolError('invalid_configuration', 'session registry and action journal must differ')
    registry = SessionRegistry(profile, registry_path, token)
    managers = {}
    lock = asyncio.Lock()
    stack = AsyncExitStack()

    async def attach(identity, request):
        async with lock:
            if identity not in managers:
                selected = profile if request is None else registry.profile_for(request)
                server = await asyncio.to_thread(create_server, selected)
                manager = StreamableHTTPSessionManager(app=server, stateless=True, json_response=True)
                await stack.enter_async_context(manager.run())
                managers[identity] = (manager, server)
            return managers[identity][0]

    @asynccontextmanager
    async def lifespan(_app):
        async with stack:
            yield
            tasks = [t for _, server in managers.values() for t in getattr(server, 'workflow_tasks')]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def endpoint(scope, receive, send):
        path = scope['path']
        parts = path.strip('/').split('/')
        sid = parts[1] if len(parts) == 3 and parts[0] == 'sessions' and parts[2] == 'mcp' else None
        try:
            expected = session_token(token, sid) if sid else token
        except ToolError:
            expected = ''
        headers = [v for k, v in scope.get('headers', []) if k.lower() == b'authorization']
        if len(headers) != 1 or not hmac.compare_digest(headers[0], ('Bearer ' + expected).encode('ascii')):
            await PlainTextResponse('Unauthorized', status_code=401, headers={'WWW-Authenticate': 'Bearer'})(scope, receive, send)
            return
        if path == '/internal/sessions' and scope['method'] == 'POST':
            chunks, size = [], 0
            while True:
                part = await receive()
                if part['type'] != 'http.request':
                    return
                chunk = part.get('body', b'')
                size += len(chunk)
                if size > 65536:
                    await PlainTextResponse('Request too large', status_code=413)(scope, receive, send)
                    return
                chunks.append(chunk)
                if not part.get('more_body', False):
                    break
            try:
                request = decode(b''.join(chunks))
                selected = await asyncio.to_thread(registry.register, request)
                downstream = os.environ.get(profile['connection']['token_env'], '')
                response = JSONResponse({'surface': selected.get('surface', 'queue'),
                    'tools': selected['tools'], 'default_issue_id': selected['default_issue_id'],
                    'default_task_id': selected.get('default_task_id'),
                    'endpoint': selected['connection']['endpoint'].rstrip('/'),
                    'credential_sha256': hashlib.sha256(downstream.encode('utf-8')).hexdigest()})
            except ToolError as exc:
                response = JSONResponse(exc.result(), status_code=409 if exc.effect == 'unknown' else 400)
            await response(scope, receive, send)
            return
        if path != '/mcp' and not sid:
            await PlainTextResponse('Not found', status_code=404)(scope, receive, send)
            return
        try:
            request = None
            if sid:
                rows = await asyncio.to_thread(registry.all)
                request = next((row for row in rows if row['session_id'] == sid), None)
                if request is None:
                    await PlainTextResponse('Not found', status_code=404)(scope, receive, send)
                    return
            manager = await attach(sid or '', request)
        except ToolError as exc:
            status = (403 if exc.code in {'forbidden', 'unauthorized', 'permission_denied'} else
                      409 if exc.code in {'recovery_binding_changed', 'intent_conflict'} else 503)
            await JSONResponse(exc.result(), status_code=status)(scope, receive, send)
            return
        except OSError:
            await PlainTextResponse('MCP downstream binding unavailable; retry the original request', status_code=503)(scope, receive, send)
            return
        await manager.handle_request(scope, receive, send)

    app = Starlette(routes=[Mount('/', app=endpoint)], lifespan=lifespan)
    uvicorn.run(app, host=host, port=port, access_log=False, log_level='warning')
