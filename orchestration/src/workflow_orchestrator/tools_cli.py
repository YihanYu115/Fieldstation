"""Installed finite tools entry point. Only import the selected surface."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from .tools_contracts import ToolError, canonical


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog='workflow-tools', description='Independent workflow record tools')
    commands = parser.add_subparsers(dest='command', required=True)
    service = commands.add_parser('serve', help='Serve selected record modules over HTTP')
    service.add_argument('--services', required=True, choices=['queue', 'board'])
    service.add_argument('--config', required=True)
    mcp = commands.add_parser('mcp', help='Serve a trusted profile over Streamable HTTP MCP')
    mcp.add_argument('--profile', required=True)
    mcp.add_argument('--registry', required=True)
    mcp.add_argument('--host', default='127.0.0.1')
    mcp.add_argument('--port', type=int, required=True)
    mcp.add_argument('--token-env', required=True)
    recover = commands.add_parser('recover', help='Host recovery of one original journal action')
    recover.add_argument('--profile', required=True)
    recover.add_argument('--operation-id', required=True)
    recover.add_argument('--registry')
    recover.add_argument('--session-id')
    recover.add_argument('--token-env')
    host = commands.add_parser('host', help='Serve finite reliable foreground launches')
    host.add_argument('--config', required=True)
    trigger = commands.add_parser('trigger', help='Run a trusted user Python script: run(tools)')
    trigger.add_argument('--script', required=True)
    discover = commands.add_parser('discover', help='Independent read-only discovery; no script or Host')
    discover.add_argument('--once', required=True, action='store_true')
    discover.add_argument('--watch', required=True)
    discover.add_argument('--kind', required=True, choices=['queue.task', 'board.message', 'board.handoff', 'inbox.packet'])
    discover.add_argument('--connection', required=True)
    discover.add_argument('--issue', required=True)
    discover.add_argument('--initial', choices=['new_only', 'from_start'])
    for command in (trigger, discover):
        command.add_argument('--connections', required=True)
        command.add_argument('--state', required=True, help='Absolute directory outside the checkout')
    args = parser.parse_args(argv)
    try:
        if args.command == 'trigger':
            from .trigger_script import run_script
            from .trigger_tools import TriggerTools
            return run_script(args.script, TriggerTools(args.connections, args.state))
        elif args.command == 'discover':
            from .listener import Listener
            with Listener(args.connections, args.state) as listener:
                listener.listen(args.watch, kind=args.kind, connection=args.connection,
                                issue_id=args.issue, initial=args.initial)
                scans = listener.scan_once()
                print(canonical({'scans': scans}))
                for candidate in listener.pending(args.watch):
                    print(canonical(candidate))
                return int(any('error' in scan for scan in scans))
        elif args.command == 'host':
            from .host_contracts import load_config
            from .host_http import HostHTTPServer
            from .launch_host import LaunchHost
            config = load_config(args.config)
            runtime = LaunchHost(config)
            with HostHTTPServer((config['listen']['host'], config['listen']['port']), runtime) as host_server:
                runtime.resume_prepared()
                print(canonical({'listening': list(host_server.server_address), 'service_id': runtime.service_id,
                                 'modules': ['host']}), flush=True)
                try:
                    host_server.serve_forever(poll_interval=0.1)
                except KeyboardInterrupt:
                    pass
        elif args.command == 'serve':
            if args.services == 'board':
                from .board_http import BoardHTTPServer, load_board_service
                records, board_bindings, address = load_board_service(args.config)
                server: Any = BoardHTTPServer(address, records, board_bindings)
            else:
                from .tools_http import ToolsHTTPServer, load_service
                queue, bindings, address = load_service(args.config)
                server = ToolsHTTPServer(address, queue, bindings)
            with server:
                print(canonical({'listening': list(server.server_address), 'service_id': server.queue.service_id,
                                 'modules': [args.services]}), flush=True)
                try:
                    server.serve_forever(poll_interval=0.1)
                except KeyboardInterrupt:
                    pass
        else:
            from .tools_mcp import load_profile
            profile = load_profile(args.profile)
            if args.command == 'mcp':
                from .mcp_http import serve
                serve(profile, args.registry, args.host, args.port, args.token_env)
            else:
                session_options = (args.registry, args.session_id, args.token_env)
                if any(session_options):
                    if not all(session_options):
                        raise ToolError('invalid_configuration', 'session recovery requires registry, session-id and token-env')
                    if not Path(args.registry).is_file():
                        raise ToolError('not_found', 'original MCP session registry is unavailable')
                    from .mcp_sessions import SessionRegistry
                    token = os.environ.get(args.token_env, '')
                    if not token or not token.isascii() or any(ch.isspace() for ch in token):
                        raise ToolError('invalid_configuration', 'host must inject the original MCP access token')
                    registry = SessionRegistry(profile, args.registry, token)
                    session = next((row for row in registry.all() if row['session_id'] == args.session_id), None)
                    if session is None:
                        raise ToolError('not_found', 'original MCP session is not registered')
                    profile = registry.profile_for(session)
                client: Any
                if profile.get('surface', 'queue') == 'im':
                    from .im_client import IMClient
                    client = IMClient.from_connection(profile['connection'], profile['journal_path'])
                elif profile.get('surface') == 'board':
                    from .board_client import BoardClient
                    client = BoardClient.from_connection(profile['connection'], profile['journal_path'])
                else:
                    from .tools_client import ToolsClient
                    client = ToolsClient.from_connection(profile['connection'], profile['journal_path'])
                print(canonical(client.recover(args.operation_id)))
        return 0
    except ToolError as exc:
        print(canonical(exc.result()), file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print(canonical(ToolError('invalid_configuration', 'configuration or runtime path is unavailable').result()),
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
