"""Small operational CLI for the fresh scoped-v2 kernel."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .errors import IssueManagerError
from .manager_api import ManagerService
from .service import IssueManager
from .store import Store
from .strict_json import strict_json_dumps


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="issuectl")
    parser.add_argument("--ledger", default="issue_ledger", help="ledger directory")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("init", help="initialize a new scoped-v2 ledger")

    serve = commands.add_parser("serve", help="run the Manager HTTP service")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--project-runtime", help="explicit outside-checkout component staging authorization")

    project = commands.add_parser("project", help="portable IM component operations on the trusted host")
    project_commands = project.add_subparsers(dest="project_command", required=True)
    export = project_commands.add_parser("export")
    export.add_argument("--output", required=True)
    export.add_argument("--token-env", default="IM_PROJECT_TOKEN")
    inspect = project_commands.add_parser("inspect")
    inspect.add_argument("--file", required=True)
    inspect.add_argument("--runtime", required=True)
    install = project_commands.add_parser("install")
    install.add_argument("--file", required=True)
    install.add_argument("--target", required=True)

    commands.add_parser("status", help="show the fixed schema and active runtime")

    backup = commands.add_parser("backup", help="create, inspect or restore a backup")
    backup_commands = backup.add_subparsers(dest="backup_command", required=True)
    create = backup_commands.add_parser("create")
    create.add_argument("--label", default="manual")
    create.add_argument("--mode", choices=("metadata", "full"), default="metadata")
    backup_commands.add_parser("list")
    verify = backup_commands.add_parser("verify")
    verify.add_argument("backup_id")
    restore = backup_commands.add_parser("restore")
    restore.add_argument("backup_id")

    recover = commands.add_parser(
        "recover-bootstrap-credential",
        help="reissue the existing bootstrap maintenance credential from this trusted host",
    )
    recover.add_argument("--reason", required=True, help="audited reason for recovery")
    return parser


def _print(value: object) -> None:
    print(strict_json_dumps(value))


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    ledger = Path(args.ledger).resolve()
    try:
        if args.command == "init":
            manager = IssueManager.initialize(ledger)
            try:
                result = {
                    "ledger": str(ledger),
                    "schema_version": manager.store._schema_version(manager.store.conn),
                    "runtime": "scoped-v2",
                }
            finally:
                manager.close()
            _print(result)
            return 0

        if args.command == "serve":
            service = ManagerService(ledger, host=args.host, port=args.port, project_runtime=args.project_runtime)
            try:
                host, port = service.address
                _print({"ledger": str(ledger), "endpoint": f"http://{host}:{port}"})
                service.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                service.close()
            return 0

        if args.command == "project":
            import os
            import shutil
            import tempfile

            from .project_component import export_component, prepare_component, validate_component

            if args.project_command == "export":
                target = Path(args.output).resolve()
                checkout = Path(__file__).resolve().parents[1]
                if checkout == target or checkout in target.parents or ledger in target.parents:
                    raise IssueManagerError("Export output must be outside checkout and source ledger")
                if target.exists():
                    raise IssueManagerError("Export target already exists")
                manager = IssueManager(ledger)
                try:
                    auth = manager.credentials.resolve(os.environ.get(args.token_env, ""))
                    auth.require("backup.manage")
                    auth.require("maintenance")
                    if auth.platform_id is not None:
                        raise IssueManagerError("Whole-ledger authorization required")
                    _print(export_component(manager, target))
                finally:
                    manager.close()
            elif args.project_command == "inspect":
                runtime = Path(args.runtime).resolve()
                checkout = Path(__file__).resolve().parents[1]
                if checkout == runtime or checkout in runtime.parents:
                    raise IssueManagerError("Inspection runtime must be outside checkout")
                runtime.mkdir(parents=True, exist_ok=True)
                with tempfile.TemporaryDirectory(dir=runtime) as temp:
                    _print(validate_component(Path(args.file).resolve(), Path(temp) / "component"))
            else:
                target = Path(args.target).resolve()
                checkout = Path(__file__).resolve().parents[1]
                if checkout == target or checkout in target.parents or target == ledger or ledger in target.parents:
                    raise IssueManagerError("Installation target must be outside checkout and source ledger")
                if target.exists():
                    raise IssueManagerError("Installation target already exists; no merge or overwrite")
                from uuid import uuid4

                stage = target.with_name('.im-preparing-' + uuid4().hex[:16])
                try:
                    result = prepare_component(Path(args.file).resolve(), stage)
                    stage.rename(target)
                    _print(result)
                except BaseException:
                    if stage.exists():
                        shutil.rmtree(stage)
                    raise
            return 0

        if args.command == "status":
            manager = IssueManager(ledger)
            try:
                _print({
                    "ledger": str(ledger),
                    "schema_version": manager.store._schema_version(manager.store.conn),
                    "runtime": "scoped-v2",
                    "rule_id": manager.context_rules.active()["rule_id"],
                })
            finally:
                manager.close()
            return 0

        if args.command == "recover-bootstrap-credential":
            manager = IssueManager(ledger)
            try:
                result = manager.credentials.recover_bootstrap_maintenance_credential(
                    reason=args.reason
                )
            finally:
                manager.close()
            _print(result)
            return 0

        if args.command == "backup":
            if args.backup_command == "create":
                backup_result: object = Store.create_backup(
                    ledger, label=args.label, mode=args.mode
                )
            elif args.backup_command == "list":
                backup_result = Store.list_backups(ledger)
            elif args.backup_command == "verify":
                backup_result = Store.verify_backup(ledger, args.backup_id)
            else:
                backup_result = Store.restore_backup(ledger, args.backup_id)
            _print(backup_result)
            return 0
    except IssueManagerError as exc:
        _print({"error": exc.code, "message": str(exc), "details": exc.details})
        return 2
    except (ValueError, OSError) as exc:
        if args.command != "project":
            raise
        _print({"error": "project_rejected", "message": str(exc)})
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
