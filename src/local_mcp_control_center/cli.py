from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .broker import Broker
from .mcp_server import run_stdio
from .models import ScopeKind
from .storage import Store
from .supervisor import RuntimeSupervisor


APP_NAME = "Local MCP Control Center"


def default_data_dir() -> Path:
    """Return the platform-appropriate private application data directory."""
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "LocalMCPControlCenter"
    return Path.home() / ".local" / "share" / "local-mcp-control-center"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="local-mcp",
        description="Least-privilege local MCP Control Center.",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=default_data_dir(),
        help="private state directory (default: platform application support directory)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("gui", help="open the native control center")
    commands.add_parser("mcp", help="run the MCP bridge over stdio")
    commands.add_parser("list-scopes", help="print configured scopes as JSON")
    commands.add_parser("list-tools", help="print tool policies as JSON")
    commands.add_parser("verify-audit", help="verify the local audit hash chain")
    commands.add_parser("status", help="print local control-center status")
    doctor = commands.add_parser("doctor", help="observe one registered project workspace")
    doctor.add_argument("project_id", help="registered project scope ID")
    observe = commands.add_parser("observe", help="observe one registered project workspace")
    observe.add_argument("project_id", help="registered project scope ID")
    prepare = commands.add_parser("prepare", help="prepare a bounded workspace work package")
    prepare.add_argument("project_id", help="registered project scope ID")
    prepare.add_argument("goal", help="bounded work goal")
    prepare.add_argument("--mode", choices=["diagnose", "implement", "review"], default="implement")
    prepare.add_argument("--scope", dest="allowed_scope", action="append", help="allowed relative path; repeatable")
    run_status = commands.add_parser("run-status", help="show a workspace run and evidence")
    run_status.add_argument("run_id", help="WorkspaceEngine run ID")
    finish = commands.add_parser("finish", help="finish a workspace run and generate handoff")
    finish.add_argument("run_id", help="WorkspaceEngine run ID")
    proposals = commands.add_parser("action-proposals", help="list pending dangerous action proposals")
    proposals.add_argument("project_id", nargs="?", help="optional registered project scope ID")
    propose = commands.add_parser("propose-action", help="create one approval-gated WorkspaceEngine controlled-action proposal")
    propose.add_argument("run_id", help="WorkspaceEngine run ID")
    propose.add_argument("action", choices=["owned_service_start", "owned_service_stop", "targeted_verification", "commit", "push"])
    propose.add_argument("--parameters-json", default="{}", help="JSON object containing bounded action parameters")
    pending = commands.add_parser("pending-approvals", help="print pending approvals as JSON")
    pending.set_defaults(command="pending-approvals")

    add_scope = commands.add_parser("add-scope", help="add a read-only scope without opening the GUI")
    add_scope.add_argument("--scope-id", required=True, help="stable identifier, for example atm-project")
    add_scope.add_argument("--label", required=True, help="human-readable label")
    add_scope.add_argument("--root", required=True, type=Path, help="existing directory or file selected by the user")
    add_scope.add_argument("--kind", choices=[kind.value for kind in ScopeKind], default=ScopeKind.DIRECTORY.value)
    add_scope.add_argument("--expose", action="store_true", help="make this scope visible to MCP")
    return parser


def _emit(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _open(data_dir: Path) -> tuple[Store, Broker]:
    data_dir = data_dir.expanduser().absolute()
    data_dir.mkdir(parents=True, exist_ok=True)
    store = Store(data_dir / "control.sqlite3", data_dir)
    return store, Broker(store)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    store, broker = _open(args.data_dir)
    if args.command == "gui":
        # Import lazily so the MCP bridge remains usable on headless systems.
        from .gui_ux import launch_gui

        try:
            launch_gui(broker, RuntimeSupervisor(store, broker.audit))
        finally:
            broker.close()
        return 0

    try:
        if args.command == "mcp":
            # tunnel-client passes its environment to the stdio child. The MCP
            # bridge has no reason to retain the tunnel runtime credential.
            os.environ.pop("CONTROL_PLANE_API_KEY", None)
            try:
                run_stdio(broker)
            finally:
                broker.close()
            return 0
        if args.command == "list-scopes":
            _emit({"status": "ok", "scopes": broker.policy.scope_summary(actor="user")})
            return 0
        if args.command == "list-tools":
            _emit({"status": "ok", "tools": broker.tool_rows()})
            return 0
        if args.command == "verify-audit":
            _emit(broker.verify_audit())
            return 0
        if args.command == "status":
            _emit(broker.invoke("runtime_status", actor="user"))
            return 0
        if args.command in {"doctor", "observe"}:
            result = broker.invoke("workspace_observe", {"project_id": args.project_id}, actor="user")
            _emit(result)
            return 0 if result.get("status") == "ok" else 2
        if args.command == "prepare":
            payload = {"project_id": args.project_id, "goal": args.goal, "mode": args.mode}
            if args.allowed_scope:
                payload["allowed_scope"] = args.allowed_scope
            result = broker.invoke("workspace_prepare", payload, actor="user")
            _emit(result)
            return 0 if result.get("status") == "ok" else 2
        if args.command == "run-status":
            result = broker.invoke("workspace_run_status", {"run_id": args.run_id}, actor="user")
            _emit(result)
            return 0 if result.get("status") == "ok" else 2
        if args.command == "finish":
            result = broker.invoke("workspace_finish", {"run_id": args.run_id}, actor="user")
            _emit(result)
            return 0 if result.get("status") == "ok" else 2
        if args.command == "action-proposals":
            payload = {} if args.project_id is None else {"project_id": args.project_id}
            result = broker.invoke("workspace_action_proposals", payload, actor="user")
            _emit(result)
            return 0 if result.get("status") == "ok" else 2
        if args.command == "propose-action":
            try:
                parameters = json.loads(args.parameters_json)
            except json.JSONDecodeError:
                _emit({"status": "denied", "error_code": "INVALID_INPUT", "message": "parameters-json must be a JSON object"})
                return 2
            if not isinstance(parameters, dict):
                _emit({"status": "denied", "error_code": "INVALID_INPUT", "message": "parameters-json must be a JSON object"})
                return 2
            result = broker.invoke("workspace_propose_action", {"run_id": args.run_id, "action": args.action, "parameters": parameters}, actor="user")
            _emit(result)
            return 0 if result.get("status") == "approval_required" else 2
        if args.command == "pending-approvals":
            _emit({"status": "ok", "approvals": broker.pending_approvals()})
            return 0
        if args.command == "add-scope":
            result = broker.add_scope(
                scope_id=args.scope_id,
                label=args.label,
                kind=args.kind,
                root=str(args.root),
                expose_to_mcp=args.expose,
                permissions={"read": {"allowed": True, "approval_mode": "never"}},
            )
            _emit(result)
            return 0 if result.get("status") == "ok" else 2
        raise SystemExit(f"unsupported command: {args.command}")
    finally:
        broker.close()


if __name__ == "__main__":
    raise SystemExit(main())
