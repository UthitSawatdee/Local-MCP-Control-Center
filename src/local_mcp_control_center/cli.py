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
        from .gui import launch_gui

        try:
            launch_gui(broker, RuntimeSupervisor(store, broker.audit))
        finally:
            store.close()
        return 0

    try:
        if args.command == "mcp":
            # tunnel-client passes its environment to the stdio child. The MCP
            # bridge has no reason to retain the tunnel runtime credential.
            os.environ.pop("CONTROL_PLANE_API_KEY", None)
            run_stdio(broker)
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
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
