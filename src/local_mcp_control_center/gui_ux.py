from __future__ import annotations

from .codex_thread_gui import show_codex_config

import tkinter as tk
from tkinter import ttk
from typing import Any

from .broker import Broker
from .gui import ControlCenterApp, format_bridge_metrics, format_bridge_state, format_runtime_status
from .supervisor import RuntimeSupervisor


def filter_tool_rows(rows: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    """Return tool rows matching a plain-text search across useful visible fields."""
    needle = query.strip().lower()
    if not needle:
        return list(rows)
    fields = ("name", "group", "risk", "approval_mode", "description")
    return [
        row
        for row in rows
        if any(needle in str(row.get(field, "")).lower() for field in fields)
    ]


def tool_summary_text(
    rows: list[dict[str, Any]],
    shown_count: int,
    bridge: dict[str, Any] | None = None,
) -> str:
    """Build a compact summary that makes tool inventory immediately visible."""
    total = len(rows)
    enabled = sum(bool(row.get("enabled")) for row in rows)
    bridge = bridge or {}
    running = bridge.get("running_tool_count", 0)
    return (
        f"Registry total {total}  •  Enabled {enabled}  •  Running bridge tools {running}  •  "
        f"{format_bridge_state(bridge)}  •  Showing {shown_count}"
    )


def _process_state(data: dict[str, Any], kind: str) -> str:
    for row in data.get("processes", []):
        if row.get("kind") == kind:
            return str(row.get("state") or "unknown")
    for row in data.get("persisted", []):
        if row.get("kind") == kind or row.get("id") == kind:
            state = str(row.get("state") or "unknown")
            if state not in {"stopped", "unknown"}:
                return state
    return "stopped"


class ControlCenterUXApp(ControlCenterApp):
    """Cleaner information architecture over the existing safe Control Center logic."""

    def _build_overview(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=18)
        self.overview_frame = frame
        notebook.add(frame, text="Overview")

        ttk.Label(frame, text="Local MCP Control Center", font=("Helvetica", 22, "bold")).pack(anchor="w")
        ttk.Label(
            frame,
            text="System health at a glance. Use Runtime for Start/Stop controls and Tools for tool policy.",
        ).pack(anchor="w", pady=(4, 18))

        summary = ttk.LabelFrame(frame, text="System summary", padding=14)
        summary.pack(fill="x")
        self.overview_text = tk.StringVar()
        ttk.Label(summary, textvariable=self.overview_text, justify="left", font=("Menlo", 12)).pack(anchor="w")
        self.bridge_metrics = tk.StringVar()
        ttk.Label(summary, textvariable=self.bridge_metrics, justify="left", font=("Menlo", 12)).pack(anchor="w", pady=(8, 0))
        self.workspace_health_text = tk.StringVar(value="No registered project scope")
        health = ttk.LabelFrame(frame, text="Workspace health", padding=10)
        health.pack(fill="x", pady=(12, 0))
        ttk.Label(health, textvariable=self.workspace_health_text, justify="left", font=("Menlo", 10)).pack(anchor="w")

        navigation = ttk.LabelFrame(frame, text="Go to", padding=12)
        navigation.pack(fill="x", pady=(16, 0))
        ttk.Button(navigation, text="Runtime & Connection", command=self._open_runtime).pack(side="left", padx=(0, 8))
        ttk.Button(navigation, text="Tools", command=self._open_tools).pack(side="left", padx=(0, 8))
        ttk.Button(navigation, text="Approvals", command=self._open_approvals).pack(side="left", padx=(0, 8))
        ttk.Button(navigation, text="Refresh status", command=self.refresh_all).pack(side="left")

        ttk.Label(
            frame,
            text=(
                "Overview is intentionally read-mostly so the same Start/Stop actions are not duplicated across pages. "
                "Runtime is the single place for service controls and tunnel diagnostics."
            ),
            wraplength=920,
        ).pack(anchor="w", pady=(18, 0))

    def _build_tools(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        self.tools_frame = frame
        notebook.add(frame, text="Tools")

        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 8))
        ttk.Label(header, text="Tools", font=("Helvetica", 18, "bold")).pack(side="left")
        self.tool_summary = tk.StringVar(value="Registry total 0  •  Enabled 0  •  Running bridge tools 0  •  Bridge stopped  •  Showing 0")
        ttk.Label(header, textvariable=self.tool_summary).pack(side="right")

        search = ttk.Frame(frame)
        search.pack(fill="x", pady=(0, 8))
        ttk.Label(search, text="Search tools").pack(side="left", padx=(0, 8))
        self.tool_search_var = tk.StringVar()
        search_entry = ttk.Entry(search, textvariable=self.tool_search_var, width=42)
        search_entry.pack(side="left")
        ttk.Button(search, text="Clear", command=lambda: self.tool_search_var.set("")).pack(side="left", padx=(8, 0))
        ttk.Label(
            search,
            text="Searches name, group, risk, approval and description.",
        ).pack(side="left", padx=(12, 0))
        self.tool_search_var.trace_add("write", lambda *_args: self._refresh_tools())

        ttk.Label(
            frame,
            text="Disabled tools are not registered in the MCP bridge until the bridge is restarted.",
        ).pack(anchor="w", pady=(0, 8))

        columns = ("name", "group", "risk", "enabled", "approval", "description")
        self.tool_tree = ttk.Treeview(frame, columns=columns, show="headings", height=18)
        headings = {
            "name": "Tool",
            "group": "Group",
            "risk": "Risk",
            "enabled": "Enabled",
            "approval": "Approval",
            "description": "Description",
        }
        widths = {"name": 200, "group": 105, "risk": 80, "enabled": 75, "approval": 120, "description": 520}
        for column in columns:
            self.tool_tree.heading(column, text=headings[column])
            self.tool_tree.column(column, width=widths[column], anchor="w")
        self.tool_tree.pack(fill="both", expand=True)

        actions = ttk.Frame(frame)
        actions.pack(fill="x", pady=(8, 0))
        ttk.Button(actions, text="Toggle selected tool", command=self._toggle_tool).pack(side="left")
        ttk.Button(actions, text="Refresh", command=self.refresh_all).pack(side="left", padx=(8, 0))
        ttk.Button(actions, text="Configure Codex", command=lambda: show_codex_config(self.root, self.broker)).pack(side="left", padx=(8, 0))

    def _build_runtime(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=18)
        self.runtime_frame = frame
        notebook.add(frame, text="Runtime")

        ttk.Label(frame, text="Runtime & Connection", font=("Helvetica", 20, "bold")).pack(anchor="w")
        ttk.Label(
            frame,
            text="One place for service controls, tunnel setup, connection health and diagnostics.",
        ).pack(anchor="w", pady=(4, 14))

        bridge = ttk.LabelFrame(frame, text="MCP bridge", padding=12)
        bridge.pack(fill="x", pady=(0, 10))
        self.runtime_mcp_state = tk.StringVar(value="Status: -")
        ttk.Label(bridge, textvariable=self.runtime_mcp_state, width=48).pack(side="left")
        ttk.Button(bridge, text="Start", command=self._start_mcp).pack(side="left", padx=(8, 6))
        ttk.Button(bridge, text="Stop", command=self._stop_mcp).pack(side="left")
        ttk.Button(bridge, text="Restart bridge", command=self._restart_bridge).pack(side="left", padx=(8, 0))
        self.runtime_bridge_metrics = tk.StringVar()
        ttk.Label(frame, textvariable=self.runtime_bridge_metrics, justify="left", font=("Menlo", 11)).pack(anchor="w", pady=(0, 10))

        tunnel = ttk.LabelFrame(frame, text="Secure tunnel", padding=12)
        tunnel.pack(fill="x", pady=(0, 10))
        self.runtime_tunnel_state = tk.StringVar(value="Status: -")
        ttk.Label(tunnel, textvariable=self.runtime_tunnel_state, width=48).pack(side="left")
        ttk.Button(tunnel, text="Start", command=self._start_tunnel).pack(side="left", padx=(8, 6))
        ttk.Button(tunnel, text="Stop", command=self._stop_tunnel).pack(side="left")

        ttk.Label(
            frame,
            text="Note: the secure tunnel starts its own fixed MCP bridge. Stop a standalone MCP bridge before starting the tunnel.",
            wraplength=920,
        ).pack(anchor="w", pady=(0, 10))

        connection = ttk.LabelFrame(frame, text="Connection", padding=12)
        connection.pack(fill="x", pady=(0, 10))
        self.runtime_connection_state = tk.StringVar(value="OpenAI connection: -")
        ttk.Label(connection, textvariable=self.runtime_connection_state, width=48).pack(side="left")
        ttk.Button(connection, text="Open ChatGPT settings", command=self._open_chatgpt_settings).pack(side="left", padx=(8, 0))

        setup = ttk.LabelFrame(frame, text="Tunnel setup", padding=12)
        setup.pack(fill="x", pady=(0, 10))
        ttk.Button(setup, text="Configure tunnel", command=self._configure_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(setup, text="Clear saved key", command=self._clear_tunnel_key).pack(side="left")

        diagnostics = ttk.LabelFrame(frame, text="Diagnostics", padding=12)
        diagnostics.pack(fill="x", pady=(0, 10))
        ttk.Button(diagnostics, text="Run tunnel doctor", command=self._doctor_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(diagnostics, text="Refresh", command=self.refresh_all).pack(side="left")

        details = ttk.LabelFrame(frame, text="Runtime details", padding=12)
        details.pack(fill="both", expand=True)
        self.runtime_text = tk.StringVar()
        ttk.Label(
            details,
            textvariable=self.runtime_text,
            justify="left",
            font=("Menlo", 10),
            wraplength=1080,
        ).pack(anchor="w", fill="x")

    def _refresh_overview(self) -> None:
        runtime = self.broker.invoke("runtime_status", actor="user")
        approvals = self.broker.actionable_approvals()
        pending_count = sum(approval["status"] == "pending" for approval in approvals)
        approved_count = sum(approval["status"] == "approved" for approval in approvals)
        bridge = runtime.get("bridge", self._bridge_status_cache)
        self._bridge_status_cache = bridge
        self.bridge_metrics.set(format_bridge_metrics(bridge))
        self.overview_text.set(
            f"Control Center: {runtime.get('control_center', 'ready')}\n"
            f"Policy version: {runtime.get('policy_version')}\n"
            f"MCP bridge: {runtime.get('mcp_bridge')}\n"
            f"Tunnel: {runtime.get('tunnel')}\n"
            f"ChatGPT path: {runtime.get('chatgpt_path')}\n"
            f"Approvals: {pending_count} pending, {approved_count} ready to apply"
        )
        self._refresh_workspace_health()

    def _refresh_tools(self) -> None:
        if not hasattr(self, "tool_tree"):
            return
        rows = self.broker.tool_rows()
        query = self.tool_search_var.get() if hasattr(self, "tool_search_var") else ""
        shown = filter_tool_rows(rows, query)
        selected = tuple(self.tool_tree.selection())
        for item in self.tool_tree.get_children():
            self.tool_tree.delete(item)
        for row in shown:
            self.tool_tree.insert(
                "",
                "end",
                iid=row["name"],
                values=(
                    row["name"],
                    row["group"],
                    row["risk"],
                    "yes" if row["enabled"] else "no",
                    row["approval_mode"],
                    row["description"],
                ),
            )
        restored = tuple(name for name in selected if name in {row["name"] for row in shown})
        if restored:
            self.tool_tree.selection_set(*restored)
        self.tool_summary.set(tool_summary_text(rows, len(shown), self._bridge_status_cache))

    def _refresh_runtime(self) -> None:
        data = self.supervisor.status()
        tunnel = data.get("tunnel", {})
        tunnel_state = str(tunnel.get("state") or "stopped")
        mcp_state = _process_state(data, "mcp_bridge")
        bridge = self._bridge_status_cache
        if bridge.get("stale"):
            mcp_label = "Bridge stale — restart required"
        elif mcp_state == "stopped" and tunnel_state in {"starting", "running", "healthy", "ready", "unhealthy"}:
            mcp_label = "managed by secure tunnel"
        else:
            mcp_label = mcp_state
        control_plane = tunnel.get("control_plane", {})
        connection_state = control_plane.get("state", "-") if tunnel_state != "stopped" else "-"
        self.runtime_mcp_state.set(f"Status: {mcp_label}")
        self.runtime_tunnel_state.set(f"Status: {tunnel_state}")
        self.runtime_connection_state.set(f"OpenAI connection: {connection_state}")
        self.runtime_bridge_metrics.set(format_bridge_metrics(bridge))
        self.runtime_text.set(format_runtime_status(data))

    def _open_tools(self) -> None:
        self.notebook.select(self.tools_frame)

    def _open_runtime(self) -> None:
        self.notebook.select(self.runtime_frame)


def launch_gui(broker: Broker, supervisor: RuntimeSupervisor) -> None:
    ControlCenterUXApp(broker, supervisor).run()
