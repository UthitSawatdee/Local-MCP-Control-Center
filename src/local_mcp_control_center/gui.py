from __future__ import annotations

import re
import shutil
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any

from .broker import Broker
from .browser import LOCAL_BROWSER_PROFILE_NAME
from .models import ApprovalMode, Capability, ScopeKind
from .supervisor import RuntimeSupervisor


BRIDGE_POLL_INTERVAL_MS = 1_000

APP_TITLE_FONT = ("Helvetica Neue", 22, "bold")
SECTION_TITLE_FONT = ("Helvetica Neue", 16, "bold")
BODY_FONT = ("Helvetica Neue", 13)
MONO_FONT = ("SF Mono", 11)
ERROR_FOREGROUND = "#a33a3a"

STATE_LABELS = {
    "not_configured": "Not configured",
    "configured_stopped": "Configured, stopped",
    "not_ready": "Not ready",
    "ready_via_tunnel": "Ready via tunnel",
    "tunnel_client_running": "Tunnel client running",
    "not_directly_observable": "Not directly observable",
    "stopped": "Stopped",
    "starting": "Starting",
    "running": "Running",
    "healthy": "Healthy",
    "ready": "Ready",
    "unhealthy": "Unhealthy",
    "unauthorized": "Unauthorized",
}


def display_value(value: Any, fallback: str = "Unknown") -> str:
    """Render optional runtime values without implying a healthy state."""
    if value is None or value == "":
        return fallback
    return str(value)


def humanize_state(value: Any, fallback: str = "Unknown") -> str:
    """Turn machine state identifiers into concise labels for people."""
    if value is None or value == "":
        return fallback
    text = str(value)
    return STATE_LABELS.get(text, text.replace("_", " ").capitalize())


def filter_rows(rows: list[dict[str, Any]], query: str, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    """Filter visible table rows using a case-insensitive plain-text query."""
    needle = query.strip().lower()
    if not needle:
        return list(rows)
    return [
        row
        for row in rows
        if any(needle in str(row.get(field, "")).lower() for field in fields)
    ]


def filter_tool_rows(rows: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    """Filter tools across the fields a user can see in the table."""
    needle = query.strip().lower()
    if not needle:
        return list(rows)
    return [
        row
        for row in rows
        if needle in " ".join(
            str(row.get(field, ""))
            for field in ("name", "group", "risk", "approval_mode", "description")
        ).lower()
        or needle in tool_approval_label(row).lower()
    ]


def tool_approval_label(row: dict[str, Any]) -> str:
    """Show the effective live execution state, including fail-closed tools."""
    if row.get("live_execution_supported") is False:
        if row.get("live_approval_required") is True and row.get("live_approval_available") is False:
            return "Preview only"
        return "Unavailable"
    return humanize_state(row.get("approval_mode"), "Unknown")


def filter_audit_rows(rows: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    """Filter audit rows without changing the source ordering or row identity."""
    return filter_rows(
        rows,
        query,
        ("seq", "occurred_at", "actor", "tool", "decision", "target_display", "error_code"),
    )


def format_overview_status(runtime: dict[str, Any], pending_count: int, approved_count: int) -> str:
    """Build a compact, source-backed status block for the Overview page."""
    bridge = runtime.get("bridge") if isinstance(runtime.get("bridge"), dict) else {}
    lines = [
        f"Policy v{display_value(runtime.get('policy_version'))}  ·  MCP bridge: {humanize_state(runtime.get('mcp_bridge'))}",
        f"Tunnel: {humanize_state(runtime.get('tunnel'))}  ·  ChatGPT path: {humanize_state(runtime.get('chatgpt_path'))}",
        f"Connection: {humanize_state(runtime.get('chatgpt_connection'))}  ·  Approvals: {pending_count} pending / {approved_count} ready",
    ]
    if bridge.get("stale"):
        lines.append("Action required: restart the bridge to apply the latest policy.")
    return "\n".join(lines)


def scope_id_for_label(label: str) -> str:
    """Build a valid stable scope ID from a Finder-selected name."""
    candidate = re.sub(r"[^a-zA-Z0-9_-]+", "-", label.lower()).strip("-") or "scope"
    if len(candidate) < 2 or not re.match(r"^[a-zA-Z]", candidate):
        candidate = f"scope-{candidate}"
    return candidate[:54]


def format_bridge_state(data: dict[str, Any]) -> str:
    """Return a short bridge state suitable for status labels."""
    if data.get("stale"):
        return "Bridge stale"
    state = data.get("state")
    return f"Bridge {humanize_state(state)}" if state else "Bridge unavailable"


def format_bridge_metrics(data: dict[str, Any]) -> str:
    """Build the compact catalog, policy, and live-bridge summary."""
    lines = [
        f"Registry total: {display_value(data.get('registry_total'))}  ·  "
        f"Enabled: {display_value(data.get('enabled_count'))}  ·  "
        f"Running bridge tools: {display_value(data.get('running_tool_count'))}  ·  "
        f"{format_bridge_state(data)}",
    ]
    if data.get("stale"):
        lines.append("Action: Restart bridge to apply the latest policy.")
    return "\n".join(lines)


def format_runtime_status(data: dict[str, Any]) -> str:
    """Build a secret-free runtime summary for the GUI."""
    tunnel = data.get("tunnel") if isinstance(data.get("tunnel"), dict) else {}
    tunnel_live = tunnel.get("state") in {"starting", "running", "healthy", "ready", "unhealthy"}
    health = tunnel.get("health") if isinstance(tunnel.get("health"), dict) else {}
    health_state = display_value(health.get("state"), "Unavailable") if tunnel_live else "Not running"
    control_plane = tunnel.get("control_plane") if isinstance(tunnel.get("control_plane"), dict) else {}
    control_plane_state = display_value(control_plane.get("state"), "Unavailable") if tunnel_live else "Not running"
    key_suffix = tunnel.get("api_key_suffix")
    stored_key = f"{display_value(tunnel.get('api_key'), 'Missing')} ({key_suffix})" if key_suffix else display_value(tunnel.get("api_key"), "Missing")
    lines = [
        f"MCP bridge process: {display_value(data.get('processes'), 'Unavailable')}",
        f"Persisted runtime records: {display_value(data.get('persisted'), 'Unavailable')}",
        f"Tunnel: {display_value(tunnel.get('state'))}",
        f"Tunnel client: {display_value(tunnel.get('client_path'), 'Unavailable')} ({'available' if tunnel.get('client_available') else 'not found'})",
        f"Profile: {display_value(tunnel.get('profile'), 'Not configured')}",
        f"Tunnel ID: {display_value(tunnel.get('tunnel_id'), 'Not configured')}",
        f"Saved API key: {stored_key}",
        f"Health: {health_state}",
        f"OpenAI connection: {control_plane_state}",
    ]
    if control_plane.get("message"):
        lines.append(control_plane["message"])
    lines.extend([
        f"Profile directory: {display_value(tunnel.get('profile_dir'), 'Unavailable')}",
        "Key Active/Inactive is managed on OpenAI Platform. This screen proves the saved key is accepted only when OpenAI connection has no authorization error.",
    ])
    return "\n".join(lines)


def format_workspace_health(data: dict[str, Any]) -> str:
    """Build a compact, read-only project health summary for the Portal."""
    project = data.get("project", {})
    git = data.get("git", {})
    runtime = data.get("runtime", {})
    services = data.get("services", {})
    environment = data.get("environment", {})
    branch = git.get("branch") or "-"
    git_parts = [str(git.get("state", "unavailable")), str(branch)]
    if git.get("ahead"):
        git_parts.append(f"ahead {git['ahead']}")
    if git.get("behind"):
        git_parts.append(f"behind {git['behind']}")
    runtime_total = len(runtime)
    runtime_available = sum(
        1 for value in runtime.values()
        if isinstance(value, dict) and value.get("state") == "available"
    )
    service_total = len(services)
    service_listening = sum(
        1 for value in services.values()
        if isinstance(value, dict) and value.get("state") == "listening"
    )
    tracked_warnings = environment.get("tracked_environment_warnings", [])
    lines = [
        f"Project: {project.get('name', '-')} ({project.get('id', '-')})",
        f"Git: {' · '.join(git_parts)}",
        f"Runtime: {runtime_available}/{runtime_total} available",
        f"Services: {service_listening}/{service_total} listening",
        f"Capsule drift: {len(data.get('capsule_drift', []))}",
        f"Tracked environment warnings: {len(tracked_warnings) if isinstance(tracked_warnings, list) else 0}",
        f"Unfinished runs: {len(data.get('unfinished_runs', [])) if isinstance(data.get('unfinished_runs', []), list) else 0}",
        f"Storage: {data.get('filesystem', {}).get('file_count', 0)} files, {data.get('filesystem', {}).get('bytes', 0)} bytes",
    ]
    return "\n".join(lines)


class ControlCenterApp:
    """Native Tkinter MVP for policy, approval, audit, and runtime controls."""

    def __init__(self, broker: Broker, supervisor: RuntimeSupervisor):
        self.broker = broker
        self.supervisor = supervisor
        self.root = tk.Tk()
        self.root.title("Local MCP Control Center")
        self.root.geometry("1200x760")
        self.root.minsize(980, 620)
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self._scope_id: str | None = None
        self._scope_vars: dict[str, tk.BooleanVar] = {}
        self.scope_enabled = tk.BooleanVar(value=True)
        self._bridge_status_cache: dict[str, Any] = {}
        self._bridge_poll_job: str | None = None
        self._build()
        self.refresh_all()
        self._bridge_poll_job = self.root.after(BRIDGE_POLL_INTERVAL_MS, self._poll_bridge_status)

    def run(self) -> None:
        self.root.mainloop()

    def _build(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("aqua")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=APP_TITLE_FONT)
        style.configure("Section.TLabel", font=SECTION_TITLE_FONT)
        style.configure("Body.TLabel", font=BODY_FONT)
        # Aqua supplies an appearance-aware label color; avoid hard-coding a
        # dark gray that becomes unreadable when macOS is in Dark Mode.
        style.configure("Muted.TLabel", font=("Helvetica Neue", 12))
        style.configure("Status.TLabel", font=("Helvetica Neue", 14, "bold"))
        style.configure("Error.TLabel", foreground=ERROR_FOREGROUND)
        style.configure("Mono.TLabel", font=MONO_FONT)
        style.configure("Treeview", rowheight=26)
        style.configure("Treeview.Heading", font=("Helvetica Neue", 11, "bold"))
        self.root.bind("<Command-r>", lambda _event: self.refresh_all())
        self.root.bind("<Control-r>", lambda _event: self.refresh_all())
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=16, pady=16)
        notebook.enable_traversal()
        self.notebook = notebook
        self._build_overview(notebook)
        self._build_paths(notebook)
        self._build_tools(notebook)
        self._build_approvals(notebook)
        self._build_audit(notebook)
        self._build_runtime(notebook)
        self._build_browser(notebook)

    def _build_overview(self, notebook: ttk.Notebook) -> None:
        container = ttk.Frame(notebook)
        self.overview_frame = container
        notebook.add(container, text="Overview")
        canvas = tk.Canvas(
            container,
            borderwidth=0,
            highlightthickness=0,
            background=ttk.Style(self.root).lookup("TFrame", "background"),
        )
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        frame = ttk.Frame(canvas, padding=18)
        window = canvas.create_window((0, 0), window=frame, anchor="nw")
        frame.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(window, width=event.width))
        self.overview_canvas = canvas

        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 4))
        ttk.Label(header, text="Local MCP Control Center", style="Title.TLabel").pack(side="left")
        ttk.Button(header, text="Refresh status", command=self.refresh_all).pack(side="right")
        ttk.Label(
            frame,
            text="Policy, connection and approval state from the local control plane.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 12))

        self.overview_state = tk.StringVar(value="Status unavailable")
        ttk.Label(frame, textvariable=self.overview_state, style="Status.TLabel").pack(anchor="w", pady=(0, 6))

        current = ttk.LabelFrame(frame, text="Current state", padding=10)
        current.pack(fill="x")
        self.overview_text = tk.StringVar()
        ttk.Label(current, textvariable=self.overview_text, justify="left", style="Body.TLabel").pack(anchor="w")
        self.bridge_metrics = tk.StringVar()
        ttk.Label(current, textvariable=self.bridge_metrics, justify="left", style="Mono.TLabel").pack(anchor="w", pady=(6, 0))

        self.workspace_health_text = tk.StringVar(value="No registered project scope")
        health = ttk.LabelFrame(frame, text="Workspace health", padding=10)
        health.pack(fill="x", pady=(8, 0))
        ttk.Label(health, textvariable=self.workspace_health_text, justify="left", style="Mono.TLabel").pack(anchor="w")

        actions = ttk.LabelFrame(frame, text="Quick actions", padding=12)
        actions.pack(fill="x", pady=(10, 0))
        connection_actions = ttk.Frame(actions)
        connection_actions.pack(anchor="w", pady=(0, 8))
        ttk.Label(connection_actions, text="Services", style="Muted.TLabel").pack(side="left", padx=(0, 12))
        ttk.Button(connection_actions, text="Start MCP bridge", command=self._start_mcp).pack(side="left", padx=(0, 8))
        ttk.Button(connection_actions, text="Stop MCP bridge", command=self._stop_mcp).pack(side="left", padx=(0, 8))
        ttk.Button(connection_actions, text="Configure tunnel", command=self._configure_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(connection_actions, text="Start tunnel", command=self._start_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(connection_actions, text="Stop tunnel", command=self._stop_tunnel).pack(side="left")
        review_actions = ttk.Frame(actions)
        review_actions.pack(anchor="w")
        ttk.Label(review_actions, text="Review", style="Muted.TLabel").pack(side="left", padx=(0, 18))
        ttk.Button(review_actions, text="Open approvals", command=self._open_approvals).pack(side="left", padx=(0, 8))
        ttk.Button(review_actions, text="Clear saved key", command=self._clear_tunnel_key).pack(side="left", padx=(0, 8))
        ttk.Button(review_actions, text="Open ChatGPT settings", command=self._open_chatgpt_settings).pack(side="left")
        ttk.Label(
            frame,
            text=(
                "วิธีเริ่มต้น: เพิ่ม scope ใน Allowed Paths, เปิด tools/permissions ตามงานจริง, "
                "จากนั้น Configure tunnel และ Start tunnel ก่อนเชื่อมต่อจาก ChatGPT. "
                "การลบไฟล์, Git restore และ Git push ต้องอนุมัติใน Approvals."
            ),
            wraplength=900,
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(10, 0))

    def _build_paths(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Allowed Paths")
        top = ttk.Frame(frame)
        top.pack(fill="x", pady=(0, 8))
        ttk.Button(top, text="Add folder scope", command=lambda: self._add_scope("folder")).pack(side="left")
        ttk.Button(top, text="Add file scope", command=lambda: self._add_scope("file")).pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Remove selected", command=self._remove_scope).pack(side="left", padx=8)
        columns = ("id", "label", "kind", "enabled", "expose", "permissions", "root")
        self.scope_tree = ttk.Treeview(frame, columns=columns, show="headings", height=12)
        headings = {"id": "ID", "label": "Label", "kind": "Kind", "enabled": "Enabled", "expose": "MCP", "permissions": "Permissions", "root": "Root"}
        widths = {"id": 130, "label": 180, "kind": 90, "enabled": 80, "expose": 70, "permissions": 330, "root": 380}
        for column in columns:
            self.scope_tree.heading(column, text=headings[column])
            self.scope_tree.column(column, width=widths[column], anchor="w")
        self.scope_tree.pack(fill="both", expand=True)
        self.scope_tree.bind("<<TreeviewSelect>>", self._select_scope)

        editor = ttk.LabelFrame(frame, text="Selected scope policy", padding=10)
        editor.pack(fill="x", pady=(10, 0))
        self.scope_label = tk.StringVar(value="No scope selected")
        ttk.Label(editor, textvariable=self.scope_label).grid(row=0, column=0, columnspan=7, sticky="w", pady=(0, 8))
        self._scope_vars = {capability: tk.BooleanVar(value=False) for capability in ("read", "execute", "write", "create", "rename", "move", "delete")}
        for index, capability in enumerate(self._scope_vars):
            ttk.Checkbutton(editor, text=capability, variable=self._scope_vars[capability]).grid(row=1, column=index, padx=4, sticky="w")
        self.scope_expose = tk.BooleanVar(value=False)
        ttk.Checkbutton(editor, text="Enabled", variable=self.scope_enabled).grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Checkbutton(editor, text="Expose to MCP", variable=self.scope_expose).grid(row=2, column=1, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Button(editor, text="Save policy", command=self._save_scope_policy).grid(row=2, column=5, columnspan=2, sticky="e", pady=(8, 0))

    def _build_tools(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=18)
        self.tools_frame = frame
        notebook.add(frame, text="Tools")

        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 4))
        ttk.Label(header, text="Tools", style="Section.TLabel").pack(side="left")
        self.tool_summary = tk.StringVar()
        ttk.Label(header, textvariable=self.tool_summary, style="Muted.TLabel").pack(side="right")

        search = ttk.Frame(frame)
        search.pack(fill="x", pady=(8, 4))
        ttk.Label(search, text="Find a tool").pack(side="left", padx=(0, 8))
        self.tool_search_var = tk.StringVar()
        tool_search = ttk.Entry(search, textvariable=self.tool_search_var, width=44)
        tool_search.pack(side="left")
        ttk.Button(search, text="Clear", command=lambda: self.tool_search_var.set("")).pack(side="left", padx=(8, 0))
        ttk.Label(search, text="name, group, risk, approval or description", style="Muted.TLabel").pack(side="left", padx=(12, 0))
        self.tool_search_var.trace_add("write", lambda *_args: self._refresh_tools())
        self.root.bind("<Command-f>", lambda _event: self._focus_tool_search(tool_search))
        self.root.bind("<Control-f>", lambda _event: self._focus_tool_search(tool_search))

        ttk.Label(
            frame,
            text="Disabled tools are not registered in the MCP bridge until it is restarted.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(0, 8))

        self.tool_filter_state = tk.StringVar(value="No tool data loaded")
        ttk.Label(frame, textvariable=self.tool_filter_state, style="Muted.TLabel").pack(anchor="w", pady=(0, 4))

        table = ttk.Frame(frame)
        table.pack(fill="both", expand=True)
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        columns = ("name", "group", "risk", "enabled", "approval", "description")
        self.tool_tree = ttk.Treeview(table, columns=columns, show="headings", height=20, selectmode="browse")
        headings = {"name": "Tool", "group": "Group", "risk": "Risk", "enabled": "Enabled", "approval": "Approval", "description": "Description"}
        widths = {"name": 190, "group": 100, "risk": 90, "enabled": 80, "approval": 120, "description": 540}
        for column in columns:
            self.tool_tree.heading(column, text=headings[column])
            self.tool_tree.column(column, width=widths[column], anchor="w")
        self.tool_tree.grid(row=0, column=0, sticky="nsew")
        tool_scroll = ttk.Scrollbar(table, orient="vertical", command=self.tool_tree.yview)
        tool_scroll.grid(row=0, column=1, sticky="ns")
        tool_horizontal = ttk.Scrollbar(table, orient="horizontal", command=self.tool_tree.xview)
        tool_horizontal.grid(row=1, column=0, sticky="ew")
        self.tool_tree.configure(yscrollcommand=tool_scroll.set, xscrollcommand=tool_horizontal.set)
        self.tool_tree.bind("<<TreeviewSelect>>", self._update_tool_action_state)
        self.tool_tree.bind("<Return>", lambda _event: self._toggle_tool())

        actions = ttk.Frame(frame)
        actions.pack(fill="x", pady=(8, 0))
        self.tool_toggle_button = ttk.Button(actions, text="Toggle selected tool", command=self._toggle_tool)
        self.tool_toggle_button.pack(side="left")
        ttk.Button(actions, text="Refresh", command=self.refresh_all).pack(side="left", padx=(8, 0))

    def _build_approvals(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=12)
        self.approvals_frame = frame
        notebook.add(frame, text="Approvals")
        self.approval_state = tk.StringVar()
        ttk.Label(
            frame,
            text="Only dangerous delete_file, git_restore_file, and git_push requests appear here. Other allowed actions run immediately. Dangerous approval is exact, expiring, and one-time.",
            wraplength=1050,
        ).pack(anchor="w", pady=(0, 4))
        ttk.Label(frame, textvariable=self.approval_state).pack(anchor="w", pady=(0, 8))
        columns = ("id", "status", "tool", "operation", "target", "expires")
        self.approval_tree = ttk.Treeview(frame, columns=columns, show="headings", height=18)
        headings = {"id": "Approval", "status": "Status", "tool": "Tool", "operation": "Operation", "target": "Target", "expires": "Expires"}
        widths = {"id": 280, "status": 100, "tool": 160, "operation": 120, "target": 430, "expires": 200}
        for column in columns:
            self.approval_tree.heading(column, text=headings[column])
            self.approval_tree.column(column, width=widths[column], anchor="w")
        self.approval_tree.pack(fill="both", expand=True)
        actions = ttk.Frame(frame)
        actions.pack(anchor="w", pady=(8, 0))
        ttk.Button(actions, text="Refresh approvals", command=self.refresh_all).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Approve once", command=self._approve).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Deny", command=self._deny).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Apply approved", command=self._apply).pack(side="left")

    def _build_audit(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=18)
        self.audit_frame = frame
        notebook.add(frame, text="Audit log")

        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 4))
        ttk.Label(header, text="Audit log", style="Section.TLabel").pack(side="left")
        self.audit_state = tk.StringVar()
        ttk.Label(header, textvariable=self.audit_state, style="Muted.TLabel").pack(side="right")

        search = ttk.Frame(frame)
        search.pack(fill="x", pady=(8, 4))
        ttk.Label(search, text="Find an event").pack(side="left", padx=(0, 8))
        self.audit_search_var = tk.StringVar()
        audit_search = ttk.Entry(search, textvariable=self.audit_search_var, width=44)
        audit_search.pack(side="left")
        ttk.Button(search, text="Clear", command=lambda: self.audit_search_var.set("")).pack(side="left", padx=(8, 0))
        ttk.Label(search, text="tool, decision, target, actor or error", style="Muted.TLabel").pack(side="left", padx=(12, 0))
        self.audit_search_var.trace_add("write", lambda *_args: self._refresh_audit())
        self.root.bind("<Command-2>", lambda _event: self._focus_audit_search(audit_search))
        self.root.bind("<Control-2>", lambda _event: self._focus_audit_search(audit_search))

        self.audit_filter_state = tk.StringVar(value="No audit data loaded")
        ttk.Label(frame, textvariable=self.audit_filter_state, style="Muted.TLabel").pack(anchor="w", pady=(0, 4))

        table = ttk.Frame(frame)
        table.pack(fill="both", expand=True)
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        columns = ("seq", "time", "actor", "tool", "decision", "target", "error")
        self.audit_tree = ttk.Treeview(table, columns=columns, show="headings", height=20, selectmode="browse")
        headings = {"seq": "#", "time": "Time", "actor": "Actor", "tool": "Tool", "decision": "Decision", "target": "Target", "error": "Error"}
        widths = {"seq": 55, "time": 190, "actor": 100, "tool": 190, "decision": 130, "target": 380, "error": 180}
        for column in columns:
            self.audit_tree.heading(column, text=headings[column])
            self.audit_tree.column(column, width=widths[column], anchor="w")
        self.audit_tree.grid(row=0, column=0, sticky="nsew")
        audit_scroll = ttk.Scrollbar(table, orient="vertical", command=self.audit_tree.yview)
        audit_scroll.grid(row=0, column=1, sticky="ns")
        audit_horizontal = ttk.Scrollbar(table, orient="horizontal", command=self.audit_tree.xview)
        audit_horizontal.grid(row=1, column=0, sticky="ew")
        self.audit_tree.configure(yscrollcommand=audit_scroll.set, xscrollcommand=audit_horizontal.set)

        actions = ttk.Frame(frame)
        actions.pack(fill="x", pady=(8, 0))
        ttk.Button(actions, text="Verify audit chain", command=self._verify_audit).pack(side="left")
        ttk.Button(actions, text="Refresh", command=self.refresh_all).pack(side="left", padx=(8, 0))

    def _build_runtime(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=18)
        self.runtime_frame = frame
        notebook.add(frame, text="Runtime")
        header = ttk.Frame(frame)
        header.pack(fill="x", pady=(0, 4))
        ttk.Label(header, text="Runtime & connection", style="Section.TLabel").pack(side="left")
        ttk.Button(header, text="Refresh status", command=self.refresh_all).pack(side="right")
        ttk.Label(
            frame,
            text="Process state, tunnel health and connection evidence reported by the local supervisor.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(2, 14))
        self.runtime_state = tk.StringVar(value="Runtime status unavailable")
        ttk.Label(frame, textvariable=self.runtime_state, style="Status.TLabel").pack(anchor="w", pady=(0, 10))
        self.runtime_text = tk.StringVar()
        ttk.Label(frame, textvariable=self.runtime_text, justify="left", style="Mono.TLabel").pack(anchor="w")
        self.runtime_bridge_metrics = tk.StringVar()
        ttk.Label(frame, textvariable=self.runtime_bridge_metrics, justify="left", style="Mono.TLabel").pack(anchor="w", pady=(8, 0))
        actions = ttk.Frame(frame)
        actions.pack(anchor="w", pady=18)
        ttk.Button(actions, text="Configure tunnel", command=self._configure_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Start MCP", command=self._start_mcp).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Stop MCP", command=self._stop_mcp).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Restart bridge", command=self._restart_bridge).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Start tunnel", command=self._start_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Stop tunnel", command=self._stop_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Clear saved key", command=self._clear_tunnel_key).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Run tunnel doctor", command=self._doctor_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Refresh", command=self.refresh_all).pack(side="left")

    def _build_browser(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=18)
        self.browser_frame = frame
        notebook.add(frame, text="Browser")
        ttk.Label(frame, text="Browser Profiles", font=("Helvetica", 20, "bold")).pack(anchor="w")
        ttk.Label(
            frame,
            text="Browser automation stays behind Broker policy, the profile network policy, and the append-only audit chain.",
            wraplength=920,
        ).pack(anchor="w", pady=(4, 14))
        profile = ttk.LabelFrame(frame, text=f"Local Browser ({LOCAL_BROWSER_PROFILE_NAME})", padding=12)
        profile.pack(fill="x")
        ttk.Label(profile, text="Target: Motion ERP · Network: HTTP/HTTPS internet enabled").pack(anchor="w")
        self.browser_state = tk.StringVar(value="Status: stopped")
        ttk.Label(profile, textvariable=self.browser_state, justify="left", font=("Menlo", 11)).pack(anchor="w", pady=(8, 8))
        actions = ttk.Frame(profile)
        actions.pack(anchor="w")
        ttk.Button(actions, text="Open Browser", command=self._open_browser).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Refresh Status", command=self._refresh_browser).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Clear Session", command=self._clear_browser_session).pack(side="left")
        ttk.Label(
            frame,
            text="First login is manual in the owned Chromium window. Password fields and auth state never enter MCP snapshots or audit metadata. The four browser tools are enabled by default; restart the bridge after policy changes.",
            wraplength=920,
        ).pack(anchor="w", pady=(16, 0))

    def refresh_all(self) -> None:
        self._refresh_errors = {}
        refreshers = (
            ("bridge", self._refresh_bridge_metrics),
            ("overview", self._refresh_overview),
            ("scopes", self._refresh_scopes),
            ("tools", self._refresh_tools),
            ("approvals", self._refresh_approvals),
            ("audit", self._refresh_audit),
            ("runtime", self._refresh_runtime),
            ("browser", self._refresh_browser),
        )
        for area, refresher in refreshers:
            try:
                refresher()
            except Exception as exc:  # pragma: no cover - defensive UI boundary
                self._record_refresh_error(area, exc)
        if self._refresh_errors and hasattr(self, "overview_state"):
            areas = ", ".join(sorted(self._refresh_errors))
            self.overview_state.set(f"Refresh incomplete — unavailable: {areas}")

    def _record_refresh_error(self, area: str, error: Exception) -> None:
        """Keep the last useful table values while making a failed refresh explicit."""
        if not hasattr(self, "_refresh_errors"):
            self._refresh_errors = {}
        self._refresh_errors[area] = type(error).__name__
        message = f"{area.capitalize()} unavailable — showing last loaded data ({type(error).__name__})."
        target = {
            "tools": getattr(self, "tool_filter_state", None),
            "audit": getattr(self, "audit_filter_state", None),
            "approvals": getattr(self, "approval_state", None),
            "runtime": getattr(self, "runtime_state", None),
        }.get(area)
        if target is not None:
            target.set(message)
        if area == "bridge" and hasattr(self, "runtime_bridge_metrics"):
            self.runtime_bridge_metrics.set(message)
        if hasattr(self, "overview_state"):
            self.overview_state.set(f"Refresh incomplete — {area} status unavailable")

    def _restore_overview_status(self) -> None:
        """Restore the last source-backed banner after a live poll recovers."""
        if not hasattr(self, "overview_state"):
            return
        if self._refresh_errors:
            areas = ", ".join(sorted(self._refresh_errors))
            self.overview_state.set(f"Refresh incomplete — unavailable: {areas}")
            return
        runtime = getattr(self, "_last_runtime_status", {})
        bridge = self._bridge_status_cache
        if bridge.get("stale"):
            self.overview_state.set("Action required — MCP bridge is stale")
        elif runtime.get("tunnel") == "not_configured":
            self.overview_state.set("Setup required — secure tunnel is not configured")
        elif runtime.get("chatgpt_path") == "not_ready":
            self.overview_state.set("Ready locally — ChatGPT path is not ready")
        elif runtime:
            self.overview_state.set(f"Connection: {humanize_state(runtime.get('chatgpt_path'))}")
        else:
            self.overview_state.set("Status available")

    def _clear_refresh_error(self, area: str) -> None:
        if not hasattr(self, "_refresh_errors"):
            return
        self._refresh_errors.pop(area, None)
        self._restore_overview_status()

    def _refresh_bridge_metrics(self) -> dict[str, Any]:
        bridge = self.broker.bridge_status()
        self._bridge_status_cache = bridge
        if hasattr(self, "bridge_metrics"):
            self.bridge_metrics.set(format_bridge_metrics(bridge))
        if hasattr(self, "runtime_bridge_metrics"):
            self.runtime_bridge_metrics.set(format_bridge_metrics(bridge))
        if hasattr(self, "runtime_mcp_state"):
            state = "Bridge stale — restart required" if bridge.get("stale") else format_bridge_state(bridge)
            self.runtime_mcp_state.set(f"Status: {state}")
        return bridge

    def _poll_bridge_status(self) -> None:
        try:
            try:
                self._refresh_bridge_metrics()
            except Exception as exc:  # pragma: no cover - defensive UI boundary
                self._record_refresh_error("bridge", exc)
            else:
                self._clear_refresh_error("bridge")
            if hasattr(self, "tool_tree"):
                try:
                    self._refresh_tools()
                except Exception as exc:  # pragma: no cover - defensive UI boundary
                    self._record_refresh_error("tools", exc)
                else:
                    self._clear_refresh_error("tools")
        finally:
            try:
                self._bridge_poll_job = self.root.after(BRIDGE_POLL_INTERVAL_MS, self._poll_bridge_status)
            except tk.TclError:
                self._bridge_poll_job = None

    @staticmethod
    def _focus_tool_search(entry: ttk.Entry) -> str:
        entry.focus_set()
        entry.selection_range(0, "end")
        return "break"

    @staticmethod
    def _focus_audit_search(entry: ttk.Entry) -> str:
        entry.focus_set()
        entry.selection_range(0, "end")
        return "break"

    def _update_tool_action_state(self, _event: Any = None) -> None:
        if hasattr(self, "tool_toggle_button"):
            self.tool_toggle_button.configure(state="normal" if self.tool_tree.selection() else "disabled")

    def _refresh_overview(self) -> None:
        runtime = self.broker.invoke("runtime_status", actor="user")
        approvals = self.broker.actionable_approvals()
        pending_count = sum(approval["status"] == "pending" for approval in approvals)
        approved_count = sum(approval["status"] == "approved" for approval in approvals)
        if runtime.get("status") != "ok":
            message = runtime.get("message", runtime.get("error_code", "runtime status unavailable"))
            self.overview_state.set("Connection status unavailable")
            self.overview_text.set(f"Runtime status unavailable: {message}")
            self._refresh_workspace_health()
            return
        self._last_runtime_status = runtime
        bridge = runtime.get("bridge")
        if isinstance(bridge, dict):
            self._bridge_status_cache = bridge
        bridge_state = self._bridge_status_cache
        if bridge_state.get("stale"):
            self.overview_state.set("Action required — MCP bridge is stale")
        elif runtime.get("tunnel") == "not_configured":
            self.overview_state.set("Setup required — secure tunnel is not configured")
        elif runtime.get("chatgpt_path") == "not_ready":
            self.overview_state.set("Ready locally — ChatGPT path is not ready")
        else:
            self.overview_state.set(f"Connection: {humanize_state(runtime.get('chatgpt_path'))}")
        self.overview_text.set(format_overview_status(runtime, pending_count, approved_count))
        self._refresh_workspace_health()

    def _refresh_workspace_health(self) -> None:
        if not hasattr(self, "workspace_health_text"):
            return
        projects = [
            scope for scope in self.broker.store.list_scopes(include_disabled=False)
            if scope.kind == ScopeKind.PROJECT.value
        ]
        if not projects:
            self.workspace_health_text.set("No registered project scope")
            return
        result = self.broker.invoke(
            "workspace_observe",
            {"project_id": projects[0].id, "max_items": 50},
            actor="user",
        )
        if result.get("status") != "ok":
            self.workspace_health_text.set(
                f"Workspace health unavailable: {result.get('error_code', 'UNKNOWN_ERROR')}"
            )
            return
        self.workspace_health_text.set(format_workspace_health(result))

    def _refresh_scopes(self) -> None:
        if not hasattr(self, "scope_tree"):
            return
        selected = tuple(self.scope_tree.selection())
        rows = self.broker.policy.scope_summary(actor="user")
        for item in self.scope_tree.get_children():
            self.scope_tree.delete(item)
        for scope in rows:
            permissions = ", ".join(key for key, value in scope["permissions"].items() if value["allowed"]) or "none"
            self.scope_tree.insert("", "end", iid=scope["id"], values=(scope["id"], scope["label"], scope["kind"], "yes" if scope["enabled"] else "no", "yes" if scope["expose_to_mcp"] else "no", permissions, scope.get("root", "")))
        restored = tuple(scope_id for scope_id in selected if scope_id in {scope["id"] for scope in rows})
        if restored:
            self.scope_tree.selection_set(*restored)

    def _refresh_tools(self) -> None:
        selected = tuple(self.tool_tree.selection())
        rows = self.broker.tool_rows()
        query = self.tool_search_var.get() if hasattr(self, "tool_search_var") else ""
        shown = filter_tool_rows(rows, query)
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
                    tool_approval_label(row),
                    row["description"],
                ),
            )
        restored = tuple(name for name in selected if name in {row["name"] for row in shown})
        if restored:
            self.tool_tree.selection_set(*restored)
        if hasattr(self, "tool_summary"):
            bridge = self._bridge_status_cache
            self.tool_summary.set(
                f"Registry {display_value(bridge.get('registry_total'), str(len(rows)))}  |  "
                f"Enabled {display_value(bridge.get('enabled_count'), str(sum(bool(row['enabled']) for row in rows)))}  |  "
                f"Running {display_value(bridge.get('running_tool_count'))}  |  "
                f"{format_bridge_state(bridge)}"
            )
        if hasattr(self, "tool_filter_state"):
            if shown:
                self.tool_filter_state.set(f"Showing {len(shown)} of {len(rows)} tools")
            elif rows:
                self.tool_filter_state.set(f"No tools match ‘{query.strip()}’. Clear the search to show all {len(rows)} tools.")
            else:
                self.tool_filter_state.set("No tool definitions are available.")
        if hasattr(self, "tool_toggle_button"):
            self.tool_toggle_button.configure(state="normal" if restored else "disabled")

    def _refresh_approvals(self) -> None:
        requests = self.broker.actionable_approvals()
        selected = tuple(self.approval_tree.selection())
        for item in self.approval_tree.get_children():
            self.approval_tree.delete(item)
        pending_count = sum(request["status"] == "pending" for request in requests)
        approved_count = sum(request["status"] == "approved" for request in requests)
        self.approval_state.set(
            f"Pending: {pending_count}  |  Ready to apply: {approved_count}  |  Select a row before using an action button."
            if requests
            else "No dangerous requests are waiting. This is normal when ChatGPT has not requested delete, Git restore, or Git push."
        )
        for request in requests:
            intent = request["intent"]
            self.approval_tree.insert("", "end", iid=request["id"], values=(request["id"], request["status"], intent.get("tool"), intent.get("operation"), self.broker._intent_display(intent), request["expires_at"]))
        restored = tuple(approval_id for approval_id in selected if approval_id in {request["id"] for request in requests})
        if restored:
            self.approval_tree.selection_set(*restored)

    def _refresh_audit(self) -> None:
        rows = self.broker.audit_page(200)
        query = self.audit_search_var.get() if hasattr(self, "audit_search_var") else ""
        shown = filter_audit_rows(rows, query)
        selected = tuple(self.audit_tree.selection())
        for item in self.audit_tree.get_children():
            self.audit_tree.delete(item)
        for row in shown:
            self.audit_tree.insert(
                "",
                "end",
                iid=str(row["seq"]),
                values=(
                    row["seq"],
                    row["occurred_at"],
                    row["actor"],
                    row["tool"],
                    row["decision"],
                    row["target_display"],
                    row["error_code"] or "",
                ),
            )
        restored = tuple(seq for seq in selected if seq in {str(row["seq"]) for row in shown})
        if restored:
            self.audit_tree.selection_set(*restored)
        verification = self.broker.verify_audit()
        self.audit_state.set("Audit chain: valid" if verification["valid"] else f"Audit chain: INVALID — {verification['message']}")
        if hasattr(self, "audit_filter_state"):
            if shown:
                self.audit_filter_state.set(f"Showing {len(shown)} of {len(rows)} events")
            elif rows:
                self.audit_filter_state.set(f"No events match ‘{query.strip()}’. Clear the search to show all {len(rows)} events.")
            else:
                self.audit_filter_state.set("No audit events have been recorded.")

    def _refresh_runtime(self) -> None:
        data = self.supervisor.status()
        self.runtime_text.set(format_runtime_status(data))
        tunnel = data.get("tunnel") if isinstance(data.get("tunnel"), dict) else {}
        tunnel_state = display_value(tunnel.get("state"))
        control_plane = tunnel.get("control_plane") if isinstance(tunnel.get("control_plane"), dict) else {}
        connection_state = display_value(control_plane.get("state"), "Not observable")
        if hasattr(self, "runtime_state"):
            self.runtime_state.set(f"Tunnel: {tunnel_state}  ·  OpenAI connection: {connection_state}")
        if hasattr(self, "runtime_bridge_metrics"):
            self.runtime_bridge_metrics.set(format_bridge_metrics(self._bridge_status_cache))

    def _refresh_browser(self) -> None:
        if not hasattr(self, "browser_state"):
            return
        data = self.broker.browser.status()
        sessions = [item for item in data.get("sessions", []) if item.get("profile") == LOCAL_BROWSER_PROFILE_NAME]
        if not sessions:
            self.browser_state.set("Status: Browser stopped\nLogin state: Login required")
            return
        session = sessions[0]
        auth = session.get("authenticated")
        login_state = "Logged in" if auth is True else "Login required" if auth is False else "Unknown"
        self.browser_state.set(
            f"Status: running\nLogin state: {login_state}\nCurrent URL: {session.get('current_url') or 'about:blank'}"
        )

    def _open_browser(self) -> None:
        result = self.broker.invoke("browser_open", {"profile": LOCAL_BROWSER_PROFILE_NAME}, actor="user")
        if result.get("status") != "ok":
            messagebox.showerror("Browser", result.get("message", result.get("error_code", "Browser open failed")))
        self.refresh_all()

    def _clear_browser_session(self) -> None:
        sessions = [item for item in self.broker.browser.status().get("sessions", []) if item.get("profile") == LOCAL_BROWSER_PROFILE_NAME]
        if not sessions:
            self._refresh_browser()
            return
        if not messagebox.askyesno("Clear browser session", "Close the owned Motion ERP browser session? The persistent profile remains available for the next login."):
            return
        for session in sessions:
            session_id = session.get("browser_session_id")
            if isinstance(session_id, str):
                self.broker.invoke("browser_close", {"browser_session_id": session_id}, actor="user")
        self.refresh_all()

    def _add_scope(self, selection_kind: str) -> None:
        selected = (
            filedialog.askdirectory(title="Choose an allowed folder")
            if selection_kind == "folder"
            else filedialog.askopenfilename(title="Choose an allowed file")
        )
        if not selected:
            return
        label = Path(selected).name or "Allowed folder"
        scope_id = scope_id_for_label(label)
        index = 2
        existing = {scope["id"] for scope in self.broker.policy.scope_summary(actor="user")}
        base_id = scope_id
        while scope_id in existing:
            scope_id = f"{base_id}-{index}"
            index += 1
        kind = (
            ScopeKind.PROJECT
            if selection_kind == "folder" and (Path(selected) / ".git").exists()
            else ScopeKind.DIRECTORY
            if selection_kind == "folder"
            else ScopeKind.FILE
        )
        result = self.broker.add_scope(
            scope_id=scope_id,
            label=label,
            kind=kind,
            root=selected,
            expose_to_mcp=True,
            permissions={"read": {"allowed": True, "approval_mode": ApprovalMode.NEVER}},
        )
        if result["status"] != "ok":
            messagebox.showerror("Scope rejected", result.get("message", result.get("error_code")))
        self.refresh_all()

    def _remove_scope(self) -> None:
        selection = self.scope_tree.selection()
        if not selection:
            return
        scope_id = selection[0]
        if messagebox.askyesno("Remove scope", f"Remove {scope_id}? This does not delete files."):
            self.broker.remove_scope(scope_id)
            self.refresh_all()

    def _select_scope(self, _event: Any = None) -> None:
        selection = self.scope_tree.selection()
        if not selection:
            return
        self._scope_id = selection[0]
        scope = self.broker.store.get_scope(self._scope_id)
        if not scope:
            return
        permissions = self.broker.store.permissions(self._scope_id)
        for capability, variable in self._scope_vars.items():
            variable.set(bool(permissions.get(capability, {}).get("allowed", False)))
        self.scope_enabled.set(scope.enabled)
        self.scope_expose.set(scope.expose_to_mcp)
        self.scope_label.set(f"{scope.label} — {scope.root}")

    def _save_scope_policy(self) -> None:
        if not self._scope_id:
            return
        for capability, variable in self._scope_vars.items():
            self.broker.set_permission(
                self._scope_id,
                capability,
                allowed=variable.get(),
                approval_mode="always" if capability == Capability.DELETE else "never",
            )
        self.broker.update_scope(self._scope_id, enabled=self.scope_enabled.get(), expose_to_mcp=self.scope_expose.get())
        self.refresh_all()

    def _toggle_tool(self) -> None:
        selection = self.tool_tree.selection()
        if not selection:
            return
        name = selection[0]
        policy = self.broker.store.get_tool_policy(name)
        if not policy:
            return
        self.broker.set_tool_policy(name, enabled=not policy.enabled, approval_mode=policy.approval_mode)
        self.refresh_all()

    def _selected_approval(self) -> str | None:
        selection = self.approval_tree.selection()
        return selection[0] if selection else None

    def _approve(self) -> None:
        approval_id = self._selected_approval()
        if not approval_id:
            messagebox.showinfo("Approval", "Select a pending dangerous request first.")
            return
        if self.approval_tree.set(approval_id, "status") != "pending":
            messagebox.showinfo("Approval", "This request is already approved or no longer pending. Use Apply approved when it is approved.")
            return
        result = self.broker.approve(approval_id)
        if result.get("status") != "ok":
            messagebox.showerror("Approval", result.get("message", result.get("error_code", "Approval failed")))
        self.refresh_all()

    def _deny(self) -> None:
        approval_id = self._selected_approval()
        if not approval_id:
            messagebox.showinfo("Approval", "Select a pending dangerous request first.")
            return
        if self.approval_tree.set(approval_id, "status") != "pending":
            messagebox.showinfo("Approval", "Only pending requests can be denied.")
            return
        result = self.broker.deny(approval_id)
        if result.get("status") != "ok":
            messagebox.showerror("Approval", result.get("message", result.get("error_code", "Deny failed")))
        self.refresh_all()

    def _apply(self) -> None:
        approval_id = self._selected_approval()
        if not approval_id:
            messagebox.showinfo("Apply approved", "Select an approved dangerous request first.")
            return
        if self.approval_tree.set(approval_id, "status") != "approved":
            messagebox.showinfo("Apply approved", "Click Approve once first, then select the approved row and apply it.")
            return
        result = self.broker.invoke("apply_approved_action", {"approval_id": approval_id}, actor="user")
        if result.get("status") != "ok":
            messagebox.showerror("Apply failed", result.get("message", result.get("error_code")))
        self.refresh_all()

    def _open_approvals(self) -> None:
        """Give users a visible shortcut to the approval tab from Overview."""
        self.notebook.select(self.approvals_frame)

    def _verify_audit(self) -> None:
        result = self.broker.verify_audit()
        messagebox.showinfo("Audit chain", "Valid" if result["valid"] else result["message"])

    def _start_mcp(self) -> None:
        result = self.supervisor.start_mcp()
        if result.get("status") != "ok":
            messagebox.showerror("MCP bridge", result.get("message", result.get("error_code")))
        self.refresh_all()

    def _restart_bridge(self) -> None:
        result = self.supervisor.restart_bridge()
        if result.get("status") != "ok":
            messagebox.showerror("MCP bridge", result.get("message", result.get("error_code")))
        else:
            messagebox.showinfo("MCP bridge", "Bridge restarted. The running tool list is now refreshed.")
        self.refresh_all()

    def _stop_mcp(self) -> None:
        result = self.supervisor.stop("mcp_bridge")
        if result.get("status") != "ok":
            messagebox.showerror("MCP bridge", result.get("message", result.get("error_code")))
        self.refresh_all()

    def _start_tunnel(self) -> None:
        result = self.supervisor.start_tunnel()
        if result.get("status") != "ok":
            messagebox.showerror("Tunnel", result.get("message", result.get("error_code")))
        else:
            health = result.get("health", {})
            messagebox.showinfo(
                "Tunnel",
                f"tunnel-client started. State: {result.get('state')}\n"
                f"Health: {health.get('state', 'starting')}\n"
                f"Log: {result.get('log_path')}",
            )
        self.refresh_all()

    def _stop_tunnel(self) -> None:
        result = self.supervisor.stop("tunnel")
        if result.get("status") != "ok":
            messagebox.showerror("Tunnel", result.get("message", result.get("error_code")))
        self.refresh_all()

    def _clear_tunnel_key(self) -> None:
        confirmed = messagebox.askyesno(
            "Clear saved key",
            "Remove the saved runtime API key from this Mac's Keychain? OpenAI keys are not affected.",
        )
        if not confirmed:
            return
        result = self.supervisor.clear_tunnel_key()
        if result.get("status") != "ok":
            messagebox.showerror("Clear saved key", result.get("message", result.get("error_code")))
        else:
            messagebox.showinfo("Clear saved key", result["message"])
        self.refresh_all()

    def _doctor_tunnel(self) -> None:
        result = self.supervisor.doctor_tunnel()
        if result.get("status") != "ok":
            self._show_text_output(
                "Tunnel doctor",
                result.get("message", result.get("error_code", "Tunnel doctor failed")),
            )
        else:
            output = result.get("output") or "No diagnostic output."
            self._show_text_output("Tunnel doctor", f"Ready\n\n{output}")
        self.refresh_all()

    def _show_text_output(self, title: str, output: str) -> None:
        """Show bounded diagnostic text in a resizable, dismissible window."""
        dialog = tk.Toplevel(self.root)
        dialog.title(title)
        dialog.transient(self.root)
        dialog.geometry("900x600")
        dialog.minsize(640, 360)
        dialog.resizable(True, True)
        dialog.columnconfigure(0, weight=1)
        dialog.rowconfigure(0, weight=1)

        frame = ttk.Frame(dialog, padding=14)
        frame.grid(row=0, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        text = scrolledtext.ScrolledText(frame, wrap="word", width=100, height=30)
        text.grid(row=0, column=0, sticky="nsew")
        text.insert("1.0", output)
        text.configure(state="disabled")

        buttons = ttk.Frame(frame)
        buttons.grid(row=1, column=0, sticky="e", pady=(12, 0))

        def close() -> None:
            if dialog.winfo_exists():
                dialog.destroy()

        close_button = ttk.Button(buttons, text="Close", command=close)
        close_button.pack(side="right")
        dialog.protocol("WM_DELETE_WINDOW", close)
        dialog.bind("<Escape>", lambda _event: close())
        close_button.focus_set()

    def _open_chatgpt_settings(self) -> None:
        webbrowser.open("https://chatgpt.com/#settings/Connectors")

    def _configure_tunnel(self) -> None:
        current = self.supervisor.tunnel_client.get_config()
        current_status = self.supervisor.status().get("tunnel", {})
        current_suffix = current_status.get("api_key_suffix")
        current_control_plane = current_status.get("control_plane", {}).get("state")
        dialog = tk.Toplevel(self.root)
        dialog.title("Configure Secure MCP Tunnel")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        client_default = current.client_path if current else shutil.which("tunnel-client") or "tunnel-client"
        client_var = tk.StringVar(value=client_default)
        profile_var = tk.StringVar(value=current.profile if current else "local-mcp-control-center")
        tunnel_id_var = tk.StringVar(value=current.tunnel_id if current else "")
        api_key_var = tk.StringVar()
        saved_key_text = f"Current saved key: {current_suffix}." if current_suffix else "No API key is currently saved."
        if current_control_plane == "unauthorized":
            saved_key_text += " OpenAI rejected it with 401; paste the current Active key instead of leaving this blank."
        status_var = tk.StringVar(value=saved_key_text)

        form = ttk.Frame(dialog, padding=18)
        form.grid(row=0, column=0, sticky="nsew")
        ttk.Label(form, text="tunnel-client executable").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=client_var, width=62).grid(row=0, column=1, sticky="w", pady=4)

        def browse_client() -> None:
            selected = filedialog.askopenfilename(
                parent=dialog,
                title="Choose tunnel-client executable",
                filetypes=[("Executable", "*"), ("All files", "*")],
            )
            if selected:
                client_var.set(selected)

        ttk.Button(form, text="Browse", command=browse_client).grid(row=0, column=2, padx=(8, 0), pady=4)
        ttk.Label(form, text="Tunnel ID").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=tunnel_id_var, width=62).grid(row=1, column=1, columnspan=2, sticky="w", pady=4)
        ttk.Label(form, text="Profile name").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=profile_var, width=62).grid(row=2, column=1, columnspan=2, sticky="w", pady=4)
        ttk.Label(form, text="Runtime API key").grid(row=3, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=api_key_var, show="*", width=62).grid(row=3, column=1, columnspan=2, sticky="w", pady=4)
        ttk.Label(
            form,
            text="เว้นว่างได้เฉพาะเมื่อต้องการใช้ key เดิม • ต้องเป็น Runtime API key ที่มี Tunnels Read + Use",
            foreground="#555555",
        ).grid(row=4, column=1, columnspan=2, sticky="w", pady=(0, 10))
        ttk.Label(
            form,
            text="MCP command จะถูกสร้างโดยโปรแกรมเองและชี้ไปยัง broker นี้เท่านั้น ไม่รับ shell command จากช่องกรอก",
            wraplength=620,
            foreground="#555555",
        ).grid(row=5, column=0, columnspan=3, sticky="w", pady=(0, 10))
        ttk.Label(form, textvariable=status_var, wraplength=620).grid(row=6, column=0, columnspan=3, sticky="w", pady=(0, 12))

        def open_platform_keys() -> None:
            webbrowser.open("https://platform.openai.com/settings/organization/api-keys")

        ttk.Button(form, text="Open Platform API keys", command=open_platform_keys).grid(row=7, column=0, sticky="w")

        buttons = ttk.Frame(form)
        buttons.grid(row=8, column=0, columnspan=3, sticky="e")

        def save() -> None:
            entered_key = api_key_var.get().strip()
            if not entered_key and current_control_plane == "unauthorized":
                message = (
                    f"The saved key {current_suffix or '(unknown)'} was rejected with 401. "
                    "Paste the current Active runtime key from Platform before saving."
                )
                status_var.set(message)
                messagebox.showerror("New runtime key required", message, parent=dialog)
                return
            status_var.set("กำลังตรวจสอบ client และสร้าง profile...")
            dialog.update_idletasks()
            result = self.supervisor.configure_tunnel(
                client_path=client_var.get().strip(),
                profile=profile_var.get().strip(),
                tunnel_id=tunnel_id_var.get().strip(),
                api_key=entered_key or None,
            )
            if result.get("status") != "ok":
                status_var.set(result.get("message", result.get("error_code", "configuration failed")))
                messagebox.showerror("Configure tunnel", status_var.get(), parent=dialog)
                self.refresh_all()
                return
            dialog.grab_release()
            dialog.destroy()
            suffix = result.get("api_key_suffix")
            next_step = "Next: click Start tunnel, wait for the status to update, then create/test the ChatGPT app."
            message = result.get("message", "Tunnel configured.")
            if suffix:
                message = f"{message}\nSaved key suffix: {suffix}\n{next_step}"
            messagebox.showinfo("Configure tunnel", message, parent=self.root)
            self.refresh_all()

        ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side="right", padx=(8, 0))
        ttk.Button(buttons, text="Save & initialize profile", command=save).pack(side="right")
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)

    def _close(self) -> None:
        if self._bridge_poll_job is not None:
            try:
                self.root.after_cancel(self._bridge_poll_job)
            except tk.TclError:
                pass
            self._bridge_poll_job = None
        self.supervisor.stop("tunnel")
        self.supervisor.stop("mcp_bridge")
        self.broker.close()
        self.root.destroy()


def launch_gui(broker: Broker, supervisor: RuntimeSupervisor) -> None:
    ControlCenterApp(broker, supervisor).run()
