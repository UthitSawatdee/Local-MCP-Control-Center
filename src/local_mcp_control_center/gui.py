from __future__ import annotations

import re
import shutil
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any

from .broker import Broker
from .models import ApprovalMode, Capability, ScopeKind
from .supervisor import RuntimeSupervisor


def format_runtime_status(data: dict[str, Any]) -> str:
    """Build a secret-free runtime summary for the GUI."""
    tunnel = data["tunnel"]
    tunnel_live = tunnel.get("state") in {"starting", "running", "healthy", "ready", "unhealthy"}
    health = tunnel.get("health", {})
    health_state = health.get("state", "-") if tunnel_live else "-"
    control_plane = tunnel.get("control_plane", {})
    control_plane_state = control_plane.get("state", "-") if tunnel_live else "-"
    key_suffix = tunnel.get("api_key_suffix")
    stored_key = f"{tunnel.get('api_key', 'missing')} ({key_suffix})" if key_suffix else tunnel.get("api_key", "missing")
    lines = [
        f"MCP bridge process: {data['processes']}",
        f"Persisted runtime records: {data['persisted']}",
        f"Tunnel: {tunnel.get('state')}",
        f"Tunnel client: {tunnel.get('client_path') or '-'} ({'available' if tunnel.get('client_available') else 'not found'})",
        f"Profile: {tunnel.get('profile') or '-'}",
        f"Tunnel ID: {tunnel.get('tunnel_id') or '-'}",
        f"Saved API key: {stored_key}",
        f"Health: {health_state}",
        f"OpenAI connection: {control_plane_state}",
    ]
    if control_plane.get("message"):
        lines.append(control_plane["message"])
    lines.extend([
        f"Profile directory: {tunnel.get('profile_dir')}",
        "Key Active/Inactive is managed on OpenAI Platform. This screen proves the saved key is accepted only when OpenAI connection has no authorization error.",
    ])
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
        self._build()
        self.refresh_all()

    def run(self) -> None:
        self.root.mainloop()

    def _build(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("aqua")
        except tk.TclError:
            pass
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=12, pady=12)
        notebook.enable_traversal()
        self.notebook = notebook
        self._build_overview(notebook)
        self._build_paths(notebook)
        self._build_tools(notebook)
        self._build_approvals(notebook)
        self._build_audit(notebook)
        self._build_runtime(notebook)

    def _build_overview(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=18)
        notebook.add(frame, text="Overview")
        ttk.Label(frame, text="Local MCP Control Center", font=("Helvetica", 22, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Least privilege, dangerous-action approvals, and append-only audit metadata.").pack(anchor="w", pady=(4, 18))
        self.overview_text = tk.StringVar()
        ttk.Label(frame, textvariable=self.overview_text, justify="left", font=("Menlo", 12)).pack(anchor="w", pady=8)
        actions = ttk.Frame(frame)
        actions.pack(anchor="w", pady=18)
        ttk.Button(actions, text="Start MCP bridge", command=self._start_mcp).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Stop MCP bridge", command=self._stop_mcp).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Configure tunnel", command=self._configure_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Start tunnel", command=self._start_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Stop tunnel", command=self._stop_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Clear saved key", command=self._clear_tunnel_key).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Open ChatGPT settings", command=self._open_chatgpt_settings).pack(side="left", padx=(0, 8))
        secondary_actions = ttk.Frame(frame)
        secondary_actions.pack(anchor="w", pady=(8, 0))
        ttk.Button(secondary_actions, text="Open Approvals", command=self._open_approvals).pack(side="left", padx=(0, 8))
        ttk.Button(secondary_actions, text="Refresh", command=self.refresh_all).pack(side="left")
        ttk.Label(
            frame,
            text=(
                "วิธีใช้งาน: 1) เพิ่มโฟลเดอร์ใน Allowed Paths  2) เปิด tools/permissions ที่ต้องการ  "
                "3) Configure tunnel แล้ว Start tunnel  4) ไปที่ ChatGPT สร้าง developer-mode app และเลือก Tunnel  "
                "5) พิมพ์คำสั่งธรรมชาติในบทสนทนา ChatGPT นั้น — หน้านี้เป็นศูนย์ควบคุม ไม่ใช่ช่องแชต  "
                "การแก้ไข/สร้าง/ย้าย/ทดสอบทำทันทีเมื่อเปิดสิทธิ์; การลบไฟล์, Git restore และ Git push ต้องอนุมัติ",
            ),
            wraplength=900,
        ).pack(anchor="w", pady=(20, 0))

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
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Tools")
        ttk.Label(frame, text="Disabled tools are not registered in the MCP bridge until it is restarted.").pack(anchor="w", pady=(0, 8))
        columns = ("name", "group", "risk", "enabled", "approval", "description")
        self.tool_tree = ttk.Treeview(frame, columns=columns, show="headings", height=20)
        headings = {"name": "Tool", "group": "Group", "risk": "Risk", "enabled": "Enabled", "approval": "Approval", "description": "Description"}
        widths = {"name": 190, "group": 100, "risk": 90, "enabled": 80, "approval": 120, "description": 540}
        for column in columns:
            self.tool_tree.heading(column, text=headings[column])
            self.tool_tree.column(column, width=widths[column], anchor="w")
        self.tool_tree.pack(fill="both", expand=True)
        ttk.Button(frame, text="Toggle selected tool", command=self._toggle_tool).pack(anchor="w", pady=(8, 0))

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
        frame = ttk.Frame(notebook, padding=12)
        notebook.add(frame, text="Audit log")
        self.audit_state = tk.StringVar()
        ttk.Label(frame, textvariable=self.audit_state).pack(anchor="w", pady=(0, 8))
        columns = ("seq", "time", "actor", "tool", "decision", "target", "error")
        self.audit_tree = ttk.Treeview(frame, columns=columns, show="headings", height=20)
        headings = {"seq": "#", "time": "Time", "actor": "Actor", "tool": "Tool", "decision": "Decision", "target": "Target", "error": "Error"}
        widths = {"seq": 55, "time": 190, "actor": 100, "tool": 190, "decision": 130, "target": 380, "error": 180}
        for column in columns:
            self.audit_tree.heading(column, text=headings[column])
            self.audit_tree.column(column, width=widths[column], anchor="w")
        self.audit_tree.pack(fill="both", expand=True)
        ttk.Button(frame, text="Verify audit chain", command=self._verify_audit).pack(anchor="w", pady=(8, 0))

    def _build_runtime(self, notebook: ttk.Notebook) -> None:
        frame = ttk.Frame(notebook, padding=18)
        notebook.add(frame, text="Runtime")
        self.runtime_text = tk.StringVar()
        ttk.Label(frame, textvariable=self.runtime_text, justify="left", font=("Menlo", 12)).pack(anchor="w")
        actions = ttk.Frame(frame)
        actions.pack(anchor="w", pady=18)
        ttk.Button(actions, text="Configure tunnel", command=self._configure_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Start MCP", command=self._start_mcp).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Stop MCP", command=self._stop_mcp).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Start tunnel", command=self._start_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Stop tunnel", command=self._stop_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Clear saved key", command=self._clear_tunnel_key).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Run tunnel doctor", command=self._doctor_tunnel).pack(side="left", padx=(0, 8))
        ttk.Button(actions, text="Refresh", command=self.refresh_all).pack(side="left")

    def refresh_all(self) -> None:
        self._refresh_overview()
        self._refresh_scopes()
        self._refresh_tools()
        self._refresh_approvals()
        self._refresh_audit()
        self._refresh_runtime()

    def _refresh_overview(self) -> None:
        runtime = self.broker.invoke("runtime_status", actor="user")
        approvals = self.broker.actionable_approvals()
        pending_count = sum(approval["status"] == "pending" for approval in approvals)
        approved_count = sum(approval["status"] == "approved" for approval in approvals)
        self.overview_text.set(
            f"Control Center: ready\nPolicy version: {runtime.get('policy_version')}\n"
            f"MCP bridge: {runtime.get('mcp_bridge')}\nTunnel: {runtime.get('tunnel')}\n"
            f"ChatGPT path: {runtime.get('chatgpt_path')}\n"
            f"Approvals: {pending_count} pending, {approved_count} ready to apply"
        )

    def _refresh_scopes(self) -> None:
        if not hasattr(self, "scope_tree"):
            return
        for item in self.scope_tree.get_children():
            self.scope_tree.delete(item)
        for scope in self.broker.policy.scope_summary(actor="user"):
            permissions = ", ".join(key for key, value in scope["permissions"].items() if value["allowed"]) or "none"
            self.scope_tree.insert("", "end", iid=scope["id"], values=(scope["id"], scope["label"], scope["kind"], "yes" if scope["enabled"] else "no", "yes" if scope["expose_to_mcp"] else "no", permissions, scope.get("root", "")))

    def _refresh_tools(self) -> None:
        for item in self.tool_tree.get_children():
            self.tool_tree.delete(item)
        for row in self.broker.tool_rows():
            self.tool_tree.insert("", "end", iid=row["name"], values=(row["name"], row["group"], row["risk"], "yes" if row["enabled"] else "no", row["approval_mode"], row["description"]))

    def _refresh_approvals(self) -> None:
        for item in self.approval_tree.get_children():
            self.approval_tree.delete(item)
        requests = self.broker.actionable_approvals()
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

    def _refresh_audit(self) -> None:
        for item in self.audit_tree.get_children():
            self.audit_tree.delete(item)
        rows = self.broker.audit_page(200)
        for row in rows:
            self.audit_tree.insert("", "end", values=(row["seq"], row["occurred_at"], row["actor"], row["tool"], row["decision"], row["target_display"], row["error_code"] or ""))
        verification = self.broker.verify_audit()
        self.audit_state.set("Audit chain: valid" if verification["valid"] else f"Audit chain: INVALID — {verification['message']}")

    def _refresh_runtime(self) -> None:
        data = self.supervisor.status()
        self.runtime_text.set(format_runtime_status(data))

    def _add_scope(self, selection_kind: str) -> None:
        selected = (
            filedialog.askdirectory(title="Choose an allowed folder")
            if selection_kind == "folder"
            else filedialog.askopenfilename(title="Choose an allowed file")
        )
        if not selected:
            return
        label = Path(selected).name or "Allowed folder"
        scope_id = re.sub(r"[^a-zA-Z0-9_-]+", "-", label.lower()).strip("-") or "scope"
        scope_id = scope_id[:54]
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
            expose_to_mcp=False,
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
        self.supervisor.stop("tunnel")
        self.supervisor.stop("mcp_bridge")
        self.broker.close()
        self.root.destroy()


def launch_gui(broker: Broker, supervisor: RuntimeSupervisor) -> None:
    ControlCenterApp(broker, supervisor).run()
