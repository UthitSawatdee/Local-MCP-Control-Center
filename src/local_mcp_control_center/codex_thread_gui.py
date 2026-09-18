"""Local-user consent dialog for Codex history access (never exposed over MCP)."""
from __future__ import annotations

import os
import shutil
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any


def show_codex_config(parent: Any, broker: Any) -> None:
    saved = broker.store.get_codex_thread_config() or {}
    dialog = tk.Toplevel(parent)
    dialog.title("Codex thread access")
    dialog.transient(parent)
    dialog.resizable(True, False)
    frame = ttk.Frame(dialog, padding=16)
    frame.pack(fill="both", expand=True)
    frame.columnconfigure(1, weight=1)
    executable = tk.StringVar(value=saved.get("executable") or shutil.which("codex") or "")
    home = tk.StringVar(value=saved.get("codex_home") or os.environ.get("CODEX_HOME") or str(Path.home() / ".codex"))
    enabled = tk.BooleanVar(value=saved.get("enabled") is True)
    ttk.Checkbutton(frame, text="Allow MCP to read my local Codex thread history", variable=enabled).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))
    ttk.Label(frame, text="Codex executable").grid(row=1, column=0, sticky="w", padx=(0, 8))
    ttk.Entry(frame, textvariable=executable, width=65).grid(row=1, column=1, sticky="ew")

    def choose_executable() -> None:
        selected = filedialog.askopenfilename(parent=dialog, title="Select the Codex executable")
        if selected:
            executable.set(selected)

    def choose_home() -> None:
        selected = filedialog.askdirectory(parent=dialog, title="Select CODEX_HOME", initialdir=home.get())
        if selected:
            home.set(selected)

    ttk.Button(frame, text="Browse", command=choose_executable).grid(row=1, column=2, padx=(8, 0))
    ttk.Label(frame, text="CODEX_HOME").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=8)
    ttk.Entry(frame, textvariable=home, width=65).grid(row=2, column=1, sticky="ew")
    ttk.Button(frame, text="Browse", command=choose_home).grid(row=2, column=2, padx=(8, 0))
    ttk.Label(frame, text="Reads stored conversations through Codex App Server. No resume, new turns, archive or delete.\nOnly this selected local history is available; remote/cloud-only threads are not fetched.\nNo generic access to CODEX_HOME or auth files is granted to MCP.", wraplength=660, justify="left").grid(row=3, column=0, columnspan=3, sticky="w", pady=(4, 12))
    actions = ttk.Frame(frame)
    actions.grid(row=4, column=0, columnspan=3, sticky="e")

    def save() -> None:
        result = broker.configure_codex_threads(executable=executable.get(), codex_home=home.get(), enabled=enabled.get())
        if result.get("status") != "ok":
            messagebox.showerror("Codex thread access", result.get("message", "Configuration failed"), parent=dialog)
            return
        messagebox.showinfo("Codex thread access", "Saved. Restart the MCP bridge, then refresh the connector tools.\nDisabling access takes effect for new reads immediately.", parent=dialog)
        dialog.destroy()

    ttk.Button(actions, text="Cancel", command=dialog.destroy).pack(side="left", padx=(0, 8))
    ttk.Button(actions, text="Save", command=save).pack(side="left")
    dialog.grab_set()
