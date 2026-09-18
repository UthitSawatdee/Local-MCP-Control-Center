from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import local_mcp_control_center.gui as gui


def test_scope_id_for_label_is_valid_for_numeric_and_short_folder_names() -> None:
    assert gui.scope_id_for_label("123 Project") == "scope-123-project"
    assert gui.scope_id_for_label("a") == "scope-a"


def test_gui_selected_scope_is_mcp_visible_by_default(monkeypatch, tmp_path: Path) -> None:
    selected = tmp_path / "123 Project"
    selected.mkdir()
    add_scope = Mock(return_value={"status": "ok"})
    app = object.__new__(gui.ControlCenterApp)
    app.broker = SimpleNamespace(
        policy=SimpleNamespace(scope_summary=lambda **_kwargs: []),
        add_scope=add_scope,
    )
    app.refresh_all = Mock()
    monkeypatch.setattr(gui.filedialog, "askdirectory", lambda **_kwargs: str(selected))

    app._add_scope("folder")

    kwargs = add_scope.call_args.kwargs
    assert kwargs["scope_id"] == "scope-123-project"
    assert kwargs["expose_to_mcp"] is True
    assert kwargs["permissions"]["read"]["allowed"] is True
    app.refresh_all.assert_called_once_with()


def test_runtime_summary_shows_only_key_suffix_and_connection_state() -> None:
    summary = gui.format_runtime_status(
        {
            "processes": [],
            "persisted": [],
            "tunnel": {
                "state": "ready",
                "client_path": "tunnel-client",
                "client_available": True,
                "profile": "local-test",
                "tunnel_id": "tunnel_" + "1" * 32,
                "api_key": "keychain",
                "api_key_suffix": "…8WgA",
                "profile_dir": "/tmp/profiles",
                "health": {"state": "ready"},
                "control_plane": {"state": "unauthorized", "message": "OpenAI rejected the runtime API key (401 Unauthorized)."},
            },
        }
    )

    assert "Saved API key: keychain (…8WgA)" in summary
    assert "OpenAI connection: unauthorized" in summary
    assert "401 Unauthorized" in summary
    assert "sk-" not in summary


def test_bridge_metrics_separate_registry_policy_and_live_counts() -> None:
    summary = gui.format_bridge_metrics(
        {
            "registry_total": 61,
            "enabled_count": 35,
            "running_tool_count": 34,
            "state": "stale",
            "stale": True,
        }
    )

    assert "Registry total: 61" in summary
    assert "Enabled: 35" in summary
    assert "Running bridge tools: 34" in summary
    assert "Bridge stale" in summary
    assert "Restart bridge" in summary


def test_missing_bridge_state_is_explicitly_unavailable() -> None:
    assert gui.format_bridge_state({}) == "Bridge unavailable"
    assert "Registry total: Unknown" in gui.format_bridge_metrics({})


def test_overview_status_keeps_connection_observability_and_stale_action() -> None:
    summary = gui.format_overview_status(
        {
            "control_center": "ready",
            "policy_version": 4,
            "mcp_bridge": "stopped",
            "tunnel": "not_configured",
            "chatgpt_path": "not_ready",
            "chatgpt_connection": "not_directly_observable",
            "bridge": {"state": "stale", "stale": True},
        },
        pending_count=2,
        approved_count=1,
    )

    assert "Connection: Not directly observable" in summary
    assert "Approvals: 2 pending / 1 ready" in summary
    assert "Tunnel: Not configured" in summary
    assert "ChatGPT path: Not ready" in summary
    assert "Action required: restart the bridge" in summary


def test_tool_and_audit_filters_search_visible_fields() -> None:
    tools = [
        {"name": "read_file", "group": "filesystem", "description": "Read an approved file"},
        {"name": "git_push", "group": "git", "description": "Push a branch", "risk": "critical"},
    ]
    audit = [
        {"seq": 1, "occurred_at": "2026-09-09T00:00:00Z", "actor": "user", "tool": "read_file", "decision": "executed", "target_display": "scope:file", "error_code": ""},
        {"seq": 2, "occurred_at": "2026-09-09T00:01:00Z", "actor": "user", "tool": "git_push", "decision": "denied", "target_display": "main", "error_code": "APPROVAL_REQUIRED"},
    ]

    assert [row["name"] for row in gui.filter_tool_rows(tools, "CRITICAL")] == ["git_push"]
    assert [row["seq"] for row in gui.filter_audit_rows(audit, "approval_required")] == [2]


def test_fail_closed_live_tool_shows_preview_only_and_is_searchable() -> None:
    row = {
        "name": "motion_timesheet_create_missing",
        "group": "erp",
        "risk": "high",
        "approval_mode": "never",
        "description": "Create missing Motion ERP rows",
        "live_execution_supported": False,
        "live_approval_required": True,
        "live_approval_available": False,
    }

    assert gui.tool_approval_label(row) == "Preview only"
    assert gui.filter_tool_rows([row], "preview") == [row]


def test_refresh_tools_filters_and_preserves_selected_row_identity() -> None:
    class FakeTree:
        def __init__(self) -> None:
            self.items = {"git_push": (), "read_file": ()}
            self.selected = ("git_push",)

        def get_children(self):
            return tuple(self.items)

        def selection(self):
            return self.selected

        def delete(self, item):
            self.items.pop(item, None)
            if item in self.selected:
                self.selected = ()

        def insert(self, _parent, _index, *, iid, tags=(), values=()):
            self.items[iid] = (tags, values)

        def selection_set(self, *items):
            self.selected = tuple(items)

    rows = [
        {"name": "git_push", "group": "git", "risk": "critical", "enabled": True, "approval_mode": "always", "description": "Push a branch"},
        {"name": "read_file", "group": "filesystem", "risk": "low", "enabled": True, "approval_mode": "never", "description": "Read an approved file"},
    ]
    tree = FakeTree()
    state = SimpleNamespace(set=Mock())
    button = SimpleNamespace(configure=Mock())
    app = object.__new__(gui.ControlCenterApp)
    app.tool_tree = tree
    app.tool_search_var = SimpleNamespace(get=lambda: "push")
    app.tool_summary = SimpleNamespace(set=Mock())
    app.tool_filter_state = state
    app.tool_toggle_button = button
    app._bridge_status_cache = {"registry_total": 2, "enabled_count": 2, "running_tool_count": 1, "state": "ready"}
    app.broker = SimpleNamespace(tool_rows=lambda: rows)

    app._refresh_tools()

    assert tuple(tree.items) == ("git_push",)
    assert tree.selected == ("git_push",)
    button.configure.assert_called_with(state="normal")
    state.set.assert_called_with("Showing 1 of 2 tools")


def test_scope_refresh_fetches_before_replacing_existing_rows() -> None:
    class FakeTree:
        def __init__(self) -> None:
            self.items = ["existing-scope"]

        def selection(self):
            return ("existing-scope",)

        def get_children(self):
            return tuple(self.items)

        def delete(self, item):
            self.items.remove(item)

    tree = FakeTree()
    app = object.__new__(gui.ControlCenterApp)
    app.scope_tree = tree
    app.broker = SimpleNamespace(
        policy=SimpleNamespace(scope_summary=Mock(side_effect=RuntimeError("store unavailable")))
    )

    try:
        app._refresh_scopes()
    except RuntimeError:
        pass

    assert tree.items == ["existing-scope"]


def test_approval_refresh_fetches_before_replacing_existing_rows() -> None:
    class FakeTree:
        def __init__(self) -> None:
            self.items = ["existing-approval"]

        def selection(self):
            return ("existing-approval",)

        def get_children(self):
            return tuple(self.items)

        def delete(self, item):
            self.items.remove(item)

    tree = FakeTree()
    app = object.__new__(gui.ControlCenterApp)
    app.approval_tree = tree
    app.broker = SimpleNamespace(actionable_approvals=Mock(side_effect=RuntimeError("store unavailable")))

    try:
        app._refresh_approvals()
    except RuntimeError:
        pass

    assert tree.items == ["existing-approval"]


def test_bridge_poll_marks_status_unavailable_when_live_read_fails() -> None:
    class FakeRoot:
        def after(self, _delay, _callback):
            return "next-poll"

    overview_state = SimpleNamespace(set=Mock())
    runtime_metrics = SimpleNamespace(set=Mock())
    app = object.__new__(gui.ControlCenterApp)
    app.root = FakeRoot()
    app._refresh_errors = {}
    app.overview_state = overview_state
    app.runtime_bridge_metrics = runtime_metrics
    app._bridge_status_cache = {}
    app._last_runtime_status = {"tunnel": "not_configured", "chatgpt_path": "not_ready"}
    app._refresh_bridge_metrics = Mock(side_effect=[RuntimeError("bridge read failed"), {"state": "stopped"}])
    app._poll_bridge_status()

    assert app._bridge_poll_job == "next-poll"
    overview_state.set.assert_called_with("Refresh incomplete — bridge status unavailable")
    runtime_metrics.set.assert_called_once()

    app._poll_bridge_status()

    overview_state.set.assert_called_with("Setup required — secure tunnel is not configured")
    assert app._refresh_errors == {}


def test_runtime_summary_does_not_claim_health_when_tunnel_is_missing() -> None:
    summary = gui.format_runtime_status({"processes": [], "persisted": [], "tunnel": {}})

    assert "Tunnel: Unknown" in summary
    assert "Health: Not running" in summary
    assert "OpenAI connection: Not running" in summary


def test_doctor_uses_a_dismissible_output_dialog(monkeypatch) -> None:
    app = object.__new__(gui.ControlCenterApp)
    app.supervisor = SimpleNamespace(
        doctor_tunnel=lambda: {"status": "ok", "output": "diagnostic output"}
    )
    app.refresh_all = Mock()
    show_info = Mock()
    show_output = Mock()
    monkeypatch.setattr(gui.messagebox, "showinfo", show_info)
    monkeypatch.setattr(app, "_show_text_output", show_output, raising=False)

    app._doctor_tunnel()

    show_info.assert_not_called()
    show_output.assert_called_once_with(
        "Tunnel doctor",
        "Ready\n\ndiagnostic output",
    )
    app.refresh_all.assert_called_once_with()


def test_text_output_dialog_has_close_button_and_escape_binding(monkeypatch) -> None:
    class FakeDialog:
        def __init__(self) -> None:
            self.destroyed = False
            self.protocols = {}
            self.bindings = {}

        def title(self, _value: str) -> None:
            pass

        def transient(self, _parent) -> None:
            pass

        def geometry(self, _value: str) -> None:
            pass

        def minsize(self, _width: int, _height: int) -> None:
            pass

        def resizable(self, _width: bool, _height: bool) -> None:
            pass

        def columnconfigure(self, _column: int, **_kwargs) -> None:
            pass

        def rowconfigure(self, _row: int, **_kwargs) -> None:
            pass

        def protocol(self, name: str, callback) -> None:
            self.protocols[name] = callback

        def bind(self, event: str, callback) -> None:
            self.bindings[event] = callback

        def grab_set(self) -> None:
            pass

        def grab_release(self) -> None:
            pass

        def winfo_exists(self) -> bool:
            return not self.destroyed

        def destroy(self) -> None:
            self.destroyed = True

    class FakeWidget:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def grid(self, **_kwargs) -> None:
            pass

        def pack(self, **_kwargs) -> None:
            pass

        def columnconfigure(self, _column: int, **_kwargs) -> None:
            pass

        def rowconfigure(self, _row: int, **_kwargs) -> None:
            pass

    class FakeText(FakeWidget):
        def __init__(self, *_args, **_kwargs) -> None:
            super().__init__(*_args, **_kwargs)
            self.value = ""

        def insert(self, _position: str, value: str) -> None:
            self.value = value

        def configure(self, **_kwargs) -> None:
            pass

    class FakeButton(FakeWidget):
        instances = []

        def __init__(self, *_args, **kwargs) -> None:
            super().__init__(*_args, **kwargs)
            self.text = kwargs["text"]
            self.command = kwargs["command"]
            self.__class__.instances.append(self)

        def focus_set(self) -> None:
            pass

    dialog = FakeDialog()
    monkeypatch.setattr(gui.tk, "Toplevel", lambda _parent: dialog)
    monkeypatch.setattr(gui.ttk, "Frame", FakeWidget)
    monkeypatch.setattr(gui.ttk, "Button", FakeButton)
    monkeypatch.setattr(gui.scrolledtext, "ScrolledText", FakeText)

    app = object.__new__(gui.ControlCenterApp)
    app.root = object()
    app._show_text_output("Tunnel doctor", "long diagnostic output")

    assert FakeButton.instances[-1].text == "Close"
    assert "WM_DELETE_WINDOW" in dialog.protocols
    assert "<Escape>" in dialog.bindings

    FakeButton.instances[-1].command()
    assert dialog.destroyed is True
