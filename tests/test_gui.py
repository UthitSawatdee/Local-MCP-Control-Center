from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import local_mcp_control_center.gui as gui


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
