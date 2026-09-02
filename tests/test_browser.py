from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
from threading import Thread
from typing import Any

import pytest

from local_mcp_control_center.browser import (
    BROWSER_PROFILES,
    LEGACY_BROWSER_PROFILE_NAME,
    LOCAL_BROWSER_PROFILE_NAME,
    BrowserManager,
    BrowserProfilePolicy,
)
from local_mcp_control_center.errors import PolicyError
from local_mcp_control_center.mcp_server import build_server

from .conftest import enable_tools


class _BrowserHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://evil.example.com/")
            self.end_headers()
            return
        body = b"""<!doctype html>
        <html><body>
        <h1>Local Browser Fixture</h1>
        <form id="entry-form" role="form">
          <label>Description <input id="description" name="description"></label>
          <label>Project <select id="project" name="project">
            <option value="atm">Project ATM</option><option value="other">Other</option>
          </select></label>
          <div id="cost-center" role="combobox" aria-label="Cost center" aria-expanded="false" tabindex="0">Choose cost center</div>
          <ul id="cost-center-options" hidden>
            <li role="option">Operations</li><li role="option">Project ATM</li>
          </ul>
          <label>Password <input id="password" type="password" value="fixture-secret"></label>
          <button id="toggle" type="button" onclick="document.getElementById('status').textContent='Clicked'">Click</button>
          <button id="popup" type="button" onclick="window.open('https://evil.example.com/', '_blank')">Open external</button>
          <button id="save" type="submit">Save</button>
        </form>
        <p id="status"></p>
        <table id="entries"><tr><th>Date</th><th>Hours</th></tr>
          <tr><td>2026-09-02</td><td>8</td></tr></table>
        <script>
        document.getElementById('cost-center').onclick = () => {
          document.getElementById('cost-center-options').hidden = false;
          document.getElementById('cost-center').setAttribute('aria-expanded', 'true');
        };
        for (const option of document.querySelectorAll('#cost-center-options [role="option"]')) {
          option.onclick = () => {
            document.getElementById('cost-center').textContent = option.textContent;
            document.getElementById('cost-center-options').hidden = true;
          };
        }
        document.getElementById('entry-form').onsubmit = (event) => {
            event.preventDefault();
            document.getElementById('status').textContent = 'Saved: ' + document.getElementById('description').value;
          };
        </script>
        </body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: Any) -> None:
        return


@pytest.fixture
def local_browser(tmp_path: Path):
    server = HTTPServer(("127.0.0.1", 0), _BrowserHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    manager = BrowserManager(
        tmp_path / "browser",
        profiles={"local-test": BrowserProfilePolicy("local-test", (origin,))},
        headless=True,
        idle_timeout_seconds=60,
    )
    try:
        yield manager, origin
    except PolicyError as exc:
        if exc.code in {"BROWSER_DEPENDENCY_MISSING", "BROWSER_LAUNCH_FAILED"}:
            pytest.skip(str(exc))
        raise
    finally:
        manager.close_all()
        server.shutdown()
        server.server_close()


def _snapshot_refs(snapshot: str) -> dict[str, str]:
    refs: dict[str, str] = {}
    for line in snapshot.splitlines():
        if line.startswith("[ref=") or line.startswith(" [ref="):
            ref = line.split("]", 1)[0].split("=", 1)[1]
            refs[ref] = line
    return refs


def _ref_containing(snapshot: str, text: str) -> str:
    return next(ref for ref, line in _snapshot_refs(snapshot).items() if text in line)


def test_browser_registry_and_mcp_registration(broker) -> None:
    names = {name for name in ("browser_open", "browser_snapshot", "browser_run_command", "browser_close")}
    server = build_server(broker)
    registered = {tool.name for tool in server._tool_manager.list_tools()}
    assert names <= registered
    browser_tool = next(tool for tool in server._tool_manager.list_tools() if tool.name == "browser_run_command")
    assert "command" not in browser_tool.fn_metadata.arg_model.model_fields


def test_browser_tools_are_enabled_by_default(broker) -> None:
    names = ("browser_open", "browser_snapshot", "browser_run_command", "browser_close")

    assert all(broker.store.get_tool_policy(name).enabled for name in names)


def test_motion_profile_allows_web_internet_and_reports_policy(tmp_path: Path) -> None:
    manager = BrowserManager(tmp_path / "browser", headless=True)
    profile = BROWSER_PROFILES[LOCAL_BROWSER_PROFILE_NAME]

    assert profile.allow_internet is True
    for url in (
        "https://example.com/",
        "https://fonts.googleapis.com/css2?family=Inter",
        "https://www.googletagmanager.com/gtm.js",
        "https://connect.facebook.net/en_US/fbevents.js",
    ):
        assert manager._url_allowed(profile, url)
    assert not manager._url_allowed(profile, "file:///tmp/private.txt")
    assert not manager._url_allowed(profile, "javascript:alert(1)")

    status = manager.status()
    motion_status = next(item for item in status["profiles"] if item["profile"] == LOCAL_BROWSER_PROFILE_NAME)
    assert motion_status["internet_access"] is True


def test_local_profile_renames_legacy_persistent_directory(tmp_path: Path) -> None:
    if LOCAL_BROWSER_PROFILE_NAME == LEGACY_BROWSER_PROFILE_NAME:
        pytest.skip("local hostname is the legacy profile name")
    legacy_dir = tmp_path / "browser" / LEGACY_BROWSER_PROFILE_NAME
    legacy_dir.mkdir(parents=True)
    (legacy_dir / "profile-marker").write_text("preserve", encoding="utf-8")

    manager = BrowserManager(tmp_path / "browser", headless=True)

    assert not legacy_dir.exists()
    assert (tmp_path / "browser" / LOCAL_BROWSER_PROFILE_NAME / "profile-marker").read_text(encoding="utf-8") == "preserve"
    manager.close_all()


def test_browser_schema_rejects_raw_code_and_invalid_action(broker) -> None:
    enable_tools(broker, "browser_run_command")
    raw_shell = broker.invoke(
        "browser_run_command",
        {"browser_session_id": "br_test", "action": "click", "command": "open https://evil.example.com"},
    )
    raw_js = broker.invoke(
        "browser_run_command",
        {"browser_session_id": "br_test", "action": "click", "javascript": "document.body"},
    )
    invalid_action = broker.invoke(
        "browser_run_command",
        {"browser_session_id": "br_test", "action": "evaluate", "code": "1+1"},
    )
    assert {raw_shell["error_code"], raw_js["error_code"], invalid_action["error_code"]} == {"INVALID_INPUT"}


def test_browser_broker_call_is_audited(broker, monkeypatch) -> None:
    enable_tools(broker, "browser_open")
    monkeypatch.setattr(
        broker.browser,
        "open",
        lambda profile: {
            "status": "ok",
            "browser_session_id": "br_test",
            "profile": profile,
            "current_url": "about:blank",
            "origin": None,
            "authenticated": None,
        },
    )
    result = broker.invoke("browser_open", {"profile": LOCAL_BROWSER_PROFILE_NAME})
    assert result["status"] == "ok"
    row = broker.store.audit_rows(1)[0]
    assert row["tool"] == "browser_open"
    assert "br_test" not in row["metadata_json"]


def test_browser_local_fixture_supports_bounded_interactions(local_browser) -> None:
    manager, origin = local_browser
    opened = manager.open("local-test")
    reused = manager.open("local-test")
    assert opened["browser_session_id"] == reused["browser_session_id"]
    session_id = opened["browser_session_id"]

    manager.execute(session_id, "navigate", url=origin + "/")
    snapshot = manager.snapshot(session_id)
    assert "password" not in snapshot["snapshot"].lower()
    description = _ref_containing(snapshot["snapshot"], "Description")
    toggle = _ref_containing(snapshot["snapshot"], 'button "Click"')
    manager.execute(session_id, "click", target={"ref": toggle})

    snapshot = manager.snapshot(session_id)
    status = _ref_containing(snapshot["snapshot"], "Clicked")
    assert manager.execute(session_id, "read_text", target={"ref": status})["text"] == "Clicked"
    description = _ref_containing(snapshot["snapshot"], "Description")
    manager.execute(session_id, "fill", target={"ref": description}, value="ATM Project Development")
    with pytest.raises(PolicyError, match="snapshot ref is stale"):
        manager.execute(session_id, "click", target={"ref": toggle})

    snapshot = manager.snapshot(session_id)
    project = _ref_containing(snapshot["snapshot"], "Project")
    manager.execute(session_id, "select", target={"ref": project}, value="atm")
    snapshot = manager.snapshot(session_id)
    cost_center = _ref_containing(snapshot["snapshot"], "Cost center")
    manager.execute(session_id, "select", target={"ref": cost_center}, value="Project ATM")
    assert "Project ATM" in manager.snapshot(session_id)["snapshot"]
    snapshot = manager.snapshot(session_id)
    description = _ref_containing(snapshot["snapshot"], "Description")
    manager.execute(session_id, "press", target={"ref": description}, key="End")
    snapshot = manager.snapshot(session_id)
    save = _ref_containing(snapshot["snapshot"], 'button "Save"')
    manager.execute(session_id, "submit", target={"ref": save})
    snapshot = manager.snapshot(session_id)
    status = _ref_containing(snapshot["snapshot"], "Saved:")
    assert manager.execute(session_id, "read_text", target={"ref": status})["text"] == "Saved: ATM Project Development"
    table = _ref_containing(snapshot["snapshot"], "] table")
    table_result = manager.execute(session_id, "read_table", target={"ref": table})
    assert table_result["rows"] == [["2026-09-02", "8"]]
    assert manager.close(session_id)["closed"] is True
    assert manager.status()["sessions"] == []


def test_browser_domain_allowlist_blocks_direct_redirect_and_popup(local_browser) -> None:
    manager, origin = local_browser
    session_id = manager.open("local-test")["browser_session_id"]
    manager.execute(session_id, "navigate", url=origin + "/")
    with pytest.raises(PolicyError) as direct:
        manager.execute(session_id, "navigate", url="https://evil.example.com/")
    assert direct.value.code == "DOMAIN_NOT_ALLOWED"
    with pytest.raises(PolicyError) as redirect:
        manager.execute(session_id, "navigate", url=origin + "/redirect")
    assert redirect.value.code == "DOMAIN_NOT_ALLOWED"
    session_id = manager.open("local-test")["browser_session_id"]
    manager.execute(session_id, "navigate", url=origin + "/")
    snapshot = manager.snapshot(session_id)
    popup = _ref_containing(snapshot["snapshot"], "Open external")
    with pytest.raises(PolicyError) as popup_error:
        manager.execute(session_id, "click", target={"ref": popup})
    assert popup_error.value.code == "DOMAIN_NOT_ALLOWED"


def test_browser_idle_cleanup_and_crash_handling(local_browser) -> None:
    manager, _origin = local_browser
    session_id = manager.open("local-test")["browser_session_id"]
    assert os.stat(manager.data_dir / "local-test").st_mode & 0o777 == 0o700
    session = manager._sessions[session_id]
    session.last_activity = 0
    manager._clock = lambda: 61
    assert manager.cleanup_idle() == 1
    assert manager.status()["sessions"] == []

    session_id = manager.open("local-test")["browser_session_id"]
    manager._sessions[session_id].context.close()
    with pytest.raises(PolicyError) as crashed:
        manager.snapshot(session_id)
    assert crashed.value.code == "BROWSER_CRASHED"
    assert manager.status()["sessions"] == []
