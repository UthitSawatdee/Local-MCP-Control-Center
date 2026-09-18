from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

import local_mcp_control_center.codex_threads as codex_module
from local_mcp_control_center.cli import main
from local_mcp_control_center.codex_threads import CodexAppServerClient, CodexThreadService, normalize_thread_id, validate_local_config
from local_mcp_control_center.errors import PolicyError
from local_mcp_control_center.mcp_server import build_server
from local_mcp_control_center.registry import TOOL_BY_NAME

THREAD = "01a0a5ab-3817-7f92-9a01-a65bf69edecb"
LINK = "codex://threads/" + THREAD
SECRET = "sk-" + "a" * 40


class FakeClient:
    runtime = "fixture-codex/1"

    def __init__(self, config, *, timeout_seconds=20):
        self.calls = []
        self.page = {
            "data": [{"id": "turn-1", "status": "completed", "items": [
                {"type": "userMessage", "id": "u1", "content": [{"type": "text", "text": "Test planning in Thai ภาษาไทย"}]},
                {"type": "agentMessage", "id": "a1", "phase": "final_answer", "text": "Done password=hidden-value " + SECRET},
                {"type": "reasoning", "id": "r1", "text": "PRIVATE_REASONING"},
                {"type": "agentMessage", "phase": "analysis", "text": "PRIVATE_ANALYSIS"},
                {"type": "systemMessage", "text": "PRIVATE_SYSTEM"},
                {"type": "commandExecution", "id": "c1", "status": "completed", "command": "pytest tests", "exitCode": 0, "aggregatedOutput": "passed " + SECRET},
                {"type": "mcpToolCall", "tool": "read_file", "arguments": {"password": "PRIVATE_ARGS"}, "result": "PRIVATE_TOOL_RESULT"},
            ]}], "nextCursor": "older-cursor",
        }

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        pass

    def request(self, method, params):
        self.calls.append((method, params))
        if method == "thread/read":
            return {"thread": {"id": THREAD, "name": "Planning", "cwd": "/private/example", "auth": SECRET}}
        if method == "thread/list":
            return {"data": [{"id": THREAD, "name": "Planning", "auth": SECRET}], "nextCursor": None}
        return self.page


@pytest.fixture
def service_fixture():
    config = {"enabled": True, "executable": "/fixture/codex", "codex_home": "/fixture/home"}
    client = FakeClient(config)
    service = CodexThreadService(lambda: dict(config), client_factory=lambda *_args, **_kwargs: client)
    return service, client, config


@pytest.mark.parametrize("value", [THREAD, THREAD.upper(), LINK])
def test_thread_id_accepts_uuid_and_deep_link(value):
    assert normalize_thread_id(value) == THREAD


@pytest.mark.parametrize("value", ["../auth.json", "https://example.com", LINK + "?file=auth.json", LINK + "#fragment", LINK + "/", "codex://threads/../../auth.json", " " + LINK, "not-a-thread"])
def test_thread_id_rejects_paths_and_ambiguous_links(value):
    with pytest.raises(PolicyError) as error:
        normalize_thread_id(value)
    assert error.value.code == "INVALID_INPUT"


def test_default_configuration_does_not_connect():
    service = CodexThreadService(lambda: None, client_factory=lambda *_args, **_kwargs: pytest.fail("must not connect"))
    assert service.status()["connection_verified"] is False
    with pytest.raises(PolicyError) as error:
        service.read_thread(LINK)
    assert error.value.code == "CODEX_NOT_CONFIGURED"


def test_visible_history_is_redacted_and_read_only(service_fixture):
    service, client, _ = service_fixture
    result = service.read_thread(LINK)
    text = json.dumps(result)
    assert result["thread_id"] == THREAD
    assert result["has_more"] is True
    assert result["next_cursor"] == "older-cursor"
    assert result["omitted_internal_items"] == 3
    assert result["persisted_history_only"] is True
    assert all(word not in text for word in (SECRET, "hidden-value", "PRIVATE_REASONING", "PRIVATE_SYSTEM", "PRIVATE_ANALYSIS", "PRIVATE_ARGS", "PRIVATE_TOOL_RESULT", "/private/example"))
    assert "aggregatedOutput" not in text and "pytest tests" not in text
    assert client.calls == [
        ("thread/read", {"threadId": THREAD, "includeTurns": False}),
        ("thread/turns/list", {"threadId": THREAD, "limit": 3, "sortDirection": "asc", "itemsView": "full"}),
    ]


def test_cursor_and_direction_pass_through_and_command_results_are_optional(service_fixture):
    service, client, _ = service_fixture
    result = service.read_thread(THREAD, cursor="exact-cursor", sort_direction="desc", limit=1, include_tool_results=True)
    command = result["turns"][0]["items"][2]
    assert command["command"] == "pytest tests"
    assert command["exit_code"] == 0
    assert SECRET not in command["output"]
    assert client.calls[-1][1]["cursor"] == "exact-cursor"
    assert client.calls[-1][1]["sortDirection"] == "desc"


def test_command_output_marks_truncation(service_fixture):
    service, client, _ = service_fixture
    client.page["data"][0]["items"][-2]["aggregatedOutput"] = "x" * 9000
    result = service.read_thread(THREAD, include_tool_results=True)
    assert result["turns"][0]["items"][2]["output_truncated"] is True


def test_titles_only_listing_avoids_index_repair_and_secrets(service_fixture):
    service, client, _ = service_fixture
    result = service.list_threads(query="Planning", archived=True, cursor="page-2", limit=1)
    assert result["search_scope"] == "thread_titles_only"
    assert result["has_more"] is False
    assert SECRET not in json.dumps(result)
    assert client.calls[0][1] == {"limit": 1, "archived": True, "sortKey": "updated_at", "useStateDbOnly": True, "searchTerm": "Planning", "cursor": "page-2"}


def test_large_visible_page_fails_without_silently_skipping_messages(service_fixture):
    service, client, _ = service_fixture
    client.page["data"][0]["items"][0]["content"][0]["text"] = "ก" * 25000
    with pytest.raises(PolicyError) as error:
        service.read_thread(THREAD)
    assert error.value.code == "CODEX_OUTPUT_TOO_LARGE"


@pytest.mark.parametrize("page", [{"data": [{"id": "t"}], "nextCursor": None}, {"data": "bad"}, {"data": [], "nextCursor": 123}])
def test_incompatible_pages_fail_closed(service_fixture, page):
    service, client, _ = service_fixture
    client.page = page
    with pytest.raises(PolicyError) as error:
        service.read_thread(THREAD)
    assert error.value.code == "CODEX_PROTOCOL_ERROR"


def test_revoking_access_during_read_discards_response(service_fixture):
    service, client, config = service_fixture
    original = client.request

    def revoke(method, params):
        result = original(method, params)
        if method == "thread/turns/list":
            config["enabled"] = False
        return result

    client.request = revoke
    with pytest.raises(PolicyError) as error:
        service.read_thread(THREAD)
    assert error.value.code == "CODEX_ACCESS_CHANGED"


def test_parallel_requests_are_bounded(service_fixture):
    service, _, _ = service_fixture
    service._slots.acquire()
    service._slots.acquire()
    try:
        with pytest.raises(PolicyError) as error:
            service.status(probe=True)
        assert error.value.code == "CODEX_BUSY"
    finally:
        service._slots.release()
        service._slots.release()


@pytest.mark.parametrize("method", ["turn/start", "thread/resume", "thread/delete", "account/read", "config/read", "shell"])
def test_transport_rejects_non_read_methods_before_io(method):
    client = CodexAppServerClient({})
    with pytest.raises(PolicyError) as error:
        client.request(method, {})
    assert error.value.code == "CODEX_METHOD_DENIED"


def test_broker_opt_in_registration_policy_revocation_and_audit(broker, tmp_path):
    tools = {tool.name for tool in build_server(broker)._tool_manager.list_tools()}
    assert "codex_status" in tools
    assert "codex_read_thread" not in tools
    assert broker.invoke("codex_read_thread", {"thread_id": LINK})["error_code"] == "TOOL_DISABLED"
    home = tmp_path / "codex-home"
    home.mkdir()
    assert broker.configure_codex_threads(executable=sys.executable, codex_home=str(home))["status"] == "ok"
    client = FakeClient({})
    broker.codex_threads.client_factory = lambda *_args, **_kwargs: client
    tools = {tool.name for tool in build_server(broker)._tool_manager.list_tools()}
    assert {"codex_status", "codex_read_thread", "codex_list_threads"} <= tools
    result = broker.invoke("codex_read_thread", {"thread_id": LINK})
    assert result["status"] == "ok"
    audit = json.dumps([dict(row) for row in broker.store._fetchall("SELECT * FROM audit_events")])
    assert "Test planning in Thai" not in audit and "PRIVATE_REASONING" not in audit and SECRET not in audit
    assert "configure_codex_threads" not in TOOL_BY_NAME
    assert broker.configure_codex_threads(enabled=False)["status"] == "ok"
    assert broker.invoke("codex_read_thread", {"thread_id": LINK})["error_code"] == "TOOL_DISABLED"
    assert broker.invoke("codex_status")["enabled"] is False


@pytest.mark.parametrize("extra", [{"executable": "/bin/sh"}, {"codex_home": "/tmp"}, {"method": "thread/delete"}, {"limit": 0}, {"limit": 21}, {"cursor": "x" * 4097}, {"thread_id": LINK + "?bad=1"}])
def test_mcp_input_rejects_raw_controls_and_invalid_bounds(broker, tmp_path, extra):
    broker.set_tool_policy("codex_read_thread", enabled=True, approval_mode="never")
    result = broker.invoke("codex_read_thread", {"thread_id": LINK, **extra})
    assert result["error_code"] == "INVALID_INPUT"


def test_cli_configuration_and_status_are_local_and_secret_free(tmp_path, capsys):
    home = tmp_path / "codex-home"
    home.mkdir()
    prefix = ["--data-dir", str(tmp_path / "state")]
    assert main(prefix + ["configure-codex", "--executable", sys.executable, "--codex-home", str(home)]) == 0
    assert json.loads(capsys.readouterr().out)["enabled"] is True
    assert main(prefix + ["codex-status"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["enabled"] is True and result["connection_verified"] is False
    assert str(home) not in json.dumps(result)
    assert main(prefix + ["configure-codex", "--disable"]) == 0
    capsys.readouterr()
    assert main(prefix + ["read-codex-thread", LINK]) == 2
    assert json.loads(capsys.readouterr().out)["error_code"] == "TOOL_DISABLED"


def _fake_executable(tmp_path: Path, body: str) -> dict:
    home = tmp_path / "fake-home"
    home.mkdir()
    executable = tmp_path / "fixture-codex"
    executable.write_text(f"#!{sys.executable}\nimport json, sys, time\n" + body, encoding="utf-8")
    executable.chmod(0o700)
    return validate_local_config(str(executable), str(home))


def test_real_stdio_handshake_fixed_argv_and_isolated_environment(tmp_path, monkeypatch):
    config = _fake_executable(tmp_path, '''for line in sys.stdin:
    req = json.loads(line)
    if req["method"] == "initialized":
        continue
    result = {"userAgent": "fixture-codex/1"} if req["method"] == "initialize" else {"data": [], "nextCursor": None}
    print(json.dumps({"id": req["id"], "result": result}), flush=True)
''')
    original = codex_module.subprocess.Popen
    captured = {}

    def popen(argv, **kwargs):
        captured.update(argv=argv, **kwargs)
        return original(argv, **kwargs)

    monkeypatch.setenv("OPENAI_API_KEY", SECRET)
    monkeypatch.setenv("CONTROL_PLANE_API_KEY", SECRET)
    monkeypatch.setattr(codex_module.subprocess, "Popen", popen)
    client = CodexAppServerClient(config, timeout_seconds=3)
    with client:
        assert client.runtime == "fixture-codex/1"
        assert client.request("thread/list", {"limit": 1})["data"] == []
    assert client.process is None
    assert captured["argv"] == [config["executable"], "app-server", "--listen", "stdio://"]
    assert captured["shell"] is False
    assert "OPENAI_API_KEY" not in captured["env"] and "CONTROL_PLANE_API_KEY" not in captured["env"]


def test_stdio_timeout_terminates_owned_child(tmp_path):
    config = _fake_executable(tmp_path, "time.sleep(10)\n")
    client = CodexAppServerClient(config, timeout_seconds=0.05)
    with pytest.raises(PolicyError) as error:
        with client:
            pass
    assert error.value.code == "CODEX_TIMEOUT"
    assert client.process is None


@pytest.mark.parametrize("response, expected", [
    ('{"id": 1, "error": {"code": -32601, "message": "unsupported"}}', "CODEX_METHOD_UNSUPPORTED"),
    ('{"id": 99, "method": "item/commandExecution/requestApproval"}', "CODEX_UNEXPECTED_ACTION"),
    ('not-json', "CODEX_PROTOCOL_ERROR"),
])
def test_stdio_errors_and_approval_requests_fail_closed(tmp_path, response, expected):
    config = _fake_executable(tmp_path, "sys.stdin.readline()\nprint(" + repr(response) + ", flush=True)\ntime.sleep(1)\n")
    client = CodexAppServerClient(config, timeout_seconds=3)
    with pytest.raises(PolicyError) as error:
        with client:
            pass
    assert error.value.code == expected
    assert client.process is None


def test_stdio_wire_size_is_bounded(tmp_path, monkeypatch):
    config = _fake_executable(tmp_path, "sys.stdin.readline()\nprint('x' * 1024, flush=True)\ntime.sleep(1)\n")
    monkeypatch.setattr(codex_module, "MAX_WIRE_BYTES", 256)
    with pytest.raises(PolicyError) as error:
        with CodexAppServerClient(config, timeout_seconds=3):
            pass
    assert error.value.code == "CODEX_OUTPUT_TOO_LARGE"
