from __future__ import annotations

import ctypes
import subprocess
from pathlib import Path

import pytest

from local_mcp_control_center.errors import TunnelError
from local_mcp_control_center.storage import Store
import local_mcp_control_center.tunnel as tunnel_module
from local_mcp_control_center.tunnel import MacOSKeychain, MemorySecretStore, TunnelClientAdapter


TUNNEL_ID = "tunnel_" + "0" * 32


def test_tunnel_configuration_rejects_non_official_executable(tmp_path: Path) -> None:
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    adapter = TunnelClientAdapter(store)
    try:
        with pytest.raises(TunnelError) as error:
            adapter.configure(
                client_path="/tmp/evil-client",
                profile="local-test",
                tunnel_id=TUNNEL_ID,
                api_key="sk-runtime-test-only",
            )
        assert error.value.code == "TUNNEL_CONFIG_INVALID"
    finally:
        store.close()


def test_keychain_write_uses_native_api_not_a_terminal_prompt(monkeypatch) -> None:
    captured = {}

    class FakeSecurity:
        def SecKeychainAddGenericPassword(self, *_args):
            captured["secret"] = ctypes.string_at(_args[6], _args[5])
            return 0

    class FakeCoreFoundation:
        def CFRelease(self, _item):
            return None

    monkeypatch.setattr(MacOSKeychain, "_frameworks", lambda _self: (FakeSecurity(), FakeCoreFoundation()))
    monkeypatch.setattr(MacOSKeychain, "delete", lambda _self: False)
    MacOSKeychain("service", "account").set("sk-runtime-test-only")

    assert captured["secret"] == b"sk-runtime-test-only"


def test_tunnel_profile_uses_fixed_mcp_command_and_keeps_key_out_of_state(tmp_path: Path) -> None:
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    captured: list[tuple[list[str], dict[str, object]]] = []
    secret_store = MemorySecretStore()

    def fake_run(argv, **kwargs):
        captured.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "profile initialized", "")

    adapter = TunnelClientAdapter(
        store,
        secret_store_factory=lambda _profile: secret_store,
        run=fake_run,
        which=lambda _name: "/opt/homebrew/bin/tunnel-client",
    )
    try:
        result = adapter.configure(
            client_path="tunnel-client",
            profile="local-test",
            tunnel_id=TUNNEL_ID,
            api_key="sk-runtime-test-only",
        )
        assert result["status"] == "ok"
        assert result["api_key_suffix"] == "…only"
        argv, kwargs = captured[0]
        assert argv[0] == "/opt/homebrew/bin/tunnel-client"
        assert argv[1:4] == ["init", "--sample", "sample_mcp_stdio_local"]
        assert "--profile-dir" in argv
        assert "--mcp-command" in argv
        assert "shell" not in kwargs or kwargs["shell"] is False
        assert kwargs["env"]["CONTROL_PLANE_API_KEY"] == "sk-runtime-test-only"
        assert "sk-runtime-test-only" not in " ".join(argv)

        row = store._conn.execute("SELECT value FROM meta WHERE key='tunnel_config'").fetchone()
        assert row is not None
        assert "sk-runtime-test-only" not in row["value"]
        assert secret_store.get() == "sk-runtime-test-only"
    finally:
        store.close()


def test_tunnel_doctor_and_run_use_profile_dir_and_loopback_health_file(tmp_path: Path) -> None:
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    calls: list[tuple[list[str], dict[str, object]]] = []
    secret_store = MemorySecretStore("sk-runtime-test-only")

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "ready", "")

    class FakeProcess:
        pid = 1234

        def poll(self):
            return None

    def fake_popen(argv, **kwargs):
        calls.append((argv, kwargs))
        return FakeProcess()

    adapter = TunnelClientAdapter(
        store,
        secret_store_factory=lambda _profile: secret_store,
        run=fake_run,
        popen=fake_popen,
        which=lambda _name: "/opt/homebrew/bin/tunnel-client",
    )
    try:
        adapter.configure(
            client_path="tunnel-client",
            profile="local-test",
            tunnel_id=TUNNEL_ID,
            api_key=None,
        )
        assert adapter.doctor()["state"] == "ready"
        process, health_file = adapter.launch(tmp_path / "state" / "logs" / "tunnel.log")
        assert process.pid == 1234
        run_argv, run_kwargs = calls[-1]
        assert run_argv[1] == "run"
        assert "--health.listen-addr" in run_argv
        assert run_argv[run_argv.index("--health.listen-addr") + 1] == "127.0.0.1:0"
        assert run_argv[run_argv.index("--health.url-file") + 1] == str(health_file)
        assert str(health_file).startswith(str(tmp_path / "state" / "run"))
        assert run_kwargs["env"]["CONTROL_PLANE_API_KEY"] == "sk-runtime-test-only"
        assert "sk-runtime-test-only" not in " ".join(run_argv)
    finally:
        store.close()


def test_tunnel_status_does_not_expose_secret(tmp_path: Path) -> None:
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    secret_store = MemorySecretStore("sk-runtime-test-only")
    adapter = TunnelClientAdapter(
        store,
        secret_store_factory=lambda _profile: secret_store,
        run=lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, "", ""),
        which=lambda _name: "/opt/homebrew/bin/tunnel-client",
    )
    try:
        adapter.configure(
            client_path="tunnel-client",
            profile="local-test",
            tunnel_id=TUNNEL_ID,
            api_key=None,
        )
        status = adapter.public_status()
        assert status["api_key"] == "keychain"
        assert "sk-runtime-test-only" not in repr(status)
    finally:
        store.close()


def test_control_plane_status_reports_unauthorized_without_exposing_log_contents(tmp_path: Path) -> None:
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    adapter = TunnelClientAdapter(store)
    log_path = tmp_path / "tunnel.log"
    log_path.write_text(
        '{"component":"controlplane","status_code":401,"status":"401 Unauthorized"}\n',
        encoding="utf-8",
    )
    try:
        status = adapter.control_plane_status(log_path)
        assert status["state"] == "unauthorized"
        assert "401 Unauthorized" in status["message"]
    finally:
        store.close()


def test_control_plane_status_reads_current_metrics_before_stale_log(tmp_path: Path, monkeypatch) -> None:
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    adapter = TunnelClientAdapter(store)

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit: int) -> bytes:
            return (
                b'http_client_request_duration_seconds_count{http_response_status_code="401"} 2\n'
                b"commands_poll_last_successful_timestamp_seconds{} 0\n"
            )

    monkeypatch.setattr(tunnel_module, "urlopen", lambda *_args, **_kwargs: Response())
    try:
        status = adapter.control_plane_status(None, health_url="http://127.0.0.1:12345")
        assert status["state"] == "unauthorized"
    finally:
        store.close()


def test_control_plane_status_accepts_scientific_timestamp_metrics(tmp_path: Path, monkeypatch) -> None:
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    adapter = TunnelClientAdapter(store)

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit: int) -> bytes:
            return (
                b"commands_poll_last_successful_timestamp_seconds{otel_scope_name=\"controlplane\"} 1.78809903e+09\n"
                b"commands_poll_errors_total{otel_scope_name=\"controlplane\"} 0\n"
            )

    monkeypatch.setattr(tunnel_module, "urlopen", lambda *_args, **_kwargs: Response())
    try:
        status = adapter.control_plane_status(None, health_url="http://127.0.0.1:12345")
        assert status["state"] == "authenticated"
    finally:
        store.close()


def test_control_plane_status_ignores_401_from_before_current_run(tmp_path: Path) -> None:
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    adapter = TunnelClientAdapter(store)
    log_path = tmp_path / "tunnel.log"
    log_path.write_text(
        "\n".join(
            [
                '{"time":"2026-08-30T12:00:00.000+00:00","status_code":401,"status":"401 Unauthorized"}',
                '{"time":"2026-08-30T13:00:00.000+00:00","component":"health","msg":"ready"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    try:
        status = adapter.control_plane_status(log_path, since="2026-08-30T12:30:00.000+00:00")
        assert status["state"] == "unverified"
    finally:
        store.close()
