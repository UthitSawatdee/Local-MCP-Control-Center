from __future__ import annotations

import subprocess
from pathlib import Path

import local_mcp_control_center.supervisor as supervisor_module
from local_mcp_control_center.audit import AuditLog
from local_mcp_control_center.storage import Store
from local_mcp_control_center.supervisor import RuntimeSupervisor
from local_mcp_control_center.tunnel import MemorySecretStore, TunnelClientAdapter


TUNNEL_ID = "tunnel_" + "1" * 32


def test_supervisor_configures_and_starts_tunnel_client_without_shell(tmp_path: Path, monkeypatch) -> None:
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    calls: list[tuple[list[str], dict[str, object]]] = []
    secret_store = MemorySecretStore()

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "ready", "")

    class FakeProcess:
        pid = 4321

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
    supervisor = RuntimeSupervisor(store, AuditLog(store), tunnel_client=adapter)
    monkeypatch.setattr(supervisor_module.os, "getpgid", lambda _pid: 4321)
    try:
        configured = supervisor.configure_tunnel(
            client_path="tunnel-client",
            profile="supervisor-test",
            tunnel_id=TUNNEL_ID,
            api_key="sk-runtime-test-only",
        )
        assert configured["status"] == "ok"

        started = supervisor.start_tunnel()
        assert started["status"] == "ok"
        assert started["state"] == "running"
        assert store.get_runtime("tunnel")["state"] == "running"
        assert calls[-1][0][1] == "run"
        assert calls[-1][1]["shell"] is False if "shell" in calls[-1][1] else True
        assert "sk-runtime-test-only" not in " ".join(calls[-1][0])
    finally:
        store.close()


def test_second_supervisor_adopts_persisted_tunnel_instead_of_launching_again(tmp_path: Path, monkeypatch) -> None:
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    secret_store = MemorySecretStore()
    launches: list[list[str]] = []

    def fake_run(argv, **_kwargs):
        return subprocess.CompletedProcess(argv, 0, "ready", "")

    class FakeProcess:
        pid = 4321

        def poll(self):
            return None

    def fake_popen(argv, **_kwargs):
        launches.append(argv)
        return FakeProcess()

    adapter = TunnelClientAdapter(
        store,
        secret_store_factory=lambda _profile: secret_store,
        run=fake_run,
        popen=fake_popen,
        which=lambda _name: "/opt/homebrew/bin/tunnel-client",
    )
    monkeypatch.setattr(supervisor_module.os, "getpgid", lambda _pid: 4321)
    monkeypatch.setattr(
        supervisor_module.subprocess,
        "check_output",
        lambda *_args, **_kwargs: "/opt/homebrew/bin/tunnel-client run --profile supervisor-test",
    )
    try:
        first = RuntimeSupervisor(store, AuditLog(store), tunnel_client=adapter)
        first.configure_tunnel(
            client_path="tunnel-client",
            profile="supervisor-test",
            tunnel_id=TUNNEL_ID,
            api_key="sk-runtime-test-only",
        )
        assert first.start_tunnel()["status"] == "ok"

        second = RuntimeSupervisor(store, AuditLog(store), tunnel_client=adapter)
        adopted = second.start_tunnel()

        assert adopted["status"] == "ok"
        assert "earlier Control Center session" in adopted["message"]
        assert len(launches) == 1
    finally:
        store.close()


def test_start_stops_tunnel_when_initial_control_plane_auth_is_unauthorized(tmp_path: Path, monkeypatch) -> None:
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    secret_store = MemorySecretStore()

    def fake_run(argv, **_kwargs):
        return subprocess.CompletedProcess(argv, 0, "ready", "")

    class FakeProcess:
        pid = 9876

        def poll(self):
            return None

        def wait(self, **_kwargs):
            return None

    adapter = TunnelClientAdapter(
        store,
        secret_store_factory=lambda _profile: secret_store,
        run=fake_run,
        popen=lambda _argv, **_kwargs: FakeProcess(),
        which=lambda _name: "/opt/homebrew/bin/tunnel-client",
    )
    adapter.wait_for_control_plane = lambda *_args, **_kwargs: {
        "state": "unauthorized",
        "message": "OpenAI rejected the runtime API key (401 Unauthorized).",
    }
    supervisor = RuntimeSupervisor(store, AuditLog(store), tunnel_client=adapter)
    monkeypatch.setattr(supervisor_module.os, "getpgid", lambda _pid: 9876)
    monkeypatch.setattr(supervisor_module.os, "killpg", lambda *_args: None)
    try:
        assert supervisor.configure_tunnel(
            client_path="tunnel-client",
            profile="supervisor-auth-test",
            tunnel_id=TUNNEL_ID,
            api_key="sk-runtime-test-only",
        )["status"] == "ok"
        result = supervisor.start_tunnel()
        assert result["status"] == "denied"
        assert result["error_code"] == "TUNNEL_AUTH_UNAUTHORIZED"
        assert store.get_runtime("tunnel")["state"] == "stopped"
    finally:
        store.close()


def test_restart_bridge_restarts_the_tunnel_managed_bridge(tmp_path: Path, monkeypatch) -> None:
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    supervisor = RuntimeSupervisor(store, AuditLog(store))
    calls: list[str] = []
    monkeypatch.setattr(supervisor, "_tunnel_status", lambda: {"state": "ready"})
    monkeypatch.setattr(supervisor, "stop", lambda kind: calls.append(f"stop:{kind}") or {"status": "ok"})
    monkeypatch.setattr(supervisor, "start_tunnel", lambda: calls.append("start:tunnel") or {"status": "ok", "state": "running"})
    try:
        result = supervisor.restart_bridge()

        assert result == {"status": "ok", "state": "running"}
        assert calls == ["stop:tunnel", "start:tunnel"]
    finally:
        store.close()
