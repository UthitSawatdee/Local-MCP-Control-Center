from __future__ import annotations

import os
import signal
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .broker import RequestContext
from .errors import PolicyError, TunnelError
from .models import utc_now
from .storage import Store
from .tunnel import TunnelClientAdapter


_ACTIVE_RUNTIME_STATES = frozenset({"starting", "running", "healthy", "ready", "unhealthy"})


class RuntimeSupervisor:
    """Owns only processes launched by this app; never kills by broad process name."""

    def __init__(self, store: Store, audit: AuditLog, tunnel_client: TunnelClientAdapter | None = None):
        self.store = store
        self.audit = audit
        self.data_dir = store.data_dir
        self.logs_dir = self.data_dir / "logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.logs_dir, 0o700)
        self._processes: dict[str, subprocess.Popen[Any]] = {}
        self._health_files: dict[str, Path] = {}
        self.tunnel_client = tunnel_client or TunnelClientAdapter(store)

    def start_mcp(self) -> dict[str, Any]:
        if self._alive("mcp_bridge"):
            return {"status": "ok", "state": "running"}
        process_id = "mcp_bridge"
        log_path = self.logs_dir / "mcp-bridge.log"
        handle = log_path.open("ab")
        command = [
            sys.executable,
            "-m",
            "local_mcp_control_center",
            "--data-dir",
            str(self.data_dir),
            "mcp",
        ]
        source_root = Path(__file__).resolve().parents[1]
        environment = os.environ.copy()
        existing_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = os.pathsep.join(
            value for value in (str(source_root), existing_pythonpath) if value
        )
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=handle,
                stderr=subprocess.STDOUT,
                cwd=str(Path(__file__).resolve().parents[2]),
                env=environment,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            self.audit.record(
                actor="user",
                tool="control.runtime",
                operation="start_mcp",
                decision="failed",
                target_display="mcp_bridge",
                error_code="PROCESS_START_FAILED",
                metadata={"exception_type": type(exc).__name__},
            )
            return {"status": "denied", "error_code": "PROCESS_START_FAILED", "message": str(exc)}
        finally:
            handle.close()
        self._processes[process_id] = process
        pgid = os.getpgid(process.pid)
        self.store.upsert_runtime({
            "id": process_id,
            "kind": "mcp_bridge",
            "profile": "mcp_stdio",
            "pid": process.pid,
            "pgid": pgid,
            "state": "running",
            "started_at": utc_now(),
            "stopped_at": None,
            "log_path": str(log_path),
        })
        self.audit.record(
            actor="user",
            tool="control.runtime",
            operation="start_mcp",
            decision="executed",
            target_display="mcp_bridge",
            metadata={"pid": process.pid},
        )
        return {"status": "ok", "state": "running", "pid": process.pid, "log_path": str(log_path)}

    def configure_tunnel(
        self,
        *,
        client_path: str,
        profile: str,
        tunnel_id: str,
        api_key: str | None,
    ) -> dict[str, Any]:
        if self._alive("tunnel") or self._persisted_process("tunnel"):
            return {
                "status": "denied",
                "error_code": "TUNNEL_RUNNING_RECONFIGURE",
                "message": "Stop the running tunnel before changing its configuration.",
            }
        try:
            result = self.tunnel_client.configure(
                client_path=client_path,
                profile=profile,
                tunnel_id=tunnel_id,
                api_key=api_key,
            )
        except TunnelError as exc:
            self._audit_tunnel("configure_tunnel", "denied", exc.code, {"profile": profile})
            return {"status": "denied", "error_code": exc.code, "message": exc.message}
        self.audit.record(
            actor="user",
            tool="control.runtime",
            operation="configure_tunnel",
            decision="executed",
            target_display="tunnel_client",
            metadata={"profile": profile, "client_path": client_path, "tunnel_id": tunnel_id},
        )
        return result

    def doctor_tunnel(self) -> dict[str, Any]:
        try:
            result = self.tunnel_client.doctor()
        except TunnelError as exc:
            self._audit_tunnel("doctor_tunnel", "failed", exc.code, {})
            return {"status": "denied", "error_code": exc.code, "message": exc.message}
        self.audit.record(
            actor="user",
            tool="control.runtime",
            operation="doctor_tunnel",
            decision="executed",
            target_display="tunnel_client",
            metadata={"profile": result.get("profile")},
        )
        return result

    def clear_tunnel_key(self) -> dict[str, Any]:
        if self._alive("tunnel") or self._persisted_process("tunnel"):
            return {
                "status": "denied",
                "error_code": "TUNNEL_RUNNING_CLEAR_KEY",
                "message": "Stop the running tunnel before removing its saved key.",
            }
        try:
            result = self.tunnel_client.clear_stored_key()
        except TunnelError as exc:
            self._audit_tunnel("clear_tunnel_key", "denied", exc.code, {})
            return {"status": "denied", "error_code": exc.code, "message": exc.message}
        self.audit.record(
            actor="user",
            tool="control.runtime",
            operation="clear_tunnel_key",
            decision="executed",
            target_display="tunnel_client",
            metadata={"removed": result["removed"]},
        )
        return result

    def start_tunnel(self) -> dict[str, Any]:
        if self._alive("tunnel"):
            return {"status": "ok", "state": "running", **self._tunnel_status()}
        if self._persisted_process("tunnel"):
            return {
                "status": "ok",
                "state": "running",
                "message": "Tunnel-client is already running from an earlier Control Center session.",
                **self._tunnel_status(),
            }
        if self._alive("mcp_bridge"):
            result = {
                "status": "denied",
                "error_code": "MCP_BRIDGE_ALREADY_RUNNING",
                "message": "Stop the standalone MCP bridge first; tunnel-client starts its own fixed MCP bridge.",
            }
            self._audit_tunnel("start_tunnel", "denied", result["error_code"], {})
            return result
        try:
            config = self.tunnel_client.get_config()
            if not config:
                raise TunnelError(
                    "TUNNEL_NOT_CONFIGURED",
                    "Configure a tunnel ID, runtime API key, and client before starting the tunnel.",
                )
            doctor = self.tunnel_client.doctor()
            log_path = self.logs_dir / "tunnel-client.log"
            started_at = utc_now()
            process, health_file = self.tunnel_client.launch(log_path)
            if process.poll() is not None:
                self._audit_tunnel("start_tunnel", "failed", "TUNNEL_EXITED", {})
                return {
                    "status": "denied",
                    "error_code": "TUNNEL_EXITED",
                    "message": "tunnel-client exited immediately; inspect the tunnel-client log.",
                    "log_path": str(log_path),
                }
        except TunnelError as exc:
            self._audit_tunnel("start_tunnel", "denied", exc.code, {})
            return {"status": "denied", "error_code": exc.code, "message": exc.message}
        self._processes["tunnel"] = process
        self._health_files["tunnel"] = health_file
        profile = config.profile
        try:
            pgid = os.getpgid(process.pid)
        except OSError:
            self._processes.pop("tunnel", None)
            self._health_files.pop("tunnel", None)
            self._audit_tunnel("start_tunnel", "failed", "TUNNEL_EXITED", {})
            return {
                "status": "denied",
                "error_code": "TUNNEL_EXITED",
                "message": "tunnel-client exited before its process could be registered; inspect the tunnel-client log.",
                "log_path": str(log_path),
            }
        self.store.upsert_runtime({
            "id": "tunnel",
            "kind": "tunnel",
            "profile": profile,
            "pid": process.pid,
            "pgid": pgid,
            "state": "running",
            "started_at": started_at,
            "stopped_at": None,
            "log_path": str(log_path),
        })
        control_plane = self.tunnel_client.wait_for_control_plane(
            log_path,
            since=started_at,
            health_url_file=health_file,
            timeout=2.0,
        )
        if control_plane.get("state") == "unauthorized":
            self.stop("tunnel")
            return {
                "status": "denied",
                "error_code": "TUNNEL_AUTH_UNAUTHORIZED",
                "message": (
                    "OpenAI rejected the runtime API key (401 Unauthorized). "
                    "Open Configure tunnel and paste the current Active runtime key, then start again."
                ),
                "log_path": str(log_path),
                "control_plane": control_plane,
            }
        self.audit.record(
            actor="user",
            tool="control.runtime",
            operation="start_tunnel",
            decision="executed",
            target_display="tunnel_client",
            metadata={"pid": process.pid, "profile": profile, "doctor_state": doctor.get("state")},
        )
        return {
            "status": "ok",
            "state": "running",
            "pid": process.pid,
            "profile": profile,
            "log_path": str(log_path),
            "health_file": str(health_file),
            "health": self.tunnel_client.health(health_file),
            "control_plane": control_plane,
        }

    def restart_bridge(self) -> dict[str, Any]:
        """Restart the active standalone bridge or tunnel-managed bridge."""
        tunnel_state = self._tunnel_status().get("state")
        if tunnel_state in _ACTIVE_RUNTIME_STATES:
            stopped = self.stop("tunnel")
            if stopped.get("status") != "ok":
                return stopped
            return self.start_tunnel()

        if self._alive("mcp_bridge") or self._persisted_process("mcp_bridge"):
            stopped = self.stop("mcp_bridge")
            if stopped.get("status") != "ok":
                return stopped
            return self.start_mcp()

        return {
            "status": "denied",
            "error_code": "BRIDGE_NOT_RUNNING",
            "message": "No running MCP bridge or secure tunnel was found.",
        }

    def stop(self, kind: str) -> dict[str, Any]:
        process = self._processes.get(kind)
        if not process:
            existing = self._persisted_process(kind)
            if not existing:
                return {"status": "denied", "error_code": "PROCESS_NOT_OWNED", "message": "process is not owned by this Control Center"}
            try:
                os.killpg(existing["pgid"], signal.SIGTERM)
            except OSError as exc:
                return {"status": "denied", "error_code": "PROCESS_STOP_FAILED", "message": str(exc)}
            self._mark_stopped(kind)
            self.audit.record(
                actor="user",
                tool="control.runtime",
                operation=f"stop_{kind}",
                decision="executed",
                target_display=kind,
                metadata={"pid": existing["pid"], "adopted": True},
            )
            return {"status": "ok", "state": "stopped"}
        if process.poll() is not None:
            self._mark_stopped(kind)
            return {"status": "ok", "state": "stopped"}
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            process.wait(timeout=5)
        except OSError as exc:
            return {"status": "denied", "error_code": "PROCESS_STOP_FAILED", "message": str(exc)}
        finally:
            self._mark_stopped(kind)
        self.audit.record(
            actor="user",
            tool="control.runtime",
            operation=f"stop_{kind}",
            decision="executed",
            target_display=kind,
            metadata={},
        )
        return {"status": "ok", "state": "stopped"}

    def status(self) -> dict[str, Any]:
        statuses = []
        for kind, process in self._processes.items():
            state = "running" if process.poll() is None else "stopped"
            statuses.append({"kind": kind, "pid": process.pid, "state": state})
            if state == "stopped":
                self._mark_stopped(kind)
        return {
            "processes": statuses,
            "persisted": self.store.list_runtime(),
            "tunnel": self._tunnel_status(),
        }

    def _tunnel_status(self) -> dict[str, Any]:
        status = self.tunnel_client.public_status()
        process = self._processes.get("tunnel")
        runtime = self.store.get_runtime("tunnel")
        if (process and process.poll() is None) or self._persisted_process("tunnel"):
            health = self.tunnel_client.health(self._health_files.get("tunnel"))
            reported_state = health.get("state") if health.get("state") in {"healthy", "ready", "unhealthy"} else "running"
            status["state"] = reported_state
            status["health"] = health
            status["control_plane"] = self.tunnel_client.control_plane_status(
                runtime.get("log_path") if runtime else None,
                since=runtime.get("started_at") if runtime else None,
                health_url=health.get("health_url"),
            )
            if runtime and runtime.get("state") != reported_state:
                self.store.update_runtime_state("tunnel", reported_state)
        return status

    def _audit_tunnel(self, operation: str, decision: str, error_code: str, metadata: dict[str, Any]) -> None:
        self.audit.record(
            actor="user",
            tool="control.runtime",
            operation=operation,
            decision=decision,
            target_display="tunnel_client",
            error_code=error_code,
            metadata=metadata,
        )

    def _alive(self, kind: str) -> bool:
        process = self._processes.get(kind)
        return bool(process and process.poll() is None)

    def _persisted_process(self, kind: str) -> dict[str, int] | None:
        """Validate a previous Control Center process before adopting or stopping it."""
        runtime = self.store.get_runtime(kind)
        if not runtime or not runtime.get("pid") or not runtime.get("pgid"):
            return None
        pid, pgid = int(runtime["pid"]), int(runtime["pgid"])
        try:
            if os.getpgid(pid) != pgid:
                self._mark_stopped(kind)
                return None
            command = subprocess.check_output(["/bin/ps", "-p", str(pid), "-o", "command="], text=True).strip()
        except (OSError, subprocess.SubprocessError):
            self._mark_stopped(kind)
            return None
        if kind == "tunnel":
            config = self.tunnel_client.get_config()
            valid = bool(config and "tunnel-client" in command and f"--profile {config.profile}" in command)
        else:
            valid = "local_mcp_control_center" in command
        if not valid:
            self._mark_stopped(kind)
            return None
        return {"pid": pid, "pgid": pgid}

    def _mark_stopped(self, kind: str) -> None:
        self._health_files.pop(kind, None)
        self.store.upsert_runtime({
            "id": kind,
            "kind": kind,
            "profile": "mcp_stdio" if kind == "mcp_bridge" else "tunnel",
            "pid": None,
            "pgid": None,
            "state": "stopped",
            "started_at": None,
            "stopped_at": utc_now(),
            "log_path": None,
        })
