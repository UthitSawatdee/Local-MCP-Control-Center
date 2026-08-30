"""Owned project-process lifecycle with bounded, redacted logs."""

from __future__ import annotations

import os
import json
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .audit import AuditLog, sha256_json
from .errors import PolicyError
from .filesystem import redact_text
from .models import utc_now
from .runner import ProjectProfile, TRUSTED_BIN_DIRS
from .storage import Store


MAX_LOG_BYTES = 1_048_576
MAX_LOG_RESPONSE_BYTES = 65_536
LOG_TRUNCATION_MARKER = b"\n[LOG_TRUNCATED]\n"


class _BoundedLog:
    def __init__(self, path: Path, max_bytes: int = MAX_LOG_BYTES):
        self.path = path
        self.max_bytes = max(1, min(max_bytes, MAX_LOG_BYTES))
        self._lock = threading.RLock()
        self._written = 0
        self._truncated = False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(mode=0o600, exist_ok=True)
        os.chmod(self.path, 0o600)

    def append(self, data: bytes) -> None:
        if not data:
            return
        text = redact_text(data.decode("utf-8", errors="replace"))
        encoded = text.encode("utf-8")
        with self._lock:
            if self._written >= self.max_bytes:
                return
            remaining = self.max_bytes - self._written
            if len(encoded) > remaining:
                encoded = encoded[:remaining]
                self._truncated = True
                if remaining > len(LOG_TRUNCATION_MARKER):
                    encoded = encoded[: remaining - len(LOG_TRUNCATION_MARKER)] + LOG_TRUNCATION_MARKER
            with self.path.open("ab") as handle:
                handle.write(encoded)
                handle.flush()
            self._written += len(encoded)

    def close_marker(self) -> None:
        with self._lock:
            if self._truncated and self._written < self.max_bytes:
                with self.path.open("ab") as handle:
                    handle.write(LOG_TRUNCATION_MARKER[: self.max_bytes - self._written])
                self._written = self.max_bytes


class ManagedProcessManager:
    """Start, inspect, tail, and stop only profiles this app owns."""

    def __init__(self, store: Store, audit: AuditLog):
        self.store = store
        self.audit = audit
        self.data_dir = store.data_dir
        self.logs_dir = self.data_dir / "process-logs"
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.logs_dir, 0o700)
        self._handles: dict[str, subprocess.Popen[bytes]] = {}
        self._sinks: dict[str, _BoundedLog] = {}
        self._trace_ids: dict[str, str | None] = {}
        self._lock = threading.RLock()

    def start(
        self,
        profile: ProjectProfile,
        *,
        scope_id: str,
        owner_session_id: str,
        timeout_seconds: int | None = None,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        timeout_ms = profile.timeout_ms if timeout_seconds is None else max(1, min(int(timeout_seconds), 3_600)) * 1000
        process_id = str(uuid.uuid4())
        log_path = self.logs_dir / f"{process_id}.log"
        sink = _BoundedLog(log_path)
        argv = [profile.executable, *profile.args]
        environment = self._environment()
        try:
            process = subprocess.Popen(
                argv,
                cwd=str(profile.working_directory),
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=False,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            sink.close_marker()
            raise PolicyError("PROCESS_START_FAILED", "unable to start the selected project profile") from exc

        try:
            process_group = os.getpgid(process.pid)
        except OSError as exc:
            try:
                process.kill()
            except OSError:
                pass
            raise PolicyError("PROCESS_START_FAILED", "started process has no verifiable process group") from exc

        started_at = utc_now()
        command_digest = sha256_json(argv)
        with self._lock:
            self._handles[process_id] = process
            self._sinks[process_id] = sink
            self._trace_ids[process_id] = trace_id
        self.store.upsert_runtime(
            {
                "id": process_id,
                "kind": "managed_project",
                "profile": profile.name,
                "pid": process.pid,
                "pgid": process_group,
                "state": "running",
                "started_at": started_at,
                "stopped_at": None,
                "log_path": str(log_path),
                "timeout_ms": timeout_ms,
                "exit_code": None,
                "scope_id": scope_id,
                "owner_session_id": owner_session_id,
                "updated_at": started_at,
                "command_digest": command_digest,
                "argv_json": json.dumps(argv, ensure_ascii=False, separators=(",", ":")),
            }
        )
        reader = threading.Thread(target=self._capture, args=(process_id, process, sink), daemon=True)
        reader.start()
        watcher = threading.Thread(
            target=self._watch,
            args=(process_id, process, sink, timeout_ms),
            daemon=True,
        )
        watcher.start()
        self.audit.record(
            actor="system",
            tool="process_start_profile",
            operation="start",
            decision="executed",
            target_display=profile.name,
            session_id=owner_session_id,
            process_id=process_id,
            trace_id=trace_id,
            metadata={"pid": process.pid, "profile": profile.name, "timeout_ms": timeout_ms},
        )
        return self._public_record(self.store.get_runtime_by_id(process_id) or {})

    def status(self, process_id: str | None = None) -> list[dict[str, Any]]:
        rows = [self.store.get_runtime_by_id(process_id)] if process_id else self.store.list_runtime()
        result: list[dict[str, Any]] = []
        for row in rows:
            if not row or row.get("kind") != "managed_project":
                continue
            self._refresh(row)
            current = self.store.get_runtime_by_id(row["id"]) or row
            result.append(self._public_record(current))
        return result

    def stop(self, process_id: str, *, trace_id: str | None = None) -> dict[str, Any]:
        row = self.store.get_runtime_by_id(process_id)
        if not row or row.get("kind") != "managed_project":
            raise PolicyError("PROCESS_NOT_FOUND", "managed process was not found")
        if not self._is_owned_alive(row):
            self.store.update_runtime(
                process_id,
                state="stopped",
                stopped_at=utc_now(),
                pid=None,
                pgid=None,
                exit_code=row.get("exit_code"),
            )
            return self._public_record(self.store.get_runtime_by_id(process_id) or row)
        pid = int(row["pid"])
        pgid = int(row["pgid"])
        try:
            os.killpg(pgid, signal.SIGTERM)
            handle = self._handles.get(process_id)
            if handle is not None:
                try:
                    handle.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(pgid, signal.SIGKILL)
                    handle.wait(timeout=5)
            else:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and self._pid_alive(pid):
                    time.sleep(0.05)
                if self._pid_alive(pid):
                    os.killpg(pgid, signal.SIGKILL)
        except OSError as exc:
            raise PolicyError("PROCESS_STOP_FAILED", "owned process could not be stopped") from exc
        self.store.update_runtime(
            process_id,
            state="stopped",
            stopped_at=utc_now(),
            pid=None,
            pgid=None,
        )
        self.audit.record(
            actor="system",
            tool="process_stop",
            operation="stop",
            decision="executed",
            target_display=process_id,
            process_id=process_id,
            trace_id=trace_id,
            metadata={"pid": pid, "process_group": pgid},
        )
        return self._public_record(self.store.get_runtime_by_id(process_id) or row)

    def logs(
        self,
        process_id: str,
        *,
        tail_lines: int = 100,
        since_sequence: int | None = None,
    ) -> dict[str, Any]:
        row = self.store.get_runtime_by_id(process_id)
        if not row or row.get("kind") != "managed_project":
            raise PolicyError("PROCESS_NOT_FOUND", "managed process was not found")
        log_path = Path(str(row.get("log_path") or ""))
        if not log_path.is_file() or self.store.data_dir not in log_path.parents:
            raise PolicyError("PROCESS_LOG_UNAVAILABLE", "managed process log is unavailable")
        tail_lines = max(1, min(int(tail_lines), 500))
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        log_was_truncated = "[LOG_TRUNCATED]" in log_text
        lines = log_text.splitlines()
        entries = [
            {"sequence": index + 1, "text": redact_text(line)[:2000]}
            for index, line in enumerate(lines)
            if since_sequence is None or index + 1 > since_sequence
        ]
        has_more = len(entries) > tail_lines if since_sequence is None else len(entries) > tail_lines
        if has_more:
            entries = entries[-tail_lines:]
        else:
            entries = entries[:tail_lines]
        used = 0
        bounded: list[dict[str, Any]] = []
        for entry in entries:
            size = len(entry["text"].encode("utf-8"))
            if bounded and used + size > MAX_LOG_RESPONSE_BYTES:
                has_more = True
                break
            bounded.append(entry)
            used += size
        next_sequence = bounded[-1]["sequence"] if bounded else since_sequence
        return {
            "status": "ok",
            "process_id": process_id,
            "entries": bounded,
            "tail_lines": tail_lines,
            "since_sequence": since_sequence,
            "has_more": has_more or log_was_truncated,
            "truncated": has_more or log_was_truncated,
            "next_sequence": next_sequence,
        }

    def _capture(self, process_id: str, process: subprocess.Popen[bytes], sink: _BoundedLog) -> None:
        stream = process.stdout
        if stream is not None:
            try:
                for chunk in iter(lambda: stream.read(8192), b""):
                    sink.append(chunk)
            except OSError:
                pass

    def _watch(
        self,
        process_id: str,
        process: subprocess.Popen[bytes],
        sink: _BoundedLog,
        timeout_ms: int,
    ) -> None:
        timed_out = False
        deadline = time.monotonic() + timeout_ms / 1000
        while process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if process.poll() is None:
            timed_out = True
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except OSError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except OSError:
                    pass
        exit_code = process.poll()
        if exit_code is None:
            try:
                exit_code = process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                exit_code = -1
        sink.close_marker()
        state = "timed_out" if timed_out else "exited"
        self.store.update_runtime(
            process_id,
            state=state,
            stopped_at=utc_now(),
            exit_code=exit_code,
            pid=None,
            pgid=None,
        )
        with self._lock:
            trace_id = self._trace_ids.get(process_id)
            self._handles.pop(process_id, None)
            self._sinks.pop(process_id, None)
            self._trace_ids.pop(process_id, None)
        self.audit.record(
            actor="system",
            tool="process_status",
            operation="complete",
            decision="executed",
            target_display=process_id,
            process_id=process_id,
            trace_id=trace_id,
            result_code=str(exit_code),
            metadata={"state": state, "timed_out": timed_out},
        )

    def _refresh(self, row: dict[str, Any]) -> None:
        process_id = str(row["id"])
        handle = self._handles.get(process_id)
        # The watcher owns the terminal transition.  A process can have
        # already exited (including after the timeout signal) while the
        # watcher is still recording ``exited`` vs ``timed_out``; do not race
        # it by rewriting the state to ``exited`` from a status read.
        if handle is not None:
            return
        if row.get("state") == "running" and not self._is_owned_alive(row):
            self.store.update_runtime(
                process_id,
                state="exited",
                stopped_at=row.get("stopped_at") or utc_now(),
                pid=None,
                pgid=None,
            )

    def _is_owned_alive(self, row: dict[str, Any]) -> bool:
        pid = row.get("pid")
        pgid = row.get("pgid")
        if not pid or not pgid:
            return False
        try:
            if os.getpgid(int(pid)) != int(pgid):
                return False
        except OSError:
            return False
        handle = self._handles.get(str(row["id"]))
        if handle is not None:
            return handle.poll() is None
        # A fresh Control Center instance may inspect/stop a process persisted
        # by its predecessor, but only after an exact command identity check.
        try:
            command = subprocess.check_output(
                ["/bin/ps", "-p", str(pid), "-o", "command="],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except (OSError, subprocess.SubprocessError):
            return False
        return bool(command and row.get("command_digest") and self._command_digest_from_ps(command, row))

    @staticmethod
    def _command_digest_from_ps(command: str, row: dict[str, Any]) -> bool:
        try:
            argv = json.loads(str(row.get("argv_json") or ""))
        except (TypeError, json.JSONDecodeError):
            return False
        if not isinstance(argv, list) or not argv or any(not isinstance(item, str) for item in argv):
            return False
        # ps output is not a byte-for-byte argv serialization on every
        # platform, so require every saved argument as a token in the command
        # line and independently verify the saved digest.  This prevents a
        # stale PID from being treated as owned after process reuse.
        if sha256_json(argv) != row.get("command_digest"):
            return False
        return all(item in command for item in argv)

    def _public_record(self, row: dict[str, Any]) -> dict[str, Any]:
        if not row:
            return {}
        return {
            "process_id": row.get("id"),
            "profile": row.get("profile"),
            "pid": row.get("pid"),
            "process_group": row.get("pgid"),
            "state": row.get("state"),
            "started_at": row.get("started_at"),
            "stopped_at": row.get("stopped_at"),
            "timeout_ms": row.get("timeout_ms"),
            "exit_code": row.get("exit_code"),
            "log_available": bool(row.get("log_path")),
        }

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        return True

    def _environment(self) -> dict[str, str]:
        runtime_home = self.data_dir / "runtime-home"
        runtime_tmp = self.data_dir / "runtime-tmp"
        runtime_home.mkdir(parents=True, exist_ok=True)
        runtime_tmp.mkdir(parents=True, exist_ok=True)
        return {
            "PATH": os.pathsep.join(str(path) for path in TRUSTED_BIN_DIRS),
            "HOME": str(runtime_home),
            "TMPDIR": str(runtime_tmp),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "CI": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "PAGER": "cat",
            "NO_COLOR": "1",
        }
