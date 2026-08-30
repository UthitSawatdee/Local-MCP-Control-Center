"""Bounded local coding-agent task management.

This module is a deliberately small seam for a later Broker integration.  It
does not make policy decisions, discover credentials, or forward work to a
remote service.  The caller must provide an already-approved ``scope_id`` and
canonical scope root (or inject a scope resolver supplied by the Broker).

Only :class:`AgentProfile` objects registered with :class:`AgentTaskManager`
can be started.  A profile owns its executable, fixed argument array, and
timeout.  Task input is delivered as bounded bytes on stdin; it is never
interpolated into argv or interpreted by a shell.  The manager gives every
subprocess a scrubbed environment and keeps task ownership in memory, so a
manager instance cannot cancel a PID it did not start.

The external interface is intentionally narrow:

* ``register_profile`` / ``configure_profile`` configure named profiles;
* ``start_task`` starts one bounded task against an approved scope;
* ``status`` and ``logs`` expose bounded JSON-safe observations;
* ``cancel`` stops only a task owned by this manager; and
* ``result`` returns a terminal task result.

The launcher, clock, sleeper, and process-group signal function are injected
seams for deterministic tests.  The default launcher is a direct
``subprocess.Popen`` call with ``shell=False``.
"""

from __future__ import annotations

import math
import os
import re
import signal
import subprocess
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from .errors import PolicyError
from .filesystem import redact_text
from .models import utc_now
from .runner import TRUSTED_BIN_DIRS


# Hard ceilings are part of the security contract.  Constructor arguments can
# lower these values for a deployment or test, but cannot raise them.
MAX_ACTIVE_TASKS = 16
MAX_RECORDED_TASKS = 256
MAX_PROMPT_BYTES = 32_768
MAX_TIMEOUT_SECONDS = 3_600.0
MAX_OUTPUT_BYTES = 1_048_576
MAX_LOG_BYTES = 1_048_576
MAX_LOG_RESPONSE_BYTES = 65_536
MAX_TAIL_LINES = 500
MAX_PROFILE_ARGS = 64
MAX_PROFILE_ARG_BYTES = 4_096
MAX_PROFILE_NAME_BYTES = 64
MAX_SCOPE_ID_BYTES = 128
MAX_TASK_ID_BYTES = 128
MAX_CANCEL_GRACE_SECONDS = 30.0

_PROFILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_SCOPE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_BIN_DIRS = tuple(
    path for path in TRUSTED_BIN_DIRS if path != Path.home() / ".local" / "bin"
)
_TERMINAL_STATES = frozenset(
    {
        "completed",
        "failed",
        "timed_out",
        "cancelled",
    }
)


class TaskState(StrEnum):
    """JSON-safe lifecycle states exposed by the manager."""

    STARTING = "starting"
    RUNNING = "running"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class AgentProfile:
    """A control-plane configured executable and immutable argument array.

    ``AgentProfile`` is configuration, not task input.  A profile should be
    constructed by trusted local configuration code and registered before an
    agent-facing Broker tool can choose it.  ``allowed_scope_ids`` is an
    optional static narrowing of the Broker-approved scope set; it is not a
    replacement for Broker policy evaluation.
    """

    name: str
    executable: str
    args: tuple[str, ...] = ()
    timeout_seconds: float = 300.0
    allowed_scope_ids: frozenset[str] | None = None

    def __post_init__(self) -> None:
        # Accept list-like configuration at the control-plane seam, but freeze
        # it before a profile becomes selectable by a task caller.
        if isinstance(self.args, list):
            object.__setattr__(self, "args", tuple(self.args))
        if isinstance(self.allowed_scope_ids, (set, frozenset, list, tuple)):
            object.__setattr__(self, "allowed_scope_ids", frozenset(self.allowed_scope_ids))

    @property
    def argv(self) -> tuple[str, ...]:
        """Return the fixed argv tuple used for every task of this profile."""

        return (self.executable, *self.args)


class ProcessLike(Protocol):
    """Minimum process surface required by the injected launcher seam."""

    pid: int
    stdin: Any
    stdout: Any
    stderr: Any

    def poll(self) -> int | None:
        ...

    def wait(self, timeout: float | None = None) -> int:
        ...

    def terminate(self) -> None:
        ...

    def kill(self) -> None:
        ...


Launcher = Callable[..., ProcessLike]
Clock = Callable[[], float]
Timestamp = Callable[[], str]
Sleeper = Callable[[float], None]
GroupSignal = Callable[[int, int], None]
ScopeResolver = Callable[[str], Path | str]


def _launch_subprocess(argv: Sequence[str], **kwargs: Any) -> ProcessLike:
    """Launch one fixed argv through the direct subprocess adapter."""

    return subprocess.Popen(list(argv), **kwargs)


def _signal_process_group(process_group: int, signum: int) -> None:
    """Signal a process group without ever resolving a process by name."""

    os.killpg(process_group, signum)


def _utf8_prefix(data: bytes, limit: int) -> str:
    if limit <= 0:
        return ""
    return data[:limit].decode("utf-8", errors="ignore")


class _BoundedText:
    """A redacted UTF-8 prefix with a hard byte bound."""

    def __init__(self, max_bytes: int, marker: str) -> None:
        self.max_bytes = max_bytes
        self.marker = marker
        self._chunks: list[str] = []
        self._written = 0
        self.truncated = False
        self._lock = threading.RLock()

    def append(self, value: str) -> None:
        redacted = redact_text(value)
        if not redacted:
            return
        encoded = redacted.encode("utf-8", errors="replace")
        with self._lock:
            if self._written >= self.max_bytes:
                self.truncated = True
                return
            remaining = self.max_bytes - self._written
            if len(encoded) <= remaining:
                piece = redacted
            else:
                self.truncated = True
                marker_bytes = self.marker.encode("utf-8")
                if remaining > len(marker_bytes):
                    piece = _utf8_prefix(encoded, remaining - len(marker_bytes)) + self.marker
                else:
                    piece = _utf8_prefix(marker_bytes, remaining)
            if not piece:
                return
            self._chunks.append(piece)
            self._written += len(piece.encode("utf-8", errors="replace"))

    def snapshot(self) -> str:
        with self._lock:
            # Redact again after joining chunks.  This also catches a
            # credential-like value that happened to be split across reads.
            value = redact_text("".join(self._chunks))
            encoded = value.encode("utf-8", errors="replace")
            if len(encoded) > self.max_bytes:
                value = _utf8_prefix(encoded, self.max_bytes)
            return value


@dataclass(frozen=True, slots=True)
class _LogEntry:
    sequence: int
    stream: str
    text: str


class _BoundedEventLog:
    """A bounded, redacted, incrementally readable event log."""

    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max_bytes
        self._entries: list[_LogEntry] = []
        self._written = 0
        self._next_sequence = 1
        self.truncated = False
        self._lock = threading.RLock()

    def append(self, stream: str, value: str) -> None:
        redacted = redact_text(value)
        if not redacted:
            return
        # Entries are line-oriented for useful tail semantics.  Keep a
        # newline-free final fragment so callers can consume partial output.
        parts = redacted.splitlines()
        if not parts:
            parts = [redacted]
        with self._lock:
            for part in parts:
                if not part and len(parts) > 1:
                    continue
                self._append_part(stream, part)
                if self._written >= self.max_bytes:
                    break

    def _append_part(self, stream: str, value: str) -> None:
        if self._written >= self.max_bytes:
            self.truncated = True
            return
        encoded = value.encode("utf-8", errors="replace")
        remaining = self.max_bytes - self._written
        if len(encoded) <= remaining:
            text = value
        else:
            self.truncated = True
            marker = "[LOG_TRUNCATED]"
            marker_bytes = marker.encode("utf-8")
            if remaining > len(marker_bytes):
                text = _utf8_prefix(encoded, remaining - len(marker_bytes)) + marker
            else:
                text = _utf8_prefix(marker_bytes, remaining)
        if not text:
            return
        self._entries.append(_LogEntry(self._next_sequence, stream, redact_text(text)))
        self._next_sequence += 1
        self._written += len(text.encode("utf-8", errors="replace"))

    def entries(self) -> list[_LogEntry]:
        with self._lock:
            return list(self._entries)


class _OutputState:
    def __init__(self, max_output_bytes: int, max_log_bytes: int) -> None:
        self.stdout = _BoundedText(max_output_bytes, "\n[OUTPUT_TRUNCATED]\n")
        self.stderr = _BoundedText(max_output_bytes, "\n[OUTPUT_TRUNCATED]\n")
        self.events = _BoundedEventLog(max_log_bytes)
        self.capture_error = False

    def append(self, stream: str, data: bytes | str) -> None:
        value = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
        if stream == "stdout":
            self.stdout.append(value)
        else:
            self.stderr.append(value)
        self.events.append(stream, value)

    def snapshot(self) -> dict[str, Any]:
        return {
            "stdout": self.stdout.snapshot(),
            "stderr": self.stderr.snapshot(),
            "stdout_truncated": self.stdout.truncated,
            "stderr_truncated": self.stderr.truncated,
            "log_truncated": self.events.truncated,
            "logs_complete": not self.capture_error,
        }


@dataclass(slots=True)
class _TaskRecord:
    task_id: str
    profile: AgentProfile
    scope_id: str
    timeout_seconds: float
    created_at: str
    started_at: str
    deadline: float
    output: _OutputState
    state: TaskState = TaskState.STARTING
    updated_at: str = ""
    finished_at: str | None = None
    pid: int | None = None
    process_group: int | None = None
    exit_code: int | None = None
    error_code: str | None = None
    cancel_requested: bool = False
    timeout_triggered: bool = False
    process: ProcessLike | None = None
    reader_threads: list[threading.Thread] = field(default_factory=list)
    feed_thread: threading.Thread | None = None
    done: threading.Event = field(default_factory=threading.Event)


class AgentTaskManager:
    """Own a bounded set of explicitly configured local agent tasks.

    The manager is intentionally not a policy engine.  ``scope_root`` is
    accepted only as an already-approved root supplied by the Broker, and the
    optional ``scope_resolver`` is the preferred seam when Broker state is
    available.  The manager validates path shape and directory identity but
    does not create scope authorization.

    Args:
        profiles: Initial :class:`AgentProfile` values.  Mapping keys must
            match the profile names.
        launcher: Process adapter.  It receives the fixed argv and subprocess
            kwargs, including ``shell=False``.  Tests can inject a fake.
        scope_resolver: Optional Broker-owned ``scope_id -> root`` resolver.
            When present, its root is authoritative; a separately supplied
            ``scope_root`` must match it after canonicalization.
        max_active_tasks: Maximum number of starting/running/cancelling tasks.
            ``max_tasks`` is accepted as a compatibility alias.
        runtime_dir: Optional private directory used for HOME/TMPDIR.  If it
            is omitted those variables are absent rather than inherited.
    """

    def __init__(
        self,
        profiles: Mapping[str, AgentProfile] | Iterable[AgentProfile] | None = None,
        *,
        launcher: Launcher | None = None,
        scope_resolver: ScopeResolver | None = None,
        max_active_tasks: int = 4,
        max_tasks: int | None = None,
        max_recorded_tasks: int = MAX_RECORDED_TASKS,
        max_prompt_bytes: int = MAX_PROMPT_BYTES,
        max_output_bytes: int = 65_536,
        max_log_bytes: int = 65_536,
        max_log_response_bytes: int = MAX_LOG_RESPONSE_BYTES,
        max_timeout_seconds: float = MAX_TIMEOUT_SECONDS,
        cancel_grace_seconds: float = 1.0,
        poll_interval_seconds: float = 0.05,
        clock: Clock = time.monotonic,
        sleeper: Sleeper = time.sleep,
        timestamp: Timestamp = utc_now,
        signal_group: GroupSignal = _signal_process_group,
        runtime_dir: Path | str | None = None,
    ) -> None:
        if max_tasks is not None:
            max_active_tasks = max_tasks
        self.max_active_tasks = self._bounded_int(
            max_active_tasks, 1, MAX_ACTIVE_TASKS, "max_active_tasks", "TASK_LIMIT_INVALID"
        )
        self.max_recorded_tasks = self._bounded_int(
            max_recorded_tasks,
            self.max_active_tasks,
            MAX_RECORDED_TASKS,
            "max_recorded_tasks",
            "TASK_LIMIT_INVALID",
        )
        self.max_prompt_bytes = self._bounded_int(
            max_prompt_bytes, 1, MAX_PROMPT_BYTES, "max_prompt_bytes", "PROMPT_LIMIT_INVALID"
        )
        self.max_output_bytes = self._bounded_int(
            max_output_bytes, 1, MAX_OUTPUT_BYTES, "max_output_bytes", "OUTPUT_LIMIT_INVALID"
        )
        self.max_log_bytes = self._bounded_int(
            max_log_bytes, 1, MAX_LOG_BYTES, "max_log_bytes", "OUTPUT_LIMIT_INVALID"
        )
        self.max_log_response_bytes = self._bounded_int(
            max_log_response_bytes,
            1,
            min(MAX_LOG_RESPONSE_BYTES, self.max_log_bytes),
            "max_log_response_bytes",
            "OUTPUT_LIMIT_INVALID",
        )
        self.max_timeout_seconds = self._bounded_float(
            max_timeout_seconds,
            0.001,
            MAX_TIMEOUT_SECONDS,
            "max_timeout_seconds",
            "TIMEOUT_INVALID",
        )
        self.cancel_grace_seconds = self._bounded_float(
            cancel_grace_seconds,
            0.0,
            MAX_CANCEL_GRACE_SECONDS,
            "cancel_grace_seconds",
            "TIMEOUT_INVALID",
        )
        self.poll_interval_seconds = self._bounded_float(
            poll_interval_seconds,
            0.001,
            1.0,
            "poll_interval_seconds",
            "TIMEOUT_INVALID",
        )
        if not callable(clock) or not callable(sleeper) or not callable(timestamp):
            raise PolicyError("MANAGER_INVALID", "clock, sleeper, and timestamp must be callable")
        if not callable(signal_group):
            raise PolicyError("MANAGER_INVALID", "signal_group must be callable")

        self._launcher = launcher or _launch_subprocess
        self._uses_default_launcher = launcher is None
        if not callable(self._launcher):
            raise PolicyError("MANAGER_INVALID", "launcher must be callable")
        self._scope_resolver = scope_resolver
        if scope_resolver is not None and not callable(scope_resolver):
            raise PolicyError("MANAGER_INVALID", "scope_resolver must be callable")
        self._clock = clock
        self._sleeper = sleeper
        self._timestamp = timestamp
        self._signal_group = signal_group
        self._lock = threading.RLock()
        self._profiles: dict[str, AgentProfile] = {}
        self._tasks: dict[str, _TaskRecord] = {}
        self._runtime_env = self._prepare_runtime_dir(runtime_dir)

        if profiles is not None:
            values: Iterable[AgentProfile]
            if isinstance(profiles, Mapping):
                for name, profile in profiles.items():
                    if not isinstance(name, str) or not isinstance(profile, AgentProfile):
                        raise PolicyError(
                            "PROFILE_INVALID",
                            "initial profiles must map string names to AgentProfile values",
                        )
                    if name != profile.name:
                        raise PolicyError("PROFILE_INVALID", "profile mapping key must match profile.name")
                values = profiles.values()
            else:
                values = profiles
            for profile in values:
                self.register_profile(profile)

    @staticmethod
    def _bounded_int(value: Any, minimum: int, maximum: int, field_name: str, code: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise PolicyError(code, f"{field_name} must be an integer from {minimum} to {maximum}")
        return value

    @staticmethod
    def _bounded_float(value: Any, minimum: float, maximum: float, field_name: str, code: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise PolicyError(code, f"{field_name} must be a finite number")
        converted = float(value)
        if not math.isfinite(converted) or not minimum <= converted <= maximum:
            raise PolicyError(code, f"{field_name} must be from {minimum} to {maximum} seconds")
        return converted

    def register_profile(self, profile: AgentProfile) -> None:
        """Register one immutable profile; duplicate names fail closed."""

        self._validate_profile(profile)
        with self._lock:
            if profile.name in self._profiles:
                raise PolicyError("PROFILE_ALREADY_CONFIGURED", "profile name is already configured")
            self._profiles[profile.name] = profile

    configure_profile = register_profile

    def profile_names(self) -> list[str]:
        """Return configured names only; executable details are not exposed."""

        with self._lock:
            return sorted(self._profiles)

    def start_task(
        self,
        profile: str,
        *,
        scope_id: str,
        scope_root: Path | str | None = None,
        prompt: str,
        timeout_seconds: float | int | None = None,
        **unsupported: Any,
    ) -> dict[str, Any]:
        """Start one owned task using a registered profile.

        The only dynamic task inputs are the Broker-approved scope identity,
        its validated root, and a bounded prompt.  Passing executable, argv,
        environment, cwd, or any other unsupported task input is rejected with
        ``UNSUPPORTED_ARGUMENT``.
        """

        if unsupported:
            raise PolicyError(
                "UNSUPPORTED_ARGUMENT",
                "task start accepts only profile, scope_id, scope_root, prompt, and bounded timeout_seconds",
            )
        selected = self._get_profile(profile)
        self._validate_scope_id(scope_id)
        if selected.allowed_scope_ids is not None and scope_id not in selected.allowed_scope_ids:
            raise PolicyError("SCOPE_NOT_ALLOWED", "selected profile is not configured for this scope_id")
        root = self._resolve_scope_root(scope_id, scope_root)
        prompt_bytes = self._validate_prompt(prompt)
        timeout = self._resolve_timeout(selected, timeout_seconds)

        created_at = self._safe_timestamp()
        task_id = str(uuid.uuid4())
        record = _TaskRecord(
            task_id=task_id,
            profile=selected,
            scope_id=scope_id,
            timeout_seconds=timeout,
            created_at=created_at,
            started_at=created_at,
            updated_at=created_at,
            deadline=self._clock() + timeout,
            output=_OutputState(self.max_output_bytes, self.max_log_bytes),
        )
        with self._lock:
            if self._active_count_locked() >= self.max_active_tasks:
                raise PolicyError(
                    "TASK_LIMIT_REACHED",
                    "maximum active agent task count reached; wait for a terminal task before retrying",
                )
            self._tasks[task_id] = record
            self._trim_terminal_records_locked()

        argv = list(selected.argv)
        environment = self._environment()
        try:
            process = self._launcher(
                argv,
                cwd=root,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
                close_fds=True,
                text=False,
            )
        except Exception as exc:
            self._finish_start_failure(record, "PROCESS_START_FAILED")
            raise PolicyError(
                "PROCESS_START_FAILED",
                "configured agent profile could not be started; verify the fixed executable is available",
            ) from exc

        if process is None:
            self._finish_start_failure(record, "PROCESS_START_FAILED")
            raise PolicyError("PROCESS_START_FAILED", "configured agent launcher returned no process")

        with self._lock:
            record.process = process
            record.pid, record.process_group = self._process_identity(process)
            record.state = TaskState.RUNNING
            record.updated_at = self._safe_timestamp()
            record.deadline = self._clock() + timeout

        try:
            self._start_workers(record, prompt_bytes)
        except Exception as exc:
            self._mark_failure(record, "PROCESS_START_FAILED")
            if record.process is not None:
                self._signal_owned_process(record, signal.SIGTERM)
                exit_code = self._wait_after_signal(record)
                self._join_output_threads(record)
                self._finalize(record, exit_code, "failed")
            raise PolicyError(
                "PROCESS_START_FAILED",
                "agent task workers could not be initialized; the owned process is being stopped",
            ) from exc
        self._reconcile(record)
        return self._snapshot(record)

    # A short alias keeps the seam convenient for a later Broker adapter.
    start = start_task
    run = start_task
    agent_run = start_task

    def status(self, task_id: str | None = None) -> dict[str, Any] | list[dict[str, Any]]:
        """Return one JSON-safe task status or all retained task statuses."""

        if task_id is None:
            with self._lock:
                records = list(self._tasks.values())
            for record in records:
                self._reconcile(record)
            return [self._snapshot(record) for record in records]
        record = self._get_task(task_id)
        self._reconcile(record)
        return self._snapshot(record)

    get_status = status

    def logs(
        self,
        task_id: str,
        *,
        tail_lines: int = 100,
        since_sequence: int | None = None,
        stream: str = "combined",
    ) -> dict[str, Any]:
        """Return bounded redacted log entries, optionally after a sequence.

        ``stream`` may be ``combined``, ``stdout``, or ``stderr``.  With no
        ``since_sequence`` the newest ``tail_lines`` entries are returned.  A
        sequence request returns the oldest available entries after that
        sequence so a caller can advance using ``next_sequence``.
        """

        record = self._get_task(task_id)
        self._reconcile(record)
        tail_lines = self._validate_tail_lines(tail_lines)
        if stream not in {"combined", "stdout", "stderr"}:
            raise PolicyError("INVALID_INPUT", "stream must be combined, stdout, or stderr")
        if since_sequence is not None and (
            isinstance(since_sequence, bool)
            or not isinstance(since_sequence, int)
            or since_sequence < 0
        ):
            raise PolicyError("INVALID_INPUT", "since_sequence must be a non-negative integer")

        entries = [
            entry
            for entry in record.output.events.entries()
            if (stream == "combined" or entry.stream == stream)
            and (since_sequence is None or entry.sequence > since_sequence)
        ]
        has_more = record.output.events.truncated
        if since_sequence is None:
            if len(entries) > tail_lines:
                has_more = True
                entries = entries[-tail_lines:]
        elif len(entries) > tail_lines:
            has_more = True
            entries = entries[:tail_lines]

        response_entries: list[dict[str, Any]] = []
        used_bytes = 0
        response_truncated = False
        for entry in entries:
            text = redact_text(entry.text)
            encoded = text.encode("utf-8", errors="replace")
            encoded_size = len(encoded)
            remaining = self.max_log_response_bytes - used_bytes
            if remaining <= 0:
                has_more = True
                break
            if encoded_size > remaining:
                text = _utf8_prefix(encoded, remaining)
                response_truncated = True
                has_more = True
            response_entry = {"sequence": entry.sequence, "stream": entry.stream, "text": text}
            if encoded_size > remaining:
                response_entry["response_truncated"] = True
            response_entries.append(response_entry)
            used_bytes += len(text.encode("utf-8", errors="replace"))
            if response_truncated:
                break
        next_sequence = response_entries[-1]["sequence"] if response_entries else since_sequence
        output = record.output.snapshot()
        return {
            "status": "ok",
            "task_id": task_id,
            "state": record.state.value,
            "entries": response_entries,
            "tail_lines": tail_lines,
            "stream": stream,
            "since_sequence": since_sequence,
            "next_sequence": next_sequence,
            "has_more": has_more,
            "truncated": output["log_truncated"] or response_truncated,
            "response_truncated": response_truncated,
            "stdout": output["stdout"],
            "stderr": output["stderr"],
            "stdout_truncated": output["stdout_truncated"],
            "stderr_truncated": output["stderr_truncated"],
            "logs_complete": output["logs_complete"],
        }

    tail_logs = logs
    get_logs = logs
    list_tasks = status

    def cancel(self, task_id: str) -> dict[str, Any]:
        """Cancel only a currently owned task, idempotently for terminal tasks."""

        record = self._get_task(task_id)
        self._reconcile(record)
        already_exited = False
        with self._lock:
            if record.state.value in _TERMINAL_STATES:
                return self._snapshot(record)
            process = record.process
            if process is None:
                self._finish_start_failure(record, "PROCESS_CANCEL_FAILED")
                return self._snapshot(record)
            try:
                already_exited = process.poll() is not None
            except Exception:
                already_exited = False
            if already_exited:
                # Do not relabel a process that had already exited before the
                # cancel request.  The watcher/reconciler owns the normal exit.
                pass
            else:
                record.cancel_requested = True
                record.state = TaskState.CANCELLING
                record.updated_at = self._safe_timestamp()

        if already_exited:
            self._reconcile(record)
            return self._snapshot(record)

        self._signal_owned_process(record, signal.SIGTERM)
        wait_budget = self.cancel_grace_seconds + 0.5
        record.done.wait(wait_budget)
        if not record.done.is_set():
            self._signal_owned_process(record, signal.SIGKILL)
            record.done.wait(wait_budget)
        self._reconcile(record)
        return self._snapshot(record)

    cancel_task = cancel

    def result(self, task_id: str) -> dict[str, Any]:
        """Return bounded output for a terminal task; never return prompt/env."""

        record = self._get_task(task_id)
        self._reconcile(record)
        with self._lock:
            if record.state.value not in _TERMINAL_STATES:
                raise PolicyError(
                    "RESULT_NOT_READY",
                    "task is still running; call status or logs and retry result after a terminal state",
                )
        result = self._snapshot(record)
        result["result_available"] = True
        return result

    get_result = result

    def _validate_profile(self, profile: AgentProfile) -> None:
        if not isinstance(profile, AgentProfile):
            raise PolicyError("PROFILE_INVALID", "profile must be an AgentProfile")
        if (
            not isinstance(profile.name, str)
            or not profile.name
            or len(profile.name.encode("utf-8", errors="ignore")) > MAX_PROFILE_NAME_BYTES
            or _PROFILE_NAME.fullmatch(profile.name) is None
        ):
            raise PolicyError(
                "PROFILE_INVALID",
                "profile name must match [A-Za-z0-9][A-Za-z0-9_.:-]{0,63}",
            )
        if (
            not isinstance(profile.executable, str)
            or not profile.executable
            or "\x00" in profile.executable
            or profile.executable.startswith("-")
        ):
            raise PolicyError("PROFILE_INVALID", "profile executable must be a non-empty fixed path or name")
        executable_path = Path(profile.executable)
        if not executable_path.is_absolute():
            if executable_path.name != profile.executable or "/" in profile.executable or "\\" in profile.executable:
                raise PolicyError(
                    "PROFILE_INVALID",
                    "relative profile executables must be one bare name resolved through the scrubbed PATH",
                )
        elif ".." in executable_path.parts:
            raise PolicyError("PROFILE_INVALID", "profile executable path cannot contain parent traversal")

        if not isinstance(profile.args, tuple) or len(profile.args) > MAX_PROFILE_ARGS:
            raise PolicyError("PROFILE_INVALID", "profile args must be a fixed tuple of at most 64 strings")
        for argument in profile.args:
            if (
                not isinstance(argument, str)
                or "\x00" in argument
                or len(argument.encode("utf-8", errors="ignore")) > MAX_PROFILE_ARG_BYTES
            ):
                raise PolicyError("PROFILE_INVALID", "profile arguments must be bounded strings without null bytes")
        self._bounded_float(
            profile.timeout_seconds,
            0.001,
            self.max_timeout_seconds,
            "profile.timeout_seconds",
            "PROFILE_INVALID",
        )
        if profile.allowed_scope_ids is not None:
            if not isinstance(profile.allowed_scope_ids, frozenset):
                raise PolicyError("PROFILE_INVALID", "allowed_scope_ids must be a fixed set of scope IDs")
            for scope_id in profile.allowed_scope_ids:
                self._validate_scope_id(scope_id)

    def _get_profile(self, profile_name: str) -> AgentProfile:
        if not isinstance(profile_name, str):
            raise PolicyError("PROFILE_NOT_ALLOWED", "profile must be the name of a configured profile")
        with self._lock:
            profile = self._profiles.get(profile_name)
        if profile is None:
            raise PolicyError("PROFILE_NOT_ALLOWED", "profile name is not configured")
        return profile

    @staticmethod
    def _validate_scope_id(scope_id: str) -> None:
        if (
            not isinstance(scope_id, str)
            or not scope_id
            or len(scope_id.encode("utf-8", errors="ignore")) > MAX_SCOPE_ID_BYTES
            or _SCOPE_ID.fullmatch(scope_id) is None
        ):
            raise PolicyError(
                "SCOPE_ID_INVALID",
                "scope_id must match [A-Za-z0-9][A-Za-z0-9_.:-]{0,127}",
            )

    def _resolve_scope_root(self, scope_id: str, supplied_root: Path | str | None) -> Path:
        selected_root: Path | str | None = supplied_root
        if self._scope_resolver is not None:
            try:
                resolved_by_broker = self._scope_resolver(scope_id)
            except PolicyError:
                raise
            except Exception as exc:
                raise PolicyError(
                    "SCOPE_NOT_ALLOWED",
                    "approved scope resolver rejected or could not resolve scope_id",
                ) from exc
            if resolved_by_broker is None:
                raise PolicyError("SCOPE_NOT_ALLOWED", "scope_id has no approved root")
            broker_root = self._canonical_root(resolved_by_broker)
            if supplied_root is not None:
                supplied_canonical = self._canonical_root(supplied_root)
                if supplied_canonical != broker_root:
                    raise PolicyError("SCOPE_ROOT_MISMATCH", "scope_root does not match the approved scope root")
            selected_root = broker_root
        if selected_root is None:
            raise PolicyError(
                "SCOPE_ROOT_REQUIRED",
                "provide the already-approved scope_root or inject a Broker-owned scope_resolver",
            )
        return self._canonical_root(selected_root)

    @staticmethod
    def _canonical_root(value: Path | str) -> Path:
        try:
            path = Path(value)
        except (TypeError, ValueError) as exc:
            raise PolicyError("SCOPE_ROOT_INVALID", "scope_root must be an absolute directory path") from exc
        if not path.is_absolute():
            raise PolicyError("SCOPE_ROOT_INVALID", "scope_root must be absolute; Broker must provide a validated root")
        try:
            if path.is_symlink():
                raise PolicyError("SCOPE_ROOT_INVALID", "scope_root itself cannot be a symlink")
            resolved = path.resolve(strict=True)
        except PolicyError:
            raise
        except (OSError, RuntimeError) as exc:
            raise PolicyError("SCOPE_ROOT_INVALID", "scope_root could not be resolved as a local directory") from exc
        if not resolved.is_dir():
            raise PolicyError("SCOPE_ROOT_INVALID", "scope_root must identify an existing directory")
        return resolved

    def _validate_prompt(self, prompt: str) -> bytes:
        if not isinstance(prompt, str) or not prompt.strip() or "\x00" in prompt:
            raise PolicyError("PROMPT_INVALID", "prompt must be non-empty text without null bytes")
        try:
            encoded = prompt.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise PolicyError("PROMPT_INVALID", "prompt must be valid UTF-8 text") from exc
        if len(encoded) > self.max_prompt_bytes:
            raise PolicyError(
                "PROMPT_TOO_LARGE",
                f"prompt exceeds the configured {self.max_prompt_bytes} byte limit",
            )
        return encoded

    def _resolve_timeout(self, profile: AgentProfile, requested: float | int | None) -> float:
        configured = self._bounded_float(
            profile.timeout_seconds,
            0.001,
            self.max_timeout_seconds,
            "profile.timeout_seconds",
            "PROFILE_INVALID",
        )
        if requested is None:
            return configured
        requested_value = self._bounded_float(
            requested,
            0.001,
            self.max_timeout_seconds,
            "timeout_seconds",
            "TIMEOUT_INVALID",
        )
        if requested_value > configured:
            raise PolicyError(
                "TIMEOUT_INVALID",
                "requested timeout cannot exceed the selected profile timeout",
            )
        return requested_value

    @staticmethod
    def _validate_tail_lines(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_TAIL_LINES:
            raise PolicyError("INVALID_INPUT", f"tail_lines must be an integer from 1 to {MAX_TAIL_LINES}")
        return value

    def _environment(self) -> dict[str, str]:
        # Never copy os.environ.  In particular, PATH, HOME, tokens, proxy
        # variables, cloud credentials, and Python injection variables are not
        # inherited from the Control Center process.
        environment = {
            "PATH": os.pathsep.join(str(path) for path in _SAFE_BIN_DIRS),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "CI": "1",
            "NO_COLOR": "1",
            "PAGER": "cat",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        environment.update(self._runtime_env)
        return environment

    def _prepare_runtime_dir(self, runtime_dir: Path | str | None) -> dict[str, str]:
        if runtime_dir is None:
            return {}
        root = self._canonical_config_dir(runtime_dir)
        home = root / "home"
        temporary = root / "tmp"
        for directory in (home, temporary):
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
        return {"HOME": str(home), "TMPDIR": str(temporary)}

    @staticmethod
    def _canonical_config_dir(value: Path | str) -> Path:
        try:
            path = Path(value)
        except (TypeError, ValueError) as exc:
            raise PolicyError("MANAGER_INVALID", "runtime_dir must be an absolute directory path") from exc
        if not path.is_absolute() or path.is_symlink():
            raise PolicyError("MANAGER_INVALID", "runtime_dir must be an absolute non-symlink path")
        try:
            path.mkdir(parents=True, exist_ok=True)
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise PolicyError("MANAGER_INVALID", "runtime_dir could not be prepared") from exc
        if not resolved.is_dir():
            raise PolicyError("MANAGER_INVALID", "runtime_dir must be a directory")
        os.chmod(resolved, 0o700)
        return resolved

    def _active_count_locked(self) -> int:
        return sum(record.state.value not in _TERMINAL_STATES for record in self._tasks.values())

    def _trim_terminal_records_locked(self) -> None:
        if len(self._tasks) < self.max_recorded_tasks:
            return
        for task_id, record in list(self._tasks.items()):
            if record.state.value in _TERMINAL_STATES:
                self._tasks.pop(task_id, None)
                if len(self._tasks) < self.max_recorded_tasks:
                    return

    def _get_task(self, task_id: str) -> _TaskRecord:
        if not isinstance(task_id, str) or not task_id or len(task_id.encode("utf-8", errors="ignore")) > MAX_TASK_ID_BYTES:
            raise PolicyError("TASK_ID_INVALID", "task_id must be a non-empty bounded string")
        with self._lock:
            record = self._tasks.get(task_id)
        if record is None:
            raise PolicyError("TASK_NOT_FOUND", "task_id is not owned by this manager")
        return record

    def _process_identity(self, process: ProcessLike) -> tuple[int | None, int | None]:
        pid: int | None = None
        try:
            candidate = getattr(process, "pid", None)
            if isinstance(candidate, int) and not isinstance(candidate, bool) and candidate > 0:
                pid = candidate
        except Exception:
            pid = None
        process_group: int | None = None
        for attribute in ("process_group", "pgid"):
            try:
                candidate = getattr(process, attribute, None)
            except Exception:
                candidate = None
            if isinstance(candidate, int) and not isinstance(candidate, bool) and candidate > 0:
                process_group = candidate
                break
        if process_group is None and pid is not None and self._uses_default_launcher and hasattr(os, "getpgid"):
            try:
                process_group = int(os.getpgid(pid))
            except OSError:
                process_group = None
        return pid, process_group

    def _start_workers(self, record: _TaskRecord, prompt: bytes) -> None:
        process = record.process
        if process is None:
            raise RuntimeError("missing process")
        threads: list[threading.Thread] = []
        for stream_name in ("stdout", "stderr"):
            stream = getattr(process, stream_name, None)
            if stream is None:
                continue
            thread = threading.Thread(
                target=self._capture_stream,
                args=(record, stream_name, stream),
                name=f"agent-task-{record.task_id[:8]}-{stream_name}",
                daemon=True,
            )
            threads.append(thread)
        record.reader_threads = threads
        record.feed_thread = threading.Thread(
            target=self._feed_prompt,
            args=(record, prompt),
            name=f"agent-task-{record.task_id[:8]}-stdin",
            daemon=True,
        )
        for thread in threads:
            thread.start()
        record.feed_thread.start()
        watcher = threading.Thread(
            target=self._watch_task,
            args=(record,),
            name=f"agent-task-{record.task_id[:8]}-watch",
            daemon=True,
        )
        watcher.start()

    def _capture_stream(self, record: _TaskRecord, stream_name: str, stream: Any) -> None:
        try:
            while True:
                chunk = stream.read(4_096)
                if not chunk:
                    break
                record.output.append(stream_name, chunk)
        except Exception:
            record.output.capture_error = True

    def _feed_prompt(self, record: _TaskRecord, prompt: bytes) -> None:
        process = record.process
        stream = getattr(process, "stdin", None) if process is not None else None
        if stream is None:
            self._mark_failure(record, "PROMPT_DELIVERY_FAILED")
            return
        try:
            stream.write(prompt)
            stream.flush()
            stream.close()
        except Exception:
            # A process that exits before consuming stdin is a failed prompt
            # delivery only if it was still alive when the write failed.
            try:
                alive = process is not None and process.poll() is None
            except Exception:
                alive = True
            if alive:
                self._mark_failure(record, "PROMPT_DELIVERY_FAILED")

    def _watch_task(self, record: _TaskRecord) -> None:
        process = record.process
        if process is None:
            self._finish_start_failure(record, "PROCESS_STATUS_FAILED")
            return
        reason: str | None = None
        exit_code: int | None = None
        try:
            while True:
                try:
                    exit_code = process.poll()
                except Exception:
                    self._mark_failure(record, "PROCESS_STATUS_FAILED")
                    reason = "failed"
                    break
                if exit_code is not None:
                    with self._lock:
                        if record.error_code is not None:
                            reason = "failed"
                        elif record.cancel_requested:
                            reason = "cancelled"
                        elif record.timeout_triggered:
                            reason = "timed_out"
                    break

                with self._lock:
                    if record.error_code is not None:
                        reason = "failed"
                    elif record.cancel_requested:
                        reason = "cancelled"
                if reason is not None:
                    self._signal_owned_process(record, signal.SIGTERM)
                    exit_code = self._wait_after_signal(record)
                    break

                if self._clock() >= record.deadline:
                    with self._lock:
                        if record.state.value in _TERMINAL_STATES:
                            return
                        record.timeout_triggered = True
                        record.updated_at = self._safe_timestamp()
                    reason = "timed_out"
                    self._signal_owned_process(record, signal.SIGTERM)
                    exit_code = self._wait_after_signal(record)
                    break
                self._sleeper(min(self.poll_interval_seconds, max(0.001, record.deadline - self._clock())))
        except Exception:
            self._mark_failure(record, "PROCESS_STATUS_FAILED")
            reason = "failed"
            try:
                exit_code = process.poll()
            except Exception:
                exit_code = None

        self._join_output_threads(record)
        self._finalize(record, exit_code, reason)

    def _wait_after_signal(self, record: _TaskRecord) -> int | None:
        process = record.process
        if process is None:
            return None
        try:
            return process.wait(timeout=self.cancel_grace_seconds)
        except subprocess.TimeoutExpired:
            self._signal_owned_process(record, signal.SIGKILL)
            try:
                return process.wait(timeout=self.cancel_grace_seconds)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    exit_code = process.poll()
                except Exception:
                    exit_code = None
                if exit_code is None:
                    self._set_error_code(record, "PROCESS_CANCEL_FAILED")
                return exit_code
        except OSError:
            try:
                exit_code = process.poll()
            except Exception:
                exit_code = None
            if exit_code is None:
                self._set_error_code(record, "PROCESS_WAIT_FAILED")
            return exit_code
        except Exception:
            self._set_error_code(record, "PROCESS_WAIT_FAILED")
            try:
                return process.poll()
            except Exception:
                return None

    def _join_output_threads(self, record: _TaskRecord) -> None:
        current = threading.current_thread()
        for thread in [*record.reader_threads, record.feed_thread]:
            if thread is not None and thread is not current:
                thread.join(timeout=0.5)

    def _signal_owned_process(self, record: _TaskRecord, signum: int) -> bool:
        # The process object is looked up only through the owned task record;
        # callers never supply a PID or process name.  A group signal is used
        # when the launch seam supplied an owned group, with process methods as
        # a safe fallback for fakes/platforms without process groups.
        process = record.process
        if process is None:
            return False
        signalled = False
        if record.process_group is not None:
            try:
                self._signal_group(record.process_group, signum)
                signalled = True
            except Exception:
                pass
        if signalled:
            return True
        try:
            if signum == signal.SIGTERM:
                process.terminate()
            else:
                process.kill()
            return True
        except Exception:
            # The watcher will reconcile an already-exited process.  A failed
            # signal must not turn into a signal against an unrelated PID.
            return False

    def _set_error_code(self, record: _TaskRecord, code: str) -> None:
        with self._lock:
            if record.state.value not in _TERMINAL_STATES:
                record.error_code = record.error_code or code

    def _mark_failure(self, record: _TaskRecord, code: str) -> None:
        should_signal = False
        with self._lock:
            if record.state.value in _TERMINAL_STATES:
                return
            record.error_code = code
            if record.process is None:
                record.state = TaskState.FAILED
                record.finished_at = self._safe_timestamp()
                record.updated_at = record.finished_at
                record.done.set()
            else:
                record.cancel_requested = True
                record.state = TaskState.CANCELLING
                record.updated_at = self._safe_timestamp()
                should_signal = True
        if should_signal:
            self._signal_owned_process(record, signal.SIGTERM)

    def _finish_start_failure(self, record: _TaskRecord, code: str) -> None:
        with self._lock:
            if record.state.value in _TERMINAL_STATES:
                return
            record.error_code = code
            record.state = TaskState.FAILED
            record.finished_at = self._safe_timestamp()
            record.updated_at = record.finished_at
            record.done.set()

    def _finalize(self, record: _TaskRecord, exit_code: int | None, reason: str | None) -> None:
        with self._lock:
            if record.state.value in _TERMINAL_STATES:
                record.done.set()
                return
            if exit_code is not None and not isinstance(exit_code, int):
                exit_code = None
                record.error_code = record.error_code or "PROCESS_STATUS_FAILED"
            record.exit_code = exit_code
            if record.error_code is not None or reason == "failed":
                record.state = TaskState.FAILED
            elif reason == "timed_out" or record.timeout_triggered:
                record.state = TaskState.TIMED_OUT
                record.error_code = "TASK_TIMED_OUT"
            elif reason == "cancelled" or record.cancel_requested:
                record.state = TaskState.CANCELLED
                record.error_code = "TASK_CANCELLED"
            elif exit_code == 0:
                record.state = TaskState.COMPLETED
            else:
                record.state = TaskState.FAILED
                record.error_code = "PROCESS_EXIT_NONZERO"
            record.finished_at = self._safe_timestamp()
            record.updated_at = record.finished_at
            record.done.set()

    def _reconcile(self, record: _TaskRecord) -> None:
        with self._lock:
            if record.state.value in _TERMINAL_STATES or record.process is None:
                return
            process = record.process
        try:
            exit_code = process.poll()
        except Exception:
            self._mark_failure(record, "PROCESS_STATUS_FAILED")
            return
        if exit_code is None:
            return
        with self._lock:
            if record.error_code is not None:
                reason = "failed"
            elif record.cancel_requested:
                reason = "cancelled"
            elif record.timeout_triggered:
                reason = "timed_out"
            else:
                reason = None
        self._join_output_threads(record)
        self._finalize(record, exit_code, reason)

    def _snapshot(self, record: _TaskRecord) -> dict[str, Any]:
        output = record.output.snapshot()
        with self._lock:
            state = record.state.value
            terminal = state in _TERMINAL_STATES
            return {
                "status": "ok",
                "task_id": record.task_id,
                "profile": record.profile.name,
                "scope_id": record.scope_id,
                "pid": record.pid,
                "process_group": record.process_group,
                "created_at": record.created_at,
                "started_at": record.started_at,
                "updated_at": record.updated_at,
                "finished_at": record.finished_at,
                "state": state,
                "timeout_seconds": record.timeout_seconds,
                "timeout": record.timeout_seconds,
                "exit_code": record.exit_code,
                "error_code": record.error_code,
                "cancel_requested": record.cancel_requested,
                "timed_out": state == TaskState.TIMED_OUT.value,
                "cancelled": state == TaskState.CANCELLED.value,
                "result_available": terminal,
                "stdout": output["stdout"],
                "stderr": output["stderr"],
                "stdout_truncated": output["stdout_truncated"],
                "stderr_truncated": output["stderr_truncated"],
                "log_truncated": output["log_truncated"],
                "logs_complete": output["logs_complete"],
            }

    def _safe_timestamp(self) -> str:
        try:
            value = self._timestamp()
        except Exception:
            return utc_now()
        return value if isinstance(value, str) else str(value)


__all__ = [
    "AgentProfile",
    "AgentTaskManager",
    "MAX_LOG_BYTES",
    "MAX_LOG_RESPONSE_BYTES",
    "MAX_OUTPUT_BYTES",
    "MAX_PROMPT_BYTES",
    "MAX_TIMEOUT_SECONDS",
    "TaskState",
]
