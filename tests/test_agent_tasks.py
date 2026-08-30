from __future__ import annotations

import json
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from local_mcp_control_center.agent_tasks import AgentProfile, AgentTaskManager
from local_mcp_control_center.errors import PolicyError


class RecordingInput:
    def __init__(self) -> None:
        self.data = bytearray()
        self.closed = False

    def write(self, value: bytes) -> int:
        self.data.extend(value)
        return len(value)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class FixedOutput:
    def __init__(self, value: bytes) -> None:
        self.value = value
        self.reads = 0

    def read(self, _size: int) -> bytes:
        if self.reads:
            return b""
        self.reads += 1
        return self.value


class FakeProcess:
    _next_pid = 10_000

    def __init__(
        self,
        *,
        returncode: int | None = 0,
        stdout: bytes = b"",
        stderr: bytes = b"",
        ignore_terminate: bool = False,
    ) -> None:
        self.pid = FakeProcess._next_pid
        FakeProcess._next_pid += 1
        self.process_group = self.pid + 1_000
        self.stdin = RecordingInput()
        self.stdout = FixedOutput(stdout)
        self.stderr = FixedOutput(stderr)
        self._returncode = returncode
        self.ignore_terminate = ignore_terminate
        self.terminated = 0
        self.killed = 0
        self._done = threading.Event()
        if returncode is not None:
            self._done.set()

    def poll(self) -> int | None:
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        if self._returncode is None:
            if not self._done.wait(timeout):
                raise subprocess.TimeoutExpired(["fake-agent"], timeout)
        assert self._returncode is not None
        return self._returncode

    def terminate(self) -> None:
        self.terminated += 1
        if not self.ignore_terminate:
            self.release(-signal.SIGTERM)

    def kill(self) -> None:
        self.killed += 1
        self.release(-signal.SIGKILL)

    def release(self, returncode: int = 0) -> None:
        self._returncode = returncode
        self._done.set()


def wait_for_terminal(manager: AgentTaskManager, task_id: str) -> dict[str, object]:
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        status = manager.status(task_id)
        assert isinstance(status, dict)
        if status["state"] in {"completed", "failed", "timed_out", "cancelled"}:
            return status
        time.sleep(0.005)
    raise AssertionError(f"task did not reach a terminal state: {manager.status(task_id)}")


def make_manager(
    root: Path,
    process: FakeProcess,
    *,
    profile: AgentProfile | None = None,
    **kwargs: object,
) -> tuple[AgentTaskManager, list[dict[str, object]], FakeProcess]:
    calls: list[dict[str, object]] = []

    def launcher(argv: list[str], **launch_kwargs: object) -> FakeProcess:
        calls.append({"argv": argv, **launch_kwargs})
        return process

    selected = profile or AgentProfile("safe", "fixed-agent", ("--fixed",), timeout_seconds=1)
    manager = AgentTaskManager(
        {selected.name: selected},
        launcher=launcher,
        **kwargs,
    )
    return manager, calls, process


def test_only_configured_profiles_and_fixed_argv_shell_boundary(tmp_path: Path) -> None:
    process = FakeProcess(stdout=b"ok\n")
    manager, calls, _ = make_manager(tmp_path, process)

    with pytest.raises(PolicyError) as error:
        manager.start_task(
            "not-configured",
            scope_id="scope-a",
            scope_root=tmp_path,
            prompt="hello",
        )
    assert error.value.code == "PROFILE_NOT_ALLOWED"
    assert calls == []

    status = manager.start_task(
        "safe",
        scope_id="scope-a",
        scope_root=tmp_path,
        prompt="hello; $(touch should-not-run)",
    )
    assert status["profile"] == "safe"
    assert calls[0]["argv"] == ["fixed-agent", "--fixed"]
    assert calls[0]["shell"] is False
    assert calls[0]["stdin"] is subprocess.PIPE
    assert calls[0]["cwd"] == tmp_path.resolve()
    environment = calls[0]["env"]
    assert isinstance(environment, dict)
    assert "SECRET_VALUE" not in environment
    assert "AWS_ACCESS_KEY_ID" not in environment
    assert "HOME" not in environment
    assert "PYTHONPATH" not in environment
    assert set(environment) <= {
        "PATH",
        "LANG",
        "LC_ALL",
        "CI",
        "NO_COLOR",
        "PAGER",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_TERMINAL_PROMPT",
        "PYTHONNOUSERSITE",
        "PYTHONDONTWRITEBYTECODE",
    }


def test_prompt_is_bounded_and_delivered_only_on_stdin(tmp_path: Path) -> None:
    prompt = "literal; $(echo no-shell); && newline\nsecond"
    process = FakeProcess()
    manager, calls, process = make_manager(tmp_path, process)

    task = manager.start_task(
        "safe",
        scope_id="scope-a",
        scope_root=tmp_path,
        prompt=prompt,
    )
    terminal = wait_for_terminal(manager, str(task["task_id"]))

    assert terminal["state"] == "completed"
    assert bytes(process.stdin.data) == prompt.encode("utf-8")
    assert process.stdin.closed is True
    assert calls[0]["argv"] == ["fixed-agent", "--fixed"]


def test_cancel_is_limited_to_owned_task_and_process_group(tmp_path: Path) -> None:
    process = FakeProcess(returncode=None)
    signals: list[tuple[int, int]] = []

    def group_signal(process_group: int, signum: int) -> None:
        signals.append((process_group, signum))
        if signum == signal.SIGTERM:
            process.release(-signal.SIGTERM)

    manager, _, _ = make_manager(
        tmp_path,
        process,
        signal_group=group_signal,
        cancel_grace_seconds=0.05,
        poll_interval_seconds=0.005,
    )
    task = manager.start_task(
        "safe",
        scope_id="scope-a",
        scope_root=tmp_path,
        prompt="cancel me",
    )
    task_id = str(task["task_id"])
    assert wait_for_running(manager, task_id)["state"] in {"running", "cancelling"}

    cancelled = manager.cancel(task_id)
    assert cancelled["state"] == "cancelled"
    assert signals == [(process.process_group, signal.SIGTERM)]
    assert process.killed == 0

    other_manager = AgentTaskManager()
    with pytest.raises(PolicyError) as error:
        other_manager.cancel(task_id)
    assert error.value.code == "TASK_NOT_FOUND"


def wait_for_running(manager: AgentTaskManager, task_id: str) -> dict[str, object]:
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        status = manager.status(task_id)
        assert isinstance(status, dict)
        if status["state"] in {"running", "cancelling"}:
            return status
        time.sleep(0.005)
    raise AssertionError(f"task did not start: {manager.status(task_id)}")


def test_timeout_race_is_terminal_and_uses_owned_group_only(tmp_path: Path) -> None:
    process = FakeProcess(returncode=None, ignore_terminate=True)
    signals: list[tuple[int, int]] = []

    def group_signal(process_group: int, signum: int) -> None:
        signals.append((process_group, signum))
        if signum == signal.SIGKILL:
            process.release(-signal.SIGKILL)

    profile = AgentProfile("slow", "fixed-agent", timeout_seconds=0.02)
    manager, _, _ = make_manager(
        tmp_path,
        process,
        profile=profile,
        signal_group=group_signal,
        cancel_grace_seconds=0.01,
        poll_interval_seconds=0.002,
    )
    task = manager.start_task(
        "slow",
        scope_id="scope-a",
        scope_root=tmp_path,
        prompt="wait",
    )
    terminal = wait_for_terminal(manager, str(task["task_id"]))

    assert terminal["state"] == "timed_out"
    assert terminal["timed_out"] is True
    assert [signum for _, signum in signals] == [signal.SIGTERM, signal.SIGKILL]


def test_logs_are_redacted_bounded_and_incremental(tmp_path: Path) -> None:
    process = FakeProcess(
        stdout=b"API_KEY=top-secret-value\n" + b"x" * 300 + b"\n",
        stderr=b"Bearer abcdefghijklmnop-secret\n",
    )
    manager, _, _ = make_manager(
        tmp_path,
        process,
        max_output_bytes=64,
        max_log_bytes=96,
        max_log_response_bytes=64,
    )
    task = manager.start_task(
        "safe",
        scope_id="scope-a",
        scope_root=tmp_path,
        prompt="capture",
    )
    task_id = str(task["task_id"])
    terminal = wait_for_terminal(manager, task_id)
    logs = manager.logs(task_id, tail_lines=20)

    assert terminal["stdout_truncated"] is True
    assert terminal["stderr"] == "[REDACTED]\n"
    assert "top-secret-value" not in str(terminal)
    assert "abcdefghijklmnop-secret" not in str(logs)
    assert len(str(terminal["stdout"]).encode("utf-8")) <= 64
    assert len(str(terminal["stderr"]).encode("utf-8")) <= 64
    assert logs["truncated"] is True
    assert logs["next_sequence"] is not None

    next_logs = manager.logs(task_id, since_sequence=int(logs["next_sequence"]))
    assert next_logs["next_sequence"] is not None
    final_logs = manager.logs(task_id, since_sequence=int(next_logs["next_sequence"]))
    assert final_logs["entries"] == []


def test_status_and_result_have_deterministic_terminal_transition(tmp_path: Path) -> None:
    process = FakeProcess(returncode=None)
    manager, _, _ = make_manager(tmp_path, process)
    task = manager.start_task(
        "safe",
        scope_id="scope-a",
        scope_root=tmp_path,
        prompt="pending",
    )
    task_id = str(task["task_id"])
    with pytest.raises(PolicyError) as error:
        manager.result(task_id)
    assert error.value.code == "RESULT_NOT_READY"

    process.release(0)
    terminal = wait_for_terminal(manager, task_id)
    assert terminal["state"] == "completed"
    result = manager.result(task_id)
    assert result["result_available"] is True
    assert result["exit_code"] == 0
    assert any(item["task_id"] == task_id for item in manager.status())
    json.dumps(result)


def test_malformed_oversized_inputs_and_unsupported_control_are_rejected(tmp_path: Path) -> None:
    process = FakeProcess()
    manager, calls, _ = make_manager(tmp_path, process, max_prompt_bytes=8)

    for prompt, code in (
        ("", "PROMPT_INVALID"),
        ("   ", "PROMPT_INVALID"),
        ("bad\x00prompt", "PROMPT_INVALID"),
        ("123456789", "PROMPT_TOO_LARGE"),
    ):
        with pytest.raises(PolicyError) as error:
            manager.start_task("safe", scope_id="scope-a", scope_root=tmp_path, prompt=prompt)
        assert error.value.code == code
    with pytest.raises(PolicyError) as error:
        manager.start_task("safe", scope_id="scope-a", scope_root=Path("relative"), prompt="ok")
    assert error.value.code == "SCOPE_ROOT_INVALID"
    with pytest.raises(PolicyError) as error:
        manager.start_task("safe", scope_id="scope-a", scope_root=tmp_path / "missing", prompt="ok")
    assert error.value.code == "SCOPE_ROOT_INVALID"
    with pytest.raises(PolicyError) as error:
        manager.start_task(
            "safe",
            scope_id="scope-a",
            scope_root=tmp_path,
            prompt="ok",
            cwd=tmp_path,
        )
    assert error.value.code == "UNSUPPORTED_ARGUMENT"
    assert calls == []


def test_profile_scope_narrowing_and_broker_resolver_are_fail_closed(tmp_path: Path) -> None:
    process = FakeProcess()
    other_root = tmp_path / "other"
    other_root.mkdir()
    profile = AgentProfile("safe", "fixed-agent", allowed_scope_ids=frozenset({"approved"}))
    manager, calls, _ = make_manager(
        tmp_path,
        process,
        profile=profile,
        scope_resolver=lambda scope_id: tmp_path if scope_id == "approved" else other_root,
    )
    with pytest.raises(PolicyError) as error:
        manager.start_task("safe", scope_id="not-approved", prompt="ok")
    assert error.value.code == "SCOPE_NOT_ALLOWED"
    with pytest.raises(PolicyError) as error:
        manager.start_task("safe", scope_id="approved", scope_root=other_root, prompt="ok")
    assert error.value.code == "SCOPE_ROOT_MISMATCH"
    task = manager.start_task("safe", scope_id="approved", prompt="ok")
    assert task["scope_id"] == "approved"
    assert calls[0]["cwd"] == tmp_path.resolve()


def test_active_task_limit_and_start_failure_do_not_cross_contaminate(tmp_path: Path) -> None:
    blocking = FakeProcess(returncode=None)
    good = FakeProcess(returncode=0)
    calls: list[list[str]] = []

    def launcher(argv: list[str], **_kwargs: object) -> FakeProcess:
        calls.append(argv)
        if argv[0] == "bad-agent":
            raise OSError("not launched")
        return blocking if len(calls) == 2 else good

    manager = AgentTaskManager(
        {
            "bad": AgentProfile("bad", "bad-agent", timeout_seconds=1),
            "safe": AgentProfile("safe", "safe-agent", timeout_seconds=1),
        },
        launcher=launcher,
        max_active_tasks=1,
        cancel_grace_seconds=0.01,
        poll_interval_seconds=0.002,
    )
    with pytest.raises(PolicyError) as error:
        manager.start_task("bad", scope_id="scope-a", scope_root=tmp_path, prompt="bad")
    assert error.value.code == "PROCESS_START_FAILED"
    failed = manager.status()
    assert isinstance(failed, list)
    assert failed[0]["state"] == "failed"

    task = manager.start_task("safe", scope_id="scope-a", scope_root=tmp_path, prompt="good")
    with pytest.raises(PolicyError) as error:
        manager.start_task("safe", scope_id="scope-a", scope_root=tmp_path, prompt="blocked")
    assert error.value.code == "TASK_LIMIT_REACHED"
    blocking.release(0)
    assert wait_for_terminal(manager, str(task["task_id"]))["state"] == "completed"


def test_real_safe_subprocess_smoke_uses_fixed_argv_and_stdin(tmp_path: Path) -> None:
    profile = AgentProfile(
        "python-echo",
        sys.executable,
        (
            "-c",
            "import sys; data = sys.stdin.buffer.read(); print(data.decode('utf-8'))",
        ),
        timeout_seconds=2,
    )
    manager = AgentTaskManager(
        {"python-echo": profile},
        runtime_dir=tmp_path / "runtime",
        poll_interval_seconds=0.005,
    )
    task = manager.start_task(
        "python-echo",
        scope_id="scope-a",
        scope_root=tmp_path,
        prompt="literal shell text: $(not-executed)",
    )
    result = manager.result(str(task["task_id"])) if task["state"] == "completed" else wait_for_terminal(manager, str(task["task_id"]))
    if result["state"] != "completed":
        result = manager.result(str(task["task_id"]))
    assert result["state"] == "completed"
    assert "literal shell text: $(not-executed)" in str(result["stdout"])
