from __future__ import annotations

import subprocess
import threading
import time
from pathlib import Path

from local_mcp_control_center.agent_runtime import (
    AgentModelProfile,
    AgentRuntimeLimits,
    FakeModelProvider,
    ProviderResult,
)
from local_mcp_control_center.broker import Broker
from local_mcp_control_center.mcp_server import build_server
from local_mcp_control_center.storage import Store

from .conftest import add_scope, allow_capabilities, enable_tools


def make_git_project(root: Path) -> Path:
    root.mkdir()
    (root / "app.py").write_text("value = 'base'\n", encoding="utf-8")
    (root / "test_app.py").write_text("def test_app():\n    assert True\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "app.py", "test_app.py"], check=True)
    subprocess.run(
        [
            "git", "-C", str(root),
            "-c", "user.name=Runtime Test",
            "-c", "user.email=runtime@example.invalid",
            "commit", "-qm", "base",
        ],
        check=True,
    )
    return root


def configure_runtime(broker: Broker, provider: FakeModelProvider) -> None:
    profile = AgentModelProfile("fake-profile", "fake", "fake-model", provider)
    assert broker.configure_agent_model_profile(profile)["status"] == "ok"
    enable_tools(
        broker,
        "create_agent_task",
        "get_agent_task",
        "get_agent_result",
        "list_agent_tasks",
        "cancel_agent_task",
        "read_file",
        "write_file",
        "create_file",
        "apply_patch",
        "run_targeted_test",
    )


def wait_for_task(broker: Broker, task_id: str, *, terminal: bool = True) -> dict[str, object]:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        value = broker.agent_runtime.get_task(task_id)
        if not terminal or value["status"] in {"completed", "failed", "cancelled"}:
            return value
        time.sleep(0.01)
    raise AssertionError(f"task did not finish: {broker.agent_runtime.get_task(task_id)}")


def test_provider_backed_implementer_is_persisted_and_isolated(tmp_path: Path) -> None:
    project = make_git_project(tmp_path / "project")
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    broker = Broker(store)
    try:
        add_scope(broker, project, scope_id="project", kind="project")
        allow_capabilities(broker, "project", "read", "write", "create", "execute")

        def implement(**kwargs):
            read = kwargs["call_tool"]("read_file", {"relative_path": "app.py"})
            assert read["status"] == "ok"
            escaped = kwargs["call_tool"](
                "write_file",
                {"relative_path": "../escape.py", "content": "must stay in scope\n"},
            )
            assert escaped["status"] == "denied"
            assert kwargs["call_tool"]("shell", {})["error_code"] == "TOOL_NOT_ALLOWED"
            changed = kwargs["call_tool"](
                "write_file",
                {"relative_path": "app.py", "content": "value = 'implemented'\n"},
            )
            assert changed["status"] == "ok", changed
            return ProviderResult(
                "implemented bounded change",
                verification=["write completed in isolated worktree"],
                tests=["not run by fake provider"],
            )

        provider = FakeModelProvider(implement)
        configure_runtime(broker, provider)
        created = broker.invoke(
            "create_agent_task",
            {
                "role": "implementer",
                "task": "Update app.py in the assigned scope.",
                "scope_id": "project",
                "model_profile": "fake-profile",
            },
        )
        assert created["status"] in {"queued", "starting", "running", "completed"}
        task_id = str(created["task_id"])
        finished = wait_for_task(broker, task_id)
        assert finished["status"] == "completed", finished
        assert finished["base_commit"]
        assert finished["source_dirty"] is False
        assert finished["source_head_commit"] == finished["base_commit"]
        assert provider.calls[0]["capability_context"]["role"] == "implementer"
        assert provider.calls[0]["capability_context"]["worktree"] is True
        assert finished["worktree"]["isolated"] is True
        assert finished["worktree"]["cleanup"] == "explicit_only"

        result = broker.invoke("get_agent_result", {"task_id": task_id})
        assert result["status"] == "completed", result
        assert result["summary"] == "implemented bounded change"
        assert result["changed_files"] == ["app.py"]
        worktree_path = Path(str(result["worktree"]["path"]))
        assert worktree_path.is_dir()
        assert (worktree_path / "app.py").read_text(encoding="utf-8") == "value = 'implemented'\n"
        assert (project / "app.py").read_text(encoding="utf-8") == "value = 'base'\n"

        listed = broker.invoke("list_agent_tasks", {"scope_id": "project"})
        assert listed["count"] == 1
        assert listed["tasks"][0]["task_id"] == task_id
        assert broker.verify_audit()["valid"] is True
    finally:
        store.close()


def test_read_only_roles_are_enforced_by_server_facade(tmp_path: Path) -> None:
    project = make_git_project(tmp_path / "project")
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    broker = Broker(store)
    try:
        add_scope(broker, project, scope_id="project", kind="project")
        allow_capabilities(broker, "project", "read")

        def explorer(**kwargs):
            denied = kwargs["call_tool"]("write_file", {"relative_path": "app.py", "content": "escape"})
            assert denied["status"] == "denied"
            assert denied["error_code"] == "TOOL_NOT_ALLOWED"
            recursive = kwargs["call_tool"]("create_agent_task", {"role": "explorer"})
            assert recursive["status"] == "denied"
            return ProviderResult("read-only findings")

        provider = FakeModelProvider(explorer)
        configure_runtime(broker, provider)
        created = broker.invoke(
            "create_agent_task",
            {
                "role": "explorer",
                "task": "Inspect the project and report risks.",
                "scope_id": "project",
                "model_profile": "fake-profile",
                "command": "must-not-be-accepted",
            },
        )
        assert created["status"] == "denied"
        assert created["error_code"] == "INVALID_INPUT"

        created = broker.invoke(
            "create_agent_task",
            {
                "role": "explorer",
                "task": "Inspect the project and report risks.",
                "scope_id": "project",
                "model_profile": "fake-profile",
            },
        )
        task_id = str(created["task_id"])
        assert wait_for_task(broker, task_id)["status"] == "completed"
        task_view = broker.invoke("get_agent_task", {"task_id": task_id})
        assert task_view["base_ref"] == "HEAD"
        assert task_view["base_commit"]
        assert (project / "app.py").read_text(encoding="utf-8") == "value = 'base'\n"
        result = broker.invoke("get_agent_result", {"task_id": task_id})
        assert result["changed_files"] == []
        denied_rows = [row for row in broker.store.audit_rows(100) if row["error_code"] == "TOOL_NOT_ALLOWED"]
        assert denied_rows
    finally:
        store.close()


def test_implementer_records_dirty_source_without_importing_it(tmp_path: Path) -> None:
    project = make_git_project(tmp_path / "project")
    (project / "app.py").write_text("value = 'local-dirty'\n", encoding="utf-8")
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    broker = Broker(store)
    try:
        add_scope(broker, project, scope_id="project", kind="project")
        allow_capabilities(broker, "project", "read", "write", "create", "execute")
        provider = FakeModelProvider()
        configure_runtime(broker, provider)
        created = broker.invoke(
            "create_agent_task",
            {
                "role": "implementer",
                "task": "Inspect the clean base without changing the local dirty source.",
                "scope_id": "project",
                "model_profile": "fake-profile",
            },
        )
        task_id = str(created["task_id"])
        finished = wait_for_task(broker, task_id)
        assert finished["status"] == "completed", finished
        assert finished["source_dirty"] is True
        assert finished["source_head_commit"] == finished["base_commit"]
        result = broker.invoke("get_agent_result", {"task_id": task_id})
        assert result["warnings"] == ["source project had uncommitted changes; worktree base is the recorded commit"]
        assert (project / "app.py").read_text(encoding="utf-8") == "value = 'local-dirty'\n"
    finally:
        broker.agent_runtime.shutdown()
        store.close()


def test_reviewer_reuses_implementer_worktree_without_write_access(tmp_path: Path) -> None:
    project = make_git_project(tmp_path / "project")
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    broker = Broker(store)
    try:
        add_scope(broker, project, scope_id="project", kind="project")
        allow_capabilities(broker, "project", "read", "write", "create", "execute")

        def implement(**kwargs):
            changed = kwargs["call_tool"](
                "write_file",
                {"relative_path": "app.py", "content": "value = 'review-me'\n"},
            )
            assert changed["status"] == "ok", changed
            return ProviderResult("implementation ready for review")

        implementer = FakeModelProvider(implement)
        configure_runtime(broker, implementer)
        created = broker.invoke(
            "create_agent_task",
            {
                "role": "implementer",
                "task": "Make the bounded change for review.",
                "scope_id": "project",
                "model_profile": "fake-profile",
            },
        )
        parent_id = str(created["task_id"])
        parent = wait_for_task(broker, parent_id)
        assert parent["status"] == "completed", parent

        reviewer = FakeModelProvider()
        broker.configure_agent_model_profile(AgentModelProfile("review-profile", "fake", "review-model", reviewer))

        def review(**kwargs):
            diff = kwargs["call_tool"]("git_diff", {})
            assert diff["status"] == "ok", diff
            denied = kwargs["call_tool"](
                "write_file",
                {"relative_path": "app.py", "content": "reviewer must not write\n"},
            )
            assert denied["status"] == "denied"
            return ProviderResult("review findings returned")

        reviewer.handler = review
        review_created = broker.invoke(
            "create_agent_task",
            {
                "role": "reviewer",
                "task": "Review the implementation diff and report findings.",
                "scope_id": "project",
                "model_profile": "review-profile",
                "parent_task_id": parent_id,
            },
        )
        review_id = str(review_created["task_id"])
        review_finished = wait_for_task(broker, review_id)
        assert review_finished["status"] == "completed", review_finished
        assert review_finished["worktree"]["path"] == parent["worktree"]["path"]
        assert review_finished["worktree"]["read_only"] is True
        assert review_finished["base_commit"] == parent["base_commit"]
        review_result = broker.invoke("get_agent_result", {"task_id": review_id})
        assert review_result["changed_files"] == []
        assert (project / "app.py").read_text(encoding="utf-8") == "value = 'base'\n"
    finally:
        broker.agent_runtime.shutdown()
        store.close()


def test_cancel_and_restart_preserve_structured_state(tmp_path: Path) -> None:
    project = make_git_project(tmp_path / "project")
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    broker = Broker(store, agent_runtime_limits=AgentRuntimeLimits(max_runtime_seconds=10))
    try:
        add_scope(broker, project, scope_id="project", kind="project")
        allow_capabilities(broker, "project", "read", "execute")
        started = threading.Event()

        def slow(**kwargs):
            started.set()
            while not kwargs["cancel_event"].is_set():
                time.sleep(0.005)
            return ProviderResult("cancelled fake")

        provider = FakeModelProvider(slow)
        configure_runtime(broker, provider)
        created = broker.invoke(
            "create_agent_task",
            {
                "role": "tester",
                "task": "Run a bounded test and wait for cancellation.",
                "scope_id": "project",
                "model_profile": "fake-profile",
            },
        )
        task_id = str(created["task_id"])
        assert started.wait(2)
        cancelled = broker.invoke("cancel_agent_task", {"task_id": task_id})
        assert cancelled["status"] == "cancelled"
        result = broker.invoke("get_agent_result", {"task_id": task_id})
        assert result["status"] == "cancelled"
        assert result["errors"]
        assert provider.cancelled == [task_id]
    finally:
        broker.agent_runtime.shutdown()
        store.close()

    restarted_store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    restarted = Broker(restarted_store)
    try:
        persisted = restarted.invoke("get_agent_task", {"task_id": task_id})
        assert persisted["status"] == "cancelled"
        persisted_result = restarted.invoke("get_agent_result", {"task_id": task_id})
        assert persisted_result["status"] == "cancelled"
    finally:
        restarted_store.close()


def test_implementer_requires_write_capability_and_limits_are_explicit(tmp_path: Path) -> None:
    project = make_git_project(tmp_path / "project")
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    broker = Broker(store, agent_runtime_limits=AgentRuntimeLimits(max_concurrent_workers=1, max_workers_per_root=2))
    try:
        add_scope(broker, project, scope_id="project", kind="project")
        allow_capabilities(broker, "project", "read", "execute")
        provider = FakeModelProvider()
        configure_runtime(broker, provider)
        denied = broker.invoke(
            "create_agent_task",
            {
                "role": "implementer",
                "task": "This must be rejected without write permissions.",
                "scope_id": "project",
                "model_profile": "fake-profile",
            },
        )
        assert denied["status"] == "denied"
        assert denied["error_code"] == "CAPABILITY_DENIED"
        assert broker.agent_runtime.limits.max_concurrent_workers == 1
        assert broker.agent_runtime.limits.max_workers_per_root == 2
        assert broker.agent_runtime.limits.max_tool_calls == 80
    finally:
        store.close()


def test_mcp_agent_task_tools_expose_bounded_schemas(tmp_path: Path) -> None:
    store = Store(tmp_path / "state" / "control.sqlite3", tmp_path / "state")
    broker = Broker(store)
    try:
        configure_runtime(broker, FakeModelProvider())
        server = build_server(broker)
        tools = {tool.name: tool for tool in server._tool_manager.list_tools()}
        assert {"create_agent_task", "get_agent_task", "get_agent_result", "list_agent_tasks", "cancel_agent_task"} <= set(tools)

        create_schema = tools["create_agent_task"].fn_metadata.arg_model.model_json_schema()
        assert set(create_schema["required"]) == {"role", "task", "scope_id", "model_profile"}
        assert create_schema["properties"]["role"]["enum"] == ["explorer", "implementer", "reviewer", "tester"]
        assert not {"system_prompt", "command", "executable", "base_url", "environment"} & set(create_schema["properties"])

        list_schema = tools["list_agent_tasks"].fn_metadata.arg_model.model_json_schema()
        status_schema = list_schema["properties"]["status"]
        status_options = status_schema.get("anyOf", [status_schema])
        assert [item["enum"] for item in status_options if "enum" in item] == [["queued", "starting", "running", "completed", "failed", "cancelled"]]
        assert list_schema["properties"]["limit"]["maximum"] == 100
    finally:
        broker.agent_runtime.shutdown()
        store.close()
