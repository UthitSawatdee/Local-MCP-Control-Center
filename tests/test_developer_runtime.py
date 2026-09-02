from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
from threading import Lock
import time
from pathlib import Path

import pytest

from local_mcp_control_center.errors import PolicyError
from local_mcp_control_center.filesystem import sha256_file
from local_mcp_control_center.processes import ManagedProcessManager
from local_mcp_control_center.runner import CommandResult, ProjectProfile

from .conftest import add_scope, allow_capabilities, enable_tools


def test_patch_paging_and_stale_hash_fail_closed(broker, workspace: Path) -> None:
    target = workspace / "module.py"
    target.write_text("line one\nline two\nline three\nline four\n", encoding="utf-8")
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read", "write")
    enable_tools(broker, "apply_patch")

    page = broker.invoke(
        "read_file_page",
        {"scope_id": "test-scope", "relative_path": "module.py", "max_lines": 2},
        session_id="session-a",
    )
    assert page["status"] == "ok"
    assert page["start_line"] == 1 and page["end_line"] == 2
    assert page["has_more"] is True
    assert page["continuation_token"]

    tampered_token = page["continuation_token"][:-1] + (
        "0" if page["continuation_token"][-1] != "0" else "1"
    )
    tampered = broker.invoke("read_file_page_continue", {"continuation_token": tampered_token})
    assert tampered["error_code"] == "INVALID_CONTINUATION_TOKEN"

    target.write_text("changed outside the agent\nline two\nline three\nline four\n", encoding="utf-8")
    continued = broker.invoke("read_file_page_continue", {"continuation_token": page["continuation_token"]})
    assert continued["error_code"] == "PRECONDITION_CHANGED"

    old_hash = sha256_file(target)
    target.write_text("changed again\nline two\nline three\nline four\n", encoding="utf-8")
    stale = broker.invoke(
        "apply_patch",
        {
            "scope_id": "test-scope",
            "relative_path": "module.py",
            "patch": "@@ -2 +2 @@\n-line two\n+line two changed\n",
            "expected_hash": old_hash,
        },
    )
    assert stale["error_code"] == "PRECONDITION_CHANGED"
    assert "line two" in target.read_text(encoding="utf-8")

    applied = broker.invoke(
        "apply_patch",
        {
            "scope_id": "test-scope",
            "relative_path": "module.py",
            "patch": "@@ -2 +2 @@\n-line two\n+line two changed\n",
        },
    )
    assert applied["status"] == "ok"
    assert applied["before_hash"].startswith("sha256:")
    assert applied["after_hash"].startswith("sha256:")
    assert applied["changed_line_ranges"] == [
        {"before_start": 2, "before_end": 2, "after_start": 2, "after_end": 2}
    ]

    inserted = broker.invoke(
        "apply_patch",
        {
            "scope_id": "test-scope",
            "relative_path": "module.py",
            "patch": "@@ -0,0 +1 @@\n+inserted first line\n",
        },
    )
    assert inserted["status"] == "ok"
    assert target.read_text(encoding="utf-8").startswith("inserted first line\n")


def test_discovery_batch_reads_regex_and_schema_boundary(broker, workspace: Path) -> None:
    (workspace / "app.py").write_text("def hello():\n    return 'token=hidden-value'\n", encoding="utf-8")
    ignored = workspace / "node_modules" / "dependency.js"
    ignored.parent.mkdir()
    ignored.write_text("hello()\n", encoding="utf-8")
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read")

    batch = broker.invoke(
        "read_many_files",
        {
            "scope_id": "test-scope",
            "files": [
                {"path": "app.py", "start_line": 1, "end_line": 1},
                {"path": "missing.py"},
            ],
        },
    )
    assert batch["status"] == "ok"
    assert [item["status"] for item in batch["files"]] == ["ok", "error"]
    assert batch["files"][1]["error_code"] == "TARGET_NOT_FOUND"

    found = broker.invoke("find_files", {"scope_id": "test-scope", "pattern": "*.js"})
    assert found["matches"] == []
    one_file = broker.invoke(
        "find_files",
        {"scope_id": "test-scope", "pattern": "app.py", "max_results": 1},
    )
    assert len(one_file["matches"]) == 1 and one_file["truncated"] is False
    regex = broker.invoke("search_regex", {"scope_id": "test-scope", "pattern": r"def\s+hello"})
    assert regex["results"][0]["relative_path"] == "app.py"
    secret = broker.invoke("read_file", {"scope_id": "test-scope", "relative_path": "app.py"})
    assert "hidden-value" not in secret["content"]
    assert "[REDACTED]" in secret["content"]

    invalid = broker.invoke(
        "find_files",
        {"scope_id": "test-scope", "pattern": "*", "unexpected": True},
    )
    assert invalid["error_code"] == "INVALID_INPUT"
    invalid_regex = broker.invoke("search_regex", {"scope_id": "test-scope", "pattern": "["})
    assert invalid_regex["error_code"] == "INVALID_INPUT"


def test_index_symbols_context_snapshot_and_trace(broker, workspace: Path) -> None:
    (workspace / "service.py").write_text(
        "class Service:\n    def execute(self):\n        return True\n\nservice = Service()\n",
        encoding="utf-8",
    )
    (workspace / "test_service.py").write_text(
        "from service import Service\n\ndef test_execute():\n    assert Service().execute()\n",
        encoding="utf-8",
    )
    add_scope(broker, workspace, kind="project")
    allow_capabilities(broker, "test-scope", "read")

    trace_id = "trace-developer-workflow"
    indexed = broker.invoke("workspace_index", {"scope_id": "test-scope"}, trace_id=trace_id)
    assert indexed["status"] == "ok"
    assert indexed["index"]["symbol_count"] >= 2
    assert indexed["trace_id"] == trace_id

    definitions = broker.invoke("find_definition", {"scope_id": "test-scope", "symbol": "Service"})
    assert definitions["results"][0]["relative_path"] == "service.py"
    references = broker.invoke("find_references", {"scope_id": "test-scope", "symbol": "Service"})
    assert any(item["relative_path"] == "test_service.py" for item in references["results"])

    snapshot = broker.invoke("workspace_snapshot", {"scope_id": "test-scope"})
    assert snapshot["status"] == "ok"
    assert "service.py" in {item["relative_path"] for item in snapshot["top_level"]}
    assert all("content" not in item for item in snapshot["top_level"])
    context = broker.invoke(
        "workspace_context",
        {"scope_id": "test-scope", "query": "execute", "intent": "trace"},
    )
    assert context["status"] == "ok"
    assert "service.py" in {item["relative_path"] for item in context["files"]}

    rows = broker.store.audit_rows(100)
    assert any(row["trace_id"] == trace_id and row["tool"] == "workspace_index" for row in rows)
    assert broker.verify_audit()["valid"] is True


def test_execution_and_profile_boundaries(broker, workspace: Path) -> None:
    (workspace / "pyproject.toml").write_text("[project]\nname='safe-test'\n", encoding="utf-8")
    add_scope(broker, workspace, kind="project")
    enable_tools(broker, "run_targeted_test", "process_start_profile")

    denied = broker.invoke("run_targeted_test", {"scope_id": "test-scope", "target": "auto"})
    assert denied["error_code"] == "CAPABILITY_DENIED"
    arbitrary = broker.invoke(
        "process_start_profile",
        {"scope_id": "test-scope", "profile": "sh -c touch escaped"},
    )
    assert arbitrary["error_code"] == "CAPABILITY_DENIED"

    allow_capabilities(broker, "test-scope", "read", "execute")
    arbitrary = broker.invoke(
        "process_start_profile",
        {"scope_id": "test-scope", "profile": "sh -c touch escaped"},
    )
    assert arbitrary["error_code"] == "PROFILE_NOT_ALLOWED"
    assert not (workspace / "escaped").exists()
    with pytest.raises(PolicyError) as error:
        broker.runner._profile("shell", workspace)
    assert error.value.code == "PROFILE_NOT_ALLOWED"


def test_managed_process_timeout_logs_and_unknown_stop(broker, workspace: Path) -> None:
    manager = ManagedProcessManager(broker.store, broker.audit)
    profile = ProjectProfile(
        "test_sleep",
        "python",
        workspace,
        sys.executable,
        ("-c", "print('token=secret-value'); import time; time.sleep(5)"),
        timeout_ms=100,
        source="test",
    )
    with pytest.raises(PolicyError) as error:
        manager.stop("not-a-real-process")
    assert error.value.code == "PROCESS_NOT_FOUND"

    record = manager.start(profile, scope_id="test-scope", owner_session_id="session-process")
    process_id = record["process_id"]
    deadline = time.monotonic() + 4
    status = record
    while time.monotonic() < deadline:
        status = manager.status(process_id)[0]
        if status["state"] != "running":
            break
        time.sleep(0.05)
    assert status["state"] == "timed_out"
    logs = manager.logs(process_id)
    assert logs["status"] == "ok"
    assert all("secret-value" not in item["text"] for item in logs["entries"])
    assert broker.verify_audit()["valid"] is True


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_controlled_git_mutation_and_dangerous_approval(broker, workspace: Path) -> None:
    _git(workspace, "init", "-q")
    _git(workspace, "config", "user.email", "test@example.invalid")
    _git(workspace, "config", "user.name", "Runtime Test")
    tracked = workspace / "tracked.txt"
    tracked.write_text("one\n", encoding="utf-8")
    _git(workspace, "add", "tracked.txt")
    _git(workspace, "commit", "-qm", "initial")
    add_scope(broker, workspace, kind="project")
    allow_capabilities(broker, "test-scope", "read", "execute")
    enable_tools(broker, "git_create_branch", "git_stage_paths", "git_commit", "git_restore_file", "git_push")

    branch = broker.invoke("git_create_branch", {"scope_id": "test-scope", "branch": "codex/safe-change"})
    assert branch["status"] == "ok", branch
    tracked.write_text("two\n", encoding="utf-8")
    staged = broker.invoke("git_stage_paths", {"scope_id": "test-scope", "paths": ["tracked.txt"]})
    assert staged["status"] == "ok", staged
    committed = broker.invoke(
        "git_commit",
        {"scope_id": "test-scope", "message": "test controlled commit", "paths": ["tracked.txt"]},
    )
    assert committed["status"] == "ok", committed
    assert "tracked.txt" in committed["result"]["stdout"] or committed["result"]["exit_code"] == 0

    tracked.write_text("three\n", encoding="utf-8")
    restore = broker.invoke("git_restore_file", {"scope_id": "test-scope", "path": "tracked.txt"})
    assert restore["status"] == "approval_required"
    assert tracked.read_text(encoding="utf-8") == "three\n"
    push = broker.invoke("git_push", {"scope_id": "test-scope", "remote": "origin"})
    assert push["status"] == "approval_required"
    assert not (workspace / "escaped").exists()

    assert broker.invoke("reset", {"args": ["--hard"]})["error_code"] == "TOOL_NOT_FOUND"
    assert broker.verify_audit()["valid"] is True


def test_project_tools_route_concurrently_by_explicit_scope(
    broker,
    workspace: Path,
    monkeypatch,
) -> None:
    projects = {
        "project-alpha": "alpha",
        "project-beta": "beta",
    }
    roots: dict[str, Path] = {}
    for scope_id, marker in projects.items():
        root = workspace / scope_id
        root.mkdir()
        (root / "tracked.txt").write_text(f"{marker}-before\n", encoding="utf-8")
        _git(root, "init", "-q")
        _git(root, "config", "user.email", "test@example.invalid")
        _git(root, "config", "user.name", "Multi Project Test")
        _git(root, "add", "tracked.txt")
        _git(root, "commit", "-qm", "initial")
        (root / "tracked.txt").write_text(f"{marker}-after\n", encoding="utf-8")
        (root / f"only-{marker}.txt").write_text("untracked\n", encoding="utf-8")
        add_scope(broker, root, scope_id=scope_id, kind="project")
        allow_capabilities(broker, scope_id, "read", "execute")
        roots[scope_id] = root

    enable_tools(
        broker,
        "git_status",
        "git_diff",
        "git_log",
        "git_commit",
        "run_targeted_test",
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(
            executor.map(
                lambda scope_id: broker.invoke("git_status", {"scope_id": scope_id}),
                projects,
            )
        )

    assert {result["scope_id"] for result in statuses} == set(projects)
    for scope_id, marker in projects.items():
        result = next(item for item in statuses if item["scope_id"] == scope_id)
        assert f"only-{marker}.txt" in result["result"]["stdout"]

    called_roots: list[Path] = []
    called_roots_lock = Lock()

    def fake_run_project_profile(profile, project_root, **kwargs):
        with called_roots_lock:
            called_roots.append(project_root)
        return CommandResult(profile, "python -m pytest", 0, "", "", False)

    monkeypatch.setattr(broker.runner, "run_project_profile", fake_run_project_profile)
    with ThreadPoolExecutor(max_workers=2) as executor:
        tests = list(
            executor.map(
                lambda scope_id: broker.invoke(
                    "run_targeted_test",
                    {"scope_id": scope_id, "target": "backend"},
                ),
                projects,
            )
        )

    assert all(result["status"] == "ok" for result in tests), tests
    assert set(called_roots) == set(roots.values())

    committed = broker.invoke(
        "git_commit",
        {
            "scope_id": "project-alpha",
            "message": "commit alpha only",
            "paths": ["tracked.txt"],
        },
    )
    assert committed["status"] == "ok", committed
    alpha_log = broker.invoke("git_log", {"scope_id": "project-alpha"})
    beta_log = broker.invoke("git_log", {"scope_id": "project-beta"})
    assert "commit alpha only" in alpha_log["result"]["stdout"]
    assert "commit alpha only" not in beta_log["result"]["stdout"]
    assert (roots["project-beta"] / "tracked.txt").read_text(encoding="utf-8") == "beta-after\n"

    missing_scope = broker.invoke("git_status")
    assert missing_scope["error_code"] == "INVALID_INPUT"
    assert broker.verify_audit()["valid"] is True


def test_registered_project_developer_workflow_sequence(broker, workspace: Path) -> None:
    """Exercise the additive developer path against a real registered project scope."""
    backend = workspace / "backend"
    backend.mkdir()
    (backend / "module.py").write_text("def greet():\n    return 'before'\n", encoding="utf-8")
    (backend / "test_module.py").write_text(
        "from module import greet\n\n\ndef test_greet():\n    assert greet() == 'after'\n",
        encoding="utf-8",
    )
    venv_root = backend / ".venv"
    try:
        venv_root.symlink_to(Path(sys.executable).parent.parent, target_is_directory=True)
    except OSError:
        pytest.skip("test environment cannot create a local profile executable symlink")

    _git(workspace, "init", "-q")
    _git(workspace, "config", "user.email", "test@example.invalid")
    _git(workspace, "config", "user.name", "Runtime Test")
    _git(workspace, "add", "backend/module.py", "backend/test_module.py")
    _git(workspace, "commit", "-qm", "initial")

    add_scope(broker, workspace, kind="project")
    allow_capabilities(broker, "test-scope", "read", "write", "execute")
    enable_tools(
        broker,
        "apply_patch",
        "find_files",
        "search_regex",
        "read_many_files",
        "workspace_snapshot",
        "workspace_context",
        "find_definition",
        "find_references",
        "git_create_branch",
        "git_diff",
        "git_status",
        "git_commit",
        "run_targeted_test",
    )
    trace_id = "trace-registered-project-workflow"

    assert broker.invoke("list_scopes", trace_id=trace_id)["status"] == "ok"
    assert broker.invoke("workspace_snapshot", {"scope_id": "test-scope"}, trace_id=trace_id)["status"] == "ok"
    assert broker.invoke("git_status", {"scope_id": "test-scope"}, trace_id=trace_id)["status"] == "ok"
    assert broker.invoke(
        "search_regex",
        {"scope_id": "test-scope", "pattern": r"def\s+greet", "relative_path": "backend"},
        trace_id=trace_id,
    )["results"]
    read = broker.invoke(
        "read_many_files",
        {"scope_id": "test-scope", "files": [{"path": "backend/module.py"}]},
        trace_id=trace_id,
    )
    expected_hash = read["files"][0]["content_hash"]
    assert broker.invoke(
        "find_definition",
        {"scope_id": "test-scope", "symbol": "greet", "relative_path": "backend"},
        trace_id=trace_id,
    )["results"]
    assert broker.invoke(
        "find_references",
        {"scope_id": "test-scope", "symbol": "greet", "relative_path": "backend"},
        trace_id=trace_id,
    )["results"]

    assert broker.invoke(
        "git_create_branch",
        {"scope_id": "test-scope", "branch": "codex/workflow"},
        trace_id=trace_id,
    )["status"] == "ok"
    patched = broker.invoke(
        "apply_patch",
        {
            "scope_id": "test-scope",
            "relative_path": "backend/module.py",
            "patch": "@@ -2 +2 @@\n-    return 'before'\n+    return 'after'\n",
            "expected_hash": expected_hash,
        },
        trace_id=trace_id,
    )
    assert patched["status"] == "ok"
    assert broker.invoke("git_diff", {"scope_id": "test-scope"}, trace_id=trace_id)["result"]["stdout"]
    tested = broker.invoke(
        "run_targeted_test",
        {"scope_id": "test-scope", "target": "backend", "test_path": "test_module.py"},
        trace_id=trace_id,
    )
    assert tested["status"] == "ok", tested
    assert tested["result"]["exit_code"] == 0, tested
    assert broker.invoke("git_status", {"scope_id": "test-scope"}, trace_id=trace_id)["status"] == "ok"
    committed = broker.invoke(
        "git_commit",
        {
            "scope_id": "test-scope",
            "message": "verify developer workflow",
            "paths": ["backend/module.py"],
        },
        trace_id=trace_id,
    )
    assert committed["status"] == "ok", committed
    assert broker.invoke("git_status", {"scope_id": "test-scope"}, trace_id=trace_id)["status"] == "ok"

    traced_tools = {row["tool"] for row in broker.store.audit_rows(200) if row["trace_id"] == trace_id}
    assert {"list_scopes", "workspace_snapshot", "apply_patch", "run_targeted_test", "git_commit"} <= traced_tools
    assert broker.verify_audit()["valid"] is True
