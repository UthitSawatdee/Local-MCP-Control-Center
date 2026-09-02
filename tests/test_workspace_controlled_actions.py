from __future__ import annotations

import subprocess
from pathlib import Path

from local_mcp_control_center.runner import CommandResult
from local_mcp_control_center.workspace_engine import WorkRequest

from .conftest import add_scope, allow_capabilities, enable_tools


def _git_fixture(root: Path) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "devos@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "DevOS Test"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "--", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)


def _python_project(root: Path) -> None:
    (root / "pyproject.toml").write_text(
        "[project]\nname = 'devos-controlled-test'\nversion = '0.0.0'\n",
        encoding="utf-8",
    )
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_parser.py").write_text("def test_parser():\n    assert True\n", encoding="utf-8")
    (root / "README.md").write_text("demo\n", encoding="utf-8")


def _prepare_project(broker, workspace: Path) -> dict:
    add_scope(broker, workspace, scope_id="demo-project", kind="project")
    allow_capabilities(broker, "demo-project", "read", "execute")
    return broker.workspace_engine.prepare(
        WorkRequest(project_id="demo-project", goal="verify controlled operation", mode="implement")
    )


def test_targeted_verification_proposal_never_executes_before_approval_and_records_fixed_runner(
    broker,
    workspace: Path,
    monkeypatch,
) -> None:
    _python_project(workspace)
    _git_fixture(workspace)
    package = _prepare_project(broker, workspace)
    enable_tools(broker, "workspace_propose_action", "run_targeted_test")
    calls: list[tuple[str, str | None]] = []

    def fake_run_project_profile(profile, project_root, *, target=None, test_path=None, **kwargs):
        calls.append((profile, test_path))
        return CommandResult(
            profile="backend_pytest",
            argv_display="python3 -m pytest -q tests/test_parser.py",
            exit_code=0,
            stdout="1 passed",
            stderr="",
            timed_out=False,
            duration_ms=7,
        )

    monkeypatch.setattr(broker.runner, "run_project_profile", fake_run_project_profile)
    pending = broker.invoke(
        "workspace_propose_action",
        {
            "run_id": package["run_id"],
            "action": "targeted_verification",
            "parameters": {"target": "backend", "test_path": "tests/test_parser.py"},
        },
    )

    assert pending["status"] == "approval_required", pending
    assert pending["executed"] is False
    assert pending["run_id"] == package["run_id"]
    assert pending["workspace_action"] == "targeted_verification"
    assert calls == []
    proposals = broker.workspace_engine.action_proposals("demo-project")
    assert proposals[0]["run_id"] == package["run_id"]
    assert proposals[0]["workspace_action"] == "targeted_verification"

    assert broker.approve(pending["approval_id"])["status"] == "ok"
    applied = broker.invoke("apply_approved_action", {"approval_id": pending["approval_id"]}, actor="user")
    assert applied["status"] == "ok", applied
    assert calls == [("run_targeted_test", "tests/test_parser.py")]

    evidence = broker.store.workspace_evidence(package["run_id"])
    verification = [item for item in evidence if item["event_type"] == "test_result"]
    assert verification
    assert verification[-1]["payload"]["evidence_source"] == "fixed_runner"
    assert verification[-1]["payload"]["target"] == "tests/test_parser.py"

    replay = broker.invoke("apply_approved_action", {"approval_id": pending["approval_id"]}, actor="user")
    assert replay["status"] == "denied"
    assert replay["error_code"] == "APPROVAL_NOT_GRANTED"


def test_workspace_proposal_fails_closed_when_underlying_tool_is_disabled(broker, workspace: Path) -> None:
    _python_project(workspace)
    _git_fixture(workspace)
    package = _prepare_project(broker, workspace)
    enable_tools(broker, "workspace_propose_action")

    result = broker.invoke(
        "workspace_propose_action",
        {
            "run_id": package["run_id"],
            "action": "targeted_verification",
            "parameters": {"target": "backend", "test_path": "tests/test_parser.py"},
        },
    )

    assert result["status"] == "denied"
    assert result["error_code"] == "TOOL_DISABLED"
    assert broker.actionable_approvals() == []


def test_workspace_commit_proposal_rejects_preexisting_dirty_paths(broker, workspace: Path) -> None:
    source = workspace / "src"
    source.mkdir()
    (source / "parser.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git_fixture(workspace)
    (source / "parser.py").write_text("VALUE = 2\n", encoding="utf-8")
    add_scope(broker, workspace, scope_id="demo-project", kind="project")
    allow_capabilities(broker, "demo-project", "read", "execute")
    enable_tools(broker, "workspace_propose_action", "git_commit")
    package = broker.workspace_engine.prepare(
        WorkRequest(
            project_id="demo-project",
            goal="do not absorb pre-existing changes",
            mode="implement",
            allowed_scope=("src",),
        )
    )

    result = broker.invoke(
        "workspace_propose_action",
        {
            "run_id": package["run_id"],
            "action": "commit",
            "parameters": {"message": "unsafe commit", "paths": ["src/parser.py"]},
        },
    )

    assert result["status"] == "denied"
    assert result["error_code"] == "INVALID_COMMIT_SCOPE"
    assert broker.actionable_approvals() == []


def test_workspace_push_approval_is_invalidated_when_head_changes(broker, workspace: Path) -> None:
    _python_project(workspace)
    _git_fixture(workspace)
    package = _prepare_project(broker, workspace)
    enable_tools(broker, "workspace_propose_action", "git_push")
    broker.workspace_engine.record_verification_result(
        package["run_id"],
        CommandResult(
            profile="backend_pytest",
            argv_display="python3 -m pytest -q tests/test_parser.py",
            exit_code=0,
            stdout="1 passed",
            stderr="",
            timed_out=False,
            duration_ms=5,
        ),
        target="tests/test_parser.py",
        expected_scope_id="demo-project",
    )
    handoff = broker.workspace_engine.finish(package["run_id"])
    assert handoff["verification"]["verified"] is True
    assert handoff["publication_readiness"] == "ready_for_review"

    pending = broker.invoke(
        "workspace_propose_action",
        {"run_id": package["run_id"], "action": "push", "parameters": {"remote": "origin"}},
    )
    assert pending["status"] == "approval_required", pending
    assert broker.approve(pending["approval_id"])["status"] == "ok"

    (workspace / "README.md").write_text("changed after approval\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(workspace), "add", "--", "README.md"], check=True)
    subprocess.run(["git", "-C", str(workspace), "commit", "-qm", "head moved"], check=True)

    applied = broker.invoke("apply_approved_action", {"approval_id": pending["approval_id"]}, actor="user")
    assert applied["status"] == "denied"
    assert applied["error_code"] == "PRECONDITION_CHANGED"
    assert broker.store.get_approval(pending["approval_id"]).status == "consumed"
