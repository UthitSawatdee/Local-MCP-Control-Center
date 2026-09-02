from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from local_mcp_control_center.cli import main
from local_mcp_control_center.errors import PolicyError, StorageError
from local_mcp_control_center.models import ScopeKind
from local_mcp_control_center.runner import CommandResult, FixedRunner
from local_mcp_control_center.workspace_engine import WorkEvent, WorkRequest, WorkspaceScope, parse_capsule

from .conftest import add_scope, allow_capabilities


def _git_fixture(root: Path) -> None:
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(root), "config", "user.email", "devos@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(root), "config", "user.name", "DevOS Test"], check=True)
    subprocess.run(["git", "-C", str(root), "add", "--", "."], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)


def test_capsule_parser_applies_safe_defaults_and_rejects_secret_reads() -> None:
    capsule = parse_capsule(
        {
            "id": "demo",
            "name": "Demo project",
            "repository": {"default_branch": "main", "push_requires_approval": True},
            "runtime": {"python": "3.12"},
            "safety": {"never_read": ["config/private.json"]},
        }
    )

    assert capsule.project_id == "demo"
    assert capsule.repository["default_branch"] == "main"
    assert ".env" in capsule.safety["never_read"]
    assert "private keys" in capsule.safety["never_read"]


def test_capsule_parser_rejects_secret_content_and_unknown_top_level_fields() -> None:
    try:
        parse_capsule({"id": "demo", "secret": "do-not-persist"})
    except ValueError as exc:
        assert "unsupported capsule field" in str(exc)
    else:
        raise AssertionError("unknown capsule field must fail closed")

    try:
        parse_capsule({"id": "demo", "safety": {"credentials": "private-token"}})
    except ValueError as exc:
        assert "safety" in str(exc)
    else:
        raise AssertionError("credential-shaped capsule field must fail closed")

    with pytest.raises(ValueError, match="safe relative Git branch"):
        parse_capsule({"id": "demo", "repository": {"default_branch": "/private/project"}})


def test_capsule_protected_path_is_planning_boundary_and_public_capsule_is_bounded(broker, workspace: Path) -> None:
    (workspace / "README.md").write_text("demo\n", encoding="utf-8")
    (workspace / "uploads").mkdir()
    (workspace / "uploads" / "private.txt").write_text("do not inspect\n", encoding="utf-8")
    _git_fixture(workspace)
    (workspace / "uploads" / "private.txt").write_text("changed but still protected\n", encoding="utf-8")
    add_scope(broker, workspace, scope_id="demo-project", kind=ScopeKind.PROJECT.value)
    allow_capabilities(broker, "demo-project", "read")
    broker.workspace_engine.configure_capsule(
        "demo-project",
        {
            "id": "demo-project",
            "name": "Demo",
            "repository": {"remote": "origin"},
            "services": {"web": {"command": "/private/project/bin/service", "port": 65534}},
            "safety": {"protected_paths": ["uploads/"], "never_read": ["uploads/private.txt"]},
        },
        source="/private/project/capsule.json",
    )

    snapshot = broker.workspace_engine.observe(WorkspaceScope.from_scope(broker.store.get_scope("demo-project")))
    encoded = json.dumps(snapshot, ensure_ascii=False)
    assert "canonical_path" not in snapshot["capsule"]["repository"]
    assert "command" not in snapshot["capsule"]["services"]["web"]
    assert "/private/project/bin/service" not in encoded
    assert "/private/project/capsule.json" not in encoded
    assert snapshot["capsule"]["source"] == "configured"
    assert "uploads/private.txt" not in snapshot["git"]["changed_files"]
    assert "uploads/private.txt" in snapshot["git"]["protected_changed_paths"]
    assert all(item["relative_path"] != "uploads" for item in snapshot["filesystem"]["top_level"])

    try:
        broker.workspace_engine.prepare(
            WorkRequest(
                project_id="demo-project",
                goal="inspect uploads",
                allowed_scope=("uploads",),
            )
        )
    except ValueError as exc:
        assert "protected path" in str(exc)
    else:
        raise AssertionError("Capsule protected path must fail closed during preparation")


def test_observe_persists_metadata_and_never_returns_secret_contents(broker, workspace: Path) -> None:
    (workspace / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (workspace / ".env").write_text("API_KEY=super-secret-value\n", encoding="utf-8")
    _git_fixture(workspace)
    add_scope(broker, workspace, scope_id="demo-project", kind=ScopeKind.PROJECT.value)
    allow_capabilities(broker, "demo-project", "read")
    scope = WorkspaceScope.from_scope(broker.store.get_scope("demo-project"))

    snapshot = broker.workspace_engine.observe(scope)
    encoded = json.dumps(snapshot, ensure_ascii=False)

    assert snapshot["project"]["id"] == "demo-project"
    assert snapshot["git"]["branch"]
    assert snapshot["environment"]["tracked_environment_warnings"]
    assert "super-secret-value" not in encoded
    assert broker.store.get_workspace_snapshot(snapshot["snapshot_id"]) is not None


def test_observe_flags_untracked_protected_changes_without_reading_contents(broker, workspace: Path) -> None:
    (workspace / "README.md").write_text("demo\n", encoding="utf-8")
    _git_fixture(workspace)
    (workspace / ".env").write_text("API_KEY=untracked-secret\n", encoding="utf-8")
    add_scope(broker, workspace, scope_id="demo-project", kind=ScopeKind.PROJECT.value)
    allow_capabilities(broker, "demo-project", "read")

    snapshot = broker.workspace_engine.observe(WorkspaceScope.from_scope(broker.store.get_scope("demo-project")))

    assert snapshot["git"]["state"] == "dirty"
    assert snapshot["git"]["protected_change_count"] == 1
    assert snapshot["environment"]["tracked_environment_warnings"]
    assert "untracked-secret" not in json.dumps(snapshot, ensure_ascii=False)


def test_prepare_record_finish_exposes_impact_tests_and_handoff(broker, workspace: Path) -> None:
    source = workspace / "src"
    tests = workspace / "tests"
    source.mkdir()
    tests.mkdir()
    (source / "parser.py").write_text("def parse(value):\n    return value\n", encoding="utf-8")
    (tests / "test_parser.py").write_text("def test_parse():\n    assert True\n", encoding="utf-8")
    _git_fixture(workspace)
    (source / "parser.py").write_text("def parse(value):\n    return value.strip()\n", encoding="utf-8")
    (workspace / "README.md").write_text("pre-existing unrelated change\n", encoding="utf-8")
    add_scope(broker, workspace, scope_id="demo-project", kind=ScopeKind.PROJECT.value)
    allow_capabilities(broker, "demo-project", "read")
    scope = WorkspaceScope.from_scope(broker.store.get_scope("demo-project"))

    package = broker.workspace_engine.prepare(
        WorkRequest(
            project_id=scope.project_id,
            goal="fix parser whitespace handling",
            mode="implement",
            allowed_scope=("src",),
        )
    )

    receipt = broker.workspace_engine.record(
        WorkEvent(
            run_id=package["run_id"],
            event_type="test_result",
            payload={
                "command": ".venv/bin/python -m pytest tests/test_parser.py",
                "status": "passed",
                "exit_code": 0,
                "duration_ms": 42,
                "target": "tests/test_parser.py",
                "stdout": "secret output must not persist",
            },
        )
    )
    handoff = broker.workspace_engine.finish(package["run_id"])

    assert package["work_run"]["status"] == "prepared"
    assert "src" in package["allowed_scope"]
    assert package["impact"]["changed_files"] == ["src/parser.py"]
    assert package["out_of_scope_changed_files"] == ["README.md"]
    assert "tests/test_parser.py" in package["test_mapping"]["nearest"]
    assert receipt["event_type"] == "test_result"
    assert handoff["run_id"] == package["run_id"]
    assert handoff["verification"]["verified"] is False
    assert handoff["publication_readiness"] == "pending_verification"
    assert "secret output" not in json.dumps(broker.store.workspace_evidence(package["run_id"]))
    with pytest.raises(ValueError, match="immutable"):
        broker.workspace_engine.record(
            WorkEvent(package["run_id"], "decision", {"decision": "late event"})
        )


def test_fixed_runner_verification_is_the_only_verified_evidence(broker, workspace: Path, monkeypatch) -> None:
    (workspace / "tests").mkdir()
    (workspace / "tests" / "test_parser.py").write_text("def test_parse():\n    assert True\n", encoding="utf-8")
    _git_fixture(workspace)
    add_scope(broker, workspace, scope_id="demo-project", kind=ScopeKind.PROJECT.value)
    allow_capabilities(broker, "demo-project", "read")
    package = broker.workspace_engine.prepare(
        WorkRequest(project_id="demo-project", goal="verify project", mode="implement")
    )

    def fake_run_project_profile(profile, project_root, *, target=None, test_path=None, **kwargs):
        assert profile == "backend_pytest"
        assert test_path == "tests/test_parser.py"
        return CommandResult(
            profile="backend_pytest",
            argv_display="python3 -m pytest tests/test_parser.py",
            exit_code=0,
            stdout="",
            stderr="",
            timed_out=False,
            duration_ms=7,
        )

    monkeypatch.setattr(broker.workspace_engine.runner, "run_project_profile", fake_run_project_profile)
    broker.workspace_engine.verify(package["run_id"], "backend_pytest", test_path="tests/test_parser.py")
    handoff = broker.workspace_engine.finish(package["run_id"])

    assert handoff["verification"]["verified"] is True
    assert handoff["verification"]["results"][0]["evidence_source"] == "fixed_runner"


def test_failed_run_requires_recovery_before_ordinary_evidence(broker, workspace: Path) -> None:
    (workspace / "README.md").write_text("demo\n", encoding="utf-8")
    add_scope(broker, workspace, scope_id="demo-project", kind=ScopeKind.PROJECT.value)
    allow_capabilities(broker, "demo-project", "read")
    package = broker.workspace_engine.prepare(
        WorkRequest(project_id="demo-project", goal="diagnose project", mode="diagnose")
    )

    broker.workspace_engine.record(
        WorkEvent(package["run_id"], "error", {"error_code": "TEST_FAILURE", "message": "failed"})
    )
    with pytest.raises(ValueError, match="require recovery"):
        broker.workspace_engine.record(WorkEvent(package["run_id"], "decision", {"decision": "continue"}))
    broker.workspace_engine.record(WorkEvent(package["run_id"], "recovery", {"reason": "retry"}))
    assert broker.workspace_engine.record(
        WorkEvent(package["run_id"], "decision", {"decision": "continue"})
    )["status"] == "ok"


def test_status_only_verification_evidence_stays_unverified(broker, workspace: Path) -> None:
    (workspace / "README.md").write_text("demo\n", encoding="utf-8")
    add_scope(broker, workspace, scope_id="demo-project", kind=ScopeKind.PROJECT.value)
    allow_capabilities(broker, "demo-project", "read")
    package = broker.workspace_engine.prepare(
        WorkRequest(project_id="demo-project", goal="diagnose project", mode="diagnose")
    )

    broker.workspace_engine.record(
        WorkEvent(package["run_id"], "test_result", {"status": "passed"})
    )
    handoff = broker.workspace_engine.finish(package["run_id"])

    assert handoff["verification"]["verified"] is False
    assert handoff["publication_readiness"] == "pending_verification"


def test_runtime_probes_use_trusted_interpreters_and_not_project_venv(tmp_path: Path, monkeypatch) -> None:
    runner = FixedRunner(tmp_path / "control")
    calls = []

    def fake_run(profile, argv, cwd, *, output_limit, timeout_seconds):
        calls.append((profile, argv, cwd))
        return CommandResult(profile, " ".join(argv), 0, "tool 1.0\n", "", False)

    monkeypatch.setattr(runner, "_trusted_executable", lambda name: f"/trusted/{name}")
    monkeypatch.setattr(runner, "_run_argv", fake_run)
    runner.inspect_runtime_versions(tmp_path / "project")

    assert calls
    assert all(".venv" not in argv[0] for _, argv, _ in calls)
    assert all(cwd == runner.runtime_home for _, _, cwd in calls)


def test_truncated_tracked_inventory_fails_closed(tmp_path: Path, monkeypatch) -> None:
    runner = FixedRunner(tmp_path / "control")

    monkeypatch.setattr(FixedRunner, "_git", staticmethod(lambda args: ["/trusted/git", *args]))
    monkeypatch.setattr(
        runner,
        "_run_argv",
        lambda *args, **kwargs: CommandResult("git_tracked_paths", "git ls-files", 0, "one", "", False, True),
    )

    with pytest.raises(PolicyError, match="inventory was truncated"):
        runner.tracked_paths(tmp_path / "project")


def test_broker_workspace_observe_is_high_level_policy_checked_tool(broker, workspace: Path) -> None:
    (workspace / "README.md").write_text("demo\n", encoding="utf-8")
    add_scope(broker, workspace, scope_id="demo-project", kind=ScopeKind.PROJECT.value)
    allow_capabilities(broker, "demo-project", "read")

    result = broker.invoke(
        "workspace_observe",
        {"project_id": "demo-project", "max_items": 20},
        actor="chatgpt",
    )

    assert result["status"] == "ok"
    assert result["project"]["id"] == "demo-project"
    assert result["snapshot_id"]


def test_cli_doctor_uses_registered_project_and_returns_json(tmp_path: Path, capsys) -> None:
    data_dir = tmp_path / "control"
    project = tmp_path / "project"
    project.mkdir()
    (project / "README.md").write_text("demo\n", encoding="utf-8")

    assert main(
        [
            "--data-dir",
            str(data_dir),
            "add-scope",
            "--scope-id",
            "demo-project",
            "--label",
            "Demo",
            "--kind",
            "project",
            "--root",
            str(project),
        ]
    ) == 0
    capsys.readouterr()

    assert main(["--data-dir", str(data_dir), "doctor", "demo-project"]) == 0
    output = json.loads(capsys.readouterr().out)

    assert output["status"] == "ok"
    assert output["project"]["id"] == "demo-project"


def test_scope_removal_cleans_workspace_metadata(broker, workspace: Path) -> None:
    (workspace / "README.md").write_text("demo\n", encoding="utf-8")
    add_scope(broker, workspace, scope_id="demo-project", kind=ScopeKind.PROJECT.value)
    allow_capabilities(broker, "demo-project", "read")
    scope = WorkspaceScope.from_scope(broker.store.get_scope("demo-project"))
    snapshot = broker.workspace_engine.observe(scope)
    package = broker.workspace_engine.prepare(
        WorkRequest(project_id="demo-project", goal="inspect project", mode="diagnose")
    )

    assert broker.remove_scope("demo-project")["status"] == "ok"
    assert broker.store.get_workspace_snapshot(snapshot["snapshot_id"]) is None
    assert broker.store.get_workspace_run(package["run_id"]) is None


def test_evidence_hash_mismatch_fails_closed(broker, workspace: Path) -> None:
    (workspace / "README.md").write_text("demo\n", encoding="utf-8")
    add_scope(broker, workspace, scope_id="demo-project", kind=ScopeKind.PROJECT.value)
    allow_capabilities(broker, "demo-project", "read")
    package = broker.workspace_engine.prepare(
        WorkRequest(project_id="demo-project", goal="inspect project", mode="diagnose")
    )
    with broker.store._lock:
        broker.store._conn.execute(
            "UPDATE workspace_evidence SET payload_json=? WHERE run_id=? AND sequence=1",
            ('{"status":"tampered"}', package["run_id"]),
        )
        broker.store._conn.commit()

    with pytest.raises(StorageError, match="hash mismatch"):
        broker.store.workspace_evidence(package["run_id"])
