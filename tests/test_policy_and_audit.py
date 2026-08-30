from __future__ import annotations

import os
from pathlib import Path

from local_mcp_control_center.models import Scope
from local_mcp_control_center.policy import PolicyEngine
from local_mcp_control_center.storage import Store

from .conftest import add_scope, allow_capabilities


def test_scope_is_relative_and_protected(broker, workspace: Path, tmp_path: Path) -> None:
    (workspace / "notes.txt").write_text("hello", encoding="utf-8")
    (workspace / ".env").write_text("TOKEN=do-not-read", encoding="utf-8")
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read")

    traversal = broker.invoke("read_file", {"scope_id": "test-scope", "relative_path": "../outside.txt"})
    absolute = broker.invoke("read_file", {"scope_id": "test-scope", "relative_path": str(workspace / "notes.txt")})
    protected = broker.invoke("read_file", {"scope_id": "test-scope", "relative_path": ".env"})

    assert traversal["error_code"] == "PATH_TRAVERSAL"
    assert absolute["error_code"] == "PATH_ABSOLUTE"
    assert protected["error_code"] == "PROTECTED_TARGET"

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    link = workspace / "link"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        return
    escaped = broker.invoke("read_file", {"scope_id": "test-scope", "relative_path": "link/secret.txt"})
    assert escaped["error_code"] in {"PATH_ESCAPE", "SYMLINK_NOT_ALLOWED"}


def test_overlapping_scope_is_rejected(broker, workspace: Path, tmp_path: Path) -> None:
    add_scope(broker, workspace, scope_id="first")
    child = workspace / "child"
    child.mkdir()
    result = broker.add_scope(
        scope_id="second",
        label="second",
        kind="directory",
        root=str(child),
    )
    assert result["status"] == "denied"
    assert result["error_code"] == "SCOPE_OVERLAP"


def test_protected_file_cannot_be_registered_as_a_scope(broker, tmp_path: Path) -> None:
    protected = tmp_path / ".env"
    protected.write_text("TOKEN=do-not-read", encoding="utf-8")
    result = broker.add_scope(
        scope_id="secret-file",
        label="secret-file",
        kind="file",
        root=str(protected),
    )
    assert result["status"] == "denied"
    assert result["error_code"] == "PROTECTED_TARGET"


def test_file_scope_exposes_only_the_selected_file(broker, tmp_path: Path) -> None:
    selected = tmp_path / "selected.txt"
    selected.write_text("selected", encoding="utf-8")
    result = broker.add_scope(
        scope_id="selected-file",
        label="selected-file",
        kind="file",
        root=str(selected),
        expose_to_mcp=True,
    )
    assert result["status"] == "ok", result
    assert broker.invoke("read_file", {"scope_id": "selected-file", "relative_path": "."})["content"] == "selected"
    denied = broker.invoke("read_file", {"scope_id": "selected-file", "relative_path": "other.txt"})
    assert denied["error_code"] == "PATH_NOT_ALLOWED"


def test_audit_hash_chain_detects_tampering(broker) -> None:
    broker.audit.record(actor="user", tool="test", operation="one", decision="executed")
    broker.audit.record(actor="user", tool="test", operation="two", decision="denied", error_code="TEST")
    assert broker.verify_audit()["valid"] is True

    with broker.store._lock:
        broker.store._conn.execute("UPDATE audit_events SET target_display='tampered' WHERE seq=1")
        broker.store._conn.commit()
    result = broker.verify_audit()
    assert result["valid"] is False
    assert "hash" in result["message"]


def test_data_directory_and_audit_files_are_private(broker) -> None:
    mode = os.stat(broker.store.data_dir).st_mode & 0o777
    assert mode == 0o700
    db_mode = os.stat(broker.store.db_path).st_mode & 0o777
    assert db_mode == 0o600


def test_existing_policy_migrates_to_delete_only_approval(tmp_path: Path) -> None:
    state = tmp_path / "state"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    db_path = state / "control.sqlite3"

    legacy = Store(db_path, state)
    legacy.add_scope(
        Scope(
            id="scope",
            label="scope",
            kind="directory",
            root=str(workspace),
            expose_to_mcp=True,
        ),
        permissions={"read": {"allowed": True}},
    )
    with legacy._lock:
        legacy._conn.execute("UPDATE tool_policies SET approval_mode='always'")
        legacy._conn.execute("UPDATE tool_policies SET enabled=0 WHERE tool_name='apply_approved_action'")
        legacy._conn.execute("UPDATE scope_permissions SET approval_mode='always'")
        legacy._conn.commit()
    legacy.close()

    migrated = Store(db_path, state)
    try:
        assert migrated.get_tool_policy("write_file").approval_mode == "never"
        assert migrated.get_tool_policy("run_build").approval_mode == "never"
        assert migrated.get_tool_policy("delete_file").approval_mode == "always"
        assert migrated.get_tool_policy("apply_approved_action").enabled is True
        permissions = migrated.permissions("scope")
        assert permissions["read"]["approval_mode"] == "never"
        assert permissions["delete"]["approval_mode"] == "always"

        engine = PolicyEngine(migrated)
        assert engine.approval_required("write_file", {"approval_mode": "always"}, "overwrite") is False
        assert engine.approval_required("run_build", {"approval_mode": "always"}, "execute") is False
        assert engine.approval_required("delete_file", {"approval_mode": "never"}, "delete") is True
    finally:
        migrated.close()
