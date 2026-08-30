from __future__ import annotations

from pathlib import Path

from .conftest import add_scope, allow_capabilities, enable_tools


def _approve_and_apply(broker, pending: dict) -> dict:
    assert pending["status"] == "approval_required", pending
    approval_id = pending["approval_id"]
    assert broker.approve(approval_id)["status"] == "ok"
    result = broker.invoke("apply_approved_action", {"approval_id": approval_id}, actor="user")
    assert result["status"] == "ok", result
    return result


def test_write_executes_immediately_with_backup(broker, workspace: Path) -> None:
    target = workspace / "note.txt"
    target.write_text("before", encoding="utf-8")
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read", "write")
    enable_tools(broker, "write_file")

    result = broker.invoke(
        "write_file",
        {"scope_id": "test-scope", "relative_path": "note.txt", "content": "after"},
        session_id="session-a",
        request_id="request-a",
    )
    assert result["status"] == "ok", result
    assert result["executed"] is True

    assert target.read_text(encoding="utf-8") == "after"
    assert result["content_hash"].startswith("sha256:")
    assert list(broker.snapshot_root.rglob("*"))

    replay = broker.invoke(
        "write_file",
        {"scope_id": "test-scope", "relative_path": "note.txt", "content": "after again"},
    )
    assert replay["status"] == "ok", replay


def test_delete_approval_fails_closed_when_target_changes(broker, workspace: Path) -> None:
    target = workspace / "note.txt"
    target.write_text("before", encoding="utf-8")
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read", "delete")
    enable_tools(broker, "delete_file")

    pending = broker.invoke(
        "delete_file",
        {"scope_id": "test-scope", "relative_path": "note.txt"},
    )
    target.write_text("changed by another actor", encoding="utf-8")
    assert broker.approve(pending["approval_id"])["status"] == "ok"
    result = broker.invoke("apply_approved_action", {"approval_id": pending["approval_id"]}, actor="user")

    assert result["error_code"] == "PRECONDITION_CHANGED"
    assert target.read_text(encoding="utf-8") == "changed by another actor"
    assert broker.store.get_approval(pending["approval_id"]).status == "consumed"


def test_file_lifecycle_requires_separate_capabilities(broker, workspace: Path) -> None:
    source = workspace / "source.txt"
    source.write_text("move me", encoding="utf-8")
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read", "rename", "move", "create", "delete")
    enable_tools(broker, "rename_file", "move_file", "create_file", "delete_file")

    renamed = broker.invoke(
        "rename_file",
        {"scope_id": "test-scope", "relative_path": "source.txt", "new_name": "renamed.txt"},
    )
    assert renamed["status"] == "ok", renamed
    assert renamed["executed"] is True
    assert (workspace / "renamed.txt").exists()

    created = broker.invoke(
        "create_file",
        {"scope_id": "test-scope", "relative_path": "created.txt", "content": "created"},
    )
    assert created["status"] == "ok", created
    assert created["executed"] is True
    assert (workspace / "created.txt").read_text(encoding="utf-8") == "created"

    deleted = broker.invoke("delete_file", {"scope_id": "test-scope", "relative_path": "created.txt"})
    _approve_and_apply(broker, deleted)
    assert not (workspace / "created.txt").exists()


def test_create_directory_is_immediate_and_requires_existing_parent(broker, workspace: Path) -> None:
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read", "create")
    enable_tools(broker, "create_directory")

    result = broker.invoke(
        "create_directory",
        {"scope_id": "test-scope", "relative_path": "01_ATM_MRP_Factory"},
    )
    assert result["status"] == "ok", result
    assert result["executed"] is True
    assert result["created"] is True
    assert result["kind"] == "directory"
    assert (workspace / "01_ATM_MRP_Factory").is_dir()
    assert broker.pending_approvals() == []

    missing_parent = broker.invoke(
        "create_directory",
        {"scope_id": "test-scope", "relative_path": "02_Missing/Child"},
    )
    assert missing_parent["status"] == "denied", missing_parent
    assert missing_parent["error_code"] == "PARENT_NOT_FOUND"

    existing = broker.invoke(
        "create_directory",
        {"scope_id": "test-scope", "relative_path": "01_ATM_MRP_Factory"},
    )
    assert existing["status"] == "denied", existing
    assert existing["error_code"] == "TARGET_EXISTS"


def test_bulk_move_files_preflights_then_moves_explicit_batch(broker, workspace: Path) -> None:
    first = workspace / "TA_2026.pdf"
    second = workspace / "ASS09_BIT07.pdf"
    destination = workspace / "01_University_BIT"
    first.write_text("first", encoding="utf-8")
    second.write_text("second", encoding="utf-8")
    destination.mkdir()
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read", "move", "create")
    enable_tools(broker, "bulk_move_files")

    result = broker.invoke(
        "bulk_move_files",
        {
            "source_scope_id": "test-scope",
            "source_relative_paths": ["TA_2026.pdf", "ASS09_BIT07.pdf"],
            "destination_scope_id": "test-scope",
            "destination_relative_directory": "01_University_BIT",
        },
    )

    assert result["status"] == "ok", result
    assert result["executed"] is True
    assert result["requested"] == 2
    assert result["moved"] == 2
    assert result["items"] == [
        {"source_relative_path": "TA_2026.pdf", "destination_relative_path": "01_University_BIT/TA_2026.pdf"},
        {"source_relative_path": "ASS09_BIT07.pdf", "destination_relative_path": "01_University_BIT/ASS09_BIT07.pdf"},
    ]
    assert not first.exists()
    assert not second.exists()
    assert (destination / first.name).read_text(encoding="utf-8") == "first"
    assert (destination / second.name).read_text(encoding="utf-8") == "second"
    assert broker.pending_approvals() == []


def test_bulk_move_files_preflight_failure_moves_nothing(broker, workspace: Path) -> None:
    existing = workspace / "TA_2026.pdf"
    destination = workspace / "01_University_BIT"
    existing.write_text("keep here", encoding="utf-8")
    destination.mkdir()
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read", "move", "create")
    enable_tools(broker, "bulk_move_files")

    result = broker.invoke(
        "bulk_move_files",
        {
            "source_scope_id": "test-scope",
            "source_relative_paths": ["TA_2026.pdf", "missing.pdf"],
            "destination_scope_id": "test-scope",
            "destination_relative_directory": "01_University_BIT",
        },
    )

    assert result["status"] == "denied", result
    assert result["error_code"] == "TARGET_NOT_FOUND"
    assert existing.read_text(encoding="utf-8") == "keep here"
    assert not (destination / existing.name).exists()


def test_bulk_move_files_rejects_existing_destination_without_overwrite(broker, workspace: Path) -> None:
    source = workspace / "TA_2026.pdf"
    destination = workspace / "01_University_BIT"
    source.write_text("source", encoding="utf-8")
    destination.mkdir()
    (destination / source.name).write_text("original destination", encoding="utf-8")
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read", "move", "create")
    enable_tools(broker, "bulk_move_files")

    result = broker.invoke(
        "bulk_move_files",
        {
            "source_scope_id": "test-scope",
            "source_relative_paths": [source.name],
            "destination_scope_id": "test-scope",
            "destination_relative_directory": destination.name,
        },
    )

    assert result["status"] == "denied", result
    assert result["error_code"] == "TARGET_EXISTS"
    assert source.read_text(encoding="utf-8") == "source"
    assert (destination / source.name).read_text(encoding="utf-8") == "original destination"


def test_delete_approved_request_remains_visible_until_apply(broker, workspace: Path) -> None:
    target = workspace / "index.md"
    target.write_text("index", encoding="utf-8")
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read", "delete")
    enable_tools(broker, "delete_file")

    requested = broker.invoke(
        "delete_file",
        {"scope_id": "test-scope", "relative_path": "index.md"},
    )
    assert requested["status"] == "approval_required"
    assert requested["executed"] is False
    assert "No file change was made" in requested["message"]
    assert broker.approve(requested["approval_id"])["status"] == "ok"

    actionable = broker.actionable_approvals()
    assert len(actionable) == 1
    assert actionable[0]["id"] == requested["approval_id"]
    assert actionable[0]["status"] == "approved"
    assert target.exists()

    applied = broker.invoke("apply_approved_action", {"approval_id": requested["approval_id"]}, actor="user")
    assert applied["status"] == "ok", applied
    assert not target.exists()
