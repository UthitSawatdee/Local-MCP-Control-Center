from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from local_mcp_control_center.mcp_server import build_server
from local_mcp_control_center.registry import TOOL_BY_NAME
from local_mcp_control_center.runner import FixedRunner
import local_mcp_control_center.runner as runner_module


def test_runner_rejects_arbitrary_profile(broker, workspace: Path) -> None:
    with pytest.raises(Exception) as error:
        broker.runner._profile("shell", workspace)
    assert getattr(error.value, "code", None) == "PROFILE_NOT_ALLOWED"


def test_runner_never_uses_a_shell(monkeypatch, broker, workspace: Path) -> None:
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout=b"ok", stderr=b"")

    monkeypatch.setattr(runner_module.subprocess, "run", fake_run)
    result = FixedRunner(broker.store.data_dir).run("git_status", workspace)

    assert result.exit_code == 0
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["stdin"] is runner_module.subprocess.DEVNULL
    assert all(isinstance(part, str) for part in captured["argv"])


def test_mcp_registry_contains_only_explicit_tools(broker) -> None:
    server = build_server(broker)
    names = {tool.name for tool in server._tool_manager.list_tools()}
    assert names == {name for name, definition in TOOL_BY_NAME.items() if definition.default_enabled}
    assert all(tool.fn_metadata.output_schema for tool in server._tool_manager.list_tools())
    assert not {"shell", "exec", "run_command", "python", "node_eval", "docker"} & set(TOOL_BY_NAME)


def test_bulk_move_tool_schema_requires_explicit_path_list(broker) -> None:
    server = build_server(broker)
    tool = next(tool for tool in server._tool_manager.list_tools() if tool.name == "bulk_move_files")
    schema = tool.fn_metadata.arg_model.model_json_schema()

    assert schema["required"] == ["source_scope_id", "source_relative_paths", "destination_scope_id"]
    assert schema["properties"]["source_relative_paths"] == {
        "items": {"type": "string"},
        "title": "Source Relative Paths",
        "type": "array",
    }
