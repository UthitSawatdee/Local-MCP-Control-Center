from __future__ import annotations

import json
from pathlib import Path

from local_mcp_control_center.cli import main
from local_mcp_control_center.mcp_server import build_server

from .conftest import enable_tools


def test_workspace_propose_action_mcp_tool_is_opt_in_and_bounded(broker) -> None:
    server = build_server(broker)
    assert "workspace_propose_action" not in {tool.name for tool in server._tool_manager.list_tools()}

    enable_tools(broker, "workspace_propose_action")
    server = build_server(broker)
    tool = next(tool for tool in server._tool_manager.list_tools() if tool.name == "workspace_propose_action")
    schema = tool.fn_metadata.arg_model.model_json_schema()

    assert set(schema["required"]) == {"run_id", "action"}
    assert set(schema["properties"]["action"]["enum"]) == {
        "owned_service_start",
        "owned_service_stop",
        "targeted_verification",
        "commit",
        "push",
    }
    assert schema["properties"]["parameters"]["anyOf"][0]["type"] == "object"


def test_cli_propose_action_rejects_non_object_parameters_before_dispatch(tmp_path: Path, capsys) -> None:
    data_dir = tmp_path / "control"

    exit_code = main(
        [
            "--data-dir",
            str(data_dir),
            "propose-action",
            "run-demo",
            "commit",
            "--parameters-json",
            "[]",
        ]
    )

    assert exit_code == 2
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "denied"
    assert output["error_code"] == "INVALID_INPUT"
