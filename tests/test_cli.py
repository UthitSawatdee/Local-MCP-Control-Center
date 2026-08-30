from __future__ import annotations

import json
from pathlib import Path

from local_mcp_control_center.cli import main


def test_cli_add_scope_is_read_only_by_default(tmp_path: Path, capsys) -> None:
    data_dir = tmp_path / "state"
    root = tmp_path / "selected"
    root.mkdir()
    assert main(["--data-dir", str(data_dir), "add-scope", "--scope-id", "selected", "--label", "Selected", "--root", str(root)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "ok"
    assert output["scope"]["permissions"]["read"]["allowed"] is True
    assert all(not value["allowed"] for key, value in output["scope"]["permissions"].items() if key != "read")

    assert main(["--data-dir", str(data_dir), "list-scopes"]) == 0
    listed = json.loads(capsys.readouterr().out)
    assert listed["scopes"][0]["root"] == str(root.resolve())
