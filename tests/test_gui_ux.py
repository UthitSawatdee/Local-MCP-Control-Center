from __future__ import annotations

from types import SimpleNamespace

from local_mcp_control_center.gui import format_workspace_health
from local_mcp_control_center.gui_ux import ControlCenterUXApp, filter_tool_rows, tool_summary_text


def _rows():
    return [
        {
            "name": "list_files",
            "group": "filesystem",
            "risk": "low",
            "enabled": True,
            "approval_mode": "never",
            "description": "List files in an approved scope",
        },
        {
            "name": "delete_file",
            "group": "filesystem",
            "risk": "high",
            "enabled": False,
            "approval_mode": "always",
            "description": "Delete one approved file",
        },
        {
            "name": "runtime_status",
            "group": "runtime",
            "risk": "low",
            "enabled": True,
            "approval_mode": "never",
            "description": "Read runtime status",
        },
    ]


def test_filter_tool_rows_matches_visible_fields_case_insensitively() -> None:
    rows = _rows()
    assert [row["name"] for row in filter_tool_rows(rows, "RUNTIME")] == ["runtime_status"]
    assert [row["name"] for row in filter_tool_rows(rows, "always")] == ["delete_file"]
    assert [row["name"] for row in filter_tool_rows(rows, "approved scope")] == ["list_files"]


def test_filter_tool_rows_empty_query_returns_all_rows() -> None:
    rows = _rows()
    assert filter_tool_rows(rows, "   ") == rows


def test_refresh_tools_preserves_selected_tool_after_rows_are_rebuilt() -> None:
    class FakeTree:
        def __init__(self) -> None:
            self.items = ["list_files", "runtime_status"]
            self.selected = ["runtime_status"]

        def get_children(self):
            return tuple(self.items)

        def selection(self):
            return tuple(self.selected)

        def delete(self, item):
            self.items.remove(item)
            self.selected = [value for value in self.selected if value != item]

        def insert(self, _parent, _index, *, iid, values):
            self.items.append(iid)

        def selection_set(self, *items):
            self.selected = list(items)

    rows = _rows()
    tree = FakeTree()
    app = object.__new__(ControlCenterUXApp)
    app.tool_tree = tree
    app.tool_search_var = SimpleNamespace(get=lambda: "")
    app.tool_summary = SimpleNamespace(set=lambda _value: None)
    app._bridge_status_cache = {}
    app.broker = SimpleNamespace(tool_rows=lambda: rows)

    app._refresh_tools()

    assert tree.selected == ["runtime_status"]


def test_tool_summary_text_reports_registry_policy_and_running_counts() -> None:
    assert tool_summary_text(
        _rows(),
        1,
        {"state": "stale", "stale": True, "running_tool_count": 1},
    ) == "Registry total 3  •  Enabled 2  •  Running bridge tools 1  •  Bridge stale  •  Showing 1"


def test_workspace_health_summary_is_compact_and_explicit() -> None:
    summary = format_workspace_health(
        {
            "project": {"id": "atm", "name": "ATM"},
            "git": {"state": "dirty", "branch": "main", "ahead": 1, "behind": 0},
            "runtime": {"python": {"state": "available", "version": "Python 3.12.4"}},
            "services": {"backend": {"state": "listening", "port": 8100}},
            "capsule_drift": [{"area": "runtime.node"}],
            "environment": {"tracked_environment_warnings": [{"relative_path": ".env", "reason": "tracked_environment_file"}]},
            "unfinished_runs": [{"run_id": "run-1"}],
            "warnings": [{"code": "DIRTY_REPOSITORY"}],
            "filesystem": {"file_count": 12, "bytes": 2048},
        }
    )

    assert "Project: ATM (atm)" in summary
    assert "Git: dirty · main · ahead 1" in summary
    assert "Runtime: 1/1 available" in summary
    assert "Capsule drift: 1" in summary
    assert "Tracked environment warnings: 1" in summary
    assert "Unfinished runs: 1" in summary
