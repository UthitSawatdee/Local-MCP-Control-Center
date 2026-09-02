from __future__ import annotations

import local_mcp_control_center.mcp_server as mcp_server
from local_mcp_control_center.registry import TOOL_DEFINITIONS


def test_bridge_status_tracks_snapshot_and_policy_staleness(broker) -> None:
    expected_enabled = sum(definition.default_enabled for definition in TOOL_DEFINITIONS)

    initial = broker.bridge_status()
    assert initial == {
        "state": "stopped",
        "stale": False,
        "registry_total": len(TOOL_DEFINITIONS),
        "enabled_count": expected_enabled,
        "running_tool_count": 0,
        "policy_version": initial["policy_version"],
        "running_policy_version": None,
        "pid": None,
        "started_at": None,
    }

    broker.record_mcp_bridge_snapshot(expected_enabled)
    ready = broker.bridge_status()
    assert ready["state"] == "ready"
    assert ready["stale"] is False
    assert ready["running_tool_count"] == expected_enabled
    assert ready["running_policy_version"] == ready["policy_version"]

    current = broker.store.get_tool_policy("write_file")
    assert current is not None
    changed = broker.set_tool_policy(
        "write_file",
        enabled=not current.enabled,
        approval_mode=current.approval_mode,
    )

    assert changed["status"] == "ok"
    assert changed["bridge"]["state"] == "stale"
    assert changed["bridge"]["stale"] is True
    stale = broker.bridge_status()
    assert stale["state"] == "stale"
    assert stale["running_tool_count"] == expected_enabled
    assert stale["running_policy_version"] != stale["policy_version"]


def test_run_stdio_clears_bridge_snapshot_after_server_stops(monkeypatch, broker) -> None:
    class FakeToolManager:
        def list_tools(self):
            return [object(), object(), object()]

    class FakeServer:
        _tool_manager = FakeToolManager()

        def run(self, *, transport: str) -> None:
            assert transport == "stdio"
            snapshot = broker.store.get_mcp_bridge_snapshot()
            assert snapshot is not None
            assert snapshot["tool_count"] == 3

    monkeypatch.setattr(mcp_server, "build_server", lambda _broker: FakeServer())

    mcp_server.run_stdio(broker)

    assert broker.store.get_mcp_bridge_snapshot() is None
