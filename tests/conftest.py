from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from local_mcp_control_center.broker import Broker
from local_mcp_control_center.storage import Store


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir()
    return root


@pytest.fixture
def broker(tmp_path: Path) -> Iterator[Broker]:
    state = tmp_path / "state"
    store = Store(state / "control.sqlite3", state)
    instance = Broker(store)
    try:
        yield instance
    finally:
        store.close()


def add_scope(
    broker: Broker,
    root: Path,
    *,
    scope_id: str = "test-scope",
    kind: str = "directory",
    expose: bool = True,
) -> None:
    result = broker.add_scope(
        scope_id=scope_id,
        label=scope_id,
        kind=kind,
        root=str(root),
        expose_to_mcp=expose,
    )
    assert result["status"] == "ok", result


def allow_capabilities(broker: Broker, scope_id: str, *capabilities: str) -> None:
    for capability in capabilities:
        result = broker.set_permission(
            scope_id,
            capability,
            allowed=True,
            approval_mode="always" if capability == "delete" else "never",
        )
        assert result["status"] == "ok", result


def enable_tools(broker: Broker, *tool_names: str) -> None:
    for tool_name in tool_names:
        current = broker.store.get_tool_policy(tool_name)
        assert current is not None
        result = broker.set_tool_policy(
            tool_name,
            enabled=True,
            approval_mode=current.approval_mode,
        )
        assert result["status"] == "ok", result
