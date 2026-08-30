from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from local_mcp_control_center.agent_tasks import AgentProfile

from .conftest import add_scope, allow_capabilities, enable_tools


def test_tool_batch_keeps_child_policy_scope_and_audit_independent(broker, workspace: Path) -> None:
    (workspace / "app.py").write_text("def execute():\n    return 'safe'\n", encoding="utf-8")
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read")
    enable_tools(broker, "tool_batch")

    result = broker.invoke(
        "tool_batch",
        {
            "scope_id": "test-scope",
            "operations": [
                {"operation": "read_file", "arguments": {"relative_path": "app.py"}},
                {"operation": "search_text", "arguments": {"query": "execute"}},
                {"operation": "write_file", "arguments": {"relative_path": "app.py", "content": "changed"}},
                {"operation": "read_file", "arguments": {"scope_id": "other-scope", "relative_path": "app.py"}},
            ],
        },
        session_id="batch-session",
        trace_id="batch-trace",
    )

    assert result["status"] == "ok"
    assert [item["status"] for item in result["results"]] == ["ok", "ok", "error", "error"]
    assert result["results"][2]["error_code"] == "NON_READ_OPERATION"
    assert result["results"][3]["error_code"] == "DISPATCHER_EXCEPTION"
    assert result["succeeded"] == 2
    assert result["failed"] == 2
    assert (workspace / "app.py").read_text(encoding="utf-8").endswith("safe'\n")
    assert all("safe" not in json.dumps(item) for item in result["results"][2:])

    audit = broker.store.audit_rows(100)
    assert any(row["tool"] == "tool_batch" and row["trace_id"] == "batch-trace" for row in audit)
    assert any(row["tool"] == "read_file" and row["trace_id"] == "batch-trace" for row in audit)
    assert broker.verify_audit()["valid"] is True


def test_dependency_graph_is_scope_bound_and_returns_metadata_only(broker, workspace: Path) -> None:
    (workspace / "main.py").write_text("from . import util\n", encoding="utf-8")
    (workspace / "util.py").write_text("value = 1\n", encoding="utf-8")
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read")

    result = broker.invoke(
        "dependency_graph",
        {"scope_id": "test-scope", "path": ".", "max_files": 10, "max_edges": 10},
        trace_id="graph-trace",
    )

    assert result["status"] == "ok"
    assert result["scope_id"] == "test-scope"
    assert result["relative_path"] == "."
    assert result["state"] == "ready"
    assert {node["relative_path"] for node in result["nodes"]} == {"main.py", "util.py"}
    assert any(edge["source"] == "main.py" and edge["target"] == "util.py" for edge in result["edges"])
    assert "from . import util" not in json.dumps(result)
    assert broker.store.audit_rows(1)[0]["trace_id"] == "graph-trace"

    invalid = broker.invoke(
        "dependency_graph",
        {"scope_id": "test-scope", "path": "main.py"},
    )
    assert invalid["error_code"] == "INVALID_SCOPE"


def test_workspace_context_ledger_omits_duplicate_snippets_and_detects_change(
    broker, workspace: Path
) -> None:
    target = workspace / "service.py"
    target.write_text("def execute():\n    return 'before'\n", encoding="utf-8")
    add_scope(broker, workspace)
    allow_capabilities(broker, "test-scope", "read")

    arguments = {
        "scope_id": "test-scope",
        "query": "execute",
        "path": ".",
        "delivery_key": "service-context",
    }
    first = broker.invoke("workspace_context", arguments)
    assert first["status"] == "ok"
    assert first["context_delivery"]["status"] == "delivered"
    assert any(item.get("snippets") for item in first["files"])

    duplicate = broker.invoke("workspace_context", arguments)
    assert duplicate["context_delivery"]["status"] == "unchanged"
    assert duplicate["content_reused"] is True
    assert all("snippets" not in item for item in duplicate["files"])
    assert all(item.get("snippets_omitted") is True for item in duplicate["files"] if item.get("reasons"))

    target.write_text("def execute():\n    return 'after'\n", encoding="utf-8")
    changed = broker.invoke("workspace_context", arguments)
    assert changed["context_delivery"]["status"] == "changed"
    assert changed.get("content_reused", False) is False
    assert json.dumps(changed, ensure_ascii=False)
    assert broker.verify_audit()["valid"] is True


def test_agent_tools_require_configured_profile_and_keep_task_scope_visible(
    broker, workspace: Path
) -> None:
    add_scope(broker, workspace, kind="project")
    allow_capabilities(broker, "test-scope", "read", "execute")
    enable_tools(
        broker,
        "agent_status",
        "agent_task_status",
        "agent_task_logs",
        "agent_result",
        "agent_run",
    )

    configured = AgentProfile(
        "python-test",
        sys.executable,
        ("-c", "print('agent-ok')"),
        timeout_seconds=2,
        allowed_scope_ids=frozenset({"test-scope"}),
    )
    assert broker.configure_agent_profile(configured)["status"] == "ok"
    status = broker.invoke("agent_status")
    assert status["profiles"] == ["python-test"]
    assert status["tasks"] == []

    invalid = broker.invoke(
        "agent_run",
        {
            "scope_id": "test-scope",
            "profile": "python-test",
            "prompt": "safe prompt",
            "argv": ["--not-accepted"],
        },
    )
    assert invalid["error_code"] == "INVALID_INPUT"

    started = broker.invoke(
        "agent_run",
        {"scope_id": "test-scope", "profile": "python-test", "prompt": "safe prompt"},
        trace_id="agent-trace",
    )
    assert started["status"] == "ok", started
    task_id = started["task_id"]
    deadline = time.monotonic() + 3
    task_status = started
    while time.monotonic() < deadline and task_status["state"] not in {
        "completed",
        "failed",
        "timed_out",
        "cancelled",
    }:
        time.sleep(0.01)
        task_status = broker.invoke("agent_task_status", {"task_id": task_id})
    assert task_status["state"] == "completed", task_status
    result = broker.invoke("agent_result", {"task_id": task_id})
    assert result["result_available"] is True
    assert "agent-ok" in result["stdout"]
    assert "safe prompt" not in json.dumps(result)
    logs = broker.invoke("agent_task_logs", {"task_id": task_id})
    assert logs["status"] == "ok"
    assert any("agent-ok" in entry["text"] for entry in logs["entries"])
    assert any(row["tool"] == "agent_run" and row["trace_id"] == "agent-trace" for row in broker.store.audit_rows(100))
