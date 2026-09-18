from __future__ import annotations

from typing import Any

import pytest

from local_mcp_control_center.errors import PolicyError
from local_mcp_control_center.mcp_server import build_server
from local_mcp_control_center.motion_erp import MotionERPService

from .conftest import enable_tools


class _UnusedBrowser:
    pass


def test_motion_calendar_month_converts_to_bangkok_and_sums_hours(monkeypatch) -> None:
    service = MotionERPService(_UnusedBrowser())  # type: ignore[arg-type]

    def fake_search_read(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        return [
            {
                "id": 10,
                "name": "Project ATM - Planning",
                "start": "2026-09-03 02:00:00",
                "stop": "2026-09-03 03:30:00",
                "duration": 1.5,
                "allday": False,
                "user_id": [7, "Uthit"],
            }
        ]

    monkeypatch.setattr(service, "_search_read", fake_search_read)
    result = service.calendar_month("br_test", "2026-09")

    assert result["event_count"] == 1
    assert result["total_hours"] == 1.5
    assert result["events"][0]["start"] == "2026-09-03T09:00+07:00"
    assert result["events"][0]["stop"] == "2026-09-03T10:30+07:00"
    assert result["events"][0]["date"] == "2026-09-03"
    assert result["events"][0]["organizer"] == {"id": 7, "name": "Uthit"}


def test_motion_calendar_month_rejects_invalid_month() -> None:
    service = MotionERPService(_UnusedBrowser())  # type: ignore[arg-type]
    with pytest.raises(PolicyError) as error:
        service.calendar_month("br_test", "09/2026")
    assert error.value.code == "INVALID_INPUT"


def test_timesheet_create_missing_is_idempotent_and_conflict_safe(monkeypatch) -> None:
    service = MotionERPService(_UnusedBrowser())  # type: ignore[arg-type]
    monkeypatch.setattr(
        service,
        "_fields_get",
        lambda *_args, **_kwargs: {
            "id": {"type": "integer"},
            "date": {"type": "date"},
            "name": {"type": "char"},
            "unit_amount": {"type": "float"},
            "project_id": {"type": "many2one"},
            "task_id": {"type": "many2one"},
            "user_id": {"type": "many2one"},
        },
    )
    monkeypatch.setattr(service, "_session_uid", lambda *_args, **_kwargs: 7)

    calls: list[tuple[str, str]] = []

    def fake_search_read(_session: str, model: str, domain: list[list[Any]], *_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
        calls.append((model, str(domain)))
        description = next((item[2] for item in domain if item[0] == "name"), "")
        if description == "Already logged":
            return [{"id": 101, "unit_amount": 2.0}]
        if description == "Conflict":
            return [{"id": 102, "unit_amount": 3.0}]
        return []

    monkeypatch.setattr(service, "_search_read", fake_search_read)
    create_calls: list[dict[str, Any]] = []

    def fake_call_kw(_session: str, model: str, method: str, args: list[Any], _kwargs: dict[str, Any]) -> int:
        assert model == "account.analytic.line"
        assert method == "create"
        create_calls.append(args[0])
        return 900 + len(create_calls)

    monkeypatch.setattr(service, "_call_kw", fake_call_kw)

    entries = [
        {"date": "2026-09-03", "project_id": 10, "task_id": 20, "description": "Already logged", "hours": 2.0},
        {"date": "2026-09-03", "project_id": 10, "task_id": 21, "description": "Conflict", "hours": 2.5},
        {"date": "2026-09-03", "project_id": 10, "task_id": 22, "description": "New work", "hours": 1.5},
    ]

    blocked = service.create_missing_timesheets("br_test", entries, dry_run=False)
    assert blocked["skipped_count"] == 1
    assert blocked["conflict_count"] == 1
    assert blocked["planned_count"] == 1
    assert blocked["created_count"] == 0
    assert blocked["can_apply"] is False
    assert create_calls == []

    preview = service.create_missing_timesheets("br_test", [entries[2]], dry_run=True)
    assert preview["planned_count"] == 1
    assert preview["created_count"] == 0
    assert preview["can_apply"] is True

    applied = service.create_missing_timesheets("br_test", [entries[2]], dry_run=False)
    assert applied["created_count"] == 1
    assert applied["created"][0]["id"] == 901
    assert create_calls[0]["name"] == "New work"
    assert create_calls[0]["unit_amount"] == 1.5
    assert create_calls[0]["user_id"] == 7


def test_timesheet_validation_rejects_invalid_hours() -> None:
    service = MotionERPService(_UnusedBrowser())  # type: ignore[arg-type]
    with pytest.raises(PolicyError) as error:
        service._normalize_timesheet_entry(
            {"date": "2026-09-03", "project_id": 10, "description": "Bad", "hours": 25}
        )
    assert error.value.code == "INVALID_INPUT"


def test_timesheet_create_missing_rejects_duplicate_business_keys_before_lookup(monkeypatch) -> None:
    service = MotionERPService(_UnusedBrowser())  # type: ignore[arg-type]
    monkeypatch.setattr(
        service,
        "_fields_get",
        lambda *_args, **_kwargs: {
            "id": {"type": "integer"},
            "date": {"type": "date"},
            "name": {"type": "char"},
            "unit_amount": {"type": "float"},
            "project_id": {"type": "many2one"},
            "task_id": {"type": "many2one"},
            "user_id": {"type": "many2one"},
        },
    )
    monkeypatch.setattr(service, "_session_uid", lambda *_args, **_kwargs: 7)
    lookups: list[Any] = []
    monkeypatch.setattr(service, "_search_read", lambda *args, **kwargs: lookups.append((args, kwargs)) or [])

    entries = [
        {"date": "2026-09-03", "project_id": 10, "task_id": 20, "description": "Same work", "hours": 1.0},
        {"date": "2026-09-03", "project_id": 10, "task_id": 20, "description": " Same work ", "hours": 2.0},
    ]
    with pytest.raises(PolicyError) as error:
        service.create_missing_timesheets("br_test", entries, dry_run=True)

    assert error.value.code == "MOTION_TIMESHEET_DUPLICATE_ENTRY"
    assert lookups == []


def test_broker_blocks_live_motion_timesheet_creation_before_rpc(broker, monkeypatch) -> None:
    enable_tools(broker, "motion_timesheet_create_missing")
    calls: list[Any] = []

    def forbidden(*args: Any, **kwargs: Any) -> dict[str, Any]:
        calls.append((args, kwargs))
        raise AssertionError("live Motion ERP creation must be blocked at the broker")

    monkeypatch.setattr(broker.motion_erp, "create_missing_timesheets", forbidden)
    result = broker.invoke(
        "motion_timesheet_create_missing",
        {
            "browser_session_id": "br_test",
            "entries": [
                {"date": "2026-09-03", "project_id": 10, "task_id": 20, "description": "New work", "hours": 1.5},
            ],
            "dry_run": False,
        },
    )

    assert result["status"] == "denied"
    assert result["error_code"] == "MOTION_ERP_WRITE_REQUIRES_APPROVAL"
    assert "dry_run=true" in result["message"]
    assert calls == []


def test_dry_run_reports_motion_write_boundary_without_overstating_approval(broker) -> None:
    enable_tools(broker, "motion_timesheet_create_missing")
    result = broker.invoke(
        "dry_run",
        {
            "tool": "motion_timesheet_create_missing",
            "arguments": {
                "browser_session_id": "br_test",
                "entries": [
                    {
                        "date": "2026-09-03",
                        "project_id": 10,
                        "task_id": 20,
                        "description": "Preview only",
                        "hours": 1.5,
                    }
                ],
                "dry_run": True,
            },
        },
    )

    assert result["status"] == "preview"
    assert result["live_execution_supported"] is False
    assert result["live_approval_required"] is True
    assert result["live_approval_available"] is False
    assert "external-action approval binding" in result["live_block_reason"]

    generic = broker.invoke("dry_run", {"tool": "list_scopes", "arguments": {}})
    assert generic["status"] == "preview"
    assert generic["approval_required"] is False
    assert "live_execution_supported" not in generic
    assert "live_block_reason" not in generic


def test_motion_tools_are_registered_with_bounded_mcp_schemas(broker) -> None:
    server = build_server(broker)
    tools = {tool.name: tool for tool in server._tool_manager.list_tools()}
    expected = {
        "motion_calendar_month",
        "motion_project_task_search",
        "motion_timesheet_month",
        "motion_timesheet_create_missing",
    }
    assert expected <= set(tools)

    create_schema = tools["motion_timesheet_create_missing"].fn_metadata.arg_model.model_json_schema()
    assert set(create_schema["required"]) == {"browser_session_id", "entries"}
    assert create_schema["properties"]["dry_run"]["default"] is True
    assert "model" not in create_schema["properties"]
    assert "method" not in create_schema["properties"]
    assert "rpc_url" not in create_schema["properties"]

    calendar_schema = tools["motion_calendar_month"].fn_metadata.arg_model.model_json_schema()
    assert calendar_schema["properties"]["limit"]["maximum"] == 1000
    assert calendar_schema["properties"]["limit"]["default"] == 500
