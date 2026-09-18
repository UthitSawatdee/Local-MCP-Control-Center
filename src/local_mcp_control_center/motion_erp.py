"""Strict Motion ERP adapters built on the owned authenticated browser session.

The MCP caller never supplies an RPC URL, model name, method name, cookies,
headers, JavaScript, or arbitrary Odoo arguments.  This module exposes only the
calendar/timesheet operations required by the monthly work-log workflow.
"""

from __future__ import annotations

import math
import re
from datetime import date, datetime, timedelta, timezone
from typing import Any, Mapping, Sequence
from zoneinfo import ZoneInfo

from .browser import LOCAL_BROWSER_PROFILE_NAME, BrowserManager
from .errors import PolicyError
from .filesystem import redact_text


MOTION_ERP_ORIGIN = "https://dynamics-motion.asia.motionerpcloud.com"
MOTION_ERP_TIMEZONE = ZoneInfo("Asia/Bangkok")
MAX_CALENDAR_EVENTS = 1000
MAX_LOOKUP_RESULTS = 50
MAX_TIMESHEET_LINES = 1000
MAX_TIMESHEET_CREATE_BATCH = 100
MAX_DESCRIPTION_CHARS = 500
_RPC_TIMEOUT_MS = 30_000
_MONTH_RE = re.compile(r"^(20[0-9]{2})-(0[1-9]|1[0-2])$")
_DATE_RE = re.compile(r"^(20[0-9]{2})-(0[1-9]|1[0-2])-([0-3][0-9])$")


class MotionERPService:
    """Bounded Odoo JSON-RPC operations for the Motion ERP profile only."""

    def __init__(self, browser: BrowserManager):
        self.browser = browser

    def calendar_month(self, session_id: str, month: str, *, limit: int = 500) -> dict[str, Any]:
        local_start, local_next = self._month_bounds(month)
        limit = self._bounded_limit(limit, maximum=MAX_CALENDAR_EVENTS)
        domain = [
            ["start", "<", self._odoo_utc(local_next)],
            ["stop", ">=", self._odoo_utc(local_start)],
        ]
        records = self._search_read(
            session_id,
            "calendar.event",
            domain,
            ["id", "name", "start", "stop", "duration", "allday", "user_id"],
            limit=limit,
            order="start asc",
        )
        events: list[dict[str, Any]] = []
        total_hours = 0.0
        for record in records:
            if not isinstance(record, Mapping):
                continue
            start_utc = self._parse_odoo_datetime(record.get("start"))
            stop_utc = self._parse_odoo_datetime(record.get("stop"))
            if start_utc is None or stop_utc is None or stop_utc < start_utc:
                continue
            start_local = start_utc.astimezone(MOTION_ERP_TIMEZONE)
            stop_local = stop_utc.astimezone(MOTION_ERP_TIMEZONE)
            overlap_start = max(start_local, local_start)
            overlap_stop = min(stop_local, local_next)
            hours_in_month = max(0.0, (overlap_stop - overlap_start).total_seconds() / 3600.0)
            raw_duration = record.get("duration")
            try:
                duration_hours = float(raw_duration)
                if not math.isfinite(duration_hours) or duration_hours < 0:
                    raise ValueError
            except (TypeError, ValueError):
                duration_hours = max(0.0, (stop_utc - start_utc).total_seconds() / 3600.0)
            title = redact_text(str(record.get("name") or ""))[:MAX_DESCRIPTION_CHARS]
            user_value = record.get("user_id")
            organizer = self._many2one(user_value)
            event = {
                "id": self._positive_int(record.get("id")),
                "title": title,
                "start": start_local.isoformat(timespec="minutes"),
                "stop": stop_local.isoformat(timespec="minutes"),
                "date": start_local.date().isoformat(),
                "duration_hours": round(duration_hours, 4),
                "hours_in_month": round(hours_in_month, 4),
                "all_day": bool(record.get("allday")),
                "organizer": organizer,
            }
            events.append(event)
            total_hours += hours_in_month
        return {
            "status": "ok",
            "month": month,
            "timezone": "Asia/Bangkok",
            "events": events,
            "event_count": len(events),
            "total_hours": round(total_hours, 4),
            "truncated": len(records) >= limit,
        }

    def project_task_search(
        self,
        session_id: str,
        query: str,
        *,
        project_id: int | None = None,
        limit: int = 20,
    ) -> dict[str, Any]:
        query = self._bounded_text(query, "query", max_chars=200)
        limit = self._bounded_limit(limit, maximum=MAX_LOOKUP_RESULTS)
        if project_id is not None:
            project_id = self._required_id(project_id, "project_id")
        projects = self._search_read(
            session_id,
            "project.project",
            [["name", "ilike", query]],
            ["id", "name"],
            limit=limit,
            order="name asc",
        )
        task_domain: list[list[Any]] = [["name", "ilike", query]]
        if project_id is not None:
            task_domain.append(["project_id", "=", project_id])
        tasks = self._search_read(
            session_id,
            "project.task",
            task_domain,
            ["id", "name", "project_id"],
            limit=limit,
            order="name asc",
        )
        return {
            "status": "ok",
            "query": query,
            "projects": [self._project_row(row) for row in projects if isinstance(row, Mapping)],
            "tasks": [self._task_row(row) for row in tasks if isinstance(row, Mapping)],
        }

    def timesheet_month(self, session_id: str, month: str, *, limit: int = 500) -> dict[str, Any]:
        local_start, local_next = self._month_bounds(month)
        limit = self._bounded_limit(limit, maximum=MAX_TIMESHEET_LINES)
        fields = self._fields_get(session_id, "account.analytic.line")
        requested = ["id", "date", "name", "unit_amount", "project_id", "task_id", "user_id"]
        selected = [field for field in requested if field in fields]
        required = {"id", "date", "name", "unit_amount", "project_id"}
        if not required <= set(selected):
            missing = ", ".join(sorted(required - set(selected)))
            raise PolicyError("MOTION_TIMESHEET_SCHEMA_UNSUPPORTED", f"timesheet model is missing required fields: {missing}")
        domain: list[list[Any]] = [
            ["date", ">=", local_start.date().isoformat()],
            ["date", "<", local_next.date().isoformat()],
        ]
        uid = self._session_uid(session_id)
        if "user_id" in fields and uid is not None:
            domain.append(["user_id", "=", uid])
        records = self._search_read(
            session_id,
            "account.analytic.line",
            domain,
            selected,
            limit=limit,
            order="date asc, id asc",
        )
        lines = [self._timesheet_row(row) for row in records if isinstance(row, Mapping)]
        return {
            "status": "ok",
            "month": month,
            "timezone": "Asia/Bangkok",
            "lines": lines,
            "line_count": len(lines),
            "total_hours": round(sum(float(row.get("hours") or 0.0) for row in lines), 4),
            "truncated": len(records) >= limit,
        }

    def create_missing_timesheets(
        self,
        session_id: str,
        entries: Sequence[Mapping[str, Any]],
        *,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        normalized = [self._normalize_timesheet_entry(item) for item in entries]
        if not normalized:
            raise PolicyError("INVALID_INPUT", "entries must contain at least one timesheet row")
        if len(normalized) > MAX_TIMESHEET_CREATE_BATCH:
            raise PolicyError("QUOTA_EXCEEDED", f"at most {MAX_TIMESHEET_CREATE_BATCH} timesheet rows can be created per call")

        fields = self._fields_get(session_id, "account.analytic.line")
        required = {"name", "date", "unit_amount", "project_id"}
        if not required <= set(fields):
            missing = ", ".join(sorted(required - set(fields)))
            raise PolicyError("MOTION_TIMESHEET_SCHEMA_UNSUPPORTED", f"timesheet model is missing required fields: {missing}")
        uid = self._session_uid(session_id)
        employee_id = self._employee_id(session_id, uid) if "employee_id" in fields else None
        employee_required = bool((fields.get("employee_id") or {}).get("required")) if "employee_id" in fields else False
        if employee_required and employee_id is None:
            raise PolicyError("MOTION_TIMESHEET_EMPLOYEE_NOT_FOUND", "current ERP user is not linked to an employee record")
        company_id = self._session_company_id(session_id) if "company_id" in fields else None

        create_plan: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        conflicts: list[dict[str, Any]] = []
        seen_keys: set[tuple[Any, ...]] = set()
        for entry in normalized:
            business_key = self._timesheet_business_key(
                entry,
                fields=fields,
                uid=uid,
                employee_id=employee_id,
                company_id=company_id,
            )
            if business_key in seen_keys:
                raise PolicyError(
                    "MOTION_TIMESHEET_DUPLICATE_ENTRY",
                    "entries contain duplicate date/project/task/description identity; submit one row per business key",
                )
            seen_keys.add(business_key)
        for entry in normalized:
            domain: list[list[Any]] = [
                ["date", "=", entry["date"]],
                ["project_id", "=", entry["project_id"]],
                ["name", "=", entry["description"]],
            ]
            if entry["task_id"] is not None and "task_id" in fields:
                domain.append(["task_id", "=", entry["task_id"]])
            elif "task_id" in fields:
                domain.append(["task_id", "=", False])
            if "user_id" in fields and uid is not None:
                domain.append(["user_id", "=", uid])
            if "employee_id" in fields and employee_id is not None:
                domain.append(["employee_id", "=", employee_id])
            if "company_id" in fields and company_id is not None:
                domain.append(["company_id", "=", company_id])
            existing = self._search_read(
                session_id,
                "account.analytic.line",
                domain,
                [field for field in ("id", "unit_amount") if field in fields],
                limit=10,
                order="id asc",
            )
            same_hours = next(
                (
                    row
                    for row in existing
                    if isinstance(row, Mapping)
                    and self._float_equal(row.get("unit_amount"), entry["hours"])
                ),
                None,
            )
            if same_hours is not None:
                skipped.append({**entry, "existing_id": self._positive_int(same_hours.get("id"))})
                continue
            if existing:
                conflicts.append(
                    {
                        **entry,
                        "existing_ids": [
                            self._positive_int(row.get("id"))
                            for row in existing
                            if isinstance(row, Mapping) and self._positive_int(row.get("id")) is not None
                        ],
                        "reason": "same date/project/task/description already exists with different hours",
                    }
                )
                continue
            values: dict[str, Any] = {
                "name": entry["description"],
                "date": entry["date"],
                "unit_amount": entry["hours"],
                "project_id": entry["project_id"],
            }
            if entry["task_id"] is not None and "task_id" in fields:
                values["task_id"] = entry["task_id"]
            if "user_id" in fields and uid is not None:
                values["user_id"] = uid
            if "employee_id" in fields and employee_id is not None:
                values["employee_id"] = employee_id
            create_plan.append({"entry": entry, "values": values})

        created: list[dict[str, Any]] = []
        if not dry_run and not conflicts:
            for item in create_plan:
                record_id = self._call_kw(
                    session_id,
                    "account.analytic.line",
                    "create",
                    [item["values"]],
                    {},
                )
                created_id = self._positive_int(record_id)
                if created_id is None:
                    raise PolicyError("MOTION_ERP_RPC_FAILED", "timesheet create did not return a valid record id")
                created.append({**item["entry"], "id": created_id})

        return {
            "status": "ok",
            "dry_run": bool(dry_run),
            "planned": [item["entry"] for item in create_plan],
            "created": created,
            "skipped_existing": skipped,
            "conflicts": conflicts,
            "can_apply": not conflicts,
            "planned_count": len(create_plan),
            "created_count": len(created),
            "skipped_count": len(skipped),
            "conflict_count": len(conflicts),
        }

    def _search_read(
        self,
        session_id: str,
        model: str,
        domain: list[list[Any]],
        fields: list[str],
        *,
        limit: int,
        order: str,
    ) -> list[dict[str, Any]]:
        result = self._call_kw(
            session_id,
            model,
            "search_read",
            [domain, fields],
            {"limit": int(limit), "order": order},
        )
        if not isinstance(result, list):
            raise PolicyError("MOTION_ERP_RPC_FAILED", "ERP search_read returned an unexpected result")
        return [dict(item) for item in result if isinstance(item, Mapping)]

    def _fields_get(self, session_id: str, model: str) -> dict[str, dict[str, Any]]:
        result = self._call_kw(
            session_id,
            model,
            "fields_get",
            [],
            {"attributes": ["type", "required", "string"]},
        )
        if not isinstance(result, Mapping):
            raise PolicyError("MOTION_ERP_RPC_FAILED", "ERP fields_get returned an unexpected result")
        return {
            str(name): dict(meta)
            for name, meta in result.items()
            if isinstance(name, str) and isinstance(meta, Mapping)
        }

    def _session_uid(self, session_id: str) -> int | None:
        result = self._rpc(session_id, "/web/session/get_session_info", {})
        if not isinstance(result, Mapping):
            return None
        return self._positive_int(result.get("uid"))

    def _session_company_id(self, session_id: str) -> int | None:
        result = self._rpc(session_id, "/web/session/get_session_info", {})
        if not isinstance(result, Mapping):
            return None
        direct = self._positive_int(result.get("company_id"))
        if direct is not None:
            return direct
        companies = result.get("user_companies")
        if isinstance(companies, Mapping):
            current = self._positive_int(companies.get("current_company"))
            if current is not None:
                return current
        return None

    def _employee_id(self, session_id: str, uid: int | None) -> int | None:
        if uid is None:
            return None
        records = self._search_read(
            session_id,
            "hr.employee",
            [["user_id", "=", uid]],
            ["id"],
            limit=2,
            order="id asc",
        )
        if not records:
            return None
        return self._positive_int(records[0].get("id"))

    def _call_kw(
        self,
        session_id: str,
        model: str,
        method: str,
        args: list[Any],
        kwargs: dict[str, Any],
    ) -> Any:
        allowed = {
            ("calendar.event", "search_read"),
            ("project.project", "search_read"),
            ("project.task", "search_read"),
            ("account.analytic.line", "search_read"),
            ("account.analytic.line", "fields_get"),
            ("account.analytic.line", "create"),
            ("hr.employee", "search_read"),
        }
        if (model, method) not in allowed:
            raise PolicyError("MOTION_ERP_OPERATION_NOT_ALLOWED", "ERP model/method is outside the fixed workflow allowlist")
        path = f"/web/dataset/call_kw/{model}/{method}"
        params = {"model": model, "method": method, "args": args, "kwargs": kwargs}
        return self._rpc(session_id, path, params)

    def _rpc(self, session_id: str, path: str, params: dict[str, Any]) -> Any:
        if not path.startswith("/web/") or ".." in path:
            raise PolicyError("MOTION_ERP_OPERATION_NOT_ALLOWED", "ERP endpoint is outside the fixed workflow allowlist")
        with self.browser._lock:  # package-internal coordination with the owned Playwright context
            session = self.browser._session(session_id)
            page = self.browser._page(session)
            self.browser._touch(session)
            if session.profile.name != LOCAL_BROWSER_PROFILE_NAME:
                raise PolicyError("MOTION_ERP_PROFILE_REQUIRED", "Motion ERP tools require the configured local Motion ERP browser profile")
            if session.current_origin != MOTION_ERP_ORIGIN:
                raise PolicyError("MOTION_ERP_NAVIGATION_REQUIRED", "open the Motion ERP web app in the owned browser before using ERP tools")
            if self.browser._authentication_state(session) is False:
                raise PolicyError("MOTION_ERP_AUTH_REQUIRED", "manual login is required in the owned Motion ERP browser window")
            payload = {"jsonrpc": "2.0", "method": "call", "params": params, "id": 1}
            try:
                response = session.context.request.post(
                    MOTION_ERP_ORIGIN + path,
                    data=payload,
                    timeout=_RPC_TIMEOUT_MS,
                )
            except Exception as exc:
                raise PolicyError("MOTION_ERP_RPC_FAILED", "unable to reach the Motion ERP JSON-RPC endpoint") from exc
            if int(getattr(response, "status", 0) or 0) >= 400:
                raise PolicyError("MOTION_ERP_RPC_FAILED", "Motion ERP returned an HTTP error")
            try:
                body = response.json()
            except Exception as exc:
                raise PolicyError("MOTION_ERP_AUTH_REQUIRED", "Motion ERP did not return JSON; the browser session may need login") from exc
            if not isinstance(body, Mapping):
                raise PolicyError("MOTION_ERP_RPC_FAILED", "Motion ERP returned an unexpected JSON-RPC response")
            if body.get("error"):
                error = body.get("error")
                message = ""
                if isinstance(error, Mapping):
                    data = error.get("data")
                    if isinstance(data, Mapping):
                        message = str(data.get("message") or data.get("name") or "")
                    message = message or str(error.get("message") or "")
                lowered = message.lower()
                if "session" in lowered or "login" in lowered or "access denied" in lowered:
                    raise PolicyError("MOTION_ERP_AUTH_REQUIRED", "Motion ERP session is not authenticated")
                raise PolicyError("MOTION_ERP_RPC_FAILED", "Motion ERP rejected the fixed workflow request")
            self.browser._touch(session)
            return body.get("result")

    @staticmethod
    def _month_bounds(month: str) -> tuple[datetime, datetime]:
        match = _MONTH_RE.fullmatch(str(month or ""))
        if not match:
            raise PolicyError("INVALID_INPUT", "month must use YYYY-MM format")
        year, month_number = int(match.group(1)), int(match.group(2))
        start = datetime(year, month_number, 1, tzinfo=MOTION_ERP_TIMEZONE)
        if month_number == 12:
            next_month = datetime(year + 1, 1, 1, tzinfo=MOTION_ERP_TIMEZONE)
        else:
            next_month = datetime(year, month_number + 1, 1, tzinfo=MOTION_ERP_TIMEZONE)
        return start, next_month

    @staticmethod
    def _odoo_utc(value: datetime) -> str:
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _parse_odoo_datetime(value: Any) -> datetime | None:
        if not isinstance(value, str) or not value.strip():
            return None
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            try:
                parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _bounded_limit(value: int, *, maximum: int) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise PolicyError("INVALID_INPUT", "limit must be a positive integer")
        return min(value, maximum)

    @staticmethod
    def _bounded_text(value: Any, field: str, *, max_chars: int) -> str:
        if not isinstance(value, str) or not value.strip():
            raise PolicyError("INVALID_INPUT", f"{field} must be a non-empty string")
        text = value.strip()
        if len(text) > max_chars:
            raise PolicyError("QUOTA_EXCEEDED", f"{field} is too long")
        return text

    @staticmethod
    def _required_id(value: Any, field: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise PolicyError("INVALID_INPUT", f"{field} must be a positive integer")
        return value

    @staticmethod
    def _positive_int(value: Any) -> int | None:
        if isinstance(value, bool):
            return None
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return None
        return parsed if parsed > 0 else None

    @staticmethod
    def _many2one(value: Any) -> dict[str, Any] | None:
        if isinstance(value, (list, tuple)) and len(value) >= 2:
            record_id = MotionERPService._positive_int(value[0])
            if record_id is None:
                return None
            return {"id": record_id, "name": redact_text(str(value[1] or ""))[:200]}
        return None

    @staticmethod
    def _project_row(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "id": MotionERPService._positive_int(row.get("id")),
            "name": redact_text(str(row.get("name") or ""))[:200],
        }

    @staticmethod
    def _task_row(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "id": MotionERPService._positive_int(row.get("id")),
            "name": redact_text(str(row.get("name") or ""))[:200],
            "project": MotionERPService._many2one(row.get("project_id")),
        }

    @staticmethod
    def _timesheet_row(row: Mapping[str, Any]) -> dict[str, Any]:
        try:
            hours = float(row.get("unit_amount") or 0.0)
        except (TypeError, ValueError):
            hours = 0.0
        return {
            "id": MotionERPService._positive_int(row.get("id")),
            "date": str(row.get("date") or "")[:10],
            "description": redact_text(str(row.get("name") or ""))[:MAX_DESCRIPTION_CHARS],
            "hours": round(hours, 4),
            "project": MotionERPService._many2one(row.get("project_id")),
            "task": MotionERPService._many2one(row.get("task_id")),
        }

    @staticmethod
    def _normalize_timesheet_entry(item: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(item, Mapping):
            raise PolicyError("INVALID_INPUT", "every timesheet entry must be an object")
        raw_date = str(item.get("date") or "")
        if not _DATE_RE.fullmatch(raw_date):
            raise PolicyError("INVALID_INPUT", "timesheet date must use YYYY-MM-DD format")
        try:
            date.fromisoformat(raw_date)
        except ValueError as exc:
            raise PolicyError("INVALID_INPUT", "timesheet date is not a valid calendar date") from exc
        project_id = MotionERPService._required_id(item.get("project_id"), "project_id")
        task_value = item.get("task_id")
        task_id = None if task_value in {None, False, 0, ""} else MotionERPService._required_id(task_value, "task_id")
        description = MotionERPService._bounded_text(item.get("description"), "description", max_chars=MAX_DESCRIPTION_CHARS)
        try:
            hours = float(item.get("hours"))
        except (TypeError, ValueError) as exc:
            raise PolicyError("INVALID_INPUT", "hours must be a number") from exc
        if not math.isfinite(hours) or hours <= 0 or hours > 24:
            raise PolicyError("INVALID_INPUT", "hours must be greater than 0 and at most 24")
        return {
            "date": raw_date,
            "project_id": project_id,
            "task_id": task_id,
            "description": description,
            "hours": round(hours, 4),
        }

    @staticmethod
    def _timesheet_business_key(
        entry: Mapping[str, Any],
        *,
        fields: Mapping[str, Any],
        uid: int | None,
        employee_id: int | None,
        company_id: int | None,
    ) -> tuple[Any, ...]:
        """Return the identity used by the fixed duplicate lookup domain.

        Hours are intentionally excluded: the same identity with a different
        amount is a conflict, while repeating that identity in one request is
        ambiguous and must fail before any row is created.
        """
        return (
            entry["date"],
            entry["project_id"],
            entry["task_id"] if "task_id" in fields else None,
            entry["description"],
            uid if "user_id" in fields else None,
            employee_id if "employee_id" in fields else None,
            company_id if "company_id" in fields else None,
        )

    @staticmethod
    def _float_equal(value: Any, expected: float) -> bool:
        try:
            actual = float(value)
        except (TypeError, ValueError):
            return False
        return math.isfinite(actual) and abs(actual - expected) <= 1e-6
