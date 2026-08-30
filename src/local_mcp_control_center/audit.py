from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from .filesystem import redact_text
from .models import utc_now
from .storage import Store


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def _redact_value(value: Any, *, depth: int = 0) -> Any:
    """Bound and redact audit metadata before it becomes durable telemetry."""
    if depth > 4:
        return "[TRUNCATED]"
    if isinstance(value, str):
        return redact_text(value)[:2000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return {
            str(key)[:100]: _redact_value(item, depth=depth + 1)
            for key, item in list(value.items())[:100]
        }
    if isinstance(value, (list, tuple)):
        return [_redact_value(item, depth=depth + 1) for item in list(value)[:100]]
    return redact_text(str(value))[:2000]


class AuditLog:
    """Append-only, hash-chained audit adapter without raw file content."""

    def __init__(self, store: Store):
        self.store = store

    def record(
        self,
        *,
        actor: str,
        tool: str,
        operation: str,
        decision: str,
        target_display: str = "",
        session_id: str | None = None,
        request_id: str | None = None,
        scope_id: str | None = None,
        approval_id: str | None = None,
        pre_hash: str | None = None,
        post_hash: str | None = None,
        result_code: str | None = None,
        error_code: str | None = None,
        metadata: dict[str, Any] | None = None,
        trace_id: str | None = None,
        duration_ms: int | None = None,
        process_id: str | None = None,
    ) -> dict[str, Any]:
        event = {
            "event_id": str(uuid.uuid4()),
            "occurred_at": utc_now(),
            "actor": actor,
            "session_id": session_id,
            "request_id": request_id,
            "tool": tool,
            "operation": operation,
            "scope_id": scope_id,
            "target_display": redact_text(str(target_display))[:500],
            "decision": decision,
            "approval_id": approval_id,
            "pre_hash": pre_hash,
            "post_hash": post_hash,
            "result_code": result_code,
            "error_code": error_code,
            "metadata_json": canonical_json(_redact_value(metadata or {})),
            "trace_id": redact_text(str(trace_id))[:200] if trace_id else None,
            "duration_ms": max(0, int(duration_ms)) if duration_ms is not None else None,
            "process_id": redact_text(str(process_id))[:200] if process_id else None,
        }
        with self.store._lock:
            previous_row = self.store._conn.execute(
                "SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous_row["event_hash"] if previous_row else "GENESIS"
            event["prev_hash"] = previous_hash
            event["event_hash"] = sha256_json(event)
            columns = ", ".join(event)
            placeholders = ", ".join("?" for _ in event)
            self.store._conn.execute(
                f"INSERT INTO audit_events ({columns}) VALUES ({placeholders})",
                tuple(event.values()),
            )
            self.store._conn.commit()
        return event

    def verify_chain(self) -> tuple[bool, str | None]:
        rows = self.store._fetchall("SELECT * FROM audit_events ORDER BY seq ASC")
        expected_previous = "GENESIS"
        for row in rows:
            data = {
                key: row[key]
                for key in (
                    "event_id",
                    "occurred_at",
                    "actor",
                    "session_id",
                    "request_id",
                    "tool",
                    "operation",
                    "scope_id",
                    "target_display",
                    "decision",
                    "approval_id",
                    "pre_hash",
                    "post_hash",
                    "result_code",
                    "error_code",
                    "metadata_json",
                    "prev_hash",
                    "trace_id",
                    "duration_ms",
                    "process_id",
                )
            }
            if row["prev_hash"] != expected_previous:
                return False, f"previous hash mismatch at seq {row['seq']}"
            computed = sha256_json(data)
            # Existing installations were hash-chained before the correlated
            # audit columns were added.  Verify those legacy events without
            # weakening verification for new events.
            if computed != row["event_hash"]:
                legacy_data = {
                    key: data[key]
                    for key in data
                    if key not in {"trace_id", "duration_ms", "process_id"}
                }
                computed = sha256_json(legacy_data)
            if computed != row["event_hash"]:
                return False, f"event hash mismatch at seq {row['seq']}"
            expected_previous = row["event_hash"]
        return True, None
