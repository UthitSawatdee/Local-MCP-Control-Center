from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class ScopeKind(StrEnum):
    PROJECT = "project"
    DIRECTORY = "directory"
    FILE = "file"


class Capability(StrEnum):
    READ = "read"
    EXECUTE = "execute"
    WRITE = "write"
    CREATE = "create"
    RENAME = "rename"
    MOVE = "move"
    DELETE = "delete"


class ApprovalMode(StrEnum):
    NEVER = "never"
    ALWAYS = "always"
    ON_RISK = "on_risk"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CONSUMED = "consumed"


class PermissionClass(StrEnum):
    """Tool side-effect class used by the registry and policy broker.

    This is intentionally separate from the per-scope filesystem capabilities.
    A read-only tool can inspect a scope, while an execute tool still needs the
    scope's explicit ``execute`` permission and an enabled tool policy.
    """

    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"
    DANGEROUS = "DANGEROUS"


@dataclass(slots=True)
class Scope:
    id: str
    label: str
    kind: str
    root: str
    enabled: bool = True
    expose_to_mcp: bool = False
    policy_version: int = 1
    created_at: str = field(default_factory=utc_now)
    updated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ToolPolicy:
    tool_name: str
    enabled: bool
    approval_mode: str
    max_duration_ms: int = 30_000
    output_limit_bytes: int = 65_536
    updated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ActionIntent:
    request_id: str
    session_id: str
    actor: str
    tool: str
    operation: str
    scope_id: str | None
    targets: list[str]
    payload_digest: str
    expected_preconditions: dict[str, str | None]
    policy_version: int

    def canonical_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "actor": self.actor,
            "tool": self.tool,
            "operation": self.operation,
            "scope_id": self.scope_id,
            "targets": self.targets,
            "payload_digest": self.payload_digest,
            "expected_preconditions": self.expected_preconditions,
            "policy_version": self.policy_version,
        }


@dataclass(slots=True)
class ApprovalRequest:
    id: str
    action_hash: str
    status: str
    intent: dict[str, Any]
    payload: dict[str, Any]
    policy_version: int
    expires_at: str
    decision_reason: str | None = None
    decided_at: str | None = None
    consumed_at: str | None = None

    def to_dict(self, include_payload: bool = False) -> dict[str, Any]:
        data = {
            "id": self.id,
            "action_hash": self.action_hash,
            "status": self.status,
            "intent": self.intent,
            "policy_version": self.policy_version,
            "expires_at": self.expires_at,
            "decision_reason": self.decision_reason,
            "decided_at": self.decided_at,
            "consumed_at": self.consumed_at,
        }
        if include_payload:
            data["payload"] = self.payload
        return data
