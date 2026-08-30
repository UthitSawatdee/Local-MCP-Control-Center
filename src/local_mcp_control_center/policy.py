from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .errors import PolicyError
from .filesystem import PROTECTED_COMPONENTS, PROTECTED_FILENAMES, PROTECTED_SUFFIXES, SafeFilesystem, is_protected_relative
from .models import Capability, Scope, ScopeKind
from .registry import TOOL_BY_NAME
from .storage import CAPABILITIES, Store


SCOPE_ID_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{1,63}$")
FORBIDDEN_ROOTS = {
    Path("/"),
    Path("/System"),
    Path("/Library"),
    Path("/Applications"),
    Path("/Users"),
    Path("/Volumes"),
}


class PolicyEngine:
    """Deep policy module: canonical paths, capabilities, tools, and quotas."""

    def __init__(self, store: Store, filesystem: SafeFilesystem | None = None):
        self.store = store
        self.filesystem = filesystem or SafeFilesystem()

    def register_scope(
        self,
        *,
        scope_id: str,
        label: str,
        kind: str,
        root: str,
        expose_to_mcp: bool = False,
        permissions: dict[str, dict[str, Any]] | None = None,
    ) -> Scope:
        if not isinstance(scope_id, str) or not SCOPE_ID_RE.fullmatch(scope_id):
            raise PolicyError("INVALID_INPUT", "scope_id must be 2-64 safe identifier characters")
        if kind not in {ScopeKind.PROJECT, ScopeKind.DIRECTORY, ScopeKind.FILE}:
            raise PolicyError("INVALID_INPUT", "unsupported scope kind")
        candidate = Path(root).expanduser().absolute()
        if not candidate.exists():
            raise PolicyError("TARGET_NOT_FOUND", "scope root does not exist")
        if candidate.is_symlink():
            raise PolicyError("SYMLINK_NOT_ALLOWED", "scope root must not be a symlink")
        canonical = candidate.resolve(strict=True)
        if canonical in FORBIDDEN_ROOTS or canonical == Path.home().resolve():
            raise PolicyError("BROAD_SCOPE_DENIED", "home and system roots are not valid scopes")
        if any(part.lower() in PROTECTED_COMPONENTS for part in canonical.parts) or is_protected_relative(canonical.name):
            raise PolicyError("PROTECTED_TARGET", "scope root contains a protected path component")
        if kind == ScopeKind.FILE and not canonical.is_file():
            raise PolicyError("INVALID_INPUT", "file scope must point to a regular file")
        if kind != ScopeKind.FILE and not canonical.is_dir():
            raise PolicyError("INVALID_INPUT", "directory/project scope must point to a directory")
        if not isinstance(label, str) or not label.strip():
            raise PolicyError("INVALID_INPUT", "scope label is required")

        for existing in self.store.list_scopes():
            existing_root = Path(existing.root)
            if canonical == existing_root or canonical in existing_root.parents or existing_root in canonical.parents:
                raise PolicyError("SCOPE_OVERLAP", "overlapping scopes are rejected for deterministic policy")

        scope = Scope(
            id=scope_id,
            label=label.strip()[:120],
            kind=kind,
            root=str(canonical),
            expose_to_mcp=bool(expose_to_mcp),
            policy_version=self.store.bump_policy_version(),
        )
        self.store.add_scope(scope, permissions)
        return scope

    def get_scope(self, scope_id: str, *, actor: str = "user", require_enabled: bool = True) -> Scope:
        scope = self.store.get_scope(scope_id)
        if not scope:
            raise PolicyError("SCOPE_NOT_FOUND", f"scope not found: {scope_id}")
        if require_enabled and not scope.enabled:
            raise PolicyError("SCOPE_DISABLED", f"scope is disabled: {scope_id}")
        if actor == "chatgpt" and (not scope.enabled or not scope.expose_to_mcp):
            raise PolicyError("MCP_EXPOSURE_DISABLED", f"scope is not exposed to MCP: {scope_id}")
        current = Path(scope.root)
        try:
            canonical = current.resolve(strict=True)
        except FileNotFoundError as exc:
            raise PolicyError("SCOPE_NOT_FOUND", "scope root is no longer available") from exc
        if canonical != current:
            raise PolicyError("SCOPE_CHANGED", "scope root canonical path changed")
        return scope

    def resolve_path(
        self,
        scope_id: str,
        relative_path: str,
        *,
        actor: str = "user",
        must_exist: bool = False,
        allow_file_scope: bool = False,
    ) -> tuple[Scope, Path, str]:
        scope = self.get_scope(scope_id, actor=actor)
        if scope.kind == ScopeKind.FILE and not allow_file_scope:
            if relative_path not in ("", "."):
                raise PolicyError("PATH_NOT_ALLOWED", "file scope only exposes its exact file")
        try:
            target = self.filesystem.resolve_under(Path(scope.root), relative_path, must_exist=must_exist)
        except FileNotFoundError as exc:
            raise PolicyError("TARGET_NOT_FOUND", "target does not exist") from exc
        relative = target.relative_to(Path(scope.root)).as_posix() if target != Path(scope.root) else "."
        if is_protected_relative(relative):
            raise PolicyError("PROTECTED_TARGET", "target is protected by default policy")
        return scope, target, relative

    def require_capability(
        self,
        scope_id: str,
        capability: str,
        *,
        actor: str = "chatgpt",
        item_count: int = 1,
        byte_count: int = 0,
    ) -> tuple[Scope, dict[str, Any]]:
        if capability not in CAPABILITIES:
            raise PolicyError("INVALID_INPUT", f"unknown capability: {capability}")
        scope = self.get_scope(scope_id, actor=actor)
        permission = self.store.permissions(scope_id).get(capability)
        if not permission or not permission["allowed"]:
            raise PolicyError("CAPABILITY_DENIED", f"{capability} is not allowed for scope {scope_id}")
        if item_count > int(permission["max_items"]):
            raise PolicyError("QUOTA_EXCEEDED", "action exceeds item quota")
        if byte_count > int(permission["max_bytes"]):
            raise PolicyError("QUOTA_EXCEEDED", "action exceeds byte quota")
        return scope, permission

    def require_execution(
        self,
        scope_id: str,
        *,
        actor: str = "chatgpt",
        item_count: int = 1,
    ) -> tuple[Scope, dict[str, Any]]:
        """Require the separate project/process execution capability."""
        return self.require_capability(
            scope_id,
            Capability.EXECUTE,
            actor=actor,
            item_count=item_count,
        )

    def require_tool(self, tool_name: str, *, actor: str = "chatgpt"):
        if tool_name not in TOOL_BY_NAME:
            raise PolicyError("TOOL_NOT_FOUND", f"unknown tool: {tool_name}")
        policy = self.store.get_tool_policy(tool_name)
        if not policy or not policy.enabled:
            raise PolicyError("TOOL_DISABLED", f"tool is disabled: {tool_name}")
        return policy

    def approval_required(self, tool_name: str, permission: dict[str, Any] | None, operation: str) -> bool:
        """Return the one approval boundary for the local control center.

        File/document edits, file moves/renames, and fixed project profiles are
        constrained by tool, scope, capability, quota, and precondition checks.
        Dangerous file/Git side effects remain the explicit approval boundary,
        regardless of stale values in an older SQLite policy row.
        """
        definition = TOOL_BY_NAME.get(tool_name)
        return (
            tool_name == "delete_file"
            or operation == "delete"
            or bool(definition and definition.destructive)
        )

    def scope_summary(self, *, actor: str = "user", include_disabled: bool = True) -> list[dict[str, Any]]:
        result = []
        for scope in self.store.list_scopes(include_disabled=include_disabled):
            if actor == "chatgpt" and (not scope.enabled or not scope.expose_to_mcp):
                continue
            data = {
                "id": scope.id,
                "label": scope.label,
                "kind": scope.kind,
                "enabled": scope.enabled,
                "expose_to_mcp": scope.expose_to_mcp,
                "permissions": self.store.permissions(scope.id),
            }
            if actor != "chatgpt":
                data["root"] = scope.root
            result.append(data)
        return result
