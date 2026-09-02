"""DevOS Workspace Engine.

This module is the deep module for local workspace intelligence.  It composes
existing filesystem, fixed-runner, dependency, and SQLite adapters behind a
small interface.  It never grants authorization and never reads secret
contents; the Broker remains the policy seam for every data-plane adapter.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import socket
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Mapping

from .audit import AuditLog, sha256_json
from .dependency_graph import GraphLimits, build_dependency_graph
from .errors import PolicyError, StorageError
from .filesystem import (
    DEFAULT_IGNORED_DIRS,
    PROTECTED_COMPONENTS,
    SafeFilesystem,
    is_protected_relative,
    redact_text,
    validate_relative_path,
)
from .models import Scope, ScopeKind, utc_now
from .runner import CommandResult, FixedRunner
from .storage import Store


_IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{1,63}$")
_MODES = frozenset({"diagnose", "implement", "review"})
_EVENT_TYPES = frozenset(
    {
        "run_start",
        "context_generated",
        "impact_detected",
        "changed_files",
        "test_result",
        "decision",
        "error",
        "recovery",
        "approval",
        "environment_fingerprint",
        "handoff_ready",
    }
)
_SENSITIVE_WORDS = frozenset({"secret", "token", "password", "credential", "private_key", "private-key", "api_key", "api-key", "apikey"})
_DEFAULT_NEVER_READ = (
    ".env",
    ".env.*",
    "credentials",
    "token files",
    "private keys",
    "SSH private keys",
    "cloud credentials",
)
_TEST_PATTERNS = (
    "test_*.py",
    "*_test.py",
    "*.spec.ts",
    "*.spec.tsx",
    "*.test.ts",
    "*.test.tsx",
    "*.test.js",
    "*.test.jsx",
)
_MAX_METADATA_DIRECTORIES = 5_000
_MAX_METADATA_SECONDS = 2.0
_ABSOLUTE_PATH_RE = re.compile(r"(?<![A-Za-z0-9:/])/(?!/)[^\s,;]+")


@dataclass(frozen=True, slots=True)
class WorkspaceScope:
    """Canonical project root passed through the WorkspaceEngine interface."""

    project_id: str
    root: Path
    label: str = ""
    kind: str = ScopeKind.PROJECT.value

    @classmethod
    def from_scope(cls, scope: Scope | None) -> "WorkspaceScope":
        if scope is None:
            raise ValueError("workspace scope is required")
        return cls(scope.id, Path(scope.root), scope.label, scope.kind)


@dataclass(frozen=True, slots=True)
class WorkRequest:
    project_id: str
    goal: str
    mode: str = "implement"
    allowed_scope: tuple[str, ...] = (".",)


@dataclass(frozen=True, slots=True)
class WorkEvent:
    run_id: str
    event_type: str
    payload: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class Project:
    id: str
    name: str
    status: str
    criticality: str
    canonical_path: str
    kind: str = ScopeKind.PROJECT.value

    def to_dict(self, *, include_path: bool = False) -> dict[str, Any]:
        value = {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "criticality": self.criticality,
            "kind": self.kind,
        }
        if include_path:
            value["canonical_path"] = self.canonical_path
        return value


@dataclass(frozen=True, slots=True)
class Capsule:
    project_id: str
    name: str
    status: str
    criticality: str
    repository: dict[str, Any]
    runtime: dict[str, str]
    services: dict[str, dict[str, Any]]
    verification: list[Any]
    safety: dict[str, list[str]]
    source: str = "default"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.project_id,
            "name": self.name,
            "status": self.status,
            "criticality": self.criticality,
            "repository": dict(self.repository),
            "runtime": dict(self.runtime),
            "services": {name: dict(value) for name, value in self.services.items()},
            "verification": list(self.verification),
            "safety": {name: list(values) for name, values in self.safety.items()},
            "source": self.source,
        }


def _public_capsule(capsule: Capsule) -> dict[str, Any]:
    value = capsule.to_dict()
    # Canonical roots are useful to the local control plane, but must not
    # leak through an MCP response that identifies projects by scope ID.
    value["repository"].pop("canonical_path", None)
    for service in value["services"].values():
        service.pop("command", None)
    value["verification"] = [
        {"configured": True} if isinstance(item, str) else {
            key: item[key] for key in ("profile", "target", "required") if key in item
        }
        for item in value["verification"]
    ]
    source = str(value.get("source") or "")
    value["source"] = source if source in {"default", "safe-default", "control-plane", "stored"} else "configured"
    return value


def _bounded_text(value: Any, *, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be non-empty text")
    if len(value) > limit:
        raise ValueError(f"{field} exceeds {limit} characters")
    return value.strip()


def _redact_workspace_text(value: str) -> str:
    return _ABSOLUTE_PATH_RE.sub("[PATH_REDACTED]", redact_text(value))


def _mapping(value: Any, *, field: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    return {str(key): item for key, item in value.items()}


def _string_list(value: Any, *, field: str, limit: int = 100) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{field} must be a list")
    if len(value) > limit:
        raise ValueError(f"{field} contains too many items")
    result: list[str] = []
    for index, item in enumerate(value):
        result.append(_bounded_text(item, field=f"{field}[{index}]", limit=1024))
    return result


def _safe_branch_name(value: Any) -> str:
    branch = _bounded_text(value, field="repository.default_branch", limit=100)
    components = branch.split("/")
    if (
        not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}", branch)
        or ".." in branch
        or "//" in branch
        or any(not item or item.startswith(".") or item.endswith(".lock") for item in components)
    ):
        raise ValueError("repository.default_branch must be a safe relative Git branch name")
    return branch


def _reject_sensitive_key(key: str, *, field: str) -> None:
    folded = key.casefold().replace("-", "_")
    if any(word in folded for word in _SENSITIVE_WORDS):
        raise ValueError(f"{field}.{key} is not allowed to contain credential data")


def parse_capsule(value: Mapping[str, Any] | str, *, project_id: str | None = None, source: str = "control-plane") -> Capsule:
    """Validate a safe capsule mapping or JSON object.

    YAML parsing is intentionally not implicit: callers provide an already
    parsed mapping or bounded JSON text.  This avoids adding a parser that
    could silently accept executable or credential-shaped configuration.
    """

    if isinstance(value, str):
        if len(value.encode("utf-8")) > 262_144:
            raise ValueError("capsule text exceeds 256 KiB")
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("capsule text must be a JSON object") from exc
    raw = _mapping(value, field="capsule")
    allowed = {"id", "name", "status", "criticality", "repository", "runtime", "services", "verification", "safety"}
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise ValueError(f"unsupported capsule field(s): {', '.join(unknown)}")

    resolved_id = project_id or raw.get("id")
    resolved_id = _bounded_text(resolved_id, field="capsule.id", limit=64)
    if not _IDENTIFIER_RE.fullmatch(resolved_id):
        raise ValueError("capsule.id must be a safe project identifier")
    name = _bounded_text(raw.get("name", resolved_id), field="capsule.name", limit=160)
    status = _bounded_text(raw.get("status", "active"), field="capsule.status", limit=40)
    criticality = _bounded_text(raw.get("criticality", "standard"), field="capsule.criticality", limit=40)

    repository_raw = _mapping(raw.get("repository"), field="capsule.repository")
    repository_allowed = {"canonical_path", "default_branch", "remote", "push_requires_approval"}
    unknown = sorted(set(repository_raw) - repository_allowed)
    if unknown:
        raise ValueError(f"unsupported capsule.repository field(s): {', '.join(unknown)}")
    repository: dict[str, Any] = {
        "default_branch": _safe_branch_name(repository_raw.get("default_branch", "main")),
        "remote": _bounded_text(repository_raw.get("remote", "origin"), field="repository.remote", limit=100),
        "push_requires_approval": repository_raw.get("push_requires_approval", True),
    }
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repository["remote"]):
        raise ValueError("repository.remote must be a remote name, not a URL or command")
    if not isinstance(repository["push_requires_approval"], bool):
        raise ValueError("repository.push_requires_approval must be boolean")
    if "canonical_path" in repository_raw:
        repository["canonical_path"] = _bounded_text(repository_raw["canonical_path"], field="repository.canonical_path", limit=1024)

    runtime_raw = _mapping(raw.get("runtime"), field="capsule.runtime")
    runtime: dict[str, str] = {}
    if len(runtime_raw) > 32:
        raise ValueError("capsule.runtime contains too many entries")
    for key, item in runtime_raw.items():
        _reject_sensitive_key(key, field="capsule.runtime")
        if not _IDENTIFIER_RE.fullmatch(key) and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", key):
            raise ValueError(f"capsule.runtime key is invalid: {key}")
        expected = _bounded_text(str(item), field=f"runtime.{key}", limit=100)
        if (
            any(character in expected for character in ("/", "\\", "\x00", "\n", "\r", ";", "|", "&", "$", "`"))
            or any(word in expected.casefold().replace("-", "_") for word in _SENSITIVE_WORDS)
        ):
            raise ValueError(f"runtime.{key} must be a safe version label")
        runtime[key] = expected

    services_raw = _mapping(raw.get("services"), field="capsule.services")
    services: dict[str, dict[str, Any]] = {}
    if len(services_raw) > 32:
        raise ValueError("capsule.services contains too many entries")
    for name_key, spec_value in services_raw.items():
        service_name = _bounded_text(name_key, field="services name", limit=80)
        _reject_sensitive_key(service_name, field="services")
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,79}", service_name):
            raise ValueError(f"services name is invalid: {service_name}")
        spec = _mapping(spec_value, field=f"services.{service_name}")
        service_allowed = {"command", "port", "health_url"}
        unknown = sorted(set(spec) - service_allowed)
        if unknown:
            raise ValueError(f"unsupported services.{service_name} field(s): {', '.join(unknown)}")
        service: dict[str, Any] = {}
        if "command" in spec:
            command = _bounded_text(spec["command"], field=f"services.{service_name}.command", limit=500)
            if re.search(r"(?i)(?:api[_-]?key|secret|token|password|credential)\s*=", command):
                raise ValueError(f"services.{service_name}.command must not embed credentials")
            service["command"] = command
        if "port" in spec:
            port = spec["port"]
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65_535:
                raise ValueError(f"services.{service_name}.port must be between 1 and 65535")
            service["port"] = port
        if "health_url" in spec:
            health_url = _bounded_text(spec["health_url"], field=f"services.{service_name}.health_url", limit=500)
            parsed = urllib.parse.urlparse(health_url)
            if (
                parsed.scheme not in {"http", "https"}
                or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(f"services.{service_name}.health_url must target localhost")
            service["health_url"] = health_url
        services[service_name] = service

    verification_raw = raw.get("verification", [])
    if not isinstance(verification_raw, (list, tuple)) or len(verification_raw) > 100:
        raise ValueError("capsule.verification must be a bounded list")
    verification: list[Any] = []
    for index, item in enumerate(verification_raw):
        if isinstance(item, str):
            command = _bounded_text(item, field=f"verification[{index}]", limit=500)
            if re.search(r"(?i)(?:api[_-]?key|secret|token|password|credential)\s*=", command):
                raise ValueError(f"verification[{index}] must not embed credentials")
            verification.append(command)
            continue
        spec = _mapping(item, field=f"verification[{index}]")
        if set(spec) - {"profile", "target", "required"}:
            raise ValueError(f"verification[{index}] contains unsupported fields")
        profile = _bounded_text(spec.get("profile"), field=f"verification[{index}].profile", limit=120)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,119}", profile):
            raise ValueError(f"verification[{index}].profile must be a safe profile name")
        target = spec.get("target")
        if target is not None:
            target = _bounded_text(target, field=f"verification[{index}].target", limit=80)
            if target.startswith(("/", "~")) or "\\" in target or any(part == ".." for part in target.split("/")):
                raise ValueError(f"verification[{index}].target must be relative")
        required = spec.get("required", True)
        if not isinstance(required, bool):
            raise ValueError(f"verification[{index}].required must be boolean")
        item_value: dict[str, Any] = {"profile": profile, "required": required}
        if target is not None:
            item_value["target"] = target
        verification.append(item_value)

    safety_raw = _mapping(raw.get("safety"), field="capsule.safety")
    safety_allowed = {"protected_paths", "never_read", "never_delete", "approval_required"}
    unknown = sorted(set(safety_raw) - safety_allowed)
    if unknown:
        raise ValueError(f"unsupported capsule.safety field(s): {', '.join(unknown)}")
    safety = {
        "protected_paths": _string_list(safety_raw.get("protected_paths"), field="safety.protected_paths"),
        "never_read": _string_list(safety_raw.get("never_read"), field="safety.never_read"),
        "never_delete": _string_list(safety_raw.get("never_delete"), field="safety.never_delete"),
        "approval_required": _string_list(safety_raw.get("approval_required"), field="safety.approval_required"),
    }
    safety["never_read"] = list(dict.fromkeys([*safety["never_read"], *_DEFAULT_NEVER_READ]))
    for field_name, values in safety.items():
        for item in values:
            if item.startswith("/") or "\x00" in item:
                raise ValueError(f"safety.{field_name} contains an unsafe path")
            if field_name in {"protected_paths", "never_delete"} and (
                "\\" in item or any(part == ".." for part in item.split("/"))
            ):
                raise ValueError(f"safety.{field_name} contains an unsafe relative pattern")

    return Capsule(
        project_id=resolved_id,
        name=name,
        status=status,
        criticality=criticality,
        repository=repository,
        runtime=runtime,
        services=services,
        verification=verification,
        safety=safety,
        source=_bounded_text(source, field="capsule.source", limit=120),
    )


def _default_capsule(project: Project) -> Capsule:
    return parse_capsule(
        {
            "id": project.id,
            "name": project.name,
            "status": project.status,
            "criticality": project.criticality,
            "repository": {
                "canonical_path": project.canonical_path,
                "default_branch": "main",
                "remote": "origin",
                "push_requires_approval": True,
            },
            "verification": ["git diff --check"],
            "safety": {"protected_paths": [], "never_read": list(_DEFAULT_NEVER_READ), "never_delete": ["*.db"]},
        },
        source="safe-default",
    )


def _matches_path_pattern(relative: str, pattern: str) -> bool:
    normalized = pattern.replace("\\", "/").rstrip("/")
    if not normalized:
        return False
    if fnmatch.fnmatch(relative, normalized) or fnmatch.fnmatch(relative, normalized + "/*"):
        return True
    prefix = normalized.split("*", 1)[0].rstrip("/")
    return bool(prefix) and (relative == prefix or relative.startswith(prefix + "/"))


class ProjectRegistry:
    """Read-only Project Registry backed by existing canonical scopes."""

    def __init__(self, store: Store):
        self.store = store

    def list(self) -> list[Project]:
        result: list[Project] = []
        for scope in self.store.list_scopes(include_disabled=True):
            if scope.kind != ScopeKind.PROJECT.value:
                continue
            result.append(self._project(scope))
        return sorted(result, key=lambda item: (item.name.casefold(), item.id))

    def get(self, project_id: str) -> Project:
        scope = self.store.get_scope(project_id)
        if scope is None or scope.kind != ScopeKind.PROJECT.value:
            raise ValueError(f"project not found: {project_id}")
        return self._project(scope)

    def duplicates(self, project: Project) -> list[str]:
        return [item.id for item in self.list() if item.id != project.id and item.canonical_path == project.canonical_path]

    @staticmethod
    def _project(scope: Scope) -> Project:
        try:
            canonical = str(Path(scope.root).resolve(strict=True))
        except OSError:
            canonical = str(Path(scope.root).absolute())
        return Project(
            id=scope.id,
            name=scope.label,
            status="active" if scope.enabled else "disabled",
            criticality="standard",
            canonical_path=canonical,
            kind=scope.kind,
        )


class _WorkspaceObserver:
    """Build normalized, bounded metadata without authorization decisions."""

    def __init__(self, store: Store, runner: FixedRunner, filesystem: SafeFilesystem):
        self.store = store
        self.runner = runner
        self.filesystem = filesystem

    def observe(self, project: Project, capsule: Capsule, *, max_items: int) -> dict[str, Any]:
        root = Path(project.canonical_path)
        git = self._git(root, protected_patterns=capsule.safety.get("protected_paths", []))
        runtime = self._runtime(root)
        services = self._services(capsule.services)
        processes = self._processes(project.id)
        verification = self._verification(root)
        tracked_warnings = self._tracked_environment_warnings(root, git)
        filesystem = self._filesystem(
            root,
            max_items=max_items,
            excluded_patterns=[
                *capsule.safety.get("protected_paths", []),
                *capsule.safety.get("never_read", []),
            ],
        )
        drift = self._capsule_drift(capsule, git, runtime, services)
        fingerprint_input = {
            "project_id": project.id,
            "git": {
                key: git.get(key)
                for key in ("state", "branch", "ahead", "behind", "changed_files", "protected_changed_paths")
            },
            "runtime": runtime,
            "services": services,
            "processes": processes,
            "verification": verification,
            "tracked_environment_warnings": tracked_warnings,
            "capsule_drift": drift,
        }
        snapshot = {
            "snapshot_id": f"snap-{uuid.uuid4().hex}",
            "created_at": utc_now(),
            "project": project.to_dict(),
            "capsule": _public_capsule(capsule),
            "git": git,
            "runtime": runtime,
            "services": services,
            "processes": processes,
            "verification": verification,
            "filesystem": filesystem,
            "environment": {
                "tracked_environment_warnings": tracked_warnings,
                "fingerprint": sha256_json(fingerprint_input),
            },
            "capsule_drift": drift,
            "duplicates": [],
            "unfinished_runs": [],
            "warnings": self._warnings(git, runtime, services, tracked_warnings, drift, verification, filesystem),
        }
        return snapshot

    def _git(self, root: Path, *, protected_patterns: list[str] | tuple[str, ...] = ()) -> dict[str, Any]:
        try:
            result = self.runner.run("git_status", root, output_limit=65_536, timeout_seconds=30)
        except PolicyError as exc:
            return {"state": "unavailable", "branch": None, "ahead": 0, "behind": 0, "changed_files": [], "error_code": exc.code}
        if result.stdout_truncated or result.stderr_truncated:
            return {
                "state": "unavailable",
                "branch": None,
                "ahead": 0,
                "behind": 0,
                "changed_files": [],
                "protected_changed_paths": [],
                "changed_file_count": 0,
                "protected_change_count": 0,
                "error_code": "GIT_STATUS_TRUNCATED",
                "truncated": True,
            }
        if result.exit_code != 0 or result.timed_out:
            return {
                "state": "unavailable",
                "branch": None,
                "ahead": 0,
                "behind": 0,
                "changed_files": [],
                "error_code": "GIT_TIMEOUT" if result.timed_out else "GIT_STATUS_FAILED",
            }
        lines = result.stdout.splitlines()
        header = next((line for line in lines if line.startswith("##")), "")
        branch = None
        ahead = 0
        behind = 0
        if header:
            branch_part = header[2:].strip().split("...", 1)[0]
            branch = branch_part or None
            match = re.search(r"\[([^]]+)\]", header)
            if match:
                for item in match.group(1).split(","):
                    item = item.strip()
                    if item.startswith("ahead "):
                        ahead = int(item[6:]) if item[6:].isdigit() else 0
                    if item.startswith("behind "):
                        behind = int(item[7:]) if item[7:].isdigit() else 0
        changed: list[str] = []
        protected_changed: list[str] = []
        change_detected = False
        for line in lines:
            if len(line) < 3 or line.startswith("##"):
                continue
            change_detected = True
            path = line[3:].strip()
            if " -> " in path:
                path = path.split(" -> ", 1)[-1]
            path = path.strip('"')
            if not path or path.startswith("/"):
                continue
            if is_protected_relative(path) or any(_matches_path_pattern(path, pattern) for pattern in protected_patterns):
                protected_changed.append(path)
            else:
                changed.append(path)
        changed = sorted(set(changed))[:500]
        protected_changed = sorted(set(protected_changed))[:200]
        return {
            "state": "dirty" if change_detected else "clean",
            "branch": branch,
            "ahead": ahead,
            "behind": behind,
            "changed_files": changed,
            "changed_file_count": len(changed),
            "protected_changed_paths": protected_changed,
            "protected_change_count": len(protected_changed),
        }

    def _runtime(self, root: Path) -> dict[str, Any]:
        try:
            values = self.runner.inspect_runtime_versions(root)
        except (AttributeError, PolicyError):
            values = {}
        return values if isinstance(values, dict) else {}

    def _services(self, definitions: dict[str, dict[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name in sorted(definitions):
            service = definitions[name]
            port = service.get("port")
            state = "not_configured"
            if isinstance(port, int):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        state = "listening"
                except OSError:
                    state = "unavailable"
            item: dict[str, Any] = {"state": state}
            if isinstance(port, int):
                item["port"] = port
            if isinstance(service.get("health_url"), str):
                item["health_url"] = service["health_url"]
            result[name] = item
        return result

    def _processes(self, scope_id: str) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for row in self.store.list_runtime():
            if row.get("scope_id") != scope_id:
                continue
            pid = row.get("pid")
            result.append(
                {
                    "id": str(row.get("id") or ""),
                    "kind": str(row.get("kind") or "unknown"),
                    "state": str(row.get("state") or "unknown"),
                    "pid_present": isinstance(pid, int) and not isinstance(pid, bool) and pid > 0,
                    "started_at": row.get("started_at"),
                    "stopped_at": row.get("stopped_at"),
                    "exit_code": row.get("exit_code"),
                }
            )
        return sorted(result, key=lambda item: (item["kind"], item["id"]))[:100]

    def _verification(self, root: Path) -> dict[str, Any]:
        try:
            profiles = self.runner.available_profiles(root)
        except (OSError, PolicyError):
            profiles = []
        visible = [
            {
                "name": str(profile.get("name") or ""),
                "project_type": str(profile.get("project_type") or ""),
                "source": str(profile.get("source") or "detected"),
            }
            for profile in profiles
            if isinstance(profile, Mapping)
        ]
        visible = [profile for profile in visible if profile["name"]]
        return {
            "state": "available" if visible else "unavailable",
            "profiles": sorted(visible, key=lambda item: item["name"])[:100],
            "test_profiles": [
                profile["name"]
                for profile in visible
                if "test" in profile["name"].casefold()
            ][:50],
        }

    def _tracked_environment_warnings(self, root: Path, git: Mapping[str, Any] | None = None) -> list[dict[str, str]]:
        try:
            paths = self.runner.tracked_paths(root)
        except (AttributeError, PolicyError) as exc:
            if getattr(exc, "code", None) in {"GIT_OUTPUT_TRUNCATED", "GIT_STATUS_FAILED"}:
                return [{"relative_path": "[unavailable]", "reason": "tracked_path_inventory_incomplete"}]
            paths = []
        warnings: list[dict[str, str]] = []
        observed = [*paths, *((git or {}).get("protected_changed_paths", []) or [])]
        for relative in dict.fromkeys(observed):
            reason = self._sensitive_path_reason(relative)
            if reason:
                warnings.append({"relative_path": relative, "reason": reason})
        return warnings[:200]

    @staticmethod
    def _sensitive_path_reason(relative: str) -> str | None:
        normalized = relative.replace("\\", "/")
        components = [part for part in normalized.split("/") if part]
        lower = [part.casefold() for part in components]
        if ".env" in lower or any(part.startswith(".env.") for part in lower):
            return "tracked_environment_file"
        if any(part in {".venv", "venv", "node_modules"} for part in lower):
            return "tracked_dependency_or_environment_tree"
        if is_protected_relative(relative):
            return "tracked_protected_target"
        if any(part.endswith((".pem", ".key", ".p12", ".pfx")) for part in lower):
            return "tracked_private_key_or_certificate"
        return None

    def _filesystem(self, root: Path, *, max_items: int, excluded_patterns: list[str] | None = None) -> dict[str, Any]:
        excluded_patterns = excluded_patterns or []
        try:
            entries = self.filesystem.list_entries(root, root, max_items=max_items + 1)
        except PolicyError as exc:
            return {"state": "unavailable", "error_code": exc.code, "top_level_count": 0, "top_level": []}
        entries = [
            entry for entry in entries
            if not any(_matches_path_pattern(str(entry.get("relative_path", "")), pattern) for pattern in excluded_patterns)
        ]
        truncated = len(entries) > max_items
        entries = entries[:max_items]
        file_count = 0
        byte_count = 0
        truncated_size = False
        walk_truncated = False
        traversed_directories = 0
        deadline = time.monotonic() + _MAX_METADATA_SECONDS
        for current, directories, files in os.walk(root, topdown=True, followlinks=False):
            if time.monotonic() >= deadline or traversed_directories >= _MAX_METADATA_DIRECTORIES:
                walk_truncated = True
                break
            directories[:] = [
                name for name in directories
                if (
                    name not in DEFAULT_IGNORED_DIRS
                    and name.casefold() not in PROTECTED_COMPONENTS
                    and not any(
                        _matches_path_pattern((Path(current) / name).relative_to(root).as_posix(), pattern)
                        for pattern in excluded_patterns
                    )
                )
            ]
            remaining_directories = _MAX_METADATA_DIRECTORIES - traversed_directories
            if len(directories) > remaining_directories:
                directories[:] = directories[:remaining_directories]
                walk_truncated = True
            traversed_directories += len(directories)
            for name in files:
                if time.monotonic() >= deadline:
                    walk_truncated = True
                    break
                relative = (Path(current) / name).relative_to(root).as_posix()
                if is_protected_relative(relative) or any(
                    _matches_path_pattern(relative, pattern) for pattern in excluded_patterns
                ):
                    continue
                try:
                    candidate = Path(current) / name
                    if candidate.is_symlink():
                        continue
                    size = candidate.stat().st_size
                except OSError:
                    continue
                file_count += 1
                byte_count += size
                if file_count >= 5_000 or byte_count >= 50_000_000:
                    truncated_size = True
                    break
            if truncated_size:
                break
            if walk_truncated and time.monotonic() >= deadline:
                break
        return {
            "state": "ready",
            "top_level": entries,
            "top_level_count": len(entries),
            "truncated": truncated,
            "file_count": file_count,
            "bytes": byte_count,
            "size_truncated": truncated_size,
            "walk_truncated": walk_truncated,
            "traversed_directories": traversed_directories,
        }

    @staticmethod
    def _capsule_drift(capsule: Capsule, git: dict[str, Any], runtime: dict[str, Any], services: dict[str, Any]) -> list[dict[str, Any]]:
        drift: list[dict[str, Any]] = []
        expected_branch = capsule.repository.get("default_branch")
        if expected_branch and git.get("branch") and git["branch"] != expected_branch:
            drift.append({"area": "repository.default_branch", "expected": expected_branch, "observed": git["branch"]})
        for name, expected in capsule.runtime.items():
            observed = runtime.get(name, {})
            observed_version = observed.get("version") if isinstance(observed, dict) else None
            if not observed_version:
                drift.append({"area": f"runtime.{name}", "expected": expected, "observed": "unavailable"})
            elif str(expected) not in str(observed_version):
                drift.append({"area": f"runtime.{name}", "expected": expected, "observed": observed_version})
        for name, observed in services.items():
            if observed.get("state") == "unavailable":
                drift.append({"area": f"services.{name}", "expected": "listening", "observed": "unavailable"})
        return drift

    @staticmethod
    def _warnings(
        git: dict[str, Any],
        runtime: dict[str, Any],
        services: dict[str, Any],
        tracked_warnings: list[dict[str, str]],
        drift: list[dict[str, Any]],
        verification: dict[str, Any],
        filesystem: dict[str, Any],
    ) -> list[dict[str, Any]]:
        warnings: list[dict[str, Any]] = []
        if git.get("state") == "dirty":
            warnings.append({"code": "DIRTY_REPOSITORY", "message": "repository has changed files"})
        if git.get("state") == "unavailable":
            warnings.append({"code": "GIT_UNAVAILABLE", "message": "Git status could not be observed"})
        if tracked_warnings:
            warnings.append({"code": "TRACKED_ENVIRONMENT_ARTIFACT", "count": len(tracked_warnings)})
        if drift:
            warnings.append({"code": "CAPSULE_DRIFT", "count": len(drift)})
        if any(item.get("state") == "unavailable" for item in services.values()):
            warnings.append({"code": "SERVICE_UNAVAILABLE"})
        if any(item.get("state") == "unavailable" for item in runtime.values() if isinstance(item, dict)):
            warnings.append({"code": "RUNTIME_UNAVAILABLE"})
        if verification.get("state") == "unavailable":
            warnings.append({"code": "VERIFICATION_UNAVAILABLE"})
        if filesystem.get("walk_truncated") or filesystem.get("size_truncated"):
            warnings.append({"code": "FILESYSTEM_SCAN_TRUNCATED"})
        return warnings


class _ImpactAnalyzer:
    def __init__(self, filesystem: SafeFilesystem):
        self.filesystem = filesystem

    def analyze(self, root: Path, changed_files: list[str], *, goal: str) -> dict[str, Any]:
        changed_files = sorted(set(changed_files))[:500]
        modules = sorted({path.split("/", 1)[0] for path in changed_files if path and "/" in path})
        if not modules:
            modules = sorted({Path(path).parent.as_posix() for path in changed_files if Path(path).parent.as_posix() != "."})
        workflows: set[str] = set()
        for path in changed_files:
            folded = path.casefold()
            if "test" in folded or "spec" in folded:
                workflows.add("verification")
            if folded.startswith("backend/") or "/backend/" in folded:
                workflows.add("backend")
            if folded.startswith("frontend/") or "/frontend/" in folded:
                workflows.add("frontend")
            if any(token in folded for token in ("migration", "schema", "docker", "compose", ".env")):
                workflows.add("environment")
        if not workflows:
            workflows.add("workspace")
        risk = "low"
        if len(changed_files) > 20 or "environment" in workflows:
            risk = "high"
        elif len(changed_files) > 5 or len(modules) > 1:
            risk = "medium"
        graph: dict[str, Any] = {"state": "not_run", "counts": {"nodes": 0, "edges": 0, "unresolved": 0}}
        if changed_files:
            try:
                graph = build_dependency_graph(
                    root,
                    files=changed_files,
                    limits=GraphLimits(max_files=200, max_edges=1000, max_file_bytes=1_000_000, max_output_bytes=250_000),
                )
            except Exception as exc:
                graph = {"state": "failed", "error_code": getattr(exc, "code", "DEPENDENCY_GRAPH_FAILED"), "counts": {"nodes": 0, "edges": 0, "unresolved": 0}}
        dependents = sorted({str(edge.get("source")) for edge in graph.get("edges", []) if edge.get("target") in changed_files})
        return {
            "changed_files": changed_files,
            "changed_file_count": len(changed_files),
            "modules": modules[:100],
            "workflows": sorted(workflows),
            "risk": risk,
            "goal_tokens": sorted({token.casefold() for token in re.findall(r"[A-Za-z0-9_-]{2,64}", goal)})[:50],
            "direct_dependents": dependents[:100],
            "dependency": {
                "state": graph.get("state"),
                "counts": graph.get("counts", {}),
                "truncated": bool(graph.get("truncated", False)),
            },
        }


class WorkspaceEngine:
    """Small interface, deep implementation for workspace state and handoff."""

    def __init__(
        self,
        store: Store,
        runner: FixedRunner,
        filesystem: SafeFilesystem,
        audit: AuditLog | None = None,
    ):
        self.store = store
        self.runner = runner
        self.filesystem = filesystem
        self.audit = audit
        self.projects = ProjectRegistry(store)
        self.observer = _WorkspaceObserver(store, runner, filesystem)
        self.impact = _ImpactAnalyzer(filesystem)
        self._lifecycle_lock = RLock()

    def observe(self, scope: WorkspaceScope, *, max_items: int = 100) -> dict[str, Any]:
        project = self.projects.get(scope.project_id)
        if project.canonical_path != str(scope.root.resolve(strict=True)):
            raise ValueError("workspace scope root does not match registered project")
        capsule = self._capsule(project)
        snapshot = self.observer.observe(project, capsule, max_items=max(1, min(int(max_items), 500)))
        snapshot["duplicates"] = self.projects.duplicates(project)
        snapshot["unfinished_runs"] = [
            self._public_run(row)
            for row in self.store.list_workspace_runs(
                scope_id=project.id,
                statuses=("prepared", "in_progress"),
                limit=100,
            )
        ]
        self.store.save_workspace_snapshot(
            snapshot["snapshot_id"],
            project.id,
            snapshot,
            environment_fingerprint=snapshot["environment"]["fingerprint"],
            created_at=snapshot["created_at"],
        )
        return snapshot

    def prepare(self, request: WorkRequest) -> dict[str, Any]:
        project = self.projects.get(request.project_id)
        goal = _redact_workspace_text(_bounded_text(request.goal, field="goal", limit=4_000))
        mode = _bounded_text(request.mode, field="mode", limit=20).casefold()
        if mode not in _MODES:
            raise ValueError("mode must be diagnose, implement, or review")
        capsule = self._capsule(project)
        allowed_scope = self._allowed_scope(project, request.allowed_scope, capsule=capsule)
        scope = WorkspaceScope(project.id, Path(project.canonical_path), project.name, project.kind)
        snapshot = self.observe(scope)
        observed_changed = list(snapshot["git"].get("changed_files", []) or [])
        in_scope_changed = [
            path for path in observed_changed
            if self._within_allowed_scope(path, allowed_scope)
        ]
        out_of_scope_changed = [path for path in observed_changed if path not in in_scope_changed]
        impact = self.impact.analyze(Path(project.canonical_path), in_scope_changed, goal=goal)
        test_mapping = self._test_mapping(Path(project.canonical_path), impact["changed_files"])
        recommended = self._recommended_files(Path(project.canonical_path), impact["changed_files"], test_mapping)
        required_verification = ["nearest tests"] if mode in {"implement", "review"} else ["diagnostic evidence"]
        known_issues = list(snapshot.get("warnings", []))
        if out_of_scope_changed:
            known_issues.append({"code": "OUT_OF_SCOPE_CHANGES", "count": len(out_of_scope_changed)})
        package = {
            "run_id": f"run-{uuid.uuid4().hex}",
            "project": project.to_dict(),
            "goal": goal,
            "mode": mode,
            "allowed_scope": allowed_scope,
            "baseline": {
                "changed_files": observed_changed[:500],
                "protected_changed_paths": list(snapshot["git"].get("protected_changed_paths", []))[:200],
                "environment_fingerprint": snapshot["environment"]["fingerprint"],
            },
            "observed_changed_files": observed_changed[:500],
            "out_of_scope_changed_files": out_of_scope_changed[:500],
            "protected_scope": list(dict.fromkeys([
                *capsule.safety.get("protected_paths", []),
                *capsule.safety.get("never_read", []),
                *capsule.safety.get("never_delete", []),
                ".git",
            ])),
            "impact": impact,
            "test_mapping": test_mapping,
            "risk": impact["risk"],
            "recommended_files": recommended,
            "required_verification": required_verification,
            "escalation_conditions": [
                "changed scope exceeds allowlist",
                "protected target or secret-shaped path is encountered",
                "required verification fails",
                "destructive action or push is requested",
            ],
            "architecture_context": {
                "engine": "WorkspaceEngine owns observation, preparation, evidence, and handoff semantics",
                "policy": "Broker and PolicyEngine remain authorization authority",
                "adapters": "MCP, CLI, and Portal call the same engine interface",
            },
            "known_issues": known_issues[:100],
            "snapshot_id": snapshot["snapshot_id"],
            "created_at": utc_now(),
        }
        work_run = {
            "run_id": package["run_id"],
            "scope_id": project.id,
            "goal": goal,
            "mode": mode,
            "status": "prepared",
            "created_at": package["created_at"],
            "started_at": None,
            "completed_at": None,
        }
        package["work_run"] = work_run
        self.store.create_workspace_run(
            {
                "run_id": package["run_id"],
                "scope_id": project.id,
                "goal": goal,
                "mode": mode,
                "status": "prepared",
                "work_package_json": json.dumps(package, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                "created_at": package["created_at"],
                "updated_at": package["created_at"],
                "started_at": None,
                "completed_at": None,
                "last_error": None,
            }
        )
        self._append_evidence(package["run_id"], "run_start", {"mode": mode, "goal_hash": sha256_json(goal)})
        self._append_evidence(package["run_id"], "context_generated", {"snapshot_id": snapshot["snapshot_id"], "recommended_files": recommended[:50]})
        self._append_evidence(
            package["run_id"],
            "impact_detected",
            {"changed_files": impact["changed_files"][:100], "status": "observed"},
        )
        self._append_evidence(
            package["run_id"],
            "environment_fingerprint",
            {"fingerprint": snapshot["environment"]["fingerprint"], "snapshot_id": snapshot["snapshot_id"]},
        )
        return package

    def record(self, event: WorkEvent) -> dict[str, Any]:
        with self._lifecycle_lock:
            return self._record(event)

    def _record(self, event: WorkEvent) -> dict[str, Any]:
        run = self.store.get_workspace_run(event.run_id)
        if run is None:
            raise ValueError("workspace run was not found")
        if run["status"] in {"completed", "finalizing"}:
            raise ValueError("completed workspace runs are immutable")
        event_type = _bounded_text(event.event_type, field="event_type", limit=80)
        if event_type not in _EVENT_TYPES:
            raise ValueError(f"unsupported workspace event type: {event_type}")
        if run["status"] == "failed" and event_type not in {"error", "recovery"}:
            raise ValueError("failed workspace runs require recovery before ordinary evidence")
        payload = self._normalize_event_payload(event_type, event.payload)
        receipt = self._append_evidence(event.run_id, event_type, payload)
        if event_type not in {"run_start", "context_generated", "handoff_ready"} and run["status"] == "prepared":
            self.store.update_workspace_run(event.run_id, status="in_progress", started_at=run["created_at"])
        if event_type == "error":
            self.store.update_workspace_run(
                event.run_id,
                status="failed",
                started_at=run.get("started_at") or run["created_at"],
                last_error=str(payload.get("error_code") or payload.get("message") or "workspace error")[:500],
            )
        elif event_type == "recovery" and run["status"] == "failed":
            self.store.update_workspace_run(event.run_id, status="in_progress")
        return {"status": "ok", **receipt}

    def finish(self, run_id: str) -> dict[str, Any]:
        with self._lifecycle_lock:
            return self._finish(run_id)

    def _finish(self, run_id: str) -> dict[str, Any]:
        run = self.store.get_workspace_run(run_id)
        if run is None:
            raise ValueError("workspace run was not found")
        existing = self.store.get_workspace_handoff(run_id)
        if existing is not None:
            return existing["report"]
        package = self._decode_json_object(run["work_package_json"], "workspace run package")
        scope = WorkspaceScope(str(run["scope_id"]), Path(self.projects.get(str(run["scope_id"])).canonical_path))
        snapshot = self.observe(scope)
        evidence = self.store.workspace_evidence(run_id)
        verification_items = [item["payload"] for item in evidence if item["event_type"] == "test_result"]
        required_targets = set(
            package.get("test_mapping", {}).get("nearest", [])
            if isinstance(package.get("test_mapping"), dict)
            else []
        )
        failures = [
            item for item in verification_items
            if not self._verification_passed(item, required_targets=required_targets)
        ]
        verified = bool(verification_items) and not failures
        decisions = [item["payload"] for item in evidence if item["event_type"] == "decision"]
        errors = [item["payload"] for item in evidence if item["event_type"] == "error"]
        baseline = package.get("baseline", {})
        baseline_files = set(baseline.get("changed_files", [])) if isinstance(baseline, dict) else set()
        current_files = set(snapshot["git"].get("changed_files", []) or [])
        recorded_files: set[str] = set()
        for item in evidence:
            if item["event_type"] != "changed_files":
                continue
            payload = item.get("payload", {})
            if not isinstance(payload, Mapping):
                continue
            for field in ("changed_files", "files"):
                values = payload.get(field, [])
                if isinstance(values, list):
                    recorded_files.update(value for value in values if isinstance(value, str))
        run_reported_files = recorded_files & current_files
        attribution_uncertain_files = sorted(current_files & baseline_files & run_reported_files)
        newly_changed = sorted(current_files - baseline_files)
        allowed_scope = package.get("allowed_scope", ["."])
        changed_files = [path for path in newly_changed if self._within_allowed_scope(path, allowed_scope)]
        out_of_scope_changes = [path for path in newly_changed if path not in changed_files]
        preexisting_files = sorted(current_files & baseline_files)
        risks = list(snapshot.get("warnings", []))
        if failures:
            risks.append({"code": "VERIFICATION_FAILED", "count": len(failures)})
        if preexisting_files:
            risks.append({"code": "PREEXISTING_CHANGES", "count": len(preexisting_files)})
        if attribution_uncertain_files:
            risks.append({"code": "PREEXISTING_CHANGE_ATTRIBUTION_UNCERTAIN", "count": len(attribution_uncertain_files)})
        if out_of_scope_changes:
            risks.append({"code": "OUT_OF_SCOPE_CHANGES", "count": len(out_of_scope_changes)})
        report = {
            "run_id": run_id,
            "project": package.get("project", {}),
            "summary": f"{run.get('mode', 'work').capitalize()} run: {run.get('goal', '')}",
            "files_changed": changed_files[:500],
            "preexisting_changed_files": preexisting_files[:500],
            "attribution_uncertain_changed_files": attribution_uncertain_files[:500],
            "out_of_scope_changed_files": out_of_scope_changes[:500],
            "verification": {
                "verified": verified,
                "results": verification_items[:100],
                "failed": failures[:100],
                "unverified": [] if verified else ["required verification evidence"],
            },
            "decisions": decisions[:100],
            "risks": risks[:100],
            "errors": errors[:100],
            "remaining_work": [] if verified and not errors and not out_of_scope_changes else ["resolve verification/errors/scope before publication"],
            "changelog_draft": f"{run.get('mode', 'work').capitalize()} workspace run completed for {run.get('goal', '')}",
            "suggested_commit_message": self._commit_message(str(run.get("goal", "workspace change"))),
            "publication_readiness": "ready_for_review" if verified and not errors and not out_of_scope_changes else "pending_verification",
            "evidence_count": len(evidence),
            "snapshot_id": snapshot["snapshot_id"],
            "finished_at": utc_now(),
        }
        self._append_evidence(run_id, "handoff_ready", {"verified": verified, "evidence_count": len(evidence)})
        completed_at = report["finished_at"]
        run_package = dict(package)
        run_package["work_run"] = {**dict(package.get("work_run", {})), "status": "completed", "completed_at": completed_at}
        self.store.update_workspace_run(
            run_id,
            status="completed",
            completed_at=completed_at,
            work_package_json=json.dumps(run_package, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            last_error=errors[-1].get("message") if errors and isinstance(errors[-1], dict) else None,
        )
        try:
            self.store.save_workspace_handoff(run_id, report, created_at=completed_at)
        except StorageError:
            saved = self.store.get_workspace_handoff(run_id)
            if saved is not None:
                return saved["report"]
            raise
        return report

    def verify(
        self,
        run_id: str,
        profile: str,
        *,
        target: str | None = None,
        test_path: str | None = None,
    ) -> dict[str, Any]:
        """Run one fixed profile and record runner-provenance evidence.

        This internal hook is deliberately not exposed as a new MCP tool while
        controlled-operation approval integration remains deferred. A caller
        submitting a plain ``test_result`` event cannot manufacture verified
        handoff evidence.
        """
        with self._lifecycle_lock:
            run = self.store.get_workspace_run(run_id)
            if run is None:
                raise ValueError("workspace run was not found")
            if run["status"] in {"completed", "finalizing"}:
                raise ValueError("completed workspace runs are immutable")
            project = self.projects.get(str(run["scope_id"]))
            if test_path is not None:
                parts = validate_relative_path(test_path)
                relative = "." if not parts else "/".join(parts)
                package = self._decode_json_object(run["work_package_json"], "workspace run package")
                protected_paths = package.get("protected_scope", [])
                if is_protected_relative(relative) or any(
                    _matches_path_pattern(relative, pattern) for pattern in protected_paths
                ):
                    raise ValueError("verification target is protected")
            try:
                result = self.runner.run_project_profile(
                    profile,
                    Path(project.canonical_path),
                    target=target,
                    test_path=test_path,
                )
            except PolicyError as exc:
                self._record(
                    WorkEvent(run_id, "error", {"error_code": exc.code, "message": str(exc), "profile": profile})
                )
                raise
            return self.record_verification_result(
                run_id, result, target=test_path or "full", expected_scope_id=str(run["scope_id"])
            )

    def record_verification_result(
        self,
        run_id: str,
        result: CommandResult,
        *,
        target: str,
        expected_scope_id: str,
    ) -> dict[str, Any]:
        """Record one Broker/FixedRunner result as trusted verification evidence."""
        with self._lifecycle_lock:
            run = self.store.get_workspace_run(run_id)
            if run is None:
                raise ValueError("workspace run was not found")
            if str(run["scope_id"]) != expected_scope_id:
                raise ValueError("workspace run scope does not match verification result")
            if run["status"] in {"completed", "finalizing"}:
                raise ValueError("completed workspace runs are immutable")
            if run["status"] == "failed":
                raise ValueError("failed workspace runs require a new run before verification")
            passed = result.exit_code == 0 and not result.timed_out
            receipt = self._append_evidence(
                run_id,
                "test_result",
                {
                    "profile": result.profile,
                    "command": result.argv_display,
                    "status": "passed" if passed else "failed",
                    "exit_code": result.exit_code,
                    "duration_ms": result.duration_ms,
                    "target": target,
                },
                trusted_execution=True,
            )
            if run["status"] == "prepared":
                self.store.update_workspace_run(run_id, status="in_progress", started_at=run["created_at"])
            if not passed:
                self.store.update_workspace_run(run_id, status="failed", last_error="verification_failed")
            return {"status": "ok", **receipt}

    def controlled_action_context(
        self,
        run_id: str,
        *,
        allow_completed: bool = False,
    ) -> dict[str, Any]:
        """Return bounded WorkRun semantics for Broker-owned controlled proposals."""
        run = self.store.get_workspace_run(run_id)
        if run is None:
            raise ValueError("workspace run was not found")
        allowed_states = {"prepared", "in_progress"}
        if allow_completed:
            allowed_states.add("completed")
        if run["status"] not in allowed_states:
            raise ValueError(f"workspace run status does not allow controlled actions: {run['status']}")
        package = self._decode_json_object(run["work_package_json"], "workspace run package")
        return {
            "run_id": run_id,
            "scope_id": str(run["scope_id"]),
            "status": str(run["status"]),
            "allowed_scope": list(package.get("allowed_scope", []))[:100],
            "protected_scope": list(package.get("protected_scope", []))[:200],
            "baseline_changed_files": list(package.get("baseline", {}).get("changed_files", []))[:500]
            if isinstance(package.get("baseline"), dict)
            else [],
            "test_mapping": dict(package.get("test_mapping", {}))
            if isinstance(package.get("test_mapping"), dict)
            else {},
            "handoff": self.store.get_workspace_handoff(run_id),
        }

    def validate_controlled_commit_paths(self, run_id: str, paths: list[str]) -> list[str]:
        context = self.controlled_action_context(run_id)
        if not isinstance(paths, list) or not paths or len(paths) > 100:
            raise ValueError("commit proposal requires 1-100 explicit paths")
        allowed_scope = context["allowed_scope"]
        protected_scope = context["protected_scope"]
        baseline = set(context["baseline_changed_files"])
        project = self.projects.get(context["scope_id"])
        result: list[str] = []
        for raw in paths:
            parts = validate_relative_path(raw)
            relative = "." if not parts else "/".join(parts)
            if relative == ".":
                raise ValueError("commit proposal paths must identify files")
            if is_protected_relative(relative) or any(
                _matches_path_pattern(relative, pattern) for pattern in protected_scope
            ):
                raise ValueError("commit proposal contains a protected path")
            if not self._within_allowed_scope(relative, allowed_scope):
                raise ValueError("commit proposal contains a path outside the WorkPackage allowed scope")
            if relative in baseline:
                raise ValueError("commit proposal cannot include a path that was already dirty when the WorkRun started")
            try:
                target = self.filesystem.resolve_under(Path(project.canonical_path), relative, must_exist=True)
            except PolicyError as exc:
                raise ValueError(str(exc)) from exc
            if not target.is_file() or target.is_symlink():
                raise ValueError("commit proposal paths must be existing regular files")
            result.append(relative)
        if len(set(result)) != len(result):
            raise ValueError("commit proposal paths must be unique")
        return result

    def validate_verification_target(self, run_id: str, test_path: str) -> str:
        context = self.controlled_action_context(run_id)
        parts = validate_relative_path(test_path)
        relative = "." if not parts else "/".join(parts)
        if relative == ".":
            raise ValueError("targeted verification requires one explicit test file")
        protected_scope = context["protected_scope"]
        if is_protected_relative(relative) or any(
            _matches_path_pattern(relative, pattern) for pattern in protected_scope
        ):
            raise ValueError("verification target is protected")
        known_tests = context["test_mapping"].get("all", [])
        if not isinstance(known_tests, list) or relative not in known_tests:
            raise ValueError("verification target is not in the WorkPackage test mapping")
        return relative

    def run_status(self, run_id: str) -> dict[str, Any]:
        run = self.store.get_workspace_run(run_id)
        if run is None:
            raise ValueError("workspace run was not found")
        package = self._decode_json_object(run["work_package_json"], "workspace run package")
        handoff = self.store.get_workspace_handoff(run_id)
        return {
            "status": "ok",
            "run": {key: value for key, value in run.items() if key != "work_package_json"},
            "work_package": package,
            "evidence": self.store.workspace_evidence(run_id),
            "handoff": handoff["report"] if handoff else None,
        }

    def action_proposals(self, scope_id: str | None = None) -> list[dict[str, Any]]:
        from .models import ApprovalStatus

        requests = self.store.list_approvals((ApprovalStatus.PENDING, ApprovalStatus.APPROVED))
        result: list[dict[str, Any]] = []
        for request in requests:
            if not self._approval_is_active(request.expires_at):
                continue
            intent = request.intent
            request_scope = intent.get("scope_id")
            if scope_id is not None and request_scope != scope_id:
                continue
            result.append(
                {
                    "proposal_id": request.id,
                    "run_id": intent.get("workspace_run_id"),
                    "workspace_action": intent.get("workspace_action"),
                    "status": request.status,
                    "tool": intent.get("tool"),
                    "operation": intent.get("operation"),
                    "scope_id": request_scope,
                    "targets": list(intent.get("targets", []))[:100],
                    "expires_at": request.expires_at,
                    "approval_required": True,
                }
            )
        return result

    @staticmethod
    def _approval_is_active(expires_at: str) -> bool:
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError):
            return False
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return expiry > datetime.now(timezone.utc)

    def configure_capsule(self, project_id: str, value: Mapping[str, Any] | str, *, source: str = "control-plane") -> dict[str, Any]:
        project = self.projects.get(project_id)
        capsule = parse_capsule(value, project_id=project.id, source=source)
        payload = capsule.to_dict()
        stored_payload = dict(payload)
        stored_payload.pop("source", None)
        self.store.upsert_workspace_capsule(
            project.id,
            stored_payload,
            content_hash=sha256_json(stored_payload),
            source=capsule.source,
        )
        return _public_capsule(capsule)

    def _capsule(self, project: Project) -> Capsule:
        stored = self.store.get_workspace_capsule(project.id)
        if not stored:
            return _default_capsule(project)
        stored_raw = dict(stored["capsule"])
        raw = dict(stored_raw)
        # Accept the first development version's serialized Capsule shape;
        # source is stored in its own SQLite column and is not schema input.
        raw.pop("source", None)
        if stored.get("content_hash") not in {sha256_json(raw), sha256_json(stored_raw)}:
            raise StorageError("workspace capsule integrity check failed")
        return parse_capsule(raw, project_id=project.id, source=str(stored.get("source") or "stored"))

    @staticmethod
    def _public_capsule(capsule: Capsule) -> dict[str, Any]:
        return _public_capsule(capsule)

    def _allowed_scope(
        self,
        project: Project,
        values: tuple[str, ...] | list[str],
        *,
        capsule: Capsule | None = None,
    ) -> list[str]:
        if not isinstance(values, (tuple, list)) or not values:
            values = (".",)
        if len(values) > 100:
            raise ValueError("allowed_scope contains too many paths")
        result: list[str] = []
        for value in values:
            parts = validate_relative_path(value)
            relative = "." if not parts else "/".join(parts)
            protected_paths = capsule.safety.get("protected_paths", []) if capsule else []
            if is_protected_relative(relative) or any(
                _matches_path_pattern(relative, pattern) for pattern in protected_paths
            ):
                raise ValueError("allowed_scope contains a protected path")
            try:
                self.filesystem.resolve_under(Path(project.canonical_path), relative, must_exist=False)
            except PolicyError as exc:
                raise ValueError(str(exc)) from exc
            result.append(relative)
        return list(dict.fromkeys(result))

    @staticmethod
    def _within_allowed_scope(relative: str, allowed_scope: list[str]) -> bool:
        normalized = relative.replace("\\", "/").strip("/")
        if "." in allowed_scope:
            return True
        return any(normalized == allowed or normalized.startswith(allowed + "/") for allowed in allowed_scope)

    def _test_mapping(self, root: Path, changed_files: list[str]) -> dict[str, Any]:
        tests: list[str] = []
        for pattern in _TEST_PATTERNS:
            matches, _ = self.filesystem.find_files(root, root, pattern, max_results=500)
            tests.extend(str(item["relative_path"]) for item in matches if item.get("kind") == "file")
        all_tests = sorted(set(tests))[:500]
        nearest: list[str] = []
        for test in all_tests:
            folded = test.casefold()
            if not changed_files or any(Path(path).stem.casefold().replace("test_", "") in folded for path in changed_files):
                nearest.append(test)
        integration = [test for test in all_tests if any(token in test.casefold() for token in ("integration", "e2e", "acceptance"))]
        return {"nearest": sorted(set(nearest))[:100], "integration": integration[:100], "all": all_tests, "escalation": ["full relevant suite when shared contract changes"]}

    @staticmethod
    def _recommended_files(root: Path, changed: list[str], test_mapping: dict[str, Any]) -> list[str]:
        candidates = [*changed, *test_mapping.get("nearest", []), *test_mapping.get("integration", [])]
        for name in ("README.md", "CONTEXT.md", "ARCHITECTURE.md", "pyproject.toml", "package.json"):
            if (root / name).is_file():
                candidates.append(name)
        return list(dict.fromkeys(path for path in candidates if not is_protected_relative(path)))[:200]

    @staticmethod
    def _normalize_event_payload(event_type: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ValueError("event payload must be an object")
        if event_type == "test_result":
            allowed = {"command", "profile", "status", "exit_code", "duration_ms", "commit", "timestamp", "target", "error_code"}
        elif event_type in {"run_start", "context_generated", "impact_detected", "changed_files", "decision", "error", "recovery", "approval", "environment_fingerprint", "handoff_ready"}:
            allowed = {
                "status", "message", "error_code", "reason", "decision", "files", "changed_files", "profile", "command",
                "exit_code", "duration_ms", "commit", "timestamp", "snapshot_id", "fingerprint", "verified", "evidence_count",
                "goal_hash", "mode", "recommended_files", "target", "approval_id",
            }
        else:
            allowed = set()
        result: dict[str, Any] = {}
        for key, value in list(payload.items())[:100]:
            if key not in allowed:
                continue
            if key in {"stdout", "stderr", "log", "logs", "content", "prompt", "environment", "env"}:
                continue
            result[str(key)[:80]] = _safe_metadata(value)
        for key in ("files", "changed_files", "recommended_files"):
            if key not in result:
                continue
            values = result[key]
            if not isinstance(values, list):
                result[key] = []
                continue
            safe_paths: list[str] = []
            for value in values:
                if not isinstance(value, str):
                    continue
                try:
                    parts = validate_relative_path(value)
                except PolicyError:
                    continue
                relative = "." if not parts else "/".join(parts)
                if not is_protected_relative(relative):
                    safe_paths.append(relative)
            result[key] = list(dict.fromkeys(safe_paths))[:100]
        for key in ("command", "target"):
            if isinstance(result.get(key), str):
                result[key] = _redact_workspace_text(result[key])[:2_000]
        if event_type == "test_result":
            if "status" not in result:
                raise ValueError("test_result requires status")
            if "exit_code" in result and (not isinstance(result["exit_code"], int) or isinstance(result["exit_code"], bool)):
                raise ValueError("test_result.exit_code must be an integer")
        return result

    def _append_evidence(
        self,
        run_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        trusted_execution: bool = False,
    ) -> dict[str, Any]:
        safe_payload = self._normalize_event_payload(event_type, payload)
        if event_type == "test_result" and trusted_execution:
            safe_payload["evidence_source"] = "fixed_runner"
        encoded = json.dumps(safe_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        receipt = self.store.append_workspace_evidence(
            {
                "evidence_id": f"ev-{uuid.uuid4().hex}",
                "run_id": run_id,
                "event_type": event_type,
                "payload_json": encoded,
                "payload_hash": sha256_json(safe_payload),
                "recorded_at": utc_now(),
            }
        )
        if self.audit is not None:
            run = self.store.get_workspace_run(run_id) or {}
            self.audit.record(
                actor="control-center",
                tool="workspace_engine",
                operation=event_type,
                decision="executed",
                target_display=run_id,
                scope_id=str(run.get("scope_id")) if run.get("scope_id") else None,
                result_code="EVIDENCE_RECORDED",
                metadata={
                    "evidence_id": receipt["evidence_id"],
                    "sequence": receipt["sequence"],
                    "payload_hash": receipt["payload_hash"],
                },
            )
        return {
            "evidence_id": receipt["evidence_id"],
            "run_id": receipt["run_id"],
            "sequence": receipt["sequence"],
            "event_type": receipt["event_type"],
            "payload_hash": receipt["payload_hash"],
            "recorded_at": receipt["recorded_at"],
        }

    @staticmethod
    def _verification_passed(
        payload: Mapping[str, Any],
        *,
        required_targets: set[str] | None = None,
    ) -> bool:
        status = str(payload.get("status", "")).casefold()
        exit_code = payload.get("exit_code")
        evidence_identity = payload.get("profile") or payload.get("command")
        target = payload.get("target")
        if required_targets and (
            not isinstance(target, str)
            or (target not in required_targets and target not in {"full", "full relevant suite"})
        ):
            return False
        return (
            payload.get("evidence_source") == "fixed_runner"
            and status in {"passed", "pass", "ok", "success", "completed"}
            and isinstance(evidence_identity, str)
            and bool(evidence_identity.strip())
            and isinstance(exit_code, int)
            and not isinstance(exit_code, bool)
            and exit_code == 0
        )

    @staticmethod
    def _commit_message(goal: str) -> str:
        clean = re.sub(r"\s+", " ", goal.strip()).rstrip(".")
        return f"feat: {clean[:170]}" if clean else "feat: update workspace"

    @staticmethod
    def _decode_json_object(value: Any, field: str) -> dict[str, Any]:
        try:
            decoded = json.loads(value)
        except (TypeError, json.JSONDecodeError) as exc:
            raise StorageError(f"{field} is corrupted") from exc
        if not isinstance(decoded, dict):
            raise StorageError(f"{field} must be an object")
        return decoded

    @staticmethod
    def _public_run(row: Mapping[str, Any]) -> dict[str, Any]:
        return {key: row.get(key) for key in ("run_id", "goal", "mode", "status", "created_at", "updated_at", "last_error")}


def _safe_metadata(value: Any, *, depth: int = 0) -> Any:
    if depth > 3:
        return "[TRUNCATED]"
    if isinstance(value, str):
        return _redact_workspace_text(value)[:2_000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, Mapping):
        return {
            str(key)[:80]: _safe_metadata(item, depth=depth + 1)
            for key, item in list(value.items())[:50]
            if str(key).casefold() not in {"stdout", "stderr", "content", "prompt", "env", "environment"}
            and not any(word in str(key).casefold().replace("-", "_") for word in _SENSITIVE_WORDS)
        }
    if isinstance(value, (list, tuple)):
        return [_safe_metadata(item, depth=depth + 1) for item in list(value)[:100]]
    return redact_text(str(value))[:500]


__all__ = [
    "Capsule",
    "Project",
    "ProjectRegistry",
    "WorkEvent",
    "WorkRequest",
    "WorkspaceEngine",
    "WorkspaceScope",
    "parse_capsule",
]
