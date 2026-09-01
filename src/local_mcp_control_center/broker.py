from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .agent_tasks import AgentProfile, AgentTaskManager
from .agent_runtime import AgentModelProfile, AgentRuntimeLimits, AgentRuntimeService
from .audit import AuditLog, sha256_json
from .browser import BrowserManager
from .code_intelligence import WorkspaceIndexService
from .compound_reads import CompoundReadExecutor
from .context_engine import WorkspaceContextService
from .context_ledger import ContextLedger
from .dependency_graph import GraphLimits, build_dependency_graph
from .documents import DocumentAdapter
from .errors import PolicyError, StorageError
from .filesystem import MAX_READ_BYTES, SafeFilesystem, redact_text, sha256_bytes, sha256_file
from .git_adapter import GitAdapter
from .models import ApprovalRequest, ApprovalStatus, Capability, ScopeKind, utc_now
from .patching import apply_text_patch
from .policy import PolicyEngine
from .processes import ManagedProcessManager
from .registry import DEFAULT_REGISTRY, ToolRegistry
from .runner import FixedRunner
from .schemas import validate_tool_args
from .storage import Store


_COMPOUND_READ_TOOLS = frozenset(
    {
        "list_files",
        "read_file",
        "search_text",
        "read_many_files",
        "find_files",
        "search_regex",
        "read_file_page",
        "workspace_snapshot",
        "workspace_index_status",
        "symbol_search",
        "find_definition",
        "find_references",
        "dependency_graph",
    }
)


@dataclass(slots=True)
class RequestContext:
    actor: str
    session_id: str
    request_id: str
    trace_id: str
    started_monotonic: float


class Broker:
    """The single local authority for MCP actions and GUI policy operations."""

    def __init__(
        self,
        store: Store,
        *,
        agent_runtime_limits: AgentRuntimeLimits | None = None,
        agent_model_profiles: Mapping[str, AgentModelProfile] | None = None,
    ):
        self.store = store
        self.data_dir = store.data_dir
        self.registry: ToolRegistry = DEFAULT_REGISTRY
        self.filesystem = SafeFilesystem()
        self.policy = PolicyEngine(store, self.filesystem)
        self.audit = AuditLog(store)
        self.documents = DocumentAdapter()
        self.browser = BrowserManager(
            self.data_dir / "browser",
            headless=os.environ.get("LOCAL_MCP_BROWSER_HEADLESS") == "1",
        )
        self.runner = FixedRunner(self.data_dir)
        self.git = GitAdapter(self.runner)
        self.processes = ManagedProcessManager(self.store, self.audit)
        self.agent_tasks = AgentTaskManager(runtime_dir=self.data_dir / "agent-runtime")
        self.agent_runtime = AgentRuntimeService(
            store=self.store,
            broker=self,
            runner=self.runner,
            audit=self.audit,
            data_dir=self.data_dir,
            limits=agent_runtime_limits,
            model_profiles=agent_model_profiles,
        )
        self.index = WorkspaceIndexService(self.store, self.filesystem)
        self.context_engine = WorkspaceContextService(self.filesystem, self.index)
        self.context_ledger = ContextLedger()
        self.compound_reads = CompoundReadExecutor(
            {
                definition.name: definition
                for definition in self.registry.all()
                if definition.name in _COMPOUND_READ_TOOLS
            },
            max_operations=20,
            max_concurrency=4,
        )
        self.snapshot_root = self.data_dir / "snapshots"
        self.snapshot_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.snapshot_root, 0o700)
        self._page_token_key = os.urandom(32)

    # ---- GUI/control plane -------------------------------------------------

    def add_scope(self, **kwargs: Any) -> dict[str, Any]:
        try:
            scope = self.policy.register_scope(**kwargs)
            self.audit.record(
                actor="user",
                tool="control.scope",
                operation="create_scope",
                decision="executed",
                scope_id=scope.id,
                target_display=scope.id,
                metadata={"label": scope.label, "kind": scope.kind},
            )
            scope_data = scope.to_dict()
            scope_data["permissions"] = self.store.permissions(scope.id)
            return {"status": "ok", "scope": scope_data}
        except (PolicyError, StorageError) as exc:
            self.audit.record(
                actor="user",
                tool="control.scope",
                operation="create_scope",
                decision="denied",
                target_display=str(kwargs.get("scope_id", "")),
                error_code=getattr(exc, "code", "STORAGE_ERROR"),
                metadata={},
            )
            return {"status": "denied", "error_code": getattr(exc, "code", "STORAGE_ERROR"), "message": str(exc)}

    def update_scope(self, scope_id: str, **changes: Any) -> dict[str, Any]:
        try:
            self.policy.get_scope(scope_id, require_enabled=False)
            self.store.bump_policy_version()
            scope = self.store.update_scope(scope_id, **changes)
            self.audit.record(
                actor="user",
                tool="control.scope",
                operation="update_scope",
                decision="executed",
                scope_id=scope_id,
                target_display=scope_id,
                metadata={"changes": {key: value for key, value in changes.items() if key != "root"}},
            )
            return {"status": "ok", "scope": scope.to_dict()}
        except (PolicyError, StorageError) as exc:
            return {"status": "denied", "error_code": getattr(exc, "code", "STORAGE_ERROR"), "message": str(exc)}

    def remove_scope(self, scope_id: str) -> dict[str, Any]:
        try:
            self.policy.get_scope(scope_id, require_enabled=False)
            self.store.bump_policy_version()
            self.store.delete_scope(scope_id)
            self.audit.record(
                actor="user",
                tool="control.scope",
                operation="delete_scope",
                decision="executed",
                scope_id=scope_id,
                target_display=scope_id,
            )
            return {"status": "ok"}
        except (PolicyError, StorageError) as exc:
            return {"status": "denied", "error_code": getattr(exc, "code", "STORAGE_ERROR"), "message": str(exc)}

    def set_permission(self, scope_id: str, capability: str, **kwargs: Any) -> dict[str, Any]:
        try:
            self.policy.get_scope(scope_id, require_enabled=False)
            self.store.set_permission(scope_id, capability, **kwargs)
            version = self.store.bump_policy_version()
            self.audit.record(
                actor="user",
                tool="control.permission",
                operation="set_permission",
                decision="executed",
                scope_id=scope_id,
                target_display=f"{scope_id}:{capability}",
                metadata={"capability": capability, "allowed": bool(kwargs.get("allowed", False)), "policy_version": version},
            )
            return {"status": "ok", "policy_version": version}
        except (PolicyError, StorageError) as exc:
            return {"status": "denied", "error_code": getattr(exc, "code", "STORAGE_ERROR"), "message": str(exc)}

    def set_tool_policy(self, tool_name: str, **kwargs: Any) -> dict[str, Any]:
        try:
            policy = self.store.set_tool_policy(tool_name, **kwargs)
            version = self.store.bump_policy_version()
            self.audit.record(
                actor="user",
                tool="control.tool",
                operation="set_tool_policy",
                decision="executed",
                target_display=tool_name,
                metadata={"enabled": policy.enabled, "approval_mode": policy.approval_mode, "policy_version": version},
            )
            return {"status": "ok", "policy": policy.to_dict(), "policy_version": version}
        except StorageError as exc:
            return {"status": "denied", "error_code": "STORAGE_ERROR", "message": str(exc)}

    def pending_approvals(self) -> list[dict[str, Any]]:
        self._expire_pending()
        return [
            request.to_dict(include_payload=False)
            for request in self.store.list_approvals((ApprovalStatus.PENDING,))
            if self._is_approval_request(request)
        ]

    def actionable_approvals(self) -> list[dict[str, Any]]:
        """Return pending requests and approved requests waiting for Apply."""
        self._expire_pending()
        return [
            request.to_dict(include_payload=False)
            for request in self.store.list_approvals((ApprovalStatus.PENDING, ApprovalStatus.APPROVED))
            if self._is_approval_request(request)
        ]

    def approve(self, approval_id: str, reason: str | None = None) -> dict[str, Any]:
        request = self.store.get_approval(approval_id)
        if not request:
            return {"status": "denied", "error_code": "APPROVAL_NOT_FOUND"}
        if not self._is_approval_request(request):
            return {"status": "denied", "error_code": "APPROVAL_NOT_REQUIRED", "message": "this action does not require Control Center approval"}
        if self._expired(request.expires_at):
            self.store.decide_approval(
                approval_id,
                ApprovalStatus.EXPIRED,
                "approval expired",
                expected_status=ApprovalStatus.PENDING,
            )
            return {"status": "denied", "error_code": "APPROVAL_EXPIRED"}
        if request.status != ApprovalStatus.PENDING:
            return {"status": "denied", "error_code": "APPROVAL_ALREADY_USED"}
        if not self.store.decide_approval(
            approval_id,
            ApprovalStatus.APPROVED,
            reason or "approved in Control Center",
            expected_status=ApprovalStatus.PENDING,
        ):
            return {"status": "denied", "error_code": "APPROVAL_ALREADY_USED"}
        self.audit.record(
            actor="user",
            tool="control.approval",
            operation="approve",
            decision="approved",
            approval_id=approval_id,
            target_display=self._intent_display(request.intent),
            request_id=request.intent.get("request_id"),
            session_id=request.intent.get("session_id"),
            trace_id=request.intent.get("trace_id"),
            metadata={"action_hash": request.action_hash},
        )
        return {"status": "ok", "approval_id": approval_id, "state": ApprovalStatus.APPROVED}

    def deny(self, approval_id: str, reason: str | None = None) -> dict[str, Any]:
        request = self.store.get_approval(approval_id)
        if not request:
            return {"status": "denied", "error_code": "APPROVAL_NOT_FOUND"}
        if request.status != ApprovalStatus.PENDING:
            return {"status": "denied", "error_code": "APPROVAL_ALREADY_USED"}
        if not self.store.decide_approval(
            approval_id,
            ApprovalStatus.DENIED,
            reason or "denied in Control Center",
            expected_status=ApprovalStatus.PENDING,
        ):
            return {"status": "denied", "error_code": "APPROVAL_ALREADY_USED"}
        self.audit.record(
            actor="user",
            tool="control.approval",
            operation="deny",
            decision="denied",
            approval_id=approval_id,
            target_display=self._intent_display(request.intent),
            request_id=request.intent.get("request_id"),
            session_id=request.intent.get("session_id"),
            trace_id=request.intent.get("trace_id"),
            error_code="USER_DENIED",
            metadata={"action_hash": request.action_hash},
        )
        return {"status": "ok", "approval_id": approval_id, "state": ApprovalStatus.DENIED}

    def audit_page(self, limit: int = 100) -> list[dict[str, Any]]:
        return self.store.audit_rows(limit)

    def verify_audit(self) -> dict[str, Any]:
        valid, message = self.audit.verify_chain()
        return {"valid": valid, "message": message}

    def tool_rows(self) -> list[dict[str, Any]]:
        policies = {policy.tool_name: policy for policy in self.store.list_tool_policies()}
        result = []
        for definition in self.registry.all():
            policy = policies[definition.name]
            result.append({
                **definition.to_metadata(),
                **policy.to_dict(),
            })
        return result

    def configure_agent_profile(self, profile: AgentProfile) -> dict[str, Any]:
        """Register one fixed agent adapter from the local control plane.

        This is deliberately a non-MCP control-plane seam.  An MCP caller can
        select only names already registered here; it cannot supply an
        executable, argument vector, environment, or working directory.
        """

        self.agent_tasks.register_profile(profile)
        self.audit.record(
            actor="user",
            tool="control.agent_profile",
            operation="configure",
            decision="executed",
            target_display=profile.name,
            metadata={"profile": profile.name},
        )
        return {"status": "ok", "profile": profile.name}

    def configure_agent_model_profile(self, profile: AgentModelProfile) -> dict[str, Any]:
        """Register a provider/model profile from trusted local configuration.

        This is deliberately outside the MCP data plane.  MCP callers can
        choose only the resulting profile name; they cannot provide provider
        URLs, credentials, executables, environments, or system prompts.
        """

        self.agent_runtime.register_model_profile(profile)
        self.audit.record(
            actor="user",
            tool="control.agent_model_profile",
            operation="configure",
            decision="executed",
            target_display=profile.name,
            metadata={"profile": profile.name, "provider": profile.provider_name, "model": profile.model},
        )
        return {"status": "ok", "profile": profile.to_dict()}

    def close(self) -> None:
        """Stop owned browser/provider runtimes before closing SQLite state."""

        try:
            self.browser.close_all()
        finally:
            try:
                self.agent_runtime.shutdown()
            finally:
                self.store.close()

    # ---- MCP data plane ----------------------------------------------------

    def invoke(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        *,
        actor: str = "chatgpt",
        session_id: str | None = None,
        request_id: str | None = None,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        if args is None:
            args = {}
        context = RequestContext(
            actor,
            session_id or str(uuid.uuid4()),
            request_id or str(uuid.uuid4()),
            trace_id or str(uuid.uuid4()),
            time.monotonic(),
        )
        if not isinstance(args, dict):
            self.audit.record(
                actor=actor,
                tool=tool,
                operation="request",
                decision="denied",
                target_display="",
                session_id=context.session_id,
                request_id=context.request_id,
                error_code="INVALID_INPUT",
                metadata={},
                trace_id=context.trace_id,
                duration_ms=self._duration_ms(context),
            )
            return {
                "status": "denied",
                "error_code": "INVALID_INPUT",
                "message": "tool arguments must be an object",
                "request_id": context.request_id,
                "trace_id": context.trace_id,
            }
        try:
            if self.registry.get(tool) is None:
                raise PolicyError("TOOL_NOT_FOUND", f"unknown tool: {tool}")
            self.policy.require_tool(tool, actor=actor)
            try:
                validate_tool_args(tool, args)
            except ValueError as exc:
                raise PolicyError("INVALID_INPUT", f"schema validation failed: {exc}") from exc
            handler = getattr(self, f"_tool_{tool}", None)
            if not handler:
                raise PolicyError("TOOL_NOT_IMPLEMENTED", f"tool is not implemented: {tool}")
            result = handler(args, context)
            if isinstance(result, dict):
                result.setdefault("request_id", context.request_id)
                result.setdefault("trace_id", context.trace_id)
            return result
        except PolicyError as exc:
            self.audit.record(
                actor=actor,
                tool=tool,
                operation="request",
                decision="denied",
                target_display=self._safe_display(args),
                session_id=context.session_id,
                request_id=context.request_id,
                scope_id=args.get("scope_id") if isinstance(args.get("scope_id"), str) else None,
                error_code=exc.code,
                metadata={},
                trace_id=context.trace_id,
                duration_ms=self._duration_ms(context),
            )
            return {
                "status": "denied",
                "error_code": exc.code,
                "message": exc.message,
                "request_id": context.request_id,
                "trace_id": context.trace_id,
            }
        except Exception as exc:  # fail closed at the MCP seam
            self.audit.record(
                actor=actor,
                tool=tool,
                operation="request",
                decision="failed",
                target_display=self._safe_display(args),
                session_id=context.session_id,
                request_id=context.request_id,
                error_code="INTERNAL_ERROR",
                metadata={"exception_type": type(exc).__name__},
                trace_id=context.trace_id,
                duration_ms=self._duration_ms(context),
            )
            return {
                "status": "failed",
                "error_code": "INTERNAL_ERROR",
                "message": "operation failed closed",
                "request_id": context.request_id,
                "trace_id": context.trace_id,
            }

    def _tool_list_scopes(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scopes = self.policy.scope_summary(actor=context.actor)
        self._audit_success(context, "list_scopes", "list", ".", metadata={"count": len(scopes)})
        return {"status": "ok", "scopes": scopes, "policy_version": self.store.policy_version()}

    def _tool_list_files(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        relative = args.get("relative_path", ".")
        scope, target, display = self.policy.resolve_path(scope_id, relative, actor=context.actor, must_exist=True)
        self.policy.require_capability(scope_id, Capability.READ, actor=context.actor, item_count=1)
        requested_items = self._bounded_int(args.get("max_items", 100), 1, 500)
        entries = self.filesystem.list_entries(target, Path(scope.root), max_items=requested_items + 1)
        truncated = len(entries) > requested_items
        entries = entries[:requested_items]
        self._audit_success(context, "list_files", "list", f"{scope_id}:{display}", scope_id=scope_id, metadata={"count": len(entries), "truncated": truncated})
        return {"status": "ok", "scope_id": scope_id, "relative_path": display, "entries": entries, "truncated": truncated, "has_more": truncated}

    def _tool_read_file(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        relative = self._require_string(args, "relative_path")
        scope, target, display = self.policy.resolve_path(scope_id, relative, actor=context.actor, must_exist=True)
        _, permission = self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
        text, digest = self.filesystem.read_text(target, max_bytes=min(MAX_READ_BYTES, int(permission["max_bytes"])))
        self._audit_success(context, "read_file", "read", f"{scope_id}:{display}", scope_id=scope_id, pre_hash=digest, metadata={"bytes": len(text.encode("utf-8"))})
        return {"status": "ok", "scope_id": scope_id, "relative_path": display, "content": text, "content_hash": digest}

    def _tool_search_text(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        relative = args.get("relative_path", ".")
        query = self._require_string(args, "query")
        scope, target, display = self.policy.resolve_path(scope_id, relative, actor=context.actor, must_exist=True)
        self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
        requested_results = self._bounded_int(args.get("max_results", 100), 1, 500)
        results = self.filesystem.search_text(Path(scope.root), target, query, max_results=requested_results + 1)
        truncated = len(results) > requested_results
        results = results[:requested_results]
        self._audit_success(context, "search_text", "search", f"{scope_id}:{display}", scope_id=scope_id, metadata={"query_length": len(query), "count": len(results), "truncated": truncated})
        return {"status": "ok", "scope_id": scope_id, "relative_path": display, "results": results, "truncated": truncated, "has_more": truncated}

    def _tool_apply_patch(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        relative = self._require_string(args, "relative_path")
        patch = self._require_string(args, "patch")
        scope, target, display = self.policy.resolve_path(
            scope_id, relative, actor=context.actor, must_exist=True
        )
        _, permission = self.policy.require_capability(
            scope_id,
            Capability.WRITE,
            actor=context.actor,
            byte_count=len(patch.encode("utf-8")),
        )
        if not target.is_file() or target.is_symlink():
            raise PolicyError("NOT_A_FILE", "apply_patch only handles one regular file")
        raw_text, current_hash = self.filesystem.read_text_raw(
            target, max_bytes=min(MAX_READ_BYTES, int(permission["max_bytes"]))
        )
        supplied_hash = args.get("expected_hash")
        if supplied_hash is not None and supplied_hash != current_hash:
            raise PolicyError("PRECONDITION_CHANGED", "target hash does not match expected_hash")
        # Always record the observed hash, even when the caller omitted the
        # optional precondition.  The execution path rechecks this exact value.
        payload = {
            "scope_id": scope_id,
            "relative_path": display,
            "patch": patch,
            "expected_hash": current_hash,
        }
        return self._authorize_mutation(
            context,
            tool="apply_patch",
            operation="patch",
            scope_id=scope_id,
            targets=[display],
            payload=payload,
            expected={display: current_hash},
            permission=permission,
        )

    def _tool_read_many_files(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        files = args.get("files")
        if not isinstance(files, list) or not files:
            raise PolicyError("INVALID_INPUT", "files must be a non-empty list")
        self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)

        def read_one(item: Any) -> dict[str, Any]:
            try:
                if not isinstance(item, dict):
                    raise PolicyError("INVALID_INPUT", "each files item must be an object")
                path = item.get("path", item.get("relative_path"))
                if not isinstance(path, str) or not path:
                    raise PolicyError("INVALID_INPUT", "each files item needs path or relative_path")
                if item.get("path") is not None and item.get("relative_path") is not None:
                    raise PolicyError("INVALID_INPUT", "provide only one of path and relative_path")
                scope, target, display = self.policy.resolve_path(
                    scope_id, path, actor=context.actor, must_exist=True
                )
                _, permission = self.policy.require_capability(
                    scope_id, Capability.READ, actor=context.actor
                )
                start_line = item.get("start_line", 1)
                end_line = item.get("end_line")
                if not isinstance(start_line, int) or start_line < 1:
                    raise PolicyError("INVALID_INPUT", "start_line must be a positive integer")
                if end_line is not None and (not isinstance(end_line, int) or end_line < start_line):
                    raise PolicyError("INVALID_INPUT", "end_line must be at least start_line")
                max_lines = min(1000, end_line - start_line + 1) if end_line is not None else 200
                content, digest, returned_start, returned_end, has_more = self.filesystem.read_text_page(
                    target,
                    start_line=start_line,
                    max_lines=max_lines,
                    max_bytes=min(int(permission["max_bytes"]), 128 * 1024),
                )
                return {
                    "status": "ok",
                    "relative_path": display,
                    "content": content,
                    "content_hash": digest,
                    "start_line": returned_start,
                    "end_line": returned_end,
                    "has_more": has_more,
                    "continuation_token": self._page_token(
                        scope_id, display, returned_end + 1, max_lines, min(int(permission["max_bytes"]), 128 * 1024), context, digest
                    ) if has_more else None,
                }
            except PolicyError as exc:
                return {
                    "status": "error",
                    "relative_path": item.get("path", item.get("relative_path")) if isinstance(item, dict) else None,
                    "error_code": exc.code,
                    "message": exc.message,
                }
            except OSError:
                return {
                    "status": "error",
                    "relative_path": item.get("path", item.get("relative_path")) if isinstance(item, dict) else None,
                    "error_code": "FILESYSTEM_ERROR",
                    "message": "unable to read requested file",
                }

        with ThreadPoolExecutor(max_workers=min(4, len(files))) as executor:
            results = list(executor.map(read_one, files))
        self._audit_success(
            context,
            "read_many_files",
            "read_many",
            f"{scope_id}:batch",
            scope_id=scope_id,
            metadata={
                "requested": len(files),
                "succeeded": sum(item.get("status") == "ok" for item in results),
                "failed": sum(item.get("status") == "error" for item in results),
            },
        )
        return {"status": "ok", "scope_id": scope_id, "files": results}

    def _tool_tool_batch(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        """Run bounded read children through the normal broker seam.

        The parent scope is only an execution anchor.  Every child is still
        dispatched through ``invoke`` so child tool enablement, schema,
        capability, path policy, and audit behavior remain independent.
        """

        scope_id = self._require_string(args, "scope_id")
        self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)

        def dispatch(operation: str, child_args: dict[str, Any]) -> dict[str, Any]:
            definition = self.registry.get(operation)
            if definition is None:
                raise PolicyError("TOOL_NOT_FOUND", f"unknown tool: {operation}")
            properties = definition.schema.get("properties", {})
            if "scope_id" in properties:
                supplied_scope = child_args.get("scope_id")
                if supplied_scope is None:
                    child_args["scope_id"] = scope_id
                elif supplied_scope != scope_id:
                    raise PolicyError("SCOPE_MISMATCH", "each batch child must use the parent scope_id")
            return self.invoke(
                operation,
                child_args,
                actor=context.actor,
                session_id=context.session_id,
                trace_id=context.trace_id,
            )

        result = self.compound_reads.execute(args.get("operations"), dispatch)
        metadata = {
            "requested": result.get("requested", len(args.get("operations", [])) if isinstance(args.get("operations"), list) else 0),
            "succeeded": result.get("succeeded", 0),
            "failed": result.get("failed", 0),
        }
        if result.get("status") == "error":
            self._audit_success(
                context,
                "tool_batch",
                "read_batch",
                f"{scope_id}:batch",
                scope_id=scope_id,
                result_code=str(result.get("error_code") or "BATCH_ERROR"),
                decision="failed",
                metadata=metadata,
            )
        else:
            self._audit_success(
                context,
                "tool_batch",
                "read_batch",
                f"{scope_id}:batch",
                scope_id=scope_id,
                metadata=metadata,
            )
        return {"scope_id": scope_id, **result}

    def _tool_find_files(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        relative = args.get("relative_path", ".")
        pattern = args.get("pattern", "*")
        scope, target, display = self.policy.resolve_path(
            scope_id, relative, actor=context.actor, must_exist=True
        )
        self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
        matches, truncated = self.filesystem.find_files(
            Path(scope.root),
            target,
            pattern,
            max_results=self._bounded_int(args.get("max_results", 100), 1, 1000),
            include_ignored=bool(args.get("include_ignored", False)),
        )
        self._audit_success(
            context,
            "find_files",
            "find",
            f"{scope_id}:{display}",
            scope_id=scope_id,
            metadata={"pattern_length": len(pattern), "count": len(matches), "truncated": truncated},
        )
        return {
            "status": "ok",
            "scope_id": scope_id,
            "relative_path": display,
            "pattern": pattern,
            "matches": matches,
            "truncated": truncated,
            "has_more": truncated,
        }

    def _tool_search_regex(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        pattern = self._require_string(args, "pattern")
        relative = args.get("relative_path", ".")
        scope, target, display = self.policy.resolve_path(
            scope_id, relative, actor=context.actor, must_exist=True
        )
        self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
        results, truncated = self.filesystem.search_regex(
            Path(scope.root),
            target,
            pattern,
            max_results=self._bounded_int(args.get("max_results", 100), 1, 1000),
            ignore_case=bool(args.get("ignore_case", False)),
            max_file_bytes=self._bounded_int(args.get("max_file_bytes", 512_000), 1, 50_000_000),
            timeout_ms=self._bounded_int(args.get("timeout_ms", 5_000), 1, 60_000),
        )
        self._audit_success(
            context,
            "search_regex",
            "search",
            f"{scope_id}:{display}",
            scope_id=scope_id,
            metadata={"pattern_length": len(pattern), "count": len(results), "truncated": truncated},
        )
        return {
            "status": "ok",
            "scope_id": scope_id,
            "relative_path": display,
            "results": results,
            "truncated": truncated,
            "has_more": truncated,
        }

    def _tool_read_file_page(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        relative = self._require_string(args, "relative_path")
        return self._read_page(
            context,
            scope_id,
            relative,
            start_line=self._bounded_int(args.get("start_line", 1), 1, 50_000_000),
            max_lines=self._bounded_int(args.get("max_lines", 200), 1, 1000),
            max_bytes=self._bounded_int(args.get("max_bytes", MAX_READ_BYTES), 1, MAX_READ_BYTES),
        )

    def _tool_read_file_page_continue(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        token = self._require_string(args, "continuation_token")
        state = self._decode_page_token(token, context)
        return self._read_page(
            context,
            state["scope_id"],
            state["relative_path"],
            start_line=state["start_line"],
            max_lines=state["max_lines"],
            max_bytes=state["max_bytes"],
            expected_hash=state["content_hash"],
        )

    def _tool_write_file(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        relative = self._require_string(args, "relative_path")
        content = args.get("content")
        if not isinstance(content, str):
            raise PolicyError("INVALID_INPUT", "content must be text")
        if len(content.encode("utf-8")) > MAX_READ_BYTES:
            raise PolicyError("QUOTA_EXCEEDED", "text write exceeds 1 MB limit")
        scope, target, display = self.policy.resolve_path(scope_id, relative, actor=context.actor, must_exist=True)
        _, permission = self.policy.require_capability(scope_id, Capability.WRITE, actor=context.actor, byte_count=len(content.encode("utf-8")))
        payload = {"scope_id": scope_id, "relative_path": display, "content": content}
        return self._authorize_mutation(
            context,
            tool="write_file",
            operation="overwrite",
            scope_id=scope_id,
            targets=[display],
            payload=payload,
            expected={display: sha256_file(target)},
            permission=permission,
        )

    def _tool_create_file(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        relative = self._require_string(args, "relative_path")
        content = args.get("content", "")
        if not isinstance(content, str):
            raise PolicyError("INVALID_INPUT", "content must be text")
        scope, target, display = self.policy.resolve_path(scope_id, relative, actor=context.actor, must_exist=False)
        if target.exists():
            raise PolicyError("TARGET_EXISTS", "create_file will not overwrite an existing file")
        _, permission = self.policy.require_capability(scope_id, Capability.CREATE, actor=context.actor, byte_count=len(content.encode("utf-8")))
        payload = {"scope_id": scope_id, "relative_path": display, "content": content}
        return self._authorize_mutation(
            context,
            tool="create_file",
            operation="create",
            scope_id=scope_id,
            targets=[display],
            payload=payload,
            expected={display: None},
            permission=permission,
        )

    def _tool_create_directory(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        relative = self._require_string(args, "relative_path")
        scope, target, display = self._resolve_new_directory(scope_id, relative, context)
        _, permission = self.policy.require_capability(scope_id, Capability.CREATE, actor=context.actor)
        payload = {"scope_id": scope_id, "relative_path": display}
        return self._authorize_mutation(
            context,
            tool="create_directory",
            operation="create",
            scope_id=scope_id,
            targets=[display],
            payload=payload,
            expected={display: None},
            permission=permission,
        )

    def _tool_rename_file(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        relative = self._require_string(args, "relative_path")
        new_name = self._require_string(args, "new_name")
        if "/" in new_name or "\\" in new_name or new_name in {".", ".."}:
            raise PolicyError("INVALID_INPUT", "new_name must be one filename")
        scope, source, source_display = self.policy.resolve_path(scope_id, relative, actor=context.actor, must_exist=True)
        if not source.is_file():
            raise PolicyError("NOT_A_FILE", "rename_file only handles regular files")
        destination = source.parent / new_name
        destination_display = f"{Path(source_display).parent.as_posix()}/{new_name}" if Path(source_display).parent.as_posix() != "." else new_name
        self.policy.resolve_path(scope_id, destination_display, actor=context.actor, must_exist=False)
        _, permission = self.policy.require_capability(scope_id, Capability.RENAME, actor=context.actor)
        payload = {"scope_id": scope_id, "relative_path": source_display, "new_name": new_name, "destination_relative_path": destination_display}
        return self._authorize_mutation(
            context,
            tool="rename_file",
            operation="rename",
            scope_id=scope_id,
            targets=[source_display, destination_display],
            payload=payload,
            expected={"source": sha256_file(source), "destination": None},
            permission=permission,
        )

    def _tool_move_file(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        source_scope_id = self._require_string(args, "source_scope_id")
        source_relative = self._require_string(args, "source_relative_path")
        destination_scope_id = self._require_string(args, "destination_scope_id")
        destination_relative = self._require_string(args, "destination_relative_path")
        source_scope, source, source_display = self.policy.resolve_path(source_scope_id, source_relative, actor=context.actor, must_exist=True)
        destination_scope, destination, destination_display = self.policy.resolve_path(destination_scope_id, destination_relative, actor=context.actor, must_exist=False)
        if not source.is_file():
            raise PolicyError("NOT_A_FILE", "move_file only handles regular files")
        if destination.exists():
            raise PolicyError("TARGET_EXISTS", "move_file will not overwrite a destination")
        self.policy.require_capability(source_scope_id, Capability.MOVE, actor=context.actor)
        self.policy.require_capability(destination_scope_id, Capability.CREATE, actor=context.actor)
        payload = {
            "source_scope_id": source_scope_id,
            "source_relative_path": source_display,
            "destination_scope_id": destination_scope_id,
            "destination_relative_path": destination_display,
        }
        return self._authorize_mutation(
            context,
            tool="move_file",
            operation="move",
            scope_id=source_scope_id,
            targets=[f"{source_scope_id}:{source_display}", f"{destination_scope_id}:{destination_display}"],
            payload=payload,
            expected={"source": sha256_file(source), "destination": None},
            permission={"approval_mode": "always", "max_bytes": 1_048_576, "max_items": 1},
        )

    def _tool_bulk_move_files(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        source_scope_id = self._require_string(args, "source_scope_id")
        destination_scope_id = self._require_string(args, "destination_scope_id")
        destination_relative_directory = args.get("destination_relative_directory", ".")
        if not isinstance(destination_relative_directory, str) or not destination_relative_directory:
            raise PolicyError("INVALID_INPUT", "destination_relative_directory is required")

        destination_display, plan, item_limit = self._prepare_bulk_move(
            source_scope_id,
            args.get("source_relative_paths"),
            destination_scope_id,
            destination_relative_directory,
            context,
        )
        source_paths = [item["source_display"] for item in plan]
        items = [
            {
                "source_relative_path": item["source_display"],
                "destination_relative_path": item["destination_display"],
            }
            for item in plan
        ]
        payload = {
            "source_scope_id": source_scope_id,
            "source_relative_paths": source_paths,
            "destination_scope_id": destination_scope_id,
            "destination_relative_directory": destination_display,
            "items": items,
        }
        expected: dict[str, str | None] = {}
        for item in plan:
            expected[f"source:{item['source_display']}"] = item["source_hash"]
            expected[f"destination:{item['destination_display']}"] = None
        _, source_permission = self.policy.require_capability(source_scope_id, Capability.MOVE, actor=context.actor)
        _, destination_permission = self.policy.require_capability(destination_scope_id, Capability.CREATE, actor=context.actor)
        permission = {
            "approval_mode": "never",
            "max_bytes": min(int(source_permission["max_bytes"]), int(destination_permission["max_bytes"])),
            "max_items": item_limit,
        }
        targets = [
            f"{source_scope_id}:{item['source_display']} -> {destination_scope_id}:{item['destination_display']}"
            for item in plan
        ]
        return self._authorize_mutation(
            context,
            tool="bulk_move_files",
            operation="bulk_move",
            scope_id=source_scope_id,
            targets=targets,
            payload=payload,
            expected=expected,
            permission=permission,
        )

    def _tool_delete_file(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        relative = self._require_string(args, "relative_path")
        scope, target, display = self.policy.resolve_path(scope_id, relative, actor=context.actor, must_exist=True)
        if not target.is_file():
            raise PolicyError("NOT_A_FILE", "delete_file only handles one regular file")
        _, permission = self.policy.require_capability(scope_id, Capability.DELETE, actor=context.actor)
        payload = {"scope_id": scope_id, "relative_path": display}
        return self._authorize_mutation(
            context,
            tool="delete_file",
            operation="delete",
            scope_id=scope_id,
            targets=[display],
            payload=payload,
            expected={display: sha256_file(target)},
            permission=permission,
        )

    def _tool_csv_transform(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        return self._tool_document_edit(args, context, tool="csv_transform", suffixes={".csv"}, adapter=self.documents.transform_csv)

    def _tool_xlsx_edit(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        return self._tool_document_edit(args, context, tool="xlsx_edit", suffixes={".xlsx", ".xlsm"}, adapter=self.documents.edit_xlsx)

    def _tool_docx_edit(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        return self._tool_document_edit(args, context, tool="docx_edit", suffixes={".docx"}, adapter=self.documents.edit_docx)

    def _tool_document_edit(
        self,
        args: dict[str, Any],
        context: RequestContext,
        *,
        tool: str,
        suffixes: set[str],
        adapter: Callable[[Path, dict[str, Any]], tuple[bytes, dict[str, Any]]],
    ) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        relative = self._require_string(args, "relative_path")
        scope, target, display = self.policy.resolve_path(scope_id, relative, actor=context.actor, must_exist=True)
        if target.suffix.lower() not in suffixes:
            raise PolicyError("FORMAT_UNSUPPORTED", f"supported formats: {sorted(suffixes)}")
        _, permission = self.policy.require_capability(scope_id, Capability.WRITE, actor=context.actor)
        payload = dict(args)
        payload["scope_id"] = scope_id
        payload["relative_path"] = display
        payload.pop("content", None)
        return self._authorize_mutation(
            context,
            tool=tool,
            operation="document_edit",
            scope_id=scope_id,
            targets=[display],
            payload=payload,
            expected={display: sha256_file(target)},
            permission=permission,
        )

    def _tool_git_status(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        return self._project_read(context, "git_status", "git_status")

    def _tool_git_diff(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        return self._project_read(context, "git_diff", "git_diff")

    def _tool_git_log(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        return self._project_read(context, "git_log", "git_log")

    def _tool_git_create_branch(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id, scope, permission = self._git_execution_scope(context)
        branch = self.git.validate_branch(self._require_string(args, "branch"))
        payload = {"scope_id": scope_id, "branch": branch}
        return self._authorize_mutation(
            context,
            tool="git_create_branch",
            operation="git_create_branch",
            scope_id=scope_id,
            targets=[branch],
            payload=payload,
            expected={"project_root": sha256_json({"root": scope.root})},
            permission=permission,
        )

    def _tool_git_stage_paths(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id, scope, permission = self._git_execution_scope(context)
        paths = self.git.validate_paths(args.get("paths"))
        expected = self._git_path_preconditions(scope_id, paths, context)
        payload = {"scope_id": scope_id, "paths": paths}
        return self._authorize_mutation(
            context,
            tool="git_stage_paths",
            operation="git_stage",
            scope_id=scope_id,
            targets=paths,
            payload=payload,
            expected={**expected, "project_root": sha256_json({"root": scope.root})},
            permission=permission,
        )

    def _tool_git_commit(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id, scope, permission = self._git_execution_scope(context)
        message = self.git.commit_message(self._require_string(args, "message"))
        paths = self.git.validate_paths(args.get("paths"))
        expected = self._git_path_preconditions(scope_id, paths, context)
        payload = {"scope_id": scope_id, "message": message, "paths": paths}
        return self._authorize_mutation(
            context,
            tool="git_commit",
            operation="git_commit",
            scope_id=scope_id,
            targets=paths,
            payload=payload,
            expected={**expected, "project_root": sha256_json({"root": scope.root})},
            permission=permission,
        )

    def _tool_git_restore_file(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id, scope, permission = self._git_execution_scope(context)
        path = self._require_string(args, "path")
        self._validate_git_paths(scope_id, [path], context, allow_missing=True)
        _, target, display = self.policy.resolve_path(scope_id, path, actor=context.actor, must_exist=False)
        current_hash = sha256_file(target) if target.is_file() else None
        supplied_hash = args.get("expected_hash")
        if supplied_hash is not None and supplied_hash != current_hash:
            raise PolicyError("PRECONDITION_CHANGED", "path hash does not match expected_hash")
        payload = {"scope_id": scope_id, "path": display, "expected_hash": current_hash}
        return self._authorize_mutation(
            context,
            tool="git_restore_file",
            operation="git_restore",
            scope_id=scope_id,
            targets=[display],
            payload=payload,
            expected={f"path:{display}": current_hash, "project_root": sha256_json({"root": scope.root})},
            permission=permission,
        )

    def _tool_git_push(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id, scope, permission = self._git_execution_scope(context)
        remote = self.git.validate_remote(str(args.get("remote", "origin")))
        branch_value = args.get("branch")
        branch = self.git.validate_branch(branch_value) if branch_value is not None else None
        current = self.git.run("current_branch", Path(scope.root), ["branch", "--show-current"])
        current_branch = self.git.current_branch(current)
        if branch is None:
            branch = current_branch
        if not branch:
            raise PolicyError("GIT_BRANCH_REQUIRED", "push requires a current or explicit branch")
        payload = {"scope_id": scope_id, "remote": remote, "branch": branch}
        return self._authorize_mutation(
            context,
            tool="git_push",
            operation="git_push",
            scope_id=scope_id,
            targets=[f"{remote}/{branch}"],
            payload=payload,
            expected={"branch": current_branch, "project_root": sha256_json({"root": scope.root})},
            permission=permission,
        )

    def _git_execution_scope(self, context: RequestContext) -> tuple[str, Any, dict[str, Any]]:
        scope_id = self._project_scope_id()
        scope, permission = self.policy.require_execution(scope_id, actor=context.actor)
        if scope.kind != ScopeKind.PROJECT:
            raise PolicyError("INVALID_SCOPE", "Git mutation requires a project scope")
        return scope_id, scope, permission

    def _validate_git_paths(
        self,
        scope_id: str,
        paths: list[str],
        context: RequestContext,
        *,
        allow_missing: bool = True,
    ) -> None:
        for path in self.git.validate_paths(paths):
            _, target, _ = self.policy.resolve_path(
                scope_id, path, actor=context.actor, must_exist=not allow_missing
            )
            if target.exists() and (target.is_dir() or target.is_symlink()):
                raise PolicyError("INVALID_INPUT", "Git operations accept regular files only")

    def _git_path_preconditions(
        self,
        scope_id: str,
        paths: list[str],
        context: RequestContext,
    ) -> dict[str, str | None]:
        self._validate_git_paths(scope_id, paths, context)
        expected: dict[str, str | None] = {}
        for path in paths:
            _, target, display = self.policy.resolve_path(
                scope_id, path, actor=context.actor, must_exist=False
            )
            expected[f"path:{display}"] = sha256_file(target) if target.is_file() else None
        return expected

    def _project_read(self, context: RequestContext, tool: str, profile: str) -> dict[str, Any]:
        scope_id = self._project_scope_id()
        scope, _ = self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
        if scope.kind != ScopeKind.PROJECT:
            raise PolicyError("INVALID_SCOPE", "git tools require a project scope")
        tool_policy = self.store.get_tool_policy(tool)
        if tool_policy is None:
            raise PolicyError("TOOL_NOT_FOUND", f"tool policy is missing: {tool}")
        result = self.runner.run(
            profile,
            Path(scope.root),
            output_limit=tool_policy.output_limit_bytes,
            timeout_seconds=max(1, tool_policy.max_duration_ms // 1000),
        )
        result = self._redact_command_result(result)
        self._audit_success(
            context,
            tool,
            "read",
            scope_id,
            scope_id=scope_id,
            result_code=str(result.exit_code),
            metadata={"profile": profile, "stdout_bytes": len(result.stdout.encode()), "stderr_bytes": len(result.stderr.encode())},
        )
        return {"status": "ok", "scope_id": scope_id, "result": result.to_dict()}

    def _tool_run_backend_test(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        return self._project_execution(context, "run_backend_test", "backend_pytest", args)

    def _tool_run_frontend_test(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        return self._project_execution(context, "run_frontend_test", "frontend_test", args)

    def _tool_run_build(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        return self._project_execution(context, "run_build", "run_build", args)

    def _tool_run_targeted_test(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        return self._project_execution(context, "run_targeted_test", "run_targeted_test", args)

    def _tool_run_lint(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        return self._project_execution(context, "run_lint", "run_lint", args)

    def _tool_run_typecheck(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        return self._project_execution(context, "run_typecheck", "run_typecheck", args)

    def _tool_process_start_profile(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        profile_name = self._require_string(args, "profile")
        scope, permission = self.policy.require_execution(scope_id, actor=context.actor)
        if scope.kind != ScopeKind.PROJECT:
            raise PolicyError("INVALID_SCOPE", "managed project processes require a project scope")
        profile = self.runner._resolve_project_profile(
            profile_name,
            Path(scope.root),
            target=None,
            test_path=None,
        )
        payload = {
            "scope_id": scope_id,
            "profile": profile.name,
            "timeout_seconds": args.get("timeout_seconds"),
        }
        return self._authorize_mutation(
            context,
            tool="process_start_profile",
            operation="process_start",
            scope_id=scope_id,
            targets=[profile.name],
            payload=payload,
            expected={"project_root": sha256_json({"root": scope.root})},
            permission=permission,
        )

    def _tool_process_status(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        process_id = args.get("process_id")
        if process_id is not None and not isinstance(process_id, str):
            raise PolicyError("INVALID_INPUT", "process_id must be text")
        records = self.processes.status(process_id)
        visible: list[dict[str, Any]] = []
        for record in records:
            row = self.store.get_runtime_by_id(record.get("process_id", "")) or {}
            scope_id = row.get("scope_id")
            if isinstance(scope_id, str):
                self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
            visible.append(record)
        self._audit_success(
            context,
            "process_status",
            "status",
            str(process_id or "managed_project"),
            process_id=process_id,
            metadata={"count": len(visible)},
        )
        return {"status": "ok", "processes": visible}

    def _tool_process_logs(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        process_id = self._require_string(args, "process_id")
        row = self.store.get_runtime_by_id(process_id)
        if not row or row.get("kind") != "managed_project":
            raise PolicyError("PROCESS_NOT_FOUND", "managed process was not found")
        scope_id = row.get("scope_id")
        if not isinstance(scope_id, str):
            raise PolicyError("PROCESS_SCOPE_UNKNOWN", "managed process has no registered scope")
        self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
        result = self.processes.logs(
            process_id,
            tail_lines=self._bounded_int(args.get("tail_lines", 100), 1, 500),
            since_sequence=args.get("since_sequence"),
        )
        self._audit_success(
            context,
            "process_logs",
            "read_logs",
            process_id,
            scope_id=scope_id,
            process_id=process_id,
            metadata={"count": len(result.get("entries", [])), "truncated": result.get("truncated", False)},
        )
        return result

    def _tool_process_stop(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        process_id = self._require_string(args, "process_id")
        row = self.store.get_runtime_by_id(process_id)
        if not row or row.get("kind") != "managed_project":
            raise PolicyError("PROCESS_NOT_FOUND", "managed process was not found")
        scope_id = row.get("scope_id")
        if not isinstance(scope_id, str):
            raise PolicyError("PROCESS_SCOPE_UNKNOWN", "managed process has no registered scope")
        _, permission = self.policy.require_execution(scope_id, actor=context.actor)
        payload = {"scope_id": scope_id, "process_id": process_id}
        return self._authorize_mutation(
            context,
            tool="process_stop",
            operation="process_stop",
            scope_id=scope_id,
            targets=[process_id],
            payload=payload,
            expected={"command_digest": row.get("command_digest")},
            permission=permission,
        )

    def _tool_workspace_snapshot(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope = self._workspace_scope(args.get("scope_id"), context)
        self.policy.require_capability(scope.id, Capability.READ, actor=context.actor)
        root = Path(scope.root)
        git_result: dict[str, Any] | None = None
        if scope.kind == ScopeKind.PROJECT:
            command = self._redact_command_result(
                self.runner.run("git_status", root, output_limit=32_768, timeout_seconds=30)
            )
            git_result = command.to_dict()
        result = self.context_engine.snapshot(
            root,
            max_items=self._bounded_int(args.get("max_items", 100), 1, 500),
            git_result=git_result,
            profiles=self.runner.available_profiles(root) if scope.kind == ScopeKind.PROJECT else [],
            processes=self._visible_processes(context),
            recent_errors=self._recent_errors(100),
        )
        result.update({"scope_id": scope.id, "status": "ok"})
        self._audit_success(
            context,
            "workspace_snapshot",
            "snapshot",
            scope.id,
            scope_id=scope.id,
            metadata={"top_level_count": len(result.get("top_level", []))},
        )
        return result

    def _tool_workspace_context(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope = self._workspace_scope(args.get("scope_id"), context)
        self.policy.require_capability(scope.id, Capability.READ, actor=context.actor)
        relative = args.get("path", ".")
        if not isinstance(relative, str):
            raise PolicyError("INVALID_INPUT", "path must be text")
        _, target, display = self.policy.resolve_path(scope.id, relative, actor=context.actor, must_exist=True)
        root = Path(scope.root)
        git_result = self._redact_command_result(
            self.runner.run("git_status", root, output_limit=32_768, timeout_seconds=30)
        )
        indexed_symbols = self.store.workspace_symbol_rows(scope.id)
        result = self.context_engine.context(
            root,
            target,
            self._require_string(args, "query"),
            intent=args.get("intent", "explore"),
            max_files=self._bounded_int(args.get("max_files", 20), 1, 100),
            max_bytes=self._bounded_int(args.get("max_bytes", 500_000), 1, 2_000_000),
            changed_files=self.context_engine.changed_paths(git_result.stdout),
            indexed_symbols=indexed_symbols,
        )
        result.update({"scope_id": scope.id, "relative_path": display})
        delivery_key = args.get("delivery_key")
        if delivery_key is not None:
            ledger_result = self.context_ledger.deliver(
                f"{scope.id}:{delivery_key}",
                sha256_json(result),
            )
            result["context_delivery"] = ledger_result
            if ledger_result.get("status") == "unchanged":
                for item in result.get("files", []):
                    if isinstance(item, dict) and "snippets" in item:
                        item.pop("snippets", None)
                        item["snippets_omitted"] = True
                result["content_reused"] = True
        self._audit_success(
            context,
            "workspace_context",
            "context",
            f"{scope.id}:{display}",
            scope_id=scope.id,
            metadata={
                "file_count": result.get("file_count", 0),
                "bytes": result.get("bytes", 0),
                "content_reused": bool(result.get("content_reused", False)),
            },
        )
        return result

    def _tool_workspace_index(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        scope = self.policy.get_scope(scope_id, actor=context.actor)
        self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
        if scope.kind == ScopeKind.FILE:
            raise PolicyError("INVALID_SCOPE", "workspace index requires a directory or project scope")
        if not bool(args.get("refresh", True)):
            result = {"status": "ok", "scope_id": scope_id, "index": self.index.status(scope_id)}
            self._audit_success(
                context,
                "workspace_index",
                "index_status",
                scope_id,
                scope_id=scope_id,
                metadata={"refresh": False},
            )
            return result
        result = self.index.build(
            scope_id,
            Path(scope.root),
            max_files=self._bounded_int(args.get("max_files", 10_000), 1, 10_000),
            include_ignored=bool(args.get("include_ignored", False)),
        )
        self._audit_success(
            context,
            "workspace_index",
            "index",
            scope_id,
            scope_id=scope_id,
            metadata=result,
        )
        return {"status": "ok", "scope_id": scope_id, "index": result}

    def _tool_workspace_index_status(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = args.get("scope_id")
        if scope_id is not None and not isinstance(scope_id, str):
            raise PolicyError("INVALID_INPUT", "scope_id must be text")
        if scope_id:
            self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
            rows = self.index.status(scope_id)
        else:
            rows = []
            for item in self.policy.scope_summary(actor=context.actor, include_disabled=False):
                if item.get("permissions", {}).get(str(Capability.READ), {}).get("allowed"):
                    rows.extend(self.index.status(str(item["id"])))
        self._audit_success(
            context,
            "workspace_index_status",
            "index_status",
            str(scope_id or "visible_scopes"),
            scope_id=scope_id,
            metadata={"count": len(rows)},
        )
        return {"status": "ok", "scope_id": scope_id, "indexes": rows}

    def _tool_dependency_graph(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        scope, target, display = self.policy.resolve_path(
            scope_id,
            args.get("path", "."),
            actor=context.actor,
            must_exist=True,
        )
        self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
        if not target.is_dir() or target.is_symlink():
            raise PolicyError("INVALID_SCOPE", "dependency graph requires a regular directory target")

        limits = GraphLimits(
            max_files=self._bounded_int(args.get("max_files", 1000), 1, 10_000),
            max_edges=self._bounded_int(args.get("max_edges", 5000), 1, 50_000),
            max_file_bytes=self._bounded_int(args.get("max_file_bytes", 1_048_576), 1, 5_000_000),
            max_output_bytes=self._bounded_int(args.get("max_output_bytes", 2_000_000), 512, 10_000_000),
            max_specifier_length=self._bounded_int(args.get("max_specifier_length", 256), 1, 4096),
        )
        graph = build_dependency_graph(
            target,
            files=args.get("files"),
            limits=limits,
            include_ignored=bool(args.get("include_ignored", False)),
        )
        self._audit_success(
            context,
            "dependency_graph",
            "dependency_graph",
            f"{scope_id}:{display}",
            scope_id=scope_id,
            metadata={
                "nodes": graph.get("counts", {}).get("nodes", 0),
                "edges": graph.get("counts", {}).get("edges", 0),
                "unresolved": graph.get("counts", {}).get("unresolved", 0),
                "truncated": bool(graph.get("truncated")),
            },
        )
        return {"status": "ok", "scope_id": scope.id, "relative_path": display, **graph}

    def _tool_agent_status(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        records = self.agent_tasks.status()
        visible: list[dict[str, Any]] = []
        for record in records:
            scope_id = record.get("scope_id")
            if not isinstance(scope_id, str):
                continue
            try:
                self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
            except PolicyError:
                continue
            visible.append(record)
        self._audit_success(
            context,
            "agent_status",
            "agent_status",
            "configured_agents",
            metadata={
                "profiles": len(self.agent_tasks.profile_names()),
                "model_profiles": len(self.agent_runtime.profile_names()),
                "tasks": len(visible),
            },
        )
        return {
            "status": "ok",
            "profiles": self.agent_tasks.profile_names(),
            "model_profiles": self.agent_runtime.profile_metadata(),
            "tasks": visible,
        }

    def _agent_task_record(
        self,
        task_id: str,
        context: RequestContext,
        capability: str,
    ) -> tuple[dict[str, Any], str]:
        record = self.agent_tasks.status(task_id)
        if not isinstance(record, dict):
            raise PolicyError("TASK_NOT_FOUND", "delegated agent task was not found")
        scope_id = record.get("scope_id")
        if not isinstance(scope_id, str) or not scope_id:
            raise PolicyError("TASK_SCOPE_UNKNOWN", "delegated agent task has no approved scope")
        self.policy.require_capability(scope_id, capability, actor=context.actor)
        return record, scope_id

    def _tool_agent_task_status(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        task_id = self._require_string(args, "task_id")
        record, scope_id = self._agent_task_record(task_id, context, Capability.READ)
        self._audit_success(
            context,
            "agent_task_status",
            "agent_task_status",
            task_id,
            scope_id=scope_id,
            metadata={"state": record.get("state")},
        )
        return record

    def _tool_agent_task_logs(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        task_id = self._require_string(args, "task_id")
        _, scope_id = self._agent_task_record(task_id, context, Capability.READ)
        result = self.agent_tasks.logs(
            task_id,
            tail_lines=self._bounded_int(args.get("tail_lines", 100), 1, 500),
            since_sequence=args.get("since_sequence"),
            stream=args.get("stream", "combined"),
        )
        self._audit_success(
            context,
            "agent_task_logs",
            "agent_task_logs",
            task_id,
            scope_id=scope_id,
            metadata={"entries": len(result.get("entries", [])), "truncated": bool(result.get("truncated"))},
        )
        return result

    def _tool_agent_result(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        task_id = self._require_string(args, "task_id")
        record, scope_id = self._agent_task_record(task_id, context, Capability.READ)
        result = self.agent_tasks.result(task_id)
        self._audit_success(
            context,
            "agent_result",
            "agent_result",
            task_id,
            scope_id=scope_id,
            metadata={"state": record.get("state"), "result_available": True},
        )
        return result

    def _tool_agent_run(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        scope, _ = self.policy.require_execution(scope_id, actor=context.actor)
        if scope.kind != ScopeKind.PROJECT:
            raise PolicyError("INVALID_SCOPE", "delegated coding-agent tasks require a project scope")
        task = self.agent_tasks.start_task(
            self._require_string(args, "profile"),
            scope_id=scope_id,
            scope_root=scope.root,
            prompt=self._require_string(args, "prompt"),
            timeout_seconds=args.get("timeout_seconds"),
        )
        self._audit_success(
            context,
            "agent_run",
            "agent_run",
            str(task.get("task_id", "agent-task")),
            scope_id=scope_id,
            metadata={"profile": task.get("profile"), "state": task.get("state")},
        )
        return task

    def _tool_agent_cancel(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        task_id = self._require_string(args, "task_id")
        _, scope_id = self._agent_task_record(task_id, context, Capability.EXECUTE)
        result = self.agent_tasks.cancel(task_id)
        self._audit_success(
            context,
            "agent_cancel",
            "agent_cancel",
            task_id,
            scope_id=scope_id,
            metadata={"state": result.get("state")},
        )
        return result

    # ---- provider-backed Agent Task API -----------------------------------

    def _agent_runtime_record(
        self,
        task_id: str,
        context: RequestContext,
        capability: str,
    ) -> dict[str, Any]:
        if not isinstance(task_id, str) or not task_id:
            raise PolicyError("TASK_ID_INVALID", "task_id is required")
        row = self.store.get_agent_task(task_id)
        if row is None:
            raise PolicyError("TASK_NOT_FOUND", "agent task was not found")
        scope_id = row.get("scope_id")
        if not isinstance(scope_id, str) or not scope_id:
            raise PolicyError("TASK_SCOPE_UNKNOWN", "agent task has no approved scope")
        self.policy.require_capability(scope_id, capability, actor=context.actor)
        return row

    def _tool_create_agent_task(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        result = self.agent_runtime.create_task(
            role=self._require_string(args, "role"),
            task=self._require_string(args, "task"),
            scope_id=self._require_string(args, "scope_id"),
            model_profile=self._require_string(args, "model_profile"),
            parent_task_id=args.get("parent_task_id"),
            base_ref=args.get("base_ref"),
            actor=context.actor,
            session_id=context.session_id,
            trace_id=context.trace_id,
        )
        self._audit_success(
            context,
            "create_agent_task",
            "create_task",
            str(result.get("task_id", "agent-task")),
            scope_id=args.get("scope_id") if isinstance(args.get("scope_id"), str) else None,
            metadata={"role": result.get("role"), "state": result.get("status"), "model_profile": result.get("model_profile")},
        )
        return result

    def _tool_get_agent_task(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        task_id = self._require_string(args, "task_id")
        row = self._agent_runtime_record(task_id, context, Capability.READ)
        result = self.agent_runtime.get_task(task_id)
        self._audit_success(
            context,
            "get_agent_task",
            "get_task",
            task_id,
            scope_id=str(row["scope_id"]),
            metadata={"state": result.get("status")},
        )
        return result

    def _tool_list_agent_tasks(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = args.get("scope_id")
        if scope_id is not None:
            if not isinstance(scope_id, str) or not scope_id:
                raise PolicyError("INVALID_INPUT", "scope_id must be text when supplied")
            self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
        tasks = self.agent_runtime.list_tasks(
            scope_id=scope_id,
            status=args.get("status"),
            limit=self._bounded_int(args.get("limit", 50), 1, 100),
        )
        visible: list[dict[str, Any]] = []
        for task in tasks:
            item_scope = task.get("scope_id")
            if not isinstance(item_scope, str):
                continue
            try:
                self.policy.require_capability(item_scope, Capability.READ, actor=context.actor)
            except PolicyError:
                continue
            visible.append(task)
        self._audit_success(
            context,
            "list_agent_tasks",
            "list_tasks",
            "agent-tasks",
            scope_id=scope_id if isinstance(scope_id, str) else None,
            metadata={"count": len(visible)},
        )
        return {"status": "ok", "tasks": visible, "count": len(visible)}

    def _tool_get_agent_result(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        task_id = self._require_string(args, "task_id")
        row = self._agent_runtime_record(task_id, context, Capability.READ)
        result = self.agent_runtime.get_result(task_id)
        self._audit_success(
            context,
            "get_agent_result",
            "get_result",
            task_id,
            scope_id=str(row["scope_id"]),
            metadata={"state": result.get("status")},
        )
        return result

    def _tool_cancel_agent_task(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        task_id = self._require_string(args, "task_id")
        row = self._agent_runtime_record(task_id, context, Capability.EXECUTE)
        result = self.agent_runtime.cancel_task(
            task_id,
            actor=context.actor,
            session_id=context.session_id,
            trace_id=context.trace_id,
        )
        self._audit_success(
            context,
            "cancel_agent_task",
            "cancel_task",
            task_id,
            scope_id=str(row["scope_id"]),
            metadata={"state": result.get("status")},
        )
        return result

    def _tool_symbol_search(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        return self._code_symbol_search(args, context, "symbol_search", definitions_only=True)

    def _tool_find_definition(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        return self._code_symbol_search(args, context, "find_definition", definitions_only=True)

    def _code_symbol_search(
        self,
        args: dict[str, Any],
        context: RequestContext,
        tool: str,
        *,
        definitions_only: bool,
    ) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        relative = args.get("relative_path", ".")
        if not isinstance(relative, str):
            raise PolicyError("INVALID_INPUT", "relative_path must be text")
        _, target, display = self.policy.resolve_path(scope_id, relative, actor=context.actor, must_exist=True)
        self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
        scope = self.policy.get_scope(scope_id, actor=context.actor)
        results, truncated = self.index.symbols(
            Path(scope.root),
            target,
            self._require_string(args, "symbol"),
            max_results=self._bounded_int(args.get("max_results", 100), 1, 1000),
            definitions_only=definitions_only,
        )
        self._audit_success(
            context,
            tool,
            "symbol_search",
            f"{scope_id}:{display}",
            scope_id=scope_id,
            metadata={"count": len(results), "truncated": truncated},
        )
        return {
            "status": "ok",
            "scope_id": scope_id,
            "relative_path": display,
            "results": results,
            "truncated": truncated,
            "has_more": truncated,
        }

    def _tool_find_references(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        scope_id = self._require_string(args, "scope_id")
        relative = args.get("relative_path", ".")
        if not isinstance(relative, str):
            raise PolicyError("INVALID_INPUT", "relative_path must be text")
        scope, target, display = self.policy.resolve_path(scope_id, relative, actor=context.actor, must_exist=True)
        self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
        results, truncated = self.index.references(
            Path(scope.root),
            target,
            self._require_string(args, "symbol"),
            max_results=self._bounded_int(args.get("max_results", 100), 1, 1000),
        )
        self._audit_success(
            context,
            "find_references",
            "reference_search",
            f"{scope_id}:{display}",
            scope_id=scope_id,
            metadata={"count": len(results), "truncated": truncated},
        )
        return {
            "status": "ok",
            "scope_id": scope_id,
            "relative_path": display,
            "results": results,
            "truncated": truncated,
            "has_more": truncated,
        }

    def _tool_dry_run(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        tool = self._require_string(args, "tool")
        arguments = args.get("arguments")
        if not isinstance(arguments, dict):
            raise PolicyError("INVALID_INPUT", "arguments must be an object")
        if tool == "dry_run":
            raise PolicyError("INVALID_INPUT", "dry_run cannot preview itself")
        definition = self.registry.get(tool)
        if definition is None:
            raise PolicyError("TOOL_NOT_FOUND", f"unknown tool: {tool}")
        try:
            validate_tool_args(tool, arguments)
        except ValueError as exc:
            raise PolicyError("INVALID_INPUT", f"schema validation failed: {exc}") from exc
        tool_enabled = True
        tool_error: str | None = None
        try:
            self.policy.require_tool(tool, actor=context.actor)
        except PolicyError as exc:
            tool_enabled = False
            tool_error = exc.code
        scope_id = arguments.get("scope_id") if isinstance(arguments.get("scope_id"), str) else None
        if scope_id is None and tool in {
            "git_create_branch", "git_stage_paths", "git_commit", "git_restore_file", "git_push",
            "run_backend_test", "run_frontend_test", "run_targeted_test", "run_lint", "run_typecheck", "run_build",
        }:
            scope_id = self._project_scope_id()
        permission_decision: dict[str, Any] = {"allowed": True}
        if scope_id:
            capability = {
                "READ": Capability.READ,
                "WRITE": Capability.WRITE,
                "EXECUTE": Capability.EXECUTE,
                "DANGEROUS": Capability.DELETE if tool == "delete_file" else Capability.EXECUTE,
            }.get(str(definition.permission_class))
            if capability is not None:
                try:
                    self.policy.require_capability(scope_id, capability, actor=context.actor)
                except PolicyError as exc:
                    permission_decision = {"allowed": False, "error_code": exc.code, "message": exc.message}
        target = self._safe_display(arguments)
        approval_required = bool(definition.destructive or tool == "delete_file")
        preconditions: dict[str, Any] = {}
        if scope_id:
            for key in ("relative_path", "path"):
                value = arguments.get(key)
                if isinstance(value, str):
                    try:
                        _, resolved, display = self.policy.resolve_path(
                            scope_id, value, actor=context.actor, must_exist=False
                        )
                        preconditions[display] = sha256_file(resolved) if resolved.is_file() else None
                        target = f"{scope_id}:{display}"
                    except PolicyError as exc:
                        preconditions["path_error"] = exc.code
                    break
        preview = {
            "status": "preview",
            "tool": tool,
            "scope_id": scope_id,
            "target": target,
            "permission_class": definition.permission_class,
            "read_only": bool(definition.read_only),
            "destructive": bool(definition.destructive),
            "approval_required": approval_required,
            "tool_enabled": tool_enabled,
            "tool_error": tool_error,
            "permission": permission_decision,
            "preconditions": preconditions,
            "expected_effect": self._dry_run_effect(definition.permission_class, tool),
            "policy_version": self.store.policy_version(),
            "executed": False,
        }
        self._audit_success(
            context,
            "dry_run",
            "preview",
            target,
            scope_id=scope_id,
            metadata={
                "preview_tool": tool,
                "permission_class": definition.permission_class,
                "approval_required": approval_required,
                "tool_enabled": tool_enabled,
            },
        )
        return preview

    def _project_execution(
        self,
        context: RequestContext,
        tool: str,
        profile: str,
        args: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        scope_id = self._project_scope_id()
        scope, permission = self.policy.require_execution(scope_id, actor=context.actor)
        if scope.kind != ScopeKind.PROJECT:
            raise PolicyError("INVALID_SCOPE", "execution tools require a project scope")
        args = args or {}
        target = args.get("target")
        test_path = args.get("test_path", args.get("test_file"))
        if target is not None and target not in {"backend", "frontend", "auto"}:
            raise PolicyError("INVALID_INPUT", "target must be backend, frontend, or auto")
        if test_path is not None and not isinstance(test_path, str):
            raise PolicyError("INVALID_INPUT", "test_path must be text")
        payload = {
            "scope_id": scope_id,
            "profile": profile,
            "target": target,
            "test_path": test_path,
        }
        return self._authorize_mutation(
            context,
            tool=tool,
            operation="execute",
            scope_id=scope_id,
            targets=["."],
            payload=payload,
            expected={"project_root": sha256_json({"root": scope.root})},
            permission=permission,
        )

    def _tool_runtime_status(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        mcp_runtime = self.store.get_runtime("mcp_bridge")
        tunnel_runtime = self.store.get_runtime("tunnel")
        tunnel_config = self.store.get_tunnel_config()
        tunnel_state = "not_configured" if not tunnel_config else (tunnel_runtime or {}).get("state", "configured_stopped")
        mcp_state = (mcp_runtime or {}).get("state")
        if mcp_state not in {"running", "healthy", "ready"} and tunnel_state in {"running", "healthy", "ready"}:
            mcp_state = "via_tunnel"
        data = {
            "control_center": "ready",
            "policy_version": self.store.policy_version(),
            "mcp_bridge": mcp_state or "stopped",
            "tunnel": tunnel_state,
            "chatgpt_path": "ready_via_tunnel" if tunnel_state in {"healthy", "ready"} else "tunnel_client_running" if tunnel_state == "running" else "not_ready",
            "chatgpt_connection": "not_directly_observable",
            "tunnel_profile": (tunnel_config or {}).get("profile"),
            "browser": self.browser.status(),
            "processes": self._visible_processes(context),
        }
        self._audit_success(context, "runtime_status", "read", ".", metadata={})
        return {"status": "ok", **data}

    def _tool_browser_open(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        profile = self._require_string(args, "profile")
        result = self.browser.open(profile)
        self._audit_success(
            context,
            "browser_open",
            "open",
            profile,
            metadata={
                "profile": profile,
                "browser_session_digest": self._browser_session_digest(result.get("browser_session_id")),
                "origin": result.get("origin"),
            },
        )
        return result

    def _tool_browser_snapshot(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        session_id = self._require_string(args, "browser_session_id")
        policy = self.store.get_tool_policy("browser_snapshot")
        max_bytes = min(
            int(args.get("max_bytes", policy.output_limit_bytes if policy else 65_536)),
            int(policy.output_limit_bytes if policy else 65_536),
            65_536,
        )
        result = self.browser.snapshot(session_id, max_bytes=max_bytes)
        self._audit_success(
            context,
            "browser_snapshot",
            "snapshot",
            f"session:{self._browser_session_digest(session_id)}",
            metadata={
                "browser_session_digest": self._browser_session_digest(session_id),
                "origin": result.get("origin"),
                "bytes": len(str(result.get("snapshot", "")).encode("utf-8")),
                "element_count": result.get("element_count", 0),
                "table_count": result.get("table_count", 0),
                "truncated": bool(result.get("truncated")),
            },
        )
        return result

    def _tool_browser_run_command(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        session_id = self._require_string(args, "browser_session_id")
        action = self._require_string(args, "action")
        policy = self.store.get_tool_policy("browser_run_command")
        max_timeout = min(int(policy.max_duration_ms if policy else 30_000), 60_000)
        requested_timeout = args.get("timeout_ms")
        timeout_ms = max_timeout if requested_timeout is None else min(int(requested_timeout), max_timeout)
        result = self.browser.execute(
            session_id,
            action,
            target=args.get("target"),
            url=args.get("url"),
            value=args.get("value"),
            key=args.get("key"),
            timeout_ms=timeout_ms,
        )
        target = args.get("target")
        target_display = f"session:{self._browser_session_digest(session_id)}"
        if isinstance(target, dict) and isinstance(target.get("ref"), str):
            target_display += f":ref={target['ref']}"
        self._audit_success(
            context,
            "browser_run_command",
            action,
            target_display,
            metadata={
                "action": action,
                "browser_session_digest": self._browser_session_digest(session_id),
                "origin": result.get("origin"),
                "current_url": result.get("current_url"),
                "value_bytes": len(str(args.get("value", "")).encode("utf-8")) if action in {"fill", "select"} else None,
                "text_bytes": len(str(result.get("text", "")).encode("utf-8")) if action == "read_text" else None,
            },
        )
        return result

    def _tool_browser_close(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        session_id = self._require_string(args, "browser_session_id")
        result = self.browser.close(session_id)
        self._audit_success(
            context,
            "browser_close",
            "close",
            f"session:{self._browser_session_digest(session_id)}",
            metadata={"browser_session_digest": self._browser_session_digest(session_id)},
        )
        return result

    def _tool_apply_approved_action(self, args: dict[str, Any], context: RequestContext) -> dict[str, Any]:
        approval_id = self._require_string(args, "approval_id")
        request = self.store.get_approval(approval_id)
        if not request:
            raise PolicyError("APPROVAL_NOT_FOUND", "approval does not exist")
        if not self._is_approval_request(request):
            raise PolicyError("APPROVAL_NOT_REQUIRED", "this action is not eligible for Control Center approval")
        if request.status != ApprovalStatus.APPROVED:
            raise PolicyError("APPROVAL_NOT_GRANTED", "approval is not in approved state")
        if self._expired(request.expires_at):
            self.store.decide_approval(
                approval_id,
                ApprovalStatus.EXPIRED,
                "approval expired before apply",
                expected_status=ApprovalStatus.APPROVED,
            )
            raise PolicyError("APPROVAL_EXPIRED", "approval expired")
        if request.policy_version != self.store.policy_version():
            self.store.consume_approval(approval_id)
            raise PolicyError("STALE_APPROVAL", "policy changed after approval")
        if sha256_json(request.payload) != request.intent.get("payload_digest"):
            self.store.consume_approval(approval_id)
            raise PolicyError("STALE_APPROVAL", "pending payload digest changed")
        if sha256_json(request.intent) != request.action_hash:
            self.store.consume_approval(approval_id)
            raise PolicyError("STALE_APPROVAL", "approval action hash is invalid")
        # Consume before executing so a crash or failed verifier cannot be retried silently.
        if not self.store.consume_approval(approval_id):
            raise PolicyError("APPROVAL_NOT_GRANTED", "approval was already claimed")
        try:
            result = self._execute_intent(request.intent, request.payload, context, approval_id=approval_id)
        except PolicyError:
            raise
        result.setdefault("executed", True)
        return result

    # ---- mutation/approval internals --------------------------------------

    def _authorize_mutation(
        self,
        context: RequestContext,
        *,
        tool: str,
        operation: str,
        scope_id: str,
        targets: list[str],
        payload: dict[str, Any],
        expected: dict[str, str | None],
        permission: dict[str, Any],
    ) -> dict[str, Any]:
        intent = {
            "request_id": context.request_id,
            "session_id": context.session_id,
            "actor": context.actor,
            "trace_id": context.trace_id,
            "tool": tool,
            "operation": operation,
            "scope_id": scope_id,
            "targets": targets,
            "payload_digest": sha256_json(payload),
            "expected_preconditions": expected,
            "policy_version": self.store.policy_version(),
        }
        action_hash = sha256_json(intent)
        needs_approval = self.policy.approval_required(tool, permission, operation)
        if needs_approval:
            approval_id = str(uuid.uuid4())
            expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat(timespec="milliseconds")
            request = ApprovalRequest(
                id=approval_id,
                action_hash=action_hash,
                status=ApprovalStatus.PENDING,
                intent=intent,
                payload=payload,
                policy_version=self.store.policy_version(),
                expires_at=expires_at,
            )
            try:
                self.store.create_approval(request)
            except Exception as exc:
                raise PolicyError("APPROVAL_CREATE_FAILED", "unable to create approval request") from exc
            self._audit_success(
                context,
                tool,
                operation,
                self._intent_display(intent),
                scope_id=scope_id,
                approval_id=approval_id,
                decision="approval_required",
                metadata={"action_hash": action_hash, "expires_at": expires_at},
            )
            return {
                "status": "approval_required",
                "executed": False,
                "approval_id": approval_id,
                "action_hash": action_hash,
                "expires_at": expires_at,
                "intent": self._public_intent(intent),
                "message": "No file change was made. Approve this request, then apply it in the Control Center.",
                "next_step": "Approvals → Approve once → Apply approved",
            }
        result = self._execute_intent(intent, payload, context)
        result.setdefault("executed", True)
        return result

    def _execute_intent(
        self,
        intent: dict[str, Any],
        payload: dict[str, Any],
        context: RequestContext,
        *,
        approval_id: str | None = None,
    ) -> dict[str, Any]:
        tool = intent["tool"]
        operation = intent["operation"]
        scope_id = intent.get("scope_id")
        expected = intent.get("expected_preconditions", {})
        pre_hash: str | None = None
        post_hash: str | None = None
        backup_path: str | None = None
        metadata: dict[str, Any] = {}
        try:
            if tool == "apply_patch":
                scope, target, display = self.policy.resolve_path(
                    scope_id, payload["relative_path"], actor=context.actor, must_exist=True
                )
                _, permission = self.policy.require_capability(scope_id, Capability.WRITE, actor=context.actor)
                raw_text, pre_hash = self.filesystem.read_text_raw(
                    target, max_bytes=min(MAX_READ_BYTES, int(permission["max_bytes"]))
                )
                if pre_hash != expected.get(display):
                    raise PolicyError("PRECONDITION_CHANGED", "target changed since patch request")
                output_text, changed_ranges = apply_text_patch(raw_text, payload["patch"])
                output = output_text.encode("utf-8")
                self.policy.require_capability(
                    scope_id, Capability.WRITE, actor=context.actor, byte_count=len(output)
                )
                backup_path = str(self.filesystem.backup(target, self.snapshot_root, intent["request_id"]))
                self.filesystem.atomic_write(target, output)
                post_hash = sha256_file(target)
                metadata = {
                    "backup_path": backup_path,
                    "changed_line_ranges": changed_ranges,
                    "bytes": len(output),
                }
                result = {
                    "status": "ok",
                    "scope_id": scope_id,
                    "relative_path": display,
                    "before_hash": pre_hash,
                    "after_hash": post_hash,
                    "changed_line_ranges": changed_ranges,
                }
            elif tool in {"git_create_branch", "git_stage_paths", "git_commit", "git_restore_file", "git_push"}:
                project_scope_id = scope_id
                scope = self.policy.get_scope(project_scope_id, actor=context.actor)
                if scope.kind != ScopeKind.PROJECT:
                    raise PolicyError("INVALID_SCOPE", "Git mutation requires a project scope")
                if expected.get("project_root") != sha256_json({"root": scope.root}):
                    raise PolicyError("STALE_APPROVAL", "project scope changed")
                self.policy.require_execution(project_scope_id, actor=context.actor)
                project_root = Path(scope.root)
                if tool == "git_create_branch":
                    branch = self.git.validate_branch(payload["branch"])
                    git_result = self.git.run("create_branch", project_root, ["switch", "-c", branch])
                    result = self._git_mutation_result(git_result, project_scope_id, "branch", branch)
                    metadata = {"exit_code": git_result.exit_code}
                elif tool == "git_stage_paths":
                    paths = self.git.validate_paths(payload["paths"])
                    displays = self._verify_git_preconditions(project_scope_id, paths, context, expected)
                    git_result = self.git.run("stage", project_root, ["add", "--", *displays])
                    result = self._git_mutation_result(git_result, project_scope_id, "paths", displays)
                    metadata = {"exit_code": git_result.exit_code, "paths": displays}
                elif tool == "git_commit":
                    paths = self.git.validate_paths(payload["paths"])
                    displays = self._verify_git_preconditions(project_scope_id, paths, context, expected)
                    before = self.runner.run("git_status", project_root, output_limit=65_536, timeout_seconds=60)
                    stage_result = self.git.run("stage_for_commit", project_root, ["add", "--", *displays])
                    if stage_result.exit_code != 0:
                        result = self._git_mutation_result(stage_result, project_scope_id, "paths", displays)
                    else:
                        git_result = self.git.run(
                            "commit",
                            project_root,
                            ["commit", "--only", "-m", self.git.commit_message(payload["message"]), "--", *displays],
                        )
                        after = self.runner.run("git_status", project_root, output_limit=65_536, timeout_seconds=60)
                        result = self._git_mutation_result(git_result, project_scope_id, "paths", displays)
                        result["before_status"] = self._redact_command_result(before).to_dict()
                        result["after_status"] = self._redact_command_result(after).to_dict()
                    metadata = {"exit_code": stage_result.exit_code if stage_result.exit_code != 0 else git_result.exit_code, "paths": displays}
                elif tool == "git_restore_file":
                    path = self._verify_git_preconditions(project_scope_id, [payload["path"]], context, expected)[0]
                    git_result = self.git.run("restore", project_root, ["restore", "--", path])
                    result = self._git_mutation_result(git_result, project_scope_id, "path", path)
                    metadata = {"exit_code": git_result.exit_code, "path": path}
                else:
                    current = self.git.run("current_branch", project_root, ["branch", "--show-current"])
                    current_branch = self.git.current_branch(current)
                    if current_branch != expected.get("branch"):
                        raise PolicyError("PRECONDITION_CHANGED", "current branch changed before push")
                    remote = self.git.validate_remote(payload["remote"])
                    branch = self.git.validate_branch(payload["branch"])
                    git_result = self.git.run("push", project_root, ["push", remote, branch])
                    result = self._git_mutation_result(git_result, project_scope_id, "remote", f"{remote}/{branch}")
                    metadata = {"exit_code": git_result.exit_code, "remote": remote, "branch": branch}
            elif tool in {"write_file", "create_file"}:
                scope, target, display = self.policy.resolve_path(scope_id, payload["relative_path"], actor=context.actor, must_exist=(tool == "write_file"))
                capability = Capability.WRITE if tool == "write_file" else Capability.CREATE
                self.policy.require_capability(scope_id, capability, actor=context.actor, byte_count=len(payload.get("content", "").encode("utf-8")))
                current = sha256_file(target) if target.exists() else None
                if current != expected.get(display):
                    raise PolicyError("PRECONDITION_CHANGED", "target changed since request")
                if tool == "create_file" and target.exists():
                    raise PolicyError("TARGET_EXISTS", "target appeared before create")
                if tool == "write_file":
                    pre_hash = current
                    backup_path = str(self.filesystem.backup(target, self.snapshot_root, approval_id or intent["request_id"]))
                self.filesystem.atomic_write(target, payload.get("content", "").encode("utf-8"))
                post_hash = sha256_file(target)
                metadata = {"bytes": target.stat().st_size, "backup_path": backup_path}
                result = {"status": "ok", "scope_id": scope_id, "relative_path": display, "content_hash": post_hash}
            elif tool == "create_directory":
                scope, target, display = self._resolve_new_directory(scope_id, payload["relative_path"], context)
                self.policy.require_capability(scope_id, Capability.CREATE, actor=context.actor)
                if expected.get(display) is not None:
                    raise PolicyError("STALE_APPROVAL", "directory creation precondition is invalid")
                try:
                    target.mkdir()
                except FileExistsError as exc:
                    raise PolicyError("TARGET_EXISTS", "directory appeared before create") from exc
                metadata = {"created_directory": True}
                result = {
                    "status": "ok",
                    "scope_id": scope_id,
                    "relative_path": display,
                    "created": True,
                    "kind": "directory",
                }
            elif tool == "rename_file":
                scope, source, source_display = self.policy.resolve_path(scope_id, payload["relative_path"], actor=context.actor, must_exist=True)
                _, destination, destination_display = self.policy.resolve_path(scope_id, payload["destination_relative_path"], actor=context.actor, must_exist=False)
                self.policy.require_capability(scope_id, Capability.RENAME, actor=context.actor)
                if sha256_file(source) != expected.get("source"):
                    raise PolicyError("PRECONDITION_CHANGED", "source changed since request")
                if destination.exists():
                    raise PolicyError("TARGET_EXISTS", "destination appeared before rename")
                source.rename(destination)
                post_hash = sha256_file(destination)
                metadata = {"destination": destination_display}
                result = {"status": "ok", "scope_id": scope_id, "relative_path": source_display, "destination_relative_path": destination_display}
            elif tool == "move_file":
                source_scope_id = payload["source_scope_id"]
                destination_scope_id = payload["destination_scope_id"]
                source_scope, source, source_display = self.policy.resolve_path(source_scope_id, payload["source_relative_path"], actor=context.actor, must_exist=True)
                destination_scope, destination, destination_display = self.policy.resolve_path(destination_scope_id, payload["destination_relative_path"], actor=context.actor, must_exist=False)
                self.policy.require_capability(source_scope_id, Capability.MOVE, actor=context.actor)
                self.policy.require_capability(destination_scope_id, Capability.CREATE, actor=context.actor)
                if sha256_file(source) != expected.get("source"):
                    raise PolicyError("PRECONDITION_CHANGED", "source changed since request")
                if destination.exists():
                    raise PolicyError("TARGET_EXISTS", "destination appeared before move")
                source.rename(destination)
                post_hash = sha256_file(destination)
                metadata = {"destination": f"{destination_scope_id}:{destination_display}"}
                result = {"status": "ok", "source": f"{source_scope_id}:{source_display}", "destination": f"{destination_scope_id}:{destination_display}"}
            elif tool == "bulk_move_files":
                source_scope_id = payload["source_scope_id"]
                destination_scope_id = payload["destination_scope_id"]
                destination_directory_display, plan, _ = self._prepare_bulk_move(
                    source_scope_id,
                    payload["source_relative_paths"],
                    destination_scope_id,
                    payload["destination_relative_directory"],
                    context,
                    expected=expected,
                )
                expected_items = [
                    {
                        "source_relative_path": item["source_display"],
                        "destination_relative_path": item["destination_display"],
                    }
                    for item in plan
                ]
                if payload.get("items") != expected_items:
                    raise PolicyError("STALE_APPROVAL", "bulk move mapping changed before execution")

                moved: list[dict[str, Any]] = []
                failed_entry: dict[str, Any] | None = None
                failure: Exception | None = None
                try:
                    for item in plan:
                        source = item["source"]
                        destination = item["destination"]
                        if not source.is_file() or sha256_file(source) != item["source_hash"]:
                            raise PolicyError("PRECONDITION_CHANGED", "a source file changed before bulk move")
                        if destination.exists() or destination.is_symlink():
                            raise PolicyError("TARGET_EXISTS", "a destination appeared before bulk move")
                        self.filesystem.move_file_no_replace(source, destination)
                        moved.append(item)
                except (OSError, PolicyError) as exc:
                    failure = exc
                    failed_index = len(moved)
                    failed_entry = plan[failed_index] if failed_index < len(plan) else None

                if failure is not None:
                    rolled_back: list[dict[str, Any]] = []
                    rollback_failures: list[dict[str, Any]] = []
                    for item in reversed(moved):
                        source = item["source"]
                        destination = item["destination"]
                        try:
                            if source.exists() or not destination.is_file() or destination.is_symlink():
                                raise PolicyError("ROLLBACK_PRECONDITION_CHANGED", "rollback target changed")
                            if sha256_file(destination) != item["source_hash"]:
                                raise PolicyError("ROLLBACK_PRECONDITION_CHANGED", "rollback file changed")
                            self.filesystem.move_file_no_replace(destination, source)
                            rolled_back.append(item)
                        except (OSError, PolicyError) as rollback_error:
                            rollback_failures.append(
                                {
                                    "source_relative_path": item["source_display"],
                                    "destination_relative_path": item["destination_display"],
                                    "error_code": getattr(rollback_error, "code", "FILESYSTEM_ERROR"),
                                }
                            )
                    still_moved = [item for item in moved if item not in rolled_back]
                    failure_code = getattr(failure, "code", "FILESYSTEM_ERROR")
                    failure_data = (
                        {
                            "source_relative_path": failed_entry["source_display"],
                            "destination_relative_path": failed_entry["destination_display"],
                        }
                        if failed_entry is not None
                        else None
                    )
                    if rollback_failures:
                        metadata = {
                            "requested": len(plan),
                            "moved": len(still_moved),
                            "rolled_back": len(rolled_back),
                            "rollback_failures": rollback_failures,
                            "failed": failure_data,
                        }
                        result = {
                            "status": "partial_failure",
                            "error_code": "BULK_MOVE_PARTIAL",
                            "message": "some files moved and could not all be rolled back; inspect the returned mappings",
                            "source_scope_id": source_scope_id,
                            "destination_scope_id": destination_scope_id,
                            "destination_relative_directory": destination_directory_display,
                            "requested": len(plan),
                            "moved": len(still_moved),
                            "items": [
                                {
                                    "source_relative_path": item["source_display"],
                                    "destination_relative_path": item["destination_display"],
                                }
                                for item in still_moved
                            ],
                            "failed": failure_data,
                            "rollback_failures": rollback_failures,
                        }
                    else:
                        metadata = {
                            "requested": len(plan),
                            "moved": 0,
                            "rolled_back": len(rolled_back),
                            "failed": failure_data,
                        }
                        result = {
                            "status": "failed",
                            "executed": False,
                            "error_code": "BULK_MOVE_ROLLED_BACK",
                            "message": "bulk move was not completed; all earlier moves were rolled back",
                            "cause_code": failure_code,
                            "source_scope_id": source_scope_id,
                            "destination_scope_id": destination_scope_id,
                            "destination_relative_directory": destination_directory_display,
                            "requested": len(plan),
                            "moved": 0,
                            "items": [],
                            "failed": failure_data,
                        }
                else:
                    mappings = [
                        {
                            "source_relative_path": item["source_display"],
                            "destination_relative_path": item["destination_display"],
                        }
                        for item in moved
                    ]
                    metadata = {"requested": len(plan), "moved": len(moved), "mapping": mappings}
                    result = {
                        "status": "ok",
                        "source_scope_id": source_scope_id,
                        "destination_scope_id": destination_scope_id,
                        "destination_relative_directory": destination_directory_display,
                        "requested": len(plan),
                        "moved": len(moved),
                        "items": mappings,
                    }
            elif tool == "delete_file":
                scope, target, display = self.policy.resolve_path(scope_id, payload["relative_path"], actor=context.actor, must_exist=True)
                self.policy.require_capability(scope_id, Capability.DELETE, actor=context.actor)
                pre_hash = sha256_file(target)
                if pre_hash != expected.get(display):
                    raise PolicyError("PRECONDITION_CHANGED", "target changed since request")
                backup_path = str(self.filesystem.backup(target, self.snapshot_root, approval_id or intent["request_id"]))
                target.unlink()
                metadata = {"backup_path": backup_path}
                result = {"status": "ok", "scope_id": scope_id, "relative_path": display, "deleted": True}
            elif tool in {"csv_transform", "xlsx_edit", "docx_edit"}:
                scope, target, display = self.policy.resolve_path(scope_id, payload["relative_path"], actor=context.actor, must_exist=True)
                self.policy.require_capability(scope_id, Capability.WRITE, actor=context.actor)
                pre_hash = sha256_file(target)
                if pre_hash != expected.get(display):
                    raise PolicyError("PRECONDITION_CHANGED", "document changed since request")
                adapter = {
                    "csv_transform": self.documents.transform_csv,
                    "xlsx_edit": self.documents.edit_xlsx,
                    "docx_edit": self.documents.edit_docx,
                }[tool]
                output, summary = adapter(target, payload)
                self.policy.require_capability(scope_id, Capability.WRITE, actor=context.actor, byte_count=len(output))
                backup_path = str(self.filesystem.backup(target, self.snapshot_root, approval_id or intent["request_id"]))
                self.filesystem.atomic_write(target, output)
                post_hash = sha256_file(target)
                metadata = {**summary, "backup_path": backup_path, "bytes": len(output)}
                result = {"status": "ok", "scope_id": scope_id, "relative_path": display, "summary": summary, "content_hash": post_hash}
            elif tool == "process_start_profile":
                project_scope_id = payload["scope_id"]
                scope = self.policy.get_scope(project_scope_id, actor=context.actor)
                if scope.kind != ScopeKind.PROJECT:
                    raise PolicyError("INVALID_SCOPE", "managed project processes require a project scope")
                expected_root = sha256_json({"root": scope.root})
                if expected.get("project_root") != expected_root:
                    raise PolicyError("STALE_APPROVAL", "project scope changed")
                self.policy.require_execution(project_scope_id, actor=context.actor)
                profile = self.runner._resolve_project_profile(
                    payload["profile"],
                    Path(scope.root),
                    target=None,
                    test_path=None,
                )
                result = self.processes.start(
                    profile,
                    scope_id=project_scope_id,
                    owner_session_id=context.session_id,
                    timeout_seconds=payload.get("timeout_seconds"),
                    trace_id=context.trace_id,
                )
                metadata = {"process_id": result.get("process_id"), "profile": profile.name}
            elif tool == "process_stop":
                process_id = payload["process_id"]
                row = self.store.get_runtime_by_id(process_id)
                if not row or row.get("kind") != "managed_project":
                    raise PolicyError("PROCESS_NOT_FOUND", "managed process was not found")
                process_scope_id = row.get("scope_id")
                if process_scope_id != scope_id or not isinstance(process_scope_id, str):
                    raise PolicyError("PROCESS_SCOPE_MISMATCH", "managed process scope does not match the action")
                self.policy.require_execution(process_scope_id, actor=context.actor)
                if row.get("command_digest") != expected.get("command_digest"):
                    raise PolicyError("PRECONDITION_CHANGED", "managed process identity changed")
                result = self.processes.stop(process_id, trace_id=context.trace_id)
                metadata = {"process_id": process_id}
            elif tool in {
                "run_backend_test", "run_frontend_test", "run_targeted_test", "run_lint",
                "run_typecheck", "run_build",
            }:
                project_scope_id = payload["scope_id"]
                scope = self.policy.get_scope(project_scope_id, actor=context.actor)
                if scope.kind != ScopeKind.PROJECT:
                    raise PolicyError("INVALID_SCOPE", "execution requires a project scope")
                expected_root = sha256_json({"root": scope.root})
                if expected.get("project_root") != expected_root:
                    raise PolicyError("STALE_APPROVAL", "project scope changed")
                self.policy.require_execution(project_scope_id, actor=context.actor)
                tool_policy = self.store.get_tool_policy(tool)
                if tool_policy is None:
                    raise PolicyError("TOOL_NOT_FOUND", f"tool policy is missing: {tool}")
                if tool in {"run_backend_test", "run_frontend_test"}:
                    result_data = self.runner.run(
                        payload["profile"],
                        Path(scope.root),
                        output_limit=tool_policy.output_limit_bytes,
                        timeout_seconds=max(1, tool_policy.max_duration_ms // 1000),
                    )
                else:
                    result_data = self.runner.run_project_profile(
                        payload["profile"],
                        Path(scope.root),
                        target=payload.get("target"),
                        test_path=payload.get("test_path"),
                        output_limit=tool_policy.output_limit_bytes,
                        timeout_seconds=max(1, tool_policy.max_duration_ms // 1000),
                    )
                result_data = self._redact_command_result(result_data)
                metadata = {
                    "profile": payload["profile"],
                    "exit_code": result_data.exit_code,
                    "timed_out": result_data.timed_out,
                    "stdout_digest": sha256_bytes(result_data.stdout.encode()),
                    "stderr_digest": sha256_bytes(result_data.stderr.encode()),
                }
                result = {"status": "ok", "scope_id": project_scope_id, "result": result_data.to_dict()}
            else:
                raise PolicyError("TOOL_NOT_IMPLEMENTED", f"mutation tool is not implemented: {tool}")
        except OSError as exc:
            raise PolicyError("FILESYSTEM_ERROR", str(exc)) from exc
        self._audit_success(
            context,
            tool,
            operation,
            self._intent_display(intent),
            scope_id=scope_id,
            approval_id=approval_id,
            pre_hash=pre_hash,
            post_hash=post_hash,
            result_code=result.get("error_code"),
            decision="executed" if result.get("status") == "ok" else "failed",
            process_id=result.get("process_id") or metadata.get("process_id"),
            metadata=metadata,
        )
        return result

    # ---- utility -----------------------------------------------------------

    def _verify_git_preconditions(
        self,
        scope_id: str,
        paths: list[str],
        context: RequestContext,
        expected: dict[str, Any],
    ) -> list[str]:
        self._validate_git_paths(scope_id, paths, context, allow_missing=True)
        displays: list[str] = []
        for path in paths:
            _, target, display = self.policy.resolve_path(
                scope_id, path, actor=context.actor, must_exist=False
            )
            current = sha256_file(target) if target.is_file() else None
            expected_hash = expected.get(f"path:{display}")
            if current != expected_hash:
                raise PolicyError("PRECONDITION_CHANGED", f"Git path changed since request: {display}")
            displays.append(display)
        return displays

    @staticmethod
    def _git_mutation_result(
        command: Any,
        scope_id: str,
        field: str,
        value: Any,
    ) -> dict[str, Any]:
        payload = command.to_dict()
        if command.exit_code != 0 or command.timed_out:
            return {
                "status": "failed",
                "error_code": "GIT_COMMAND_FAILED" if not command.timed_out else "GIT_TIMEOUT",
                "scope_id": scope_id,
                field: value,
                "result": payload,
            }
        return {"status": "ok", "scope_id": scope_id, field: value, "result": payload}

    def _read_page(
        self,
        context: RequestContext,
        scope_id: str,
        relative: str,
        *,
        start_line: int,
        max_lines: int,
        max_bytes: int,
        expected_hash: str | None = None,
    ) -> dict[str, Any]:
        scope, target, display = self.policy.resolve_path(
            scope_id, relative, actor=context.actor, must_exist=True
        )
        _, permission = self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
        max_bytes = min(max_bytes, int(permission["max_bytes"]), MAX_READ_BYTES)
        content, digest, returned_start, returned_end, has_more = self.filesystem.read_text_page(
            target,
            start_line=start_line,
            max_lines=max_lines,
            max_bytes=max_bytes,
        )
        if expected_hash is not None and digest != expected_hash:
            raise PolicyError("PRECONDITION_CHANGED", "file changed before continuation")
        continuation = self._page_token(
            scope_id, display, returned_end + 1, max_lines, max_bytes, context, digest
        ) if has_more else None
        self._audit_success(
            context,
            "read_file_page",
            "read_page",
            f"{scope_id}:{display}",
            scope_id=scope_id,
            pre_hash=digest,
            metadata={
                "start_line": returned_start,
                "end_line": returned_end,
                "has_more": has_more,
                "bytes": len(content.encode("utf-8")),
            },
        )
        return {
            "status": "ok",
            "scope_id": scope_id,
            "relative_path": display,
            "content": content,
            "content_hash": digest,
            "start_line": returned_start,
            "end_line": returned_end,
            "has_more": has_more,
            "continuation_token": continuation,
        }

    def _page_token(
        self,
        scope_id: str,
        relative_path: str,
        start_line: int,
        max_lines: int,
        max_bytes: int,
        context: RequestContext,
        content_hash: str | None = None,
    ) -> str:
        payload = {
            "version": 1,
            "actor": context.actor,
            "scope_id": scope_id,
            "relative_path": relative_path,
            "start_line": int(start_line),
            "max_lines": int(max_lines),
            "max_bytes": int(max_bytes),
            "content_hash": content_hash,
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        body = base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("=")
        signature = hmac.new(self._page_token_key, body.encode("ascii"), "sha256").hexdigest()
        return f"{body}.{signature}"

    def _decode_page_token(self, token: str, context: RequestContext) -> dict[str, Any]:
        if len(token) > 4096:
            raise PolicyError("INVALID_CONTINUATION_TOKEN", "continuation token is too large")
        try:
            body, signature = token.split(".", 1)
            expected_signature = hmac.new(self._page_token_key, body.encode("ascii"), "sha256").hexdigest()
            if not hmac.compare_digest(signature, expected_signature):
                raise PolicyError("INVALID_CONTINUATION_TOKEN", "continuation token signature is invalid")
            padding = "=" * (-len(body) % 4)
            value = json.loads(base64.urlsafe_b64decode(body + padding).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error) as exc:
            raise PolicyError("INVALID_CONTINUATION_TOKEN", "continuation token is invalid") from exc
        if (
            not isinstance(value, dict)
            or value.get("version") != 1
            or value.get("actor") != context.actor
            or not isinstance(value.get("scope_id"), str)
            or not isinstance(value.get("relative_path"), str)
            or not isinstance(value.get("start_line"), int)
            or not isinstance(value.get("max_lines"), int)
            or not isinstance(value.get("max_bytes"), int)
            or not isinstance(value.get("content_hash"), str)
        ):
            raise PolicyError("INVALID_CONTINUATION_TOKEN", "continuation token fields are invalid")
        if value["start_line"] < 1 or value["max_lines"] < 1 or value["max_bytes"] < 1:
            raise PolicyError("INVALID_CONTINUATION_TOKEN", "continuation token limits are invalid")
        return value

    def _resolve_new_directory(
        self,
        scope_id: str,
        relative_path: str,
        context: RequestContext,
    ) -> tuple[Any, Path, str]:
        """Resolve one absent directory whose parent is already present."""
        try:
            scope, target, display = self.policy.resolve_path(
                scope_id,
                relative_path,
                actor=context.actor,
                must_exist=False,
            )
        except PolicyError as exc:
            if exc.code == "TARGET_NOT_FOUND":
                raise PolicyError(
                    "PARENT_NOT_FOUND",
                    "parent directory must already exist; create parent directories one at a time",
                ) from exc
            raise
        if target.exists():
            raise PolicyError("TARGET_EXISTS", "create_directory will not overwrite an existing file or directory")
        if not target.parent.is_dir():
            raise PolicyError(
                "PARENT_NOT_FOUND",
                "parent directory must already exist; create parent directories one at a time",
            )
        return scope, target, display

    def _prepare_bulk_move(
        self,
        source_scope_id: str,
        source_relative_paths: Any,
        destination_scope_id: str,
        destination_relative_directory: str,
        context: RequestContext,
        *,
        expected: dict[str, Any] | None = None,
    ) -> tuple[str, list[dict[str, Any]], int]:
        """Validate and hash an explicit complete batch before any move."""
        if not isinstance(source_relative_paths, list) or not source_relative_paths:
            raise PolicyError("INVALID_INPUT", "source_relative_paths must be a non-empty list")
        if len(source_relative_paths) > 100:
            raise PolicyError("QUOTA_EXCEEDED", "bulk move is limited to 100 files per request")
        if not isinstance(destination_relative_directory, str) or not destination_relative_directory:
            raise PolicyError("INVALID_INPUT", "destination_relative_directory is required")

        normalized_paths: list[str] = []
        for index, value in enumerate(source_relative_paths):
            if not isinstance(value, str) or not value:
                raise PolicyError("INVALID_INPUT", f"source_relative_paths[{index}] must be a non-empty relative path")
            if any(character in value for character in "*?[]"):
                raise PolicyError("INVALID_INPUT", "bulk move accepts explicit paths only; wildcards are rejected")
            normalized_paths.append(value)
        if len(set(normalized_paths)) != len(normalized_paths):
            raise PolicyError("INVALID_INPUT", "source_relative_paths must not contain duplicates")

        _, source_permission = self.policy.require_capability(source_scope_id, Capability.MOVE, actor=context.actor)
        _, destination_permission = self.policy.require_capability(destination_scope_id, Capability.CREATE, actor=context.actor)
        item_limit = min(int(source_permission["max_items"]), int(destination_permission["max_items"]))
        if len(normalized_paths) > item_limit:
            raise PolicyError("QUOTA_EXCEEDED", f"bulk move exceeds the configured limit of {item_limit} files")

        try:
            _, destination_directory, destination_directory_display = self.policy.resolve_path(
                destination_scope_id,
                destination_relative_directory,
                actor=context.actor,
                must_exist=True,
            )
        except PolicyError as exc:
            if exc.code == "TARGET_NOT_FOUND":
                raise PolicyError(
                    "DESTINATION_DIRECTORY_NOT_FOUND",
                    "destination directory must already exist; create it first with create_directory",
                ) from exc
            raise
        if not destination_directory.is_dir():
            raise PolicyError("NOT_A_DIRECTORY", "destination_relative_directory must identify an existing directory")

        source_seen: set[str] = set()
        destination_seen: set[str] = set()
        plan: list[dict[str, Any]] = []
        for raw_path in normalized_paths:
            _, source, source_display = self.policy.resolve_path(
                source_scope_id,
                raw_path,
                actor=context.actor,
                must_exist=True,
            )
            if not source.is_file() or source.is_symlink():
                raise PolicyError("NOT_A_FILE", "bulk_move_files only handles regular files, not directories or symlinks")
            filename = Path(source_display).name
            if not filename:
                raise PolicyError("INVALID_INPUT", "each source path must identify a file")
            destination_relative = filename if destination_directory_display == "." else f"{destination_directory_display}/{filename}"
            _, destination, destination_display = self.policy.resolve_path(
                destination_scope_id,
                destination_relative,
                actor=context.actor,
                must_exist=False,
            )
            if source_display in source_seen:
                raise PolicyError("INVALID_INPUT", "source paths must resolve to unique files")
            if destination_display in destination_seen:
                raise PolicyError("INVALID_INPUT", "source filenames must map to unique destinations")
            if source == destination:
                raise PolicyError("INVALID_INPUT", "source and destination must be different")
            if destination.exists() or destination.is_symlink():
                raise PolicyError("TARGET_EXISTS", "bulk move will not overwrite any destination")
            source_hash = sha256_file(source)
            if expected is not None:
                if expected.get(f"source:{source_display}") != source_hash:
                    raise PolicyError("PRECONDITION_CHANGED", "a source file changed since bulk move was requested")
                if expected.get(f"destination:{destination_display}") is not None:
                    raise PolicyError("STALE_APPROVAL", "a destination precondition is invalid")
            source_seen.add(source_display)
            destination_seen.add(destination_display)
            plan.append(
                {
                    "source": source,
                    "source_display": source_display,
                    "source_hash": source_hash,
                    "destination": destination,
                    "destination_display": destination_display,
                }
            )
        return destination_directory_display, plan, item_limit

    @staticmethod
    def _is_approval_request(request: ApprovalRequest) -> bool:
        return request.intent.get("tool") in {"delete_file", "git_restore_file", "git_push"}

    @staticmethod
    def _is_delete_approval(request: ApprovalRequest) -> bool:
        """Backward-compatible helper for callers that only handle deletes."""
        return request.intent.get("tool") == "delete_file" and request.intent.get("operation") == "delete"

    def _project_scope_id(self) -> str:
        projects = [scope.id for scope in self.store.list_scopes(include_disabled=False) if scope.kind == ScopeKind.PROJECT and scope.expose_to_mcp]
        if len(projects) != 1:
            raise PolicyError("PROJECT_SCOPE_AMBIGUOUS", "exactly one MCP-visible project scope is required")
        return projects[0]

    def _workspace_scope(self, scope_id: Any, context: RequestContext) -> Any:
        selected = scope_id if isinstance(scope_id, str) and scope_id else self._project_scope_id()
        scope = self.policy.get_scope(selected, actor=context.actor)
        if scope.kind == ScopeKind.FILE:
            raise PolicyError("INVALID_SCOPE", "workspace operations require a directory or project scope")
        return scope

    def _visible_processes(self, context: RequestContext) -> list[dict[str, Any]]:
        visible: list[dict[str, Any]] = []
        for record in self.processes.status():
            row = self.store.get_runtime_by_id(str(record.get("process_id") or "")) or {}
            scope_id = row.get("scope_id")
            if not isinstance(scope_id, str):
                continue
            try:
                self.policy.require_capability(scope_id, Capability.READ, actor=context.actor)
            except PolicyError:
                continue
            visible.append(record)
        return visible

    def _recent_errors(self, limit: int) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for row in self.store.audit_rows(max(1, min(limit, 100))):
            if row.get("decision") not in {"failed", "denied"} and not row.get("error_code"):
                continue
            result.append(
                {
                    "occurred_at": row.get("occurred_at"),
                    "tool": row.get("tool"),
                    "decision": row.get("decision"),
                    "error_code": row.get("error_code"),
                    "result_code": row.get("result_code"),
                    "target": row.get("target_display"),
                    "trace_id": row.get("trace_id"),
                }
            )
            if len(result) >= limit:
                break
        return result

    @staticmethod
    def _dry_run_effect(permission_class: str | None, tool: str) -> str:
        if tool in {"git_restore_file", "git_push", "delete_file"}:
            return "destructive side effect; exact approval and precondition recheck required"
        if permission_class == "WRITE":
            return "bounded filesystem or Git working-tree mutation"
        if permission_class == "EXECUTE":
            return "run a locally detected project/process profile with bounded output and timeout"
        if permission_class == "DANGEROUS":
            return "dangerous side effect; disabled or approval-gated by policy"
        return "read-only inspection; no mutation"

    def _expire_pending(self) -> None:
        for request in self.store.list_approvals((ApprovalStatus.PENDING,)):
            if self._expired(request.expires_at):
                self.store.decide_approval(
                    request.id,
                    ApprovalStatus.EXPIRED,
                    "approval expired",
                    expected_status=ApprovalStatus.PENDING,
                )

    @staticmethod
    def _expired(value: str) -> bool:
        try:
            return datetime.fromisoformat(value) <= datetime.now(timezone.utc)
        except ValueError:
            return True

    @staticmethod
    def _require_string(args: dict[str, Any], key: str) -> str:
        value = args.get(key)
        if not isinstance(value, str) or not value:
            raise PolicyError("INVALID_INPUT", f"{key} is required")
        return value

    @staticmethod
    def _bounded_int(value: Any, lower: int, upper: int) -> int:
        if not isinstance(value, int):
            raise PolicyError("INVALID_INPUT", "numeric limit is required")
        return max(lower, min(value, upper))

    @staticmethod
    def _safe_display(args: dict[str, Any]) -> str:
        values = []
        for key in ("scope_id", "relative_path", "source_relative_path", "destination_relative_path", "query"):
            value = args.get(key)
            if isinstance(value, str):
                values.append(f"{key}={value[:160]}")
        session_id = args.get("browser_session_id")
        if isinstance(session_id, str):
            values.append(f"browser_session_digest={Broker._browser_session_digest(session_id)}")
        target = args.get("target")
        if isinstance(target, dict) and isinstance(target.get("ref"), str):
            values.append(f"target_ref={target['ref'][:32]}")
        paths = args.get("source_relative_paths")
        if isinstance(paths, list):
            values.append(f"source_relative_paths_count={len(paths)}")
        return ";".join(values)[:500]

    @staticmethod
    def _browser_session_digest(session_id: Any) -> str:
        if not isinstance(session_id, str) or not session_id:
            return "missing"
        return sha256_bytes(session_id.encode("utf-8"))

    @staticmethod
    def _intent_display(intent: dict[str, Any]) -> str:
        scope_id = intent.get("scope_id") or ""
        targets = ",".join(str(value)[:160] for value in intent.get("targets", []))
        return f"{scope_id}:{targets}"[:500]

    @staticmethod
    def _redact_command_result(result: Any) -> Any:
        """Keep command output useful without returning obvious secret material."""
        return type(result)(
            result.profile,
            result.argv_display,
            result.exit_code,
            redact_text(result.stdout),
            redact_text(result.stderr),
            result.timed_out,
            result.stdout_truncated,
            result.stderr_truncated,
            result.duration_ms,
        )

    @staticmethod
    def _public_intent(intent: dict[str, Any]) -> dict[str, Any]:
        return {
            key: intent[key]
            for key in ("trace_id", "tool", "operation", "scope_id", "targets", "payload_digest", "expected_preconditions", "policy_version")
            if key in intent
        }

    def _audit_success(
        self,
        context: RequestContext,
        tool: str,
        operation: str,
        target_display: str,
        *,
        scope_id: str | None = None,
        approval_id: str | None = None,
        pre_hash: str | None = None,
        post_hash: str | None = None,
        result_code: str | None = None,
        decision: str = "executed",
        process_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.audit.record(
            actor=context.actor,
            tool=tool,
            operation=operation,
            decision=decision,
            target_display=target_display,
            session_id=context.session_id,
            request_id=context.request_id,
            scope_id=scope_id,
            approval_id=approval_id,
            pre_hash=pre_hash,
            post_hash=post_hash,
            result_code=result_code,
            metadata=metadata or {},
            trace_id=context.trace_id,
            duration_ms=self._duration_ms(context),
            process_id=process_id,
        )

    @staticmethod
    def _duration_ms(context: RequestContext) -> int:
        return max(0, int((time.monotonic() - context.started_monotonic) * 1000))
