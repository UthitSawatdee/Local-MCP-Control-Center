"""Codex bridge registration and broker integration; configuration is local-only."""
from __future__ import annotations

from threading import Lock
from typing import Annotated, Any, Callable, Literal

from pydantic import Field

from .codex_threads import CodexThreadService, MAX_OUTPUT_BYTES, normalize_thread_id, validate_local_config
from .errors import PolicyError, StorageError


class CodexThreadBrokerMixin:
    _codex_service_lock = Lock()

    @property
    def codex_threads(self) -> CodexThreadService:
        with self._codex_service_lock:
            service = self.__dict__.get("_codex_thread_service")
            if service is None:
                service = CodexThreadService(self.store.get_codex_thread_config)
                self.__dict__["_codex_thread_service"] = service
            return service

    def configure_codex_threads(self, *, executable: str = "", codex_home: str = "", enabled: bool = True) -> dict[str, Any]:
        """Local GUI/CLI only. This method is deliberately absent from the MCP registry."""
        try:
            config = validate_local_config(executable, codex_home) if enabled else {"enabled": False}
            # Fail closed throughout a multi-step grant change.
            self.store.set_codex_thread_config({"enabled": False})
            for name in ("codex_list_threads", "codex_read_thread"):
                result = self.set_tool_policy(name, enabled=enabled, approval_mode="never")
                if result.get("status") != "ok":
                    raise PolicyError("CODEX_CONFIG_INVALID", "Codex tool policy could not be updated; history access remains disabled")
            self.store.set_codex_thread_config(config)
            version = self.store.bump_policy_version()
            self.audit.record(actor="user", tool="control.codex_threads", operation="configure", decision="executed", target_display="codex-local", metadata={"enabled": enabled, "policy_version": version})
            return {"status": "ok", "enabled": enabled, "policy_version": version, "restart_bridge_required": True}
        except (PolicyError, StorageError) as exc:
            return {"status": "denied", "error_code": getattr(exc, "code", "STORAGE_ERROR"), "message": str(exc)}

    def _codex_limits(self, name: str) -> dict[str, Any]:
        policy = self.store.get_tool_policy(name)
        return {
            "timeout_seconds": min(20.0, max(0.01, policy.max_duration_ms / 1000)),
            "max_bytes": min(MAX_OUTPUT_BYTES, max(0, policy.output_limit_bytes - 512)),
        }

    def _tool_codex_status(self, args: dict[str, Any], context: Any) -> dict[str, Any]:
        result = self.codex_threads.status(probe=bool(args.get("probe", False)), timeout_seconds=self._codex_limits("codex_status")["timeout_seconds"])
        self._audit_success(context, "codex_status", "read", "codex-local", metadata={"enabled": result["enabled"], "connection_verified": result["connection_verified"]})
        return result

    def _tool_codex_list_threads(self, args: dict[str, Any], context: Any) -> dict[str, Any]:
        result = self.codex_threads.list_threads(**args, **self._codex_limits("codex_list_threads"))
        self._audit_success(context, "codex_list_threads", "read", "codex-local", metadata={"count": len(result["threads"]), "has_more": result["has_more"]})
        return result

    def _tool_codex_read_thread(self, args: dict[str, Any], context: Any) -> dict[str, Any]:
        result = self.codex_threads.read_thread(**args, **self._codex_limits("codex_read_thread"))
        self._audit_success(context, "codex_read_thread", "read", normalize_thread_id(args["thread_id"]), metadata={"turn_count": len(result["turns"]), "has_more": result["has_more"], "omitted_internal_items": result["omitted_internal_items"]})
        return result


def register_codex_tools(broker: Any, register: Callable[[str, Any], None]) -> None:
    def codex_status(probe: bool = False) -> dict[str, Any]:
        return broker.invoke("codex_status", {"probe": probe})

    def codex_list_threads(
        query: Annotated[str, Field(max_length=200)] = "",
        limit: Annotated[int, Field(ge=1, le=50)] = 20,
        cursor: Annotated[str, Field(min_length=1, max_length=4096)] | None = None,
        archived: bool = False,
    ) -> dict[str, Any]:
        args = {"query": query, "limit": limit, "cursor": cursor, "archived": archived}
        return broker.invoke("codex_list_threads", {key: value for key, value in args.items() if value is not None})

    def codex_read_thread(
        thread_id: Annotated[str, Field(min_length=36, max_length=52)],
        limit: Annotated[int, Field(ge=1, le=20)] = 3,
        cursor: Annotated[str, Field(min_length=1, max_length=4096)] | None = None,
        sort_direction: Literal["asc", "desc"] = "asc",
        include_tool_results: bool = False,
    ) -> dict[str, Any]:
        args = {"thread_id": thread_id, "limit": limit, "cursor": cursor, "sort_direction": sort_direction, "include_tool_results": include_tool_results}
        return broker.invoke("codex_read_thread", {key: value for key, value in args.items() if value is not None})

    register("codex_status", codex_status)
    register("codex_list_threads", codex_list_threads)
    register("codex_read_thread", codex_read_thread)
