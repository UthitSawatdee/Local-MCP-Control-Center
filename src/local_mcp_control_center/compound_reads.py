"""Bounded, read-only compound operation execution.

This module deliberately has no knowledge of the broker, registry, filesystem,
process runtime, or MCP transport.  The caller supplies the read-only
allowlist and a dispatcher adapter.  Each accepted child is sent to that
adapter independently; the adapter remains responsible for the child's
policy and schema checks.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import inspect
import json
import re
from typing import Any, TypeAlias


JsonObject: TypeAlias = dict[str, Any]
Dispatcher: TypeAlias = Callable[[str, JsonObject], Any]

MAX_OPERATION_COUNT = 100
MAX_CONCURRENCY = 32
MAX_ALLOWLIST_COUNT = 256
MAX_OPERATION_NAME_LENGTH = 128
MAX_ARGUMENT_BYTES = 1_048_576

_READ_PERMISSION = "READ"
_NON_READ_PERMISSIONS = frozenset({"WRITE", "EXECUTE", "DANGEROUS"})
_OPERATION_NAME = re.compile(
    rf"^[A-Za-z][A-Za-z0-9_.:-]{{0,{MAX_OPERATION_NAME_LENGTH - 1}}}$"
)

# Names are classified conservatively when a caller supplies a plain iterable
# of names.  A read-only allowlist must not accidentally turn an obvious
# mutation or execution operation into a child read.
_NON_READ_MARKERS = (
    "write",
    "create",
    "delete",
    "remove",
    "rename",
    "move",
    "update",
    "mutat",
    "execute",
    "exec",
    "run",
    "start",
    "stop",
    "commit",
    "push",
    "restore",
    "patch",
    "edit",
    "apply",
    "append",
    "insert",
    "truncate",
    "drop",
    "grant",
    "revoke",
    "approve",
    "deny",
    "kill",
    "shell",
    "command",
    "danger",
)


class CompoundReadConfigurationError(ValueError):
    """Invalid trusted configuration for the compound-read module."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class ReadOperationSpec:
    """Caller-owned metadata proving that one operation is safe to fan out."""

    name: str
    permission_class: str = _READ_PERMISSION
    read_only: bool = True
    destructive: bool = False
    parallel_safe: bool = True

    def __post_init__(self) -> None:
        _validate_configured_name(self.name)
        permission_class = _normalise_permission_class(self.permission_class)
        if permission_class in _NON_READ_PERMISSIONS:
            raise CompoundReadConfigurationError(
                "NON_READ_ALLOWLIST",
                f"allowlisted operation {self.name!r} has permission class {permission_class}; only READ is allowed",
            )
        if permission_class != _READ_PERMISSION:
            raise CompoundReadConfigurationError(
                "INVALID_ALLOWLIST",
                f"allowlisted operation {self.name!r} must declare permission class READ",
            )
        if type(self.read_only) is not bool:
            raise CompoundReadConfigurationError(
                "INVALID_ALLOWLIST",
                f"allowlisted operation {self.name!r} read_only must be boolean",
            )
        if not self.read_only:
            raise CompoundReadConfigurationError(
                "NON_READ_ALLOWLIST",
                f"allowlisted operation {self.name!r} is not read-only",
            )
        if type(self.destructive) is not bool:
            raise CompoundReadConfigurationError(
                "INVALID_ALLOWLIST",
                f"allowlisted operation {self.name!r} destructive must be boolean",
            )
        if self.destructive:
            raise CompoundReadConfigurationError(
                "NON_READ_ALLOWLIST",
                f"allowlisted operation {self.name!r} is destructive",
            )
        if type(self.parallel_safe) is not bool:
            raise CompoundReadConfigurationError(
                "INVALID_ALLOWLIST",
                f"allowlisted operation {self.name!r} parallel_safe must be boolean",
            )
        if not self.parallel_safe:
            raise CompoundReadConfigurationError(
                "NON_PARALLEL_OPERATION",
                f"allowlisted operation {self.name!r} is not marked parallel-safe",
            )
        if _looks_non_read(self.name):
            raise CompoundReadConfigurationError(
                "NON_READ_ALLOWLIST",
                f"operation name {self.name!r} is reserved for write, execute, or dangerous behavior",
            )
        object.__setattr__(self, "permission_class", permission_class)


@dataclass(frozen=True, slots=True)
class ReadOperation:
    """Typed form of one request item accepted by :class:`CompoundReadExecutor`."""

    operation: str
    arguments: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _ValidatedOperation:
    index: int
    operation: str
    arguments: JsonObject


class _JsonValueError(ValueError):
    """Internal marker for invalid JSON-shaped input or output."""


def _normalise_permission_class(value: Any) -> str:
    if isinstance(value, str):
        return value.upper()
    enum_value = getattr(value, "value", None)
    if isinstance(enum_value, str):
        return enum_value.upper()
    return ""


def _validate_configured_name(name: Any) -> None:
    if not isinstance(name, str) or not _OPERATION_NAME.fullmatch(name):
        raise CompoundReadConfigurationError(
            "INVALID_ALLOWLIST",
            f"allowlist operation names must match [A-Za-z][A-Za-z0-9_.:-]{{0,{MAX_OPERATION_NAME_LENGTH - 1}}}",
        )


def _looks_non_read(operation: str) -> bool:
    lowered = operation.lower()
    return any(marker in lowered for marker in _NON_READ_MARKERS)


def _descriptor_to_spec(name: Any, descriptor: Any) -> ReadOperationSpec:
    if isinstance(descriptor, ReadOperationSpec):
        if descriptor.name != name:
            raise CompoundReadConfigurationError(
                "INVALID_ALLOWLIST",
                f"allowlist key {name!r} does not match spec name {descriptor.name!r}",
            )
        return descriptor

    if isinstance(descriptor, str) or isinstance(getattr(descriptor, "value", None), str):
        return ReadOperationSpec(name=name, permission_class=descriptor)

    if isinstance(descriptor, Mapping):
        allowed_keys = {"permission_class", "read_only", "destructive", "parallel_safe"}
        unknown_keys = set(descriptor) - allowed_keys
        if unknown_keys:
            unknown = ", ".join(sorted(str(key) for key in unknown_keys))
            raise CompoundReadConfigurationError(
                "INVALID_ALLOWLIST",
                f"allowlist metadata for {name!r} has unsupported field(s): {unknown}",
            )
        return ReadOperationSpec(
            name=name,
            permission_class=descriptor.get("permission_class", _READ_PERMISSION),
            read_only=descriptor.get("read_only", True),
            destructive=descriptor.get("destructive", False),
            parallel_safe=descriptor.get("parallel_safe", True),
        )

    # This also permits a future Broker/registry definition to be passed in
    # without importing that integration here.  Only security metadata is
    # consumed; no object method is called.
    if any(hasattr(descriptor, attribute) for attribute in ("permission_class", "read_only", "destructive")):
        return ReadOperationSpec(
            name=name,
            permission_class=getattr(descriptor, "permission_class", _READ_PERMISSION),
            read_only=getattr(descriptor, "read_only", True),
            destructive=getattr(descriptor, "destructive", False),
            parallel_safe=getattr(descriptor, "parallel_safe", True),
        )

    raise CompoundReadConfigurationError(
        "INVALID_ALLOWLIST",
        f"allowlist entry for {name!r} must be READ metadata or ReadOperationSpec",
    )


def _normalise_allowlist(allowed_operations: Any) -> dict[str, ReadOperationSpec]:
    if isinstance(allowed_operations, Mapping):
        try:
            entries = list(allowed_operations.items())
        except BaseException as exc:
            raise CompoundReadConfigurationError(
                "INVALID_ALLOWLIST",
                "allowed_operations mapping could not be read safely",
            ) from exc
    else:
        if isinstance(allowed_operations, (str, bytes, bytearray)):
            raise CompoundReadConfigurationError(
                "INVALID_ALLOWLIST",
                "allowed_operations must be a collection of operation names or name-to-READ metadata",
            )
        try:
            raw_entries = list(allowed_operations)
        except BaseException as exc:
            raise CompoundReadConfigurationError(
                "INVALID_ALLOWLIST",
                "allowed_operations must be a collection of operation names or name-to-READ metadata",
            ) from exc
        entries = []
        for entry in raw_entries:
            if isinstance(entry, ReadOperationSpec):
                entries.append((entry.name, entry))
            else:
                entries.append((entry, _READ_PERMISSION))

    if not entries:
        raise CompoundReadConfigurationError(
            "EMPTY_ALLOWLIST",
            "at least one explicit read-only operation must be configured",
        )
    if len(entries) > MAX_ALLOWLIST_COUNT:
        raise CompoundReadConfigurationError(
            "ALLOWLIST_TOO_LARGE",
            f"allowlist contains {len(entries)} operations; maximum is {MAX_ALLOWLIST_COUNT}",
        )

    specs: dict[str, ReadOperationSpec] = {}
    for name, descriptor in entries:
        _validate_configured_name(name)
        if name in specs:
            raise CompoundReadConfigurationError(
                "DUPLICATE_ALLOWLIST_ENTRY",
                f"operation {name!r} appears more than once in the allowlist",
            )
        specs[name] = _descriptor_to_spec(name, descriptor)
    return specs


def _json_round_trip(value: Any, *, max_bytes: int | None = None) -> Any:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as exc:
        raise _JsonValueError("value is not JSON-serializable") from exc
    try:
        encoded_bytes = len(encoded.encode("utf-8"))
    except UnicodeError as exc:
        raise _JsonValueError("value is not JSON-serializable") from exc
    if max_bytes is not None and encoded_bytes > max_bytes:
        raise _JsonValueError(f"JSON value exceeds {max_bytes} bytes")
    try:
        return json.loads(encoded)
    except (TypeError, ValueError, RecursionError) as exc:
        raise _JsonValueError("value is not JSON-serializable") from exc


def _item_error(index: int, operation: str | None, code: str, message: str) -> dict[str, Any]:
    return {
        "index": index,
        "operation": operation,
        "status": "error",
        "error_code": code,
        "message": message,
    }


def _batch_error(code: str, message: str, *, requested: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "error",
        "error_code": code,
        "message": message,
        "results": [],
    }
    if requested is not None:
        result["requested"] = requested
    return result


def _validate_dispatcher(dispatcher: Any) -> tuple[str, str] | None:
    if not callable(dispatcher):
        return (
            "INVALID_DISPATCHER",
            "dispatcher must be a synchronous callable accepting (operation, arguments); no child was dispatched",
        )
    try:
        is_async = inspect.iscoroutinefunction(dispatcher) or inspect.iscoroutinefunction(
            getattr(dispatcher, "__call__", None)
        )
    except BaseException:
        return (
            "INVALID_DISPATCHER",
            "dispatcher async status could not be inspected safely; no child was dispatched",
        )
    if is_async:
        return (
            "INVALID_DISPATCHER",
            "dispatcher must be synchronous; an async callback cannot be awaited implicitly",
        )
    try:
        signature = inspect.signature(dispatcher)
        signature.bind("read_operation", {})
    except (TypeError, ValueError):
        return (
            "INVALID_DISPATCHER",
            "dispatcher must accept exactly the positional call shape (operation, arguments); no child was dispatched",
        )
    except BaseException:
        return (
            "INVALID_DISPATCHER",
            "dispatcher signature could not be inspected safely; no child was dispatched",
        )
    return None


def _normalise_arguments(arguments: Any, *, index: int, operation: str | None) -> tuple[JsonObject | None, dict[str, Any] | None]:
    if not isinstance(arguments, Mapping):
        return None, _item_error(index, operation, "INVALID_ARGUMENTS", "arguments must be a JSON object")
    try:
        argument_object = dict(arguments)
        cloned = _json_round_trip(argument_object, max_bytes=MAX_ARGUMENT_BYTES)
    except _JsonValueError as exc:
        if "exceeds" in str(exc):
            return None, _item_error(
                index,
                operation,
                "ARGUMENTS_TOO_LARGE",
                f"arguments exceed the {MAX_ARGUMENT_BYTES}-byte limit; reduce this child request",
            )
        return None, _item_error(
            index,
            operation,
            "INVALID_ARGUMENTS",
            "arguments must contain only JSON-serializable values",
        )
    except BaseException:
        return None, _item_error(
            index,
            operation,
            "INVALID_ARGUMENTS",
            "arguments could not be read as a JSON object",
        )
    if not isinstance(cloned, dict):
        return None, _item_error(index, operation, "INVALID_ARGUMENTS", "arguments must be a JSON object")
    return cloned, None


class CompoundReadExecutor:
    """Execute an explicitly allowlisted batch of independent read operations.

    The public interface is ``execute(operations, dispatcher)``.  ``operations``
    is a list of objects with an ``operation`` name and optional ``arguments``
    object (``args`` is accepted as a compatibility spelling).  The configured
    allowlist is copied during construction and cannot be changed by a request.
    """

    def __init__(
        self,
        allowed_operations: Mapping[str, Any] | Iterable[str | ReadOperationSpec],
        *,
        max_operations: int = 20,
        max_concurrency: int = 4,
    ) -> None:
        if type(max_operations) is not int or not 1 <= max_operations <= MAX_OPERATION_COUNT:
            raise CompoundReadConfigurationError(
                "INVALID_LIMIT",
                f"max_operations must be an integer from 1 to {MAX_OPERATION_COUNT}",
            )
        if type(max_concurrency) is not int or not 1 <= max_concurrency <= MAX_CONCURRENCY:
            raise CompoundReadConfigurationError(
                "INVALID_LIMIT",
                f"max_concurrency must be an integer from 1 to {MAX_CONCURRENCY}",
            )
        self._allowed_operations = _normalise_allowlist(allowed_operations)
        self.max_operations = max_operations
        self.max_concurrency = max_concurrency

    @property
    def allowed_operations(self) -> tuple[str, ...]:
        """Return a stable snapshot of the configured read-only operation names."""

        return tuple(sorted(self._allowed_operations))

    def execute(self, operations: Any, dispatcher: Any) -> dict[str, Any]:
        """Validate and execute a bounded batch, returning ordered JSON data."""

        dispatcher_error = _validate_dispatcher(dispatcher)
        if dispatcher_error is not None:
            code, message = dispatcher_error
            return _batch_error(code, message)

        if not isinstance(operations, list):
            return _batch_error(
                "INVALID_BATCH",
                "operations must be a JSON array (Python list) of named operation objects; no child was dispatched",
            )
        requested = len(operations)
        if requested == 0:
            return _batch_error(
                "EMPTY_BATCH",
                "operations must contain at least one named read operation; no child was dispatched",
                requested=0,
            )
        if requested > self.max_operations:
            return _batch_error(
                "BATCH_TOO_LARGE",
                f"batch contains {requested} operations; maximum is {self.max_operations}; split the request",
                requested=requested,
            )

        ordered_results: list[dict[str, Any] | None] = []
        validated: list[_ValidatedOperation] = []
        for index, item in enumerate(operations):
            operation, arguments, error = self._validate_item(index, item)
            if error is not None:
                ordered_results.append(error)
                continue
            if operation is None or arguments is None:
                ordered_results.append(
                    _item_error(
                        index,
                        None,
                        "VALIDATION_ERROR",
                        "read child validation did not produce a complete operation; it failed closed",
                    )
                )
                continue
            ordered_results.append(None)
            validated.append(_ValidatedOperation(index, operation, arguments))

        if validated:
            self._dispatch_validated(validated, dispatcher, ordered_results)

        # A scheduling failure is still represented as an item result.  This is
        # defensive containment for executor setup failures; it is not a retry.
        for index, result in enumerate(ordered_results):
            if result is None:
                ordered_results[index] = _item_error(
                    index,
                    None,
                    "EXECUTOR_ERROR",
                    "read child could not be scheduled and failed closed; no retry was attempted",
                )

        final_results = [result for result in ordered_results if result is not None]
        succeeded = sum(result["status"] == "ok" for result in final_results)
        return {
            "status": "ok",
            "requested": requested,
            "succeeded": succeeded,
            "failed": requested - succeeded,
            "results": final_results,
        }

    def _validate_item(
        self,
        index: int,
        item: Any,
    ) -> tuple[str | None, JsonObject | None, dict[str, Any] | None]:
        operation: Any = None
        arguments: Any = {}
        if isinstance(item, ReadOperation):
            operation = item.operation
            arguments = item.arguments
        elif isinstance(item, Mapping):
            try:
                item_object = dict(item)
                keys = set(item_object)
            except BaseException:
                return None, None, _item_error(index, None, "INVALID_ITEM", "batch item keys could not be read safely")
            allowed_keys = {"operation", "arguments", "args"}
            unexpected = keys - allowed_keys
            if unexpected:
                names = ", ".join(sorted(str(key) for key in unexpected))
                return None, None, _item_error(
                    index,
                    item_object.get("operation") if isinstance(item_object.get("operation"), str) else None,
                    "INVALID_ITEM",
                    f"batch item has unsupported field(s): {names}; use operation and arguments only",
                )
            if "operation" not in item_object:
                return None, None, _item_error(
                    index,
                    None,
                    "INVALID_ITEM",
                    "batch item must include a named operation",
                )
            operation = item_object.get("operation")
            if "arguments" in item_object and "args" in item_object:
                return None, None, _item_error(
                    index,
                    operation if isinstance(operation, str) else None,
                    "INVALID_ITEM",
                    "provide only one arguments object; do not send both arguments and args",
                )
            if "arguments" in item_object:
                arguments = item_object.get("arguments")
            elif "args" in item_object:
                arguments = item_object.get("args")
        else:
            return None, None, _item_error(
                index,
                None,
                "INVALID_ITEM",
                "each batch item must be an object with operation and optional arguments",
            )

        if not isinstance(operation, str) or not operation:
            return None, None, _item_error(
                index,
                None,
                "INVALID_OPERATION",
                "operation must be a non-empty string",
            )
        if not _OPERATION_NAME.fullmatch(operation):
            return None, None, _item_error(
                index,
                operation,
                "INVALID_OPERATION",
                f"operation must match [A-Za-z][A-Za-z0-9_.:-]{{0,{MAX_OPERATION_NAME_LENGTH - 1}}}",
            )
        if _looks_non_read(operation):
            return None, None, _item_error(
                index,
                operation,
                "NON_READ_OPERATION",
                f"operation {operation!r} is not eligible for a read-only compound batch",
            )
        if operation not in self._allowed_operations:
            return None, None, _item_error(
                index,
                operation,
                "UNKNOWN_OPERATION",
                f"operation {operation!r} is not in the configured read-only allowlist; omit it or configure it explicitly",
            )
        normalised_arguments, error = _normalise_arguments(arguments, index=index, operation=operation)
        return operation, normalised_arguments, error

    def _dispatch_validated(
        self,
        validated: list[_ValidatedOperation],
        dispatcher: Dispatcher,
        ordered_results: list[dict[str, Any] | None],
    ) -> None:
        try:
            with ThreadPoolExecutor(max_workers=min(len(validated), self.max_concurrency)) as executor:
                futures = {
                    executor.submit(_dispatch_one, request, dispatcher): request
                    for request in validated
                }
                for future, request in futures.items():
                    try:
                        ordered_results[request.index] = future.result()
                    except BaseException as exc:
                        ordered_results[request.index] = _item_error(
                            request.index,
                            request.operation,
                            "EXECUTOR_ERROR",
                            f"read child failed closed while collecting its result ({type(exc).__name__}); no retry was attempted",
                        )
        except BaseException:
            # The caller's dispatcher is never retried.  Any future that was
            # not assigned a result is filled by execute() with EXECUTOR_ERROR.
            return


def _dispatch_one(request: _ValidatedOperation, dispatcher: Dispatcher) -> dict[str, Any]:
    try:
        value = dispatcher(request.operation, dict(request.arguments))
    except BaseException as exc:
        return _item_error(
            request.index,
            request.operation,
            "DISPATCHER_EXCEPTION",
            f"dispatcher raised {type(exc).__name__}; child failed closed; inspect the child policy/schema handler before retrying",
        )

    try:
        serialised_value = _json_round_trip(value)
    except _JsonValueError:
        return _item_error(
            request.index,
            request.operation,
            "NON_SERIALIZABLE_RESULT",
            "dispatcher returned a non-JSON-serializable result; return JSON-compatible data",
        )
    if isinstance(serialised_value, dict) and serialised_value.get("status") in {"denied", "error", "failed"}:
        error_code = serialised_value.get("error_code")
        if not isinstance(error_code, str) or not error_code:
            error_code = "CHILD_ERROR"
        message = serialised_value.get("message")
        if not isinstance(message, str) or not message:
            message = "dispatcher returned a child error result; inspect the child policy/schema response"
        return {
            **_item_error(request.index, request.operation, error_code, message),
            "result": serialised_value,
        }
    return {
        "index": request.index,
        "operation": request.operation,
        "status": "ok",
        "result": serialised_value,
    }


def execute_compound_reads(
    operations: Any,
    dispatcher: Any,
    *,
    allowed_operations: Mapping[str, Any] | Iterable[str | ReadOperationSpec],
    max_operations: int = 20,
    max_concurrency: int = 4,
) -> dict[str, Any]:
    """Functional convenience wrapper around :class:`CompoundReadExecutor`."""

    executor = CompoundReadExecutor(
        allowed_operations,
        max_operations=max_operations,
        max_concurrency=max_concurrency,
    )
    return executor.execute(operations, dispatcher)


__all__ = [
    "Dispatcher",
    "CompoundReadConfigurationError",
    "CompoundReadExecutor",
    "ReadOperation",
    "ReadOperationSpec",
    "execute_compound_reads",
]
