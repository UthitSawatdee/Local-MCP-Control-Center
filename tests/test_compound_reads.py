from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import threading

import pytest

from local_mcp_control_center.compound_reads import (
    CompoundReadConfigurationError,
    CompoundReadExecutor,
    ReadOperationSpec,
)


def _executor(*names: str, max_operations: int = 20, max_concurrency: int = 4) -> CompoundReadExecutor:
    return CompoundReadExecutor(
        {name: "READ" for name in names},
        max_operations=max_operations,
        max_concurrency=max_concurrency,
    )


def test_results_preserve_request_order_even_when_children_finish_out_of_order() -> None:
    release_first = threading.Event()
    first_started = threading.Event()

    def dispatcher(operation: str, arguments: dict) -> dict:
        if operation == "first_read":
            first_started.set()
            assert release_first.wait(timeout=2)
        return {"operation": operation, "value": arguments["value"]}

    executor = _executor("first_read", "second_read", max_concurrency=2)
    with ThreadPoolExecutor(max_workers=1) as caller_pool:
        future = caller_pool.submit(
            executor.execute,
            [
                {"operation": "first_read", "arguments": {"value": 1}},
                {"operation": "second_read", "arguments": {"value": 2}},
            ],
            dispatcher,
        )
        assert first_started.wait(timeout=2)
        release_first.set()
        result = future.result(timeout=2)

    assert [item["operation"] for item in result["results"]] == ["first_read", "second_read"]
    assert [item["result"]["value"] for item in result["results"]] == [1, 2]
    assert result["succeeded"] == 2
    json.dumps(result, allow_nan=False)


def test_concurrency_never_exceeds_configured_cap_without_timing_assumptions() -> None:
    active = 0
    peak = 0
    lock = threading.Lock()
    two_workers_ready = threading.Event()
    release_workers = threading.Event()

    def dispatcher(operation: str, arguments: dict) -> str:
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            if active == 2:
                two_workers_ready.set()
        assert release_workers.wait(timeout=2)
        with lock:
            active -= 1
        return operation

    executor = _executor("read_one", "read_two", "read_three", "read_four", max_concurrency=2)
    with ThreadPoolExecutor(max_workers=1) as caller_pool:
        future = caller_pool.submit(
            executor.execute,
            [{"operation": name} for name in ("read_one", "read_two", "read_three", "read_four")],
            dispatcher,
        )
        assert two_workers_ready.wait(timeout=2)
        with lock:
            assert active == 2
            assert peak == 2
        release_workers.set()
        result = future.result(timeout=2)

    assert peak == 2
    assert result["succeeded"] == 4


def test_one_dispatcher_failure_is_contained_and_unrelated_reads_run() -> None:
    calls: list[str] = []

    def dispatcher(operation: str, arguments: dict) -> dict:
        calls.append(operation)
        if operation == "read_b":
            raise RuntimeError("child failure")
        return {"seen": operation}

    result = _executor("read_a", "read_b", "read_c").execute(
        [{"operation": name} for name in ("read_a", "read_b", "read_c")],
        dispatcher,
    )

    assert sorted(calls) == ["read_a", "read_b", "read_c"]
    assert [item["status"] for item in result["results"]] == ["ok", "error", "ok"]
    assert result["results"][1]["error_code"] == "DISPATCHER_EXCEPTION"
    assert "RuntimeError" in result["results"][1]["message"]
    assert result["failed"] == 1


def test_unknown_and_non_read_operations_are_rejected_before_dispatch() -> None:
    calls: list[str] = []

    def dispatcher(operation: str, arguments: dict) -> str:
        calls.append(operation)
        return operation

    result = _executor("read_ok").execute(
        [
            {"operation": "read_ok"},
            {"operation": "not_configured"},
            {"operation": "write_file"},
            {"operation": "run_backend_test"},
        ],
        dispatcher,
    )

    assert calls == ["read_ok"]
    assert [item.get("error_code") for item in result["results"][1:]] == [
        "UNKNOWN_OPERATION",
        "NON_READ_OPERATION",
        "NON_READ_OPERATION",
    ]


def test_empty_oversized_and_non_list_batches_fail_closed_without_dispatch() -> None:
    calls: list[str] = []

    def dispatcher(operation: str, arguments: dict) -> str:
        calls.append(operation)
        return operation

    executor = _executor("read_ok", max_operations=1)
    assert executor.execute([], dispatcher)["error_code"] == "EMPTY_BATCH"
    assert executor.execute([{"operation": "read_ok"}, {"operation": "read_ok"}], dispatcher)["error_code"] == "BATCH_TOO_LARGE"
    assert executor.execute({"operation": "read_ok"}, dispatcher)["error_code"] == "INVALID_BATCH"
    assert calls == []


def test_malformed_item_gets_error_while_valid_sibling_remains_independent() -> None:
    calls: list[str] = []

    def dispatcher(operation: str, arguments: dict) -> str:
        calls.append(operation)
        return "ok"

    result = _executor("read_ok").execute(
        [
            {"operation": "read_ok", "arguments": []},
            {"operation": "read_ok", "arguments": {}, "unexpected": True},
            {"operation": "read_ok"},
        ],
        dispatcher,
    )

    assert calls == ["read_ok"]
    assert [item.get("error_code") for item in result["results"]] == [
        "INVALID_ARGUMENTS",
        "INVALID_ITEM",
        None,
    ]
    assert result["results"][2]["status"] == "ok"


def test_invalid_dispatcher_is_rejected_before_any_child_dispatch() -> None:
    executor = _executor("read_ok")
    result = executor.execute([{"operation": "read_ok"}], None)
    assert result == {
        "status": "error",
        "error_code": "INVALID_DISPATCHER",
        "message": "dispatcher must be a synchronous callable accepting (operation, arguments); no child was dispatched",
        "results": [],
    }


def test_async_dispatcher_is_rejected_without_implicit_await() -> None:
    calls = 0

    async def dispatcher(operation: str, arguments: dict) -> str:
        nonlocal calls
        calls += 1
        return operation

    result = _executor("read_ok").execute([{"operation": "read_ok"}], dispatcher)
    assert result["error_code"] == "INVALID_DISPATCHER"
    assert calls == 0


def test_non_serializable_result_is_a_child_error() -> None:
    result = _executor("read_object").execute(
        [{"operation": "read_object"}],
        lambda operation, arguments: {"bad": object()},
    )
    assert result["status"] == "ok"
    assert result["results"][0]["error_code"] == "NON_SERIALIZABLE_RESULT"


def test_dispatcher_returned_error_is_preserved_as_a_child_error() -> None:
    result = _executor("read_denied").execute(
        [{"operation": "read_denied"}],
        lambda operation, arguments: {
            "status": "denied",
            "error_code": "CAPABILITY_DENIED",
            "message": "read capability is not enabled",
        },
    )
    item = result["results"][0]
    assert item["status"] == "error"
    assert item["error_code"] == "CAPABILITY_DENIED"
    assert item["result"]["status"] == "denied"


def test_configuration_rejects_non_read_metadata_and_unbounded_limits() -> None:
    with pytest.raises(CompoundReadConfigurationError) as permission_error:
        CompoundReadExecutor({"read_file": "WRITE"})
    assert permission_error.value.code == "NON_READ_ALLOWLIST"

    with pytest.raises(CompoundReadConfigurationError) as name_error:
        CompoundReadExecutor(["write_file"])
    assert name_error.value.code == "NON_READ_ALLOWLIST"

    with pytest.raises(CompoundReadConfigurationError) as limit_error:
        CompoundReadExecutor({"read_file": "READ"}, max_concurrency=33)
    assert limit_error.value.code == "INVALID_LIMIT"


def test_read_operation_spec_accepts_read_metadata_and_rejects_parallel_unsafe() -> None:
    spec = ReadOperationSpec("read_file", permission_class="read")
    assert spec.permission_class == "READ"
    assert CompoundReadExecutor([spec]).allowed_operations == ("read_file",)

    with pytest.raises(CompoundReadConfigurationError) as error:
        ReadOperationSpec("read_file", parallel_safe=False)
    assert error.value.code == "NON_PARALLEL_OPERATION"


def test_dispatcher_exception_does_not_abort_later_children() -> None:
    seen: list[str] = []

    def dispatcher(operation: str, arguments: dict) -> str:
        seen.append(operation)
        if operation == "read_bad":
            raise KeyboardInterrupt
        return operation

    result = _executor("read_bad", "read_after").execute(
        [{"operation": "read_bad"}, {"operation": "read_after"}],
        dispatcher,
    )
    assert seen == ["read_bad", "read_after"]
    assert result["results"][0]["error_code"] == "DISPATCHER_EXCEPTION"
    assert result["results"][1]["status"] == "ok"
