from __future__ import annotations

import json

import pytest

from local_mcp_control_center.context_ledger import ContextLedger


def assert_json_serializable(result: dict) -> None:
    json.dumps(result, sort_keys=True)


def test_first_duplicate_and_changed_delivery_are_bounded_and_retrievable() -> None:
    ledger = ContextLedger(max_entries=4, max_content_bytes=256, max_preview_bytes=64)
    original = "alpha\nbeta\n"

    first = ledger.deliver("atm-project/src/app.py", original, now=100)
    assert first["status"] == "delivered"
    assert first["delivery"] == "first"
    assert first["preview"] == original
    assert first["preview_truncated"] is False
    assert first["content_hash"].startswith("sha256:")
    assert first["reference"].startswith("ctx:v1:")
    assert first["entry_count"] == 1
    assert_json_serializable(first)

    duplicate = ledger.deliver("atm-project/src/app.py", original, now=101)
    assert duplicate["status"] == "unchanged"
    assert duplicate["delivery"] == "duplicate"
    assert duplicate["duplicate"] is True
    assert duplicate["reference"] == first["reference"]
    assert duplicate["content_hash"] == first["content_hash"]
    assert "preview" not in duplicate
    assert_json_serializable(duplicate)

    changed = ledger.deliver("atm-project/src/app.py", "alpha\ngamma\n", now=102)
    assert changed["status"] == "changed"
    assert changed["delivery"] == "changed"
    assert changed["reference"] == first["reference"]
    assert changed["previous_content_hash"] == first["content_hash"]
    assert changed["content_hash"] != first["content_hash"]
    assert "-beta" in changed["diff"]
    assert "+gamma" in changed["diff"]
    assert len(changed["diff"].encode("utf-8")) <= ledger.max_preview_bytes
    assert_json_serializable(changed)

    retrieved = ledger.retrieve(first["reference"], now=103)
    assert retrieved["status"] == "retrieved"
    assert retrieved["content"] == "alpha\ngamma\n"
    assert retrieved["content_hash"] == changed["content_hash"]
    assert retrieved["key"] == "atm-project/src/app.py"
    assert_json_serializable(retrieved)


def test_content_and_preview_byte_bounds_fail_closed() -> None:
    ledger = ContextLedger(max_content_bytes=12, max_preview_bytes=5)

    first = ledger.deliver("caller:item", "ก" * 4, now=1)
    assert first["status"] == "delivered"
    assert len(first["preview"].encode("utf-8")) <= 5
    assert first["preview_truncated"] is True
    assert first["content_bytes"] == len(("ก" * 4).encode("utf-8"))

    too_large = ledger.deliver("caller:too-large", "x" * 13, now=2)
    assert too_large["status"] == "error"
    assert too_large["error_code"] == "CONTENT_TOO_LARGE"
    assert too_large["retryable"] is False
    assert "preview" not in too_large
    assert ledger.retrieve(first["reference"], now=2)["status"] == "retrieved"
    assert_json_serializable(too_large)

    unicode_too_large = ledger.deliver("caller:unicode-too-large", "ก" * 5, now=3)
    assert unicode_too_large["status"] == "error"
    assert unicode_too_large["error_code"] == "CONTENT_TOO_LARGE"

    redaction_expansion = ContextLedger(max_content_bytes=8, max_preview_bytes=8).deliver(
        "caller:redaction-expansion",
        "token=x\n",
        now=4,
    )
    assert redaction_expansion["status"] == "error"
    assert redaction_expansion["error_code"] == "CONTENT_TOO_LARGE"


def test_capacity_eviction_is_fifo_and_observable() -> None:
    ledger = ContextLedger(max_entries=2, max_content_bytes=64, max_preview_bytes=32)
    first = ledger.deliver("scope/a.txt", "a", now=1)
    second = ledger.deliver("scope/b.txt", "b", now=2)

    unchanged_second = ledger.deliver("scope/b.txt", "b", now=3)
    assert unchanged_second["status"] == "unchanged"

    third = ledger.deliver("scope/c.txt", "c", now=4)
    assert third["status"] == "delivered"
    assert third["entry_count"] == 2
    assert third["evictions"] == [{"reference": first["reference"], "reason": "capacity"}]
    assert ledger.retrieve(first["reference"], now=4)["status"] == "not_found"
    assert ledger.retrieve(second["reference"], now=4)["status"] == "retrieved"
    assert ledger.retrieve(third["reference"], now=4)["status"] == "retrieved"


def test_ttl_expiry_is_deterministic_and_requires_redelivery() -> None:
    ledger = ContextLedger(
        max_entries=2,
        max_content_bytes=64,
        max_preview_bytes=32,
        ttl_seconds=10,
    )
    first = ledger.deliver("scope/short-lived.txt", "value", now=100)
    assert ledger.retrieve(first["reference"], now=109)["status"] == "retrieved"

    expired = ledger.retrieve(first["reference"], now=110)
    assert expired["status"] == "expired"
    assert expired["error_code"] == "REFERENCE_EXPIRED"
    assert expired["evictions"] == [{"reference": first["reference"], "reason": "ttl"}]

    redelivered = ledger.deliver("scope/short-lived.txt", "value", now=110)
    assert redelivered["status"] == "delivered"
    assert redelivered["delivery"] == "first"
    assert redelivered["reference"] == first["reference"]


def test_obvious_secrets_are_redacted_before_hashing_storage_and_return() -> None:
    secret_content = (
        "api_key=super-secret-value\n"
        "OPENAI_API_KEY=another-secret-value\n"
        "SECRET_TOKEN=rotating-secret-value\n"
        "password: hunter with spaces\n"
        "Authorization: Bearer abcdefghijklmnop\n"
        "sk-proj-provider-secret-1234567890\n"
        "AKIA1234567890ABCDEF\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "private-material\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    ledger = ContextLedger(max_content_bytes=512, max_preview_bytes=512)

    delivered = ledger.deliver("scope/config.example", secret_content, now=1)
    assert delivered["status"] == "delivered"
    assert delivered["redacted"] is True
    assert "super-secret-value" not in delivered["preview"]
    assert "another-secret-value" not in delivered["preview"]
    assert "rotating-secret-value" not in delivered["preview"]
    assert "hunter with spaces" not in delivered["preview"]
    assert "abcdefghijklmnop" not in delivered["preview"]
    assert "provider-secret-1234567890" not in delivered["preview"]
    assert "private-material" not in delivered["preview"]
    assert "[REDACTED]" in delivered["preview"]

    retrieved = ledger.retrieve(delivered["reference"], now=2)
    assert retrieved["status"] == "retrieved"
    for secret in (
        "super-secret-value",
        "another-secret-value",
        "rotating-secret-value",
        "hunter with spaces",
        "abcdefghijklmnop",
        "provider-secret-1234567890",
        "private-material",
    ):
        assert secret not in retrieved["content"]
    assert_json_serializable(retrieved)

    # Source hashes preserve change detection while the stored diff remains
    # safe when only a redacted credential value changed.
    changed = ledger.deliver(
        "scope/config.example",
        secret_content.replace("super-secret-value", "rotated-secret-value"),
        now=3,
    )
    assert changed["status"] == "changed"
    assert changed["redaction_only_change"] is True
    assert "rotated-secret-value" not in changed["diff"]
    assert changed["previous_content_hash"] == delivered["content_hash"]
    assert changed["content_hash"] != delivered["content_hash"]


@pytest.mark.parametrize(
    "key",
    [None, "", "/absolute/path", "../escape", "scope/../escape", "scope\\file", "scope//file", "scope\x00file"],
)
def test_malformed_keys_and_content_return_actionable_json_errors(key) -> None:
    ledger = ContextLedger(max_entries=1, max_content_bytes=64, max_preview_bytes=32)
    invalid_key = ledger.deliver(key, "safe", now=1)
    assert invalid_key["status"] == "error"
    assert invalid_key["error_code"] == "INVALID_KEY"
    assert invalid_key["field"] == "key"
    assert invalid_key["resolution"]
    assert_json_serializable(invalid_key)

    valid = ledger.deliver("scope/valid", "safe", now=1)
    assert valid["status"] == "delivered"
    assert ledger.retrieve(valid["reference"], now=1)["status"] == "retrieved"

    for content in (None, b"bytes", {"not": "text"}, "contains\x00nul"):
        invalid_content = ledger.deliver("scope/valid", content, now=2)
        assert invalid_content["status"] == "error"
        assert invalid_content["error_code"] == "INVALID_CONTENT"
        assert invalid_content["field"] == "content"
        assert_json_serializable(invalid_content)


def test_malformed_references_times_and_limits_fail_closed() -> None:
    ledger = ContextLedger(max_entries=1, max_content_bytes=64, max_preview_bytes=32)

    invalid_reference = ledger.retrieve("not-a-reference", now=1)
    assert invalid_reference["status"] == "error"
    assert invalid_reference["error_code"] == "INVALID_REFERENCE"

    invalid_time = ledger.deliver("scope/item", "safe", now=float("nan"))
    assert invalid_time["status"] == "error"
    assert invalid_time["error_code"] == "INVALID_TIME"
    assert ledger.retrieve("ctx:v1:" + "0" * 64, now=1)["status"] == "not_found"

    for kwargs in (
        {"max_entries": 0},
        {"max_entries": True},
        {"max_content_bytes": 0},
        {"max_preview_bytes": 65_537},
        {"max_content_bytes": 4, "max_preview_bytes": 5},
        {"ttl_seconds": 0},
        {"ttl_seconds": float("inf")},
    ):
        with pytest.raises(ValueError):
            ContextLedger(**kwargs)
