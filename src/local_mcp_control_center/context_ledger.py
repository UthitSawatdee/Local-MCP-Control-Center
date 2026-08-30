"""Short-lived, bounded context observation ledger.

The ledger is an intentionally isolated in-memory module.  It accepts one
stable caller key and redacted text observation at a time, then returns a
small JSON-serializable result describing whether the observation was first
seen, unchanged, or changed.  A stable opaque reference can retrieve the
latest bounded, redacted content while it remains in the ledger.

Interface
----------
``ContextLedger.deliver(key, content, *, now=None)`` stores or compares an
observation.  ``key`` is a caller-owned identifier such as
``"atm-project/src/app.py"``; it is not resolved against the filesystem.
``ContextLedger.retrieve(reference, *, now=None)`` retrieves the latest safe
content for a reference returned by ``deliver``.

Successful delivery results use ``status`` values ``"delivered"`` (first
delivery), ``"unchanged"`` (duplicate source hash), or ``"changed"``.
Retrieval uses ``"retrieved"``.  Rejected inputs use ``status: "error"`` and
an actionable ``error_code``, ``message``, ``resolution``, and ``retryable``;
an expired or capacity-evicted reference is reported as ``"expired"`` or
``"not_found"`` respectively.

The implementation deliberately stores only redacted text, hashes the
bounded source bytes without retaining or returning the source, caps every
accepted/stored/returned value, and never reads files, secrets, environment
variables, or external services.
Capacity eviction is FIFO and is reported in the result that caused it.
TTL expiry is checked at the start of each public operation; callers may pass
``now`` in a monotonic seconds domain to make expiry deterministic in tests.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import difflib
import hashlib
import math
import re
import time
from typing import Any


# Hard ceilings keep a caller from configuring an accidentally unbounded
# in-memory cache.  The defaults are deliberately smaller than the ceilings.
DEFAULT_MAX_ENTRIES = 64
DEFAULT_MAX_CONTENT_BYTES = 65_536
DEFAULT_MAX_PREVIEW_BYTES = 4_096
MAX_ENTRIES = 256
MAX_CONTENT_BYTES = 1_048_576
MAX_PREVIEW_BYTES = 65_536
MAX_KEY_BYTES = 256
MAX_TTL_SECONDS = 7 * 24 * 60 * 60

_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+/-]*$")
_REFERENCE_RE = re.compile(r"^ctx:v1:[0-9a-f]{64}$")

# These patterns intentionally target obvious credential forms only.  They
# run after the input-size guard, and all returned/stored text goes through
# them before the text is stored or diffed; the source is used only to compute
# a bounded digest and is never retained or returned.
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:api[_-]?key|access[_-]?(?:key|token)|"
    r"secret(?:[_-]?(?:key|token))?|auth(?:orization|[_-]?token)?|token|"
    r"session[_-]?token|password|passwd|pwd|client[_-]?secret|private[_-]?key|"
    r"refresh[_-]?token)(?=\s*(?:=>|[:=]))"
    r"\s*(?:=>|[:=])\s*(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\r\n,;]+)"
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 -]{1,80}PRIVATE KEY-----[\s\S]*?"
    r"-----END [A-Z0-9 -]{1,80}PRIVATE KEY-----"
)
_AUTH_HEADER_RE = re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_GITHUB_TOKEN_RE = re.compile(r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{8,}\b")
_GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")
_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{12,}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PROVIDER_TOKEN_RE = re.compile(r"\b(?:sk-(?:proj|live|test)-|sk-ant-)[A-Za-z0-9_-]{16,}\b")


@dataclass(slots=True)
class _Entry:
    """Safe internal state for one key; never contains the raw input."""

    key: str
    reference: str
    content: str
    content_hash: str
    redacted: bool
    expires_at: float | None


class ContextLedger:
    """Keep bounded, redacted observations briefly available by stable key.

    The public seam is intentionally small and side-effect free outside this
    object's memory.  A delivery never returns an unbounded value.  If the
    redacted input is larger than ``max_content_bytes`` it is rejected so a
    caller must page or bound the observation before retrying.

    Args:
        max_entries: Maximum number of keys retained.  Capacity eviction is
            deterministic FIFO and never exceeds ``MAX_ENTRIES``.
        max_content_bytes: Maximum UTF-8 bytes accepted and retained for one
            observation.  It is also the upper bound for ``retrieve`` content.
        max_preview_bytes: Maximum UTF-8 bytes in a first-delivery preview or
            changed-delivery diff.  It must not exceed the content limit.
        ttl_seconds: Optional lifetime from the most recent successful
            delivery.  It must be positive and no greater than
            ``MAX_TTL_SECONDS``.
    """

    def __init__(
        self,
        *,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        max_content_bytes: int = DEFAULT_MAX_CONTENT_BYTES,
        max_preview_bytes: int = DEFAULT_MAX_PREVIEW_BYTES,
        ttl_seconds: int | float | None = None,
    ) -> None:
        self.max_entries = self._validate_limit(
            max_entries,
            name="max_entries",
            minimum=1,
            maximum=MAX_ENTRIES,
        )
        self.max_content_bytes = self._validate_limit(
            max_content_bytes,
            name="max_content_bytes",
            minimum=1,
            maximum=MAX_CONTENT_BYTES,
        )
        self.max_preview_bytes = self._validate_limit(
            max_preview_bytes,
            name="max_preview_bytes",
            minimum=1,
            maximum=MAX_PREVIEW_BYTES,
        )
        if self.max_preview_bytes > self.max_content_bytes:
            raise ValueError("max_preview_bytes must not exceed max_content_bytes")

        if ttl_seconds is not None:
            if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)):
                raise ValueError("ttl_seconds must be a finite number or None")
            if not math.isfinite(float(ttl_seconds)):
                raise ValueError("ttl_seconds must be a finite number or None")
            if ttl_seconds <= 0 or ttl_seconds > MAX_TTL_SECONDS:
                raise ValueError(
                    f"ttl_seconds must be greater than 0 and at most {MAX_TTL_SECONDS}"
                )
            self.ttl_seconds: float | None = float(ttl_seconds)
        else:
            self.ttl_seconds = None

        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        self._references: dict[str, str] = {}

    def deliver(self, key: str, content: str, *, now: int | float | None = None) -> dict[str, Any]:
        """Compare and retain one bounded text observation.

        ``key`` must be a non-empty ASCII identifier using POSIX-like
        relative segments.  Absolute paths, parent traversal, backslashes,
        control characters, and drive-prefixed paths are rejected.  The key
        is used only as an opaque lookup identity; this method performs no
        filesystem access.

        The first accepted observation returns a bounded ``preview`` and
        ``content_hash``.  A duplicate returns no content field.  A changed
        observation returns ``previous_content_hash``, the new
        ``content_hash``, and a bounded unified ``diff``.  Both first and
        changed results include the same stable ``reference``.
        """

        key_error = self._validate_key(key)
        if key_error is not None:
            return self._error(
                "INVALID_KEY",
                key_error,
                field="key",
                resolution="Use a stable relative key such as 'scope/path.py' or 'caller:item'.",
            )

        safe_content, content_bytes, redacted, content_hash, content_error = self._prepare_content(content)
        if content_error is not None:
            return content_error

        current_time, time_error = self._resolve_now(now)
        if time_error is not None:
            return time_error
        assert current_time is not None

        evictions = self._purge_expired(current_time)
        reference = self._reference_for_key(key)
        previous = self._entries.get(key)

        if previous is not None and previous.content_hash == content_hash:
            previous.expires_at = self._expiry(current_time)
            return self._success(
                status="unchanged",
                delivery="duplicate",
                key=key,
                reference=reference,
                content_hash=content_hash,
                duplicate=True,
                redacted=redacted,
                entry_count=len(self._entries),
                evictions=evictions,
                reason="content_hash_matches",
            )

        if previous is None:
            evictions.extend(self._evict_for_capacity())
            entry = _Entry(
                key=key,
                reference=reference,
                content=safe_content,
                content_hash=content_hash,
                redacted=redacted,
                expires_at=self._expiry(current_time),
            )
            self._entries[key] = entry
            self._references[reference] = key
            return self._success(
                status="delivered",
                delivery="first",
                key=key,
                reference=reference,
                content_hash=content_hash,
                preview=self._bounded_text(safe_content, self.max_preview_bytes),
                preview_truncated=content_bytes > self.max_preview_bytes,
                content_bytes=content_bytes,
                redacted=redacted,
                duplicate=False,
                entry_count=len(self._entries),
                evictions=evictions,
            )

        previous_hash = previous.content_hash
        previous_content = previous.content
        previous.content = safe_content
        previous.content_hash = content_hash
        previous.redacted = redacted
        previous.expires_at = self._expiry(current_time)
        redaction_only_change = previous_content == safe_content
        if redaction_only_change:
            diff, diff_truncated = self._bounded_text_with_truncation(
                "[REDACTED CONTENT CHANGED]",
                self.max_preview_bytes,
            )
        else:
            diff, diff_truncated = self._bounded_diff(
                previous_content=previous_content,
                current_content=safe_content,
            )
        return self._success(
            status="changed",
            delivery="changed",
            key=key,
            reference=reference,
            previous_content_hash=previous_hash,
            content_hash=content_hash,
            diff=diff,
            diff_truncated=diff_truncated,
            redaction_only_change=redaction_only_change,
            content_bytes=content_bytes,
            redacted=redacted,
            duplicate=False,
            entry_count=len(self._entries),
            evictions=evictions,
        )

    def retrieve(self, reference: str, *, now: int | float | None = None) -> dict[str, Any]:
        """Retrieve the latest safe bounded content for a stable reference."""

        reference_error = self._validate_reference(reference)
        if reference_error is not None:
            return self._error(
                "INVALID_REFERENCE",
                reference_error,
                field="reference",
                resolution="Use the exact reference returned by a successful deliver call.",
            )

        current_time, time_error = self._resolve_now(now)
        if time_error is not None:
            return time_error
        assert current_time is not None

        evictions = self._purge_expired(current_time)
        key = self._references.get(reference)
        if key is None:
            if any(
                item["reference"] == reference and item["reason"] == "ttl"
                for item in evictions
            ):
                return self._failure(
                    status="expired",
                    error_code="REFERENCE_EXPIRED",
                    message="The reference expired and is no longer retained in this ledger.",
                    resolution="Deliver the observation again with its stable key.",
                    retryable=True,
                    reference=reference,
                    entry_count=len(self._entries),
                    evictions=evictions,
                )
            return self._failure(
                status="not_found",
                error_code="REFERENCE_NOT_FOUND",
                message="The reference is not retained in this ledger.",
                resolution="Deliver the observation again with its stable key.",
                retryable=True,
                reference=reference,
                entry_count=len(self._entries),
                evictions=evictions,
            )

        entry = self._entries[key]
        return self._success(
            status="retrieved",
            reference=reference,
            key=entry.key,
            content=entry.content,
            content_hash=entry.content_hash,
            content_bytes=len(entry.content.encode("utf-8")),
            redacted=entry.redacted,
            entry_count=len(self._entries),
            evictions=evictions,
        )

    @staticmethod
    def _validate_limit(value: Any, *, name: str, minimum: int, maximum: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer in {minimum}..{maximum}")
        if value < minimum or value > maximum:
            raise ValueError(f"{name} must be an integer in {minimum}..{maximum}")
        return value

    @staticmethod
    def _validate_key(key: Any) -> str | None:
        if not isinstance(key, str) or not key:
            return "key must be a non-empty ASCII stable identifier"
        try:
            key_bytes = key.encode("utf-8")
        except UnicodeEncodeError:
            return "key must contain valid Unicode characters"
        if len(key) > MAX_KEY_BYTES or len(key_bytes) > MAX_KEY_BYTES:
            return f"key must be at most {MAX_KEY_BYTES} UTF-8 bytes"
        if key != key.strip():
            return "key must not have leading or trailing whitespace"
        if "\x00" in key or any(ord(char) < 0x20 or ord(char) == 0x7F for char in key):
            return "key must not contain control characters"
        if key.startswith(("/", "~")) or "\\" in key:
            return "key must be relative and use '/' separators"
        if re.match(r"^[A-Za-z]:", key):
            return "drive-prefixed paths are not accepted as keys"
        parts = key.split("/")
        if any(not part or part in {".", ".."} for part in parts):
            return "key path segments must not be empty, '.' or '..'"
        if _KEY_RE.fullmatch(key) is None:
            return "key may use letters, digits, . _ : @ + - and '/' only"
        return None

    @staticmethod
    def _validate_reference(reference: Any) -> str | None:
        if not isinstance(reference, str) or _REFERENCE_RE.fullmatch(reference) is None:
            return "reference must match the opaque ctx:v1:<64 lowercase hex> format"
        return None

    def _prepare_content(self, content: Any) -> tuple[str, int, bool, str, dict[str, Any] | None]:
        if not isinstance(content, str):
            return "", 0, False, "", self._error(
                "INVALID_CONTENT",
                "content must be a UTF-8 text string",
                field="content",
                resolution="Page or serialize a text observation before calling deliver.",
            )
        # Since every UTF-8 code point is at least one byte, this fast guard
        # prevents encoding a string that is already too large.  The later
        # byte check handles multi-byte text exactly.
        if len(content) > self.max_content_bytes:
            return "", 0, False, "", self._error(
                "CONTENT_TOO_LARGE",
                f"content exceeds the {self.max_content_bytes} UTF-8 byte limit",
                field="content",
                resolution="Page or truncate the observation before retrying.",
            )
        if "\x00" in content:
            return "", 0, False, "", self._error(
                "INVALID_CONTENT",
                "content must not contain NUL bytes",
                field="content",
                resolution="Provide text-only observation content.",
            )
        try:
            raw_content = content.encode("utf-8")
        except UnicodeEncodeError:
            return "", 0, False, "", self._error(
                "INVALID_CONTENT",
                "content contains invalid Unicode surrogate characters",
                field="content",
                resolution="Provide valid UTF-8 text.",
            )
        if len(raw_content) > self.max_content_bytes:
            return "", 0, False, "", self._error(
                "CONTENT_TOO_LARGE",
                f"content exceeds the {self.max_content_bytes} UTF-8 byte limit",
                field="content",
                resolution="Page or truncate the observation before retrying.",
            )

        source_hash = self._hash_bytes(raw_content)
        safe_content = self._redact(content)
        safe_bytes = len(safe_content.encode("utf-8"))
        if safe_bytes > self.max_content_bytes:
            return "", 0, False, "", self._error(
                "CONTENT_TOO_LARGE",
                f"redaction expands content beyond the {self.max_content_bytes} UTF-8 byte limit",
                field="content",
                resolution="Page the observation or use a larger bounded content limit before retrying.",
            )
        return safe_content, safe_bytes, safe_content != content, source_hash, None

    def _resolve_now(self, now: int | float | None) -> tuple[float | None, dict[str, Any] | None]:
        current = time.monotonic() if now is None else now
        if isinstance(current, bool) or not isinstance(current, (int, float)):
            return None, self._error(
                "INVALID_TIME",
                "now must be a finite number of monotonic seconds",
                field="now",
                resolution="Omit now or provide a finite numeric test clock value.",
            )
        if not math.isfinite(float(current)):
            return None, self._error(
                "INVALID_TIME",
                "now must be a finite number of monotonic seconds",
                field="now",
                resolution="Omit now or provide a finite numeric test clock value.",
            )
        return float(current), None

    def _expiry(self, current_time: float) -> float | None:
        if self.ttl_seconds is None:
            return None
        return current_time + self.ttl_seconds

    def _purge_expired(self, current_time: float) -> list[dict[str, str]]:
        if self.ttl_seconds is None:
            return []
        evictions: list[dict[str, str]] = []
        for key, entry in tuple(self._entries.items()):
            if entry.expires_at is not None and current_time >= entry.expires_at:
                del self._entries[key]
                self._references.pop(entry.reference, None)
                evictions.append({"reference": entry.reference, "reason": "ttl"})
        return evictions

    def _evict_for_capacity(self) -> list[dict[str, str]]:
        if len(self._entries) < self.max_entries:
            return []
        key, entry = self._entries.popitem(last=False)
        del key
        self._references.pop(entry.reference, None)
        return [{"reference": entry.reference, "reason": "capacity"}]

    def _bounded_diff(self, *, previous_content: str, current_content: str) -> tuple[str, bool]:
        diff = "".join(
            difflib.unified_diff(
                previous_content.splitlines(keepends=True),
                current_content.splitlines(keepends=True),
                fromfile="previous",
                tofile="current",
                n=2,
            )
        )
        if not diff:
            # This is defensive only; it keeps a changed result actionable if
            # the diff implementation ever changes its output convention.
            diff = current_content
        truncated = len(diff.encode("utf-8")) > self.max_preview_bytes
        return self._bounded_text(diff, self.max_preview_bytes), truncated

    @staticmethod
    def _bounded_text(value: str, max_bytes: int) -> str:
        raw = value.encode("utf-8")
        if len(raw) <= max_bytes:
            return value
        return raw[:max_bytes].decode("utf-8", errors="ignore")

    @staticmethod
    def _redact(content: str) -> str:
        safe = content
        for pattern in (
            _PRIVATE_KEY_RE,
            _AUTH_HEADER_RE,
            _SECRET_ASSIGNMENT_RE,
            _AWS_ACCESS_KEY_RE,
            _GITHUB_TOKEN_RE,
            _GOOGLE_API_KEY_RE,
            _SLACK_TOKEN_RE,
            _JWT_RE,
            _PROVIDER_TOKEN_RE,
        ):
            safe = pattern.sub("[REDACTED]", safe)
        return safe

    @staticmethod
    def _hash_bytes(data: bytes) -> str:
        return "sha256:" + hashlib.sha256(data).hexdigest()

    @staticmethod
    def _bounded_text_with_truncation(value: str, max_bytes: int) -> tuple[str, bool]:
        raw = value.encode("utf-8")
        return ContextLedger._bounded_text(value, max_bytes), len(raw) > max_bytes

    @staticmethod
    def _reference_for_key(key: str) -> str:
        key_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return f"ctx:v1:{key_digest}"

    @staticmethod
    def _success(**fields: Any) -> dict[str, Any]:
        fields.setdefault("ok", True)
        return fields

    @staticmethod
    def _failure(**fields: Any) -> dict[str, Any]:
        fields.setdefault("ok", False)
        return fields

    @classmethod
    def _error(
        cls,
        error_code: str,
        message: str,
        *,
        field: str,
        resolution: str,
        retryable: bool = False,
    ) -> dict[str, Any]:
        return cls._failure(
            status="error",
            error_code=error_code,
            message=message,
            field=field,
            resolution=resolution,
            retryable=retryable,
        )


__all__ = [
    "ContextLedger",
    "DEFAULT_MAX_CONTENT_BYTES",
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_MAX_PREVIEW_BYTES",
    "MAX_CONTENT_BYTES",
    "MAX_ENTRIES",
    "MAX_KEY_BYTES",
    "MAX_PREVIEW_BYTES",
    "MAX_TTL_SECONDS",
]
