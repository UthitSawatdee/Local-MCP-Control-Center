from __future__ import annotations


class ControlCenterError(Exception):
    """Base error for the control center."""


class PolicyError(ControlCenterError):
    """An action was rejected by an explicit policy or invariant."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class StorageError(ControlCenterError):
    """The policy/audit state could not be read or written."""


class ApprovalError(ControlCenterError):
    """An approval is absent, stale, expired, or already consumed."""


class TunnelError(ControlCenterError):
    """The configured tunnel client could not be validated or started."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message
