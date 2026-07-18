"""Stable public failures for the fixed remote execution protocol."""

from __future__ import annotations

from enum import IntEnum
from typing import Any


class ReturnCode(IntEnum):
    """Process and response return codes."""

    SUCCESS = 0
    PROTOCOL_ERROR = 10
    UNSUPPORTED_OPERATION = 11
    PATH_OUTSIDE_ALLOWLIST = 20
    PATH_UNAVAILABLE = 21
    SYMLINK_OR_ESCAPE = 22
    BUDGET_EXCEEDED = 30
    TIMEOUT = 31
    PREFLIGHT_FAILED = 40
    DEPLOYMENT_FAILED = 41
    APPROVAL_REQUIRED = 42
    STATE_CONFLICT = 43
    RUN_FAILED = 44
    INTERNAL_ERROR = 50


class AgentFailure(Exception):
    """Expected sanitized failure suitable for a response envelope."""

    def __init__(
        self,
        return_code: ReturnCode,
        code: str,
        message: str,
        *,
        context: dict[str, Any] | None = None,
        remediation: list[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.return_code = return_code
        self.code = code
        self.message = message
        self.context = dict(context or {})
        self.remediation = list(remediation or [])


__all__ = ["AgentFailure", "ReturnCode"]
