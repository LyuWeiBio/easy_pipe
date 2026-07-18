"""Stable probe failures and process return codes."""

from __future__ import annotations

from enum import IntEnum
from typing import Any


class ReturnCode(IntEnum):
    """Public return codes shared by response envelopes and the process."""

    SUCCESS = 0
    PROTOCOL_ERROR = 10
    UNSUPPORTED_OPERATION = 11
    PATH_OUTSIDE_ALLOWLIST = 20
    PATH_UNAVAILABLE = 21
    SYMLINK_OR_ESCAPE = 22
    BUDGET_EXCEEDED = 30
    TIMEOUT = 31
    UNSUPPORTED_FORMAT = 40
    INVALID_FASTQ = 41
    INTERNAL_ERROR = 50


class ProbeFailure(Exception):
    """Expected, sanitized failure suitable for a JSONL response."""

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


__all__ = ["ProbeFailure", "ReturnCode"]
