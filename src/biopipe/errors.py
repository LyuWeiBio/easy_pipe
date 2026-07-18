"""Stable, machine-readable errors used by the controller."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any


class ErrorSeverity(str, Enum):
    """The effect an error has on the requested operation."""

    WARNING = "warning"
    BLOCKING = "blocking"
    INTERNAL = "internal"


class ErrorCode(str, Enum):
    """Stable controller error codes; values are additive across milestones."""

    VALIDATION_FAILED = "VALIDATION_FAILED"
    SERIALIZATION_FAILED = "SERIALIZATION_FAILED"
    ARTIFACT_READ_FAILED = "ARTIFACT_READ_FAILED"
    ARTIFACT_WRITE_FAILED = "ARTIFACT_WRITE_FAILED"
    AUDIT_WRITE_FAILED = "AUDIT_WRITE_FAILED"
    SOURCE_ALREADY_EXISTS = "SOURCE_ALREADY_EXISTS"
    SOURCE_NOT_FOUND = "SOURCE_NOT_FOUND"
    SOURCE_STORAGE_FAILED = "SOURCE_STORAGE_FAILED"
    SSH_AUTH_FAILED = "SSH_AUTH_FAILED"
    SSH_CLIENT_NOT_FOUND = "SSH_CLIENT_NOT_FOUND"
    SSH_CONNECTION_FAILED = "SSH_CONNECTION_FAILED"
    SSH_EXECUTION_FAILED = "SSH_EXECUTION_FAILED"
    SSH_HOST_KEY_MISMATCH = "SSH_HOST_KEY_MISMATCH"
    SSH_OUTPUT_LIMIT_EXCEEDED = "SSH_OUTPUT_LIMIT_EXCEEDED"
    SSH_TIMEOUT = "SSH_TIMEOUT"
    PROBE_PROTOCOL_ERROR = "PROBE_PROTOCOL_ERROR"
    PROBE_REQUEST_MISMATCH = "PROBE_REQUEST_MISMATCH"
    PROBE_REMOTE_FAILED = "PROBE_REMOTE_FAILED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class BioPipeError(Exception):
    """An operational error with a stable representation for CLI and API callers."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        severity: ErrorSeverity | str = ErrorSeverity.BLOCKING,
        context: Mapping[str, Any] | None = None,
        remediation: Sequence[str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.severity = ErrorSeverity(severity)
        self.context = dict(context or {})
        self.remediation = list(remediation or [])

    def to_dict(self) -> dict[str, Any]:
        """Return the stable error envelope used by machine-readable output."""

        return {
            "error": {
                "code": self.code.value,
                "severity": self.severity.value,
                "message": self.message,
                "context": self.context,
                "remediation": self.remediation,
            }
        }

    def to_json(self) -> str:
        """Serialize the error deterministically without leaking exception internals."""

        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


__all__ = ["BioPipeError", "ErrorCode", "ErrorSeverity"]
