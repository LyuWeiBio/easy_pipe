"""Tests for stable, machine-readable application errors."""

from __future__ import annotations

import json
import re

from biopipe.errors import BioPipeError, ErrorCode

EXPECTED_ERROR_CODES = {
    "ARTIFACT_READ_FAILED": "ARTIFACT_READ_FAILED",
    "ARTIFACT_WRITE_FAILED": "ARTIFACT_WRITE_FAILED",
    "AUDIT_WRITE_FAILED": "AUDIT_WRITE_FAILED",
    "APPROVAL_ARTIFACT_MISMATCH": "APPROVAL_ARTIFACT_MISMATCH",
    "APPROVAL_REQUIRED": "APPROVAL_REQUIRED",
    "DEPLOYMENT_FAILED": "DEPLOYMENT_FAILED",
    "EXECUTION_PROFILE_INVALID": "EXECUTION_PROFILE_INVALID",
    "INTERNAL_ERROR": "INTERNAL_ERROR",
    "MANIFEST_INTEGRITY_FAILED": "MANIFEST_INTEGRITY_FAILED",
    "MANIFEST_OVERRIDE_CONFLICT": "MANIFEST_OVERRIDE_CONFLICT",
    "MANIFEST_STORAGE_FAILED": "MANIFEST_STORAGE_FAILED",
    "NOT_IMPLEMENTED": "NOT_IMPLEMENTED",
    "OUTPUT_ALREADY_EXISTS": "OUTPUT_ALREADY_EXISTS",
    "PREFLIGHT_FAILED": "PREFLIGHT_FAILED",
    "PREFLIGHT_STALE": "PREFLIGHT_STALE",
    "PROBE_PROTOCOL_ERROR": "PROBE_PROTOCOL_ERROR",
    "PROBE_REQUEST_MISMATCH": "PROBE_REQUEST_MISMATCH",
    "PROBE_REMOTE_FAILED": "PROBE_REMOTE_FAILED",
    "SERIALIZATION_FAILED": "SERIALIZATION_FAILED",
    "REMOTE_EXECUTION_PROTOCOL_ERROR": "REMOTE_EXECUTION_PROTOCOL_ERROR",
    "RESUME_INCOMPATIBLE": "RESUME_INCOMPATIBLE",
    "RUN_STATUS_FAILED": "RUN_STATUS_FAILED",
    "RUN_SUBMISSION_FAILED": "RUN_SUBMISSION_FAILED",
    "SOURCE_ALREADY_EXISTS": "SOURCE_ALREADY_EXISTS",
    "SOURCE_NOT_FOUND": "SOURCE_NOT_FOUND",
    "SOURCE_STORAGE_FAILED": "SOURCE_STORAGE_FAILED",
    "SSH_AUTH_FAILED": "SSH_AUTH_FAILED",
    "SSH_CLIENT_NOT_FOUND": "SSH_CLIENT_NOT_FOUND",
    "SSH_CONNECTION_FAILED": "SSH_CONNECTION_FAILED",
    "SSH_EXECUTION_FAILED": "SSH_EXECUTION_FAILED",
    "SSH_HOST_KEY_MISMATCH": "SSH_HOST_KEY_MISMATCH",
    "SSH_OUTPUT_LIMIT_EXCEEDED": "SSH_OUTPUT_LIMIT_EXCEEDED",
    "SSH_TIMEOUT": "SSH_TIMEOUT",
    "VALIDATION_FAILED": "VALIDATION_FAILED",
}


def test_error_codes_are_unique_stable_identifiers() -> None:
    values = [code.value for code in ErrorCode]

    assert values
    assert len(values) == len(set(values))
    assert all(re.fullmatch(r"[A-Z][A-Z0-9_]*", value) for value in values)
    assert {code.name: code.value for code in ErrorCode} == EXPECTED_ERROR_CODES


def test_biopipe_error_has_stable_json_shape() -> None:
    code = ErrorCode.VALIDATION_FAILED
    error = BioPipeError(
        code=code,
        message="Synthetic blocking failure.",
        severity="blocking",
        context={"fixture": "safe"},
        remediation=["Review the synthetic fixture."],
    )

    first = error.to_json()
    second = error.to_json()
    payload = json.loads(first)

    assert isinstance(error, Exception)
    assert first == second
    assert payload == {
        "error": {
            "code": code.value,
            "severity": "blocking",
            "message": "Synthetic blocking failure.",
            "context": {"fixture": "safe"},
            "remediation": ["Review the synthetic fixture."],
        }
    }
    assert error.to_dict() == payload
