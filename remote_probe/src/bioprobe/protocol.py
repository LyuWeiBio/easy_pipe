"""Strict JSON request parsing and stable JSON response envelopes."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any

from . import PROTOCOL_VERSION
from .errors import ProbeFailure, ReturnCode

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MAX_JSON_NESTING = 128
_TOP_LEVEL_FIELDS = {
    "protocol_version",
    "request_id",
    "operation",
    "root",
    "paths",
    "policy",
}
_POLICY_FIELDS = {
    "inspection_level",
    "max_depth",
    "max_entries",
    "max_runtime_seconds",
    "follow_symlinks",
    "sample_fastq_records",
    "return_sequences",
    "return_qualities",
    "return_read_names",
}


@dataclass(frozen=True, slots=True)
class RequestPolicy:
    """Client-requested limits, later capped by server configuration."""

    inspection_level: str = "metadata_only"
    max_depth: int | None = None
    max_entries: int | None = None
    max_runtime_seconds: float | None = None
    follow_symlinks: bool = False
    sample_fastq_records: int = 0


@dataclass(frozen=True, slots=True)
class ProbeRequest:
    """Validated M2 request independent of controller-side dependencies."""

    request_id: str
    operation: str
    root: str | None
    paths: tuple[str, ...]
    policy: RequestPolicy


def decode_json_line(data: bytes) -> Any:
    """Decode one finite, duplicate-key-free UTF-8 JSON value."""

    try:
        text = data.decode("utf-8")
        _reject_excessive_nesting(text)
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ProbeFailure(
            ReturnCode.PROTOCOL_ERROR,
            "INVALID_JSON",
            "request line must contain one strict UTF-8 JSON object",
        ) from exc


def parse_request(payload: Any) -> ProbeRequest:
    """Validate an object against the fixed M2 request schema."""

    if not isinstance(payload, dict):
        raise _schema_error("request must be a JSON object")
    unknown = set(payload) - _TOP_LEVEL_FIELDS
    if unknown:
        raise _schema_error("request contains unsupported fields")
    if payload.get("protocol_version") != PROTOCOL_VERSION:
        raise _schema_error("unsupported or missing protocol_version")

    request_id = payload.get("request_id")
    if not isinstance(request_id, str) or not _IDENTIFIER.fullmatch(request_id):
        raise _schema_error("request_id has an invalid format")
    operation = payload.get("operation")
    if not isinstance(operation, str) or not operation or len(operation) > 128:
        raise _schema_error("operation must be a non-empty string")

    root_value = payload.get("root")
    if root_value is not None and not isinstance(root_value, str):
        raise _schema_error("root must be a string or null")
    paths_value = payload.get("paths", [])
    if not isinstance(paths_value, list) or not all(
        isinstance(value, str) for value in paths_value
    ):
        raise _schema_error("paths must be an array of strings")
    if len(paths_value) != len(set(paths_value)):
        raise _schema_error("paths must not contain duplicates")

    policy_value = payload.get("policy", {})
    if not isinstance(policy_value, dict):
        raise _schema_error("policy must be an object")
    if set(policy_value) - _POLICY_FIELDS:
        raise _schema_error("policy contains unsupported fields")
    policy = _parse_policy(policy_value)

    if operation == "list_tree" and root_value is None:
        raise _schema_error("list_tree requires root")
    if operation == "stat_files" and not paths_value:
        raise _schema_error("stat_files requires at least one path")
    if operation in {"detect_formats", "summarize_fastq"}:
        if root_value is None:
            raise _schema_error(f"{operation} requires root")
        if not paths_value:
            raise _schema_error(f"{operation} requires at least one path")
        if policy.inspection_level != "format_summary":
            raise _schema_error(f"{operation} requires inspection_level format_summary")
    if operation == "summarize_fastq" and policy.sample_fastq_records < 1:
        raise _schema_error("summarize_fastq requires sample_fastq_records >= 1")

    return ProbeRequest(
        request_id=request_id,
        operation=operation,
        root=root_value,
        paths=tuple(paths_value),
        policy=policy,
    )


def response_success(request_id: str, result: dict[str, Any]) -> dict[str, Any]:
    """Create a successful protocol envelope."""

    return {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request_id,
        "success": True,
        "return_code": int(ReturnCode.SUCCESS),
        "result": result,
        "error": None,
    }


def response_failure(request_id: str, failure: ProbeFailure) -> dict[str, Any]:
    """Create a sanitized failed protocol envelope."""

    return {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request_id,
        "success": False,
        "return_code": int(failure.return_code),
        "result": None,
        "error": {
            "code": failure.code,
            "message": failure.message,
            "context": failure.context,
            "remediation": failure.remediation,
        },
    }


def encode_json(value: Any) -> bytes:
    """Serialize protocol data to its deterministic ASCII JSON representation."""

    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def encode_response_line(response: dict[str, Any]) -> bytes:
    """Serialize one complete JSONL response, including its newline."""

    return encode_json(response) + b"\n"


def response_budget_failure(request_id: str, limit: int) -> dict[str, Any]:
    """Create the stable code-30 replacement for an oversized response."""

    failure = ProbeFailure(
        ReturnCode.BUDGET_EXCEEDED,
        "RESPONSE_BUDGET_EXCEEDED",
        "response exceeds max_response_bytes",
        context={"max_response_bytes": limit},
    )
    return response_failure(request_id, failure)


def enforce_response_limit(response: dict[str, Any], max_response_bytes: int) -> dict[str, Any]:
    """Replace any oversized response with a bounded code-30 envelope."""

    if len(encode_response_line(response)) <= max_response_bytes:
        return response
    request_id = safe_request_id(response)
    bounded = response_budget_failure(request_id, max_response_bytes)
    if len(encode_response_line(bounded)) <= max_response_bytes:
        return bounded
    compact = response_budget_failure("unknown", max_response_bytes)
    if len(encode_response_line(compact)) > max_response_bytes:
        raise RuntimeError("max_response_bytes is too small for the failure envelope")
    return compact


def safe_request_id(payload: Any) -> str:
    """Extract an ID for an error envelope without trusting invalid input."""

    if isinstance(payload, dict):
        value = payload.get("request_id")
        if isinstance(value, str) and _IDENTIFIER.fullmatch(value):
            return value
    return "unknown"


def _parse_policy(value: dict[str, Any]) -> RequestPolicy:
    inspection = value.get("inspection_level", "metadata_only")
    if inspection not in {"metadata_only", "format_summary", "integrity_check"}:
        raise _schema_error("inspection_level is unsupported")
    sample_records = value.get("sample_fastq_records", 0)
    if (
        isinstance(sample_records, bool)
        or not isinstance(sample_records, int)
        or not 0 <= sample_records <= 100_000
    ):
        raise _schema_error("sample_fastq_records is outside its supported range")
    for key in ("return_sequences", "return_qualities", "return_read_names"):
        raw_return = value.get(key, False)
        if not isinstance(raw_return, bool):
            raise _schema_error(f"{key} must be a boolean")
        if raw_return:
            raise ProbeFailure(
                ReturnCode.PROTOCOL_ERROR,
                "RAW_CONTENT_FORBIDDEN",
                "M2 never returns FASTQ records or file contents",
            )

    follow_symlinks = value.get("follow_symlinks", False)
    if not isinstance(follow_symlinks, bool):
        raise _schema_error("follow_symlinks must be a boolean")
    if follow_symlinks:
        raise ProbeFailure(
            ReturnCode.SYMLINK_OR_ESCAPE,
            "SYMLINK_FORBIDDEN",
            "M2 does not permit following symlinks",
        )
    max_depth = _optional_int(value, "max_depth", 0, 64)
    max_entries = _optional_int(value, "max_entries", 1, 10_000_000)
    max_runtime = _optional_number(value, "max_runtime_seconds", 0.000001, 3_600.0)
    return RequestPolicy(
        inspection_level=inspection,
        max_depth=max_depth,
        max_entries=max_entries,
        max_runtime_seconds=max_runtime,
        follow_symlinks=follow_symlinks,
        sample_fastq_records=sample_records,
    )


def _optional_int(values: dict[str, Any], key: str, minimum: int, maximum: int) -> int | None:
    if key not in values:
        return None
    value = values[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise _schema_error(f"{key} must be an integer")
    if not minimum <= value <= maximum:
        raise _schema_error(f"{key} is outside its supported range")
    return int(value)


def _optional_number(
    values: dict[str, Any], key: str, minimum: float, maximum: float
) -> float | None:
    if key not in values:
        return None
    value = values[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _schema_error(f"{key} must be a number")
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise _schema_error(f"{key} is outside its supported range")
    return number


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _reject_excessive_nesting(value: str) -> None:
    """Enforce a deterministic nesting limit before the version-specific decoder."""

    depth = 0
    in_string = False
    escaped = False
    for character in value:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > _MAX_JSON_NESTING:
                raise ValueError("JSON nesting limit exceeded")
        elif character in "]}" and depth:
            depth -= 1


def _schema_error(message: str) -> ProbeFailure:
    return ProbeFailure(ReturnCode.PROTOCOL_ERROR, "SCHEMA_ERROR", message)


__all__ = [
    "ProbeRequest",
    "RequestPolicy",
    "decode_json_line",
    "encode_json",
    "encode_response_line",
    "enforce_response_limit",
    "parse_request",
    "response_budget_failure",
    "response_failure",
    "response_success",
    "safe_request_id",
]
