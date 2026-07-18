"""Strict duplicate-free JSONL request and response contracts."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any, cast

from . import PROTOCOL_VERSION
from .errors import AgentFailure, ReturnCode

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TOP_LEVEL_FIELDS = frozenset({"protocol_version", "request_id", "operation", "payload"})
_OPERATIONS = frozenset({"health", "preflight", "deploy", "submit", "status", "resume", "abandon"})
_MAX_JSON_NESTING = 128


@dataclass(frozen=True)
class Request:
    """One validated top-level request with an operation-specific payload."""

    request_id: str
    operation: str
    payload: dict[str, Any]


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
        raise AgentFailure(
            ReturnCode.PROTOCOL_ERROR,
            "INVALID_JSON",
            "request line must contain one strict UTF-8 JSON object",
        ) from exc


def parse_request(value: Any) -> Request:
    """Validate the common envelope and reject every unreviewed operation."""

    if not isinstance(value, dict):
        raise _schema_error("request must be a JSON object")
    if set(value) != _TOP_LEVEL_FIELDS:
        raise _schema_error("request fields do not match the fixed envelope")
    if value.get("protocol_version") != PROTOCOL_VERSION:
        raise _schema_error("unsupported protocol_version")
    request_id = require_identifier(value.get("request_id"), "request_id")
    operation = value.get("operation")
    if not isinstance(operation, str) or operation not in _OPERATIONS:
        raise AgentFailure(
            ReturnCode.UNSUPPORTED_OPERATION,
            "UNSUPPORTED_OPERATION",
            "operation is not implemented by this agent",
        )
    payload = value.get("payload")
    if not isinstance(payload, dict):
        raise _schema_error("payload must be an object")
    return Request(request_id=request_id, operation=operation, payload=payload)


def require_exact_fields(
    payload: dict[str, Any],
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> None:
    """Require an exact operation-specific field allowlist."""

    optional_fields = optional or set()
    if not required.issubset(payload) or set(payload) - required - optional_fields:
        raise _schema_error("payload fields do not match the fixed operation contract")


def require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise _schema_error(f"{field} must be a safe identifier")
    return value


def require_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise _schema_error(f"{field} must be a lowercase SHA-256 digest")
    return value


def require_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise _schema_error(f"{field} must be a boolean")
    return value


def require_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise _schema_error(f"{field} is outside its supported integer range")
    return cast(int, value)


def require_string(value: Any, field: str, *, maximum_bytes: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or len(value.encode("utf-8")) > maximum_bytes
    ):
        raise _schema_error(f"{field} must be bounded safe text")
    return value


def response_success(request_id: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request_id,
        "success": True,
        "return_code": int(ReturnCode.SUCCESS),
        "result": result,
        "error": None,
    }


def response_failure(request_id: str, failure: AgentFailure) -> dict[str, Any]:
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
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def encode_response_line(response: dict[str, Any]) -> bytes:
    return encode_json(response) + b"\n"


def enforce_response_limit(response: dict[str, Any], maximum: int) -> dict[str, Any]:
    if len(encode_response_line(response)) <= maximum:
        return response
    request_id = safe_request_id(response)
    bounded = response_failure(
        request_id,
        AgentFailure(
            ReturnCode.BUDGET_EXCEEDED,
            "RESPONSE_BUDGET_EXCEEDED",
            "response exceeds max_response_bytes",
            context={"max_response_bytes": maximum},
        ),
    )
    if len(encode_response_line(bounded)) <= maximum:
        return bounded
    return response_failure(
        "unknown",
        AgentFailure(
            ReturnCode.BUDGET_EXCEEDED,
            "RESPONSE_BUDGET_EXCEEDED",
            "response exceeds the configured limit",
        ),
    )


def safe_request_id(value: Any) -> str:
    if isinstance(value, dict):
        candidate = value.get("request_id")
        if isinstance(candidate, str) and _IDENTIFIER.fullmatch(candidate):
            return candidate
    return "unknown"


def _schema_error(message: str) -> AgentFailure:
    return AgentFailure(ReturnCode.PROTOCOL_ERROR, "SCHEMA_ERROR", message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _reject_excessive_nesting(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
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
                raise ValueError("JSON nesting exceeds the supported limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ValueError("JSON delimiters are unbalanced")
    if not math.isfinite(float(depth)) or depth != 0 or in_string:
        raise ValueError("JSON structure is incomplete")


__all__ = [
    "Request",
    "decode_json_line",
    "encode_response_line",
    "enforce_response_limit",
    "parse_request",
    "require_bool",
    "require_exact_fields",
    "require_identifier",
    "require_int",
    "require_sha256",
    "require_string",
    "response_failure",
    "response_success",
    "safe_request_id",
]
