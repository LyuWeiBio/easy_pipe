"""One-request JSONL entry point for the fixed execution agent."""

from __future__ import annotations

import sys
from typing import Any, BinaryIO

from . import PROTOCOL_VERSION, __version__
from .config import AgentConfig, Limits, load_config
from .deployment import deploy_bundle
from .errors import AgentFailure, ReturnCode
from .preflight import run_preflight
from .protocol import (
    decode_json_line,
    encode_response_line,
    enforce_response_limit,
    parse_request,
    require_exact_fields,
    response_failure,
    response_success,
    safe_request_id,
)
from .state import StateStore


def main() -> int:
    """Load policy, handle exactly one request, and mirror the response return code."""

    try:
        config = load_config()
    except AgentFailure as failure:
        response = response_failure("unknown", failure)
        sys.stdout.buffer.write(encode_response_line(response))
        sys.stdout.buffer.flush()
        return int(failure.return_code)
    response = serve_once(sys.stdin.buffer, config)
    sys.stdout.buffer.write(encode_response_line(response))
    sys.stdout.buffer.flush()
    return int(response["return_code"])


def serve_once(stream: BinaryIO, config: AgentConfig) -> dict[str, Any]:
    """Read and execute one complete line; never mutate after ambiguous framing."""

    request_id = "unknown"
    try:
        raw = _read_single_line(stream, config.limits)
        decoded = decode_json_line(raw)
        request_id = safe_request_id(decoded)
        request = parse_request(decoded)
        request_id = request.request_id
        result = _dispatch(request.operation, request.payload, config)
        response = response_success(request.request_id, result)
    except AgentFailure as failure:
        response = response_failure(request_id, failure)
    except Exception:
        response = response_failure(
            request_id,
            AgentFailure(
                ReturnCode.INTERNAL_ERROR,
                "INTERNAL_ERROR",
                "the fixed execution agent could not complete the request",
            ),
        )
    return enforce_response_limit(response, config.limits.max_response_bytes)


def _dispatch(operation: str, payload: dict[str, Any], config: AgentConfig) -> dict[str, Any]:
    state = StateStore(config.state_root)
    if operation == "health":
        require_exact_fields(payload, required=set())
        return {
            "status": "ok",
            "agent_version": __version__,
            "protocol_version": PROTOCOL_VERSION,
            "profile_id": config.profile_id,
            "profile_hash": config.profile_hash,
            "operations": [
                "abandon",
                "deploy",
                "health",
                "preflight",
                "resume",
                "status",
                "submit",
            ],
        }
    if operation == "preflight":
        result, record = run_preflight(payload, config, state=state)
        if record is not None:
            state.create("preflights", record["preflight_id"], record)
        return result
    if operation == "deploy":
        return deploy_bundle(payload, config, state)
    if operation in {"submit", "status", "resume", "abandon"}:
        from .runner import handle_run_operation

        return handle_run_operation(operation, payload, config, state)
    raise AgentFailure(
        ReturnCode.UNSUPPORTED_OPERATION,
        "UNSUPPORTED_OPERATION",
        "operation is not implemented by this agent",
    )


def _read_single_line(stream: BinaryIO, limits: Limits) -> bytes:
    raw = stream.read(limits.max_request_bytes + 1)
    if len(raw) > limits.max_request_bytes:
        raise AgentFailure(
            ReturnCode.BUDGET_EXCEEDED,
            "REQUEST_BUDGET_EXCEEDED",
            "request exceeds max_request_bytes",
            context={"max_request_bytes": limits.max_request_bytes},
        )
    if not raw or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise AgentFailure(
            ReturnCode.PROTOCOL_ERROR,
            "INVALID_JSONL_FRAME",
            "stdin must contain exactly one newline-terminated JSON request",
        )
    line = raw[:-1]
    if not line or line.endswith(b"\r"):
        raise AgentFailure(
            ReturnCode.PROTOCOL_ERROR,
            "INVALID_JSONL_FRAME",
            "stdin must contain one canonical LF-terminated JSON request",
        )
    return line


__all__ = ["main", "serve_once"]
