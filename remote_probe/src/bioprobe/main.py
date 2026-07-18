"""Bounded JSONL stdin/stdout process entrypoint."""

from __future__ import annotations

import sys
from collections.abc import Sequence
from typing import Any, BinaryIO, TextIO

from .config import ProbeConfig, ProbeLimits, load_config
from .errors import ProbeFailure, ReturnCode
from .protocol import (
    decode_json_line,
    encode_response_line,
    enforce_response_limit,
    response_failure,
    safe_request_id,
)
from .service import handle_request


def main(argv: Sequence[str] | None = None) -> int:
    """Process JSONL until EOF and return the first failed response code."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments:
        failure = ProbeFailure(
            ReturnCode.PROTOCOL_ERROR,
            "ARGUMENTS_FORBIDDEN",
            "bioprobe accepts requests only through JSONL stdin",
        )
        _write_response(
            sys.stdout,
            response_failure("unknown", failure),
            ProbeLimits().max_response_bytes,
        )
        return int(failure.return_code)

    config_failure: ProbeFailure | None = None
    try:
        config = load_config()
    except ProbeFailure as failure:
        config = ProbeConfig.fail_closed_default()
        config_failure = failure

    return run_stream(
        sys.stdin.buffer,
        sys.stdout,
        config,
        startup_failure=config_failure,
    )


def run_stream(
    stream: BinaryIO,
    output: TextIO,
    config: ProbeConfig,
    *,
    startup_failure: ProbeFailure | None = None,
) -> int:
    """Read bounded request lines and write exactly one response per line."""

    first_failure = int(ReturnCode.SUCCESS)
    line_limit = config.limits.max_request_bytes
    while True:
        data = stream.readline(line_limit + 1)
        if not data:
            break
        if len(data) > line_limit:
            if not data.endswith(b"\n"):
                _discard_to_newline(stream, line_limit)
            failure = ProbeFailure(
                ReturnCode.BUDGET_EXCEEDED,
                "REQUEST_BUDGET_EXCEEDED",
                "request line exceeds max_request_bytes",
                context={"max_request_bytes": line_limit},
            )
            response = response_failure("unknown", failure)
        else:
            if data.endswith(b"\n"):
                data = data[:-1]
            if data.endswith(b"\r"):
                data = data[:-1]
            payload: Any = None
            try:
                payload = decode_json_line(data)
                if startup_failure is not None:
                    response = response_failure(safe_request_id(payload), startup_failure)
                else:
                    response = handle_request(payload, config)
            except ProbeFailure as failure:
                response = response_failure(safe_request_id(payload), failure)
        response = _write_response(
            output,
            response,
            config.limits.max_response_bytes,
        )
        return_code = response["return_code"]
        if first_failure == 0 and isinstance(return_code, int) and return_code != 0:
            first_failure = return_code
    return first_failure


def _discard_to_newline(stream: BinaryIO, chunk_size: int) -> None:
    while True:
        chunk = stream.readline(chunk_size)
        if not chunk or chunk.endswith(b"\n"):
            return


def _write_response(
    output: TextIO,
    response: dict[str, Any],
    max_response_bytes: int,
) -> dict[str, Any]:
    bounded = enforce_response_limit(response, max_response_bytes)
    serialized = encode_response_line(bounded)
    output.write(serialized.decode("ascii"))
    output.flush()
    return bounded


__all__ = ["main", "run_stream"]
