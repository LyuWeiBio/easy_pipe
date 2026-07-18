"""Operation dispatch for one already-decoded JSON request."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .config import ProbeConfig
from .errors import ProbeFailure, ReturnCode
from .operations import detect_formats, health, list_tree, stat_files, summarize_fastq
from .protocol import (
    enforce_response_limit,
    parse_request,
    response_failure,
    response_success,
    safe_request_id,
)


def handle_request(payload: Mapping[str, object] | object, config: ProbeConfig) -> dict[str, Any]:
    """Handle one request and always return a protocol response envelope."""

    request_id = safe_request_id(payload)
    try:
        request = parse_request(payload)
        request_id = request.request_id
        handlers = {
            "detect_formats": detect_formats,
            "health": health,
            "list_tree": list_tree,
            "stat_files": stat_files,
            "summarize_fastq": summarize_fastq,
        }
        handler = handlers.get(request.operation)
        if handler is None:
            raise ProbeFailure(
                ReturnCode.UNSUPPORTED_OPERATION,
                "UNSUPPORTED_OPERATION",
                "operation is not implemented by this probe",
                context={"supported_operations": sorted(handlers)},
            )
        response = response_success(request_id, handler(request, config))
    except ProbeFailure as failure:
        response = response_failure(request_id, failure)
    except Exception:
        internal_failure = ProbeFailure(
            ReturnCode.INTERNAL_ERROR,
            "INTERNAL_ERROR",
            "probe encountered an internal error",
            remediation=["Review sanitized server-side diagnostics."],
        )
        response = response_failure(request_id, internal_failure)
    return enforce_response_limit(response, config.limits.max_response_bytes)


__all__ = ["handle_request"]
