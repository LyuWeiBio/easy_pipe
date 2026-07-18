"""Bounded OpenSSH transport for the fixed remote execution agent."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath
from typing import Any, Final, Literal, Protocol
from uuid import uuid4

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.models import SourceProfile
from biopipe.probe.bounded import run_bounded

ExecutionOperation = Literal[
    "health",
    "preflight",
    "deploy",
    "submit",
    "status",
    "resume",
    "abandon",
]

_SAFE_REMOTE_PATH: Final[re.Pattern[str]] = re.compile(r"^(?:/|~/)[A-Za-z0-9_./~-]+$")
_SAFE_REQUEST_ID: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_OPERATIONS: Final[frozenset[str]] = frozenset(
    {"health", "preflight", "deploy", "submit", "status", "resume", "abandon"}
)
_MAX_REQUEST_BYTES: Final[int] = 64 * 1024 * 1024
_MAX_RESPONSE_BYTES: Final[int] = 1024 * 1024
_MAX_STDERR_BYTES: Final[int] = 4096
_DEFAULT_TIMEOUT_SECONDS: Final[float] = 300.0
_HOST_KEY_MARKERS: Final[tuple[str, ...]] = (
    "host key verification failed",
    "remote host identification has changed",
    "host identification has changed",
    "host key is not cached",
)
_AUTH_MARKERS: Final[tuple[str, ...]] = (
    "permission denied",
    "authentication failed",
    "too many authentication failures",
)


class ExecutionSubprocessRunner(Protocol):
    """Test seam matching the safe subset of ``subprocess.run``."""

    def __call__(
        self,
        args: Sequence[str],
        *,
        input: str,
        text: bool,
        capture_output: bool,
        timeout: float,
        check: bool,
        shell: bool,
    ) -> subprocess.CompletedProcess[str]:
        """Run one fixed invocation."""


class OpenSSHExecutionClient:
    """Invoke only the reviewed ``bioexec.pyz`` JSONL service over OpenSSH."""

    def __init__(
        self,
        *,
        runner: ExecutionSubprocessRunner | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        max_request_bytes: int = _MAX_REQUEST_BYTES,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
        max_stderr_bytes: int = _MAX_STDERR_BYTES,
    ) -> None:
        if not 0 < timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be between 0 and 3600")
        for name, value, upper in (
            ("max_request_bytes", max_request_bytes, _MAX_REQUEST_BYTES),
            ("max_response_bytes", max_response_bytes, 16 * 1024 * 1024),
            ("max_stderr_bytes", max_stderr_bytes, 1024 * 1024),
        ):
            if not 1 <= value <= upper:
                raise ValueError(f"{name} is outside its supported range")
        self._runner = runner
        self._timeout_seconds = timeout_seconds
        self._max_request_bytes = max_request_bytes
        self._max_response_bytes = max_response_bytes
        self._max_stderr_bytes = max_stderr_bytes

    def invoke(
        self,
        source: SourceProfile,
        *,
        agent_path: str,
        operation: ExecutionOperation,
        payload: Mapping[str, Any],
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Send one internally constructed operation and return its validated result."""

        if operation not in _OPERATIONS:
            raise ValueError("unsupported execution operation")
        selected_id = request_id or f"exec-{uuid4().hex}"
        if not _SAFE_REQUEST_ID.fullmatch(selected_id):
            raise ValueError("request_id is not a safe identifier")
        request = {
            "protocol_version": "1.0",
            "request_id": selected_id,
            "operation": operation,
            "payload": dict(payload),
        }
        try:
            encoded = (
                json.dumps(
                    request,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise BioPipeError(
                ErrorCode.REMOTE_EXECUTION_PROTOCOL_ERROR,
                "The fixed execution request could not be serialized.",
                context={"operation": operation},
            ) from exc
        if len(encoded.encode("ascii")) > self._max_request_bytes:
            raise BioPipeError(
                ErrorCode.DEPLOYMENT_FAILED
                if operation == "deploy"
                else ErrorCode.REMOTE_EXECUTION_PROTOCOL_ERROR,
                "The fixed execution request exceeds its size limit.",
                context={"operation": operation, "limit_bytes": self._max_request_bytes},
                remediation=["Reduce the generated project bundle and retry."],
            )

        arguments = self.build_argv(source, agent_path)
        try:
            if self._runner is None:
                completed = run_bounded(
                    arguments,
                    input_text=encoded,
                    timeout=self._timeout_seconds,
                    stdout_limit=self._max_response_bytes,
                    stderr_limit=self._max_stderr_bytes,
                )
            else:
                completed = self._runner(
                    arguments,
                    input=encoded,
                    text=True,
                    capture_output=True,
                    timeout=self._timeout_seconds,
                    check=False,
                    shell=False,
                )
        except subprocess.TimeoutExpired as exc:
            raise BioPipeError(
                ErrorCode.SSH_TIMEOUT,
                "The remote execution request exceeded its timeout.",
                context={"source_id": source.source_id, "operation": operation},
                remediation=["Check the execution host and query status before retrying."],
            ) from exc
        except FileNotFoundError as exc:
            raise BioPipeError(
                ErrorCode.SSH_CLIENT_NOT_FOUND,
                "The system OpenSSH client was not found.",
                context={"source_id": source.source_id},
            ) from exc
        except OSError as exc:
            context: dict[str, object] = {"source_id": source.source_id, "operation": operation}
            if exc.errno is not None:
                context["errno"] = exc.errno
            raise BioPipeError(
                ErrorCode.SSH_EXECUTION_FAILED,
                "The fixed OpenSSH execution transport could not start.",
                context=context,
            ) from exc

        stdout = _captured_text(completed.stdout)
        stderr = _captured_text(completed.stderr)
        if len(stdout.encode("utf-8")) > self._max_response_bytes:
            raise BioPipeError(
                ErrorCode.SSH_OUTPUT_LIMIT_EXCEEDED,
                "The remote execution response exceeded its size limit.",
                context={"source_id": source.source_id, "operation": operation},
            )
        response = _parse_response(stdout, selected_id)
        if response is not None:
            remote_return_code = response["return_code"]
            if completed.returncode != remote_return_code:
                raise _protocol_error(operation)
            if not response["success"]:
                error = response["error"]
                assert isinstance(error, dict)
                code = _operation_error_code(operation, str(error["code"]))
                raise BioPipeError(
                    code,
                    "The remote execution agent rejected the fixed request.",
                    context={
                        "source_id": source.source_id,
                        "operation": operation,
                        "remote_code": str(error["code"]),
                        "return_code": remote_return_code,
                    },
                    remediation=["Review the execution profile and the stable remote error code."],
                )
            result = response["result"]
            assert isinstance(result, dict)
            return result

        if completed.returncode != 0:
            lowered = stderr.casefold()
            if any(marker in lowered for marker in _HOST_KEY_MARKERS):
                code = ErrorCode.SSH_HOST_KEY_MISMATCH
                message = "Strict SSH host-key verification failed."
            elif any(marker in lowered for marker in _AUTH_MARKERS):
                code = ErrorCode.SSH_AUTH_FAILED
                message = "SSH authentication failed for the execution host."
            else:
                code = ErrorCode.SSH_CONNECTION_FAILED
                message = "The fixed SSH execution request failed."
            raise BioPipeError(
                code,
                message,
                context={
                    "source_id": source.source_id,
                    "operation": operation,
                    "return_code": completed.returncode,
                },
            )
        raise _protocol_error(operation)

    @staticmethod
    def build_argv(source: SourceProfile, agent_path: str) -> list[str]:
        """Build the only permitted remote command vector."""

        safe_path = _safe_agent_path(agent_path)
        arguments = [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "StrictHostKeyChecking=yes",
        ]
        if source.port is not None:
            arguments.extend(["-p", str(source.port)])
        if source.username is not None:
            arguments.extend(["-l", source.username])
        arguments.extend(["--", source.ssh_alias, safe_path])
        return arguments


def _safe_agent_path(value: str) -> str:
    if not _SAFE_REMOTE_PATH.fullmatch(value):
        raise ValueError("bioexec path is not a safe fixed remote executable path")
    relative = value.removeprefix("~")
    if ".." in PurePosixPath(relative).parts:
        raise ValueError("bioexec path must not contain parent traversal")
    return value


def _parse_response(stdout: str, request_id: str) -> dict[str, Any] | None:
    lines = stdout.splitlines()
    if len(lines) != 1:
        return None
    try:
        payload = json.loads(
            lines[0],
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(payload, dict) or set(payload) != {
        "protocol_version",
        "request_id",
        "success",
        "return_code",
        "result",
        "error",
    }:
        return None
    if payload["protocol_version"] != "1.0" or payload["request_id"] != request_id:
        return None
    if type(payload["success"]) is not bool or type(payload["return_code"]) is not int:
        return None
    if not 0 <= payload["return_code"] <= 255:
        return None
    if payload["success"]:
        if payload["return_code"] != 0 or not isinstance(payload["result"], dict):
            return None
        if payload["error"] is not None:
            return None
    else:
        error = payload["error"]
        if payload["return_code"] == 0 or payload["result"] is not None:
            return None
        if not isinstance(error, dict) or set(error) != {
            "code",
            "message",
            "context",
            "remediation",
        }:
            return None
        if not isinstance(error["code"], str) or not _SAFE_REQUEST_ID.fullmatch(error["code"]):
            return None
        if not isinstance(error["message"], str):
            return None
        if not isinstance(error["context"], dict) or not isinstance(error["remediation"], list):
            return None
    return payload


def _operation_error_code(operation: str, remote_code: str) -> ErrorCode:
    if remote_code == "OUTPUT_ALREADY_EXISTS":
        return ErrorCode.OUTPUT_ALREADY_EXISTS
    if remote_code == "RESUME_INCOMPATIBLE":
        return ErrorCode.RESUME_INCOMPATIBLE
    return {
        "preflight": ErrorCode.PREFLIGHT_FAILED,
        "deploy": ErrorCode.DEPLOYMENT_FAILED,
        "submit": ErrorCode.RUN_SUBMISSION_FAILED,
        "resume": ErrorCode.RUN_SUBMISSION_FAILED,
        "status": ErrorCode.RUN_STATUS_FAILED,
        "abandon": ErrorCode.RUN_STATUS_FAILED,
        "health": ErrorCode.REMOTE_EXECUTION_PROTOCOL_ERROR,
    }[operation]


def _protocol_error(operation: str) -> BioPipeError:
    return BioPipeError(
        ErrorCode.REMOTE_EXECUTION_PROTOCOL_ERROR,
        "The remote execution agent returned an invalid response.",
        context={"operation": operation},
        remediation=["Install the reviewed bioexec.pyz version and retry."],
    )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _captured_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


__all__ = ["ExecutionOperation", "OpenSSHExecutionClient"]
