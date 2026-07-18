"""Constrained OpenSSH transport for the fixed remote probe protocol."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Sequence
from pathlib import PurePosixPath
from typing import Any, Final, Protocol
from uuid import uuid4

from pydantic import ValidationError

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.models import ProbePolicy, ProbeRequest, ProbeResponse, SourceProfile
from biopipe.probe.bounded import run_bounded
from biopipe.probe.results import (
    HealthResult,
    ProbeResultValidationError,
    validate_success_result,
)

ProbeClientErrorCode = ErrorCode

_SAFE_REMOTE_PATH: Final[re.Pattern[str]] = re.compile(r"^(?:/|~/)[A-Za-z0-9_./~-]+$")
_PEM_BLOCK: Final[re.Pattern[str]] = re.compile(
    r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?"
    r"(?:-----END [^-\r\n]*PRIVATE KEY-----|\Z)",
    flags=re.IGNORECASE | re.DOTALL,
)
_TRUNCATED_PEM_HEADER: Final[re.Pattern[str]] = re.compile(
    r"-----BEGIN[^\r\n]*\Z",
    flags=re.IGNORECASE,
)
_SECRET_ASSIGNMENT: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(password|passwd|passphrase|token|secret|private[_ -]?key|authorization)"
    r"(\s*[:=]\s*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
_AUTHORIZATION_VALUE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b((?:proxy-)?authorization)(\s*[:=]\s*)[^\r\n]*"
)
_BEARER_TOKEN: Final[re.Pattern[str]] = re.compile(r"(?i)\bbearer\s+[^\s,;]+")

_HOST_KEY_MARKERS: Final[tuple[str, ...]] = (
    "host key verification failed",
    "remote host identification has changed",
    "host identification has changed",
    "offending ecdsa key",
    "offending ed25519 key",
    "offending rsa key",
    "host key is known and you have requested strict checking",
    "host key is not cached",
)
_AUTH_MARKERS: Final[tuple[str, ...]] = (
    "permission denied",
    "authentication failed",
    "no supported authentication methods",
    "too many authentication failures",
)
_CONNECTION_MARKERS: Final[tuple[str, ...]] = (
    "connection refused",
    "connection timed out",
    "operation timed out",
    "could not resolve hostname",
    "name or service not known",
    "no route to host",
    "network is unreachable",
    "connection closed",
    "connection reset",
    "kex_exchange_identification",
)
_M1_FAILURE_RETURN_CODES: Final[frozenset[int]] = frozenset(
    {10, 11, 20, 21, 22, 30, 31, 40, 41, 50}
)


class SubprocessRunner(Protocol):
    """Callable boundary used to test the transport without opening a connection."""

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
        """Run the fixed SSH invocation and return its captured result."""


class ProbeClientError(BioPipeError):
    """Base class for a stable controller-side probe failure."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        context: dict[str, object] | None = None,
        remediation: Sequence[str] | None = None,
        response: ProbeResponse | None = None,
    ) -> None:
        super().__init__(code, message, context=context, remediation=remediation)
        self.response = response


class ProbeTransportError(ProbeClientError):
    """OpenSSH could not safely deliver or collect a probe request."""


class ProbeProtocolError(ProbeClientError):
    """The remote stdout did not contain one matching response envelope."""


class RemoteProbeError(ProbeClientError):
    """The probe returned a validated, structured business failure."""


class OpenSSHProbeClient:
    """Invoke one fixed remote probe through the system OpenSSH client.

    User paths are serialized only into the JSONL standard-input payload. The SSH
    argument vector contains fixed options, validated connection fields, and the
    validated probe executable path; no general remote command API is exposed.
    """

    def __init__(
        self,
        *,
        runner: SubprocessRunner | None = None,
        max_stdout_bytes: int | None = None,
        max_stderr_bytes: int | None = None,
    ) -> None:
        self._runner = runner
        self._max_stdout_bytes = _positive_optional_limit(max_stdout_bytes, "max_stdout_bytes")
        self._max_stderr_bytes = _positive_optional_limit(max_stderr_bytes, "max_stderr_bytes")

    def invoke(self, source: SourceProfile, request: ProbeRequest) -> ProbeResponse:
        """Send one request and return its validated successful response.

        Transport failures, invalid protocol output, request-ID mismatches, and
        validated remote failures are represented by distinct ``ProbeClientError``
        subclasses. Error serialization never includes the request's root or paths.
        """

        arguments = self.build_argv(source)
        _validate_request_scope(source, request)
        request_jsonl = request.model_dump_json(exclude_none=False) + "\n"
        _validate_outbound_budget(source, request, request_jsonl)
        sensitive_paths = _request_paths(request)
        stdout_limit = _effective_limit(source.probe.max_response_bytes, self._max_stdout_bytes)
        stderr_limit = _effective_limit(source.probe.stderr_limit_bytes, self._max_stderr_bytes)

        try:
            if self._runner is None:
                completed = run_bounded(
                    arguments,
                    input_text=request_jsonl,
                    timeout=float(source.probe.max_runtime_seconds),
                    stdout_limit=stdout_limit,
                    stderr_limit=stderr_limit,
                )
            else:
                completed = self._runner(
                    arguments,
                    input=request_jsonl,
                    text=True,
                    capture_output=True,
                    timeout=float(source.probe.max_runtime_seconds),
                    check=False,
                    shell=False,
                )
        except subprocess.TimeoutExpired as exc:
            diagnostic = _safe_diagnostic(exc.stderr, stderr_limit, sensitive_paths)
            timeout_context = _error_context(source, diagnostic=diagnostic)
            timeout_context["timeout_seconds"] = source.probe.max_runtime_seconds
            raise ProbeTransportError(
                ErrorCode.SSH_TIMEOUT,
                "The SSH probe request exceeded its configured timeout.",
                context=timeout_context,
                remediation=["Check source connectivity and the configured probe runtime budget."],
            ) from exc
        except FileNotFoundError as exc:
            raise ProbeTransportError(
                ErrorCode.SSH_CLIENT_NOT_FOUND,
                "The system OpenSSH client was not found.",
                context={"source_id": source.source_id},
                remediation=["Install OpenSSH and ensure the ssh executable is on PATH."],
            ) from exc
        except OSError as exc:
            os_context: dict[str, object] = {"source_id": source.source_id}
            if exc.errno is not None:
                os_context["errno"] = exc.errno
            raise ProbeTransportError(
                ErrorCode.SSH_EXECUTION_FAILED,
                "The system OpenSSH client could not be started.",
                context=os_context,
                remediation=["Check the local OpenSSH installation and permissions."],
            ) from exc

        stdout = _captured_text(completed.stdout)
        stderr = _captured_text(completed.stderr)
        diagnostic = _safe_diagnostic(stderr, stderr_limit, sensitive_paths)
        if _utf8_size(stdout) > stdout_limit:
            raise ProbeTransportError(
                ErrorCode.SSH_OUTPUT_LIMIT_EXCEEDED,
                "The remote probe response exceeded its configured size limit.",
                context=_error_context(
                    source,
                    return_code=completed.returncode,
                    diagnostic=diagnostic,
                    extra={"limit_bytes": stdout_limit},
                ),
                remediation=["Reduce the scan budget or inspect a narrower directory."],
            )

        response = self._parse_response(
            source,
            request,
            stdout,
            return_code=completed.returncode,
            diagnostic=diagnostic,
        )
        if response is not None:
            if completed.returncode != response.return_code:
                raise ProbeProtocolError(
                    ErrorCode.PROBE_PROTOCOL_ERROR,
                    "The probe envelope conflicts with the process return code.",
                    context=_error_context(
                        source,
                        return_code=completed.returncode,
                        diagnostic=diagnostic,
                        extra={"envelope_return_code": response.return_code},
                    ),
                    remediation=["Verify that the installed remote probe is compatible."],
                )
            if not response.success:
                assert response.error is not None
                if (
                    response.result is not None
                    or response.return_code not in _M1_FAILURE_RETURN_CODES
                ):
                    raise ProbeProtocolError(
                        ErrorCode.PROBE_PROTOCOL_ERROR,
                        "The failed probe envelope violates the fixed M1 protocol.",
                        context=_error_context(
                            source,
                            return_code=completed.returncode,
                            diagnostic=diagnostic,
                        ),
                        remediation=["Verify that the installed remote probe is compatible."],
                    )
                remote_message = _redact_text(response.error.message, sensitive_paths)
                remote_remediation = [
                    _redact_text(item, sensitive_paths) for item in response.error.remediation
                ]
                raise RemoteProbeError(
                    ErrorCode.PROBE_REMOTE_FAILED,
                    remote_message or "The remote probe rejected the request.",
                    context={
                        "source_id": source.source_id,
                        "probe_code": response.error.code,
                        "return_code": response.return_code,
                    },
                    remediation=remote_remediation,
                    response=response,
                )
            try:
                validated_result = validate_success_result(source, request, response.result)
            except ProbeResultValidationError as exc:
                raise ProbeProtocolError(
                    ErrorCode.PROBE_PROTOCOL_ERROR,
                    "The probe success result violates its fixed metadata contract.",
                    context=_error_context(
                        source,
                        return_code=completed.returncode,
                        diagnostic=diagnostic,
                    ),
                    remediation=["Verify that the installed remote probe is compatible."],
                ) from exc
            response.result = validated_result.model_dump(mode="json")
            return response

        if completed.returncode != 0:
            raise _transport_failure(
                source,
                completed.returncode,
                stderr,
                diagnostic,
            )
        raise ProbeProtocolError(
            ErrorCode.PROBE_PROTOCOL_ERROR,
            "The remote probe did not return one valid JSONL response.",
            context=_error_context(source, diagnostic=diagnostic),
            remediation=["Verify that the installed remote probe is compatible."],
        )

    def build_argv(self, source: SourceProfile) -> list[str]:
        """Build the complete fixed SSH argument vector for *source*."""

        alias = _safe_connection_argument(source.ssh_alias, "ssh_alias")
        remote_path = _safe_probe_path(source.probe.remote_path)
        arguments = [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
        ]
        if source.port is not None:
            arguments.extend(["-p", str(source.port)])
        if source.username is not None:
            arguments.extend(["-l", _safe_connection_argument(source.username, "username")])
        arguments.extend(["--", alias, remote_path])
        return arguments

    def verify(
        self,
        source: SourceProfile,
        *,
        request_id: str | None = None,
    ) -> ProbeResponse:
        """Verify SSH connectivity and fixed-probe health."""

        request = ProbeRequest(
            request_id=request_id or _request_id("verify"),
            operation="health",
            policy=_metadata_policy(source),
        )
        response = self.invoke(source, request)
        health = HealthResult.model_validate(response.result)
        if not health.configuration.configured:
            raise RemoteProbeError(
                ErrorCode.PROBE_REMOTE_FAILED,
                "The remote probe has no configured allowed roots.",
                context={
                    "source_id": source.source_id,
                    "probe_code": "PROBE_NOT_CONFIGURED",
                    "return_code": response.return_code,
                },
                remediation=[
                    "Install a probe configuration with at least one reviewed allowed root."
                ],
                response=response,
            )
        return response

    def list_tree(
        self,
        source: SourceProfile,
        root: str,
        *,
        request_id: str | None = None,
    ) -> ProbeResponse:
        """Request a bounded metadata-only directory listing."""

        request = ProbeRequest(
            request_id=request_id or _request_id("list-tree"),
            operation="list_tree",
            root=root,
            policy=_metadata_policy(source),
        )
        return self.invoke(source, request)

    def stat_files(
        self,
        source: SourceProfile,
        root: str,
        paths: Sequence[str],
        *,
        request_id: str | None = None,
    ) -> ProbeResponse:
        """Request metadata for an explicit bounded set of remote file paths."""

        request = ProbeRequest(
            request_id=request_id or _request_id("stat-files"),
            operation="stat_files",
            root=root,
            paths=list(paths),
            policy=_metadata_policy(source),
        )
        return self.invoke(source, request)

    @staticmethod
    def _parse_response(
        source: SourceProfile,
        request: ProbeRequest,
        stdout: str,
        *,
        return_code: int,
        diagnostic: str,
    ) -> ProbeResponse | None:
        lines = [line for line in stdout.splitlines() if line.strip()]
        if len(lines) != 1:
            return None
        try:
            payload = json.loads(
                lines[0],
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
            response = ProbeResponse.model_validate(payload)
        except (json.JSONDecodeError, ValidationError, ValueError, TypeError, RecursionError):
            return None
        if response.request_id != request.request_id:
            raise ProbeProtocolError(
                ErrorCode.PROBE_REQUEST_MISMATCH,
                "The remote probe response does not match the request identifier.",
                context=_error_context(
                    source,
                    return_code=return_code,
                    diagnostic=diagnostic,
                ),
                remediation=["Retry the request and verify the installed probe version."],
            )
        return response


def verify(
    source: SourceProfile,
    *,
    client: OpenSSHProbeClient | None = None,
    request_id: str | None = None,
) -> ProbeResponse:
    """Verify *source* using a constrained OpenSSH probe client."""

    return (client or OpenSSHProbeClient()).verify(source, request_id=request_id)


def list_tree(
    source: SourceProfile,
    root: str,
    *,
    client: OpenSSHProbeClient | None = None,
    request_id: str | None = None,
) -> ProbeResponse:
    """Return a bounded metadata-only tree response for *root*."""

    return (client or OpenSSHProbeClient()).list_tree(source, root, request_id=request_id)


def stat_files(
    source: SourceProfile,
    root: str,
    paths: Sequence[str],
    *,
    client: OpenSSHProbeClient | None = None,
    request_id: str | None = None,
) -> ProbeResponse:
    """Return metadata for explicit remote *paths* under *root*."""

    return (client or OpenSSHProbeClient()).stat_files(
        source,
        root,
        paths,
        request_id=request_id,
    )


def _positive_optional_limit(value: int | None, field_name: str) -> int | None:
    if value is not None and value < 1:
        raise ValueError(f"{field_name} must be positive")
    return value


def _effective_limit(profile_limit: int, override: int | None) -> int:
    return profile_limit if override is None else min(profile_limit, override)


def _captured_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _utf8_size(value: str) -> int:
    return len(value.encode("utf-8", errors="replace"))


def _safe_connection_argument(value: str, field_name: str) -> str:
    if (
        not value
        or value.startswith("-")
        or any(
            character.isspace() or ord(character) < 32 or ord(character) == 127
            for character in value
        )
    ):
        raise ProbeClientError(
            ErrorCode.VALIDATION_FAILED,
            f"The configured {field_name} is not a safe SSH argument.",
            context={"field": field_name},
        )
    return value


def _safe_probe_path(value: str) -> str:
    path_without_home = value.removeprefix("~")
    if not _SAFE_REMOTE_PATH.fullmatch(value) or ".." in PurePosixPath(path_without_home).parts:
        raise ProbeClientError(
            ErrorCode.VALIDATION_FAILED,
            "The configured remote probe path is unsafe.",
            context={"field": "probe.remote_path"},
            remediation=["Use one absolute path or a path beginning with ~/ only."],
        )
    return value


def _metadata_policy(source: SourceProfile) -> ProbePolicy:
    return ProbePolicy(
        inspection_level="metadata_only",
        max_depth=source.probe.max_depth,
        max_entries=source.probe.max_entries,
        max_runtime_seconds=source.probe.max_runtime_seconds,
        follow_symlinks=source.probe.follow_symlinks,
        sample_fastq_records=0,
        return_sequences=False,
        return_qualities=False,
        return_read_names=False,
    )


def _validate_outbound_budget(
    source: SourceProfile,
    request: ProbeRequest,
    request_jsonl: str,
) -> None:
    if len(request.paths) > source.probe.max_paths:
        raise ProbeClientError(
            ErrorCode.VALIDATION_FAILED,
            "The probe request contains too many paths.",
            context={
                "source_id": source.source_id,
                "path_count": len(request.paths),
                "limit": source.probe.max_paths,
            },
            remediation=["Split the metadata request into smaller batches."],
        )
    request_size = _utf8_size(request_jsonl)
    if request_size > source.probe.max_request_bytes:
        raise ProbeClientError(
            ErrorCode.VALIDATION_FAILED,
            "The serialized probe request exceeds its configured size limit.",
            context={
                "source_id": source.source_id,
                "request_bytes": request_size,
                "limit_bytes": source.probe.max_request_bytes,
            },
            remediation=["Split the metadata request into smaller batches."],
        )


def _validate_request_scope(source: SourceProfile, request: ProbeRequest) -> None:
    """Apply the SourceProfile's lexical allowlist before contacting SSH.

    The Remote Probe remains authoritative because only it can canonicalize a
    remote filesystem path. This controller-side check prevents requests that
    are plainly outside the reviewed profile from crossing the trust boundary.
    """

    allowed_roots = tuple(PurePosixPath(root) for root in source.allowed_roots)
    request_paths = ([request.root] if request.root is not None else []) + request.paths
    for index, value in enumerate(request_paths):
        assert value is not None
        candidate = PurePosixPath(value)
        if not any(_is_posix_relative_to(candidate, root) for root in allowed_roots):
            raise ProbeClientError(
                ErrorCode.VALIDATION_FAILED,
                "The requested remote path is outside the SourceProfile allowlist.",
                context={"source_id": source.source_id, "path_index": index},
                remediation=["Choose a path below one of the reviewed allowed roots."],
            )

    if request.root is not None and request.paths:
        request_root = PurePosixPath(request.root)
        for index, value in enumerate(request.paths):
            if not _is_posix_relative_to(PurePosixPath(value), request_root):
                raise ProbeClientError(
                    ErrorCode.VALIDATION_FAILED,
                    "A stat_files path is outside the requested root.",
                    context={"source_id": source.source_id, "path_index": index},
                    remediation=["Choose paths below the requested root."],
                )


def _is_posix_relative_to(path: PurePosixPath, root: PurePosixPath) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _request_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex}"


def _request_paths(request: ProbeRequest) -> tuple[str, ...]:
    values = ([request.root] if request.root is not None else []) + request.paths
    return tuple(sorted(set(values), key=len, reverse=True))


def _redact_text(text: str, sensitive_paths: Sequence[str]) -> str:
    redacted = _PEM_BLOCK.sub("<redacted-private-key>", text)
    redacted = _TRUNCATED_PEM_HEADER.sub("<redacted-private-key>", redacted)
    redacted = _AUTHORIZATION_VALUE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<redacted>", redacted
    )
    redacted = _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<redacted>", redacted
    )
    redacted = _BEARER_TOKEN.sub("Bearer <redacted>", redacted)
    for path in sensitive_paths:
        if path:
            redacted = redacted.replace(path, "<redacted-path>")
    return redacted


def _bounded_utf8(text: str, limit_bytes: int) -> str:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit_bytes:
        return text
    marker = b"...[truncated]"
    if limit_bytes <= len(marker):
        return marker[:limit_bytes].decode("ascii", errors="ignore")
    prefix = encoded[: limit_bytes - len(marker)].decode("utf-8", errors="ignore")
    return prefix + marker.decode("ascii")


def _safe_diagnostic(
    value: str | bytes | None,
    limit_bytes: int,
    sensitive_paths: Sequence[str],
) -> str:
    text = _captured_text(value)
    return _bounded_utf8(_redact_text(text, sensitive_paths), limit_bytes)


def _error_context(
    source: SourceProfile,
    *,
    return_code: int | None = None,
    diagnostic: str = "",
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    context: dict[str, object] = {"source_id": source.source_id}
    if return_code is not None:
        context["return_code"] = return_code
    if diagnostic:
        context["diagnostic"] = diagnostic
    if extra:
        context.update(extra)
    return context


def _transport_failure(
    source: SourceProfile,
    return_code: int,
    raw_stderr: str,
    diagnostic: str,
) -> ProbeTransportError:
    lowered = raw_stderr.casefold()
    if any(marker in lowered for marker in _HOST_KEY_MARKERS):
        return ProbeTransportError(
            ErrorCode.SSH_HOST_KEY_MISMATCH,
            "SSH host-key verification failed.",
            context=_error_context(source, return_code=return_code, diagnostic=diagnostic),
            remediation=[
                "Verify the host key through a trusted channel and update known_hosts manually."
            ],
        )
    if any(marker in lowered for marker in _AUTH_MARKERS):
        return ProbeTransportError(
            ErrorCode.SSH_AUTH_FAILED,
            "SSH authentication failed in non-interactive mode.",
            context=_error_context(source, return_code=return_code, diagnostic=diagnostic),
            remediation=["Check the SSH alias, agent, account, and BatchMode credentials."],
        )
    if any(marker in lowered for marker in _CONNECTION_MARKERS):
        return ProbeTransportError(
            ErrorCode.SSH_CONNECTION_FAILED,
            "The SSH connection could not be established.",
            context=_error_context(source, return_code=return_code, diagnostic=diagnostic),
            remediation=["Check the SSH alias, network route, and source host availability."],
        )
    return ProbeTransportError(
        ErrorCode.SSH_EXECUTION_FAILED,
        "The fixed remote probe command did not complete successfully.",
        context=_error_context(source, return_code=return_code, diagnostic=diagnostic),
        remediation=["Check the source configuration and remote probe installation."],
    )


__all__ = [
    "OpenSSHProbeClient",
    "ProbeClientError",
    "ProbeClientErrorCode",
    "ProbeProtocolError",
    "ProbeTransportError",
    "RemoteProbeError",
    "SubprocessRunner",
    "list_tree",
    "stat_files",
    "verify",
]
