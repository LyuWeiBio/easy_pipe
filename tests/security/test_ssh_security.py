"""Mocked OpenSSH failure and injection security tests."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from biopipe.models import ProbeConfiguration, ProbeRequest, SourceProfile
from biopipe.probe import OpenSSHProbeClient, ProbeClientError, ProbeClientErrorCode


def _source_profile(**probe_overrides: object) -> SourceProfile:
    probe = {"remote_path": "~/.local/bin/bioprobe.pyz", **probe_overrides}
    return SourceProfile(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        allowed_roots=["/srv/synthetic-raw"],
        probe=probe,
    )


def _health_request() -> ProbeRequest:
    return ProbeRequest(request_id="health-001", operation="health")


def _error_code(error: ProbeClientError) -> str:
    code = error.code
    return code.value if hasattr(code, "value") else str(code)


def test_ssh_timeout_has_stable_error_code() -> None:
    def timeout_runner(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd=["ssh"], timeout=1)

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=timeout_runner).invoke(
            _source_profile(max_runtime_seconds=1),
            _health_request(),
        )

    assert _error_code(exc_info.value) == ProbeClientErrorCode.SSH_TIMEOUT.value


def test_host_key_mismatch_has_distinct_error_code() -> None:
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=255,
            stdout="",
            stderr=(
                "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\nHost key verification failed.\n"
            ),
        )
    )

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=runner).invoke(_source_profile(), _health_request())

    assert _error_code(exc_info.value) == ProbeClientErrorCode.SSH_HOST_KEY_MISMATCH.value


@pytest.mark.parametrize(
    ("stderr", "expected_code"),
    [
        ("Permission denied (publickey).", "SSH_AUTH_FAILED"),
        ("ssh: Could not resolve hostname synthetic-host", "SSH_CONNECTION_FAILED"),
        ("remote process ended unexpectedly", "SSH_EXECUTION_FAILED"),
    ],
)
def test_nonzero_ssh_failures_have_distinct_error_codes(
    stderr: str,
    expected_code: str,
) -> None:
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=255,
            stdout="",
            stderr=stderr,
        )
    )

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=runner).invoke(_source_profile(), _health_request())

    assert _error_code(exc_info.value) == expected_code


@pytest.mark.parametrize("stdout", ["not-json\n", "", "{}\n{}\n"])
def test_invalid_probe_stdout_is_protocol_error(stdout: str) -> None:
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=stdout,
            stderr="",
        )
    )

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=runner).invoke(_source_profile(), _health_request())

    assert _error_code(exc_info.value) == ProbeClientErrorCode.PROBE_PROTOCOL_ERROR.value


def test_mismatched_response_id_is_protocol_error() -> None:
    stdout = (
        json.dumps(
            {
                "protocol_version": "1.0",
                "request_id": "different-request",
                "success": True,
                "return_code": 0,
                "result": {},
                "error": None,
            }
        )
        + "\n"
    )
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=stdout,
            stderr="",
        )
    )

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=runner).invoke(_source_profile(), _health_request())

    assert _error_code(exc_info.value) == ProbeClientErrorCode.PROBE_REQUEST_MISMATCH.value


def test_failed_probe_response_is_a_structured_remote_error() -> None:
    stdout = (
        json.dumps(
            {
                "protocol_version": "1.0",
                "request_id": "health-001",
                "success": False,
                "return_code": 20,
                "result": None,
                "error": {
                    "code": "PATH_OUTSIDE_ALLOWLIST",
                    "message": "Synthetic remote rejection.",
                    "context": {"sequence": "ACGTSENSITIVE"},
                    "remediation": ["Quality IIIISENSITIVE"],
                },
            }
        )
        + "\n"
    )
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=20,
            stdout=stdout,
            stderr="",
        )
    )

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=runner).invoke(_source_profile(), _health_request())

    assert _error_code(exc_info.value) == ProbeClientErrorCode.PROBE_REMOTE_FAILED.value
    assert exc_info.value.response is not None
    assert exc_info.value.response.return_code == 20
    serialized = exc_info.value.to_json() + exc_info.value.response.model_dump_json()
    assert "Synthetic remote rejection" not in serialized
    assert "ACGTSENSITIVE" not in serialized
    assert "IIIISENSITIVE" not in serialized
    assert "PATH_OUTSIDE_ALLOWLIST" in serialized


def test_unknown_remote_failure_code_is_a_protocol_error() -> None:
    stdout = (
        json.dumps(
            {
                "protocol_version": "1.0",
                "request_id": "health-001",
                "success": False,
                "return_code": 20,
                "result": None,
                "error": {
                    "code": "PATH_OUTSIDE_ALLOWED_ROOT",
                    "message": "Untrusted text.",
                    "context": {},
                    "remediation": [],
                },
            }
        )
        + "\n"
    )
    runner = Mock(
        return_value=subprocess.CompletedProcess(args=[], returncode=20, stdout=stdout, stderr="")
    )

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=runner).invoke(_source_profile(), _health_request())

    assert _error_code(exc_info.value) == ProbeClientErrorCode.PROBE_PROTOCOL_ERROR.value


@pytest.mark.parametrize("process_return_code", [0, 50, 255])
def test_probe_envelope_and_process_return_code_must_match(
    process_return_code: int,
) -> None:
    stdout = (
        json.dumps(
            {
                "protocol_version": "1.0",
                "request_id": "health-001",
                "success": False,
                "return_code": 20,
                "result": None,
                "error": {
                    "code": "PATH_OUTSIDE_ALLOWLIST",
                    "message": "Synthetic remote rejection.",
                    "context": {},
                    "remediation": [],
                },
            }
        )
        + "\n"
    )
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=process_return_code,
            stdout=stdout,
            stderr="",
        )
    )

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=runner).invoke(_source_profile(), _health_request())

    assert _error_code(exc_info.value) == ProbeClientErrorCode.PROBE_PROTOCOL_ERROR.value


def test_oversized_probe_stdout_is_rejected_before_json_parsing() -> None:
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="x" * 2048,
            stderr="",
        )
    )
    client = OpenSSHProbeClient(runner=runner, max_stdout_bytes=1024)

    with pytest.raises(ProbeClientError) as exc_info:
        client.invoke(_source_profile(), _health_request())

    assert _error_code(exc_info.value) == ProbeClientErrorCode.SSH_OUTPUT_LIMIT_EXCEEDED.value


def test_stderr_is_bounded_and_redacts_paths_and_secrets() -> None:
    sensitive_root = "/srv/synthetic-raw/private-project"
    stderr = (
        f"failed while reading {sensitive_root} password=hunter2 token=secret-token {'x' * 1024}"
    )
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=255,
            stdout="",
            stderr=stderr,
        )
    )
    request = ProbeRequest(
        request_id="tree-001",
        operation="list_tree",
        root=sensitive_root,
    )

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=runner, max_stderr_bytes=128).invoke(
            _source_profile(),
            request,
        )

    serialized_error = exc_info.value.to_json()
    diagnostic = str(exc_info.value.context["diagnostic"])
    assert sensitive_root not in serialized_error
    assert "hunter2" not in serialized_error
    assert "secret-token" not in serialized_error
    assert "<redacted-path>" in diagnostic
    assert len(diagnostic.encode("utf-8")) <= 128


def test_truncated_private_key_block_is_fully_redacted() -> None:
    stderr = (
        "diagnostic prefix\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAA synthetic key material"
    )
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=255,
            stdout="",
            stderr=stderr,
        )
    )

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=runner).invoke(_source_profile(), _health_request())

    serialized_error = exc_info.value.to_json()
    assert "BEGIN OPENSSH PRIVATE KEY" not in serialized_error
    assert "b3BlbnNzaC1rZXktdjE" not in serialized_error
    assert "<redacted-private-key>" in serialized_error


@pytest.mark.parametrize("header", ["Authorization", "Proxy-Authorization"])
def test_authorization_header_redacts_scheme_and_credential(header: str) -> None:
    credential = "dXNlcjpwYXNz"
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=255,
            stdout="",
            stderr=f"{header}: Basic {credential}\n",
        )
    )

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=runner).invoke(_source_profile(), _health_request())

    serialized_error = exc_info.value.to_json()
    assert "Basic" not in serialized_error
    assert credential not in serialized_error
    assert "<redacted>" in serialized_error


@pytest.mark.parametrize(
    "remote_path",
    [
        "~/.local/bin/bioprobe.pyz --help",
        "~/.local/bin/bioprobe.pyz;touch PWNED",
        "~/../tmp/bioprobe.pyz",
        "--proxy-command",
    ],
)
def test_remote_probe_path_cannot_inject_ssh_arguments(remote_path: str) -> None:
    with pytest.raises(ValidationError):
        SourceProfile(
            source_id="synthetic-source",
            ssh_alias="synthetic-host",
            allowed_roots=["/srv/synthetic-raw"],
            probe={"remote_path": remote_path},
        )


def test_client_defensively_rejects_injected_model_construct_probe_path() -> None:
    unsafe_probe = ProbeConfiguration.model_construct(
        remote_path="~/.local/bin/bioprobe.pyz --proxy-command",
    )
    unsafe_source = SourceProfile.model_construct(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        username=None,
        port=None,
        probe=unsafe_probe,
    )

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=Mock()).invoke(unsafe_source, _health_request())

    assert _error_code(exc_info.value) == ProbeClientErrorCode.VALIDATION_FAILED.value


def test_controller_rejects_path_outside_profile_before_ssh() -> None:
    runner = Mock()
    request = ProbeRequest(
        request_id="tree-outside-001",
        operation="list_tree",
        root="/srv/other-data",
    )

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=runner).invoke(_source_profile(), request)

    assert _error_code(exc_info.value) == ProbeClientErrorCode.VALIDATION_FAILED.value
    assert "/srv/other-data" not in exc_info.value.to_json()
    runner.assert_not_called()


def test_controller_rejects_stat_path_outside_request_root_before_ssh() -> None:
    runner = Mock()
    request = ProbeRequest(
        request_id="stat-outside-root-001",
        operation="stat_files",
        root="/srv/synthetic-raw/run-a",
        paths=["/srv/synthetic-raw/run-b/sample.fastq.gz"],
    )

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=runner).invoke(_source_profile(), request)

    assert _error_code(exc_info.value) == ProbeClientErrorCode.VALIDATION_FAILED.value
    assert "sample.fastq.gz" not in exc_info.value.to_json()
    runner.assert_not_called()
