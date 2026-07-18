"""Strict controller validation for successful Remote Probe results."""

from __future__ import annotations

import json
import subprocess
from pathlib import PurePosixPath
from typing import Any
from unittest.mock import Mock

import pytest

from biopipe.models import ProbeRequest, SourceProfile
from biopipe.probe import OpenSSHProbeClient, ProbeClientError, ProbeClientErrorCode

SOURCE_ROOT = "/srv/synthetic-raw"


def _source_profile(**probe_overrides: object) -> SourceProfile:
    return SourceProfile(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        allowed_roots=[SOURCE_ROOT],
        probe=probe_overrides,
    )


def _budgets() -> dict[str, int | float]:
    return {
        "max_depth": 6,
        "max_entries": 100_000,
        "max_runtime_seconds": 300.0,
    }


def _metadata(root: str, relative: str) -> dict[str, Any]:
    path = str(PurePosixPath(root) / relative)
    return {
        "path": path,
        "relative_path": relative,
        "name": PurePosixPath(path).name,
        "kind": "file",
        "size_bytes": 12,
        "mtime_ns": 1_700_000_000_000_000_000,
        "mode": "0644",
        "depth": len(PurePosixPath(relative).parts),
    }


def _tree_result(root: str = SOURCE_ROOT) -> dict[str, Any]:
    entry = _metadata(root, "run-001/sample.fastq.gz")
    return {
        "operation": "list_tree",
        "root": root,
        "entries": [entry],
        "entry_count": 1,
        "max_depth_observed": 2,
        "budgets": _budgets(),
    }


def _stat_result(root: str, relative: str) -> dict[str, Any]:
    return {
        "operation": "stat_files",
        "root": root,
        "files": [_metadata(root, relative)],
        "file_count": 1,
        "budgets": _budgets(),
    }


def _health_result(*, configured: bool) -> dict[str, Any]:
    return {
        "operation": "health",
        "status": "ok",
        "probe_version": "0.1.0",
        "protocol_version": "1.0",
        "capabilities": [
            "detect_formats",
            "health",
            "list_tree",
            "stat_files",
            "summarize_fastq",
        ],
        "configuration": {
            "configured": configured,
            "config_source": "environment" if configured else "none",
            "allowed_root_count": 1 if configured else 0,
            "follow_symlinks": False,
            "allow_mount_crossing": False,
            "limits": {
                **_budgets(),
                "max_request_bytes": 1024 * 1024,
                "max_response_bytes": 10 * 1024 * 1024,
                "max_paths": 10_000,
                "max_path_bytes": 4096,
                "max_sample_records_total": 100_000,
                "max_content_bytes": 268_435_456,
                "max_input_bytes": 268_435_456,
                "max_fastq_line_bytes": 1_048_576,
            },
        },
    }


def _success_stdout(request_id: str, result: dict[str, Any]) -> str:
    return (
        json.dumps(
            {
                "protocol_version": "1.0",
                "request_id": request_id,
                "success": True,
                "return_code": 0,
                "result": result,
                "error": None,
            }
        )
        + "\n"
    )


def _client_for_result(request_id: str, result: dict[str, Any]) -> OpenSSHProbeClient:
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=_success_stdout(request_id, result),
            stderr="",
        )
    )
    return OpenSSHProbeClient(runner=runner)


def _tree_request() -> ProbeRequest:
    return ProbeRequest(
        request_id="tree-001",
        operation="list_tree",
        root=SOURCE_ROOT,
        policy={"inspection_level": "metadata_only"},
    )


def _assert_protocol_rejection(result: dict[str, Any]) -> None:
    with pytest.raises(ProbeClientError) as exc_info:
        _client_for_result("tree-001", result).invoke(_source_profile(), _tree_request())

    assert exc_info.value.code is ProbeClientErrorCode.PROBE_PROTOCOL_ERROR


def _invalid_tree_results() -> list[tuple[str, dict[str, Any]]]:
    cases: list[tuple[str, dict[str, Any]]] = []

    missing = _tree_result()
    missing.pop("budgets")
    cases.append(("missing top-level field", missing))

    unknown = _tree_result()
    unknown["unreviewed"] = "value"
    cases.append(("unknown top-level field", unknown))

    operation = _tree_result()
    operation["operation"] = "stat_files"
    cases.append(("operation mismatch", operation))

    wrong_type = _tree_result()
    wrong_type["entry_count"] = "1"
    cases.append(("wrong count type", wrong_type))

    wrong_count = _tree_result()
    wrong_count["entry_count"] = 0
    cases.append(("count mismatch", wrong_count))

    wrong_root = _tree_result()
    wrong_root["root"] = "/unrelated/root"
    cases.append(("unrelated root", wrong_root))

    excessive_budget = _tree_result()
    excessive_budget["budgets"]["max_entries"] = 100_001
    cases.append(("budget above request", excessive_budget))

    wrong_size = _tree_result()
    wrong_size["entries"][0]["size_bytes"] = "12"
    cases.append(("wrong metadata type", wrong_size))

    outside_path = _tree_result()
    outside_path["entries"][0]["path"] = "/etc/passwd"
    outside_path["entries"][0]["name"] = "passwd"
    outside_path["entries"][0]["relative_path"] = "passwd"
    outside_path["entries"][0]["depth"] = 1
    cases.append(("metadata path outside root", outside_path))

    wrong_relative = _tree_result()
    wrong_relative["entries"][0]["relative_path"] = "other/sample.fastq.gz"
    cases.append(("relative path mismatch", wrong_relative))

    return cases


@pytest.mark.parametrize(
    ("case", "result"),
    _invalid_tree_results(),
    ids=[case for case, _ in _invalid_tree_results()],
)
def test_tree_success_result_rejects_untrusted_shapes(
    case: str,
    result: dict[str, Any],
) -> None:
    assert case
    _assert_protocol_rejection(result)


@pytest.mark.parametrize("payload_key", ["content", "sequence", "quality", "read_name"])
def test_file_metadata_rejects_payload_like_fields(payload_key: str) -> None:
    result = _tree_result()
    result["entries"][0][payload_key] = "SYNTHETIC_RAW_PAYLOAD"

    _assert_protocol_rejection(result)


def test_stat_result_rejects_unknown_file_metadata_field() -> None:
    requested = f"{SOURCE_ROOT}/requested.fastq.gz"
    request = ProbeRequest(
        request_id="stat-001",
        operation="stat_files",
        root=SOURCE_ROOT,
        paths=[requested],
    )
    result = _stat_result(SOURCE_ROOT, "requested.fastq.gz")
    result["files"][0]["raw_content"] = "must not cross trust boundary"

    with pytest.raises(ProbeClientError) as exc_info:
        _client_for_result("stat-001", result).invoke(_source_profile(), request)

    assert exc_info.value.code is ProbeClientErrorCode.PROBE_PROTOCOL_ERROR


def test_stat_result_rejects_unrequested_path() -> None:
    requested = f"{SOURCE_ROOT}/requested.fastq.gz"
    request = ProbeRequest(
        request_id="stat-001",
        operation="stat_files",
        root=SOURCE_ROOT,
        paths=[requested],
    )
    result = _stat_result(SOURCE_ROOT, "different.fastq.gz")

    with pytest.raises(ProbeClientError) as exc_info:
        _client_for_result("stat-001", result).invoke(_source_profile(), request)

    assert exc_info.value.code is ProbeClientErrorCode.PROBE_PROTOCOL_ERROR


def test_canonical_ancestor_prefix_change_is_accepted() -> None:
    canonical_root = "/canonical/mount/synthetic-raw"
    result = _tree_result(canonical_root)

    response = _client_for_result("tree-001", result).invoke(
        _source_profile(),
        _tree_request(),
    )

    assert response.success is True
    assert response.result is not None
    assert response.result["root"] == canonical_root


def test_verify_rejects_health_when_probe_has_no_configured_roots() -> None:
    client = _client_for_result("verify-001", _health_result(configured=False))

    with pytest.raises(ProbeClientError) as exc_info:
        client.verify(_source_profile(), request_id="verify-001")

    assert exc_info.value.code is ProbeClientErrorCode.PROBE_REMOTE_FAILED
    assert exc_info.value.context["probe_code"] == "PROBE_NOT_CONFIGURED"


def test_max_paths_is_rejected_before_injected_runner_call() -> None:
    source = _source_profile(max_paths=1)
    request = ProbeRequest(
        request_id="stat-001",
        operation="stat_files",
        root=SOURCE_ROOT,
        paths=[f"{SOURCE_ROOT}/a", f"{SOURCE_ROOT}/b"],
    )
    runner = Mock()

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=runner).invoke(source, request)

    assert exc_info.value.code is ProbeClientErrorCode.VALIDATION_FAILED
    runner.assert_not_called()


def test_max_request_bytes_is_rejected_before_injected_runner_call() -> None:
    source = _source_profile(max_request_bytes=1024)
    long_path = f"{SOURCE_ROOT}/{'x' * 2000}"
    request = ProbeRequest(
        request_id="stat-001",
        operation="stat_files",
        root=SOURCE_ROOT,
        paths=[long_path],
    )
    runner = Mock()

    with pytest.raises(ProbeClientError) as exc_info:
        OpenSSHProbeClient(runner=runner).invoke(source, request)

    assert exc_info.value.code is ProbeClientErrorCode.VALIDATION_FAILED
    runner.assert_not_called()
