"""Mocked integration tests for Controller-to-OpenSSH request transport."""

from __future__ import annotations

import json
import subprocess
from pathlib import PurePosixPath
from typing import Any
from unittest.mock import Mock

from biopipe.models import ProbeRequest, SourceProfile
from biopipe.probe import OpenSSHProbeClient


def _source_profile() -> SourceProfile:
    return SourceProfile(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        allowed_roots=["/srv/synthetic-raw"],
    )


def _successful_stdout(request_id: str, result: dict[str, Any]) -> str:
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


def _budgets(
    *,
    max_depth: int = 6,
    max_entries: int = 100_000,
    max_runtime_seconds: float = 300.0,
) -> dict[str, int | float]:
    return {
        "max_depth": max_depth,
        "max_entries": max_entries,
        "max_runtime_seconds": max_runtime_seconds,
    }


def _tree_result(root: str) -> dict[str, Any]:
    return {
        "operation": "list_tree",
        "root": root,
        "entries": [],
        "entry_count": 0,
        "max_depth_observed": 0,
        "budgets": _budgets(),
    }


def _file_metadata(path: str, root: str) -> dict[str, Any]:
    absolute = PurePosixPath(path)
    relative = absolute.relative_to(PurePosixPath(root))
    return {
        "path": path,
        "relative_path": str(relative),
        "name": absolute.name,
        "kind": "file",
        "size_bytes": 0,
        "mtime_ns": 0,
        "mode": "0644",
        "depth": len(relative.parts),
    }


def _stat_result(
    root: str,
    paths: list[str],
    *,
    budgets: dict[str, int | float] | None = None,
) -> dict[str, Any]:
    files = [_file_metadata(path, root) for path in paths]
    return {
        "operation": "stat_files",
        "root": root,
        "files": files,
        "file_count": len(files),
        "budgets": budgets or _budgets(),
    }


def test_probe_request_is_jsonl_stdin_not_ssh_argv() -> None:
    sensitive_root = "/srv/synthetic-raw/project with spaces"
    request = ProbeRequest(
        request_id="tree-001",
        operation="list_tree",
        root=sensitive_root,
        policy={"inspection_level": "metadata_only"},
    )
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=_successful_stdout("tree-001", _tree_result(sensitive_root)),
            stderr="",
        )
    )

    response = OpenSSHProbeClient(runner=runner).invoke(_source_profile(), request)

    assert response.success is True
    runner.assert_called_once()
    call = runner.call_args
    argv = list(call.args[0])
    assert argv[:2] == ["ssh", "-T"]
    assert "BatchMode=yes" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert argv[-3:] == ["--", "synthetic-host", "~/.local/bin/bioprobe.pyz"]
    assert sensitive_root not in argv
    assert all("project with spaces" not in argument for argument in argv)

    sent_request = json.loads(call.kwargs["input"])
    assert sent_request["root"] == sensitive_root
    assert call.kwargs["input"].endswith("\n")
    assert call.kwargs["text"] is True
    assert call.kwargs["capture_output"] is True
    assert call.kwargs["check"] is False
    assert call.kwargs["shell"] is False
    assert call.kwargs["timeout"] == 300


def test_stat_file_paths_are_transported_only_in_stdin() -> None:
    paths = [
        "/srv/synthetic-raw/$(touch CONTROLLER_PWNED)",
        "/srv/synthetic-raw/semicolon;name.fastq.gz",
    ]
    request = ProbeRequest(
        request_id="stat-001",
        operation="stat_files",
        root="/srv/synthetic-raw",
        paths=paths,
    )
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=_successful_stdout(
                "stat-001",
                _stat_result("/srv/synthetic-raw", paths),
            ),
            stderr="",
        )
    )

    OpenSSHProbeClient(runner=runner).invoke(_source_profile(), request)

    call = runner.call_args
    argv = list(call.args[0])
    assert all(path not in argv for path in paths)
    assert json.loads(call.kwargs["input"])["paths"] == paths
    assert call.kwargs["shell"] is False


def test_stat_files_helper_forces_bounded_metadata_only_policy() -> None:
    source = SourceProfile(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        allowed_roots=["/srv/synthetic-raw"],
        probe={
            "max_depth": 3,
            "max_entries": 17,
            "max_runtime_seconds": 9,
        },
    )
    paths = ["/srv/synthetic-raw/a.fastq.gz", "/srv/synthetic-raw/b.fastq.gz"]
    runner = Mock(
        return_value=subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=_successful_stdout(
                "stat-helper-001",
                _stat_result(
                    "/srv/synthetic-raw",
                    paths,
                    budgets=_budgets(
                        max_depth=3,
                        max_entries=17,
                        max_runtime_seconds=9.0,
                    ),
                ),
            ),
            stderr="",
        )
    )
    client = OpenSSHProbeClient(runner=runner)

    response = client.stat_files(
        source,
        "/srv/synthetic-raw",
        paths,
        request_id="stat-helper-001",
    )

    assert response.success is True
    call = runner.call_args
    request = json.loads(call.kwargs["input"])
    assert request["operation"] == "stat_files"
    assert request["paths"] == paths
    assert request["policy"]["inspection_level"] == "metadata_only"
    assert request["policy"]["max_depth"] == 3
    assert request["policy"]["max_entries"] == 17
    assert request["policy"]["max_runtime_seconds"] == 9
    assert request["policy"]["sample_fastq_records"] == 0
    assert request["policy"]["return_sequences"] is False
    assert request["policy"]["return_qualities"] is False
    assert request["policy"]["return_read_names"] is False
