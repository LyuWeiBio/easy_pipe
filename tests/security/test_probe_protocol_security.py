"""Protocol and resource-budget security tests for the Remote Probe."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REMOTE_PROBE_SOURCE = REPOSITORY_ROOT / "remote_probe" / "src"


def test_unknown_operation_is_rejected(
    tmp_path: Path,
    probe_config: Path,
    invoke_probe: Callable[[Path, str, Path], tuple[dict[str, Any], object]],
) -> None:
    request = {
        "protocol_version": "1.0",
        "request_id": "unknown-001",
        "operation": "shell",
    }

    response, _ = invoke_probe(probe_config, json.dumps(request) + "\n", tmp_path)

    assert response["success"] is False
    assert response["return_code"] == 11


@pytest.mark.parametrize("invalid_line", ["not-json\n", "[]\n", '{"unterminated":\n'])
def test_invalid_json_or_envelope_is_rejected(
    tmp_path: Path,
    probe_config: Path,
    invoke_probe: Callable[[Path, str, Path], tuple[dict[str, Any], object]],
    invalid_line: str,
) -> None:
    response, _ = invoke_probe(probe_config, invalid_line, tmp_path)

    assert response["success"] is False
    assert response["return_code"] == 10


def test_deeply_nested_json_returns_structured_error_without_traceback(
    tmp_path: Path,
    probe_config: Path,
    invoke_probe: Callable[[Path, str, Path], tuple[dict[str, Any], object]],
) -> None:
    nested_json = "[" * 1500 + "0" + "]" * 1500 + "\n"

    response, completed = invoke_probe(probe_config, nested_json, tmp_path)

    assert response["success"] is False
    assert response["return_code"] == 10
    assert response["error"]["code"] == "INVALID_JSON"
    assert isinstance(completed, subprocess.CompletedProcess)
    assert completed.stderr == ""


def test_oversized_request_is_rejected(
    tmp_path: Path,
    probe_config: Path,
    invoke_probe: Callable[[Path, str, Path], tuple[dict[str, Any], object]],
) -> None:
    oversized = {
        "protocol_version": "1.0",
        "request_id": "oversized-001",
        "operation": "health",
        "padding": "x" * 8192,
    }

    response, _ = invoke_probe(probe_config, json.dumps(oversized) + "\n", tmp_path)

    assert response["success"] is False
    assert response["return_code"] == 30


def test_max_entries_budget_is_enforced(
    tmp_path: Path,
    allowed_root: Path,
    probe_config: Path,
    invoke_probe: Callable[[Path, str, Path], tuple[dict[str, Any], object]],
) -> None:
    for index in range(3):
        (allowed_root / f"entry-{index}.txt").write_text("synthetic", encoding="utf-8")
    request = {
        "protocol_version": "1.0",
        "request_id": "entries-001",
        "operation": "list_tree",
        "root": str(allowed_root),
        "policy": {"max_depth": 6, "max_entries": 2, "follow_symlinks": False},
    }

    response, _ = invoke_probe(probe_config, json.dumps(request) + "\n", tmp_path)

    assert response["success"] is False
    assert response["return_code"] == 30


def test_max_depth_budget_is_enforced(
    tmp_path: Path,
    allowed_root: Path,
    probe_config: Path,
    invoke_probe: Callable[[Path, str, Path], tuple[dict[str, Any], object]],
) -> None:
    nested = allowed_root / "level-1" / "level-2"
    nested.mkdir(parents=True)
    (nested / "too-deep.txt").write_text("synthetic", encoding="utf-8")
    request = {
        "protocol_version": "1.0",
        "request_id": "depth-001",
        "operation": "list_tree",
        "root": str(allowed_root),
        "policy": {"max_depth": 1, "max_entries": 100, "follow_symlinks": False},
    }

    response, _ = invoke_probe(probe_config, json.dumps(request) + "\n", tmp_path)

    assert response["success"] is False
    assert response["return_code"] == 30


def test_runtime_budget_uses_monotonic_deadline(
    tmp_path: Path,
    allowed_root: Path,
    probe_config: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.syspath_prepend(str(REMOTE_PROBE_SOURCE))
    from bioprobe import operations
    from bioprobe.config import load_config
    from bioprobe.service import handle_request

    clock_values = iter([0.0, 2.0])
    monkeypatch.setattr(operations.time, "monotonic", lambda: next(clock_values))
    config = load_config(probe_config)
    request = {
        "protocol_version": "1.0",
        "request_id": "timeout-001",
        "operation": "list_tree",
        "root": str(allowed_root),
        "policy": {"max_runtime_seconds": 1.0},
    }

    response = handle_request(request, config)

    assert response["success"] is False
    assert response["return_code"] == 31
    assert response["error"]["code"] == "SCAN_TIMEOUT"
