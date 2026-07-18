"""Black-box JSONL integration tests for the local Remote Probe process."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REMOTE_PROBE_SOURCE = REPOSITORY_ROOT / "remote_probe" / "src"


def _write_config(tmp_path: Path, allowed_root: Path) -> Path:
    config = tmp_path / "bioprobe.config.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "allowed_roots": [str(allowed_root)],
                "limits": {
                    "max_depth": 6,
                    "max_entries": 100,
                    "max_runtime_seconds": 10,
                    "max_request_bytes": 4096,
                    "max_paths": 100,
                },
                "follow_symlinks": False,
            }
        ),
        encoding="utf-8",
    )
    return config


def _invoke_probe(
    config: Path,
    request: dict[str, Any],
    *,
    cwd: Path,
) -> tuple[dict[str, Any], subprocess.CompletedProcess[str]]:
    environment = os.environ.copy()
    environment["BIOPROBE_CONFIG"] = str(config)
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(REMOTE_PROBE_SOURCE), existing_pythonpath) if part
    )
    completed = subprocess.run(
        [sys.executable, "-m", "bioprobe"],
        input=json.dumps(request) + "\n",
        text=True,
        capture_output=True,
        check=False,
        cwd=cwd,
        env=environment,
        timeout=5,
    )
    assert completed.returncode == 0, completed.stderr
    lines = completed.stdout.splitlines()
    assert len(lines) == 1, completed.stdout
    return json.loads(lines[0]), completed


def test_health_round_trip(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    config = _write_config(tmp_path, allowed_root)
    request = {
        "protocol_version": "1.0",
        "request_id": "health-001",
        "operation": "health",
    }

    response, completed = _invoke_probe(config, request, cwd=tmp_path)

    assert response["protocol_version"] == "1.0"
    assert response["request_id"] == "health-001"
    assert response["success"] is True
    assert response["return_code"] == 0
    assert isinstance(response["result"], dict)
    assert response["error"] is None
    assert completed.stderr == ""


def test_list_tree_returns_metadata_without_file_content(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    nested = allowed_root / "nested"
    nested.mkdir(parents=True)
    secret_content = "SYNTHETIC_CONTENT_MUST_NOT_BE_RETURNED"
    (allowed_root / "sample-a.fastq.gz").write_text(secret_content, encoding="utf-8")
    (nested / "sample-b.txt").write_text("synthetic", encoding="utf-8")
    config = _write_config(tmp_path, allowed_root)
    request = {
        "protocol_version": "1.0",
        "request_id": "tree-001",
        "operation": "list_tree",
        "root": str(allowed_root),
        "policy": {
            "inspection_level": "metadata_only",
            "max_depth": 6,
            "max_entries": 100,
            "follow_symlinks": False,
        },
    }

    response, _ = _invoke_probe(config, request, cwd=tmp_path)
    serialized_result = json.dumps(response["result"], sort_keys=True)

    assert response["success"] is True
    assert response["return_code"] == 0
    assert "sample-a.fastq.gz" in serialized_result
    assert "sample-b.txt" in serialized_result
    assert secret_content not in serialized_result


def test_stat_files_returns_metadata_for_requested_paths(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    first = allowed_root / "first.txt"
    second = allowed_root / "second.txt"
    first.write_text("one", encoding="utf-8")
    second.write_text("two-two", encoding="utf-8")
    config = _write_config(tmp_path, allowed_root)
    request = {
        "protocol_version": "1.0",
        "request_id": "stat-001",
        "operation": "stat_files",
        "root": str(allowed_root),
        "paths": [str(first), str(second)],
    }

    response, _ = _invoke_probe(config, request, cwd=tmp_path)
    serialized_result = json.dumps(response["result"], sort_keys=True)

    assert response["success"] is True
    assert response["return_code"] == 0
    assert str(first) in serialized_result
    assert str(second) in serialized_result
    assert "one" not in serialized_result
    assert "two-two" not in serialized_result
