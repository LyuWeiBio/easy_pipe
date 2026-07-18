"""Reproducible build and execution tests for the Remote Probe zipapp."""

from __future__ import annotations

import json
import os
import runpy
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BUILD_SCRIPT = REPOSITORY_ROOT / "remote_probe" / "build_zipapp.py"


def _build_function() -> Callable[[Path, int], Path]:
    namespace = runpy.run_path(str(BUILD_SCRIPT))
    build = namespace["build"]
    assert callable(build)
    return build


def test_zipapp_build_is_reproducible_and_runs_health(tmp_path: Path) -> None:
    build = _build_function()
    epoch = 1_700_000_000
    first = build(tmp_path / "first" / "bioprobe.pyz", epoch)
    second = build(tmp_path / "second" / "bioprobe.pyz", epoch)

    assert first.read_bytes() == second.read_bytes()
    assert first.read_bytes().startswith(b"#!/usr/bin/env python3\n")

    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    config = tmp_path / "bioprobe.config.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "allowed_roots": [str(allowed_root)],
                "limits": {"max_runtime_seconds": 10},
                "follow_symlinks": False,
            }
        ),
        encoding="utf-8",
    )
    environment = os.environ.copy()
    environment["BIOPROBE_CONFIG"] = str(config)
    request = {
        "protocol_version": "1.0",
        "request_id": "zipapp-health-001",
        "operation": "health",
    }

    completed = subprocess.run(
        [sys.executable, str(first)],
        input=json.dumps(request) + "\n",
        text=True,
        capture_output=True,
        check=False,
        cwd=tmp_path,
        env=environment,
        timeout=5,
    )

    assert completed.returncode == 0, completed.stderr
    response = json.loads(completed.stdout)
    assert response["request_id"] == "zipapp-health-001"
    assert response["success"] is True
    assert response["return_code"] == 0
    assert response["result"]["status"] == "ok"
