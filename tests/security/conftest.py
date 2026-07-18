"""Synthetic process harness for Remote Probe security tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REMOTE_PROBE_SOURCE = REPOSITORY_ROOT / "remote_probe" / "src"
ProbeInvocation = tuple[dict[str, Any], subprocess.CompletedProcess[str]]


@pytest.fixture
def allowed_root(tmp_path: Path) -> Path:
    root = tmp_path / "allowed"
    root.mkdir()
    return root


@pytest.fixture
def probe_config(tmp_path: Path, allowed_root: Path) -> Path:
    path = tmp_path / "bioprobe.config.json"
    path.write_text(
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
    return path


@pytest.fixture
def invoke_probe() -> Callable[[Path, str, Path], ProbeInvocation]:
    def invoke(config: Path, request_line: str, cwd: Path) -> ProbeInvocation:
        environment = os.environ.copy()
        environment["BIOPROBE_CONFIG"] = str(config)
        existing_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = os.pathsep.join(
            part for part in (str(REMOTE_PROBE_SOURCE), existing_pythonpath) if part
        )
        completed = subprocess.run(
            [sys.executable, "-m", "bioprobe"],
            input=request_line,
            text=True,
            capture_output=True,
            check=False,
            cwd=cwd,
            env=environment,
            timeout=5,
        )
        lines = completed.stdout.splitlines()
        assert len(lines) == 1, completed.stdout
        response = json.loads(lines[0])
        assert completed.returncode == response["return_code"], completed.stderr
        return response, completed

    return invoke
