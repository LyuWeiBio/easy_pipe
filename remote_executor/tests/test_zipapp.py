from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from bioexec.config import AgentConfig

from .conftest import config_json, write_config

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LICENSE_FILE = REPOSITORY_ROOT / "LICENSE"


def _builder_module() -> object:
    path = Path(__file__).parents[1] / "build_zipapp.py"
    spec = importlib.util.spec_from_file_location("bioexec_build_zipapp", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_zipapp_build_is_byte_reproducible_and_health_is_one_json_line(
    agent_config: AgentConfig,
    tmp_path: Path,
) -> None:
    builder = _builder_module()
    first = tmp_path / "first.pyz"
    second = tmp_path / "second.pyz"
    builder.build(first, 315_532_800)  # type: ignore[attr-defined]
    builder.build(second, 315_532_800)  # type: ignore[attr-defined]
    assert (
        hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()
    )
    with zipfile.ZipFile(first) as archive:
        license_info = archive.getinfo("LICENSE")
        assert archive.read("LICENSE") == LICENSE_FILE.read_bytes()
        assert stat.S_IMODE(license_info.external_attr >> 16) == 0o644
        assert license_info.date_time == time.gmtime(315_532_800)[:6]
    config_path = tmp_path / ".config" / "bioexec" / "config.json"
    config_path.parent.mkdir(parents=True)
    write_config(config_path, config_json(agent_config))
    request = {
        "protocol_version": "1.0",
        "request_id": "health-1",
        "operation": "health",
        "payload": {},
    }
    environment = {**os.environ, "HOME": str(tmp_path)}
    environment.pop("BIOEXEC_CONFIG", None)
    environment.pop("XDG_CONFIG_HOME", None)
    system_python = Path("/usr/bin/python3")
    completed = subprocess.run(
        [str(system_python if system_python.exists() else Path(sys.executable)), str(first)],
        input=json.dumps(request, separators=(",", ":")) + "\n",
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
        shell=False,
        env=environment,
    )
    assert completed.returncode == 0
    assert completed.stderr == ""
    assert len(completed.stdout.splitlines()) == 1
    response = json.loads(completed.stdout)
    assert response["success"] is True
    assert response["result"]["status"] == "ok"
    assert "exec" not in response["result"]["operations"]


def test_compute_worker_is_a_distinct_reproducible_silent_entrypoint(
    tmp_path: Path,
) -> None:
    builder = _builder_module()
    first = tmp_path / "bioexec-compute-preflight"
    second = tmp_path / "second-bioexec-compute-preflight"

    builder.build(first, 315_532_800, "compute-preflight")  # type: ignore[attr-defined]
    builder.build(second, 315_532_800, "compute-preflight")  # type: ignore[attr-defined]

    assert first.read_bytes() == second.read_bytes()
    assert stat.S_IMODE(first.stat().st_mode) == 0o755
    with zipfile.ZipFile(first) as archive:
        assert archive.read("__main__.py") == (
            b"from bioexec.compute_worker import main\nraise SystemExit(main())\n"
        )
        assert archive.read("LICENSE") == LICENSE_FILE.read_bytes()
        assert "bioexec/compute_worker.py" in archive.namelist()
    system_python = Path("/usr/bin/python3")
    completed = subprocess.run(
        [
            str(system_python if system_python.exists() else Path(sys.executable)),
            "-I",
            "-S",
            str(first),
        ],
        text=False,
        capture_output=True,
        timeout=5,
        check=False,
        shell=False,
        env={"LANG": "C", "LC_ALL": "C"},
    )
    assert completed.returncode == 70
    assert completed.stdout == b""
    assert completed.stderr == b""
