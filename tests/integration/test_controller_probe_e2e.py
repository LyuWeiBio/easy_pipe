"""Offline end-to-end checks across Controller and the real Remote Probe process."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from biopipe.models import SourceProfile
from biopipe.probe import OpenSSHProbeClient

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REMOTE_PROBE_SOURCE = REPOSITORY_ROOT / "remote_probe" / "src"


def test_controller_round_trips_real_probe_without_network(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    sample = allowed_root / "sample.fastq.gz"
    secret_content = "SYNTHETIC_SEQUENCE_CONTENT_MUST_NOT_LEAVE_SOURCE"
    sample.write_text(secret_content, encoding="utf-8")
    before_stat = sample.stat()
    config = tmp_path / "bioprobe.config.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "allowed_roots": [str(allowed_root)],
                "limits": {
                    "max_depth": 4,
                    "max_entries": 100,
                    "max_runtime_seconds": 10,
                    "max_request_bytes": 1024 * 1024,
                    "max_response_bytes": 10 * 1024 * 1024,
                    "max_paths": 100,
                    "max_path_bytes": 4096,
                },
                "follow_symlinks": False,
            }
        ),
        encoding="utf-8",
    )

    def local_probe_runner(
        args: Sequence[str],
        *,
        input: str,
        text: bool,
        capture_output: bool,
        timeout: float,
        check: bool,
        shell: bool,
    ) -> subprocess.CompletedProcess[str]:
        assert text is True
        assert capture_output is True
        assert check is False
        assert shell is False
        environment = os.environ.copy()
        environment["BIOPROBE_CONFIG"] = str(config)
        existing_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = os.pathsep.join(
            part for part in (str(REMOTE_PROBE_SOURCE), existing_pythonpath) if part
        )
        completed = subprocess.run(
            [sys.executable, "-m", "bioprobe"],
            input=input,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout,
            env=environment,
        )
        return subprocess.CompletedProcess(
            args=list(args),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    source = SourceProfile(
        source_id="local-synthetic-source",
        ssh_alias="unused-offline-alias",
        allowed_roots=[str(allowed_root)],
        probe={
            "max_depth": 4,
            "max_entries": 100,
            "max_runtime_seconds": 10,
            "max_paths": 100,
        },
    )
    client = OpenSSHProbeClient(runner=local_probe_runner)

    health = client.verify(source, request_id="offline-health")
    tree = client.list_tree(source, str(allowed_root), request_id="offline-tree")
    stats = client.stat_files(
        source,
        str(allowed_root),
        [str(sample)],
        request_id="offline-stat",
    )

    assert health.result is not None
    assert health.result["configuration"]["configured"] is True
    assert tree.result is not None
    assert tree.result["entry_count"] == 1
    assert stats.result is not None
    assert stats.result["file_count"] == 1
    assert secret_content not in json.dumps(tree.result)
    assert secret_content not in json.dumps(stats.result)
    after_stat = sample.stat()
    assert sample.read_text(encoding="utf-8") == secret_content
    assert after_stat.st_size == before_stat.st_size
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
    assert after_stat.st_mode == before_stat.st_mode
