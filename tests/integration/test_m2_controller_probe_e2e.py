"""Offline M2 Controller-to-real-Probe FASTQ manifest integration."""

from __future__ import annotations

import gzip
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from biopipe.inspection import inspect_fastq_dataset
from biopipe.manifests import sanitize_manifest, verify_manifest
from biopipe.models import SourceProfile
from biopipe.probe import OpenSSHProbeClient

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REMOTE_PROBE_SOURCE = REPOSITORY_ROOT / "remote_probe" / "src"


def test_m2_builds_manifest_without_exporting_or_modifying_reads(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    read1 = allowed_root / "SensitiveSample_S1_L001_R1_001.fastq.gz"
    read2 = allowed_root / "SensitiveSample_S1_L001_R2_001.fastq.gz"
    note = allowed_root / "delivery-note.txt"
    raw_values = {
        "header1": "INST:1:FC:1:1101:100:100 1:N:0:ACGT",
        "header2": "INST:1:FC:1:1101:100:100 2:N:0:ACGT",
        "sequence1": "ACGTTGCA",
        "sequence2": "TGCACGTT",
        "quality": "#$%&'()*",
    }
    _write_fastq(read1, raw_values["header1"], raw_values["sequence1"], raw_values["quality"])
    _write_fastq(read2, raw_values["header2"], raw_values["sequence2"], raw_values["quality"])
    note.write_text("synthetic non-FASTQ delivery note", encoding="utf-8")
    before = {path: (path.read_bytes(), path.stat()) for path in (read1, read2, note)}
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
    manifest = inspect_fastq_dataset(
        source,
        str(allowed_root),
        client=OpenSSHProbeClient(runner=local_probe_runner),
        sample_fastq_records=10,
        scanned_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert verify_manifest(manifest)
    assert manifest.classification.dataset_type == "illumina_fastq"
    assert manifest.classification.layout == "paired_end"
    assert manifest.classification.confidence == 1.0
    assert manifest.errors == []
    assert [issue.code for issue in manifest.warnings] == ["unsupported_files_ignored"]
    assert len(manifest.samples) == 1
    assert manifest.samples[0].sample_id == "sample_001"
    assert manifest.samples[0].original_sample_name == "SensitiveSample"
    assert manifest.samples[0].lanes[0].lane == "L001"
    assert manifest.samples[0].lanes[0].read1 == str(read1)
    assert manifest.samples[0].lanes[0].read2 == str(read2)

    serialized = manifest.model_dump_json()
    for raw_value in raw_values.values():
        assert raw_value not in serialized
    sanitized = sanitize_manifest(manifest).model_dump_json()
    assert "SensitiveSample" not in sanitized
    for path, (content, item_stat) in before.items():
        after_stat = path.stat()
        assert path.read_bytes() == content
        assert after_stat.st_size == item_stat.st_size
        assert after_stat.st_mtime_ns == item_stat.st_mtime_ns
        assert after_stat.st_mode == item_stat.st_mode


def test_controller_splits_real_probe_request_level_record_budget(tmp_path: Path) -> None:
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    for index in range(3):
        (allowed_root / f"sample{index}.fastq").write_text(
            f"@private-read-{index}\nACGT\n+\n!!!!\n",
            encoding="ascii",
        )
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
                    "max_sample_records_total": 2,
                    "max_content_bytes": 1024 * 1024,
                    "max_input_bytes": 1024 * 1024,
                    "max_fastq_line_bytes": 4096,
                },
                "follow_symlinks": False,
            }
        ),
        encoding="utf-8",
    )
    operation_calls: dict[str, int] = {}

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
        request = json.loads(input)
        operation = str(request["operation"])
        operation_calls[operation] = operation_calls.get(operation, 0) + 1
        environment = os.environ.copy()
        environment["BIOPROBE_CONFIG"] = str(config)
        environment["PYTHONPATH"] = os.pathsep.join(
            part for part in (str(REMOTE_PROBE_SOURCE), environment.get("PYTHONPATH")) if part
        )
        completed = subprocess.run(
            [sys.executable, "-m", "bioprobe"],
            input=input,
            text=text,
            capture_output=capture_output,
            check=check,
            timeout=timeout,
            env=environment,
        )
        assert shell is False
        return subprocess.CompletedProcess(
            args=list(args),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    source = SourceProfile(
        source_id="local-budget-source",
        ssh_alias="unused-offline-alias",
        allowed_roots=[str(allowed_root)],
        probe={
            "max_depth": 4,
            "max_entries": 100,
            "max_runtime_seconds": 10,
            "max_paths": 100,
        },
    )
    manifest = inspect_fastq_dataset(
        source,
        str(allowed_root),
        client=OpenSSHProbeClient(runner=local_probe_runner),
        sample_fastq_records=1,
        scanned_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert manifest.classification.layout == "single_end"
    assert len(manifest.samples) == 3
    assert not manifest.errors
    assert operation_calls["detect_formats"] == 3
    assert operation_calls["summarize_fastq"] == 3


def _write_fastq(path: Path, header: str, sequence: str, quality: str) -> None:
    with gzip.open(path, mode="wt", encoding="ascii", newline="\n") as stream:
        stream.write(f"@{header}\n{sequence}\n+\n{quality}\n")
