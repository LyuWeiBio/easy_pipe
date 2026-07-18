"""Structural assertions for synthetic FASTQ-QC workflow outputs."""

from __future__ import annotations

import csv
import gzip
import json
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Literal

from biopipe.workflow_test.fixtures import SyntheticFastqFixture

_MAX_OUTPUT_FILES = 1_000
_MAX_PARSED_FILE_BYTES = 16 * 1024 * 1024
_SUCCESSFUL_TRACE_STATES = {"CACHED", "COMPLETED"}


class OutputAssertionError(ValueError):
    """A stable structural failure that never includes raw output contents."""


def assert_workflow_outputs(
    results_root: str | Path,
    fixture: SyntheticFastqFixture,
    *,
    trimming_enabled: bool,
    mode: Literal["stub", "e2e"],
) -> tuple[str, ...]:
    """Assert critical per-sample reports and a successful Nextflow trace."""

    root = Path(results_root)
    inventory = _inventory(root)
    critical: set[str] = set()
    for row in fixture.rows:
        chunk = row.chunk or "unchunked"
        raw_directory = PurePosixPath("fastqc_raw", row.sample_id, row.lane, chunk)
        critical.update(
            _require_fastqc(
                root,
                inventory,
                raw_directory,
                paired=fixture.layout == "paired_end",
                mode=mode,
            )
        )
        if trimming_enabled:
            fastp_directory = PurePosixPath("fastp", row.sample_id, row.lane, chunk)
            critical.update(
                _require_fastp(
                    root,
                    inventory,
                    fastp_directory,
                    paired=fixture.layout == "paired_end",
                    mode=mode,
                )
            )
            trimmed_directory = PurePosixPath(
                "fastqc_trimmed",
                row.sample_id,
                row.lane,
                chunk,
            )
            critical.update(
                _require_fastqc(
                    root,
                    inventory,
                    trimmed_directory,
                    paired=fixture.layout == "paired_end",
                    mode=mode,
                )
            )

    multiqc_report = _require_exact(inventory, "multiqc/multiqc_report.html")
    critical.add(multiqc_report)
    multiqc_data_files = [name for name in inventory if name.startswith("multiqc/multiqc_data/")]
    if not multiqc_data_files:
        raise OutputAssertionError("MultiQC data directory is missing or empty")
    critical.add("multiqc/multiqc_data")
    if mode == "e2e":
        _require_html(root / multiqc_report)

    trace = _require_exact(inventory, "pipeline_info/execution_trace.txt")
    critical.add(trace)
    required_processes = {"FASTQC_RAW", "MULTIQC"}
    if trimming_enabled:
        required_processes.update({"FASTP", "FASTQC_POST_TRIM"})
    _assert_trace(root / trace, required_processes)
    for name in (
        "pipeline_info/execution_report.html",
        "pipeline_info/timeline.html",
        "pipeline_info/pipeline_dag.html",
    ):
        critical.add(_require_exact(inventory, name))
        if mode == "e2e":
            _require_html(root / name)
    return tuple(sorted(critical))


def _inventory(root: Path) -> dict[str, int]:
    if root.is_symlink() or not root.is_dir():
        raise OutputAssertionError("workflow results directory is missing or unsafe")
    files: dict[str, int] = {}
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for directory in directories:
            if (current_path / directory).is_symlink():
                raise OutputAssertionError("workflow results contain a symlink")
        for filename in filenames:
            path = current_path / filename
            if path.is_symlink():
                raise OutputAssertionError("workflow results contain a symlink")
            metadata = path.stat(follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1:
                raise OutputAssertionError("workflow result files must be non-empty regular files")
            relative = path.relative_to(root).as_posix()
            files[relative] = metadata.st_size
            if len(files) > _MAX_OUTPUT_FILES:
                raise OutputAssertionError("workflow results exceed the file-count limit")
    return files


def _require_fastqc(
    root: Path,
    inventory: dict[str, int],
    directory: PurePosixPath,
    *,
    paired: bool,
    mode: Literal["stub", "e2e"],
) -> set[str]:
    required: set[str] = set()
    for read in ("read1", "read2") if paired else ("read1",):
        zip_name = _require_one_suffix(inventory, directory, f".{read}_fastqc.zip")
        html_name = _require_one_suffix(inventory, directory, f".{read}_fastqc.html")
        required.update({zip_name, html_name})
        if mode == "e2e":
            if not zipfile.is_zipfile(root / zip_name):
                raise OutputAssertionError("FastQC ZIP output is not parseable")
            _require_html(root / html_name)
    return required


def _require_fastp(
    root: Path,
    inventory: dict[str, int],
    directory: PurePosixPath,
    *,
    paired: bool,
    mode: Literal["stub", "e2e"],
) -> set[str]:
    required = {
        _require_one_suffix(inventory, directory, ".fastp.json"),
        _require_one_suffix(inventory, directory, ".fastp.html"),
    }
    trimmed_suffixes = (
        (".R1.trimmed.fastq.gz", ".R2.trimmed.fastq.gz") if paired else (".trimmed.fastq.gz",)
    )
    required.update(
        _require_one_suffix(inventory, directory, suffix) for suffix in trimmed_suffixes
    )
    if mode == "e2e":
        json_name = next(name for name in required if name.endswith(".fastp.json"))
        html_name = next(name for name in required if name.endswith(".fastp.html"))
        payload = _read_small(root / json_name)
        try:
            parsed = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OutputAssertionError("fastp JSON output is not parseable") from exc
        if not isinstance(parsed, dict):
            raise OutputAssertionError("fastp JSON output must be an object")
        _require_html(root / html_name)
        for name in required:
            if name.endswith(".fastq.gz"):
                try:
                    with gzip.open(root / name, "rb") as stream:
                        if not stream.read(1):
                            raise OutputAssertionError("trimmed FASTQ output contains no records")
                except OSError as exc:
                    raise OutputAssertionError("trimmed FASTQ gzip output is invalid") from exc
    return required


def _require_one_suffix(
    inventory: dict[str, int],
    directory: PurePosixPath,
    suffix: str,
) -> str:
    prefix = f"{directory.as_posix()}/"
    matches = [
        name
        for name in inventory
        if name.startswith(prefix) and "/" not in name[len(prefix) :] and name.endswith(suffix)
    ]
    if len(matches) != 1:
        raise OutputAssertionError("a required per-sample workflow output is missing or duplicated")
    return matches[0]


def _require_exact(inventory: dict[str, int], name: str) -> str:
    if name not in inventory:
        raise OutputAssertionError("a required project-level workflow output is missing")
    return name


def _require_html(path: Path) -> None:
    payload = _read_small(path)
    if b"<html" not in payload[:4096].lower() and b"<!doctype html" not in payload[:4096].lower():
        raise OutputAssertionError("HTML workflow output is not structurally recognizable")


def _assert_trace(path: Path, required_processes: set[str]) -> None:
    try:
        text = _read_small(path).decode("utf-8")
        rows = list(csv.DictReader(text.splitlines(), delimiter="\t"))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise OutputAssertionError("Nextflow trace is not parseable") from exc
    if not rows or "status" not in rows[0] or "name" not in rows[0]:
        raise OutputAssertionError("Nextflow trace has no task status records")
    if any(row.get("status") not in _SUCCESSFUL_TRACE_STATES for row in rows):
        raise OutputAssertionError("Nextflow trace contains a non-successful task")
    observed = {
        process
        for row in rows
        for process in required_processes
        if process in (row.get("name") or "")
    }
    if observed != required_processes:
        raise OutputAssertionError("Nextflow trace is missing a required process")


def _read_small(path: Path) -> bytes:
    metadata = path.stat(follow_symlinks=False)
    if metadata.st_size > _MAX_PARSED_FILE_BYTES:
        raise OutputAssertionError("workflow metadata output exceeds the parse limit")
    return path.read_bytes()


__all__ = ["OutputAssertionError", "assert_workflow_outputs"]
