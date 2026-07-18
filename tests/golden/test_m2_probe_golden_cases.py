"""Golden cases exercised through the real local Remote Probe process."""

from __future__ import annotations

import gzip
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from biopipe.inspection import inspect_fastq_dataset
from biopipe.manifests import render_samplesheet, sanitize_manifest, verify_manifest
from biopipe.models import SourceProfile
from biopipe.probe import OpenSSHProbeClient

CASES = Path(__file__).resolve().parents[1] / "fixtures" / "golden_cases"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REMOTE_PROBE_SOURCE = REPOSITORY_ROOT / "remote_probe" / "src"
FIXTURE_ROOT = PurePosixPath("/srv/raw")


@pytest.mark.parametrize(
    "case_dir",
    sorted(path for path in CASES.iterdir() if path.is_dir() and path.name != "path_security"),
)
def test_real_probe_golden_case(case_dir: Path, tmp_path: Path) -> None:
    case: dict[str, Any] = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    allowed_root = tmp_path / case_dir.name / "input"
    allowed_root.mkdir(parents=True)
    forbidden_raw: list[str] = []
    for facts in case["files"]:
        path = allowed_root / _relative_fixture_path(facts["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        header, sequence, quality = _synthetic_record(facts)
        forbidden_raw.extend([header, sequence, quality])
        if facts["structure_valid"]:
            marker_counts = facts.get("mate_markers") or {}
            record_count = (
                sum(int(marker_counts.get(key, 0)) for key in ("read_1", "read_2", "unknown")) or 1
            )
            _write_fastq(
                path,
                compression=facts["compression"],
                header=header,
                sequence=sequence,
                quality=quality,
                record_count=record_count,
            )
        else:
            path.write_bytes(b"@truncated-golden-read\nACGT\n+\n")
    for index in range(case.get("ignored_non_fastq_count", 0)):
        (allowed_root / f"ignored-{index}.txt").write_text(
            "synthetic delivery note",
            encoding="utf-8",
        )

    config = tmp_path / f"{case_dir.name}.bioprobe.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "allowed_roots": [str(allowed_root)],
                "limits": {
                    "max_depth": 8,
                    "max_entries": 100,
                    "max_runtime_seconds": 10,
                    "max_request_bytes": 1024 * 1024,
                    "max_response_bytes": 10 * 1024 * 1024,
                    "max_paths": 100,
                    "max_path_bytes": 4096,
                    "max_sample_records_total": 100,
                    "max_content_bytes": 1024 * 1024,
                    "max_input_bytes": 1024 * 1024,
                    "max_fastq_line_bytes": 4096,
                },
                "follow_symlinks": False,
            }
        ),
        encoding="utf-8",
    )
    probe_envelopes: list[dict[str, Any]] = []

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
        environment["PYTHONPATH"] = os.pathsep.join(
            part for part in (str(REMOTE_PROBE_SOURCE), environment.get("PYTHONPATH")) if part
        )
        completed = subprocess.run(
            [sys.executable, "-m", "bioprobe"],
            input=input,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=environment,
        )
        probe_envelopes.append(json.loads(completed.stdout))
        return subprocess.CompletedProcess(
            args=list(args),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    source = SourceProfile(
        source_id="golden-source",
        ssh_alias="unused-offline-alias",
        allowed_roots=[str(allowed_root)],
        probe={
            "max_depth": 8,
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
    samplesheet = None if manifest.errors else render_samplesheet(manifest)
    actual_artifacts = _normalize_artifacts(
        probe_envelopes,
        manifest.model_dump(mode="json"),
        samplesheet,
        allowed_root,
    )
    expected_artifacts = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
    assert actual_artifacts == expected_artifacts

    expected = case["expected"]
    expected_errors = expected.get("probe_error_codes", expected["error_codes"])

    assert verify_manifest(manifest)
    assert manifest.classification.dataset_type == expected["dataset_type"]
    assert manifest.classification.layout == expected["layout"]
    assert len(manifest.samples) == expected["sample_count"]
    assert sum(len(sample.lanes) for sample in manifest.samples) == expected["lane_count"]
    assert [sample.original_sample_name for sample in manifest.samples] == expected[
        "original_names"
    ]
    assert [issue.code for issue in manifest.warnings] == expected["warning_codes"]
    assert [issue.code for issue in manifest.errors] == expected_errors

    operations = {
        envelope["result"]["operation"] for envelope in probe_envelopes if envelope["success"]
    }
    assert {"list_tree", "detect_formats"} <= operations
    assert "summarize_fastq" in operations or case_dir.name == "malformed_fastq"
    expected_facts = {
        str(_relative_fixture_path(facts["path"])): facts
        for facts in case["files"]
        if facts["structure_valid"]
    }
    returned_summaries = [
        item
        for envelope in probe_envelopes
        if envelope["success"] and envelope["result"]["operation"] == "summarize_fastq"
        for item in envelope["result"]["files"]
    ]
    assert len(returned_summaries) == len(expected_facts)
    for summary in returned_summaries:
        relative = str(Path(summary["path"]).relative_to(allowed_root))
        facts = expected_facts[relative]
        assert summary["compression"] == facts["compression"]
        assert summary["structure_valid"] is True
        assert summary["read_length"] == facts["read_length"]
        assert summary["likely_quality_encoding"] == facts["likely_quality_encoding"]
        assert summary["header_family"] == facts["header_family"]
        assert summary["mate_markers"] == facts["mate_markers"]
    serialized_responses = json.dumps(probe_envelopes, sort_keys=True)
    for raw_value in forbidden_raw:
        assert raw_value not in serialized_responses

    sanitized = sanitize_manifest(manifest).model_dump_json()
    for sensitive in case.get("sanitized_forbidden", []):
        assert sensitive not in sanitized
    if samplesheet is not None:
        assert samplesheet.splitlines()[0] == "sample_id,lane,chunk,read1,read2"
        assert len(samplesheet.splitlines()) == expected["lane_count"] + 1


def _normalize_artifacts(
    probe_envelopes: list[dict[str, Any]],
    manifest: dict[str, Any],
    samplesheet: str | None,
    actual_root: Path,
) -> dict[str, Any]:
    """Normalize only volatile host-local values before exact golden comparison."""

    normalized_manifest = _normalize_value(manifest, actual_root)
    normalized_manifest["integrity"]["manifest_sha256"] = "<manifest-sha256>"
    return {
        "snapshot_version": "1.0",
        "probe_responses": _normalize_value(probe_envelopes, actual_root),
        "manifest": normalized_manifest,
        "samplesheet": _normalize_value(samplesheet, actual_root),
    }


def _normalize_value(value: Any, actual_root: Path) -> Any:
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if key == "request_id":
                normalized[key] = "<request-id>"
            elif key == "mtime_ns":
                normalized[key] = "<mtime-ns>"
            elif key == "entries" and isinstance(item, list):
                normalized[key] = sorted(
                    _normalize_value(item, actual_root),
                    key=lambda entry: entry["relative_path"],
                )
            else:
                normalized[key] = _normalize_value(item, actual_root)
        return normalized
    if isinstance(value, list):
        return [_normalize_value(item, actual_root) for item in value]
    if isinstance(value, str):
        root = str(actual_root)
        if root in value:
            return value.replace(root, str(FIXTURE_ROOT))
    return value


def _relative_fixture_path(value: str) -> Path:
    relative = PurePosixPath(value).relative_to(FIXTURE_ROOT)
    return Path(*relative.parts)


def _synthetic_record(facts: dict[str, Any]) -> tuple[str, str, str]:
    markers = facts.get("mate_markers") or {}
    mate = "1" if markers.get("read_1", 0) else "2" if markers.get("read_2", 0) else None
    family = facts.get("header_family")
    if family == "illumina_casava_1_8":
        header = f"GOLDEN:1:FC:1:1101:100:100 {mate or '1'}:N:0:ACGT"
    elif family == "illumina_legacy":
        header = f"GOLDEN:1:FC:1:1101:100:100/{mate or '1'}"
    else:
        header = "golden-sensitive-read-token" + (f"/{mate}" if mate else "")
    length_facts = facts.get("read_length")
    length = int(length_facts["median"]) if length_facts is not None else 4
    sequence = ("ACGT" * ((length + 3) // 4))[:length]
    quality_character = {
        "phred33": "#",
        "phred64": "h",
        "unknown": "I",
    }[facts.get("likely_quality_encoding", "unknown")]
    return header, sequence, quality_character * length


def _write_fastq(
    path: Path,
    *,
    compression: str,
    header: str,
    sequence: str,
    quality: str,
    record_count: int,
) -> None:
    record = "".join(f"@{header}\n{sequence}\n+\n{quality}\n" for _ in range(record_count))
    if compression == "gzip":
        with gzip.open(path, mode="wt", encoding="ascii", newline="\n") as stream:
            stream.write(record)
        return
    path.write_text(record, encoding="ascii", newline="\n")
