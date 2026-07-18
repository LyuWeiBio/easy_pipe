"""Data-driven M2 manifest golden cases."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from biopipe.detectors import FastqFileFacts, detect_fastq_dataset
from biopipe.manifests import build_manifest, sanitize_manifest, verify_manifest
from biopipe.models import ManifestIssue

CASES = Path(__file__).resolve().parents[1] / "fixtures" / "golden_cases"


@pytest.mark.parametrize("case_dir", sorted(path for path in CASES.iterdir() if path.is_dir()))
def test_m2_golden_case(case_dir: Path) -> None:
    payload: dict[str, Any] = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    if payload.get("expected_validation_error"):
        validation_error_count = 0
        for path in payload["invalid_paths"]:
            with pytest.raises(ValidationError):
                FastqFileFacts(
                    path=path,
                    compression="none",
                    structure_valid=True,
                )
            validation_error_count += 1
        expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
        assert expected == {
            "snapshot_version": "1.0",
            "probe_responses": None,
            "manifest": None,
            "samplesheet": None,
            "validation_error_count": validation_error_count,
        }
        return

    files = [FastqFileFacts.model_validate(item) for item in payload["files"]]
    detection = detect_fastq_dataset(files)
    warnings = []
    if payload.get("ignored_non_fastq_count"):
        warnings.append(
            ManifestIssue(
                code="unsupported_files_ignored",
                severity="warning",
                message="Non-FASTQ files were ignored after content-backed detection.",
                context={"file_count": payload["ignored_non_fastq_count"]},
            )
        )
    manifest = build_manifest(
        source_id="golden-source",
        root="/srv/raw",
        scanned_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        detection=detection,
        additional_warnings=warnings,
    )
    expected = payload["expected"]

    assert verify_manifest(manifest)
    assert manifest.classification.dataset_type == expected["dataset_type"]
    assert manifest.classification.layout == expected["layout"]
    assert len(manifest.samples) == expected["sample_count"]
    assert sum(len(sample.lanes) for sample in manifest.samples) == expected["lane_count"]
    assert [sample.original_sample_name for sample in manifest.samples] == expected[
        "original_names"
    ]
    assert [issue.code for issue in manifest.warnings] == expected["warning_codes"]
    assert [issue.code for issue in manifest.errors] == expected["error_codes"]
    sanitized = sanitize_manifest(manifest).model_dump_json()
    for sensitive in payload.get("sanitized_forbidden", []):
        assert sensitive not in sanitized
