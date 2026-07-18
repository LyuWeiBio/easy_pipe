"""Strict controller validation for privacy-safe M2 FASTQ results."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Literal

import pytest

from biopipe.models import ProbeRequest, SourceProfile
from biopipe.probe.results import ProbeResultValidationError, validate_success_result

ROOT = "/srv/synthetic-raw"
FASTQ = f"{ROOT}/sample_R1.fastq.gz"


def _source() -> SourceProfile:
    return SourceProfile(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        allowed_roots=[ROOT],
    )


def _request(
    operation: Literal["detect_formats", "summarize_fastq"] = "summarize_fastq",
) -> ProbeRequest:
    return ProbeRequest(
        request_id="fastq-result-001",
        operation=operation,
        root=ROOT,
        paths=[FASTQ],
        policy={
            "inspection_level": "format_summary",
            "sample_fastq_records": 10,
        },
    )


def _budgets() -> dict[str, int | float]:
    return {
        "max_depth": 6,
        "max_entries": 100_000,
        "max_runtime_seconds": 300.0,
    }


def _summary_result() -> dict[str, Any]:
    return {
        "operation": "summarize_fastq",
        "root": ROOT,
        "files": [
            {
                "path": FASTQ,
                "format": "fastq",
                "compression": "gzip",
                "records_sampled": 2,
                "structure_valid": True,
                "read_length": {"minimum": 4, "median": 4.0, "maximum": 4},
                "likely_quality_encoding": "phred33",
                "header_family": "illumina_casava_1_8",
                "mate_markers": {
                    "read_1": 2,
                    "read_2": 0,
                    "unknown": 0,
                    "mixed": False,
                },
            }
        ],
        "file_count": 1,
        "budgets": _budgets(),
    }


def test_accepts_only_aggregate_fastq_summary() -> None:
    result = validate_success_result(_source(), _request(), _summary_result())

    assert result.operation == "summarize_fastq"
    assert result.files[0].records_sampled == 2
    serialized = result.model_dump_json()
    assert "ACGT" not in serialized
    assert "IIII" not in serialized


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("sequence", "ACGT"),
        ("quality", "IIII"),
        ("read_name", "synthetic-sensitive-identifier"),
        ("records_sampled", "2"),
    ],
)
def test_rejects_raw_or_coerced_fastq_fields(mutation: str, value: object) -> None:
    payload = _summary_result()
    payload["files"][0][mutation] = value

    with pytest.raises(ProbeResultValidationError):
        validate_success_result(_source(), _request(), payload)


def test_rejects_inconsistent_counts_paths_and_sampling_budget() -> None:
    variants = []
    wrong_count = _summary_result()
    wrong_count["file_count"] = 2
    variants.append(wrong_count)
    wrong_path = _summary_result()
    wrong_path["files"][0]["path"] = f"{ROOT}/other_R1.fastq.gz"
    variants.append(wrong_path)
    too_many_records = _summary_result()
    too_many_records["files"][0]["records_sampled"] = 11
    too_many_records["files"][0]["mate_markers"]["read_1"] = 11
    variants.append(too_many_records)
    mixed_mismatch = _summary_result()
    mixed_mismatch["files"][0]["mate_markers"]["mixed"] = True
    variants.append(mixed_mismatch)

    for payload in variants:
        with pytest.raises(ProbeResultValidationError):
            validate_success_result(_source(), _request(), payload)


def test_detect_formats_accepts_unknown_but_rejects_extra_content() -> None:
    request = _request("detect_formats")
    result = {
        "operation": "detect_formats",
        "root": ROOT,
        "files": [
            {
                "path": FASTQ,
                "format": "unknown",
                "compression": "unknown",
                "extension_candidate": True,
            }
        ],
        "file_count": 1,
        "budgets": _budgets(),
    }

    validated = validate_success_result(_source(), request, result)
    assert validated.files[0].format == "unknown"

    leaked = deepcopy(result)
    leaked["files"][0]["raw_line"] = "@sensitive"
    with pytest.raises(ProbeResultValidationError):
        validate_success_result(_source(), request, leaked)


@pytest.mark.parametrize(
    ("path", "claimed_candidate"),
    [
        (FASTQ, False),
        (f"{ROOT}/notes.txt", True),
    ],
)
def test_detect_formats_recomputes_extension_candidate_from_path(
    path: str,
    claimed_candidate: bool,
) -> None:
    request = ProbeRequest(
        request_id="fastq-result-001",
        operation="detect_formats",
        root=ROOT,
        paths=[path],
        policy={"inspection_level": "format_summary"},
    )
    result = {
        "operation": "detect_formats",
        "root": ROOT,
        "files": [
            {
                "path": path,
                "format": "unknown",
                "compression": "unknown",
                "extension_candidate": claimed_candidate,
            }
        ],
        "file_count": 1,
        "budgets": _budgets(),
    }

    with pytest.raises(ProbeResultValidationError):
        validate_success_result(_source(), request, result)
