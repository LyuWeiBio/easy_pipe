"""Exhaustive unit tests for pure FASTQ classification and pairing."""

from __future__ import annotations

from collections.abc import Sequence

import pytest
from pydantic import ValidationError

from biopipe.detectors import (
    FastqFileFacts,
    MateMarkerCounts,
    assess_generic_fastq,
    assess_illumina_fastq,
    detect_fastq_dataset,
    parse_fastq_filename,
)
from biopipe.models import ManifestIssue, ReadLengthSummary

ROOT = "/srv/synthetic-raw"


def _markers(state: str = "unknown", count: int = 4) -> MateMarkerCounts:
    counts = {
        "read1": (count, 0, 0, False),
        "read2": (0, count, 0, False),
        "unknown": (0, 0, count, False),
        "mixed": (2, 1, 1, True),
    }
    read1, read2, unknown, mixed = counts[state]
    return MateMarkerCounts(read_1=read1, read_2=read2, unknown=unknown, mixed=mixed)


def _facts(
    relative_path: str,
    *,
    compression: str = "gzip",
    valid: bool = True,
    quality: str = "phred33",
    header: str = "generic",
    marker: str = "unknown",
    marker_count: int = 4,
    read_length: ReadLengthSummary | None = None,
) -> FastqFileFacts:
    length = read_length
    if length is None and valid:
        length = ReadLengthSummary(minimum=100, median=101.0, maximum=102)
    return FastqFileFacts.model_validate(
        {
            "path": f"{ROOT}/{relative_path}",
            "compression": compression,
            "structure_valid": valid,
            "read_length": length,
            "likely_quality_encoding": quality,
            "header_family": header,
            "mate_markers": _markers(marker, marker_count),
        }
    )


def _codes(issues: Sequence[ManifestIssue]) -> set[str]:
    return {issue.code for issue in issues}


@pytest.mark.parametrize(
    ("filename", "sample", "direction", "convention"),
    [
        ("sample_R1.fastq.gz", "sample", "read1", "underscore_r"),
        ("sample_R2.fq", "sample", "read2", "underscore_r"),
        ("sample_1.fastq", "sample", "read1", "underscore_numeric"),
        ("sample_2.fq.gz", "sample", "read2", "underscore_numeric"),
        ("sample.1.fastq.gz", "sample", "read1", "dot_numeric"),
        ("sample.2.fastq.gz", "sample", "read2", "dot_numeric"),
    ],
)
def test_parses_required_generic_pairing_patterns(
    filename: str, sample: str, direction: str, convention: str
) -> None:
    parsed = parse_fastq_filename(f"{ROOT}/{filename}")

    assert parsed.sample_key == sample
    assert parsed.read_direction == direction
    assert parsed.convention == convention
    assert parsed.lane == "unlaned"
    assert parsed.chunk is None


def test_parses_illumina_sample_lane_direction_and_chunk() -> None:
    parsed = parse_fastq_filename(f"{ROOT}/tumor_S12_L003_R2_017.fastq.gz")

    assert parsed.sample_key == "tumor"
    assert parsed.sample_number == "S12"
    assert parsed.lane == "L003"
    assert parsed.read_direction == "read2"
    assert parsed.chunk == "017"
    assert parsed.convention == "illumina"


def test_parses_single_end_name_without_inventing_direction() -> None:
    parsed = parse_fastq_filename(f"{ROOT}/control.fastq.gz")

    assert parsed.sample_key == "control"
    assert parsed.read_direction is None
    assert parsed.convention == "single"


def test_unrecognized_suffix_does_not_invent_a_sample_key() -> None:
    parsed = parse_fastq_filename(f"{ROOT}/sample_R1.txt")

    assert parsed.sample_key is None
    assert parsed.convention == "unrecognized"
    assert parsed.extension_recognized is False


def test_detects_complete_generic_pair() -> None:
    result = detect_fastq_dataset(
        [
            _facts("sample_R1.fastq.gz", marker="read1"),
            _facts("sample_R2.fastq.gz", marker="read2"),
        ]
    )

    assert result.classification.dataset_type == "generic_fastq"
    assert result.classification.layout == "paired_end"
    assert result.classification.confidence == 1.0
    assert not result.errors
    slot = result.samples[0].slots[0]
    assert slot.status == "paired"
    assert slot.read1_candidates == (f"{ROOT}/sample_R1.fastq.gz",)
    assert slot.read2_candidates == (f"{ROOT}/sample_R2.fastq.gz",)


def test_same_sample_name_is_not_auto_paired_across_directories() -> None:
    result = detect_fastq_dataset(
        [
            _facts("run-a/sample_R1.fastq.gz", marker="read1"),
            _facts("run-b/sample_R2.fastq.gz", marker="read2"),
        ]
    )

    assert result.classification.layout == "unknown"
    assert result.samples[0].slots[0].status == "naming_conflict"
    assert "naming_conflict" in _codes(result.errors)


def test_paired_files_with_different_sampled_record_counts_are_blocking() -> None:
    result = detect_fastq_dataset(
        [
            _facts("sample_R1.fastq.gz", marker="read1", marker_count=2),
            _facts("sample_R2.fastq.gz", marker="read2", marker_count=1),
        ]
    )

    assert result.classification.layout == "unknown"
    assert result.samples[0].slots[0].status == "invalid"
    assert "sampled_record_count_mismatch" in _codes(result.errors)


@pytest.mark.parametrize(
    ("read1", "read2"),
    [
        ("sample_R1.fastq.gz", "sample_R2.fastq.gz"),
        ("sample_1.fastq.gz", "sample_2.fastq.gz"),
        ("sample.1.fastq.gz", "sample.2.fastq.gz"),
    ],
)
def test_all_required_generic_conventions_pair(read1: str, read2: str) -> None:
    result = detect_fastq_dataset([_facts(read2, marker="read2"), _facts(read1, marker="read1")])

    assert result.classification.layout == "paired_end"
    assert result.samples[0].slots[0].status == "paired"


def test_detects_single_end_without_treating_header_unknown_as_a_conflict() -> None:
    result = detect_fastq_dataset([_facts("sample.fastq")])

    assert result.classification.layout == "single_end"
    assert result.samples[0].slots[0].status == "single"
    assert not result.errors


def test_preserves_multiple_illumina_lanes_and_chunks() -> None:
    files = []
    for lane, chunk in (("L001", "001"), ("L001", "002"), ("L002", "001")):
        files.extend(
            [
                _facts(
                    f"sample_S1_{lane}_R1_{chunk}.fastq.gz",
                    header="illumina_casava_1_8",
                    marker="read1",
                ),
                _facts(
                    f"sample_S1_{lane}_R2_{chunk}.fastq.gz",
                    header="illumina_casava_1_8",
                    marker="read2",
                ),
            ]
        )

    result = detect_fastq_dataset(list(reversed(files)))

    assert result.classification.dataset_type == "illumina_fastq"
    assert result.classification.layout == "paired_end"
    assert [(slot.lane, slot.chunk) for slot in result.samples[0].slots] == [
        ("L001", "001"),
        ("L001", "002"),
        ("L002", "001"),
    ]
    assert all(slot.status == "paired" for slot in result.samples[0].slots)


def test_input_order_cannot_change_output() -> None:
    files = [
        _facts("zeta_R2.fastq.gz", marker="read2"),
        _facts("alpha_R1.fastq.gz", marker="read1"),
        _facts("zeta_R1.fastq.gz", marker="read1"),
        _facts("alpha_R2.fastq.gz", marker="read2"),
    ]

    forward = detect_fastq_dataset(files)
    reverse = detect_fastq_dataset(list(reversed(files)))

    assert forward.model_dump(mode="json") == reverse.model_dump(mode="json")
    assert [sample.sample_key for sample in forward.samples] == ["alpha", "zeta"]


def test_missing_mate_is_blocking_and_never_promoted_to_single_end() -> None:
    result = detect_fastq_dataset([_facts("sample_R1.fastq.gz", marker="read1")])

    assert result.classification.layout == "unknown"
    assert result.samples[0].slots[0].status == "missing_mate"
    assert "missing_mate" in _codes(result.errors)


def test_duplicate_mate_preserves_every_candidate() -> None:
    result = detect_fastq_dataset(
        [
            _facts("run-a/sample_R1.fastq.gz", marker="read1"),
            _facts("run-b/sample_R1.fastq.gz", marker="read1"),
            _facts("sample_R2.fastq.gz", marker="read2"),
        ]
    )

    slot = result.samples[0].slots[0]
    assert slot.status == "duplicate_mate"
    assert slot.read1_candidates == (
        f"{ROOT}/run-a/sample_R1.fastq.gz",
        f"{ROOT}/run-b/sample_R1.fastq.gz",
    )
    assert "duplicate_mate" in _codes(result.errors)
    assert result.classification.layout == "unknown"


def test_mixed_direction_conventions_are_a_naming_conflict() -> None:
    result = detect_fastq_dataset(
        [
            _facts("sample_R1.fastq.gz", marker="read1"),
            _facts("sample_2.fastq.gz", marker="read2"),
        ]
    )

    assert result.samples[0].slots[0].status == "naming_conflict"
    assert "naming_conflict" in _codes(result.errors)


def test_illumina_sample_number_conflict_blocks_all_affected_lanes() -> None:
    files = [
        _facts(f"sample_S{sample_no}_{lane}_R{read}_001.fastq.gz", marker=f"read{read}")
        for sample_no, lane in ((1, "L001"), (2, "L002"))
        for read in (1, 2)
    ]

    result = detect_fastq_dataset(files)

    assert "naming_conflict" in _codes(result.errors)
    assert {slot.status for slot in result.samples[0].slots} == {"naming_conflict"}


def test_filename_and_header_mate_conflict_is_blocking() -> None:
    result = detect_fastq_dataset(
        [
            _facts("sample_R1.fastq.gz", marker="read2"),
            _facts("sample_R2.fastq.gz", marker="read2"),
        ]
    )

    assert "header_mate_conflict" in _codes(result.errors)
    assert result.samples[0].slots[0].status == "invalid"
    assert result.classification.layout == "unknown"


def test_mixed_header_mate_categories_are_blocking() -> None:
    result = detect_fastq_dataset(
        [
            _facts("sample_R1.fastq.gz", marker="mixed"),
            _facts("sample_R2.fastq.gz", marker="read2"),
        ]
    )

    assert "mixed_header_mates" in _codes(result.errors)
    assert result.samples[0].slots[0].status == "invalid"


def test_single_end_header_marker_warns_but_does_not_infer_a_missing_mate() -> None:
    result = detect_fastq_dataset([_facts("sample.fastq.gz", marker="read1")])

    assert result.classification.layout == "single_end"
    assert "unpaired_header_marker" in _codes(result.warnings)
    assert "missing_mate" not in _codes(result.errors)


def test_mixed_single_and_paired_layout_is_blocking() -> None:
    result = detect_fastq_dataset(
        [
            _facts("paired_R1.fastq.gz", marker="read1"),
            _facts("paired_R2.fastq.gz", marker="read2"),
            _facts("single.fastq.gz"),
        ]
    )

    assert result.classification.layout == "unknown"
    assert "mixed_layout" in _codes(result.errors)


def test_invalid_structure_produces_stable_blocking_error() -> None:
    result = detect_fastq_dataset([_facts("sample.fastq.gz", valid=False, read_length=None)])

    assert result.classification.dataset_type == "unknown"
    assert result.classification.layout == "unknown"
    assert result.samples[0].slots[0].status == "invalid"
    assert _codes(result.errors) == {"invalid_fastq_structure"}


def test_unknown_compression_is_blocking() -> None:
    result = detect_fastq_dataset([_facts("sample.fastq.gz", compression="unknown")])

    assert result.observations.compression == "unknown"
    assert result.classification.layout == "unknown"
    assert "unknown_compression" in _codes(result.errors)


def test_empty_input_is_unknown_with_stable_error() -> None:
    result = detect_fastq_dataset([])

    assert result.classification.dataset_type == "unknown"
    assert result.classification.layout == "unknown"
    assert result.classification.confidence == 0.0
    assert not result.samples
    assert _codes(result.errors) == {"no_fastq_files"}


def test_unrecognized_suffix_is_not_silently_grouped() -> None:
    result = detect_fastq_dataset([_facts("sample_R1.txt")])

    assert not result.samples
    assert result.classification.layout == "unknown"
    assert "unrecognized_fastq_name" in _codes(result.errors)
    assert result.classification.confidence < 0.9


def test_mixed_compression_is_preserved_and_warned() -> None:
    result = detect_fastq_dataset(
        [
            _facts("sample_R1.fastq.gz", compression="gzip", marker="read1"),
            _facts("sample_R2.fastq", compression="none", marker="read2"),
        ]
    )

    assert result.observations.compression == "mixed"
    assert result.classification.layout == "paired_end"
    assert "mixed_compression" in _codes(result.warnings)


def test_mixed_quality_encoding_and_header_families_are_explicit() -> None:
    result = detect_fastq_dataset(
        [
            _facts("sample_R1.fastq.gz", quality="phred33", header="generic", marker="read1"),
            _facts(
                "sample_R2.fastq.gz",
                quality="phred64",
                header="illumina_legacy",
                marker="read2",
            ),
        ]
    )

    assert result.observations.likely_quality_encoding == "unknown"
    assert result.observations.header_family == "mixed"
    assert {"mixed_quality_encoding", "mixed_header_family"} <= _codes(result.warnings)


def test_illumina_header_can_identify_renamed_generic_files_with_lower_confidence() -> None:
    result = detect_fastq_dataset(
        [
            _facts("sample_R1.fastq.gz", header="illumina_casava_1_8", marker="read1"),
            _facts("sample_R2.fastq.gz", header="illumina_casava_1_8", marker="read2"),
        ]
    )

    assert result.classification.dataset_type == "illumina_fastq"
    assert 0.6 <= result.classification.confidence < 0.9


def test_partial_illumina_header_evidence_is_a_low_confidence_candidate() -> None:
    result = detect_fastq_dataset(
        [
            _facts("sample_R1.fastq.gz", header="illumina_legacy", marker="read1"),
            _facts("sample_R2.fastq.gz", header="unknown", marker="read2"),
        ]
    )

    assert result.classification.dataset_type == "illumina_fastq"
    assert result.classification.confidence == 0.6


def test_illumina_filename_with_generic_header_is_explainable_warning() -> None:
    result = detect_fastq_dataset(
        [
            _facts("sample_S1_L001_R1_001.fastq.gz", marker="read1"),
            _facts("sample_S1_L001_R2_001.fastq.gz", marker="read2"),
        ]
    )

    assert result.classification.dataset_type == "illumina_fastq"
    assert "illumina_header_conflict" in _codes(result.warnings)
    assert result.classification.layout == "paired_end"


def test_mixed_illumina_and_generic_naming_families_are_visible() -> None:
    result = detect_fastq_dataset(
        [
            _facts(
                "illumina_S1_L001_R1_001.fastq.gz",
                header="illumina_casava_1_8",
                marker="read1",
            ),
            _facts(
                "illumina_S1_L001_R2_001.fastq.gz",
                header="illumina_casava_1_8",
                marker="read2",
            ),
            _facts("generic_R1.fastq.gz", marker="read1"),
            _facts("generic_R2.fastq.gz", marker="read2"),
        ]
    )

    assert result.classification.dataset_type == "generic_fastq"
    assert "mixed_naming_family" in _codes(result.warnings)


def test_duplicate_input_path_is_reported_even_when_facts_match() -> None:
    item = _facts("sample.fastq.gz")

    result = detect_fastq_dataset([item, item])

    assert "duplicate_path" in _codes(result.errors)
    assert result.samples[0].slots[0].status == "invalid"


def test_conflicting_facts_for_one_path_are_deterministic() -> None:
    first = _facts("sample.fastq.gz", quality="phred33")
    second = _facts("sample.fastq.gz", quality="phred64")

    forward = detect_fastq_dataset([first, second])
    reverse = detect_fastq_dataset([second, first])

    assert "conflicting_file_facts" in _codes(forward.errors)
    assert forward.model_dump(mode="json") == reverse.model_dump(mode="json")


def test_detector_assessments_expose_fixed_explainable_rules() -> None:
    files = [
        _facts(
            "sample_S1_L001_R1_001.fastq.gz",
            header="illumina_casava_1_8",
            marker="read1",
        )
    ]

    generic = assess_generic_fastq(files)
    illumina = assess_illumina_fastq(files)

    assert generic.dataset_type == "generic_fastq"
    assert illumina.dataset_type == "illumina_fastq"
    assert {item.rule for item in generic.evidence} == {
        "valid_fastq_structure",
        "fastq_extension",
        "parseable_naming",
        "read_length_aggregate",
        "quality_encoding_aggregate",
    }
    assert illumina.confidence == 1.0


@pytest.mark.parametrize("path", ["relative.fastq", "/srv/../escape.fastq", "/srv//x.fastq"])
def test_input_path_must_be_absolute_normalized_posix(path: str) -> None:
    with pytest.raises(ValidationError):
        FastqFileFacts(
            path=path,
            compression="gzip",
            structure_valid=True,
        )


def test_raw_content_fields_are_rejected_by_the_input_contract() -> None:
    payload = {
        "path": f"{ROOT}/sample.fastq",
        "compression": "none",
        "structure_valid": True,
        "sequence": "ACGT",
        "quality": "IIII",
        "read_name": "sensitive-read-id",
    }

    with pytest.raises(ValidationError):
        FastqFileFacts.model_validate(payload)


def test_mate_marker_mixed_flag_must_match_aggregate_categories() -> None:
    with pytest.raises(ValidationError):
        MateMarkerCounts(read_1=2, read_2=2, unknown=0, mixed=False)
