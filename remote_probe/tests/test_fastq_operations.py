"""M2 FASTQ detection, aggregation, privacy, and descriptor-safety tests."""

from __future__ import annotations

import gzip
import json
import os
from pathlib import Path
from typing import Any

import pytest

from bioprobe.config import ProbeConfig, load_config
from bioprobe.errors import ReturnCode
from bioprobe.fastq import (
    FastqBudgetExceeded,
    FastqContentBudget,
    detect_compression,
    sample_fastq,
)
from bioprobe.operations import Deadline
from bioprobe.paths import OpenedDirectory, OpenedFile, PathGuard
from bioprobe.protocol import encode_response_line
from bioprobe.service import handle_request


def _config(
    tmp_path: Path,
    root: Path,
    *,
    max_response_bytes: int = 65_536,
    max_sample_records_total: int = 100_000,
    max_content_bytes: int = 268_435_456,
    max_input_bytes: int = 268_435_456,
    max_fastq_line_bytes: int = 1_048_576,
    max_entries: int = 100,
    max_paths: int = 100,
) -> ProbeConfig:
    config_path = tmp_path / "probe-config.json"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "allowed_roots": [str(root)],
                "limits": {
                    "max_entries": max_entries,
                    "max_paths": max_paths,
                    "max_runtime_seconds": 10,
                    "max_response_bytes": max_response_bytes,
                    "max_sample_records_total": max_sample_records_total,
                    "max_content_bytes": max_content_bytes,
                    "max_input_bytes": max_input_bytes,
                    "max_fastq_line_bytes": max_fastq_line_bytes,
                },
                "follow_symlinks": False,
            }
        ),
        encoding="utf-8",
    )
    return load_config(config_path)


def _request(
    operation: str,
    root: Path,
    paths: list[Path],
    *,
    sample_records: int = 100,
) -> dict[str, Any]:
    return {
        "protocol_version": "1.0",
        "request_id": f"m2-{operation}",
        "operation": operation,
        "root": str(root),
        "paths": [str(path) for path in paths],
        "policy": {
            "inspection_level": "format_summary",
            "max_entries": 100,
            "max_runtime_seconds": 10,
            "sample_fastq_records": sample_records,
            "return_sequences": False,
            "return_qualities": False,
            "return_read_names": False,
        },
    }


def _record(header: bytes, sequence: bytes, quality: bytes, plus: bytes = b"+") -> bytes:
    return b"\n".join((b"@" + header, sequence, plus, quality)) + b"\n"


def test_summarize_plain_and_gzip_fastq_returns_only_aggregates(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    plain = root / "sample_R1.fastq.gz"
    compressed = root / "sample_R2.data"
    r1_identifiers = (
        b"INSTRUMENT-A:7:FLOWCELL-X:1:1101:100:200 1:N:0:INDEX-A",
        b"INSTRUMENT-A:7:FLOWCELL-X:1:1101:101:201 1:N:0:INDEX-A",
    )
    r2_identifiers = (
        b"HWUSI-EAS100R:6:73:941:1973#0/2",
        b"HWUSI-EAS100R:6:73:941:1974#0/2",
    )
    sequences = (b"ACGT", b"GATTAC", b"TTAA", b"AACCGG")
    qualities = (b"!!!!", b"!!!!!!", b"hhhh", b"hhhhhh")
    plain.write_bytes(
        _record(r1_identifiers[0], sequences[0], qualities[0])
        + _record(
            r1_identifiers[1],
            sequences[1],
            qualities[1],
            plus=b"+" + r1_identifiers[1],
        )
    )
    compressed.write_bytes(
        gzip.compress(
            _record(r2_identifiers[0], sequences[2], qualities[2])
            + _record(r2_identifiers[1], sequences[3], qualities[3])
        )
    )
    response = handle_request(
        _request("summarize_fastq", root, [plain, compressed]),
        _config(tmp_path, root),
    )

    assert response["success"] is True
    assert response["return_code"] == ReturnCode.SUCCESS
    result = response["result"]
    assert result["operation"] == "summarize_fastq"
    assert result["root"] == str(root)
    assert result["file_count"] == 2
    first, second = result["files"]
    assert first == {
        "path": str(plain),
        "format": "fastq",
        "compression": "none",
        "records_sampled": 2,
        "structure_valid": True,
        "read_length": {"minimum": 4, "median": 5.0, "maximum": 6},
        "likely_quality_encoding": "phred33",
        "header_family": "illumina_casava_1_8",
        "mate_markers": {"read_1": 2, "read_2": 0, "unknown": 0, "mixed": False},
    }
    assert second == {
        "path": str(compressed),
        "format": "fastq",
        "compression": "gzip",
        "records_sampled": 2,
        "structure_valid": True,
        "read_length": {"minimum": 4, "median": 5.0, "maximum": 6},
        "likely_quality_encoding": "phred64",
        "header_family": "illumina_legacy",
        "mate_markers": {"read_1": 0, "read_2": 2, "unknown": 0, "mixed": False},
    }

    serialized = encode_response_line(response)
    for forbidden in (*r1_identifiers, *r2_identifiers, *sequences, *qualities):
        assert forbidden not in serialized


def test_detect_formats_uses_content_and_magic_for_mixed_batch(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    plain_with_gzip_suffix = root / "plain.fastq.gz"
    gzip_without_fastq_suffix = root / "reads.binary"
    malformed_candidate = root / "broken.fq"
    unsupported = root / "notes.txt"
    valid_record = _record(b"generic-read", b"ACGT", b"!!!!")
    plain_with_gzip_suffix.write_bytes(valid_record)
    gzip_without_fastq_suffix.write_bytes(gzip.compress(valid_record))
    malformed_candidate.write_bytes(b"not a FASTQ stream\n")
    unsupported.write_bytes(b"unrelated content\n")

    response = handle_request(
        _request(
            "detect_formats",
            root,
            [plain_with_gzip_suffix, gzip_without_fastq_suffix, malformed_candidate, unsupported],
        ),
        _config(tmp_path, root),
    )

    assert response["success"] is True
    assert response["result"]["files"] == [
        {
            "path": str(plain_with_gzip_suffix),
            "format": "fastq",
            "compression": "none",
            "extension_candidate": True,
        },
        {
            "path": str(gzip_without_fastq_suffix),
            "format": "fastq",
            "compression": "gzip",
            "extension_candidate": False,
        },
        {
            "path": str(malformed_candidate),
            "format": "unknown",
            "compression": "none",
            "extension_candidate": True,
        },
        {
            "path": str(unsupported),
            "format": "unknown",
            "compression": "none",
            "extension_candidate": False,
        },
    ]


@pytest.mark.parametrize(
    "content",
    [
        b"@read-identifier\nACGT\n+\n",
        b"@read-identifier\nACGT\n+\n!!!\n",
        b"@read-identifier\nACGT\n-\n!!!!\n",
        b"@read-identifier\nACGT\n+different-identifier\n!!!!\n",
    ],
)
def test_summarize_fastq_returns_stable_code_41_for_invalid_candidate(
    tmp_path: Path,
    content: bytes,
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    malformed = root / "malformed.fastq"
    malformed.write_bytes(content)

    response = handle_request(
        _request("summarize_fastq", root, [malformed]),
        _config(tmp_path, root),
    )

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.INVALID_FASTQ
    assert response["error"]["code"] == "INVALID_FASTQ"
    assert response["error"]["context"] == {"path_index": 0}
    serialized = encode_response_line(response)
    assert b"read-identifier" not in serialized
    assert b"ACGT" not in serialized
    assert b"!!!!" not in serialized


def test_summarize_fastq_distinguishes_unsupported_content(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    unsupported = root / "notes.txt"
    unsupported.write_bytes(b"this is not sequencing data\n")

    response = handle_request(
        _request("summarize_fastq", root, [unsupported]),
        _config(tmp_path, root),
    )

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.UNSUPPORTED_FORMAT
    assert response["error"]["code"] == "UNSUPPORTED_FORMAT"
    assert b"this is not sequencing data" not in encode_response_line(response)


def test_summarize_fastq_rejects_truncated_gzip_with_code_41(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    truncated = root / "truncated.fastq.gz"
    complete = gzip.compress(_record(b"synthetic-secret-id/1", b"ACGTACGT", b"!!!!!!!!"))
    truncated.write_bytes(complete[:-8])

    response = handle_request(
        _request("summarize_fastq", root, [truncated], sample_records=10),
        _config(tmp_path, root),
    )

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.INVALID_FASTQ
    assert response["error"]["code"] == "INVALID_FASTQ"
    serialized = encode_response_line(response)
    assert b"synthetic-secret-id" not in serialized
    assert b"ACGTACGT" not in serialized


@pytest.mark.parametrize(
    ("name", "expected_code"),
    [
        ("corrupt.bin", ReturnCode.UNSUPPORTED_FORMAT),
        ("corrupt.fastq.gz", ReturnCode.INVALID_FASTQ),
    ],
)
def test_corrupt_gzip_magic_uses_filename_only_for_error_category(
    tmp_path: Path,
    name: str,
    expected_code: ReturnCode,
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    corrupt = root / name
    corrupt.write_bytes(b"\x1f\x8bprivate-corrupt-content")

    response = handle_request(
        _request("summarize_fastq", root, [corrupt]),
        _config(tmp_path, root),
    )

    assert response["success"] is False
    assert response["return_code"] == expected_code
    serialized = encode_response_line(response)
    assert b"private-corrupt-content" not in serialized


@pytest.mark.parametrize("operation", ["detect_formats", "summarize_fastq"])
def test_content_response_limit_returns_bounded_code_30(
    tmp_path: Path,
    operation: str,
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    paths = []
    for index in range(12):
        path = root / f"{index:02d}-{'x' * 80}.fastq"
        path.write_bytes(_record(f"read-{index}".encode(), b"ACGT", b"!!!!"))
        paths.append(path)

    config = _config(tmp_path, root, max_response_bytes=900)
    response = handle_request(_request(operation, root, paths), config)

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.BUDGET_EXCEEDED
    assert response["error"]["code"] == "RESPONSE_BUDGET_EXCEEDED"
    assert len(encode_response_line(response)) <= config.limits.max_response_bytes


@pytest.mark.parametrize(
    ("config_kwargs", "budget"),
    [({"max_paths": 1}, "max_paths"), ({"max_entries": 1}, "max_entries")],
)
def test_content_path_count_budgets_fail_before_reading(
    tmp_path: Path,
    config_kwargs: dict[str, int],
    budget: str,
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    paths = [root / "first.fastq", root / "second.fastq"]
    for path in paths:
        path.write_bytes(_record(b"private-read", b"ACGT", b"!!!!"))

    response = handle_request(
        _request("summarize_fastq", root, paths),
        _config(tmp_path, root, **config_kwargs),
    )

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.BUDGET_EXCEEDED
    assert response["error"]["context"] == {"budget": budget, "limit": 1}
    serialized = encode_response_line(response)
    assert b"private-read" not in serialized
    assert b"ACGT" not in serialized


@pytest.mark.parametrize(
    "request_update",
    [
        {"root": None},
        {"paths": []},
        {"policy": {"inspection_level": "metadata_only", "sample_fastq_records": 10}},
        {"policy": {"inspection_level": "format_summary", "sample_fastq_records": 0}},
    ],
)
def test_summarize_fastq_request_contract_is_fail_closed(
    tmp_path: Path,
    request_update: dict[str, Any],
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    fastq = root / "reads.fastq"
    fastq.write_bytes(_record(b"read", b"ACGT", b"!!!!"))
    request = _request("summarize_fastq", root, [fastq])
    request.update(request_update)

    response = handle_request(request, _config(tmp_path, root))

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.PROTOCOL_ERROR
    assert response["error"]["code"] == "SCHEMA_ERROR"


def test_fastq_file_is_read_from_open_descriptor_after_name_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    target = root / "reads.fastq"
    original = root / "original.fastq"
    outside = tmp_path / "outside.fastq"
    target.write_bytes(_record(b"safe-id", b"ACGT", b"!!!!"))
    outside.write_bytes(b"OUTSIDE_SECRET_CONTENT\n")
    config = _config(tmp_path, root)
    original_open = PathGuard.open_file
    swapped = False

    def open_then_swap(
        guard: PathGuard,
        value: str,
        *,
        base: OpenedDirectory | None = None,
    ) -> OpenedFile:
        nonlocal swapped
        opened = original_open(guard, value, base=base)
        if not swapped:
            target.rename(original)
            target.symlink_to(outside)
            swapped = True
        return opened

    monkeypatch.setattr(PathGuard, "open_file", open_then_swap)
    response = handle_request(_request("summarize_fastq", root, [target]), config)

    assert response["success"] is True
    assert response["result"]["files"][0]["records_sampled"] == 1
    serialized = encode_response_line(response)
    assert b"safe-id" not in serialized
    assert b"ACGT" not in serialized
    assert b"OUTSIDE_SECRET_CONTENT" not in serialized


@pytest.mark.parametrize("operation", ["detect_formats", "summarize_fastq"])
def test_fastq_operations_reject_symlink_file(tmp_path: Path, operation: str) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    real = root / "real.fastq"
    linked = root / "linked.fastq"
    real.write_bytes(_record(b"read", b"ACGT", b"!!!!"))
    linked.symlink_to(real)

    response = handle_request(
        _request(operation, root, [linked]),
        _config(tmp_path, root),
    )

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.SYMLINK_OR_ESCAPE
    assert response["error"]["code"] == "SYMLINK_FORBIDDEN"


@pytest.mark.parametrize("operation", ["detect_formats", "summarize_fastq"])
def test_fastq_operations_reject_intermediate_symlink_and_outside_path(
    tmp_path: Path,
    operation: str,
) -> None:
    root = tmp_path / "allowed"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    outside_fastq = outside / "private.fastq"
    outside_fastq.write_bytes(_record(b"private-read", b"ACGT", b"!!!!"))
    linked_directory = root / "linked-directory"
    linked_directory.symlink_to(outside, target_is_directory=True)
    config = _config(tmp_path, root)

    symlink_response = handle_request(
        _request(operation, root, [linked_directory / outside_fastq.name]),
        config,
    )
    outside_response = handle_request(
        _request(operation, root, [outside_fastq]),
        config,
    )

    assert symlink_response["success"] is False
    assert symlink_response["return_code"] == ReturnCode.SYMLINK_OR_ESCAPE
    assert outside_response["success"] is False
    assert outside_response["return_code"] == ReturnCode.PATH_OUTSIDE_ALLOWLIST
    serialized = encode_response_line(symlink_response) + encode_response_line(outside_response)
    assert b"private-read" not in serialized
    assert b"ACGT" not in serialized


@pytest.mark.parametrize("operation", ["detect_formats", "summarize_fastq"])
def test_fastq_operations_share_record_budget_across_all_request_paths(
    tmp_path: Path,
    operation: str,
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    first = root / "first.fastq"
    second = root / "second.fastq"
    first.write_bytes(_record(b"private-first/1", b"ACGT", b"!!!!"))
    second.write_bytes(_record(b"private-second/2", b"TGCA", b"####"))

    response = handle_request(
        _request(operation, root, [first, second], sample_records=1),
        _config(tmp_path, root, max_sample_records_total=1),
    )

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.BUDGET_EXCEEDED
    assert response["error"]["code"] == "SCAN_BUDGET_EXCEEDED"
    assert response["error"]["context"] == {
        "budget": "max_sample_records_total",
        "limit": 1,
    }
    serialized = encode_response_line(response)
    for forbidden in (b"private-first", b"private-second", b"ACGT", b"TGCA"):
        assert forbidden not in serialized


@pytest.mark.parametrize("operation", ["detect_formats", "summarize_fastq"])
def test_fastq_operations_allow_exact_record_budget_boundary(
    tmp_path: Path,
    operation: str,
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    paths = [root / "first.fastq", root / "second.fastq"]
    for index, path in enumerate(paths):
        path.write_bytes(_record(f"read-{index}".encode(), b"ACGT", b"!!!!"))

    response = handle_request(
        _request(operation, root, paths, sample_records=1),
        _config(tmp_path, root, max_sample_records_total=2),
    )

    assert response["success"] is True
    assert response["result"]["file_count"] == 2


def test_record_budget_wins_before_validating_a_later_record(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    fastq = root / "two-records.fastq"
    fastq.write_bytes(_record(b"first", b"ACGT", b"!!!!") + b"@private-second\nACGT\n+\n!\n")

    response = handle_request(
        _request("summarize_fastq", root, [fastq], sample_records=2),
        _config(tmp_path, root, max_sample_records_total=1),
    )

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.BUDGET_EXCEEDED
    assert response["error"]["code"] == "SCAN_BUDGET_EXCEEDED"
    serialized = encode_response_line(response)
    assert b"private-second" not in serialized
    assert b"ACGT" not in serialized


def test_exhausted_record_budget_reads_no_next_header(tmp_path: Path) -> None:
    fastq = tmp_path / "private.fastq"
    fastq.write_bytes(_record(b"private-next-header", b"ACGT", b"!!!!"))
    descriptor = os.open(fastq, os.O_RDONLY)
    budget = FastqContentBudget(
        max_sample_records_total=1,
        max_content_bytes=1024,
        max_input_bytes=1024,
        records_sampled=1,
    )
    try:
        with pytest.raises(FastqBudgetExceeded) as captured:
            sample_fastq(
                descriptor,
                "none",
                1,
                Deadline(10),
                budget,
                1024,
            )
    finally:
        os.close(descriptor)

    assert captured.value.budget == "max_sample_records_total"
    assert budget.input_bytes_read == 0
    assert budget.content_bytes_read == 0


def test_gzip_header_reads_are_input_bounded_and_deadline_checked(tmp_path: Path) -> None:
    gzip_path = tmp_path / "adversarial.fastq.gz"
    gzip_path.write_bytes(b"\x1f\x8b\x08\x08" + b"\x00" * 6 + b"private-name" * 10_000)

    class CountingDeadline:
        def __init__(self) -> None:
            self.checks = 0

        def check(self) -> None:
            self.checks += 1

    deadline = CountingDeadline()
    budget = FastqContentBudget(
        max_sample_records_total=1,
        max_content_bytes=1024,
        max_input_bytes=64,
    )
    descriptor = os.open(gzip_path, os.O_RDONLY)
    try:
        compression = detect_compression(descriptor, deadline, budget)
        with pytest.raises(FastqBudgetExceeded) as captured:
            sample_fastq(
                descriptor,
                compression,
                1,
                deadline,
                budget,
                1024,
            )
    finally:
        os.close(descriptor)

    assert captured.value.budget == "max_input_bytes"
    assert budget.input_bytes_read == budget.max_input_bytes
    assert budget.content_bytes_read == 0
    assert deadline.checks > 20


@pytest.mark.parametrize("operation", ["detect_formats", "summarize_fastq"])
def test_magic_detection_fails_before_pread_when_input_budget_is_too_small(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    fastq = root / "private.fastq"
    fastq.write_bytes(_record(b"private-read", b"ACGT", b"!!!!"))
    pread_called = False

    def unexpected_pread(file_descriptor: int, size: int, offset: int) -> bytes:
        del file_descriptor, size, offset
        nonlocal pread_called
        pread_called = True
        return b""

    monkeypatch.setattr(os, "pread", unexpected_pread)
    response = handle_request(
        _request(operation, root, [fastq], sample_records=1),
        _config(tmp_path, root, max_input_bytes=1),
    )

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.BUDGET_EXCEEDED
    assert response["error"]["code"] == "SCAN_BUDGET_EXCEEDED"
    assert response["error"]["context"] == {
        "budget": "max_input_bytes",
        "limit": 1,
    }
    assert pread_called is False
    serialized = encode_response_line(response)
    assert b"private-read" not in serialized
    assert b"ACGT" not in serialized


@pytest.mark.parametrize("operation", ["detect_formats", "summarize_fastq"])
def test_magic_detection_respects_one_remaining_shared_input_byte(
    tmp_path: Path,
    operation: str,
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    content = _record(b"private-read", b"ACGT", b"!!!!")
    paths = [root / "first.fastq", root / "second.fastq"]
    for path in paths:
        path.write_bytes(content)

    # The first file consumes two magic bytes plus its complete sampled record,
    # leaving one byte. The second two-byte magic read must fail before I/O.
    input_limit = len(content) + 3
    response = handle_request(
        _request(operation, root, paths, sample_records=1),
        _config(tmp_path, root, max_input_bytes=input_limit),
    )

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.BUDGET_EXCEEDED
    assert response["error"]["code"] == "SCAN_BUDGET_EXCEEDED"
    assert response["error"]["context"] == {
        "budget": "max_input_bytes",
        "limit": input_limit,
    }
    serialized = encode_response_line(response)
    assert b"private-read" not in serialized
    assert b"ACGT" not in serialized


def test_summarize_fastq_counts_decompressed_bytes_across_gzip_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    content = _record(b"read", b"ACGT", b"!!!!")
    paths = [root / "first.fastq.gz", root / "second.fastq.gz"]
    for path in paths:
        path.write_bytes(gzip.compress(content))
    exact_decompressed_bytes = len(content) * len(paths)

    boundary_response = handle_request(
        _request("summarize_fastq", root, paths, sample_records=1),
        _config(tmp_path, root, max_content_bytes=exact_decompressed_bytes),
    )
    assert boundary_response["success"] is True

    exceeded_response = handle_request(
        _request("summarize_fastq", root, paths, sample_records=1),
        _config(tmp_path, root, max_content_bytes=exact_decompressed_bytes - 1),
    )
    assert exceeded_response["success"] is False
    assert exceeded_response["return_code"] == ReturnCode.BUDGET_EXCEEDED
    assert exceeded_response["error"]["code"] == "SCAN_BUDGET_EXCEEDED"
    assert exceeded_response["error"]["context"] == {
        "budget": "max_content_bytes",
        "limit": exact_decompressed_bytes - 1,
    }
    serialized = encode_response_line(exceeded_response)
    assert b"read" not in serialized
    assert b"ACGT" not in serialized
    assert b"!!!!" not in serialized


@pytest.mark.parametrize("operation", ["detect_formats", "summarize_fastq"])
def test_valid_overlong_fastq_line_is_a_budget_error(
    tmp_path: Path,
    operation: str,
) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    fastq = root / "overlong.fastq"
    sequence = b"ACGTACGTA"
    fastq.write_bytes(_record(b"read", sequence, b"!!!!!!!!!"))

    response = handle_request(
        _request(operation, root, [fastq], sample_records=1),
        _config(tmp_path, root, max_fastq_line_bytes=len(sequence) - 1),
    )

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.BUDGET_EXCEEDED
    assert response["error"]["code"] == "SCAN_BUDGET_EXCEEDED"
    assert response["error"]["context"] == {
        "budget": "max_fastq_line_bytes",
        "limit": len(sequence) - 1,
    }
    serialized = encode_response_line(response)
    assert sequence not in serialized
    assert b"!!!!!!!!!" not in serialized


def test_health_advertises_m2_content_capabilities(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    response = handle_request(
        {
            "protocol_version": "1.0",
            "request_id": "m2-health",
            "operation": "health",
        },
        _config(tmp_path, root),
    )

    assert response["success"] is True
    assert response["result"]["capabilities"] == [
        "detect_formats",
        "health",
        "list_tree",
        "stat_files",
        "summarize_fastq",
    ]
    limits = response["result"]["configuration"]["limits"]
    assert {
        "max_sample_records_total": limits["max_sample_records_total"],
        "max_content_bytes": limits["max_content_bytes"],
        "max_input_bytes": limits["max_input_bytes"],
        "max_fastq_line_bytes": limits["max_fastq_line_bytes"],
    } == {
        "max_sample_records_total": 100_000,
        "max_content_bytes": 268_435_456,
        "max_input_bytes": 268_435_456,
        "max_fastq_line_bytes": 1_048_576,
    }
