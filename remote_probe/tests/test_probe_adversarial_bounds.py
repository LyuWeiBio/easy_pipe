"""Adversarial bounds tests for the Remote Probe FASTQ path.

A gzip bomb (tiny file, huge decompressed content) and budget exhaustion must
surface as bounded ``BUDGET_EXCEEDED`` failures, never as unbounded memory
growth, hangs, or unhandled exceptions.
"""

from __future__ import annotations

import gzip
import json
import time
from pathlib import Path
from typing import Any

from bioprobe.config import ProbeConfig, load_config
from bioprobe.errors import ReturnCode
from bioprobe.service import handle_request


def _config(
    tmp_path: Path,
    root: Path,
    *,
    max_sample_records_total: int = 100_000,
    max_content_bytes: int = 268_435_456,
    max_input_bytes: int = 268_435_456,
) -> ProbeConfig:
    config_path = tmp_path / "probe-config.json"
    config_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "allowed_roots": [str(root)],
                "limits": {
                    "max_entries": 100,
                    "max_paths": 100,
                    "max_runtime_seconds": 30,
                    "max_response_bytes": 65_536,
                    "max_sample_records_total": max_sample_records_total,
                    "max_content_bytes": max_content_bytes,
                    "max_input_bytes": max_input_bytes,
                    "max_fastq_line_bytes": 1_048_576,
                },
                "follow_symlinks": False,
            }
        ),
        encoding="utf-8",
    )
    config_path.chmod(0o600)
    return load_config(config_path)


def _request(
    operation: str, root: Path, paths: list[Path], *, sample_records: int = 100
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
            "max_runtime_seconds": 30,
            "sample_fastq_records": sample_records,
            "return_sequences": False,
            "return_qualities": False,
            "return_read_names": False,
        },
    }


def _valid_record(index: int) -> bytes:
    # Highly compressible but structurally valid FASTQ.
    return (
        f"@synthetic-read-{index}\n"
        + "A" * 100 + "\n+\n" + "!" * 100 + "\n"
    ).encode("ascii")


def test_gzip_bomb_is_bounded_not_unbounded(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    # ~11 MB of valid FASTQ compresses to ~11 KB: a 1000x bomb.
    bomb = root / "bomb.fastq.gz"
    bomb.write_bytes(gzip.compress(b"".join(_valid_record(i) for i in range(50_000))))
    assert bomb.stat().st_size < 1_000_000  # ~11 MB -> ~150 KB: still a real bomb

    config = _config(tmp_path, root, max_content_bytes=1_048_576)
    started = time.monotonic()
    response = handle_request(
        _request("summarize_fastq", root, [bomb], sample_records=50_000), config
    )
    elapsed = time.monotonic() - started

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.BUDGET_EXCEEDED
    assert response["error"]["code"] == "SCAN_BUDGET_EXCEEDED"
    assert elapsed < 25


def test_record_budget_exhaustion_is_bounded(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    many = root / "many.fastq"
    many.write_bytes(b"".join(_valid_record(i) for i in range(200)))

    config = _config(tmp_path, root, max_sample_records_total=5)
    response = handle_request(
        _request("summarize_fastq", root, [many], sample_records=200), config
    )

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.BUDGET_EXCEEDED


def test_input_byte_budget_exhaustion_is_bounded(tmp_path: Path) -> None:
    root = tmp_path / "allowed"
    root.mkdir()
    big = root / "big.fastq"
    big.write_bytes(b"".join(_valid_record(i) for i in range(200)))

    # Enough budget for the first records to parse cleanly, then the stream
    # must trip the input byte budget (not hang, not OOM, not misparse).
    config = _config(
        tmp_path, root, max_input_bytes=3 * len(_valid_record(0)) + 100
    )
    response = handle_request(
        _request("summarize_fastq", root, [big], sample_records=200), config
    )

    assert response["success"] is False
    assert response["return_code"] == ReturnCode.BUDGET_EXCEEDED


def test_gzip_bomb_with_default_budgets_still_terminates(tmp_path: Path) -> None:
    # Even with generous budgets the bomb must terminate (budget, not memory,
    # is the bound) and must not leak decompressed content into the response.
    root = tmp_path / "allowed"
    root.mkdir()
    bomb = root / "bomb2.fastq.gz"
    bomb.write_bytes(gzip.compress(b"".join(_valid_record(i) for i in range(50_000))))

    config = _config(tmp_path, root)
    started = time.monotonic()
    response = handle_request(
        _request("summarize_fastq", root, [bomb], sample_records=50_000), config
    )
    elapsed = time.monotonic() - started

    assert elapsed < 25
    serialized = json.dumps(response, ensure_ascii=True).encode("ascii")
    assert b"AAAAAAAAAA" not in serialized
