"""Strict loading of tiny, explicitly synthetic FASTQ fixtures."""

from __future__ import annotations

import csv
import io
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from biopipe.io import read_model
from biopipe.models import StrictModel

_MAX_FASTQ_BYTES = 64 * 1024
_MAX_FIXTURE_BYTES = 256 * 1024
_MAX_RECORDS = 16
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SAMPLE_PATTERN = re.compile(r"^synthetic_(?:se|pe)_[0-9]{3}$")
_READ_PATH_PATTERN = re.compile(r"^reads/synthetic_(?:se|pe)_R[12]\.(?:fastq|fq)$")
_HEADER_PATTERN = re.compile(r"^@SYNTHETIC_(?:SE|PE)_[0-9]{4}(?:/[12])?$")
_SEQUENCE_PATTERN = re.compile(r"^[ACGTN]+$")


class FixtureValidationError(ValueError):
    """A non-sensitive failure while validating committed synthetic data."""


class _FixtureRow(StrictModel):
    sample_id: str
    lane: str
    chunk: str | None = None
    read1: str
    read2: str | None = None

    @field_validator("sample_id")
    @classmethod
    def validate_sample_id(cls, value: str) -> str:
        if not _SAMPLE_PATTERN.fullmatch(value):
            raise ValueError("synthetic sample IDs must use the reserved layout/number format")
        return value

    @field_validator("lane", "chunk")
    @classmethod
    def validate_identifier(cls, value: str | None) -> str | None:
        if value is not None and not _IDENTIFIER_PATTERN.fullmatch(value):
            raise ValueError("fixture lane and chunk must be safe identifiers")
        return value

    @field_validator("read1", "read2")
    @classmethod
    def validate_relative_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or ".." in path.parts
            or any(part in {"", "."} for part in path.parts)
            or path.suffix not in {".fastq", ".fq"}
            or not _READ_PATH_PATTERN.fullmatch(path.as_posix())
        ):
            raise ValueError("fixture reads must use safe relative FASTQ paths")
        return path.as_posix()


class _FixtureDocument(StrictModel):
    fixture_version: Literal["1.0"] = "1.0"
    synthetic: Literal[True]
    layout: Literal["single_end", "paired_end"]
    rows: tuple[_FixtureRow, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def validate_rows(self) -> _FixtureDocument:
        slots = [(row.sample_id, row.lane, row.chunk) for row in self.rows]
        if len(slots) != len(set(slots)):
            raise ValueError("fixture sample/lane/chunk rows must be unique")
        paths = [path for row in self.rows for path in (row.read1, row.read2) if path is not None]
        if len(paths) != len(set(paths)):
            raise ValueError("fixture FASTQ paths must be unique")
        if self.layout == "paired_end" and any(row.read2 is None for row in self.rows):
            raise ValueError("paired fixtures require read2 for every row")
        if self.layout == "single_end" and any(row.read2 is not None for row in self.rows):
            raise ValueError("single fixtures must not include read2")
        expected_prefix = "synthetic_se_" if self.layout == "single_end" else "synthetic_pe_"
        if any(not row.sample_id.startswith(expected_prefix) for row in self.rows):
            raise ValueError("fixture sample IDs must match the declared layout")
        return self


@dataclass(frozen=True, slots=True)
class SyntheticFastqRow:
    """One validated row of synthetic FASTQ inputs."""

    sample_id: str
    lane: str
    chunk: str | None
    read1: Path
    read2: Path | None
    read1_payload: bytes
    read2_payload: bytes | None


@dataclass(frozen=True, slots=True)
class SyntheticFastqFixture:
    """Validated fixture whose files stay below one synthetic-only root."""

    root: Path
    layout: Literal["single_end", "paired_end"]
    rows: tuple[SyntheticFastqRow, ...]


def load_synthetic_fixture(root: str | Path) -> SyntheticFastqFixture:
    """Load a tiny fixture and validate every FASTQ record before execution."""

    requested = Path(root)
    try:
        if requested.is_symlink():
            raise FixtureValidationError("synthetic fixture root must not be a symlink")
        fixture_root = requested.resolve(strict=True)
        if not fixture_root.is_dir():
            raise FixtureValidationError("synthetic fixture root must be a directory")
        document_path = fixture_root / "fixture.json"
        if document_path.is_symlink():
            raise FixtureValidationError("fixture.json must not be a symlink")
        document_metadata = document_path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(document_metadata.st_mode)
            or not 0 < document_metadata.st_size <= _MAX_FASTQ_BYTES
        ):
            raise FixtureValidationError("fixture.json must be a small regular file")
        document = read_model(document_path, _FixtureDocument)
    except FixtureValidationError:
        raise
    except Exception as exc:
        raise FixtureValidationError("synthetic fixture metadata is invalid") from exc

    rows: list[SyntheticFastqRow] = []
    total_bytes = 0
    for row in document.rows:
        read1 = _resolve_read(fixture_root, row.read1)
        read1_headers, read1_payload = _validate_fastq(
            read1, expected_mate=None if document.layout == "single_end" else 1
        )
        total_bytes += len(read1_payload)
        read2: Path | None = None
        read2_payload: bytes | None = None
        if row.read2 is not None:
            read2 = _resolve_read(fixture_root, row.read2)
            read2_headers, read2_payload = _validate_fastq(read2, expected_mate=2)
            total_bytes += len(read2_payload)
            if read1_headers != read2_headers:
                raise FixtureValidationError("synthetic paired FASTQ record IDs do not match")
        rows.append(
            SyntheticFastqRow(
                sample_id=row.sample_id,
                lane=row.lane,
                chunk=row.chunk,
                read1=read1,
                read2=read2,
                read1_payload=read1_payload,
                read2_payload=read2_payload,
            )
        )
    if total_bytes > _MAX_FIXTURE_BYTES:
        raise FixtureValidationError("synthetic fixture exceeds the total byte limit")
    return SyntheticFastqFixture(
        root=fixture_root,
        layout=document.layout,
        rows=tuple(rows),
    )


def render_synthetic_samplesheet(
    fixture: SyntheticFastqFixture,
    *,
    source_root: Path | None = None,
) -> str:
    """Render absolute, synthetic-only inputs for an isolated Nextflow test run."""

    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(("sample_id", "lane", "chunk", "read1", "read2"))
    for row in fixture.rows:
        read1 = _display_read_path(row.read1, fixture.root, source_root)
        read2 = (
            None if row.read2 is None else _display_read_path(row.read2, fixture.root, source_root)
        )
        writer.writerow(
            (
                row.sample_id,
                row.lane,
                row.chunk or "",
                str(read1),
                "" if read2 is None else str(read2),
            )
        )
    return stream.getvalue()


def _display_read_path(path: Path, fixture_root: Path, source_root: Path | None) -> Path:
    if source_root is None:
        return path
    return source_root.joinpath(*path.relative_to(fixture_root).parts)


def _resolve_read(root: Path, relative: str) -> Path:
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    if candidate.is_symlink():
        raise FixtureValidationError("synthetic FASTQ inputs must not be symlinks")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise FixtureValidationError("synthetic FASTQ input escapes the fixture root") from exc
    return resolved


def _validate_fastq(path: Path, expected_mate: int | None) -> tuple[tuple[str, ...], bytes]:
    payload, _size = _read_bounded_regular_file(path)
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FixtureValidationError("synthetic FASTQ inputs must be ASCII") from exc
    lines = text.splitlines()
    if not lines or len(lines) % 4 != 0 or len(lines) // 4 > _MAX_RECORDS:
        raise FixtureValidationError("synthetic FASTQ structure or record count is invalid")

    normalized_headers: list[str] = []
    for offset in range(0, len(lines), 4):
        header, sequence, separator, quality = lines[offset : offset + 4]
        if not _HEADER_PATTERN.fullmatch(header):
            raise FixtureValidationError("synthetic FASTQ headers must use the reserved prefix")
        mate_suffix = f"/{expected_mate}" if expected_mate is not None else ""
        if mate_suffix and not header.endswith(mate_suffix):
            raise FixtureValidationError("synthetic FASTQ header mate markers are inconsistent")
        if expected_mate is None and header.endswith(("/1", "/2")):
            raise FixtureValidationError(
                "single-end synthetic FASTQ headers must not use mate markers"
            )
        if separator != "+" or not sequence or not _SEQUENCE_PATTERN.fullmatch(sequence):
            raise FixtureValidationError("synthetic FASTQ sequence structure is invalid")
        if len(sequence) != len(quality) or any(not 33 <= ord(value) <= 126 for value in quality):
            raise FixtureValidationError("synthetic FASTQ quality structure is invalid")
        normalized_headers.append(header.removesuffix(mate_suffix))
    return tuple(normalized_headers), payload


def _read_bounded_regular_file(path: Path) -> tuple[bytes, int]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise FixtureValidationError("synthetic FASTQ input cannot be opened safely") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_FASTQ_BYTES:
            raise FixtureValidationError("synthetic FASTQ input must be a small regular file")
        chunks: list[bytes] = []
        remaining = _MAX_FASTQ_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > _MAX_FASTQ_BYTES:
            raise FixtureValidationError("synthetic FASTQ input exceeds the byte limit")
        return payload, len(payload)
    finally:
        os.close(descriptor)


__all__ = [
    "FixtureValidationError",
    "SyntheticFastqFixture",
    "SyntheticFastqRow",
    "load_synthetic_fixture",
    "render_synthetic_samplesheet",
]
