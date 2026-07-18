"""Privacy-safe, bounded FASTQ sampling from already-open file descriptors."""

from __future__ import annotations

import gzip
import os
import statistics
import zlib
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Literal, Protocol, cast

Compression = Literal["gzip", "none"]
HeaderFamily = Literal[
    "illumina_casava_1_8",
    "illumina_legacy",
    "generic",
    "unknown",
]
MateMarker = Literal["read_1", "read_2", "unknown"]
QualityEncoding = Literal["phred33", "phred64", "unknown"]

_GZIP_MAGIC = b"\x1f\x8b"
_FASTQ_SUFFIXES = (".fastq", ".fq", ".fastq.gz", ".fq.gz")


class CheckableDeadline(Protocol):
    """The small timeout interface needed by the streaming parser."""

    def check(self) -> None:
        """Raise when the caller's monotonic deadline has expired."""


class FastqFormatError(Exception):
    """A sanitized parse failure that records whether FASTQ evidence was seen."""

    def __init__(self, *, recognized_fastq: bool) -> None:
        super().__init__("sampled content is not valid FASTQ")
        self.recognized_fastq = recognized_fastq


class FastqBudgetExceeded(Exception):
    """A sanitized request-level FASTQ content budget exhaustion."""

    def __init__(self, budget: str, limit: int) -> None:
        super().__init__("FASTQ content budget exceeded")
        self.budget = budget
        self.limit = limit


@dataclass(slots=True)
class FastqContentBudget:
    """Shared counters for every FASTQ stream read by one request."""

    max_sample_records_total: int
    max_content_bytes: int
    max_input_bytes: int
    records_sampled: int = 0
    content_bytes_read: int = 0
    input_bytes_read: int = 0

    def next_read_limit(self, max_line_bytes: int) -> int:
        """Bound the next stream read by both the line and remaining byte budgets."""

        remaining = self.max_content_bytes - self.content_bytes_read
        return min(max_line_bytes + 3, remaining + 1)

    def consume_content_bytes(self, count: int) -> None:
        """Account for decompressed bytes returned by a content stream."""

        if count < 0:
            raise ValueError("content byte count must not be negative")
        projected = self.content_bytes_read + count
        if projected > self.max_content_bytes:
            raise FastqBudgetExceeded("max_content_bytes", self.max_content_bytes)
        self.content_bytes_read = projected

    def consume_input_bytes(self, count: int) -> None:
        """Account for bytes read from plain or compressed source files."""

        if count < 0:
            raise ValueError("input byte count must not be negative")
        projected = self.input_bytes_read + count
        if projected > self.max_input_bytes:
            raise FastqBudgetExceeded("max_input_bytes", self.max_input_bytes)
        self.input_bytes_read = projected

    @property
    def input_bytes_remaining(self) -> int:
        return self.max_input_bytes - self.input_bytes_read

    def ensure_input_available(self, count: int) -> None:
        """Fail before a source read that cannot fit its remaining budget."""

        if count < 0:
            raise ValueError("input byte count must not be negative")
        if count > self.input_bytes_remaining:
            raise FastqBudgetExceeded("max_input_bytes", self.max_input_bytes)

    def consume_record(self) -> None:
        """Account for one structurally valid sampled FASTQ record."""

        self.ensure_record_available()
        self.records_sampled += 1

    def ensure_record_available(self) -> None:
        """Fail before parsing another record after the request cap is reached."""

        if self.records_sampled >= self.max_sample_records_total:
            raise FastqBudgetExceeded(
                "max_sample_records_total",
                self.max_sample_records_total,
            )


@dataclass(frozen=True, slots=True)
class FastqAggregate:
    """Only the non-sensitive aggregate facts retained from sampled records."""

    records_sampled: int
    minimum_read_length: int
    median_read_length: float
    maximum_read_length: int
    likely_quality_encoding: QualityEncoding
    header_family: HeaderFamily
    read_1_markers: int
    read_2_markers: int
    unknown_markers: int

    def to_result(self, path: Path, compression: Compression) -> dict[str, object]:
        """Serialize the fixed controller-facing summary allowlist."""

        marker_kinds = sum(
            count > 0
            for count in (
                self.read_1_markers,
                self.read_2_markers,
                self.unknown_markers,
            )
        )
        return {
            "path": str(path),
            "format": "fastq",
            "compression": compression,
            "records_sampled": self.records_sampled,
            "structure_valid": True,
            "read_length": {
                "minimum": self.minimum_read_length,
                "median": self.median_read_length,
                "maximum": self.maximum_read_length,
            },
            "likely_quality_encoding": self.likely_quality_encoding,
            "header_family": self.header_family,
            "mate_markers": {
                "read_1": self.read_1_markers,
                "read_2": self.read_2_markers,
                "unknown": self.unknown_markers,
                "mixed": marker_kinds > 1,
            },
        }


class _BudgetedInputReader:
    """Meter unbuffered source-file reads beneath plain or gzip parsing."""

    def __init__(
        self,
        raw: BinaryIO,
        snapshot_size: int,
        content_budget: FastqContentBudget,
        deadline: CheckableDeadline,
    ) -> None:
        self._raw = raw
        self._snapshot_size = snapshot_size
        self._content_budget = content_budget
        self._deadline = deadline

    @property
    def name(self) -> object:
        return getattr(self._raw, "name", "")

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b""
        limit = self._read_limit(size)
        if limit == 0:
            return b""
        self._deadline.check()
        value = self._raw.read(limit)
        self._deadline.check()
        self._content_budget.consume_input_bytes(len(value))
        return value

    def readline(self, size: int = -1) -> bytes:
        if size == 0:
            return b""
        limit = self._read_limit(size)
        if limit == 0:
            return b""
        self._deadline.check()
        value = self._raw.readline(limit)
        self._deadline.check()
        self._content_budget.consume_input_bytes(len(value))
        return value

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        self._deadline.check()
        position = self._raw.seek(offset, whence)
        self._deadline.check()
        return position

    def tell(self) -> int:
        return self._raw.tell()

    def seekable(self) -> bool:
        return self._raw.seekable()

    def readable(self) -> bool:
        return True

    def _read_limit(self, requested: int) -> int:
        position = self._raw.tell()
        file_remaining = max(0, self._snapshot_size - position)
        if file_remaining == 0:
            return 0
        budget_remaining = self._content_budget.input_bytes_remaining
        if budget_remaining == 0:
            raise FastqBudgetExceeded(
                "max_input_bytes",
                self._content_budget.max_input_bytes,
            )
        desired = file_remaining if requested < 0 else min(requested, file_remaining)
        return min(desired, budget_remaining)


def is_fastq_extension_candidate(path: Path) -> bool:
    """Return whether the name is a hint, never a content classification."""

    return path.name.lower().endswith(_FASTQ_SUFFIXES)


def detect_compression(
    file_descriptor: int,
    deadline: CheckableDeadline,
    content_budget: FastqContentBudget,
) -> Compression:
    """Classify gzip only by its magic bytes without changing the file offset."""

    magic_size = min(len(_GZIP_MAGIC), os.fstat(file_descriptor).st_size)
    content_budget.ensure_input_available(magic_size)
    deadline.check()
    magic = os.pread(file_descriptor, magic_size, 0)
    deadline.check()
    content_budget.consume_input_bytes(len(magic))
    return "gzip" if magic == _GZIP_MAGIC else "none"


def sample_fastq(
    file_descriptor: int,
    compression: Compression,
    max_records: int,
    deadline: CheckableDeadline,
    content_budget: FastqContentBudget,
    max_line_bytes: int,
) -> FastqAggregate:
    """Validate and aggregate at most ``max_records`` four-line FASTQ records."""

    if max_records < 1:
        raise ValueError("max_records must be positive")
    if max_line_bytes < 1:
        raise ValueError("max_line_bytes must be positive")

    read_lengths: list[int] = []
    quality_minimum = 127
    quality_maximum = 0
    header_families: set[HeaderFamily] = set()
    marker_counts: dict[MateMarker, int] = {"read_1": 0, "read_2": 0, "unknown": 0}
    recognized_fastq = False

    try:
        with _content_stream(
            file_descriptor,
            compression,
            content_budget,
            deadline,
        ) as stream:
            for _ in range(max_records):
                deadline.check()
                content_budget.ensure_record_available()
                header = _read_line(
                    stream,
                    deadline,
                    content_budget,
                    max_line_bytes,
                    recognized_fastq=recognized_fastq,
                )
                if header is None:
                    if read_lengths:
                        break
                    raise FastqFormatError(recognized_fastq=False)
                if header.startswith(b"@"):
                    recognized_fastq = True
                sequence = _required_line(
                    stream,
                    deadline,
                    content_budget,
                    max_line_bytes,
                    recognized_fastq,
                )
                separator = _required_line(
                    stream,
                    deadline,
                    content_budget,
                    max_line_bytes,
                    recognized_fastq,
                )
                quality = _required_line(
                    stream,
                    deadline,
                    content_budget,
                    max_line_bytes,
                    recognized_fastq,
                )
                _validate_record(header, sequence, separator, quality, recognized_fastq)
                content_budget.consume_record()

                read_lengths.append(len(sequence))
                quality_minimum = min(quality_minimum, min(quality))
                quality_maximum = max(quality_maximum, max(quality))
                header_families.add(_header_family(header))
                marker_counts[_mate_marker(header)] += 1
                deadline.check()
    except (gzip.BadGzipFile, EOFError, zlib.error) as exc:
        raise FastqFormatError(recognized_fastq=recognized_fastq or bool(read_lengths)) from exc

    if not read_lengths:
        raise FastqFormatError(recognized_fastq=recognized_fastq)
    family: HeaderFamily = next(iter(header_families)) if len(header_families) == 1 else "unknown"
    return FastqAggregate(
        records_sampled=len(read_lengths),
        minimum_read_length=min(read_lengths),
        median_read_length=float(statistics.median(read_lengths)),
        maximum_read_length=max(read_lengths),
        likely_quality_encoding=_quality_encoding(quality_minimum, quality_maximum),
        header_family=family,
        read_1_markers=marker_counts["read_1"],
        read_2_markers=marker_counts["read_2"],
        unknown_markers=marker_counts["unknown"],
    )


@contextmanager
def _content_stream(
    file_descriptor: int,
    compression: Compression,
    content_budget: FastqContentBudget,
    deadline: CheckableDeadline,
) -> Iterator[BinaryIO]:
    duplicate = os.dup(file_descriptor)
    raw = os.fdopen(duplicate, "rb", buffering=0, closefd=True)
    metered = _BudgetedInputReader(
        raw,
        os.fstat(file_descriptor).st_size,
        content_budget,
        deadline,
    )
    try:
        if compression == "gzip":
            with gzip.GzipFile(fileobj=cast(BinaryIO, metered), mode="rb") as decompressed:
                yield cast(BinaryIO, decompressed)
        else:
            yield cast(BinaryIO, metered)
    finally:
        raw.close()


def _read_line(
    stream: BinaryIO,
    deadline: CheckableDeadline,
    content_budget: FastqContentBudget,
    max_line_bytes: int,
    *,
    recognized_fastq: bool,
) -> bytes | None:
    deadline.check()
    raw = stream.readline(content_budget.next_read_limit(max_line_bytes))
    deadline.check()
    content_budget.consume_content_bytes(len(raw))
    if raw == b"":
        return None
    if raw.endswith(b"\n"):
        raw = raw[:-1]
        if raw.endswith(b"\r"):
            raw = raw[:-1]
    if len(raw) > max_line_bytes:
        raise FastqBudgetExceeded("max_fastq_line_bytes", max_line_bytes)
    return raw


def _required_line(
    stream: BinaryIO,
    deadline: CheckableDeadline,
    content_budget: FastqContentBudget,
    max_line_bytes: int,
    recognized_fastq: bool,
) -> bytes:
    line = _read_line(
        stream,
        deadline,
        content_budget,
        max_line_bytes,
        recognized_fastq=recognized_fastq,
    )
    if line is None:
        raise FastqFormatError(recognized_fastq=recognized_fastq)
    return line


def _validate_record(
    header: bytes,
    sequence: bytes,
    separator: bytes,
    quality: bytes,
    recognized_fastq: bool,
) -> None:
    valid_header = (
        len(header) > 1
        and header.startswith(b"@")
        and all(32 <= value <= 126 for value in header[1:])
    )
    valid_sequence = bool(sequence) and all(33 <= value <= 126 for value in sequence)
    valid_separator = separator.startswith(b"+")
    if valid_separator and len(separator) > 1:
        valid_separator = separator[1:] == header[1:]
    valid_quality = (
        len(quality) == len(sequence)
        and bool(quality)
        and all(33 <= value <= 126 for value in quality)
    )
    if not (valid_header and valid_sequence and valid_separator and valid_quality):
        raise FastqFormatError(recognized_fastq=recognized_fastq or valid_header)


def _header_family(header: bytes) -> HeaderFamily:
    body = header[1:]
    parts = body.split(maxsplit=1)
    first = parts[0]
    if len(parts) == 2:
        casava_fields = parts[1].split(b":")
        if (
            len(first.split(b":")) == 7
            and len(casava_fields) >= 4
            and casava_fields[0] in {b"1", b"2"}
            and casava_fields[1] in {b"Y", b"N"}
            and casava_fields[2].isdigit()
        ):
            return "illumina_casava_1_8"
    if first.endswith((b"/1", b"/2")) and first.count(b":") >= 4:
        return "illumina_legacy"
    return "generic"


def _mate_marker(header: bytes) -> MateMarker:
    body = header[1:]
    parts = body.split(maxsplit=1)
    first = parts[0]
    if first.endswith(b"/1"):
        return "read_1"
    if first.endswith(b"/2"):
        return "read_2"
    if len(parts) == 2:
        marker = parts[1].split(b":", maxsplit=1)[0]
        if marker == b"1":
            return "read_1"
        if marker == b"2":
            return "read_2"
    return "unknown"


def _quality_encoding(minimum: int, maximum: int) -> QualityEncoding:
    if minimum < 59:
        return "phred33"
    if minimum >= 64 and maximum > 74:
        return "phred64"
    return "unknown"


__all__ = [
    "Compression",
    "FastqAggregate",
    "FastqBudgetExceeded",
    "FastqContentBudget",
    "FastqFormatError",
    "detect_compression",
    "is_fastq_extension_candidate",
    "sample_fastq",
]
