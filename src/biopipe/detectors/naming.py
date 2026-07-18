"""Pure FASTQ filename parsing with explicit, ordered conventions."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from biopipe.detectors.models import NamingConvention, ParsedFastqName, ReadDirection

_FASTQ_SUFFIXES = (".fastq.gz", ".fq.gz", ".fastq", ".fq")
_ILLUMINA_PATTERN = re.compile(
    r"^(?P<sample>.+)_S(?P<sample_number>[1-9][0-9]*)_"
    r"(?P<lane>L[0-9]{3})_R(?P<read>[12])_(?P<chunk>[0-9]{3})$",
    flags=re.IGNORECASE,
)
_UNDERSCORE_R_PATTERN = re.compile(r"^(?P<sample>.+)_R(?P<read>[12])$", re.IGNORECASE)
_UNDERSCORE_NUMERIC_PATTERN = re.compile(r"^(?P<sample>.+)_(?P<read>[12])$")
_DOT_NUMERIC_PATTERN = re.compile(r"^(?P<sample>.+)\.(?P<read>[12])$")


def parse_fastq_filename(path: str) -> ParsedFastqName:
    """Parse supported naming evidence without touching the filesystem.

    The returned sample key preserves case and punctuation. Normalization only
    removes the recognized FASTQ suffix and an unambiguous read/lane suffix.
    """

    name = PurePosixPath(path).name
    stem = _strip_fastq_suffix(name)
    if stem is None:
        return ParsedFastqName(
            path=path,
            sample_key=None,
            convention="unrecognized",
            extension_recognized=False,
        )

    illumina = _ILLUMINA_PATTERN.fullmatch(stem)
    if illumina is not None:
        return ParsedFastqName(
            path=path,
            sample_key=illumina.group("sample"),
            lane=illumina.group("lane").upper(),
            chunk=illumina.group("chunk"),
            sample_number=f"S{illumina.group('sample_number')}",
            read_direction=_direction(illumina.group("read")),
            convention="illumina",
            extension_recognized=True,
        )

    generic_patterns: tuple[tuple[re.Pattern[str], NamingConvention], ...] = (
        (_UNDERSCORE_R_PATTERN, "underscore_r"),
        (_UNDERSCORE_NUMERIC_PATTERN, "underscore_numeric"),
        (_DOT_NUMERIC_PATTERN, "dot_numeric"),
    )
    for pattern, convention in generic_patterns:
        matched = pattern.fullmatch(stem)
        if matched is not None:
            return ParsedFastqName(
                path=path,
                sample_key=matched.group("sample"),
                read_direction=_direction(matched.group("read")),
                convention=convention,
                extension_recognized=True,
            )

    return ParsedFastqName(
        path=path,
        sample_key=stem,
        convention="single",
        extension_recognized=True,
    )


def _strip_fastq_suffix(name: str) -> str | None:
    lowered = name.lower()
    for suffix in _FASTQ_SUFFIXES:
        if lowered.endswith(suffix):
            stem = name[: -len(suffix)]
            return stem or None
    return None


def _direction(value: str) -> ReadDirection:
    return "read1" if value == "1" else "read2"


__all__ = ["parse_fastq_filename"]
