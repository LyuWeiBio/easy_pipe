"""Typed, privacy-preserving contracts for controller-side FASTQ detection."""

from __future__ import annotations

import math
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from biopipe.models import (
    DatasetClassification,
    DatasetObservations,
    DetectionEvidence,
    ManifestIssue,
    ReadLengthSummary,
)

Compression = Literal["gzip", "none", "unknown"]
HeaderFamily = Literal[
    "illumina_casava_1_8",
    "illumina_legacy",
    "generic",
    "unknown",
]
NamingConvention = Literal[
    "illumina",
    "underscore_r",
    "underscore_numeric",
    "dot_numeric",
    "single",
    "unrecognized",
]
ReadDirection = Literal["read1", "read2"]
PairingStatus = Literal[
    "paired",
    "single",
    "missing_mate",
    "duplicate_mate",
    "naming_conflict",
    "invalid",
]


class DetectorModel(BaseModel):
    """Strict immutable base for deterministic detector inputs and outputs."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _safe_absolute_path(value: str) -> str:
    if not value or len(value.encode("utf-8")) > 4096:
        raise ValueError("path must contain between 1 and 4096 UTF-8 bytes")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("path must not contain control characters")
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError("path must be an absolute normalized POSIX path")
    return value


class MateMarkerCounts(DetectorModel):
    """Counts of privacy-safe header mate categories from bounded sampling."""

    read_1: int = Field(ge=0, le=100_000)
    read_2: int = Field(ge=0, le=100_000)
    unknown: int = Field(ge=0, le=100_000)
    mixed: bool

    @model_validator(mode="after")
    def validate_mixed_flag(self) -> MateMarkerCounts:
        expected = sum(count > 0 for count in (self.read_1, self.read_2, self.unknown)) > 1
        if self.mixed != expected:
            raise ValueError("mixed must reflect whether multiple mate categories were sampled")
        return self


class FastqFileFacts(DetectorModel):
    """Sanitized aggregate facts for one remote file; raw reads are never accepted."""

    path: str
    compression: Compression
    structure_valid: bool
    read_length: ReadLengthSummary | None = None
    likely_quality_encoding: Literal["phred33", "phred64", "unknown"] = "unknown"
    header_family: HeaderFamily = "unknown"
    mate_markers: MateMarkerCounts | None = None

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _safe_absolute_path(value)


class ParsedFastqName(DetectorModel):
    """A lossless parse of supported FASTQ naming evidence."""

    path: str
    sample_key: str | None
    lane: str = "unlaned"
    chunk: str | None = None
    sample_number: str | None = None
    read_direction: ReadDirection | None = None
    convention: NamingConvention
    extension_recognized: bool

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        return _safe_absolute_path(value)


class PairingSlotFacts(DetectorModel):
    """All candidates for one sample/lane/chunk slot without an arbitrary choice."""

    sample_key: str
    lane: str
    chunk: str | None = None
    sample_numbers: tuple[str, ...] = ()
    naming_conventions: tuple[NamingConvention, ...]
    read1_candidates: tuple[str, ...] = ()
    read2_candidates: tuple[str, ...] = ()
    unpaired_candidates: tuple[str, ...] = ()
    status: PairingStatus


class SamplePairingFacts(DetectorModel):
    """Deterministically ordered lane/chunk pairing facts for one sample key."""

    sample_key: str
    slots: tuple[PairingSlotFacts, ...] = Field(min_length=1)


class DetectorAssessment(DetectorModel):
    """Score and evidence emitted by one named FASTQ detector."""

    dataset_type: Literal["generic_fastq", "illumina_fastq"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: tuple[DetectionEvidence, ...]

    @field_validator("confidence")
    @classmethod
    def finite_confidence(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("confidence must be finite")
        return value


class FastqDetectionResult(DetectorModel):
    """Explainable dataset classification and non-lossy pairing outcome."""

    classification: DatasetClassification
    observations: DatasetObservations
    samples: tuple[SamplePairingFacts, ...]
    evidence: tuple[DetectionEvidence, ...]
    warnings: tuple[ManifestIssue, ...]
    errors: tuple[ManifestIssue, ...]


__all__ = [
    "Compression",
    "DetectorAssessment",
    "FastqDetectionResult",
    "FastqFileFacts",
    "HeaderFamily",
    "MateMarkerCounts",
    "NamingConvention",
    "PairingSlotFacts",
    "PairingStatus",
    "ParsedFastqName",
    "ReadDirection",
    "SamplePairingFacts",
]
