"""Deterministic manifest sanitization for privacy-preserving review."""

from __future__ import annotations

import hashlib
import json

from biopipe.manifests.integrity import finalize_manifest, require_valid_manifest
from biopipe.models import (
    DatasetManifest,
    DatasetObservations,
    DatasetSample,
    DetectionEvidence,
    LaneFiles,
    ManifestIntegrity,
    ManifestIssue,
    ManifestPrivacy,
    ManifestSource,
)

_REDACTED_ISSUE_MESSAGE = "Details are available only in the local full manifest."
_REDACTED_REMEDIATION = ["Review the local full manifest before resolving this issue."]

# Domain separation for the sanitized sample-order seed.
_ORDER_SEED_DOMAIN = b"biopipe-sanitized-sample-order/v1"


def _sample_structure_key(sample: DatasetSample) -> str:
    """Name-independent structural fingerprint of one sample.

    Only facts that remain visible in the sanitized manifest are used: lane
    identifiers, chunk presence, and read pairing. Original names, sample ids,
    and file paths never enter the key.
    """

    lanes = sorted(
        (lane.lane, lane.chunk is not None, lane.read2 is not None)
        for lane in sample.lanes
    )
    return json.dumps(
        {"lane_count": len(sample.lanes), "lanes": lanes},
        sort_keys=True,
        separators=(",", ":"),
    )


def _order_samples_name_independent(
    samples: list[DatasetSample],
) -> list[DatasetSample]:
    """Permute samples deterministically without using original names.

    Sorting the sanitized samples by original name would let anyone holding
    the candidate name set recover the name<->sample_NNN mapping by sorting
    the candidates. Instead the order is a Fisher-Yates shuffle driven by a
    SHA-256 counter DRBG seeded over the *sorted* structural fingerprints:
    the seed (and therefore the permutation) is a pure function of the
    multiset of visible structures, revealing nothing about the names. The
    DRBG is implemented explicitly so the permutation does not depend on
    ``random`` module internals.
    """

    seed = hashlib.sha256(
        _ORDER_SEED_DOMAIN
        + b"\x00".join(
            key.encode("utf-8") for key in sorted(_sample_structure_key(s) for s in samples)
        )
    ).digest()
    ordered = list(samples)
    for i in range(len(ordered) - 1, 0, -1):
        digest = hashlib.sha256(seed + i.to_bytes(4, "big")).digest()
        j = int.from_bytes(digest, "big") % (i + 1)
        ordered[i], ordered[j] = ordered[j], ordered[i]
    return ordered
_SAFE_HEADER_FAMILIES = {
    "generic",
    "illumina_casava_1_8",
    "illumina_legacy",
    "mixed",
    "unknown",
}
_SAFE_EVIDENCE_RULES = {
    "fastq_extension",
    "header_mate_consistency",
    "illumina_filename",
    "illumina_header",
    "parseable_naming",
    "quality_encoding_aggregate",
    "read_length_aggregate",
    "valid_fastq_structure",
}
_SAFE_ISSUE_CODES = {
    "conflicting_file_facts",
    "duplicate_mate",
    "duplicate_path",
    "header_mate_conflict",
    "illumina_header_conflict",
    "invalid_fastq",
    "invalid_fastq_structure",
    "missing_mate",
    "mixed_compression",
    "mixed_header_family",
    "mixed_header_mates",
    "mixed_layout",
    "mixed_naming_family",
    "mixed_quality_encoding",
    "naming_conflict",
    "no_fastq_files",
    "sampled_record_count_mismatch",
    "unpaired_header_marker",
    "unknown_compression",
    "unrecognized_fastq_name",
    "unsupported_fastq_candidate",
    "unsupported_files_ignored",
}


def sanitize_manifest(manifest: DatasetManifest) -> DatasetManifest:
    """Create a stable manifest that contains no original sample names or paths."""

    require_valid_manifest(manifest)
    ordered_samples = _order_samples_name_independent(manifest.samples)
    sanitized_samples = [
        _sanitize_sample(sample, index, manifest)
        for index, sample in enumerate(ordered_samples, start=1)
    ]
    sanitized = DatasetManifest(
        manifest_version=manifest.manifest_version,
        source=ManifestSource(
            source_id="source_001",
            root="/redacted",
            scanned_at=manifest.source.scanned_at,
            scan_policy=manifest.source.scan_policy,
        ),
        classification=manifest.classification.model_copy(deep=True),
        samples=sanitized_samples,
        observations=DatasetObservations(
            compression=manifest.observations.compression,
            read_length=(
                None
                if manifest.observations.read_length is None
                else manifest.observations.read_length.model_copy(deep=True)
            ),
            likely_quality_encoding=manifest.observations.likely_quality_encoding,
            header_family=(
                manifest.observations.header_family
                if manifest.observations.header_family in _SAFE_HEADER_FAMILIES
                else "unknown"
            ),
        ),
        evidence=[
            DetectionEvidence(
                rule=(item.rule if item.rule in _SAFE_EVIDENCE_RULES else "redacted_evidence"),
                score=item.score,
                detail=None,
            )
            for item in manifest.evidence
        ],
        warnings=[_sanitize_issue(issue) for issue in manifest.warnings],
        errors=[_sanitize_issue(issue) for issue in manifest.errors],
        privacy=ManifestPrivacy(
            artifact_scope="sanitized",
            filenames_may_contain_identifiers=False,
            raw_content_exported=False,
        ),
        integrity=ManifestIntegrity(manifest_sha256=None),
    )
    return finalize_manifest(sanitized)


def _sanitize_sample(
    sample: DatasetSample,
    index: int,
    manifest: DatasetManifest,
) -> DatasetSample:
    sample_id = f"sample_{index:03d}"
    suffix = ".fastq.gz" if manifest.observations.compression == "gzip" else ".fastq"
    lanes: list[LaneFiles] = []
    for lane_index, lane in enumerate(
        sorted(sample.lanes, key=lambda item: (item.lane, item.chunk or "")),
        start=1,
    ):
        lane_directory = f"lane_{lane_index:03d}"
        base = f"/redacted/{sample_id}/{lane_directory}"
        lanes.append(
            LaneFiles(
                lane=f"lane_{lane_index:03d}",
                chunk=None if lane.chunk is None else "chunk_001",
                read1=f"{base}/read1{suffix}",
                read2=None if lane.read2 is None else f"{base}/read2{suffix}",
            )
        )
    return DatasetSample(sample_id=sample_id, original_sample_name=None, lanes=lanes)


def _sanitize_issue(issue: ManifestIssue) -> ManifestIssue:
    return ManifestIssue(
        code=issue.code if issue.code in _SAFE_ISSUE_CODES else "redacted_issue",
        severity=issue.severity,
        message=_REDACTED_ISSUE_MESSAGE,
        context={},
        remediation=_REDACTED_REMEDIATION,
    )


__all__ = ["sanitize_manifest"]
