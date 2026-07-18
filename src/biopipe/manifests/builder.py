"""Convert immutable detector facts into a finalized dataset manifest."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from biopipe.detectors import FastqDetectionResult, PairingSlotFacts
from biopipe.manifests.integrity import finalize_manifest
from biopipe.models import (
    DatasetManifest,
    DatasetSample,
    LaneFiles,
    ManifestIntegrity,
    ManifestIssue,
    ManifestPrivacy,
    ManifestSource,
)


def build_manifest(
    *,
    source_id: str,
    root: str,
    scanned_at: datetime,
    detection: FastqDetectionResult,
    additional_warnings: Sequence[ManifestIssue] = (),
    additional_errors: Sequence[ManifestIssue] = (),
) -> DatasetManifest:
    """Build a deterministic full manifest without changing detector facts."""

    samples: list[DatasetSample] = []
    for index, detected_sample in enumerate(
        sorted(detection.samples, key=lambda item: item.sample_key),
        start=1,
    ):
        lanes = [
            lane for slot in detected_sample.slots if (lane := _lane_from_slot(slot)) is not None
        ]
        if lanes:
            samples.append(
                DatasetSample(
                    sample_id=f"sample_{index:03d}",
                    original_sample_name=detected_sample.sample_key,
                    lanes=sorted(lanes, key=lambda item: (item.lane, item.chunk or "")),
                )
            )
    manifest = DatasetManifest(
        source=ManifestSource(
            source_id=source_id,
            root=root,
            scanned_at=scanned_at,
            scan_policy="format_summary",
        ),
        classification=detection.classification.model_copy(deep=True),
        samples=samples,
        observations=detection.observations.model_copy(deep=True),
        evidence=[item.model_copy(deep=True) for item in detection.evidence],
        warnings=sorted(
            [
                *(item.model_copy(deep=True) for item in detection.warnings),
                *(item.model_copy(deep=True) for item in additional_warnings),
            ],
            key=_issue_key,
        ),
        errors=sorted(
            [
                *(item.model_copy(deep=True) for item in detection.errors),
                *(item.model_copy(deep=True) for item in additional_errors),
            ],
            key=_issue_key,
        ),
        privacy=ManifestPrivacy(
            filenames_may_contain_identifiers=True,
            raw_content_exported=False,
        ),
        integrity=ManifestIntegrity(manifest_sha256=None),
    )
    return finalize_manifest(manifest)


def _lane_from_slot(slot: PairingSlotFacts) -> LaneFiles | None:
    if slot.status == "paired":
        if len(slot.read1_candidates) != 1 or len(slot.read2_candidates) != 1:
            return None
        return LaneFiles(
            lane=slot.lane,
            chunk=slot.chunk,
            read1=slot.read1_candidates[0],
            read2=slot.read2_candidates[0],
        )
    if slot.status == "single":
        if len(slot.unpaired_candidates) != 1:
            return None
        return LaneFiles(
            lane=slot.lane,
            chunk=slot.chunk,
            read1=slot.unpaired_candidates[0],
        )
    if slot.status == "missing_mate" and len(slot.read1_candidates) == 1:
        return LaneFiles(
            lane=slot.lane,
            chunk=slot.chunk,
            read1=slot.read1_candidates[0],
        )
    return None


def _issue_key(issue: ManifestIssue) -> tuple[str, str, str]:
    return issue.severity, issue.code, issue.message


__all__ = ["build_manifest"]
