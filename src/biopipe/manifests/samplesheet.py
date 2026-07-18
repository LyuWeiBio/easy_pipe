"""Deterministic candidate samplesheet generation."""

from __future__ import annotations

import csv
import io

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.manifests.integrity import require_valid_manifest
from biopipe.models import DatasetManifest


def render_samplesheet(manifest: DatasetManifest) -> str:
    """Render one stable row per retained lane without touching FASTQ files."""

    require_valid_manifest(manifest)
    if manifest.errors or manifest.classification.layout == "unknown" or not manifest.samples:
        raise BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "A samplesheet requires a non-empty manifest with a resolved layout.",
            context={
                "blocking_error_count": len(manifest.errors),
                "layout_resolved": manifest.classification.layout != "unknown",
                "sample_count": len(manifest.samples),
            },
            remediation=["Resolve manifest pairing and format errors first."],
        )
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["sample_id", "lane", "chunk", "read1", "read2"])
    for sample in sorted(manifest.samples, key=lambda item: item.sample_id):
        for lane in sorted(sample.lanes, key=lambda item: (item.lane, item.chunk or "")):
            writer.writerow(
                [
                    sample.sample_id,
                    lane.lane,
                    lane.chunk or "",
                    lane.read1,
                    lane.read2 or "",
                ]
            )
    return output.getvalue()


__all__ = ["render_samplesheet"]
