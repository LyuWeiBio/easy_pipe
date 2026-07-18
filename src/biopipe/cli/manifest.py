"""Dataset manifest inspection and explicit override commands."""

from __future__ import annotations

from pathlib import Path

import typer
from pydantic import BaseModel

from biopipe.cli.common import emit, fail
from biopipe.errors import BioPipeError
from biopipe.io import read_model
from biopipe.manifests import (
    ManifestArtifactStore,
    apply_overrides,
    render_samplesheet,
    require_valid_manifest,
    sanitize_manifest,
)
from biopipe.models import DatasetManifest, ManifestOverrides

manifest_app = typer.Typer(help="Inspect and resolve dataset manifests.", no_args_is_help=True)


@manifest_app.command("show")
def manifest_show(
    manifest_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Show sample, lane, pairing, warning, and integrity summaries."""

    try:
        manifest = require_valid_manifest(read_model(manifest_path, DatasetManifest))
        lanes = [lane for sample in manifest.samples for lane in sample.lanes]
        summary = {
            "manifest_version": manifest.manifest_version,
            "manifest_sha256": manifest.integrity.manifest_sha256,
            "source_id": manifest.source.source_id,
            "root": manifest.source.root,
            "dataset_type": manifest.classification.dataset_type,
            "layout": manifest.classification.layout,
            "confidence": manifest.classification.confidence,
            "sample_count": len(manifest.samples),
            "lane_count": len(lanes),
            "paired_lane_count": sum(lane.read2 is not None for lane in lanes),
            "samples": [
                {
                    "sample_id": sample.sample_id,
                    "lane_count": len(sample.lanes),
                    "paired_lane_count": sum(lane.read2 is not None for lane in sample.lanes),
                }
                for sample in sorted(manifest.samples, key=lambda item: item.sample_id)
            ],
            "warnings": [issue.code for issue in manifest.warnings],
            "blocking_errors": [issue.code for issue in manifest.errors],
        }
    except BioPipeError as error:
        fail(error)
    emit(summary, as_json=as_json)


@manifest_app.command("apply-overrides")
def manifest_apply_overrides(
    manifest_path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    overrides_path: Path = typer.Option(
        ...,
        "--overrides",
        exists=True,
        dir_okay=False,
        readable=True,
    ),
    output_dir: Path | None = typer.Option(None, "--output-dir", file_okay=False),
    name: str = typer.Option("dataset", "--name"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Apply an attributable override without modifying the original manifest."""

    try:
        original = require_valid_manifest(read_model(manifest_path, DatasetManifest))
        overrides = read_model(overrides_path, ManifestOverrides)
        application = apply_overrides(original, overrides)
        resolved = application.resolved_manifest
        sanitized = sanitize_manifest(resolved)
        samplesheet = None if resolved.errors else render_samplesheet(resolved)
        destination = output_dir.expanduser() if output_dir is not None else manifest_path.parent
        store = ManifestArtifactStore(destination)
        names = {
            "resolved_manifest": f"{name}.manifest.resolved.json",
            "sanitized_manifest": f"{name}.manifest.resolved.sanitized.json",
            "applied_override": f"{name}.override.applied.json",
            "override_diff": f"{name}.override.diff.json",
            "samplesheet": f"{name}.samplesheet.csv",
        }
        artifacts: dict[str, BaseModel | str] = {
            names["resolved_manifest"]: resolved,
            names["sanitized_manifest"]: sanitized,
            names["applied_override"]: overrides,
            names["override_diff"]: application.diff,
        }
        if samplesheet is not None:
            artifacts[names["samplesheet"]] = samplesheet
        paths = store.create_bundle(artifacts)
        created = {
            key: None if key == "samplesheet" and samplesheet is None else str(paths[value])
            for key, value in names.items()
        }
        result = {
            "status": "resolved_with_blocking_errors" if resolved.errors else "resolved",
            "manifest_sha256": resolved.integrity.manifest_sha256,
            "blocking_errors": [issue.code for issue in resolved.errors],
            "artifacts": created,
        }
    except BioPipeError as error:
        fail(error)
    emit(result, as_json=as_json)


__all__ = ["manifest_app", "manifest_apply_overrides", "manifest_show"]
