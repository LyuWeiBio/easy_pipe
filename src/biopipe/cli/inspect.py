"""Bounded metadata or FASTQ-manifest inspection commands."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from pydantic import BaseModel

from biopipe.cli.common import controller_config_dir, emit, fail
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.inspection import inspect_fastq_dataset
from biopipe.manifests import ManifestArtifactStore, render_samplesheet, sanitize_manifest
from biopipe.probe import OpenSSHProbeClient
from biopipe.sources import SourceRegistry


def _split_target(target: str) -> tuple[str, str]:
    source_id, separator, root = target.partition(":")
    if not separator or not source_id or not root:
        raise BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "Inspection target must use SOURCE_ID:/absolute/path syntax.",
            remediation=["Example: hpc01:/data/raw/run42"],
        )
    return source_id, root


def inspect_command(
    target: str = typer.Argument(..., help="SOURCE_ID:/absolute/path"),
    policy: str = typer.Option("metadata-only", "--policy"),
    output: Path | None = typer.Option(None, "--output"),
    sample_fastq_records: int = typer.Option(1_000, "--sample-fastq-records", min=1, max=100_000),
    config_dir: Path | None = typer.Option(None, "--config-dir", hidden=True),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Return metadata or a privacy-bounded FASTQ manifest from a Source Host."""

    try:
        normalized_policy = policy.replace("_", "-")
        if normalized_policy not in {"metadata-only", "format-summary"}:
            raise BioPipeError(
                ErrorCode.VALIDATION_FAILED,
                "Inspection policy must be metadata-only or format-summary.",
                remediation=["Use --policy metadata-only or --policy format-summary."],
            )
        source_id, root = _split_target(target)
        base = config_dir.expanduser() if config_dir is not None else controller_config_dir()
        profile = SourceRegistry(base / "sources").get(source_id)
        client = OpenSSHProbeClient(
            max_stdout_bytes=profile.probe.max_response_bytes,
            max_stderr_bytes=profile.probe.stderr_limit_bytes,
        )
        result: BaseModel
        if normalized_policy == "metadata-only":
            response = client.list_tree(profile, root)
            if output is not None:
                payload = json.dumps(
                    response.model_dump(mode="json"),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                ManifestArtifactStore(output.parent).create_text(output.name, payload + "\n")
            result = response
        else:
            manifest = inspect_fastq_dataset(
                profile,
                root,
                client=client,
                sample_fastq_records=sample_fastq_records,
            )
            if output is not None:
                if output.suffix.lower() != ".json":
                    raise BioPipeError(
                        ErrorCode.VALIDATION_FAILED,
                        "A manifest output filename must end in .json.",
                    )
                store = ManifestArtifactStore(output.parent)
                artifacts: dict[str, BaseModel | str] = {
                    output.name: manifest,
                    f"{output.stem}.sanitized.json": sanitize_manifest(manifest),
                }
                if not manifest.errors:
                    artifacts[f"{output.stem}.samplesheet.csv"] = render_samplesheet(manifest)
                store.create_bundle(artifacts)
            result = manifest
    except BioPipeError as error:
        fail(error)
    emit(result, as_json=as_json)


__all__ = ["inspect_command"]
