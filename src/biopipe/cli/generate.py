"""Generate a deterministic Nextflow project from reviewed M3 artifacts."""

from __future__ import annotations

from pathlib import Path

import typer

from biopipe.cli.common import emit, fail
from biopipe.compiler import compile_nextflow_project
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.io import read_model
from biopipe.models import DatasetManifest, ExecutionPlan, PipelineSpec, SoftwareLock
from biopipe.planner import reconstruct_planned_pipeline
from biopipe.registry import RegistryValidationError, load_default_registry


def generate_command(
    spec_path: Path = typer.Option(
        ...,
        "--spec",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Reviewed PipelineSpec YAML.",
    ),
    output: Path = typer.Option(
        ...,
        "--output",
        help="New generated-project directory; existing paths are never replaced.",
    ),
    manifest_path: Path | None = typer.Option(
        None,
        "--manifest",
        dir_okay=False,
        readable=True,
        help="Full manifest; defaults to the fixed sibling artifact.",
    ),
    execution_plan_path: Path | None = typer.Option(
        None,
        "--execution-plan",
        dir_okay=False,
        readable=True,
    ),
    software_lock_path: Path | None = typer.Option(
        None,
        "--software-lock",
        dir_okay=False,
        readable=True,
    ),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Compile the fixed graph after revalidating every planning artifact."""

    sibling_dir = spec_path.expanduser().parent
    selected_manifest = manifest_path or sibling_dir / "dataset.manifest.resolved.json"
    selected_execution_plan = execution_plan_path or sibling_dir / "execution.plan.yaml"
    selected_software_lock = software_lock_path or sibling_dir / "software.lock.yaml"
    try:
        spec = read_model(spec_path, PipelineSpec)
        manifest = read_model(selected_manifest, DatasetManifest)
        execution_plan = read_model(selected_execution_plan, ExecutionPlan)
        software_lock = read_model(selected_software_lock, SoftwareLock)
        registry = load_default_registry()
        planned = reconstruct_planned_pipeline(
            spec,
            execution_plan,
            software_lock,
            registry=registry,
        )
        generated = compile_nextflow_project(
            output,
            manifest=manifest,
            planned=planned,
            registry=registry,
        )
        result = {
            "status": "generated",
            "output_directory": str(generated.output_directory),
            "generation_fingerprint": generated.generation_fingerprint,
            "files": list(generated.files),
            "artifact_hashes": dict(sorted(generated.artifact_hashes.items())),
        }
    except RegistryValidationError:
        fail(
            BioPipeError(
                ErrorCode.VALIDATION_FAILED,
                "The reviewed component registry could not be loaded.",
                remediation=["Restore the packaged M3 registry and retry."],
            )
        )
    except BioPipeError as error:
        fail(error)
    emit(result, as_json=as_json)


__all__ = ["generate_command"]
