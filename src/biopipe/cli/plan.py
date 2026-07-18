"""Create the reviewed artifacts for the fixed FASTQ-QC planning target."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Literal, cast

import typer
import yaml
from pydantic import BaseModel, ValidationError

from biopipe.cli.common import emit, fail, validation_error
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.io import read_model
from biopipe.manifests import ManifestArtifactStore
from biopipe.models import DatasetManifest
from biopipe.planner import PlanningOptions, plan_fastq_qc
from biopipe.registry import RegistryValidationError, load_default_registry

_RESOLVED_MANIFEST_NAME = "dataset.manifest.resolved.json"
_EXECUTION_PLAN_NAME = "execution.plan.yaml"
_SOFTWARE_LOCK_NAME = "software.lock.yaml"
_YAML_SUFFIXES = {".yaml", ".yml"}


def plan_command(
    manifest_path: Path = typer.Option(
        ...,
        "--manifest",
        exists=True,
        dir_okay=False,
        readable=True,
        help="Integrity-verified full dataset manifest.",
    ),
    goal: str = typer.Option("fastq-qc", "--goal", help="Fixed analysis goal."),
    output: Path = typer.Option(
        ...,
        "--output",
        dir_okay=False,
        help="Destination PipelineSpec YAML; sibling planning artifacts are also created.",
    ),
    project_name: str = typer.Option("fastq-qc", "--project-name"),
    trimming_enabled: bool = typer.Option(
        False,
        "--trimming/--no-trimming",
        help="Enable the reviewed fastp stage.",
    ),
    minimum_length: int | None = typer.Option(
        None,
        "--minimum-length",
        min=1,
        max=1_000,
        help="Controlled fastp minimum read length; valid only with --trimming.",
    ),
    executor: str = typer.Option("local", "--executor", help="local or slurm."),
    container_engine: str = typer.Option(
        "apptainer",
        "--container-engine",
        help="apptainer or docker.",
    ),
    source_host: str | None = typer.Option(None, "--source-host"),
    execution_host: str | None = typer.Option(None, "--execution-host"),
    execution_root: str | None = typer.Option(
        None,
        "--execution-root",
        help="Absolute POSIX raw-data root visible on the execution host.",
    ),
    work_dir: str | None = typer.Option(None, "--work-dir"),
    results_dir: str | None = typer.Option(None, "--results-dir"),
    container_cache: str | None = typer.Option(None, "--container-cache"),
    max_cpus: int = typer.Option(4, "--max-cpus", min=1, max=1_024),
    max_memory_gb: int = typer.Option(16, "--max-memory-gb", min=1, max=16_384),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Plan the only supported M3 target and create immutable review artifacts."""

    try:
        if goal != "fastq-qc":
            raise BioPipeError(
                ErrorCode.VALIDATION_FAILED,
                "Only the fixed fastq-qc planning goal is supported.",
                context={"goal": goal},
                remediation=["Use --goal fastq-qc."],
            )
        _validate_spec_destination(output)
        manifest = read_model(manifest_path, DatasetManifest)
        effective_root = execution_root or manifest.source.root
        defaults = _default_execution_paths(effective_root, project_name)
        options = PlanningOptions(
            project_name=project_name,
            trimming_enabled=trimming_enabled,
            minimum_length=minimum_length,
            source_host=source_host,
            execution_host=execution_host,
            execution_root=execution_root,
            executor=cast(Literal["local", "slurm"], executor),
            container_engine=cast(Literal["apptainer", "docker"], container_engine),
            max_cpus=max_cpus,
            max_memory_gb=max_memory_gb,
            work_dir=work_dir or defaults[0],
            output_dir=results_dir or defaults[1],
            container_cache=container_cache or defaults[2],
        )
        registry = load_default_registry()
        planned = plan_fastq_qc(manifest, options, registry)
        paths = _create_plan_bundle(
            output=output,
            manifest_path=manifest_path,
            manifest=manifest,
            spec=planned.spec,
            execution_plan=planned.execution_plan,
            software_lock=planned.software_lock,
        )
        result = {
            "status": "planned",
            "goal": "fastq-qc",
            "registry_version": planned.registry_version,
            "components": list(planned.component_ids),
            "artifacts": {name: str(path) for name, path in sorted(paths.items())},
        }
    except ValidationError as error:
        validation_error(error)
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


def _default_execution_paths(root: str, project_name: str) -> tuple[str, str, str]:
    raw_root = PurePosixPath(root)
    if not raw_root.is_absolute() or raw_root == PurePosixPath("/"):
        raise BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "Safe execution paths cannot be derived from this raw-data root.",
            remediation=[
                "Provide separate --work-dir, --results-dir, and --container-cache paths."
            ],
        )
    parent = raw_root.parent
    return (
        str(parent / ".biopipe-work" / project_name),
        str(parent / ".biopipe-results" / project_name),
        str(parent / ".biopipe-containers"),
    )


def _validate_spec_destination(output: Path) -> None:
    if output.suffix.lower() not in _YAML_SUFFIXES:
        raise BioPipeError(
            ErrorCode.SERIALIZATION_FAILED,
            "PipelineSpec output must end in .yaml or .yml.",
            context={"suffix": output.suffix.lower()},
            remediation=["Choose a YAML output filename."],
        )
    if output.name in {_EXECUTION_PLAN_NAME, _SOFTWARE_LOCK_NAME}:
        raise BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "PipelineSpec output collides with a reserved sibling artifact name.",
            context={"artifact": output.name},
            remediation=["Use pipeline.spec.yaml or another distinct YAML filename."],
        )


def _create_plan_bundle(
    *,
    output: Path,
    manifest_path: Path,
    manifest: DatasetManifest,
    spec: BaseModel,
    execution_plan: BaseModel,
    software_lock: BaseModel,
) -> dict[str, Path]:
    destination_dir = output.expanduser().parent
    artifacts: dict[str, str] = {
        output.name: _yaml_model(spec),
        _EXECUTION_PLAN_NAME: _yaml_model(execution_plan),
        _SOFTWARE_LOCK_NAME: _yaml_model(software_lock),
    }
    manifest_destination = destination_dir / _RESOLVED_MANIFEST_NAME
    try:
        source_manifest = manifest_path.expanduser().resolve(strict=True)
        same_manifest = source_manifest == manifest_destination.resolve(strict=True)
    except FileNotFoundError:
        same_manifest = False
    if not same_manifest:
        artifacts[_RESOLVED_MANIFEST_NAME] = _json_model(manifest)
    created = ManifestArtifactStore(destination_dir).create_bundle(artifacts)
    if same_manifest:
        created[_RESOLVED_MANIFEST_NAME] = manifest_destination
    return created


def _yaml_model(model: BaseModel) -> str:
    return yaml.safe_dump(
        model.model_dump(mode="json", exclude_none=False),
        allow_unicode=True,
        sort_keys=True,
    )


def _json_model(model: BaseModel) -> str:
    return (
        json.dumps(
            model.model_dump(mode="json", exclude_none=False),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


__all__ = ["plan_command"]
