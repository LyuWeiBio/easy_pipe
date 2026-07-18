"""Deterministic planner for the fixed FASTQ-QC workflow."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Literal, cast

from pydantic import Field, field_validator, model_validator

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.manifests.integrity import require_valid_manifest
from biopipe.models import (
    DatasetManifest,
    ExecutionPaths,
    ExecutionPlan,
    PathMapping,
    PipelineAnalysis,
    PipelineExecution,
    PipelineInput,
    PipelineParameters,
    PipelinePaths,
    PipelineProject,
    PipelineSpec,
    PipelineStage,
    SoftwareLock,
    StrictModel,
    TrimmingParameters,
)
from biopipe.registry import (
    ArtifactType,
    ComponentRegistry,
    RegistryValidationError,
    load_default_registry,
)

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _safe_identifier(value: str, field_name: str) -> str:
    if not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"{field_name} must be a safe identifier")
    return value


def _absolute_path(value: str, field_name: str) -> str:
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{field_name} must be a safe absolute POSIX path")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field_name} must not contain control characters")
    return str(path)


def _paths_overlap(first: str, second: str) -> bool:
    first_path = PurePosixPath(first)
    second_path = PurePosixPath(second)
    return (
        first_path == second_path
        or first_path in second_path.parents
        or second_path in first_path.parents
    )


class PlanningOptions(StrictModel):
    """Explicit, controlled user choices for the fixed planner."""

    project_name: str
    trimming_enabled: bool = Field(strict=True)
    minimum_length: int | None = Field(default=None, ge=1, le=1_000, strict=True)
    manifest_path: Literal["dataset.manifest.resolved.json"] = "dataset.manifest.resolved.json"
    source_host: str | None = None
    execution_host: str | None = None
    execution_root: str | None = None
    executor: Literal["local", "slurm"] = "local"
    container_engine: Literal["apptainer", "docker"] = "apptainer"
    max_cpus: int = Field(default=4, ge=1, le=1_024, strict=True)
    max_memory_gb: int = Field(default=16, ge=1, le=16_384, strict=True)
    work_dir: str
    output_dir: str
    container_cache: str

    @field_validator("project_name")
    @classmethod
    def validate_project_name(cls, value: str) -> str:
        return _safe_identifier(value, "project_name")

    @field_validator("source_host", "execution_host")
    @classmethod
    def validate_hosts(cls, value: str | None) -> str | None:
        return None if value is None else _safe_identifier(value, "host")

    @field_validator("execution_root", "work_dir", "output_dir", "container_cache")
    @classmethod
    def validate_paths(cls, value: str | None) -> str | None:
        return None if value is None else _absolute_path(value, "planning path")

    @model_validator(mode="after")
    def validate_choices(self) -> PlanningOptions:
        if not self.trimming_enabled and self.minimum_length is not None:
            raise ValueError("minimum_length is only valid when trimming_enabled is true")
        execution_paths = (self.work_dir, self.output_dir, self.container_cache)
        for index, first in enumerate(execution_paths):
            for second in execution_paths[index + 1 :]:
                if _paths_overlap(first, second):
                    raise ValueError("work_dir, output_dir, and container_cache must not overlap")
        return self


class PlannedPipeline(StrictModel):
    """All deterministic planning artifacts consumed by the compiler."""

    planning_version: Literal["1.0"] = "1.0"
    spec: PipelineSpec
    execution_plan: ExecutionPlan
    software_lock: SoftwareLock
    registry_version: str
    component_ids: tuple[str, ...] = Field(min_length=1)

    @field_validator("registry_version")
    @classmethod
    def validate_registry_version(cls, value: str) -> str:
        if not value:
            raise ValueError("registry_version must not be empty")
        return value

    @field_validator("component_ids")
    @classmethod
    def validate_component_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("component_ids must not contain duplicates")
        return tuple(_safe_identifier(value, "component_id") for value in values)

    @model_validator(mode="after")
    def validate_artifact_consistency(self) -> PlannedPipeline:
        if self.software_lock.resolver_version != (f"component-registry/{self.registry_version}"):
            raise ValueError("software lock resolver version does not match registry_version")
        if self.spec.execution.executor != self.execution_plan.executor:
            raise ValueError("PipelineSpec and ExecutionPlan executor values must match")
        if self.spec.paths.work_dir != self.execution_plan.paths.work_dir:
            raise ValueError("PipelineSpec and ExecutionPlan work_dir values must match")
        if self.spec.paths.output_dir != self.execution_plan.paths.output_dir:
            raise ValueError("PipelineSpec and ExecutionPlan output_dir values must match")
        if self.spec.paths.container_cache != self.execution_plan.paths.container_cache:
            raise ValueError("PipelineSpec and ExecutionPlan container_cache values must match")
        writable_paths = (
            self.spec.paths.work_dir,
            self.spec.paths.output_dir,
            self.spec.paths.container_cache,
        )
        for index, first in enumerate(writable_paths):
            for second in writable_paths[index + 1 :]:
                if _paths_overlap(first, second):
                    raise ValueError("planned writable paths must not overlap")
        for writable_path in writable_paths:
            for raw_root in {
                self.execution_plan.paths.source_root,
                self.execution_plan.paths.execution_root,
            }:
                if _paths_overlap(writable_path, raw_root):
                    raise ValueError("planned writable paths must not overlap FASTQ input roots")
        return self

    @property
    def pipeline_spec(self) -> PipelineSpec:
        """Compatibility alias for callers that prefer the full artifact name."""

        return self.spec


def plan_fastq_qc(
    manifest: DatasetManifest,
    options: PlanningOptions,
    registry: ComponentRegistry | None = None,
) -> PlannedPipeline:
    """Plan the fixed QC graph from one finalized, error-free manifest."""

    require_valid_manifest(manifest)
    if manifest.privacy.artifact_scope != "full":
        raise BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "Sanitized manifests are review artifacts and cannot be planned for execution.",
            context={"artifact_scope": manifest.privacy.artifact_scope},
            remediation=["Use the integrity-verified local full manifest for planning."],
        )
    if manifest.errors:
        raise BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "The dataset manifest still contains blocking errors.",
            context={"issue_codes": sorted({issue.code for issue in manifest.errors})},
            remediation=["Resolve manifest errors with an attributable override before planning."],
        )
    if manifest.classification.layout not in {"single_end", "paired_end"}:
        raise BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "The dataset layout must be resolved before FASTQ-QC planning.",
            context={"layout": manifest.classification.layout},
            remediation=["Inspect pairing evidence and resolve the manifest layout."],
        )
    if manifest.classification.dataset_type == "unknown" or not manifest.samples:
        raise BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "The manifest does not contain a supported FASTQ dataset.",
            context={"dataset_type": manifest.classification.dataset_type},
            remediation=["Create a resolved generic_fastq or illumina_fastq manifest."],
        )

    try:
        selected_registry = registry or load_default_registry()
    except RegistryValidationError as exc:
        raise _planning_registry_error() from exc
    layout = cast(
        Literal["single_end", "paired_end"],
        manifest.classification.layout,
    )
    component_ids = _component_ids(
        layout=layout,
        trimming_enabled=options.trimming_enabled,
    )
    input_type: ArtifactType = "single_fastq" if layout == "single_end" else "paired_fastq"
    execution_root = options.execution_root or manifest.source.root
    for writable_path in (options.work_dir, options.output_dir, options.container_cache):
        for raw_root in {manifest.source.root, execution_root}:
            if _paths_overlap(writable_path, raw_root):
                raise BioPipeError(
                    ErrorCode.VALIDATION_FAILED,
                    "Execution paths must not overlap immutable FASTQ input roots.",
                    context={"reason": "rawdata_path_overlap"},
                    remediation=["Choose separate work, output, and container-cache directories."],
                )
    try:
        selected_components = selected_registry.validate_graph(component_ids, input_type)
        minimum_length = _minimum_length(selected_registry, component_ids, options)
    except RegistryValidationError as exc:
        raise _planning_registry_error() from exc
    if any(
        component.resources.cpus > options.max_cpus
        or component.resources.memory_gb > options.max_memory_gb
        for component in selected_components
    ):
        raise BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "Execution resource limits are below a selected component requirement.",
            context={"reason": "component_resources_exceed_plan"},
            remediation=["Increase max_cpus or max_memory_gb for the fixed component graph."],
        )

    stages: list[PipelineStage] = (
        ["raw_fastqc", "optional_trimming", "post_trim_fastqc", "multiqc"]
        if options.trimming_enabled
        else ["raw_fastqc", "multiqc"]
    )
    specification = PipelineSpec(
        project=PipelineProject(name=options.project_name),
        input=PipelineInput(
            manifest=options.manifest_path,
            layout=layout,
        ),
        analysis=PipelineAnalysis(stages=stages),
        parameters=PipelineParameters(
            trimming=TrimmingParameters(
                enabled=options.trimming_enabled,
                minimum_length=minimum_length,
            )
        ),
        execution=PipelineExecution(
            executor=options.executor,
            container_engine=options.container_engine,
            max_cpus=options.max_cpus,
            max_memory_gb=options.max_memory_gb,
        ),
        paths=PipelinePaths(
            work_dir=options.work_dir,
            output_dir=options.output_dir,
            container_cache=options.container_cache,
        ),
    )

    source_host = options.source_host or manifest.source.source_id
    execution_host = options.execution_host or source_host
    mapping = (
        None
        if execution_root == manifest.source.root
        else [
            PathMapping(
                source_prefix=manifest.source.root,
                execution_prefix=execution_root,
            )
        ]
    )
    execution_plan = ExecutionPlan(
        source_host=source_host,
        execution_host=execution_host,
        executor=options.executor,
        paths=ExecutionPaths(
            source_root=manifest.source.root,
            execution_root=execution_root,
            work_dir=options.work_dir,
            output_dir=options.output_dir,
            container_cache=options.container_cache,
        ),
        path_mapping=mapping,
    )

    try:
        software_lock = selected_registry.software_lock(component_ids)
    except RegistryValidationError as exc:
        raise _planning_registry_error() from exc
    return reconstruct_planned_pipeline(
        specification,
        execution_plan,
        software_lock,
        registry=selected_registry,
    )


def component_ids_for_spec(spec: PipelineSpec) -> tuple[str, ...]:
    """Derive the only allowed registry graph for a validated PipelineSpec."""

    return _component_ids(
        layout=spec.input.layout,
        trimming_enabled=spec.parameters.trimming.enabled,
    )


def reconstruct_planned_pipeline(
    spec: PipelineSpec,
    execution_plan: ExecutionPlan,
    software_lock: SoftwareLock,
    *,
    registry: ComponentRegistry | None = None,
) -> PlannedPipeline:
    """Rebuild a compiler input from strict artifacts and verify registry consistency."""

    spec = PipelineSpec.model_validate(spec.model_dump(mode="python"))
    execution_plan = ExecutionPlan.model_validate(execution_plan.model_dump(mode="python"))
    software_lock = SoftwareLock.model_validate(software_lock.model_dump(mode="python"))
    try:
        selected_registry = registry or load_default_registry()
    except RegistryValidationError as exc:
        raise _planning_registry_error() from exc
    component_ids = component_ids_for_spec(spec)
    input_type: ArtifactType = (
        "single_fastq" if spec.input.layout == "single_end" else "paired_fastq"
    )
    try:
        selected_components = selected_registry.validate_graph(component_ids, input_type)
        if spec.parameters.trimming.enabled:
            fastp_id = next(
                component_id for component_id in component_ids if "fastp_" in component_id
            )
            selected_registry.validate_parameters(
                fastp_id,
                {"minimum_length": spec.parameters.trimming.minimum_length},
            )
        expected_lock = selected_registry.software_lock(component_ids)
    except RegistryValidationError as exc:
        raise _planning_registry_error() from exc
    if any(
        component.resources.cpus > spec.execution.max_cpus
        or component.resources.memory_gb > spec.execution.max_memory_gb
        for component in selected_components
    ):
        raise BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "Execution resource limits are below a selected component requirement.",
            context={"reason": "component_resources_exceed_plan"},
            remediation=["Increase max_cpus or max_memory_gb for the fixed component graph."],
        )
    if software_lock != expected_lock:
        raise BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "The software lock does not match the selected component registry graph.",
            context={"registry_version": selected_registry.version},
            remediation=["Recreate the software lock from the reviewed component registry."],
        )
    return PlannedPipeline(
        spec=spec,
        execution_plan=execution_plan,
        software_lock=software_lock,
        registry_version=selected_registry.version,
        component_ids=component_ids,
    )


def _planning_registry_error() -> BioPipeError:
    return BioPipeError(
        ErrorCode.VALIDATION_FAILED,
        "The reviewed component registry cannot satisfy the fixed FASTQ-QC plan.",
        context={"reason": "registry_validation_failed"},
        remediation=["Restore a valid, versioned component registry before planning."],
    )


def _component_ids(
    *,
    layout: Literal["single_end", "paired_end"],
    trimming_enabled: bool,
) -> tuple[str, ...]:
    if not trimming_enabled:
        return "fastqc_raw_v1", "multiqc_v1"
    fastp = "fastp_single_v1" if layout == "single_end" else "fastp_paired_v1"
    return "fastqc_raw_v1", fastp, "fastqc_post_trim_v1", "multiqc_v1"


def _minimum_length(
    registry: ComponentRegistry,
    component_ids: tuple[str, ...],
    options: PlanningOptions,
) -> int:
    if options.trimming_enabled:
        fastp_id = next(component_id for component_id in component_ids if "fastp_" in component_id)
        requested = (
            {} if options.minimum_length is None else {"minimum_length": options.minimum_length}
        )
        return registry.validate_parameters(fastp_id, requested)["minimum_length"]

    single_default = registry.get("fastp_single_v1").parameters["minimum_length"].default
    paired_default = registry.get("fastp_paired_v1").parameters["minimum_length"].default
    if single_default != paired_default:
        raise ValueError("default registry fastp minimum_length values must match")
    return single_default


__all__ = [
    "PlannedPipeline",
    "PlanningOptions",
    "component_ids_for_spec",
    "plan_fastq_qc",
    "reconstruct_planned_pipeline",
]
