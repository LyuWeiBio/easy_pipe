"""Deterministic compiler from reviewed M3 artifacts to Nextflow DSL2."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol
from uuid import NAMESPACE_URL, uuid5

import yaml
from pydantic import BaseModel

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.manifests.integrity import require_valid_manifest
from biopipe.models import (
    AuditEvent,
    DatasetManifest,
    ExecutionApproval,
    ExecutionPlan,
    PipelinePolicy,
    PipelineSpec,
    PreflightRequirements,
    SoftwareLock,
)
from biopipe.registry import (
    ArtifactType,
    ComponentDefinition,
    ComponentRegistry,
    RegistryValidationError,
    load_default_registry,
)
from biopipe.version import COMPILER_VERSION

from .store import ProjectBundleStore
from .templates import StrictTemplateRenderer

_RESOLVED_MANIFEST = "dataset.manifest.resolved.json"
_LATEST_TOKEN = re.compile(r"(?i)(?:^|[^A-Za-z0-9_.-])latest(?:$|[^A-Za-z0-9_.-])")
_COMPONENT_METADATA: Mapping[str, tuple[str, str]] = {
    "fastqc_raw_v1": ("fastqc", "templates/components/fastqc/main.nf.j2"),
    "fastp_single_v1": ("fastp_single", "templates/components/fastp_single/main.nf.j2"),
    "fastp_paired_v1": ("fastp_paired", "templates/components/fastp_paired/main.nf.j2"),
    "fastqc_post_trim_v1": (
        "fastqc_post_trim",
        "templates/components/fastqc_post_trim/main.nf.j2",
    ),
    "multiqc_v1": ("multiqc", "templates/components/multiqc/main.nf.j2"),
}


class PlannedPipelineLike(Protocol):
    """The stable planner result consumed by the compiler."""

    spec: PipelineSpec
    execution_plan: ExecutionPlan
    software_lock: SoftwareLock
    registry_version: str
    component_ids: tuple[str, ...]


@dataclass(frozen=True)
class GeneratedProject:
    """Description of a successfully published immutable project bundle."""

    output_directory: Path
    files: tuple[str, ...]
    artifact_hashes: Mapping[str, str]
    generation_fingerprint: str


@dataclass(frozen=True)
class _ProcessSettings:
    label: str
    cpus: int
    memory: str
    container: str


class NextflowCompiler:
    """Compile a fixed FASTQ-QC graph using reviewed templates only."""

    def __init__(self) -> None:
        self._renderer = StrictTemplateRenderer()

    def compile_planned(
        self,
        output_directory: str | Path,
        *,
        manifest: DatasetManifest,
        planned: PlannedPipelineLike,
        registry: ComponentRegistry,
    ) -> GeneratedProject:
        """Compile a planner result after verifying its registry provenance."""

        if planned.registry_version != registry.version:
            raise self._validation_error("The plan and component registry versions differ.")
        return self.compile(
            output_directory,
            manifest=manifest,
            spec=planned.spec,
            execution_plan=planned.execution_plan,
            software_lock=planned.software_lock,
            registry=registry,
            component_ids=planned.component_ids,
        )

    def compile(
        self,
        output_directory: str | Path,
        *,
        manifest: DatasetManifest,
        spec: PipelineSpec,
        execution_plan: ExecutionPlan,
        software_lock: SoftwareLock,
        registry: ComponentRegistry,
        component_ids: Sequence[str],
    ) -> GeneratedProject:
        """Render and create one complete project without replacing any path."""

        selected = self._validate_inputs(
            manifest,
            spec,
            execution_plan,
            software_lock,
            registry,
            component_ids,
        )
        artifacts = self._render_artifacts(
            manifest,
            spec,
            execution_plan,
            software_lock,
            registry,
            selected,
        )
        self._reject_latest_tokens(artifacts)
        fingerprint = _generation_fingerprint(artifacts, registry)
        artifacts["audit/events.jsonl"] = self._audit_event(
            manifest,
            spec,
            artifacts,
            registry,
            fingerprint,
        )
        self._reject_latest_tokens(artifacts)

        files = ProjectBundleStore(output_directory).create(artifacts)
        hashes = {name: _sha256(artifacts[name]) for name in files}
        return GeneratedProject(
            output_directory=Path(output_directory).expanduser(),
            files=files,
            artifact_hashes=hashes,
            generation_fingerprint=fingerprint,
        )

    def _validate_inputs(
        self,
        manifest: DatasetManifest,
        spec: PipelineSpec,
        execution_plan: ExecutionPlan,
        software_lock: SoftwareLock,
        registry: ComponentRegistry,
        component_ids: Sequence[str],
    ) -> tuple[ComponentDefinition, ...]:
        require_valid_manifest(manifest)
        if manifest.privacy.artifact_scope != "full":
            raise self._validation_error(
                "Project generation requires the full resolved manifest, not a sanitized artifact."
            )
        if manifest.errors or not manifest.samples or manifest.classification.layout == "unknown":
            raise self._validation_error(
                "Project generation requires a non-empty manifest without blocking errors."
            )
        if spec.input.manifest != _RESOLVED_MANIFEST:
            raise self._validation_error(
                f"PipelineSpec input.manifest must be {_RESOLVED_MANIFEST!r}."
            )
        if manifest.classification.layout != spec.input.layout:
            raise self._validation_error("The manifest and PipelineSpec layouts differ.")
        if execution_plan.executor != spec.execution.executor:
            raise self._validation_error("The PipelineSpec and execution plan executors differ.")
        if execution_plan.paths.source_root != manifest.source.root:
            raise self._validation_error(
                "The execution plan source root differs from the manifest."
            )
        if (
            execution_plan.paths.work_dir != spec.paths.work_dir
            or execution_plan.paths.output_dir != spec.paths.output_dir
            or execution_plan.paths.container_cache != spec.paths.container_cache
        ):
            raise self._validation_error("PipelineSpec and execution plan paths differ.")
        if spec.policy.overwrite_existing_outputs:
            raise self._validation_error(
                "Generated projects must keep output replacement disabled."
            )
        if spec.policy != PipelinePolicy() or execution_plan.approval != ExecutionApproval():
            raise self._validation_error(
                "Project generation requires the default-deny execution policy."
            )
        if execution_plan.preflight != PreflightRequirements():
            raise self._validation_error(
                "Project generation requires the complete execution preflight contract."
            )
        expected_stages = (
            ["raw_fastqc", "optional_trimming", "post_trim_fastqc", "multiqc"]
            if spec.parameters.trimming.enabled
            else ["raw_fastqc", "multiqc"]
        )
        if spec.analysis.stages != expected_stages:
            raise self._validation_error("PipelineSpec stages do not match the fixed FASTQ-QC DAG.")
        immutable_roots = (manifest.source.root, execution_plan.paths.execution_root)
        writable_paths = (
            spec.paths.work_dir,
            spec.paths.output_dir,
            spec.paths.container_cache,
        )
        if any(
            _paths_overlap(writable, immutable)
            for writable in writable_paths
            for immutable in immutable_roots
        ) or any(
            _paths_overlap(first, second)
            for index, first in enumerate(writable_paths)
            for second in writable_paths[index + 1 :]
        ):
            raise self._validation_error(
                "Input, work, output, and container-cache paths must not overlap."
            )

        expected = _expected_component_ids(
            layout=spec.input.layout,
            trimming_enabled=spec.parameters.trimming.enabled,
        )
        selected_ids = tuple(component_ids)
        if selected_ids != expected:
            raise self._validation_error(
                "The selected component graph is not the fixed FASTQ-QC graph."
            )
        reviewed_registry = load_default_registry()
        if registry.document != reviewed_registry.document:
            raise self._validation_error(
                "The component registry is not the reviewed default registry."
            )
        input_type: ArtifactType = (
            "paired_fastq" if spec.input.layout == "paired_end" else "single_fastq"
        )
        try:
            selected = registry.validate_graph(selected_ids, input_type)
            expected_lock = registry.software_lock(selected_ids)
        except RegistryValidationError as exc:
            raise self._validation_error("The selected registry graph is invalid.") from exc
        if software_lock != expected_lock:
            raise self._validation_error(
                "The software lock does not match the selected registry graph."
            )

        for component in selected:
            expected_metadata = _COMPONENT_METADATA.get(component.component_id)
            if expected_metadata != (component.template.key, component.template.nextflow):
                raise self._validation_error(
                    "A component references an unreviewed template identity."
                )
            if (
                component.resources.cpus > spec.execution.max_cpus
                or component.resources.memory_gb > spec.execution.max_memory_gb
            ):
                raise self._validation_error(
                    "A selected component exceeds the PipelineSpec resource ceiling."
                )
            locked = software_lock.components.get(component.tool.name)
            if locked is None or (
                locked.version != component.tool.version
                or locked.image != component.container.image
                or locked.digest != component.container.digest
                or locked.license != component.tool.license
            ):
                raise self._validation_error("A component does not match its software lock entry.")

        if spec.parameters.trimming.enabled:
            fastp_id = "fastp_paired_v1" if spec.input.layout == "paired_end" else "fastp_single_v1"
            try:
                resolved = registry.validate_parameters(
                    fastp_id,
                    {"minimum_length": spec.parameters.trimming.minimum_length},
                )
            except RegistryValidationError as exc:
                raise self._validation_error("The controlled fastp parameter is invalid.") from exc
            definition = registry.get(fastp_id).parameters.get("minimum_length")
            if (
                resolved != {"minimum_length": spec.parameters.trimming.minimum_length}
                or definition is None
                or definition.cli_flag != "--length_required"
            ):
                raise self._validation_error("The fastp parameter mapping is not reviewed.")
        return selected

    def _render_artifacts(
        self,
        manifest: DatasetManifest,
        spec: PipelineSpec,
        execution_plan: ExecutionPlan,
        software_lock: SoftwareLock,
        registry: ComponentRegistry,
        selected: tuple[ComponentDefinition, ...],
    ) -> dict[str, bytes]:
        trimming = spec.parameters.trimming.enabled
        paired = spec.input.layout == "paired_end"
        components = {component.component_id: component for component in selected}
        processes = [
            _process_settings("fastqc_raw", components["fastqc_raw_v1"]),
        ]
        if trimming:
            fastp_id = "fastp_paired_v1" if paired else "fastp_single_v1"
            processes.extend(
                [
                    _process_settings("fastp", components[fastp_id]),
                    _process_settings("fastqc_post_trim", components["fastqc_post_trim_v1"]),
                ]
            )
        processes.append(_process_settings("multiqc", components["multiqc_v1"]))

        common: dict[str, object] = {
            "paired_end": paired,
            "trimming_enabled": trimming,
        }
        fixture_directory = "paired_end" if paired else "single_end"
        fixture_sample_id = "synthetic_pe_001" if paired else "synthetic_se_001"
        fixture_read1 = "synthetic_pe_R1.fastq" if paired else "synthetic_se_R1.fastq"
        nf_test_context: dict[str, object] = {
            **common,
            "expected_task_count": 4 if trimming else 2,
            "fixture_directory": fixture_directory,
            "layout_label": "paired-end" if paired else "single-end",
            "read1_name": fixture_read1,
            "read2_name": "synthetic_pe_R2.fastq",
            "sample_id": fixture_sample_id,
        }
        artifacts: dict[str, bytes] = {
            "LICENSE": self._renderer.render("project/LICENSE.j2", {}),
            "main.nf": self._renderer.render("project/main.nf.j2", common),
            "nextflow.config": self._renderer.render(
                "project/nextflow.config.j2",
                {
                    "project_name": spec.project.name,
                    "source_root": execution_plan.paths.execution_root,
                    "output_dir": spec.paths.output_dir,
                    "work_dir": spec.paths.work_dir,
                    "container_cache": spec.paths.container_cache,
                    "apptainer_enabled": spec.execution.container_engine == "apptainer",
                },
            ),
            "conf/base.config": self._renderer.render(
                "project/conf/base.config.j2",
                {"processes": processes},
            ),
            "conf/local.config": self._renderer.render(
                "project/conf/local.config.j2",
                {"queue_size": spec.execution.max_cpus},
            ),
            "conf/slurm.config": self._renderer.render(
                "project/conf/slurm.config.j2",
                {"queue_size": spec.execution.max_cpus},
            ),
            "nf-test.config": self._renderer.render(
                "project/nf-test.config.j2",
                {},
            ),
            "tests/nextflow.config": self._renderer.render(
                "project/tests/nextflow.config.j2",
                {"max_cpus": spec.execution.max_cpus},
            ),
            "tests/pipeline.nf.test": self._renderer.render(
                "project/tests/pipeline.nf.test.j2",
                nf_test_context,
            ),
            "tests/fixtures/README.md": self._renderer.render(
                "project/tests/fixtures/README.md.j2",
                {},
            ),
            "tests/fixtures/single_end/fixture.json": self._renderer.render(
                "project/tests/fixtures/single_end/fixture.json.j2",
                {},
            ),
            "tests/fixtures/single_end/reads/synthetic_se_R1.fastq": self._renderer.render(
                "project/tests/fixtures/single_end/reads/synthetic_se_R1.fastq.j2",
                {},
            ),
            "tests/fixtures/paired_end/fixture.json": self._renderer.render(
                "project/tests/fixtures/paired_end/fixture.json.j2",
                {},
            ),
            "tests/fixtures/paired_end/reads/synthetic_pe_R1.fastq": self._renderer.render(
                "project/tests/fixtures/paired_end/reads/synthetic_pe_R1.fastq.j2",
                {},
            ),
            "tests/fixtures/paired_end/reads/synthetic_pe_R2.fastq": self._renderer.render(
                "project/tests/fixtures/paired_end/reads/synthetic_pe_R2.fastq.j2",
                {},
            ),
            "modules/fastqc/raw.nf": self._renderer.render(
                _component_template(components["fastqc_raw_v1"]),
                {
                    **common,
                    "process_name": "FASTQC_RAW",
                    "process_label": "fastqc_raw",
                    "result_subdir": "fastqc_raw",
                    "report_label": "raw",
                    "report_arity": "2" if paired else "1",
                    "raw_inputs": True,
                },
            ),
            "modules/multiqc/main.nf": self._renderer.render(
                _component_template(components["multiqc_v1"]),
                {},
            ),
            "assets/samplesheet.csv": _render_execution_samplesheet(
                manifest,
                execution_plan,
            ).encode("utf-8"),
            _RESOLVED_MANIFEST: _json_model(manifest),
            "pipeline.spec.yaml": _yaml_model(spec),
            "execution.plan.yaml": _yaml_model(execution_plan),
            "software.lock.yaml": _yaml_model(software_lock),
            "README.md": self._renderer.render(
                "project/README.md.j2",
                {
                    **common,
                    "project_name": spec.project.name,
                    "layout": spec.input.layout,
                    "trimming_label": "enabled" if trimming else "disabled",
                    "registry_version": registry.version,
                    "warning_codes": sorted({issue.code for issue in manifest.warnings}),
                    "warning_count": len(manifest.warnings),
                },
            ),
        }
        if trimming:
            common["minimum_length"] = spec.parameters.trimming.minimum_length
            artifacts["modules/fastp/main.nf"] = self._renderer.render(
                _component_template(components[fastp_id]),
                common,
            )
            artifacts["modules/fastqc/post_trim.nf"] = self._renderer.render(
                _component_template(components["fastqc_post_trim_v1"]),
                {
                    **common,
                    "process_name": "FASTQC_POST_TRIM",
                    "process_label": "fastqc_post_trim",
                    "result_subdir": "fastqc_trimmed",
                    "report_label": "trimmed",
                    "report_arity": "2" if paired else "1",
                    "raw_inputs": False,
                },
            )
        return artifacts

    @staticmethod
    def _audit_event(
        manifest: DatasetManifest,
        spec: PipelineSpec,
        artifacts: Mapping[str, bytes],
        registry: ComponentRegistry,
        fingerprint: str,
    ) -> bytes:
        input_names = (
            _RESOLVED_MANIFEST,
            "pipeline.spec.yaml",
            "execution.plan.yaml",
            "software.lock.yaml",
        )
        output_names = sorted(set(artifacts) - set(input_names))
        registry_payload = _json_model(registry.document)
        event = AuditEvent(
            event_id=uuid5(NAMESPACE_URL, f"easy-pipe/compiler/v1/{fingerprint}"),
            timestamp=manifest.source.scanned_at,
            event_type="PIPELINE_GENERATED",
            project_id=spec.project.name,
            actor="biopipe_compiler",
            input_hashes={
                **{name: _sha256(artifacts[name]) for name in input_names},
                "component.registry.json": _sha256(registry_payload),
            },
            output_hashes={name: _sha256(artifacts[name]) for name in output_names},
            status="success",
            summary=f"Deterministic Nextflow project generated by compiler {COMPILER_VERSION}.",
        )
        return (
            json.dumps(
                event.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")

    @staticmethod
    def _reject_latest_tokens(artifacts: Mapping[str, bytes]) -> None:
        for name, payload in artifacts.items():
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise NextflowCompiler._validation_error(
                    "Generated artifacts must be valid UTF-8 text."
                ) from exc
            if _LATEST_TOKEN.search(text):
                raise NextflowCompiler._validation_error(
                    f"Generated artifact {name!r} contains a forbidden floating version token."
                )

    @staticmethod
    def _validation_error(message: str) -> BioPipeError:
        return BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            message,
            remediation=["Regenerate the plan from a resolved manifest and reviewed registry."],
        )


def compile_nextflow_project(
    output_directory: str | Path,
    *,
    manifest: DatasetManifest,
    planned: PlannedPipelineLike,
    registry: ComponentRegistry,
) -> GeneratedProject:
    """Convenience API for compiling one validated planner result."""

    return NextflowCompiler().compile_planned(
        output_directory,
        manifest=manifest,
        planned=planned,
        registry=registry,
    )


def _expected_component_ids(
    *,
    layout: str,
    trimming_enabled: bool,
) -> tuple[str, ...]:
    if not trimming_enabled:
        return ("fastqc_raw_v1", "multiqc_v1")
    fastp = "fastp_paired_v1" if layout == "paired_end" else "fastp_single_v1"
    return ("fastqc_raw_v1", fastp, "fastqc_post_trim_v1", "multiqc_v1")


def _process_settings(label: str, component: ComponentDefinition) -> _ProcessSettings:
    return _ProcessSettings(
        label=label,
        cpus=component.resources.cpus,
        memory=f"{component.resources.memory_gb} GB",
        container=component.container.immutable_reference,
    )


def _component_template(component: ComponentDefinition) -> str:
    path = PurePosixPath(component.template.nextflow)
    if not path.parts or path.parts[0] != "templates":
        raise NextflowCompiler._validation_error("A component template path is outside the bundle.")
    return PurePosixPath(*path.parts[1:]).as_posix()


def _render_execution_samplesheet(
    manifest: DatasetManifest,
    execution_plan: ExecutionPlan,
) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["sample_id", "lane", "chunk", "read1", "read2"])
    mapped_paths: set[str] = set()
    for sample in sorted(manifest.samples, key=lambda item: item.sample_id):
        for lane in sorted(sample.lanes, key=lambda item: (item.lane, item.chunk or "")):
            read1 = _map_execution_path(lane.read1, execution_plan)
            read2 = _map_execution_path(lane.read2, execution_plan) if lane.read2 else ""
            current_paths = {read1, read2} - {""}
            if mapped_paths.intersection(current_paths):
                raise NextflowCompiler._validation_error(
                    "Execution path mappings assign more than one read to the same path."
                )
            mapped_paths.update(current_paths)
            writer.writerow(
                [
                    sample.sample_id,
                    lane.lane,
                    lane.chunk or "",
                    read1,
                    read2,
                ]
            )
    return output.getvalue()


def _map_execution_path(source_value: str, plan: ExecutionPlan) -> str:
    source = PurePosixPath(source_value)
    candidates: list[tuple[int, PurePosixPath, PurePosixPath]] = []
    for mapping in plan.path_mapping or []:
        source_prefix = PurePosixPath(mapping.source_prefix)
        try:
            relative = source.relative_to(source_prefix)
        except ValueError:
            continue
        candidates.append(
            (len(source_prefix.parts), PurePosixPath(mapping.execution_prefix), relative)
        )
    if candidates:
        longest = max(length for length, _prefix, _relative in candidates)
        equally_specific = [candidate for candidate in candidates if candidate[0] == longest]
        mapped_values = {str(prefix / relative) for _length, prefix, relative in equally_specific}
        if len(mapped_values) != 1:
            raise NextflowCompiler._validation_error("Execution path mappings are ambiguous.")
        mapped = PurePosixPath(mapped_values.pop())
    elif plan.path_mapping:
        raise NextflowCompiler._validation_error(
            "A manifest read path is not covered by the explicit execution path mappings."
        )
    else:
        source_root = PurePosixPath(plan.paths.source_root)
        execution_root = PurePosixPath(plan.paths.execution_root)
        if source_root != execution_root:
            raise NextflowCompiler._validation_error(
                "Different source and execution roots require an explicit path mapping."
            )
        try:
            relative = source.relative_to(source_root)
        except ValueError as exc:
            raise NextflowCompiler._validation_error(
                "A manifest read path is outside the execution plan source root."
            ) from exc
        mapped = execution_root / relative
    execution_root = PurePosixPath(plan.paths.execution_root)
    try:
        relative_to_execution = mapped.relative_to(execution_root)
    except ValueError as exc:
        raise NextflowCompiler._validation_error(
            "A mapped read path is outside the planned execution root."
        ) from exc
    if relative_to_execution == PurePosixPath("."):
        raise NextflowCompiler._validation_error(
            "A mapped read path resolves to the execution root."
        )
    return str(mapped)


def _json_model(model: BaseModel) -> bytes:
    data = model.model_dump(mode="json", exclude_none=False)
    return (
        json.dumps(
            data,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _yaml_model(model: BaseModel) -> bytes:
    data = model.model_dump(mode="json", exclude_none=False)
    return yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=True,
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _paths_overlap(first: str, second: str) -> bool:
    first_path = PurePosixPath(first)
    second_path = PurePosixPath(second)
    return (
        first_path == second_path
        or first_path in second_path.parents
        or second_path in first_path.parents
    )


def _generation_fingerprint(
    artifacts: Mapping[str, bytes],
    registry: ComponentRegistry,
) -> str:
    digest = hashlib.sha256()
    digest.update(f"compiler/{COMPILER_VERSION}\0registry/{registry.version}\0".encode())
    digest.update(_sha256(_json_model(registry.document)).encode("ascii"))
    digest.update(b"\0")
    for name, payload in sorted(artifacts.items()):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_sha256(payload).encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


__all__ = [
    "GeneratedProject",
    "NextflowCompiler",
    "PlannedPipelineLike",
    "compile_nextflow_project",
]
