"""Behavior-locking tests for NextflowCompiler._validate_inputs.

P3 #37: these tests pin the exact error message of every validation check
in _validate_inputs, so the table-driven refactor cannot silently change
error codes or wording. Each case mutates exactly one input of an otherwise
valid (manifest, spec, execution_plan, software_lock, registry,
component_ids) bundle and asserts the verbatim message.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from biopipe.compiler import NextflowCompiler
from biopipe.errors import BioPipeError
from biopipe.manifests import finalize_manifest
from biopipe.models import (
    DatasetClassification,
    DatasetManifest,
    DatasetObservations,
    DatasetSample,
    LaneFiles,
    ManifestIssue,
    ManifestPrivacy,
    ManifestSource,
)
from biopipe.planner.fastq_qc import PlanningOptions, plan_fastq_qc
from biopipe.registry import ComponentRegistry, load_default_registry


def _manifest() -> DatasetManifest:
    samples = [
        DatasetSample(
            sample_id="sample-A",
            lanes=[
                LaneFiles(
                    lane="L001",
                    chunk="001",
                    read1="/srv/raw/sample-A_L001_R1_001.fastq.gz",
                    read2="/srv/raw/sample-A_L001_R2_001.fastq.gz",
                )
            ],
        )
    ]
    return finalize_manifest(
        DatasetManifest(
            source=ManifestSource(
                source_id="source-a",
                root="/srv/raw",
                scanned_at=datetime(2026, 7, 18, 1, 2, 3, tzinfo=timezone.utc),
            ),
            classification=DatasetClassification(
                dataset_type="illumina_fastq",
                layout="paired_end",
                confidence=0.99,
            ),
            samples=samples,
            observations=DatasetObservations(compression="gzip"),
            privacy=ManifestPrivacy(
                filenames_may_contain_identifiers=False,
                raw_content_exported=False,
            ),
        )
    )


def _bundle() -> dict[str, Any]:
    manifest = _manifest()
    planned = plan_fastq_qc(
        manifest,
        PlanningOptions(
            project_name="project-qc",
            trimming_enabled=True,
            minimum_length=35,
            work_dir="/work/project-qc",
            output_dir="/results/project-qc",
            container_cache="/containers/cache",
            max_cpus=8,
            max_memory_gb=16,
        ),
    )
    registry = load_default_registry()
    return {
        "manifest": manifest,
        "spec": planned.spec,
        "execution_plan": planned.execution_plan,
        "software_lock": planned.software_lock,
        "registry": registry,
        "component_ids": planned.component_ids,
    }


def _compile_with(mutation: Callable[[dict[str, Any]], None], tmp_path: Path) -> str:
    bundle = _bundle()
    mutation(bundle)
    compiler = NextflowCompiler()
    with pytest.raises(BioPipeError) as caught:
        compiler.compile(
            tmp_path / "output",
            manifest=bundle["manifest"],
            spec=bundle["spec"],
            execution_plan=bundle["execution_plan"],
            software_lock=bundle["software_lock"],
            registry=bundle["registry"],
            component_ids=bundle["component_ids"],
        )
    return str(caught.value)


def _replace_privacy_scope(bundle: dict[str, Any]) -> None:
    manifest = bundle["manifest"]
    privacy = manifest.privacy.model_copy(update={"artifact_scope": "review"})
    bundle["manifest"] = finalize_manifest(manifest.model_copy(update={"privacy": privacy}))


def _add_manifest_error(bundle: dict[str, Any]) -> None:
    manifest = bundle["manifest"]
    issue = ManifestIssue(
        code="SYNTHETIC", severity="blocking", message="synthetic", remediation=["fix"]
    )
    bundle["manifest"] = finalize_manifest(manifest.model_copy(update={"errors": (issue,)}))


def _wrong_spec_manifest_name(bundle: dict[str, Any]) -> None:
    spec = bundle["spec"]
    bundle["spec"] = spec.model_copy(
        update={"input": spec.input.model_copy(update={"manifest": "other.json"})}
    )


def _layout_mismatch(bundle: dict[str, Any]) -> None:
    spec = bundle["spec"]
    bundle["spec"] = spec.model_copy(
        update={"input": spec.input.model_copy(update={"layout": "single_end"})}
    )


def _executor_mismatch(bundle: dict[str, Any]) -> None:
    plan = bundle["execution_plan"]
    bundle["execution_plan"] = plan.model_copy(update={"executor": "slurm"})


def _source_root_mismatch(bundle: dict[str, Any]) -> None:
    plan = bundle["execution_plan"]
    bundle["execution_plan"] = plan.model_copy(
        update={"paths": plan.paths.model_copy(update={"source_root": "/other/raw"})}
    )


def _paths_mismatch(bundle: dict[str, Any]) -> None:
    plan = bundle["execution_plan"]
    bundle["execution_plan"] = plan.model_copy(
        update={"paths": plan.paths.model_copy(update={"work_dir": "/other/work"})}
    )


def _overwrite_enabled(bundle: dict[str, Any]) -> None:
    spec = bundle["spec"]
    bundle["spec"] = spec.model_copy(
        update={"policy": spec.policy.model_copy(update={"overwrite_existing_outputs": True})}
    )


def _policy_changed(bundle: dict[str, Any]) -> None:
    spec = bundle["spec"]
    bundle["spec"] = spec.model_copy(
        update={"policy": spec.policy.model_copy(update={"network_access_during_tasks": True})}
    )


def _approval_changed(bundle: dict[str, Any]) -> None:
    plan = bundle["execution_plan"]
    bundle["execution_plan"] = plan.model_copy(
        update={
            "approval": plan.approval.model_copy(
                update={"real_data_execution_required": False}
            )
        }
    )


def _preflight_changed(bundle: dict[str, Any]) -> None:
    plan = bundle["execution_plan"]
    bundle["execution_plan"] = plan.model_copy(
        update={
            "preflight": plan.preflight.model_copy(update={"require_container_runtime": False})
        }
    )


def _stages_changed(bundle: dict[str, Any]) -> None:
    spec = bundle["spec"]
    bundle["spec"] = spec.model_copy(
        update={"analysis": spec.analysis.model_copy(update={"stages": ["raw_fastqc"]})}
    )


def _paths_overlap(bundle: dict[str, Any]) -> None:
    # Change both spec and plan work_dir together so the "paths differ" check
    # still passes; the overlap check then fires on source_root.
    spec = bundle["spec"]
    plan = bundle["execution_plan"]
    bundle["spec"] = spec.model_copy(
        update={"paths": spec.paths.model_copy(update={"work_dir": "/srv/raw/work"})}
    )
    bundle["execution_plan"] = plan.model_copy(
        update={"paths": plan.paths.model_copy(update={"work_dir": "/srv/raw/work"})}
    )


def _component_ids_changed(bundle: dict[str, Any]) -> None:
    bundle["component_ids"] = tuple(reversed(bundle["component_ids"]))


def _software_lock_changed(bundle: dict[str, Any]) -> None:
    lock = bundle["software_lock"]
    bundle["software_lock"] = lock.model_copy(update={"resolver_version": "tampered"})


def _registry_tampered(bundle: dict[str, Any]) -> None:
    registry = bundle["registry"]
    document = registry.document.model_copy(
        update={"registry_version": "9.9.9-tampered"}
    )
    bundle["registry"] = ComponentRegistry(document)


_CASES: list[tuple[str, Callable[[dict[str, Any]], None], str]] = [
    (
        "sanitized manifest",
        _replace_privacy_scope,
        "Project generation requires the full resolved manifest, not a sanitized artifact.",
    ),
    (
        "manifest with errors",
        _add_manifest_error,
        "Project generation requires a classified FASTQ dataset without blocking errors.",
    ),
    (
        "wrong spec input manifest name",
        _wrong_spec_manifest_name,
        "PipelineSpec input.manifest must be 'dataset.manifest.resolved.json'.",
    ),
    (
        "layout mismatch",
        _layout_mismatch,
        "The manifest and PipelineSpec layouts differ.",
    ),
    (
        "executor mismatch",
        _executor_mismatch,
        "The PipelineSpec and execution plan executors differ.",
    ),
    (
        "source root mismatch",
        _source_root_mismatch,
        "The execution plan source root differs from the manifest.",
    ),
    (
        "paths mismatch",
        _paths_mismatch,
        "PipelineSpec and execution plan paths differ.",
    ),
    (
        "overwrite enabled",
        _overwrite_enabled,
        "Generated projects must keep output replacement disabled.",
    ),
    (
        "policy changed",
        _policy_changed,
        "Project generation requires the default-deny execution policy.",
    ),
    (
        "approval changed",
        _approval_changed,
        "Project generation requires the default-deny execution policy.",
    ),
    (
        "preflight changed",
        _preflight_changed,
        "Project generation requires the complete execution preflight contract.",
    ),
    (
        "stages changed",
        _stages_changed,
        "PipelineSpec stages do not match the fixed FASTQ-QC DAG.",
    ),
    (
        "paths overlap",
        _paths_overlap,
        "Input, work, output, and container-cache paths must not overlap.",
    ),
    (
        "component ids changed",
        _component_ids_changed,
        "The selected component graph is not the fixed FASTQ-QC graph.",
    ),
    (
        "software lock changed",
        _software_lock_changed,
        "The software lock does not match the selected registry graph.",
    ),
    (
        "registry tampered",
        _registry_tampered,
        "The component registry is not the reviewed default registry.",
    ),
]


@pytest.mark.parametrize("name,mutation,expected", _CASES, ids=[c[0] for c in _CASES])
def test_validate_inputs_error_messages_are_locked(
    name: str,
    mutation: Callable[[dict[str, Any]], None],
    expected: str,
    tmp_path: Path,
) -> None:
    assert _compile_with(mutation, tmp_path) == expected
