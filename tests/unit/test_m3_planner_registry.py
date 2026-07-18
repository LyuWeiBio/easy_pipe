"""M3 contracts for fixed FASTQ-QC planning and the reviewed registry."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path

import pytest
from pydantic import ValidationError

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.manifests.integrity import finalize_manifest
from biopipe.manifests.privacy import sanitize_manifest
from biopipe.models import (
    DatasetClassification,
    DatasetManifest,
    DatasetSample,
    LaneFiles,
    LockedComponent,
    ManifestIntegrity,
    ManifestIssue,
    ManifestSource,
    PipelineSpec,
)
from biopipe.planner import (
    PlanningOptions,
    plan_fastq_qc,
    reconstruct_planned_pipeline,
)
from biopipe.registry import (
    ComponentContainer,
    RegistryDocument,
    RegistryValidationError,
    load_default_registry,
)


def _manifest(
    layout: str = "single_end",
    *,
    blocking: bool = False,
) -> DatasetManifest:
    samples: list[DatasetSample]
    if layout == "single_end":
        samples = [
            DatasetSample(
                sample_id="sample_001",
                lanes=[
                    LaneFiles(
                        lane="L001",
                        read1="/srv/raw/run42/sample_L001_R1.fastq.gz",
                    ),
                    LaneFiles(
                        lane="L002",
                        read1="/srv/raw/run42/sample_L002_R1.fastq.gz",
                    ),
                ],
            )
        ]
    elif layout == "paired_end":
        samples = [
            DatasetSample(
                sample_id="sample_001",
                lanes=[
                    LaneFiles(
                        lane="L001",
                        read1="/srv/raw/run42/sample_L001_R1.fastq.gz",
                        read2="/srv/raw/run42/sample_L001_R2.fastq.gz",
                    )
                ],
            )
        ]
    else:
        samples = []

    errors = []
    if blocking or layout == "unknown":
        errors.append(
            ManifestIssue(
                code="unresolved_pairing",
                severity="blocking",
                message="Synthetic unresolved pairing issue.",
            )
        )
    manifest = DatasetManifest(
        source=ManifestSource(
            source_id="hpc01",
            root="/srv/raw/run42",
            scanned_at=datetime(2026, 7, 18, tzinfo=timezone.utc),
        ),
        classification=DatasetClassification(
            dataset_type="unknown" if layout == "unknown" else "illumina_fastq",
            layout=layout,  # type: ignore[arg-type]
            confidence=0.95 if layout != "unknown" else 0.0,
        ),
        samples=samples,
        errors=errors,
    )
    return finalize_manifest(manifest)


def _options(*, trimming: bool, minimum_length: int | None = None) -> PlanningOptions:
    return PlanningOptions(
        project_name="run42-fastq-qc",
        trimming_enabled=trimming,
        minimum_length=minimum_length,
        work_dir="/srv/work/run42-fastq-qc",
        output_dir="/srv/results/run42-fastq-qc",
        container_cache="/srv/cache/apptainer",
    )


def test_default_registry_is_versioned_pinned_and_self_compatible() -> None:
    registry = load_default_registry()

    assert registry.version == "1.0.0"
    assert set(registry.components) == {
        "fastqc_raw_v1",
        "fastp_single_v1",
        "fastp_paired_v1",
        "fastqc_post_trim_v1",
        "multiqc_v1",
    }
    for component in registry.components.values():
        assert ":latest" not in component.container.image.casefold()
        assert component.container.digest.startswith("sha256:")
        assert component.container.immutable_reference == (
            f"{component.container.image.rsplit(':', maxsplit=1)[0]}@{component.container.digest}"
        )


def test_immutable_reference_removes_tag_without_losing_registry_port() -> None:
    container = ComponentContainer(
        image="registry.example:5000/team/tool:1.2.3",
        digest=f"sha256:{'a' * 64}",
    )

    assert container.immutable_reference == (f"registry.example:5000/team/tool@sha256:{'a' * 64}")


@pytest.mark.parametrize(
    "digest",
    [
        f"sha256:{'0' * 64}",
        f"sha256:{'A' * 64}",
        f"sha256:{'a' * 63}",
    ],
)
def test_registry_and_lock_reject_placeholder_or_malformed_digests(digest: str) -> None:
    with pytest.raises(ValidationError):
        ComponentContainer(image="registry.example/tool:1.0", digest=digest)
    with pytest.raises(ValidationError):
        LockedComponent(
            version="1.0",
            image="registry.example/tool:1.0",
            digest=digest,
            license="MIT",
        )


def test_packaged_registry_matches_review_copy_and_is_cwd_independent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resource = resources.files("biopipe.registry").joinpath("data").joinpath("fastq_qc.v1.yaml")
    with resources.as_file(resource) as packaged:
        packaged_bytes = packaged.read_bytes()
    review_copy = (
        Path(__file__).resolve().parents[2] / "registry" / "components" / "fastq_qc.v1.yaml"
    )
    assert packaged_bytes == review_copy.read_bytes()

    monkeypatch.chdir(tmp_path)
    assert load_default_registry().version == "1.0.0"


def test_registry_rejects_incompatible_graph_and_uncontrolled_parameters() -> None:
    registry = load_default_registry()

    with pytest.raises(RegistryValidationError, match="accepts"):
        registry.validate_graph(("fastp_paired_v1",), "single_fastq")
    with pytest.raises(RegistryValidationError, match="does not allow"):
        registry.validate_parameters("fastp_single_v1", {"extra_cli_args": 1})
    with pytest.raises(RegistryValidationError, match="between"):
        registry.validate_parameters("fastp_single_v1", {"minimum_length": 1_001})
    with pytest.raises(RegistryValidationError, match="integer"):
        registry.validate_parameters("fastp_single_v1", {"minimum_length": True})


def test_registry_access_does_not_allow_mutating_loaded_components() -> None:
    registry = load_default_registry()
    selected = registry.get("fastqc_raw_v1")
    selected.resources.cpus = 99
    registry.components["fastqc_raw_v1"].resources.memory_gb = 99

    assert registry.get("fastqc_raw_v1").resources.cpus == 4
    assert registry.get("fastqc_raw_v1").resources.memory_gb == 4


def test_registry_schema_rejects_latest_images() -> None:
    payload = deepcopy(load_default_registry().document.model_dump(mode="python"))
    payload["components"][0]["container"]["image"] = "quay.io/example/tool:latest"

    with pytest.raises(ValidationError):
        RegistryDocument.model_validate(payload)


@pytest.mark.parametrize(
    "image",
    [
        "registry.example/tool",
        "registry.example/tool:latest",
        "registry.example/tool:1.0;unsafe",
    ],
)
def test_registry_and_lock_reject_unsafe_or_floating_images(image: str) -> None:
    with pytest.raises(ValidationError):
        ComponentContainer(image=image, digest=f"sha256:{'a' * 64}")
    with pytest.raises(ValidationError):
        LockedComponent(
            version="1.0",
            image=image,
            digest=f"sha256:{'a' * 64}",
            license="MIT",
        )


def test_planner_selects_single_fastp_and_builds_a_deterministic_lock() -> None:
    manifest = _manifest("single_end")
    options = _options(trimming=True, minimum_length=35)

    first = plan_fastq_qc(manifest, options)
    second = plan_fastq_qc(manifest, options)

    assert first == second
    assert first.component_ids == (
        "fastqc_raw_v1",
        "fastp_single_v1",
        "fastqc_post_trim_v1",
        "multiqc_v1",
    )
    assert first.spec.analysis.stages == [
        "raw_fastqc",
        "optional_trimming",
        "post_trim_fastqc",
        "multiqc",
    ]
    assert first.spec.parameters.trimming.minimum_length == 35
    assert set(first.software_lock.components) == {"fastqc", "fastp", "multiqc"}
    assert first.software_lock.resolved_at == datetime(2026, 7, 18, tzinfo=timezone.utc)
    assert first.execution_plan.approval.approved is False
    assert first.spec.policy.run_real_data is False
    assert (
        reconstruct_planned_pipeline(
            first.spec,
            first.execution_plan,
            first.software_lock,
        )
        == first
    )


def test_reconstruction_rejects_lock_that_does_not_match_registry() -> None:
    planned = plan_fastq_qc(_manifest(), _options(trimming=False))
    changed_lock = planned.software_lock.model_copy(deep=True)
    changed_lock.components["fastqc"].digest = f"sha256:{'a' * 64}"

    with pytest.raises(BioPipeError) as exc_info:
        reconstruct_planned_pipeline(
            planned.spec,
            planned.execution_plan,
            changed_lock,
        )

    assert exc_info.value.code is ErrorCode.VALIDATION_FAILED


def test_planner_selects_paired_fastp_and_emits_explicit_path_mapping() -> None:
    options = _options(trimming=True)
    options.execution_host = "compute01"
    options.execution_root = "/shared/raw/run42"

    planned = plan_fastq_qc(_manifest("paired_end"), options)

    assert planned.component_ids[1] == "fastp_paired_v1"
    assert planned.spec.input.layout == "paired_end"
    assert planned.spec.parameters.trimming.minimum_length == 30
    assert planned.execution_plan.execution_host == "compute01"
    assert planned.execution_plan.path_mapping is not None
    assert planned.execution_plan.path_mapping[0].source_prefix == "/srv/raw/run42"
    assert planned.execution_plan.path_mapping[0].execution_prefix == "/shared/raw/run42"


def test_planner_emits_identity_mapping_for_distinct_hosts_with_shared_paths() -> None:
    options = _options(trimming=False)
    options.execution_host = "compute01"
    options.execution_root = "/srv/raw/run42"

    planned = plan_fastq_qc(_manifest(), options)

    assert planned.execution_plan.source_host == "hpc01"
    assert planned.execution_plan.execution_host == "compute01"
    assert planned.execution_plan.path_mapping is not None
    assert planned.execution_plan.path_mapping[0].source_prefix == "/srv/raw/run42"
    assert planned.execution_plan.path_mapping[0].execution_prefix == "/srv/raw/run42"


def test_planner_no_trimming_has_no_fastp_or_post_trim_stage() -> None:
    planned = plan_fastq_qc(_manifest(), _options(trimming=False))

    assert planned.component_ids == ("fastqc_raw_v1", "multiqc_v1")
    assert planned.spec.analysis.stages == ["raw_fastqc", "multiqc"]
    assert planned.spec.parameters.trimming.enabled is False
    assert set(planned.software_lock.components) == {"fastqc", "multiqc"}


def test_planning_options_reject_ignored_or_arbitrary_parameters() -> None:
    payload = {
        "project_name": "run42-fastq-qc",
        "trimming_enabled": False,
        "work_dir": "/srv/work/run42",
        "output_dir": "/srv/results/run42",
        "container_cache": "/srv/cache/apptainer",
    }
    with pytest.raises(ValidationError, match="minimum_length"):
        PlanningOptions.model_validate({**payload, "minimum_length": 30})
    with pytest.raises(ValidationError, match="extra_forbidden"):
        PlanningOptions.model_validate({**payload, "extra_cli_args": "--unsafe"})
    with pytest.raises(ValidationError, match="bool_type"):
        PlanningOptions.model_validate({**payload, "trimming_enabled": "false"})


@pytest.mark.parametrize(
    ("work_dir", "output_dir"),
    [
        ("/data/results/work", "/data/results"),
        ("/data/results", "/data/results/work"),
    ],
)
def test_planning_options_reject_overlapping_writable_paths(
    work_dir: str,
    output_dir: str,
) -> None:
    with pytest.raises(ValidationError, match="must not overlap"):
        PlanningOptions(
            project_name="run42",
            trimming_enabled=False,
            work_dir=work_dir,
            output_dir=output_dir,
            container_cache="/data/cache",
        )


@pytest.mark.parametrize(
    "output_dir",
    [
        "/srv/raw/run42/results",
        "/srv/raw",
    ],
)
def test_planner_rejects_writable_paths_that_overlap_rawdata(output_dir: str) -> None:
    options = PlanningOptions(
        project_name="run42",
        trimming_enabled=False,
        work_dir="/srv/work/run42",
        output_dir=output_dir,
        container_cache="/srv/cache/apptainer",
    )

    with pytest.raises(BioPipeError) as exc_info:
        plan_fastq_qc(_manifest(), options)

    assert exc_info.value.code is ErrorCode.VALIDATION_FAILED
    assert exc_info.value.context == {"reason": "rawdata_path_overlap"}


def test_planner_rejects_resource_limits_below_component_requirements() -> None:
    options = _options(trimming=False)
    options.max_cpus = 1

    with pytest.raises(BioPipeError) as exc_info:
        plan_fastq_qc(_manifest(), options)

    assert exc_info.value.code is ErrorCode.VALIDATION_FAILED
    assert exc_info.value.context == {"reason": "component_resources_exceed_plan"}


@pytest.mark.parametrize(
    "manifest",
    [
        pytest.param(_manifest("single_end", blocking=True), id="blocking-error"),
        pytest.param(_manifest("unknown"), id="unknown-layout"),
    ],
)
def test_planner_rejects_unresolved_manifests(manifest: DatasetManifest) -> None:
    with pytest.raises(BioPipeError) as exc_info:
        plan_fastq_qc(manifest, _options(trimming=False))

    assert exc_info.value.code is ErrorCode.VALIDATION_FAILED


def test_planner_rejects_manifest_with_invalid_integrity_before_planning() -> None:
    tampered = _manifest().model_copy(
        update={"integrity": ManifestIntegrity(manifest_sha256="0" * 64)}
    )

    with pytest.raises(BioPipeError) as exc_info:
        plan_fastq_qc(tampered, _options(trimming=False))

    assert exc_info.value.code is ErrorCode.MANIFEST_INTEGRITY_FAILED


def test_planner_rejects_integrity_valid_sanitized_manifest() -> None:
    sanitized = sanitize_manifest(_manifest())

    with pytest.raises(BioPipeError) as exc_info:
        plan_fastq_qc(sanitized, _options(trimming=False))

    assert exc_info.value.code is ErrorCode.VALIDATION_FAILED
    assert exc_info.value.context == {"artifact_scope": "sanitized"}


def test_pipeline_spec_rejects_stages_that_disagree_with_trimming() -> None:
    planned = plan_fastq_qc(_manifest(), _options(trimming=False))
    payload = planned.spec.model_dump(mode="python")
    payload["analysis"]["stages"] = [
        "raw_fastqc",
        "optional_trimming",
        "post_trim_fastqc",
        "multiqc",
    ]

    with pytest.raises(ValidationError, match="fixed fastq_qc graph"):
        PipelineSpec.model_validate(payload)
