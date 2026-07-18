"""Deterministic and fail-closed Nextflow compiler tests."""

from __future__ import annotations

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path

import pytest

from biopipe.compiler import NextflowCompiler, ProjectBundleStore, StrictTemplateRenderer
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.manifests import finalize_manifest, sanitize_manifest
from biopipe.models import (
    DatasetClassification,
    DatasetManifest,
    DatasetObservations,
    DatasetSample,
    LaneFiles,
    LockedComponent,
    ManifestPrivacy,
    ManifestSource,
    PathMapping,
)
from biopipe.planner import PlanningOptions, plan_fastq_qc
from biopipe.registry import load_default_registry

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _manifest(
    *,
    layout: str = "paired_end",
    root: str = "/srv/raw",
    multilane: bool = False,
) -> DatasetManifest:
    lane_names = ("L001", "L002") if multilane else ("L001",)
    samples = [
        DatasetSample(
            sample_id="sample-A",
            lanes=[
                LaneFiles(
                    lane=lane,
                    chunk="001",
                    read1=f"{root}/sample-A_{lane}_R1_001.fastq.gz",
                    read2=(
                        f"{root}/sample-A_{lane}_R2_001.fastq.gz"
                        if layout == "paired_end"
                        else None
                    ),
                )
                for lane in lane_names
            ],
        )
    ]
    return finalize_manifest(
        DatasetManifest(
            source=ManifestSource(
                source_id="source-a",
                root=root,
                scanned_at=datetime(2026, 7, 18, 1, 2, 3, tzinfo=timezone.utc),
            ),
            classification=DatasetClassification(
                dataset_type="illumina_fastq",
                layout=layout,  # type: ignore[arg-type]
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


def _planned(
    manifest: DatasetManifest,
    *,
    trimming: bool,
    execution_root: str | None = None,
):
    return plan_fastq_qc(
        manifest,
        PlanningOptions(
            project_name="project-qc",
            trimming_enabled=trimming,
            minimum_length=35 if trimming else None,
            execution_root=execution_root,
            work_dir="/work/project-qc",
            output_dir="/results/project-qc",
            container_cache="/containers/cache",
            max_cpus=8,
            max_memory_gb=16,
        ),
    )


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_compile_paired_multilane_trimming_bundle_is_fully_deterministic(
    tmp_path: Path,
) -> None:
    manifest = _manifest(multilane=True)
    planned = _planned(manifest, trimming=True)
    registry = load_default_registry()
    first = tmp_path / "first"
    second = tmp_path / "second"

    first_result = NextflowCompiler().compile_planned(
        first,
        manifest=manifest,
        planned=planned,
        registry=registry,
    )
    second_result = NextflowCompiler().compile_planned(
        second,
        manifest=manifest,
        planned=planned,
        registry=registry,
    )

    assert _tree_bytes(first) == _tree_bytes(second)
    assert first_result.generation_fingerprint == second_result.generation_fingerprint
    assert set(first_result.files) == {
        "LICENSE",
        "README.md",
        "assets/samplesheet.csv",
        "audit/events.jsonl",
        "conf/base.config",
        "conf/local.config",
        "conf/slurm.config",
        "dataset.manifest.resolved.json",
        "execution.plan.yaml",
        "main.nf",
        "modules/fastp/main.nf",
        "modules/fastqc/post_trim.nf",
        "modules/fastqc/raw.nf",
        "modules/multiqc/main.nf",
        "nf-test.config",
        "nextflow.config",
        "pipeline.spec.yaml",
        "software.lock.yaml",
        "tests/fixtures/README.md",
        "tests/fixtures/paired_end/fixture.json",
        "tests/fixtures/paired_end/reads/synthetic_pe_R1.fastq",
        "tests/fixtures/paired_end/reads/synthetic_pe_R2.fastq",
        "tests/fixtures/single_end/fixture.json",
        "tests/fixtures/single_end/reads/synthetic_se_R1.fastq",
        "tests/nextflow.config",
        "tests/pipeline.nf.test",
    }
    license_payload = (REPOSITORY_ROOT / "LICENSE").read_bytes()
    assert (first / "LICENSE").read_bytes() == license_payload
    assert first_result.artifact_hashes["LICENSE"] == hashlib.sha256(license_payload).hexdigest()
    samplesheet_lines = (first / "assets/samplesheet.csv").read_text().splitlines()
    assert samplesheet_lines == [
        "sample_id,lane,chunk,read1,read2",
        "sample-A,L001,001,/srv/raw/sample-A_L001_R1_001.fastq.gz,/srv/raw/sample-A_L001_R2_001.fastq.gz",
        "sample-A,L002,001,/srv/raw/sample-A_L002_R1_001.fastq.gz,/srv/raw/sample-A_L002_R2_001.fastq.gz",
    ]

    main = (first / "main.nf").read_text()
    assert "FASTP(reads_ch)" in main
    assert "FASTQC_POST_TRIM(FASTP.out.reads)" in main
    assert main.count(".flatMap { item ->") == 2
    assert "samplesheet_ch = channel.fromPath" in main
    assert ".mix(trimmed_fastqc_reports)" in main
    assert ".mix(FASTQC_POST_TRIM.out.zip)" not in main
    assert "path reports" in (first / "modules/multiqc/main.nf").read_text()
    assert "stub:" in (first / "modules/multiqc/main.nf").read_text()
    assert "stub:" in (first / "modules/fastp/main.nf").read_text()
    assert "stub:" in (first / "modules/fastqc/raw.nf").read_text()
    assert (
        "path '*.fastp.json', arity: '1', emit: json"
        in (first / "modules/fastp/main.nf").read_text()
    )
    assert "mv multiqc.html multiqc_report.html" in (first / "modules/multiqc/main.nf").read_text()
    assert "--no-version-check" in (first / "modules/multiqc/main.nf").read_text()

    nf_test_config = (first / "nf-test.config").read_text()
    assert '"nf-test": "0.9.5"' in nf_test_config
    assert "BIOPIPE_NF_TEST_WORK_DIR" in nf_test_config
    assert 'options "-stub-run"' in nf_test_config
    pipeline_test = (first / "tests/pipeline.nf.test").read_text()
    assert "synthetic_pe_001" in pipeline_test
    assert "synthetic_pe_R1.fastq" in pipeline_test
    assert "synthetic_pe_R2.fastq" in pipeline_test
    assert "workflow.trace.succeeded().size() == 4" in pipeline_test
    assert "fastqc_trimmed" in pipeline_test
    test_config = (first / "tests/nextflow.config").read_text()
    assert "docker.enabled = false" in test_config
    assert "apptainer.enabled = false" in test_config
    assert "executor.cpus = 8" in test_config

    base_config = (first / "conf/base.config").read_text()
    for digest in (
        "sha256:e194048df39c3145d9b4e0a14f4da20b59d59250465b6f2a9cb698445fd45900",
        "sha256:cbbe2402b6b6704df470d7d77dcb498eefd5bcd01f4c38be0ec69899e79ac134",
        "sha256:b65e3fe879df27b92334dda0fd987a6e21bdee09a2848551d4f287099a93b7ac",
    ):
        assert digest in base_config
    assert ":0.12.1--hdfd78af_0@sha256:" not in base_config
    assert ":1.3.6--h43da1c4_0@sha256:" not in base_config
    assert ":1.35--pyhdfd78af_1@sha256:" not in base_config
    assert "latest" not in "\n".join(
        payload.decode("utf-8").casefold() for payload in _tree_bytes(first).values()
    )

    events = (first / "audit/events.jsonl").read_text().splitlines()
    assert len(events) == 1
    event = json.loads(events[0])
    assert event["timestamp"] == "2026-07-18T01:02:03Z"
    assert event["status"] == "success"
    assert "audit/events.jsonl" not in event["output_hashes"]
    assert event["output_hashes"]["LICENSE"] == hashlib.sha256(license_payload).hexdigest()


def test_compile_single_end_without_trimming_omits_unselected_processes(
    tmp_path: Path,
) -> None:
    manifest = _manifest(layout="single_end")
    planned = _planned(manifest, trimming=False)

    NextflowCompiler().compile_planned(
        tmp_path / "generated",
        manifest=manifest,
        planned=planned,
        registry=load_default_registry(),
    )

    main = (tmp_path / "generated/main.nf").read_text()
    assert "FASTQC_RAW(reads_ch)" in main
    assert "FASTP" not in main
    assert "FASTQC_POST_TRIM" not in main
    assert "raw_fastqc_reports.collect()" in main
    assert not (tmp_path / "generated/modules/fastp").exists()
    assert not (tmp_path / "generated/modules/fastqc/post_trim.nf").exists()
    assert (
        (tmp_path / "generated/assets/samplesheet.csv")
        .read_text()
        .endswith("sample-A,L001,001,/srv/raw/sample-A_L001_R1_001.fastq.gz,\n")
    )
    pipeline_test = (tmp_path / "generated/tests/pipeline.nf.test").read_text()
    assert "synthetic_se_001" in pipeline_test
    assert "synthetic_se_R1.fastq" in pipeline_test
    assert "synthetic_pe_R2.fastq" not in pipeline_test
    assert "workflow.trace.succeeded().size() == 2" in pipeline_test
    assert "fastqc_trimmed" not in pipeline_test


def test_execution_path_mapping_is_applied_to_every_multilane_mate(tmp_path: Path) -> None:
    manifest = _manifest(multilane=True)
    planned = _planned(manifest, trimming=True, execution_root="/mnt/shared/raw")

    NextflowCompiler().compile_planned(
        tmp_path / "mapped",
        manifest=manifest,
        planned=planned,
        registry=load_default_registry(),
    )

    samplesheet = (tmp_path / "mapped/assets/samplesheet.csv").read_text()
    assert "/srv/raw" not in samplesheet
    assert samplesheet.count("/mnt/shared/raw/") == 4
    config = (tmp_path / "mapped/nextflow.config").read_text()
    assert "source_root = '/mnt/shared/raw'" in config


def test_execution_path_mapping_uses_longest_match_and_rejects_ambiguity(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    planned = _planned(manifest, trimming=False, execution_root="/mnt/shared/raw")
    plan_payload = planned.execution_plan.model_dump(mode="python")
    plan_payload["path_mapping"] = [
        PathMapping(source_prefix="/srv", execution_prefix="/mnt"),
        PathMapping(source_prefix="/srv/raw", execution_prefix="/mnt/shared/raw"),
    ]
    longest_plan = type(planned.execution_plan).model_validate(plan_payload)
    longest_planned = planned.model_copy(update={"execution_plan": longest_plan})

    NextflowCompiler().compile_planned(
        tmp_path / "longest",
        manifest=manifest,
        planned=longest_planned,
        registry=load_default_registry(),
    )
    assert "/mnt/shared/raw/sample-A" in (tmp_path / "longest/assets/samplesheet.csv").read_text()

    plan_payload["paths"]["execution_root"] = "/mnt/shared"  # type: ignore[index]
    plan_payload["path_mapping"] = [
        PathMapping(source_prefix="/srv/raw", execution_prefix="/mnt/shared/a"),
        PathMapping(source_prefix="/srv/raw", execution_prefix="/mnt/shared/b"),
    ]
    ambiguous_plan = type(planned.execution_plan).model_validate(plan_payload)
    ambiguous_planned = planned.model_copy(update={"execution_plan": ambiguous_plan})
    with pytest.raises(BioPipeError):
        NextflowCompiler().compile_planned(
            tmp_path / "ambiguous",
            manifest=manifest,
            planned=ambiguous_planned,
            registry=load_default_registry(),
        )
    assert not (tmp_path / "ambiguous").exists()


def test_compile_rejects_tampered_lock_and_sanitized_manifest(tmp_path: Path) -> None:
    manifest = _manifest()
    planned = _planned(manifest, trimming=True)
    locked_fastqc = planned.software_lock.components["fastqc"]
    tampered = planned.software_lock.model_copy(
        update={
            "components": {
                **planned.software_lock.components,
                "fastqc": LockedComponent(
                    version=locked_fastqc.version,
                    image="quay.io/example/fastqc:0.12.1",
                    digest="sha256:" + "a" * 64,
                    license=locked_fastqc.license,
                ),
            }
        },
        deep=True,
    )
    compiler = NextflowCompiler()

    with pytest.raises(BioPipeError) as lock_error:
        compiler.compile(
            tmp_path / "tampered",
            manifest=manifest,
            spec=planned.spec,
            execution_plan=planned.execution_plan,
            software_lock=tampered,
            registry=load_default_registry(),
            component_ids=planned.component_ids,
        )
    assert lock_error.value.code is ErrorCode.VALIDATION_FAILED
    assert not (tmp_path / "tampered").exists()

    sanitized = sanitize_manifest(manifest)
    with pytest.raises(BioPipeError) as privacy_error:
        compiler.compile_planned(
            tmp_path / "sanitized",
            manifest=sanitized,
            planned=planned,
            registry=load_default_registry(),
        )
    assert privacy_error.value.code is ErrorCode.VALIDATION_FAILED
    assert not (tmp_path / "sanitized").exists()


def test_compiler_escapes_groovy_paths_and_has_no_arbitrary_cli_channel(tmp_path: Path) -> None:
    manifest = _manifest(root="/srv/raw'quoted")
    planned = _planned(manifest, trimming=True)

    NextflowCompiler().compile_planned(
        tmp_path / "quoted",
        manifest=manifest,
        planned=planned,
        registry=load_default_registry(),
    )

    config = (tmp_path / "quoted/nextflow.config").read_text()
    assert "source_root = '/srv/raw\\'quoted'" in config
    fastp = (tmp_path / "quoted/modules/fastp/main.nf").read_text()
    assert "--length_required 35" in fastp
    assert "params.fastp_minimum_length" not in fastp
    assert "params.extra" not in fastp
    assert "task.ext.args" not in fastp


def test_compiler_rejects_weakened_preflight_or_approval_contract(tmp_path: Path) -> None:
    manifest = _manifest()
    planned = _planned(manifest, trimming=True)
    compiler = NextflowCompiler()

    for field, value in (
        (
            "preflight",
            {**planned.execution_plan.preflight.model_dump(), "require_container_runtime": False},
        ),
        (
            "approval",
            {
                **planned.execution_plan.approval.model_dump(),
                "real_data_execution_required": False,
            },
        ),
    ):
        payload = planned.execution_plan.model_dump(mode="python")
        payload[field] = value
        weakened_plan = type(planned.execution_plan).model_validate(payload)
        weakened = planned.model_copy(update={"execution_plan": weakened_plan})
        with pytest.raises(BioPipeError):
            compiler.compile_planned(
                tmp_path / field,
                manifest=manifest,
                planned=weakened,
                registry=load_default_registry(),
            )
        assert not (tmp_path / field).exists()


def test_project_bundle_is_create_only_and_leaves_no_partial_tree_on_publish_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing = tmp_path / "existing"
    existing.mkdir()
    marker = existing / "keep.txt"
    marker.write_text("keep")
    with pytest.raises(BioPipeError):
        ProjectBundleStore(existing).create({"main.nf": b"workflow {}\n"})
    assert marker.read_text() == "keep"

    destination = tmp_path / "late-failure"

    def fail_publish(_source: Path, _destination: Path) -> None:
        raise OSError(5, "synthetic exclusive-rename failure")

    monkeypatch.setattr(
        ProjectBundleStore,
        "_rename_exclusive",
        staticmethod(fail_publish),
    )
    with pytest.raises(BioPipeError):
        ProjectBundleStore(destination).create(
            {"a/main.nf": b"one\n", "b/nextflow.config": b"two\n"}
        )
    assert not destination.exists()


def test_project_bundle_concurrent_publish_has_one_complete_winner(tmp_path: Path) -> None:
    destination = tmp_path / "concurrent"
    artifacts = {"a/main.nf": b"one\n", "b/nextflow.config": b"two\n"}
    barrier = threading.Barrier(2)

    def publish() -> bool:
        barrier.wait()
        try:
            ProjectBundleStore(destination).create(artifacts)
        except BioPipeError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: publish(), range(2)))

    assert sorted(results) == [False, True]
    assert _tree_bytes(destination) == artifacts
    assert not list(tmp_path.glob(".concurrent.biopipe-*"))


def test_registry_template_resources_exist_and_match_review_copies() -> None:
    registry = load_default_registry()
    package_root = resources.files("biopipe.compiler").joinpath("_templates")
    review_root = Path(__file__).parents[2] / "templates" / "nextflow"

    for component in registry.components.values():
        relative = component.template.nextflow.removeprefix("templates/")
        packaged = package_root.joinpath(*relative.split("/"))
        reviewed = review_root / relative
        assert packaged.is_file(), component.component_id
        assert reviewed.is_file(), component.component_id
        assert packaged.read_bytes() == reviewed.read_bytes()

    for relative in (
        "project/LICENSE.j2",
        "project/main.nf.j2",
        "project/nextflow.config.j2",
        "project/conf/base.config.j2",
        "project/conf/local.config.j2",
        "project/conf/slurm.config.j2",
        "project/README.md.j2",
        "project/nf-test.config.j2",
        "project/tests/nextflow.config.j2",
        "project/tests/pipeline.nf.test.j2",
        "project/tests/fixtures/README.md.j2",
        "project/tests/fixtures/single_end/fixture.json.j2",
        "project/tests/fixtures/single_end/reads/synthetic_se_R1.fastq.j2",
        "project/tests/fixtures/paired_end/fixture.json.j2",
        "project/tests/fixtures/paired_end/reads/synthetic_pe_R1.fastq.j2",
        "project/tests/fixtures/paired_end/reads/synthetic_pe_R2.fastq.j2",
        "components/_shared/fastp.nf.j2",
    ):
        packaged = package_root.joinpath(*relative.split("/"))
        reviewed = review_root / relative
        assert packaged.is_file()
        assert packaged.read_bytes() == reviewed.read_bytes()


def test_strict_templates_reject_missing_context() -> None:
    with pytest.raises(BioPipeError):
        StrictTemplateRenderer().render("project/nextflow.config.j2", {})
