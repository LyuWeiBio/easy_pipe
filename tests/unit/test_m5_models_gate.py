"""M5 execution-profile storage and real-data approval gate tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from biopipe.compiler import NextflowCompiler
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution import (
    AllowedExecutionRoots,
    ApprovalArtifactPaths,
    ApprovalGate,
    ApprovalRequest,
    ApprovalSigner,
    ContainerArtifact,
    CoreArtifactHashes,
    ExecutionProfile,
    ExecutionProfileRegistry,
    LocalExecutionRuntime,
    PreflightCheck,
    PreflightReport,
    RunPolicy,
    assert_resume_compatible,
    compute_input_set_hash,
    compute_project_hash,
)
from biopipe.manifests import finalize_manifest
from biopipe.models import (
    DatasetClassification,
    DatasetManifest,
    DatasetObservations,
    DatasetSample,
    LaneFiles,
    ManifestPrivacy,
    ManifestSource,
)
from biopipe.planner import PlanningOptions, plan_fastq_qc
from biopipe.registry import load_default_registry
from biopipe.validation import validate_generated_project
from biopipe.workflow_test import WorkflowTestCode, WorkflowTestReport, WorkflowTestStatus

_CHECK_NAMES = (
    "cache_writable",
    "container",
    "disk_space",
    "host_relationship",
    "output_dir_writable",
    "path_mapping",
    "rawdata_readable",
    "runtime",
    "ssh",
    "workdir_writable",
)
_CHECKED_AT = datetime(2026, 7, 18, 5, 0, tzinfo=timezone.utc)


@dataclass(frozen=True)
class _GateFixture:
    project: Path
    paths: ApprovalArtifactPaths
    profile: ExecutionProfile
    core_hashes: CoreArtifactHashes
    request: ApprovalRequest
    bundle_hash: str
    manifest: DatasetManifest


def _manifest() -> DatasetManifest:
    root = "/srv/raw"
    return finalize_manifest(
        DatasetManifest(
            source=ManifestSource(
                source_id="source-a",
                root=root,
                scanned_at=datetime(2026, 7, 18, 1, 2, 3, tzinfo=timezone.utc),
            ),
            classification=DatasetClassification(
                dataset_type="illumina_fastq",
                layout="paired_end",
                confidence=0.99,
            ),
            samples=[
                DatasetSample(
                    sample_id="sample-A",
                    lanes=[
                        LaneFiles(
                            lane="L001",
                            chunk="001",
                            read1=f"{root}/sample-A_L001_R1_001.fastq.gz",
                            read2=f"{root}/sample-A_L001_R2_001.fastq.gz",
                        )
                    ],
                )
            ],
            observations=DatasetObservations(compression="gzip"),
            privacy=ManifestPrivacy(
                filenames_may_contain_identifiers=False,
                raw_content_exported=False,
            ),
        )
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _runtime_report(mode: str) -> WorkflowTestReport:
    return WorkflowTestReport(
        mode=mode,  # type: ignore[arg-type]
        status=WorkflowTestStatus.PASSED,
        code=WorkflowTestCode.OK,
        layout="paired_end",
        trimming_enabled=False,
    )


def _setup(tmp_path: Path) -> _GateFixture:
    manifest = _manifest()
    planned = plan_fastq_qc(
        manifest,
        PlanningOptions(
            project_name="project-qc",
            trimming_enabled=False,
            work_dir="/work/project-qc",
            output_dir="/results/project-qc",
            container_cache="/containers/cache",
            max_cpus=8,
            max_memory_gb=16,
        ),
    )
    project = tmp_path / "generated"
    NextflowCompiler().compile_planned(
        project,
        manifest=manifest,
        planned=planned,
        registry=load_default_registry(),
    )
    static = validate_generated_project(project)
    assert static.status == "valid"
    validation_payload = {
        "report_version": "1.0",
        "command": "validate",
        "status": "passed",
        "code": "OK",
        "project_directory": str(project),
        "report_path": "reports/validation.json",
        "synthetic_data_only": True,
        "static_validation": static.to_dict(),
        "runtime_validation": _runtime_report("validate").model_dump(mode="json"),
        "remediation": [],
    }
    test_payload = {
        "report_version": "1.0",
        "command": "test",
        "profile": "test",
        "status": "passed",
        "code": "OK",
        "project_directory": str(project),
        "report_path": "reports/test.json",
        "synthetic_data_only": True,
        "static_validation": static.to_dict(),
        "runs": {mode: _runtime_report(mode).model_dump(mode="json") for mode in ("e2e", "stub")},
        "remediation": [],
    }
    validation_path = project / "reports" / "validation.json"
    test_path = project / "reports" / "test.json"
    _write_json(validation_path, validation_payload)
    _write_json(test_path, test_payload)

    containers = {
        name: ContainerArtifact(
            image=component.image,
            digest=component.digest,
            local_path=f"/containers/cache/{name}.sif",
            file_sha256="f" * 64,
        )
        for name, component in planned.software_lock.components.items()
    }
    approval_key = tmp_path / "approval.key"
    approval_key.write_text("9" * 64 + "\n", encoding="ascii")
    approval_key.chmod(0o600)
    profile = ExecutionProfile(
        profile_id="local-hpc",
        source_host="source-a",
        execution_host="source-a",
        ssh_alias="source-a",
        username="runner",
        port=22,
        approval_signer=ApprovalSigner(
            key_id="controller-1",
            key_file=str(approval_key),
        ),
        allowed_roots=AllowedExecutionRoots(
            deploy=("/deploy",),
            work=("/work",),
            output=("/results",),
            cache=("/containers",),
        ),
        runtime=LocalExecutionRuntime(container_engine="apptainer"),
        containers=containers,
    )
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(profile.to_json(), encoding="utf-8")
    core_hashes = CoreArtifactHashes(
        dataset_manifest=_sha256(project / "dataset.manifest.resolved.json"),
        pipeline_spec=_sha256(project / "pipeline.spec.yaml"),
        execution_plan=_sha256(project / "execution.plan.yaml"),
        software_lock=_sha256(project / "software.lock.yaml"),
        execution_profile=_sha256(profile_path),
    )
    mapped_inputs = sorted(
        path
        for sample in manifest.samples
        for lane in sample.lanes
        for path in (lane.read1, lane.read2)
        if path is not None
    )
    preflight = PreflightReport(
        status="passed",
        checked_at=_CHECKED_AT,
        profile_id=profile.profile_id,
        source_host=profile.source_host,
        execution_host=profile.execution_host,
        artifact_hashes=core_hashes,
        preflight_id="preflight-1",
        project_hash=compute_project_hash(core_hashes),
        input_count=len(mapped_inputs),
        input_set_hash=compute_input_set_hash(mapped_inputs),
        checks=tuple(PreflightCheck(name=name, status="passed") for name in _CHECK_NAMES),
    )
    preflight_path = project / "reports" / "preflight.json"
    preflight_path.write_text(preflight.to_json(), encoding="utf-8")
    paths = ApprovalArtifactPaths(
        dataset_manifest=project / "dataset.manifest.resolved.json",
        pipeline_spec=project / "pipeline.spec.yaml",
        execution_plan=project / "execution.plan.yaml",
        software_lock=project / "software.lock.yaml",
        validation_report=validation_path,
        test_report=test_path,
        execution_profile=profile_path,
        preflight_report=preflight_path,
    )
    request = ApprovalRequest(
        policy=RunPolicy(run_real_data=True, require_approval=True),
        approve_real_data=True,
        actor="test-operator",
        approved_at=_CHECKED_AT + timedelta(seconds=5),
    )
    return _GateFixture(
        project=project,
        paths=paths,
        profile=profile,
        core_hashes=core_hashes,
        request=request,
        bundle_hash="b" * 64,
        manifest=manifest,
    )


def _authorize(fixture: _GateFixture, **kwargs: object):
    return ApprovalGate().authorize(
        fixture.paths,
        fixture.request,
        bundle_hash=fixture.bundle_hash,
        now=_CHECKED_AT + timedelta(seconds=10),
        **kwargs,  # type: ignore[arg-type]
    )


def test_gate_authorizes_exact_evidence_without_mutating_m3_artifacts(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    core_before = {
        name: path.read_bytes()
        for name, path in {
            "manifest": fixture.paths.dataset_manifest,
            "spec": fixture.paths.pipeline_spec,
            "plan": fixture.paths.execution_plan,
            "lock": fixture.paths.software_lock,
        }.items()
    }

    first = _authorize(fixture)
    second = _authorize(fixture)

    assert first == second
    assert first.cli_approved is True
    assert first.policy.run_real_data is True
    assert first.bundle_hash == fixture.bundle_hash
    assert first.artifact_hashes.dataset_manifest == fixture.core_hashes.dataset_manifest
    assert core_before == {
        name: path.read_bytes()
        for name, path in {
            "manifest": fixture.paths.dataset_manifest,
            "spec": fixture.paths.pipeline_spec,
            "plan": fixture.paths.execution_plan,
            "lock": fixture.paths.software_lock,
        }.items()
    }


def test_gate_requires_cli_approval_and_attribution(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    denied = fixture.request.model_copy(update={"approve_real_data": False})

    with pytest.raises(BioPipeError) as caught:
        ApprovalGate().authorize(fixture.paths, denied, bundle_hash=fixture.bundle_hash)

    assert caught.value.code is ErrorCode.APPROVAL_REQUIRED
    forged = fixture.request.model_copy(update={"actor": "\n"})
    with pytest.raises(BioPipeError) as invalid:
        ApprovalGate().authorize(fixture.paths, forged, bundle_hash=fixture.bundle_hash)
    assert invalid.value.code is ErrorCode.APPROVAL_REQUIRED


@pytest.mark.parametrize(
    ("age", "expected"),
    [
        (timedelta(seconds=901), ErrorCode.PREFLIGHT_STALE),
        (timedelta(seconds=10), ErrorCode.PREFLIGHT_FAILED),
    ],
)
def test_gate_rejects_stale_or_failed_preflight(
    tmp_path: Path,
    age: timedelta,
    expected: ErrorCode,
) -> None:
    fixture = _setup(tmp_path)
    if expected is ErrorCode.PREFLIGHT_FAILED:
        payload = json.loads(fixture.paths.preflight_report.read_text(encoding="utf-8"))
        payload["status"] = "failed"
        payload["checks"][0]["status"] = "failed"
        _write_json(fixture.paths.preflight_report, payload)

    with pytest.raises(BioPipeError) as caught:
        ApprovalGate().authorize(
            fixture.paths,
            fixture.request,
            bundle_hash=fixture.bundle_hash,
            now=_CHECKED_AT + age,
        )

    assert caught.value.code is expected


def test_gate_rejects_report_or_preflight_hash_tampering(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    payload = json.loads(fixture.paths.test_report.read_text(encoding="utf-8"))
    payload["static_validation"]["artifact_hashes"]["pipeline.spec.yaml"] = "0" * 64
    _write_json(fixture.paths.test_report, payload)

    with pytest.raises(BioPipeError) as caught:
        _authorize(fixture)

    assert caught.value.code is ErrorCode.APPROVAL_ARTIFACT_MISMATCH


def test_gate_rejects_duplicate_json_keys_and_symlink_artifacts(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    fixture.paths.test_report.write_text('{"status":"passed","status":"passed"}\n')
    with pytest.raises(BioPipeError) as duplicate:
        _authorize(fixture)
    assert duplicate.value.code is ErrorCode.APPROVAL_ARTIFACT_MISMATCH

    fixture = _setup(tmp_path / "second")
    real = fixture.paths.preflight_report
    target = tmp_path / "preflight-target.json"
    real.replace(target)
    real.symlink_to(target)
    with pytest.raises(BioPipeError) as symlink:
        ApprovalGate().authorize(
            fixture.paths,
            fixture.request,
            bundle_hash=fixture.bundle_hash,
            now=_CHECKED_AT + timedelta(seconds=10),
        )
    assert symlink.value.code is ErrorCode.APPROVAL_ARTIFACT_MISMATCH


def test_execution_profile_enforces_container_runtime_contract(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    payload = fixture.profile.model_dump(mode="python")
    payload["ssh_alias"] = "-oProxyCommand=bad"
    with pytest.raises(ValidationError):
        ExecutionProfile.model_validate(payload)

    payload = fixture.profile.model_dump(mode="python")
    payload["containers"] = {
        name: {**artifact, "local_path": None, "file_sha256": None}
        for name, artifact in payload["containers"].items()
    }
    with pytest.raises(ValidationError):
        ExecutionProfile.model_validate(payload)


def test_profile_registry_is_create_only_and_rejects_symlinks(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    registry = ExecutionProfileRegistry(tmp_path / "profiles")
    assert registry.list() == ()
    stored = registry.register(fixture.profile)
    assert registry.load(fixture.profile.profile_id) == fixture.profile
    assert registry.list() == (fixture.profile,)
    with pytest.raises(BioPipeError) as duplicate:
        registry.register(fixture.profile)
    assert duplicate.value.code is ErrorCode.EXECUTION_PROFILE_INVALID

    stored.unlink()
    target = tmp_path / "outside.json"
    target.write_text(fixture.profile.to_json(), encoding="utf-8")
    stored.symlink_to(target)
    with pytest.raises(BioPipeError) as symlink:
        registry.load(fixture.profile.profile_id)
    assert symlink.value.code is ErrorCode.EXECUTION_PROFILE_INVALID

    outside = tmp_path / "outside-directory"
    outside.mkdir()
    linked_directory = tmp_path / "linked-directory"
    linked_directory.symlink_to(outside, target_is_directory=True)
    unsafe_registry = ExecutionProfileRegistry(linked_directory / "profiles")
    with pytest.raises(BioPipeError) as ancestor:
        unsafe_registry.register(fixture.profile)
    assert ancestor.value.code is ErrorCode.EXECUTION_PROFILE_INVALID
    assert not (outside / "profiles").exists()


def test_resume_requires_the_same_profile_project_and_bundle(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    previous = _authorize(fixture)
    resume_request = fixture.request.model_copy(
        update={"policy": RunPolicy(run_real_data=True, require_approval=True, resume=True)}
    )
    current = ApprovalGate().authorize(
        fixture.paths,
        resume_request,
        bundle_hash=fixture.bundle_hash,
        previous_authorization=previous,
        now=_CHECKED_AT + timedelta(seconds=10),
    )
    assert current.compatibility_hash == previous.compatibility_hash

    incompatible = current.model_copy(update={"compatibility_hash": "0" * 64})
    with pytest.raises(BioPipeError) as caught:
        assert_resume_compatible(previous, incompatible)
    assert caught.value.code is ErrorCode.RESUME_INCOMPATIBLE
