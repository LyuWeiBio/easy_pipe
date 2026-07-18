"""M6 dry-run guarantees for every controller write or remote surface."""

from __future__ import annotations

import hashlib
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from typer.testing import CliRunner, Result

from biopipe.cli.app import app
from biopipe.cli.reports import write_project_report_atomic
from biopipe.compiler import NextflowCompiler
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution.models import (
    AllowedExecutionRoots,
    ApprovalSigner,
    ContainerArtifact,
    ExecutionProfile,
    LocalExecutionRuntime,
    compute_input_set_hash,
)
from biopipe.execution.preflight import run_preflight
from biopipe.execution.runner import query_run_status, submit_approved_run
from biopipe.manifests import finalize_manifest
from biopipe.models import (
    DatasetClassification,
    DatasetManifest,
    DatasetObservations,
    DatasetSample,
    LaneFiles,
    ManifestPrivacy,
    ManifestSource,
    SourceProfile,
)
from biopipe.planner import PlanningOptions, plan_fastq_qc
from biopipe.registry import load_default_registry
from biopipe.validation import ValidationReport, validate_generated_project
from biopipe.version import CLI_CONTRACT_VERSION
from biopipe.workflow_test import WorkflowTestCode, WorkflowTestReport, WorkflowTestStatus

runner = CliRunner()

_REMOTE_PREFLIGHT_CHECKS = (
    "cache_writable",
    "container",
    "disk_space",
    "host_relationship",
    "output_dir_writable",
    "path_mapping",
    "rawdata_readable",
    "runtime",
    "workdir_writable",
)


def _forbidden(*_args: object, **_kwargs: object) -> Any:
    raise AssertionError("dry-run reached a forbidden side-effect boundary")


def _valid_static_report(project: Path) -> ValidationReport:
    return ValidationReport(
        project_directory=str(project.absolute()),
        status="valid",
        checked_artifacts=[],
        artifact_hashes={},
        findings=[],
    )


def _assert_dry_run(result: Result) -> dict[str, Any]:
    assert result.exit_code == 0, result.output
    payload = cast(dict[str, Any], json.loads(result.stdout))
    assert CLI_CONTRACT_VERSION == "1.0"
    assert payload["cli_contract_version"] == CLI_CONTRACT_VERSION
    assert payload["dry_run"] is True
    assert payload["side_effects_performed"] is False
    return payload


def _tree_fingerprint(root: Path) -> dict[str, tuple[int, int, int, str | None]]:
    fingerprint: dict[str, tuple[int, int, int, str | None]] = {}
    for path in sorted((root, *root.rglob("*"))):
        metadata = path.lstat()
        digest = (
            hashlib.sha256(path.read_bytes()).hexdigest()
            if stat.S_ISREG(metadata.st_mode)
            else None
        )
        fingerprint[path.relative_to(root.parent).as_posix()] = (
            metadata.st_mode,
            metadata.st_size,
            metadata.st_mtime_ns,
            digest,
        )
    return fingerprint


class _ExecutionClient:
    def __init__(self, *, lose_submit_response: bool = False) -> None:
        self.work_dir = ""
        self.output_dir = ""
        self.remote_status = "running"
        self.lose_submit_response = lose_submit_response

    def invoke(
        self,
        source: SourceProfile,
        *,
        agent_path: str,
        operation: str,
        payload: dict[str, Any],
        request_id: str | None = None,
    ) -> dict[str, Any]:
        del source, agent_path, request_id
        if operation == "preflight":
            execution_paths = cast(list[str], payload["execution_paths"])
            self.work_dir = cast(str, payload["work_dir"])
            self.output_dir = cast(str, payload["output_dir"])
            return {
                "preflight_id": payload["preflight_id"],
                "preflight_token": "t" * 64,
                "status": "passed",
                "checks": [
                    {"name": name, "status": "passed", "code": None, "message": None}
                    for name in _REMOTE_PREFLIGHT_CHECKS
                ],
                "input_count": len(set(execution_paths)),
                "input_set_hash": compute_input_set_hash(execution_paths),
            }
        if operation == "deploy":
            return {
                "deployment_id": payload["deployment_id"],
                "bundle_hash": payload["bundle_hash"],
                "file_count": len(cast(list[object], payload["files"])),
                "status": "deployed",
            }
        if operation in {"submit", "resume"}:
            if self.lose_submit_response:
                raise BioPipeError(
                    ErrorCode.SSH_TIMEOUT,
                    "The remote execution request exceeded its timeout.",
                    context={"operation": operation},
                )
            return {
                "run_id": payload["run_id"],
                "status": "submitted",
                "remote_work_dir": self.work_dir,
                "result_dir": self.output_dir,
                "command_hash": "a" * 64,
                "environment_hash": "b" * 64,
            }
        if operation == "status":
            return {
                "run_id": payload["run_id"],
                "status": self.remote_status,
                "return_code": 0 if self.remote_status == "succeeded" else None,
                "command_hash": "a" * 64,
                "environment_hash": "b" * 64,
            }
        raise AssertionError(f"unexpected operation: {operation}")


def _workflow_report(mode: str) -> WorkflowTestReport:
    return WorkflowTestReport(
        mode=mode,  # type: ignore[arg-type]
        status=WorkflowTestStatus.PASSED,
        code=WorkflowTestCode.OK,
        layout="paired_end",
        trimming_enabled=False,
    )


def _setup_run_project(tmp_path: Path) -> SimpleNamespace:
    raw_root = "/remote/raw"
    manifest = finalize_manifest(
        DatasetManifest(
            source=ManifestSource(
                source_id="source-a",
                root=raw_root,
                scanned_at=datetime(2026, 7, 18, 1, 0, tzinfo=UTC),
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
                            read1=f"{raw_root}/sample-A_L001_R1_001.fastq.gz",
                            read2=f"{raw_root}/sample-A_L001_R2_001.fastq.gz",
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
    planned = plan_fastq_qc(
        manifest,
        PlanningOptions(
            project_name="project-qc",
            trimming_enabled=False,
            container_engine="docker",
            work_dir="/remote/work/project-qc",
            output_dir="/remote/results/project-qc",
            container_cache="/remote/cache/project-qc",
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
    write_project_report_atomic(
        project,
        "validation.json",
        {
            "report_version": "1.0",
            "command": "validate",
            "status": "passed",
            "code": "OK",
            "project_directory": str(project),
            "report_path": "reports/validation.json",
            "synthetic_data_only": True,
            "static_validation": static.to_dict(),
            "runtime_validation": _workflow_report("validate").model_dump(mode="json"),
            "remediation": [],
        },
    )
    write_project_report_atomic(
        project,
        "test.json",
        {
            "report_version": "1.0",
            "command": "test",
            "profile": "test",
            "status": "passed",
            "code": "OK",
            "project_directory": str(project),
            "report_path": "reports/test.json",
            "synthetic_data_only": True,
            "static_validation": static.to_dict(),
            "runs": {
                mode: _workflow_report(mode).model_dump(mode="json") for mode in ("e2e", "stub")
            },
            "remediation": [],
        },
    )
    approval_key = tmp_path / "approval.key"
    approval_key.write_text("9" * 64 + "\n", encoding="ascii")
    approval_key.chmod(0o600)
    profile = ExecutionProfile(
        profile_id="remote-local",
        source_host="source-a",
        execution_host="source-a",
        ssh_alias="source-a",
        username="runner",
        approval_signer=ApprovalSigner(
            key_id="controller-1",
            key_file=str(approval_key),
        ),
        allowed_roots=AllowedExecutionRoots(
            deploy=("/remote/deploy",),
            work=("/remote/work",),
            output=("/remote/results",),
            cache=("/remote/cache",),
        ),
        runtime=LocalExecutionRuntime(container_engine="docker"),
        containers={
            name: ContainerArtifact(image=component.image, digest=component.digest)
            for name, component in planned.software_lock.components.items()
        },
    )
    profile_path = tmp_path / "remote-local.json"
    profile_path.write_text(profile.to_json(), encoding="utf-8")
    return SimpleNamespace(project=project, profile_path=profile_path, profile=profile)


def _prepared_run_fixture(
    tmp_path: Path,
    *,
    resume: bool = False,
    pending: bool = False,
    nonterminal: bool = False,
) -> Any:
    assert sum((resume, pending, nonterminal)) <= 1
    fixture = _setup_run_project(tmp_path)
    client = _ExecutionClient(lose_submit_response=pending)
    first_preflight_at = datetime.now(UTC) - timedelta(seconds=2)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=first_preflight_at,
    )
    fixture.resume_run_id = None
    if resume or pending or nonterminal:
        if pending:
            with pytest.raises(BioPipeError) as caught:
                submit_approved_run(
                    fixture.project,
                    fixture.profile_path,
                    actor="pytest-operator",
                    approve_real_data=True,
                    client=client,
                    approved_at=first_preflight_at + timedelta(seconds=1),
                )
            assert caught.value.code is ErrorCode.SSH_TIMEOUT
        else:
            submitted = submit_approved_run(
                fixture.project,
                fixture.profile_path,
                actor="pytest-operator",
                approve_real_data=True,
                client=client,
                approved_at=first_preflight_at + timedelta(seconds=1),
            )
            assert submitted.run_id is not None
            if resume:
                client.remote_status = "succeeded"
                query_run_status(
                    fixture.project,
                    fixture.profile_path,
                    run_id=submitted.run_id,
                    client=client,
                )
                run_preflight(
                    fixture.project,
                    fixture.profile_path,
                    client=client,
                    checked_at=datetime.now(UTC),
                    resume_run_id=submitted.run_id,
                )
            fixture.resume_run_id = submitted.run_id
    Path(fixture.profile.approval_signer.key_file).unlink()
    return fixture


def test_source_add_dry_run_does_not_create_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("biopipe.cli.source.SourceRegistry.add", _forbidden)
    config = tmp_path / "controller"

    result = runner.invoke(
        app,
        [
            "source",
            "add",
            "synthetic-source",
            "--host",
            "synthetic-host",
            "--allowed-root",
            "/srv/synthetic-raw",
            "--config-dir",
            str(config),
            "--dry-run",
            "--json",
        ],
    )

    payload = _assert_dry_run(result)
    assert payload["status"] == "would_add"
    assert not config.exists()


@pytest.mark.parametrize(
    ("command", "status", "remote"),
    [
        ("remove", "would_remove", []),
        ("verify", "would_verify", ["probe.health"]),
    ],
)
def test_existing_source_dry_runs_neither_mutate_nor_contact_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    status: str,
    remote: list[str],
) -> None:
    profile = SourceProfile(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        allowed_roots=["/srv/synthetic-raw"],
    )
    monkeypatch.setattr("biopipe.cli.source.SourceRegistry.get", lambda *_args: profile)
    monkeypatch.setattr("biopipe.cli.source.SourceRegistry.remove", _forbidden)
    monkeypatch.setattr("biopipe.cli.source.OpenSSHProbeClient", _forbidden)
    config = tmp_path / "controller"

    result = runner.invoke(
        app,
        [
            "source",
            command,
            "synthetic-source",
            "--config-dir",
            str(config),
            "--dry-run",
            "--json",
        ],
    )

    payload = _assert_dry_run(result)
    assert payload["status"] == status
    assert payload["remote_operations"] == remote
    assert not config.exists()


def test_inspect_dry_run_never_constructs_probe_client_or_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = SourceProfile(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        allowed_roots=["/srv/synthetic-raw"],
    )
    monkeypatch.setattr("biopipe.cli.inspect.SourceRegistry.get", lambda *_args: profile)
    monkeypatch.setattr("biopipe.cli.inspect.OpenSSHProbeClient", _forbidden)
    output = tmp_path / "artifacts" / "dataset.json"

    result = runner.invoke(
        app,
        [
            "inspect",
            "synthetic-source:/srv/synthetic-raw",
            "--policy",
            "format-summary",
            "--output",
            str(output),
            "--config-dir",
            str(tmp_path / "controller"),
            "--dry-run",
            "--json",
        ],
    )

    payload = _assert_dry_run(result)
    assert payload["remote_operations"] == [
        "probe.detect_formats",
        "probe.list_tree",
        "probe.summarize_fastq",
    ]
    assert not output.parent.exists()


@pytest.mark.parametrize("root", ["relative/path", "/srv/outside-allowlist"])
def test_inspect_dry_run_rejects_invalid_or_out_of_scope_root_before_ssh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    root: str,
) -> None:
    profile = SourceProfile(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        allowed_roots=["/srv/synthetic-raw"],
    )
    monkeypatch.setattr("biopipe.cli.inspect.SourceRegistry.get", lambda *_args: profile)
    monkeypatch.setattr("biopipe.cli.inspect.OpenSSHProbeClient", _forbidden)

    result = runner.invoke(
        app,
        [
            "inspect",
            f"synthetic-source:{root}",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "VALIDATION_FAILED"


def test_manifest_override_dry_run_resolves_in_memory_without_bundle_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved = SimpleNamespace(
        errors=[],
        integrity=SimpleNamespace(manifest_sha256="a" * 64),
    )
    monkeypatch.setattr("biopipe.cli.manifest.read_model", lambda *_args: object())
    monkeypatch.setattr("biopipe.cli.manifest.require_valid_manifest", lambda value: value)
    monkeypatch.setattr(
        "biopipe.cli.manifest.apply_overrides",
        lambda *_args: SimpleNamespace(resolved_manifest=resolved, diff=object()),
    )
    monkeypatch.setattr("biopipe.cli.manifest.sanitize_manifest", lambda *_args: object())
    monkeypatch.setattr("biopipe.cli.manifest.render_samplesheet", lambda *_args: "sample\n")
    monkeypatch.setattr("biopipe.cli.manifest.ManifestArtifactStore.create_bundle", _forbidden)
    destination = tmp_path / "resolved"
    manifest_path = tmp_path / "manifest.json"
    overrides_path = tmp_path / "overrides.json"
    manifest_path.write_text("{}\n", encoding="utf-8")
    overrides_path.write_text("{}\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "manifest",
            "apply-overrides",
            str(manifest_path),
            "--overrides",
            str(overrides_path),
            "--output-dir",
            str(destination),
            "--dry-run",
            "--json",
        ],
    )

    _assert_dry_run(result)
    assert not destination.exists()


def test_plan_dry_run_does_not_create_planning_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = SimpleNamespace(source=SimpleNamespace(root="/srv/synthetic-raw"))
    planned = SimpleNamespace(
        component_ids=("fastqc_raw_v1", "multiqc_v1"),
        registry_version="1.0.0",
    )
    monkeypatch.setattr("biopipe.cli.plan.read_model", lambda *_args: manifest)
    monkeypatch.setattr("biopipe.cli.plan.plan_fastq_qc", lambda *_args: planned)
    monkeypatch.setattr("biopipe.cli.plan._create_plan_bundle", _forbidden)
    output = tmp_path / "planning" / "pipeline.spec.yaml"
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{}\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "plan",
            "--manifest",
            str(manifest_path),
            "--output",
            str(output),
            "--dry-run",
            "--json",
        ],
    )

    _assert_dry_run(result)
    assert not output.parent.exists()


def test_generate_dry_run_does_not_render_project(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    planned = SimpleNamespace(
        component_ids=("fastqc_raw_v1", "multiqc_v1"),
        registry_version="1.0.0",
    )
    monkeypatch.setattr("biopipe.cli.generate.read_model", lambda *_args: object())
    monkeypatch.setattr(
        "biopipe.cli.generate.reconstruct_planned_pipeline",
        lambda *_args, **_kwargs: planned,
    )
    monkeypatch.setattr("biopipe.cli.generate.require_valid_manifest", lambda *_args: None)
    monkeypatch.setattr("biopipe.cli.generate.compile_nextflow_project", _forbidden)
    output = tmp_path / "generated"
    spec_path = tmp_path / "pipeline.spec.yaml"
    spec_path.write_text("{}\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "generate",
            "--spec",
            str(spec_path),
            "--output",
            str(output),
            "--dry-run",
            "--json",
        ],
    )

    _assert_dry_run(result)
    assert not output.exists()


@pytest.mark.parametrize("command", ["validate", "test"])
def test_workflow_check_dry_runs_skip_external_tools_and_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
) -> None:
    project = tmp_path / "generated"
    target = f"biopipe.cli.{command}"
    monkeypatch.setattr(
        f"{target}.validate_generated_project",
        lambda *_args, **_kwargs: _valid_static_report(project),
    )
    monkeypatch.setattr(f"{target}.WorkflowTestRunner", _forbidden)
    monkeypatch.setattr(f"{target}.write_project_report_atomic", _forbidden)

    result = runner.invoke(app, [command, str(project), "--dry-run", "--json"])

    _assert_dry_run(result)
    assert not project.exists()


def test_execution_profile_dry_run_never_reads_key_or_registers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    software_lock = load_default_registry().software_lock(("fastqc_raw_v1", "multiqc_v1"))
    monkeypatch.setattr("biopipe.cli.execution_profile.read_model", lambda *_args: software_lock)
    monkeypatch.setattr("biopipe.cli.execution_profile.validate_approval_key", _forbidden)
    monkeypatch.setattr(
        "biopipe.cli.execution_profile.ExecutionProfileRegistry.register",
        _forbidden,
    )
    output = tmp_path / "profiles"

    result = runner.invoke(
        app,
        [
            "execution-profile",
            "create",
            "local-docker",
            "--source-host",
            "source-a",
            "--execution-host",
            "source-a",
            "--ssh-alias",
            "source-a",
            "--software-lock",
            str(tmp_path / "software.lock.yaml"),
            "--output-dir",
            str(output),
            "--deploy-root",
            "/remote/deploy",
            "--work-root",
            "/remote/work",
            "--output-root",
            "/remote/results",
            "--cache-root",
            "/remote/cache",
            "--container-engine",
            "docker",
            "--approval-key-id",
            "controller-1",
            "--approval-key-file",
            str(tmp_path / "missing.key"),
            "--dry-run",
            "--json",
        ],
    )

    _assert_dry_run(result)
    assert not output.exists()


def test_preflight_dry_run_never_contacts_executor_or_writes_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "generated"
    monkeypatch.setattr(
        "biopipe.cli.preflight.read_model",
        lambda *_args: SimpleNamespace(profile_id="local-docker"),
    )
    monkeypatch.setattr(
        "biopipe.cli.preflight.validate_generated_project",
        lambda *_args, **_kwargs: _valid_static_report(project),
    )
    monkeypatch.setattr("biopipe.cli.preflight.run_preflight", _forbidden)

    result = runner.invoke(
        app,
        [
            "preflight",
            str(project),
            "--execution-profile",
            str(tmp_path / "profile.json"),
            "--dry-run",
            "--json",
        ],
    )

    payload = _assert_dry_run(result)
    assert payload["remote_operations"] == ["executor.preflight"]
    assert not project.exists()


@pytest.mark.parametrize(
    ("mode_options", "expected_remote"),
    [
        (["--status", "run-" + "2" * 32], ["executor.status"]),
        (["--abandon-pending", "run-" + "3" * 32], ["executor.abandon"]),
    ],
)
def test_status_and_abandon_dry_run_remain_side_effect_free_previews(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode_options: list[str],
    expected_remote: list[str],
) -> None:
    monkeypatch.setattr("biopipe.cli.run.submit_approved_run", _forbidden)
    monkeypatch.setattr("biopipe.cli.run.query_run_status", _forbidden)
    monkeypatch.setattr("biopipe.cli.run.abandon_pending_run", _forbidden)
    project = tmp_path / "does-not-exist"

    result = runner.invoke(
        app,
        [
            "run",
            str(project),
            "--execution-profile",
            str(tmp_path / "missing-profile.json"),
            *mode_options,
            "--dry-run",
            "--json",
        ],
    )

    payload = _assert_dry_run(result)
    assert payload["remote_operations"] == expected_remote
    assert not project.exists()


@pytest.mark.parametrize(
    ("resume", "expected_status", "expected_remote"),
    [
        (False, "would_submit", ["executor.deploy", "executor.submit"]),
        (True, "would_resume", ["executor.resume"]),
    ],
)
def test_submit_and_resume_dry_run_validate_local_gate_without_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    resume: bool,
    expected_status: str,
    expected_remote: list[str],
) -> None:
    fixture = _prepared_run_fixture(tmp_path, resume=resume)
    mode_options = (
        ["--resume", cast(str, fixture.resume_run_id), "--approve-real-data"]
        if resume
        else ["--approve-real-data"]
    )
    before = _tree_fingerprint(fixture.project)
    profile_before = fixture.profile_path.read_bytes()
    forbidden = (
        "biopipe.cli.run.submit_approved_run",
        "biopipe.cli.run.query_run_status",
        "biopipe.cli.run.abandon_pending_run",
        "biopipe.execution.preflight.build_deployment_bundle",
        "biopipe.execution.deploy.build_deployment_bundle",
        "biopipe.execution.runner.load_execution_context",
        "biopipe.execution.runner.OpenSSHExecutionClient",
        "biopipe.execution.runner.AuditWriter",
        "biopipe.execution.runner.sign_run_payload",
        "biopipe.execution.signing._read_key",
        "biopipe.execution.runner.write_project_private_state_atomic",
        "biopipe.execution.runner.write_project_report_atomic",
        "biopipe.execution.runner.write_project_report_create_only_atomic",
        "biopipe.compiler.NextflowCompiler.compile_planned",
        "biopipe.execution.deploy.tempfile.TemporaryDirectory",
    )
    for target in forbidden:
        monkeypatch.setattr(target, _forbidden)

    result = runner.invoke(
        app,
        [
            "run",
            str(fixture.project),
            "--execution-profile",
            str(fixture.profile_path),
            "--actor",
            "pytest-operator",
            *mode_options,
            "--dry-run",
            "--json",
        ],
    )

    payload = _assert_dry_run(result)
    assert payload["status"] == expected_status
    assert payload["local_gate_validation"] == "passed"
    assert payload["remote_operations"] == expected_remote
    assert payload["details"]["approval_required_for_execution"] is True
    assert payload["details"]["real_data_approval_provided"] is True
    assert _tree_fingerprint(fixture.project) == before
    assert fixture.profile_path.read_bytes() == profile_before
    assert not Path(fixture.profile.approval_signer.key_file).exists()


def test_resume_dry_run_rejects_an_unrecorded_run_id_without_side_effects(
    tmp_path: Path,
) -> None:
    fixture = _prepared_run_fixture(tmp_path)
    before = _tree_fingerprint(fixture.project)

    result = runner.invoke(
        app,
        [
            "run",
            str(fixture.project),
            "--execution-profile",
            str(fixture.profile_path),
            "--resume",
            "run-" + "1" * 32,
            "--actor",
            "pytest-operator",
            "--approve-real-data",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["code"] == "RUN_STATUS_FAILED"
    assert _tree_fingerprint(fixture.project) == before


def test_resume_dry_run_rejects_a_recorded_nonterminal_run_without_side_effects(
    tmp_path: Path,
) -> None:
    fixture = _prepared_run_fixture(tmp_path, nonterminal=True)
    before = _tree_fingerprint(fixture.project)

    result = runner.invoke(
        app,
        [
            "run",
            str(fixture.project),
            "--execution-profile",
            str(fixture.profile_path),
            "--resume",
            cast(str, fixture.resume_run_id),
            "--actor",
            "pytest-operator",
            "--approve-real-data",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["code"] == "RESUME_INCOMPATIBLE"
    assert _tree_fingerprint(fixture.project) == before


def test_resume_dry_run_rejects_changed_authorization_compatibility_without_side_effects(
    tmp_path: Path,
) -> None:
    fixture = _prepared_run_fixture(tmp_path, resume=True)
    state_path = fixture.project / "reports" / ".run-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["authorization"]["compatibility_hash"] = "0" * 64
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    before = _tree_fingerprint(fixture.project)

    result = runner.invoke(
        app,
        [
            "run",
            str(fixture.project),
            "--execution-profile",
            str(fixture.profile_path),
            "--resume",
            cast(str, fixture.resume_run_id),
            "--actor",
            "pytest-operator",
            "--approve-real-data",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "RESUME_INCOMPATIBLE"
    assert error["context"]["reason"] == "authorization_inputs_changed"
    assert _tree_fingerprint(fixture.project) == before


@pytest.mark.parametrize("field", ["deployment_dir", "deployment_id"])
def test_resume_dry_run_rejects_changed_private_deployment_binding_without_side_effects(
    tmp_path: Path,
    field: str,
) -> None:
    fixture = _prepared_run_fixture(tmp_path, resume=True)
    state_path = fixture.project / "reports" / ".preflight-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state[field] = "/remote/deploy/other" if field == "deployment_dir" else "deployment-" + "0" * 32
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    before = _tree_fingerprint(fixture.project)

    result = runner.invoke(
        app,
        [
            "run",
            str(fixture.project),
            "--execution-profile",
            str(fixture.profile_path),
            "--resume",
            cast(str, fixture.resume_run_id),
            "--actor",
            "pytest-operator",
            "--approve-real-data",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["code"] == "APPROVAL_ARTIFACT_MISMATCH"
    assert _tree_fingerprint(fixture.project) == before


def test_submit_dry_run_rejects_a_pending_submission_without_side_effects(
    tmp_path: Path,
) -> None:
    fixture = _prepared_run_fixture(tmp_path, pending=True)
    before = _tree_fingerprint(fixture.project)

    result = runner.invoke(
        app,
        [
            "run",
            str(fixture.project),
            "--execution-profile",
            str(fixture.profile_path),
            "--actor",
            "pytest-operator",
            "--approve-real-data",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["code"] == "RUN_SUBMISSION_FAILED"
    assert _tree_fingerprint(fixture.project) == before


@pytest.mark.parametrize(
    "approval_options",
    [[], ["--actor", "pytest-operator"], ["--approve-real-data"]],
)
def test_submit_dry_run_requires_actor_and_approval_before_reading_local_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    approval_options: list[str],
) -> None:
    monkeypatch.setattr("biopipe.cli.run._validate_local_submission_gate", _forbidden)

    result = runner.invoke(
        app,
        [
            "run",
            str(tmp_path / "missing-project"),
            "--execution-profile",
            str(tmp_path / "missing-profile.json"),
            *approval_options,
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["code"] == "APPROVAL_REQUIRED"


def test_submit_dry_run_rejects_unsafe_actor_before_reading_local_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("biopipe.cli.run._validate_local_submission_gate", _forbidden)

    result = runner.invoke(
        app,
        [
            "run",
            str(tmp_path / "missing-project"),
            "--execution-profile",
            str(tmp_path / "missing-profile.json"),
            "--actor",
            "unsafe actor",
            "--approve-real-data",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["code"] == "APPROVAL_REQUIRED"


@pytest.mark.parametrize("tamper", ["missing_project", "missing_profile", "generated_code"])
def test_submit_dry_run_rejects_missing_or_tampered_local_gate_inputs(
    tmp_path: Path,
    tamper: str,
) -> None:
    if tamper == "missing_project":
        project = tmp_path / "missing-project"
        profile = tmp_path / "missing-profile.json"
    else:
        fixture = _prepared_run_fixture(tmp_path)
        project = fixture.project
        profile = fixture.profile_path
        if tamper == "missing_profile":
            profile.unlink()
        else:
            (project / "main.nf").write_text("tampered\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "run",
            str(project),
            "--execution-profile",
            str(profile),
            "--actor",
            "pytest-operator",
            "--approve-real-data",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["code"] in {
        "APPROVAL_ARTIFACT_MISMATCH",
        "DEPLOYMENT_FAILED",
    }


@pytest.mark.parametrize(
    ("tamper", "expected_code"),
    [
        ("missing_validation_report", "APPROVAL_ARTIFACT_MISMATCH"),
        ("missing_test_report", "APPROVAL_ARTIFACT_MISMATCH"),
        ("failed_validation_report", "APPROVAL_ARTIFACT_MISMATCH"),
        ("missing_private_preflight_state", "ARTIFACT_READ_FAILED"),
        ("private_preflight_id_mismatch", "APPROVAL_ARTIFACT_MISMATCH"),
        ("private_checked_at_mismatch", "APPROVAL_ARTIFACT_MISMATCH"),
        ("private_bundle_hash_mismatch", "APPROVAL_ARTIFACT_MISMATCH"),
        ("private_deployment_dir_mismatch", "APPROVAL_ARTIFACT_MISMATCH"),
        ("report_hash_mismatch", "APPROVAL_ARTIFACT_MISMATCH"),
        ("symlink_profile", "APPROVAL_ARTIFACT_MISMATCH"),
        ("failed_preflight", "PREFLIGHT_FAILED"),
        ("preflight_profile_mismatch", "APPROVAL_ARTIFACT_MISMATCH"),
        ("preflight_artifact_mismatch", "APPROVAL_ARTIFACT_MISMATCH"),
        ("preflight_input_mismatch", "APPROVAL_ARTIFACT_MISMATCH"),
        ("stale_preflight", "PREFLIGHT_STALE"),
        ("future_preflight", "PREFLIGHT_STALE"),
    ],
)
def test_submit_dry_run_requires_bound_successful_fresh_gate_evidence(
    tmp_path: Path,
    tamper: str,
    expected_code: str,
) -> None:
    fixture = _prepared_run_fixture(tmp_path)
    if tamper == "missing_validation_report":
        (fixture.project / "reports" / "validation.json").unlink()
    elif tamper == "missing_test_report":
        (fixture.project / "reports" / "test.json").unlink()
    elif tamper == "failed_validation_report":
        validation_path = fixture.project / "reports" / "validation.json"
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        validation["status"] = "failed"
        validation["code"] = "CONFIG_CHECK_FAILED"
        validation["runtime_validation"]["status"] = "failed"
        validation["runtime_validation"]["code"] = "CONFIG_CHECK_FAILED"
        validation_path.write_text(json.dumps(validation, sort_keys=True), encoding="utf-8")
    elif tamper == "missing_private_preflight_state":
        (fixture.project / "reports" / ".preflight-state.json").unlink()
    elif tamper.startswith("private_"):
        state_path = fixture.project / "reports" / ".preflight-state.json"
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if tamper == "private_preflight_id_mismatch":
            state["preflight_id"] = "preflight-" + "0" * 32
        elif tamper == "private_checked_at_mismatch":
            state["checked_at"] = "2000-01-01T00:00:00Z"
        elif tamper == "private_deployment_dir_mismatch":
            state["deployment_dir"] = "/remote/deploy/other"
        else:
            state["bundle_hash"] = "0" * 64
        state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    elif tamper == "report_hash_mismatch":
        validation_path = fixture.project / "reports" / "validation.json"
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        validation["static_validation"]["artifact_hashes"]["pipeline.spec.yaml"] = "0" * 64
        validation_path.write_text(json.dumps(validation), encoding="utf-8")
    elif tamper == "symlink_profile":
        profile_bytes = fixture.profile_path.read_bytes()
        real_profile = tmp_path / "real-profile.json"
        real_profile.write_bytes(profile_bytes)
        fixture.profile_path.unlink()
        fixture.profile_path.symlink_to(real_profile)
    else:
        preflight_path = fixture.project / "reports" / "preflight.json"
        preflight = json.loads(preflight_path.read_text(encoding="utf-8"))
        if tamper == "failed_preflight":
            preflight["status"] = "failed"
            preflight["checks"][0]["status"] = "failed"
        elif tamper == "preflight_profile_mismatch":
            preflight["profile_id"] = "other-profile"
        elif tamper == "preflight_artifact_mismatch":
            preflight["artifact_hashes"]["pipeline_spec"] = "0" * 64
        elif tamper == "preflight_input_mismatch":
            preflight["input_set_hash"] = "0" * 64
        elif tamper == "stale_preflight":
            preflight["checked_at"] = "2000-01-01T00:00:00Z"
        else:
            preflight["checked_at"] = "2100-01-01T00:00:00Z"
        preflight_path.write_text(json.dumps(preflight), encoding="utf-8")
    before = _tree_fingerprint(fixture.project)

    result = runner.invoke(
        app,
        [
            "run",
            str(fixture.project),
            "--execution-profile",
            str(fixture.profile_path),
            "--actor",
            "pytest-operator",
            "--approve-real-data",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["code"] == expected_code
    assert _tree_fingerprint(fixture.project) == before


def test_submit_dry_run_rejects_preflight_that_hypothetical_approval_would_precede(
    tmp_path: Path,
) -> None:
    fixture = _prepared_run_fixture(tmp_path)
    checked_at = (datetime.now(UTC) + timedelta(minutes=2)).replace(microsecond=0)
    checked_at_text = checked_at.isoformat().replace("+00:00", "Z")
    preflight_path = fixture.project / "reports" / "preflight.json"
    preflight = json.loads(preflight_path.read_text(encoding="utf-8"))
    preflight["checked_at"] = checked_at_text
    preflight_path.write_text(json.dumps(preflight, sort_keys=True), encoding="utf-8")
    state_path = fixture.project / "reports" / ".preflight-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["checked_at"] = checked_at_text
    state["preflight_report_sha256"] = hashlib.sha256(preflight_path.read_bytes()).hexdigest()
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    before = _tree_fingerprint(fixture.project)

    result = runner.invoke(
        app,
        [
            "run",
            str(fixture.project),
            "--execution-profile",
            str(fixture.profile_path),
            "--actor",
            "pytest-operator",
            "--approve-real-data",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "APPROVAL_REQUIRED"
    assert error["context"]["reason"] == "approval_precedes_preflight"
    assert _tree_fingerprint(fixture.project) == before


@pytest.mark.parametrize("field", ["preflight_id", "deployment_dir"])
def test_real_submit_shares_exact_private_preflight_bindings_before_remote_operations(
    tmp_path: Path,
    field: str,
) -> None:
    fixture = _setup_run_project(tmp_path)
    checked_at = datetime.now(UTC) - timedelta(seconds=2)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=_ExecutionClient(),
        checked_at=checked_at,
    )
    state_path = fixture.project / "reports" / ".preflight-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state[field] = "preflight-" + "0" * 32 if field == "preflight_id" else "/remote/deploy/other"
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    before = _tree_fingerprint(fixture.project)
    forbidden_client = SimpleNamespace(invoke=_forbidden)

    with pytest.raises(BioPipeError) as caught:
        submit_approved_run(
            fixture.project,
            fixture.profile_path,
            actor="pytest-operator",
            approve_real_data=True,
            client=cast(Any, forbidden_client),
            approved_at=checked_at + timedelta(seconds=1),
        )

    assert caught.value.code is ErrorCode.APPROVAL_ARTIFACT_MISMATCH
    assert _tree_fingerprint(fixture.project) == before


def test_run_dry_run_rejects_invalid_run_identifier_before_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("biopipe.cli.run.query_run_status", _forbidden)

    result = runner.invoke(
        app,
        [
            "run",
            str(tmp_path / "project"),
            "--execution-profile",
            str(tmp_path / "profile.json"),
            "--status",
            "not-a-run-id",
            "--dry-run",
            "--json",
        ],
    )

    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "VALIDATION_FAILED"


def test_schema_export_dry_run_does_not_create_output(tmp_path: Path) -> None:
    output = tmp_path / "schemas"

    result = runner.invoke(
        app,
        ["schema", "export", "--output", str(output), "--dry-run", "--json"],
    )

    payload = _assert_dry_run(result)
    assert payload["status"] == "would_export"
    assert not output.exists()
