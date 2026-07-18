"""M5 controller-to-executor acceptance through the production JSONL protocol."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import stat
import subprocess
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from bioexec.config import (
    AgentConfig,
    ConfiguredRoot,
    ExecutableIdentity,
    Executables,
    Limits,
)
from bioexec.main import serve_once
from bioexec.protocol import encode_response_line
from biopipe.cli.reports import write_project_report_atomic
from biopipe.compiler import NextflowCompiler
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution.client import OpenSSHExecutionClient
from biopipe.execution.deploy import build_deployment_bundle
from biopipe.execution.models import (
    AllowedExecutionRoots,
    ApprovalSigner,
    ContainerArtifact,
    DiskThreshold,
    ExecutionProfile,
    LocalExecutionRuntime,
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
)
from biopipe.planner import PlanningOptions, plan_fastq_qc
from biopipe.registry import load_default_registry
from biopipe.validation import validate_generated_project
from biopipe.workflow_test import WorkflowTestCode, WorkflowTestReport, WorkflowTestStatus

_RAW_SENTINEL = b"RAW-CONTENT-MUST-NEVER-BE-COPIED\n"


@dataclass(slots=True)
class _ProtocolRunner:
    """Stand in only for SSH while retaining both production protocol endpoints."""

    config: AgentConfig
    requests: list[dict[str, Any]] = field(default_factory=list)
    ssh_argv: list[list[str]] = field(default_factory=list)

    def __call__(
        self,
        args: list[str],
        *,
        input: str,
        text: bool,
        capture_output: bool,
        timeout: float,
        check: bool,
        shell: bool,
    ) -> subprocess.CompletedProcess[str]:
        assert text is True
        assert capture_output is True
        assert timeout > 0
        assert check is False
        assert shell is False
        request = json.loads(input)
        assert isinstance(request, dict)
        self.requests.append(request)
        self.ssh_argv.append(list(args))
        response = serve_once(io.BytesIO(input.encode("ascii")), self.config)
        return subprocess.CompletedProcess(
            args,
            int(response["return_code"]),
            encode_response_line(response).decode("ascii"),
            "",
        )


@dataclass(frozen=True, slots=True)
class _AcceptanceFixture:
    project: Path
    profile_path: Path
    client: OpenSSHExecutionClient
    protocol: _ProtocolRunner
    raw_paths: tuple[Path, Path]
    remote_roots: tuple[Path, ...]
    work_dir: Path
    output_dir: Path
    nextflow_trace: Path


def _configured_root(path: Path) -> ConfiguredRoot:
    metadata = path.stat()
    return ConfiguredRoot(path=path, device=metadata.st_dev, inode=metadata.st_ino)


def _identity(path: Path) -> ExecutableIdentity:
    metadata = path.stat()
    return ExecutableIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def _write_executable(path: Path, source: str) -> Path:
    path.write_text(source, encoding="utf-8")
    path.chmod(0o500)
    return path


def _workflow_report(mode: str) -> WorkflowTestReport:
    return WorkflowTestReport(
        mode=mode,  # type: ignore[arg-type]
        status=WorkflowTestStatus.PASSED,
        code=WorkflowTestCode.OK,
        layout="paired_end",
        trimming_enabled=False,
    )


def _write_gate_reports(project: Path) -> None:
    static = validate_generated_project(project)
    assert static.status == "valid"
    common = {
        "report_version": "1.0",
        "status": "passed",
        "code": "OK",
        "project_directory": str(project),
        "synthetic_data_only": True,
        "static_validation": static.to_dict(),
        "remediation": [],
    }
    write_project_report_atomic(
        project,
        "validation.json",
        {
            **common,
            "command": "validate",
            "report_path": "reports/validation.json",
            "runtime_validation": _workflow_report("validate").model_dump(mode="json"),
        },
    )
    write_project_report_atomic(
        project,
        "test.json",
        {
            **common,
            "command": "test",
            "profile": "test",
            "report_path": "reports/test.json",
            "runs": {
                mode: _workflow_report(mode).model_dump(mode="json") for mode in ("e2e", "stub")
            },
        },
    )


def _setup_acceptance(tmp_path: Path) -> _AcceptanceFixture:
    remote = tmp_path / "remote"
    remote.mkdir(mode=0o700)
    roots: dict[str, Path] = {}
    for name in ("raw;metadata-only", "deploy", "work", "output", "cache", "state"):
        path = remote / name
        path.mkdir(mode=0o700)
        roots[name] = path
    cache_dir = roots["cache"] / "project-qc"
    cache_dir.mkdir(mode=0o700)

    read1 = roots["raw;metadata-only"] / "sample;touch raw-injected_R1_001.fastq.gz"
    read2 = roots["raw;metadata-only"] / "sample;touch raw-injected_R2_001.fastq.gz"
    read1.write_bytes(_RAW_SENTINEL + b"READ-ONE\n")
    read2.write_bytes(_RAW_SENTINEL + b"READ-TWO\n")
    read1.chmod(0o400)
    read2.chmod(0o400)

    work_dir = roots["work"] / "project-qc;touch injected-marker"
    output_dir = roots["output"] / "project-qc;touch injected-marker"
    manifest = finalize_manifest(
        DatasetManifest(
            source=ManifestSource(
                source_id="source-a",
                root=str(roots["raw;metadata-only"]),
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
                            read1=str(read1),
                            read2=str(read2),
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
            source_host="source-a",
            execution_host="source-a",
            container_engine="docker",
            work_dir=str(work_dir),
            output_dir=str(output_dir),
            container_cache=str(cache_dir),
            max_cpus=8,
            max_memory_gb=16,
        ),
    )
    project = tmp_path / "controller-project"
    NextflowCompiler().compile_planned(
        project,
        manifest=manifest,
        planned=planned,
        registry=load_default_registry(),
    )
    _write_gate_reports(project)

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
            deploy=(str(roots["deploy"]),),
            work=(str(roots["work"]),),
            output=(str(roots["output"]),),
            cache=(str(roots["cache"]),),
        ),
        runtime=LocalExecutionRuntime(container_engine="docker"),
        containers={
            name: ContainerArtifact(image=component.image, digest=component.digest)
            for name, component in planned.software_lock.components.items()
        },
        disk_threshold=DiskThreshold(minimum_free_bytes=1024**3),
    )
    profile_path = tmp_path / "remote-local.json"
    profile_path.write_text(profile.to_json(), encoding="utf-8")
    profile_hash = hashlib.sha256(profile_path.read_bytes()).hexdigest()

    binaries = remote / "bin"
    binaries.mkdir(mode=0o700)
    nextflow_trace = remote / "nextflow-argv.txt"
    java = _write_executable(
        binaries / "java",
        "#!/bin/sh\nprintf '%s\\n' 'openjdk version 21' >&2\n",
    )
    nextflow = _write_executable(
        binaries / "nextflow",
        "#!/bin/sh\n"
        'if [ "${1:-}" = "-version" ]; then\n'
        "  printf '%s\\n' 'nextflow version 24.10.0'\n"
        "  exit 0\n"
        "fi\n"
        f"trace={str(nextflow_trace)!r}\n"
        ': > "$trace"\n'
        'for argument in "$@"; do printf \'%s\\n\' "$argument" >> "$trace"; done\n'
        "exit 0\n",
    )
    docker = _write_executable(
        binaries / "docker",
        "#!/bin/sh\n"
        'if [ "${1:-}" = "version" ]; then printf \'%s\\n\' \'"27.0.0"\'; exit 0; fi\n'
        "printf '%s\\n' \"$*\"\n",
    )
    nextflow_jar = binaries / "nextflow-24.10.0-one.jar"
    nextflow_jar.write_bytes(b"synthetic pinned Nextflow launcher\n")
    nextflow_jar.chmod(0o400)
    config = AgentConfig(
        profile_id=profile.profile_id,
        profile_hash=profile_hash,
        read_roots=(_configured_root(roots["raw;metadata-only"]),),
        deploy_roots=(_configured_root(roots["deploy"]),),
        work_roots=(_configured_root(roots["work"]),),
        output_roots=(_configured_root(roots["output"]),),
        cache_roots=(_configured_root(roots["cache"]),),
        state_root=_configured_root(roots["state"]),
        executables=Executables(
            java=java,
            nextflow=nextflow,
            docker=docker,
            java_identity=_identity(java),
            nextflow_identity=_identity(nextflow),
            docker_identity=_identity(docker),
        ),
        nextflow_version="24.10.0",
        nextflow_jar=nextflow_jar,
        nextflow_jar_sha256=hashlib.sha256(nextflow_jar.read_bytes()).hexdigest(),
        nextflow_jar_identity=_identity(nextflow_jar),
        approval_key_id="controller-1",
        approval_hmac_key=bytes.fromhex("9" * 64),
        limits=Limits(
            max_request_bytes=64 * 1024 * 1024,
            max_response_bytes=1024 * 1024,
            max_deployment_files=128,
            max_file_bytes=16 * 1024 * 1024,
            max_deployment_bytes=48 * 1024 * 1024,
            max_raw_paths=100,
            max_command_output_bytes=64 * 1024,
            command_timeout_seconds=5,
            run_timeout_seconds=10,
            preflight_ttl_seconds=300,
            minimum_free_bytes=1,
        ),
    )
    protocol = _ProtocolRunner(config)
    return _AcceptanceFixture(
        project=project,
        profile_path=profile_path,
        client=OpenSSHExecutionClient(runner=protocol),
        protocol=protocol,
        raw_paths=(read1, read2),
        remote_roots=tuple(roots.values()),
        work_dir=work_dir,
        output_dir=output_dir,
        nextflow_trace=nextflow_trace,
    )


def _assert_sentinel_absent(roots: tuple[Path, ...]) -> None:
    for root in roots:
        for path in root.rglob("*"):
            if path.is_file():
                assert _RAW_SENTINEL not in path.read_bytes(), path


def test_controller_executor_local_acceptance_is_gated_audited_and_shell_free(
    tmp_path: Path,
) -> None:
    fixture = _setup_acceptance(tmp_path)
    initial_bundle_hash = build_deployment_bundle(fixture.project).bundle_hash
    preflight_at = datetime.now(UTC) - timedelta(seconds=1)
    preflight = run_preflight(
        fixture.project,
        fixture.profile_path,
        client=fixture.client,
        checked_at=preflight_at,
    )
    assert preflight.status == "passed"
    assert {check.name for check in preflight.checks} == {
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
    }

    calls_before_denial = len(fixture.protocol.requests)
    with pytest.raises(BioPipeError) as denied:
        submit_approved_run(
            fixture.project,
            fixture.profile_path,
            actor="acceptance-operator",
            approve_real_data=False,
            client=fixture.client,
        )
    assert denied.value.code is ErrorCode.APPROVAL_REQUIRED
    assert len(fixture.protocol.requests) == calls_before_denial

    run = submit_approved_run(
        fixture.project,
        fixture.profile_path,
        actor="acceptance-operator",
        approve_real_data=True,
        client=fixture.client,
        approved_at=datetime.now(UTC),
    )
    assert run.status == "submitted"
    assert [request["operation"] for request in fixture.protocol.requests] == [
        "preflight",
        "deploy",
        "submit",
    ]
    with pytest.raises(BioPipeError) as output_conflict:
        build_deployment_bundle(fixture.project)
    assert output_conflict.value.code is ErrorCode.DEPLOYMENT_FAILED
    assert output_conflict.value.context["finding_codes"] == ["PATH_OUTPUT_CONFLICT"]
    post_submit_bundle = build_deployment_bundle(
        fixture.project,
        check_output_conflict=False,
    )
    assert post_submit_bundle.bundle_hash == initial_bundle_hash

    status = None
    for _attempt in range(100):
        status = query_run_status(
            fixture.project,
            fixture.profile_path,
            run_id=run.run_id,
            client=fixture.client,
        )
        if status.status in {"succeeded", "failed"}:
            break
        time.sleep(0.02)
    assert status is not None
    assert status.status == "succeeded"
    assert status.return_code == 0
    assert fixture.work_dir.is_dir()
    assert fixture.output_dir.is_dir()

    deploy = next(
        request["payload"]
        for request in fixture.protocol.requests
        if request["operation"] == "deploy"
    )
    assert all(
        not item["path"].endswith((".fastq", ".fastq.gz", ".fq", ".fq.gz"))
        for item in deploy["files"]
    )
    assert all(
        _RAW_SENTINEL not in base64.b64decode(item["content_base64"]) for item in deploy["files"]
    )
    _assert_sentinel_absent((fixture.project, *fixture.remote_roots[1:]))
    assert all(path.read_bytes().startswith(_RAW_SENTINEL) for path in fixture.raw_paths)

    assert fixture.nextflow_trace.is_file()
    nextflow_argv = fixture.nextflow_trace.read_text(encoding="utf-8").splitlines()
    assert str(fixture.work_dir) in nextflow_argv
    assert str(fixture.output_dir) in nextflow_argv
    assert any(";touch injected-marker" in argument for argument in nextflow_argv)
    assert not list(tmp_path.rglob("injected-marker"))
    assert all(
        str(fixture.work_dir) not in argv
        and str(fixture.output_dir) not in argv
        and all(str(raw_path) not in argv for raw_path in fixture.raw_paths)
        for argv in fixture.protocol.ssh_argv
    )

    audit_events = [
        json.loads(line)
        for line in (fixture.project / "audit" / "events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    event_types = [event["event_type"] for event in audit_events]
    for required in (
        "REAL_DATA_APPROVED",
        "PIPELINE_DEPLOYED",
        "RUN_SUBMISSION_STARTED",
        "RUN_SUBMITTED",
        "RUN_STATUS_QUERIED",
        "RUN_COMPLETED",
    ):
        assert required in event_types
    assert event_types.index("REAL_DATA_APPROVED") < event_types.index("RUN_SUBMITTED")
    assert event_types.index("RUN_SUBMITTED") < event_types.index("RUN_COMPLETED")
    terminal = next(event for event in audit_events if event["event_type"] == "RUN_COMPLETED")
    assert terminal["actor"] == "acceptance-operator"
    assert terminal["output_hashes"]["command"] == run.command_hash
    assert terminal["output_hashes"]["environment"] == run.environment_hash
    assert terminal["output_hashes"]["return_code"] == hashlib.sha256(b"0").hexdigest()

    calls_before_conflict = len(fixture.protocol.requests)
    with pytest.raises(BioPipeError) as repeated_preflight:
        run_preflight(
            fixture.project,
            fixture.profile_path,
            client=fixture.client,
            checked_at=datetime.now(UTC),
        )
    assert repeated_preflight.value.code is ErrorCode.DEPLOYMENT_FAILED
    assert repeated_preflight.value.context["finding_codes"] == ["PATH_OUTPUT_CONFLICT"]
    assert len(fixture.protocol.requests) == calls_before_conflict

    main = fixture.project / "main.nf"
    main.write_text(main.read_text(encoding="utf-8") + "// unexpected mutation\n", encoding="utf-8")
    with pytest.raises(BioPipeError) as mutated:
        build_deployment_bundle(fixture.project, check_output_conflict=False)
    assert mutated.value.code is ErrorCode.DEPLOYMENT_FAILED
    assert "TEMPLATE_CONTENT_MISMATCH" in mutated.value.context["finding_codes"]
