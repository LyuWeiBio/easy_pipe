"""M5 controller transport, preflight, deployment, and run orchestration tests."""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from biopipe.audit import AuditWriter
from biopipe.cli.reports import (
    read_project_private_state,
    read_project_report_optional,
    write_project_report_atomic,
)
from biopipe.compiler import NextflowCompiler
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution.client import ExecutionOperation, OpenSSHExecutionClient
from biopipe.execution.deploy import build_deployment_bundle
from biopipe.execution.models import (
    AllowedExecutionRoots,
    ApprovalSigner,
    ContainerArtifact,
    ExecutionProfile,
    LocalExecutionRuntime,
    compute_input_set_hash,
)
from biopipe.execution.preflight import run_preflight
from biopipe.execution.runner import (
    abandon_pending_run,
    query_run_status,
    submit_approved_run,
)
from biopipe.execution.signing import canonical_attestation_bytes
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
from biopipe.validation import validate_generated_project
from biopipe.workflow_test import WorkflowTestCode, WorkflowTestReport, WorkflowTestStatus

_REMOTE_CHECKS = (
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
_COMMAND_HASH = hashlib.sha256(b"fixed-nextflow-command").hexdigest()
_ENVIRONMENT_HASH = hashlib.sha256(b"fixed-nextflow-environment").hexdigest()


@dataclass(frozen=True, slots=True)
class _ControllerFixture:
    project: Path
    profile_path: Path
    profile: ExecutionProfile
    manifest: DatasetManifest


@dataclass(slots=True)
class _FakeExecutionClient:
    calls: list[tuple[ExecutionOperation, dict[str, Any]]] = field(default_factory=list)
    work_dir: str = ""
    output_dir: str = ""
    remote_status: str = "running"
    remote_return_code: int | None = None
    command_hash: str | None = _COMMAND_HASH
    environment_hash: str | None = _ENVIRONMENT_HASH

    def invoke(
        self,
        source: SourceProfile,
        *,
        agent_path: str,
        operation: ExecutionOperation,
        payload: dict[str, Any],
        request_id: str | None = None,
    ) -> dict[str, Any]:
        del request_id
        assert source.source_id == payload["profile_id"]
        assert agent_path.endswith("/bioexec.pyz")
        self.calls.append((operation, payload))
        if operation == "preflight":
            self.work_dir = payload["work_dir"]
            self.output_dir = payload["output_dir"]
            assert payload["network_disabled"] is True
            assert payload["artifact_hashes"]["execution_profile"] == payload["profile_hash"]
            return {
                "preflight_id": payload["preflight_id"],
                "preflight_token": "t" * 64,
                "status": "passed",
                "checks": [
                    {"name": name, "status": "passed", "code": None, "message": None}
                    for name in _REMOTE_CHECKS
                ],
                "input_count": len(set(payload["execution_paths"])),
                "input_set_hash": compute_input_set_hash(payload["execution_paths"]),
            }
        if operation == "deploy":
            assert all(not item["path"].startswith("tests/") for item in payload["files"])
            assert all(
                not item["path"].endswith((".fastq", ".fastq.gz", ".bam", ".cram"))
                for item in payload["files"]
            )
            return {
                "deployment_id": payload["deployment_id"],
                "bundle_hash": payload["bundle_hash"],
                "file_count": len(payload["files"]),
                "status": "deployed",
            }
        if operation in {"submit", "resume", "abandon"}:
            approval = payload["approval"]
            assert approval["key_id"] == "controller-1"
            unsigned_approval = {
                key: value for key, value in approval.items() if key != "signature"
            }
            unsigned_payload = {**payload, "approval": unsigned_approval}
            expected = hmac.new(
                bytes.fromhex("9" * 64),
                canonical_attestation_bytes(operation, unsigned_payload),
                hashlib.sha256,
            ).hexdigest()
            assert hmac.compare_digest(approval["signature"], expected)
            if operation == "abandon":
                assert set(payload) == {
                    "run_id",
                    "profile_id",
                    "profile_hash",
                    "project_hash",
                    "bundle_hash",
                    "deployment_id",
                    "resume_run_id",
                    "submitted_at",
                    "approval",
                }
                assert set(approval) == {"key_id", "signature"}
                assert payload["submitted_at"].endswith("Z")
                assert payload["deployment_id"].startswith("deployment-")
                return {"run_id": payload["run_id"], "status": "abandoned"}
            assert approval["approved"] is True
            assert approval["artifact_hashes"]["execution_profile"] == payload["profile_hash"]
            assert approval["bundle_hash"] == payload["bundle_hash"]
            return {
                "run_id": payload["run_id"],
                "status": "submitted",
                "remote_work_dir": self.work_dir,
                "result_dir": self.output_dir,
                "command_hash": self.command_hash,
                "environment_hash": self.environment_hash,
            }
        if operation == "status":
            return {
                "run_id": payload["run_id"],
                "status": self.remote_status,
                "return_code": self.remote_return_code,
                "command_hash": self.command_hash,
                "environment_hash": self.environment_hash,
            }
        raise AssertionError(f"unexpected operation: {operation}")


@dataclass(slots=True)
class _TimeoutAfterSubmitClient(_FakeExecutionClient):
    timed_out_run_id: str | None = None

    def invoke(
        self,
        source: SourceProfile,
        *,
        agent_path: str,
        operation: ExecutionOperation,
        payload: dict[str, Any],
        request_id: str | None = None,
    ) -> dict[str, Any]:
        result = _FakeExecutionClient.invoke(
            self,
            source,
            agent_path=agent_path,
            operation=operation,
            payload=payload,
            request_id=request_id,
        )
        if operation == "submit" and self.timed_out_run_id is None:
            self.timed_out_run_id = payload["run_id"]
            raise BioPipeError(
                ErrorCode.SSH_TIMEOUT,
                "The remote execution request exceeded its timeout.",
                context={"operation": "submit"},
            )
        return result


@dataclass(slots=True)
class _TimeoutAfterDeployClient(_FakeExecutionClient):
    timed_out_deployment_id: str | None = None

    def invoke(
        self,
        source: SourceProfile,
        *,
        agent_path: str,
        operation: ExecutionOperation,
        payload: dict[str, Any],
        request_id: str | None = None,
    ) -> dict[str, Any]:
        result = _FakeExecutionClient.invoke(
            self,
            source,
            agent_path=agent_path,
            operation=operation,
            payload=payload,
            request_id=request_id,
        )
        if operation == "deploy" and self.timed_out_deployment_id is None:
            self.timed_out_deployment_id = payload["deployment_id"]
            raise BioPipeError(
                ErrorCode.SSH_TIMEOUT,
                "The remote deployment response was lost.",
                context={"operation": "deploy"},
            )
        return result


@dataclass(slots=True)
class _RejectAbandonClient(_FakeExecutionClient):
    def invoke(
        self,
        source: SourceProfile,
        *,
        agent_path: str,
        operation: ExecutionOperation,
        payload: dict[str, Any],
        request_id: str | None = None,
    ) -> dict[str, Any]:
        if operation == "abandon":
            self.calls.append((operation, payload))
            raise BioPipeError(
                ErrorCode.RUN_STATUS_FAILED,
                "The remote run exists and cannot be abandoned.",
                context={"operation": "abandon", "remote_code": "RUN_EXISTS"},
            )
        return _FakeExecutionClient.invoke(
            self,
            source,
            agent_path=agent_path,
            operation=operation,
            payload=payload,
            request_id=request_id,
        )


@dataclass(slots=True)
class _UncertainAbandonClient(_FakeExecutionClient):
    def invoke(
        self,
        source: SourceProfile,
        *,
        agent_path: str,
        operation: ExecutionOperation,
        payload: dict[str, Any],
        request_id: str | None = None,
    ) -> dict[str, Any]:
        if operation == "abandon":
            self.calls.append((operation, payload))
            raise BioPipeError(
                ErrorCode.SSH_TIMEOUT,
                "The signed remote abandonment outcome is uncertain.",
                context={"operation": "abandon"},
            )
        return _FakeExecutionClient.invoke(
            self,
            source,
            agent_path=agent_path,
            operation=operation,
            payload=payload,
            request_id=request_id,
        )


@dataclass(slots=True)
class _TimeoutAfterResumeClient(_FakeExecutionClient):
    timed_out_run_id: str | None = None

    def invoke(
        self,
        source: SourceProfile,
        *,
        agent_path: str,
        operation: ExecutionOperation,
        payload: dict[str, Any],
        request_id: str | None = None,
    ) -> dict[str, Any]:
        result = _FakeExecutionClient.invoke(
            self,
            source,
            agent_path=agent_path,
            operation=operation,
            payload=payload,
            request_id=request_id,
        )
        if operation == "resume" and self.timed_out_run_id is None:
            self.timed_out_run_id = payload["run_id"]
            raise BioPipeError(
                ErrorCode.SSH_TIMEOUT,
                "The remote resume request exceeded its timeout.",
                context={"operation": "resume"},
            )
        return result


def _manifest() -> DatasetManifest:
    root = "/remote/raw"
    return finalize_manifest(
        DatasetManifest(
            source=ManifestSource(
                source_id="source-a",
                root=root,
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


def _workflow_report(mode: str) -> WorkflowTestReport:
    return WorkflowTestReport(
        mode=mode,  # type: ignore[arg-type]
        status=WorkflowTestStatus.PASSED,
        code=WorkflowTestCode.OK,
        layout="paired_end",
        trimming_enabled=False,
    )


def _setup(tmp_path: Path) -> _ControllerFixture:
    manifest = _manifest()
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
    validation = {
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
    }
    test = {
        "report_version": "1.0",
        "command": "test",
        "profile": "test",
        "status": "passed",
        "code": "OK",
        "project_directory": str(project),
        "report_path": "reports/test.json",
        "synthetic_data_only": True,
        "static_validation": static.to_dict(),
        "runs": {mode: _workflow_report(mode).model_dump(mode="json") for mode in ("e2e", "stub")},
        "remediation": [],
    }
    write_project_report_atomic(project, "validation.json", validation)
    write_project_report_atomic(project, "test.json", test)
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
    return _ControllerFixture(
        project=project,
        profile_path=profile_path,
        profile=profile,
        manifest=manifest,
    )


def test_fixed_ssh_transport_keeps_payload_out_of_argv_and_disables_forwarding() -> None:
    captured: dict[str, Any] = {}

    def runner(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["args"] = args
        captured.update(kwargs)
        request = json.loads(kwargs["input"])
        response = {
            "protocol_version": "1.0",
            "request_id": request["request_id"],
            "success": True,
            "return_code": 0,
            "result": {"status": "ok"},
            "error": None,
        }
        return subprocess.CompletedProcess(args, 0, json.dumps(response) + "\n", "")

    source = SourceProfile(
        source_id="exec-a",
        ssh_alias="exec-a",
        username="runner",
        port=2222,
        allowed_roots=["/remote"],
    )
    result = OpenSSHExecutionClient(runner=runner).invoke(
        source,
        agent_path="~/.local/bin/bioexec.pyz",
        operation="health",
        payload={"sensitive_path": "/remote/raw/sample.fastq.gz"},
        request_id="request-1",
    )

    assert result == {"status": "ok"}
    assert captured["shell"] is False
    assert captured["check"] is False
    assert captured["args"] == [
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-p",
        "2222",
        "-l",
        "runner",
        "--",
        "exec-a",
        "~/.local/bin/bioexec.pyz",
    ]
    assert "/remote/raw" not in " ".join(captured["args"])


@pytest.mark.parametrize(
    "agent_path",
    ["bioexec.pyz", "~/../bioexec.pyz", "~/bin/bioexec.pyz;id", "~/bin/x bioexec.pyz"],
)
def test_fixed_ssh_transport_rejects_agent_path_injection(agent_path: str) -> None:
    source = SourceProfile(
        source_id="exec-a",
        ssh_alias="exec-a",
        allowed_roots=["/remote"],
    )
    with pytest.raises(ValueError):
        OpenSSHExecutionClient.build_argv(source, agent_path)


def test_deployment_bundle_is_deterministic_and_excludes_all_synthetic_reads(
    tmp_path: Path,
) -> None:
    fixture = _setup(tmp_path)
    first = build_deployment_bundle(fixture.project)
    second = build_deployment_bundle(fixture.project)

    assert first.bundle_hash == second.bundle_hash
    assert [item.path for item in first.files] == [item.path for item in second.files]
    assert all(not item.path.startswith(("tests/", "reports/")) for item in first.files)
    assert all(
        not item.path.endswith((".fastq", ".fastq.gz", ".bam", ".cram")) for item in first.files
    )
    contents = {item.path: item.content for item in first.files}
    assert "assets/samplesheet.csv" in contents
    repository_license = Path(__file__).resolve().parents[2] / "LICENSE"
    assert contents["LICENSE"] == repository_license.read_bytes()


def test_optional_run_report_reader_returns_none_for_a_bound_missing_path(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)

    assert read_project_report_optional(fixture.project, "run.json") is None


def test_preflight_persists_sanitized_report_and_private_one_time_token(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    client = _FakeExecutionClient()
    report = run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=datetime.now(UTC) - timedelta(seconds=1),
    )

    assert report.status == "passed"
    assert {check.name for check in report.checks} >= {*_REMOTE_CHECKS, "ssh"}
    public = (fixture.project / "reports" / "preflight.json").read_text(encoding="utf-8")
    assert "t" * 64 not in public
    private = read_project_private_state(fixture.project, ".preflight-state.json")
    assert private["preflight_token"] == "t" * 64
    assert private["bundle_hash"] == build_deployment_bundle(fixture.project).bundle_hash
    assert [operation for operation, _payload in client.calls] == ["preflight"]


def test_direct_submit_without_cli_approval_performs_no_remote_mutation(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    client = _FakeExecutionClient()
    checked_at = datetime.now(UTC) - timedelta(seconds=1)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=checked_at,
    )
    call_count = len(client.calls)

    with pytest.raises(BioPipeError) as caught:
        submit_approved_run(
            fixture.project,
            fixture.profile_path,
            actor="pytest-operator",
            approve_real_data=False,
            client=client,
            approved_at=checked_at + timedelta(milliseconds=500),
        )

    assert caught.value.code is ErrorCode.APPROVAL_REQUIRED
    assert len(client.calls) == call_count


def test_unsafe_approval_key_blocks_before_remote_deployment(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    client = _FakeExecutionClient()
    preflight_at = datetime.now(UTC) - timedelta(seconds=2)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=preflight_at,
    )
    Path(fixture.profile.approval_signer.key_file).chmod(0o644)
    calls_before_submit = len(client.calls)

    with pytest.raises(BioPipeError) as caught:
        submit_approved_run(
            fixture.project,
            fixture.profile_path,
            actor="pytest-operator",
            approve_real_data=True,
            client=client,
            approved_at=preflight_at + timedelta(seconds=1),
        )

    assert caught.value.code is ErrorCode.APPROVAL_REQUIRED
    assert len(client.calls) == calls_before_submit
    assert not (fixture.project / "reports" / ".run-state.json").exists()


def test_lost_deploy_response_reuses_the_deterministic_deployment_id(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    client = _TimeoutAfterDeployClient()
    preflight_at = datetime.now(UTC) - timedelta(seconds=2)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=preflight_at,
    )

    with pytest.raises(BioPipeError) as timeout:
        submit_approved_run(
            fixture.project,
            fixture.profile_path,
            actor="pytest-operator",
            approve_real_data=True,
            client=client,
            approved_at=preflight_at + timedelta(seconds=1),
        )

    assert timeout.value.code is ErrorCode.SSH_TIMEOUT
    assert client.timed_out_deployment_id is not None
    assert not (fixture.project / "reports" / ".run-state.json").exists()
    retried = submit_approved_run(
        fixture.project,
        fixture.profile_path,
        actor="pytest-operator",
        approve_real_data=True,
        client=client,
        approved_at=datetime.now(UTC),
    )
    deployment_ids = [
        payload["deployment_id"] for operation, payload in client.calls if operation == "deploy"
    ]
    assert deployment_ids == [client.timed_out_deployment_id] * 2
    assert retried.deployment_id == client.timed_out_deployment_id


def test_full_approved_submit_status_and_compatible_resume_flow(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    client = _FakeExecutionClient()
    first_preflight_at = datetime.now(UTC) - timedelta(seconds=2)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=first_preflight_at,
    )
    first = submit_approved_run(
        fixture.project,
        fixture.profile_path,
        actor="pytest-operator",
        approve_real_data=True,
        client=client,
        approved_at=first_preflight_at + timedelta(seconds=1),
    )

    assert first.status == "submitted"
    assert [operation for operation, _payload in client.calls] == [
        "preflight",
        "deploy",
        "submit",
    ]
    state = read_project_private_state(fixture.project, ".run-state.json")
    assert state["run_id"] == first.run_id
    assert state["authorization"]["actor"] == "pytest-operator"
    assert state["command_hash"] == _COMMAND_HASH
    assert state["environment_hash"] == _ENVIRONMENT_HASH
    assert validate_generated_project(fixture.project).status == "valid"

    client.remote_status = "succeeded"
    client.remote_return_code = 0
    status = query_run_status(
        fixture.project,
        fixture.profile_path,
        run_id=first.run_id,
        client=client,
    )
    assert status.status == "succeeded"
    assert status.command_hash == _COMMAND_HASH
    assert status.environment_hash == _ENVIRONMENT_HASH
    repeated = query_run_status(
        fixture.project,
        fixture.profile_path,
        run_id=first.run_id,
        client=client,
    )
    assert repeated.status == "succeeded"
    assert (
        json.loads((fixture.project / "reports" / "status.json").read_text(encoding="utf-8"))[
            "run_id"
        ]
        == first.run_id
    )

    resume_preflight_at = datetime.now(UTC) - timedelta(milliseconds=500)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=resume_preflight_at,
        resume_run_id=first.run_id,
    )
    resumed = submit_approved_run(
        fixture.project,
        fixture.profile_path,
        actor="pytest-operator",
        approve_real_data=True,
        resume_run_id=first.run_id,
        client=client,
        approved_at=datetime.now(UTC),
    )

    assert resumed.resume_from == first.run_id
    assert resumed.deployment_id == first.deployment_id
    assert [operation for operation, _payload in client.calls].count("deploy") == 1
    assert client.calls[-1][0] == "resume"
    audit_lines = (fixture.project / "audit" / "events.jsonl").read_text().splitlines()
    audit_events = [json.loads(line) for line in audit_lines]
    assert len(audit_lines) >= 9
    terminal = [event for event in audit_events if event["event_type"] == "RUN_COMPLETED"]
    assert len(terminal) == 1
    assert terminal[0]["output_hashes"]["command"] == _COMMAND_HASH
    assert terminal[0]["output_hashes"]["environment"] == _ENVIRONMENT_HASH
    assert terminal[0]["output_hashes"]["return_code"] == hashlib.sha256(b"0").hexdigest()
    assert sum(event["event_type"] == "RUN_STATUS_QUERIED" for event in audit_events) == 2
    assert all("preflight_token" not in line for line in audit_lines)


def test_submit_timeout_preserves_recoverable_pending_state_and_status(
    tmp_path: Path,
) -> None:
    fixture = _setup(tmp_path)
    client = _TimeoutAfterSubmitClient()
    preflight_at = datetime.now(UTC) - timedelta(seconds=2)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=preflight_at,
    )

    with pytest.raises(BioPipeError) as caught:
        submit_approved_run(
            fixture.project,
            fixture.profile_path,
            actor="pytest-operator",
            approve_real_data=True,
            client=client,
            approved_at=preflight_at + timedelta(seconds=1),
        )

    assert caught.value.code is ErrorCode.SSH_TIMEOUT
    run_id = caught.value.context["run_id"]
    assert run_id == client.timed_out_run_id
    assert caught.value.context["recovery_action"] == "query_status"
    assert caught.value.context["status_query_required"] is True
    state = read_project_private_state(fixture.project, ".run-state.json")
    assert state["submission_state"] == "pending"
    assert state["remote_status"] == "pending"
    assert state["run_id"] == run_id
    assert state["authorization"]["actor"] == "pytest-operator"
    assert state["deployment_id"].startswith("deployment-")
    assert state["deployment_dir"].startswith("/remote/deploy/")
    assert state["remote_work_dir"] == "/remote/work/project-qc"
    assert state["result_dir"] == "/remote/results/project-qc"
    assert state["command_hash"] is None
    assert state["environment_hash"] is None
    assert state["return_code"] is None
    assert state["previous_state"] is None
    assert not (fixture.project / "reports" / "run.json").exists()

    audit_events = [
        json.loads(line)
        for line in (fixture.project / "audit" / "events.jsonl").read_text().splitlines()
    ]
    started = next(
        event for event in audit_events if event["event_type"] == "RUN_SUBMISSION_STARTED"
    )
    assert run_id in started["summary"]
    assert run_id in started["output_hashes"]

    calls_before_retry = len(client.calls)
    with pytest.raises(BioPipeError) as pending:
        submit_approved_run(
            fixture.project,
            fixture.profile_path,
            actor="pytest-operator",
            approve_real_data=True,
            client=client,
            approved_at=datetime.now(UTC),
        )
    assert pending.value.code is ErrorCode.RUN_SUBMISSION_FAILED
    assert pending.value.context["run_id"] == run_id
    assert len(client.calls) == calls_before_retry

    recovered = query_run_status(
        fixture.project,
        fixture.profile_path,
        run_id=run_id,
        client=client,
    )
    assert recovered.status == "running"
    recovered_state = read_project_private_state(fixture.project, ".run-state.json")
    assert recovered_state["submission_state"] == "accepted"
    assert recovered_state["remote_status"] == "running"
    assert recovered_state["run_id"] == run_id
    assert recovered_state["command_hash"] == _COMMAND_HASH
    assert recovered_state["environment_hash"] == _ENVIRONMENT_HASH
    assert recovered_state["acceptance_report"] is None
    run_report = json.loads((fixture.project / "reports" / "run.json").read_text(encoding="utf-8"))
    assert run_report["run_id"] == run_id
    assert run_report["status"] == "running"
    assert run_report["command_hash"] == _COMMAND_HASH
    assert read_project_private_state(fixture.project, ".preflight-state.json") == {
        "state_version": "1.0",
        "preflight_id": state["preflight_id"],
        "consumed": True,
    }
    query_run_status(
        fixture.project,
        fixture.profile_path,
        run_id=run_id,
        client=client,
    )
    recovered_events = [
        json.loads(line)
        for line in (fixture.project / "audit" / "events.jsonl").read_text().splitlines()
    ]
    submitted = [event for event in recovered_events if event["event_type"] == "RUN_SUBMITTED"]
    assert len(submitted) == 1
    assert submitted[0]["output_hashes"]["command"] == _COMMAND_HASH
    assert submitted[0]["output_hashes"]["environment"] == _ENVIRONMENT_HASH


def test_acceptance_retries_after_run_report_without_changing_its_first_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _setup(tmp_path)
    client = _FakeExecutionClient()
    preflight_at = datetime.now(UTC) - timedelta(seconds=2)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=preflight_at,
    )
    execution_runner = importlib.import_module("biopipe.execution.runner")
    original_write_state = execution_runner.write_project_private_state_atomic
    failed_once = False

    def fail_first_capability_consumption(
        project: Path,
        filename: str,
        payload: dict[str, Any],
    ) -> Path:
        nonlocal failed_once
        if (
            filename == ".preflight-state.json"
            and payload.get("consumed") is True
            and not failed_once
        ):
            failed_once = True
            raise BioPipeError(
                ErrorCode.ARTIFACT_WRITE_FAILED,
                "Synthetic crash after the durable run report.",
            )
        return original_write_state(project, filename, payload)

    monkeypatch.setattr(
        execution_runner,
        "write_project_private_state_atomic",
        fail_first_capability_consumption,
    )
    with pytest.raises(BioPipeError) as interrupted:
        submit_approved_run(
            fixture.project,
            fixture.profile_path,
            actor="pytest-operator",
            approve_real_data=True,
            client=client,
            approved_at=preflight_at + timedelta(seconds=1),
        )
    run_id = str(interrupted.value.context["run_id"])
    pending = read_project_private_state(fixture.project, ".run-state.json")
    assert pending["submission_state"] == "pending"
    assert pending["acceptance_report"]["status"] == "submitted"
    first_report = json.loads(
        (fixture.project / "reports" / "run.json").read_text(encoding="utf-8")
    )
    assert first_report["status"] == "submitted"

    recovered = query_run_status(
        fixture.project,
        fixture.profile_path,
        run_id=run_id,
        client=client,
    )
    assert recovered.status == "running"
    assert (
        json.loads((fixture.project / "reports" / "run.json").read_text(encoding="utf-8"))
        == first_report
    )
    state = read_project_private_state(fixture.project, ".run-state.json")
    assert state["submission_state"] == "accepted"
    assert state["remote_status"] == "running"
    assert state["acceptance_report"] is None
    events = [
        json.loads(line)
        for line in (fixture.project / "audit" / "events.jsonl").read_text().splitlines()
    ]
    assert sum(event["event_type"] == "RUN_SUBMITTED" for event in events) == 1


def test_pending_acceptance_rejects_a_conflicting_existing_run_report(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    client = _TimeoutAfterSubmitClient()
    preflight_at = datetime.now(UTC) - timedelta(seconds=2)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=preflight_at,
    )
    with pytest.raises(BioPipeError) as timeout:
        submit_approved_run(
            fixture.project,
            fixture.profile_path,
            actor="pytest-operator",
            approve_real_data=True,
            client=client,
            approved_at=preflight_at + timedelta(seconds=1),
        )
    run_id = str(timeout.value.context["run_id"])
    write_project_report_atomic(fixture.project, "run.json", {"conflicting": True})

    with pytest.raises(BioPipeError) as conflict:
        query_run_status(
            fixture.project,
            fixture.profile_path,
            run_id=run_id,
            client=client,
        )

    assert conflict.value.code is ErrorCode.ARTIFACT_WRITE_FAILED
    state = read_project_private_state(fixture.project, ".run-state.json")
    assert state["submission_state"] == "pending"
    assert state["acceptance_report"] is not None
    assert (
        read_project_private_state(fixture.project, ".preflight-state.json").get("consumed") is None
    )
    events = [
        json.loads(line)
        for line in (fixture.project / "audit" / "events.jsonl").read_text().splitlines()
    ]
    assert all(event["event_type"] != "RUN_SUBMITTED" for event in events)


@pytest.mark.parametrize(
    ("stored_status", "stored_return_code", "regressed_status", "regressed_return_code"),
    [
        ("running", None, "submitted", None),
        ("failed", 17, "succeeded", 0),
    ],
)
def test_pending_canonical_acceptance_rejects_status_regression(
    tmp_path: Path,
    stored_status: str,
    stored_return_code: int | None,
    regressed_status: str,
    regressed_return_code: int | None,
) -> None:
    fixture = _setup(tmp_path)
    client = _TimeoutAfterSubmitClient()
    preflight_at = datetime.now(UTC) - timedelta(seconds=2)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=preflight_at,
    )
    with pytest.raises(BioPipeError) as timeout:
        submit_approved_run(
            fixture.project,
            fixture.profile_path,
            actor="pytest-operator",
            approve_real_data=True,
            client=client,
            approved_at=preflight_at + timedelta(seconds=1),
        )
    run_id = str(timeout.value.context["run_id"])
    write_project_report_atomic(fixture.project, "run.json", {"conflicting": True})
    client.remote_status = stored_status
    client.remote_return_code = stored_return_code
    with pytest.raises(BioPipeError):
        query_run_status(
            fixture.project,
            fixture.profile_path,
            run_id=run_id,
            client=client,
        )
    bound = read_project_private_state(fixture.project, ".run-state.json")
    assert bound["acceptance_report"]["status"] == stored_status

    client.remote_status = regressed_status
    client.remote_return_code = regressed_return_code
    with pytest.raises(BioPipeError) as regression:
        query_run_status(
            fixture.project,
            fixture.profile_path,
            run_id=run_id,
            client=client,
        )

    assert regression.value.code is ErrorCode.REMOTE_EXECUTION_PROTOCOL_ERROR
    assert read_project_private_state(fixture.project, ".run-state.json") == bound


def test_acceptance_audit_is_not_duplicated_when_final_state_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _setup(tmp_path)
    client = _TimeoutAfterSubmitClient()
    preflight_at = datetime.now(UTC) - timedelta(seconds=2)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=preflight_at,
    )
    with pytest.raises(BioPipeError) as timeout:
        submit_approved_run(
            fixture.project,
            fixture.profile_path,
            actor="pytest-operator",
            approve_real_data=True,
            client=client,
            approved_at=preflight_at + timedelta(seconds=1),
        )
    run_id = str(timeout.value.context["run_id"])
    execution_runner = importlib.import_module("biopipe.execution.runner")
    original_write_state = execution_runner.write_project_private_state_atomic
    failed_once = False

    def fail_first_accepted_state(
        project: Path,
        filename: str,
        payload: dict[str, Any],
    ) -> Path:
        nonlocal failed_once
        if (
            filename == ".run-state.json"
            and payload.get("submission_state") == "accepted"
            and not failed_once
        ):
            failed_once = True
            raise BioPipeError(
                ErrorCode.ARTIFACT_WRITE_FAILED,
                "Synthetic failure after acceptance audit persistence.",
            )
        return original_write_state(project, filename, payload)

    monkeypatch.setattr(
        execution_runner,
        "write_project_private_state_atomic",
        fail_first_accepted_state,
    )
    with pytest.raises(BioPipeError) as interrupted:
        query_run_status(
            fixture.project,
            fixture.profile_path,
            run_id=run_id,
            client=client,
        )
    assert interrupted.value.code is ErrorCode.ARTIFACT_WRITE_FAILED
    assert (
        read_project_private_state(fixture.project, ".run-state.json")["submission_state"]
        == "pending"
    )

    query_run_status(
        fixture.project,
        fixture.profile_path,
        run_id=run_id,
        client=client,
    )
    events = [
        json.loads(line)
        for line in (fixture.project / "audit" / "events.jsonl").read_text().splitlines()
    ]
    assert sum(event["event_type"] == "RUN_SUBMITTED" for event in events) == 1
    assert (
        read_project_private_state(fixture.project, ".run-state.json")["submission_state"]
        == "accepted"
    )


def test_pending_run_requires_delay_and_signed_remote_abandonment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _setup(tmp_path)
    timeout_client = _TimeoutAfterSubmitClient()
    preflight_at = datetime.now(UTC) - timedelta(seconds=2)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=timeout_client,
        checked_at=preflight_at,
    )
    with pytest.raises(BioPipeError) as caught:
        submit_approved_run(
            fixture.project,
            fixture.profile_path,
            actor="pytest-operator",
            approve_real_data=True,
            client=timeout_client,
            approved_at=preflight_at + timedelta(seconds=1),
        )
    run_id = str(caught.value.context["run_id"])
    state = read_project_private_state(fixture.project, ".run-state.json")
    submitted_at = datetime.fromisoformat(str(state["submitted_at"]).replace("Z", "+00:00"))
    successful = _FakeExecutionClient()

    with pytest.raises(BioPipeError) as grace_error:
        abandon_pending_run(
            fixture.project,
            fixture.profile_path,
            run_id=run_id,
            client=successful,
            confirmed_at=submitted_at + timedelta(minutes=4),
        )

    assert grace_error.value.code is ErrorCode.RUN_STATUS_FAILED
    assert successful.calls == []

    rejected = _RejectAbandonClient()
    with pytest.raises(BioPipeError) as rejected_error:
        abandon_pending_run(
            fixture.project,
            fixture.profile_path,
            run_id=run_id,
            client=rejected,
            confirmed_at=submitted_at + timedelta(minutes=6),
        )
    assert rejected_error.value.code is ErrorCode.RUN_STATUS_FAILED
    assert read_project_private_state(fixture.project, ".run-state.json") == state

    uncertain = _UncertainAbandonClient()
    with pytest.raises(BioPipeError) as uncertain_error:
        abandon_pending_run(
            fixture.project,
            fixture.profile_path,
            run_id=run_id,
            client=uncertain,
            confirmed_at=submitted_at + timedelta(minutes=6),
        )
    assert uncertain_error.value.code is ErrorCode.SSH_TIMEOUT
    assert read_project_private_state(fixture.project, ".run-state.json") == state

    execution_runner = importlib.import_module("biopipe.execution.runner")
    original_write_state = execution_runner.write_project_private_state_atomic
    failed_once = False

    def fail_first_local_release(
        project: Path,
        filename: str,
        payload: dict[str, Any],
    ) -> Path:
        nonlocal failed_once
        if filename == ".run-state.json" and not failed_once:
            failed_once = True
            raise BioPipeError(
                ErrorCode.ARTIFACT_WRITE_FAILED,
                "Synthetic local release failure after remote abandonment.",
            )
        return original_write_state(project, filename, payload)

    monkeypatch.setattr(
        execution_runner,
        "write_project_private_state_atomic",
        fail_first_local_release,
    )
    with pytest.raises(BioPipeError) as local_failure:
        abandon_pending_run(
            fixture.project,
            fixture.profile_path,
            run_id=run_id,
            client=successful,
            confirmed_at=submitted_at + timedelta(minutes=6),
        )
    assert local_failure.value.code is ErrorCode.ARTIFACT_WRITE_FAILED
    assert read_project_private_state(fixture.project, ".run-state.json") == state

    reconciled = abandon_pending_run(
        fixture.project,
        fixture.profile_path,
        run_id=run_id,
        client=successful,
        confirmed_at=submitted_at + timedelta(minutes=6),
    )
    assert reconciled.status == "abandoned"
    abandoned = read_project_private_state(fixture.project, ".run-state.json")
    assert abandoned["submission_state"] == "abandoned"
    assert abandoned["remote_status"] == "not_found"
    assert successful.calls[-1][0] == "abandon"
    events = [
        json.loads(line)
        for line in (fixture.project / "audit" / "events.jsonl").read_text().splitlines()
    ]
    assert sum(event["event_type"] == "RUN_SUBMISSION_ABANDONED" for event in events) == 1
    assert validate_generated_project(fixture.project).status == "valid"


@pytest.mark.parametrize(
    "changed_hash",
    [None, hashlib.sha256(b"changed-command").hexdigest()],
)
def test_status_rejects_a_missing_or_changed_bound_runtime_hash(
    tmp_path: Path,
    changed_hash: str | None,
) -> None:
    fixture = _setup(tmp_path)
    client = _FakeExecutionClient()
    preflight_at = datetime.now(UTC) - timedelta(seconds=2)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=preflight_at,
    )
    report = submit_approved_run(
        fixture.project,
        fixture.profile_path,
        actor="pytest-operator",
        approve_real_data=True,
        client=client,
        approved_at=preflight_at + timedelta(seconds=1),
    )
    original = read_project_private_state(fixture.project, ".run-state.json")
    client.command_hash = changed_hash

    with pytest.raises(BioPipeError) as caught:
        query_run_status(
            fixture.project,
            fixture.profile_path,
            run_id=report.run_id,
            client=client,
        )

    assert caught.value.code is ErrorCode.REMOTE_EXECUTION_PROTOCOL_ERROR
    assert read_project_private_state(fixture.project, ".run-state.json") == original


def test_failed_terminal_status_is_audited_once_with_runtime_evidence(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    client = _FakeExecutionClient()
    preflight_at = datetime.now(UTC) - timedelta(seconds=2)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=preflight_at,
    )
    run = submit_approved_run(
        fixture.project,
        fixture.profile_path,
        actor="pytest-operator",
        approve_real_data=True,
        client=client,
        approved_at=preflight_at + timedelta(seconds=1),
    )
    client.remote_status = "failed"
    client.remote_return_code = 17

    first = query_run_status(
        fixture.project,
        fixture.profile_path,
        run_id=run.run_id,
        client=client,
    )
    second = query_run_status(
        fixture.project,
        fixture.profile_path,
        run_id=run.run_id,
        client=client,
    )

    assert first.status == second.status == "failed"
    events = [
        json.loads(line)
        for line in (fixture.project / "audit" / "events.jsonl").read_text().splitlines()
    ]
    failed = [event for event in events if event["event_type"] == "RUN_FAILED"]
    assert len(failed) == 1
    assert failed[0]["output_hashes"]["return_code"] == hashlib.sha256(b"17").hexdigest()
    assert validate_generated_project(fixture.project).status == "valid"


def test_timeout_resume_status_rebuilds_acceptance_artifacts_once(tmp_path: Path) -> None:
    fixture = _setup(tmp_path)
    client = _TimeoutAfterResumeClient()
    initial_preflight_at = datetime.now(UTC) - timedelta(seconds=6)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=initial_preflight_at,
    )
    original = submit_approved_run(
        fixture.project,
        fixture.profile_path,
        actor="pytest-operator",
        approve_real_data=True,
        client=client,
        approved_at=initial_preflight_at + timedelta(seconds=1),
    )
    client.remote_status = "succeeded"
    client.remote_return_code = 0
    query_run_status(
        fixture.project,
        fixture.profile_path,
        run_id=original.run_id,
        client=client,
    )
    resume_preflight_at = datetime.now(UTC) - timedelta(seconds=2)
    resume_preflight = run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=resume_preflight_at,
        resume_run_id=original.run_id,
    )
    with pytest.raises(BioPipeError) as timeout:
        submit_approved_run(
            fixture.project,
            fixture.profile_path,
            actor="pytest-operator",
            approve_real_data=True,
            resume_run_id=original.run_id,
            client=client,
            approved_at=resume_preflight_at + timedelta(seconds=1),
        )
    resumed_run_id = str(timeout.value.context["run_id"])
    client.remote_status = "running"
    client.remote_return_code = None

    recovered = query_run_status(
        fixture.project,
        fixture.profile_path,
        run_id=resumed_run_id,
        client=client,
    )
    assert recovered.status == "running"
    run_report = json.loads((fixture.project / "reports" / "run.json").read_text(encoding="utf-8"))
    assert run_report["run_id"] == resumed_run_id
    assert run_report["resume_from"] == original.run_id
    assert read_project_private_state(fixture.project, ".preflight-state.json") == {
        "state_version": "1.0",
        "preflight_id": resume_preflight.preflight_id,
        "consumed": True,
    }
    query_run_status(
        fixture.project,
        fixture.profile_path,
        run_id=resumed_run_id,
        client=client,
    )
    events = [
        json.loads(line)
        for line in (fixture.project / "audit" / "events.jsonl").read_text().splitlines()
    ]
    resumed = [event for event in events if event["event_type"] == "RUN_RESUMED"]
    assert len(resumed) == 1
    assert resumed[0]["output_hashes"]["command"] == _COMMAND_HASH
    assert resumed[0]["output_hashes"]["environment"] == _ENVIRONMENT_HASH


def test_terminal_audit_is_retried_without_duplication_after_uncertain_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _setup(tmp_path)
    client = _FakeExecutionClient()
    preflight_at = datetime.now(UTC) - timedelta(seconds=2)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=preflight_at,
    )
    run = submit_approved_run(
        fixture.project,
        fixture.profile_path,
        actor="pytest-operator",
        approve_real_data=True,
        client=client,
        approved_at=preflight_at + timedelta(seconds=1),
    )
    state_before_terminal = read_project_private_state(fixture.project, ".run-state.json")
    client.remote_status = "succeeded"
    client.remote_return_code = 0
    original_append_once = AuditWriter.append_once
    failed_once = False

    def uncertain_append_once(writer: AuditWriter, event: Any) -> bool:
        nonlocal failed_once
        appended = original_append_once(writer, event)
        if not failed_once:
            failed_once = True
            raise BioPipeError(
                ErrorCode.AUDIT_WRITE_FAILED,
                "Synthetic failure after the durable append.",
            )
        return appended

    monkeypatch.setattr(AuditWriter, "append_once", uncertain_append_once)
    with pytest.raises(BioPipeError) as first_attempt:
        query_run_status(
            fixture.project,
            fixture.profile_path,
            run_id=run.run_id,
            client=client,
        )
    assert first_attempt.value.code is ErrorCode.AUDIT_WRITE_FAILED
    assert read_project_private_state(fixture.project, ".run-state.json") == state_before_terminal

    recovered = query_run_status(
        fixture.project,
        fixture.profile_path,
        run_id=run.run_id,
        client=client,
    )
    assert recovered.status == "succeeded"
    events = [
        json.loads(line)
        for line in (fixture.project / "audit" / "events.jsonl").read_text().splitlines()
    ]
    assert sum(event["event_type"] == "RUN_COMPLETED" for event in events) == 1
    terminal_state = read_project_private_state(fixture.project, ".run-state.json")
    assert terminal_state["remote_status"] == "succeeded"


def test_abandoned_ambiguous_resume_restores_the_original_terminal_run(
    tmp_path: Path,
) -> None:
    fixture = _setup(tmp_path)
    client = _TimeoutAfterResumeClient()
    initial_preflight_at = datetime.now(UTC) - timedelta(seconds=10)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=initial_preflight_at,
    )
    original = submit_approved_run(
        fixture.project,
        fixture.profile_path,
        actor="pytest-operator",
        approve_real_data=True,
        client=client,
        approved_at=initial_preflight_at + timedelta(seconds=1),
    )
    client.remote_status = "succeeded"
    client.remote_return_code = 0
    query_run_status(
        fixture.project,
        fixture.profile_path,
        run_id=original.run_id,
        client=client,
    )
    original_state = read_project_private_state(fixture.project, ".run-state.json")

    resume_preflight_at = initial_preflight_at + timedelta(seconds=3)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=resume_preflight_at,
        resume_run_id=original.run_id,
    )
    with pytest.raises(BioPipeError) as timeout:
        submit_approved_run(
            fixture.project,
            fixture.profile_path,
            actor="pytest-operator",
            approve_real_data=True,
            resume_run_id=original.run_id,
            client=client,
            approved_at=resume_preflight_at + timedelta(seconds=1),
        )
    pending_run_id = str(timeout.value.context["run_id"])
    pending = read_project_private_state(fixture.project, ".run-state.json")
    assert pending["submission_state"] == "pending"
    assert pending["previous_state"] == original_state
    submitted_at = datetime.fromisoformat(str(pending["submitted_at"]).replace("Z", "+00:00"))

    abandon_pending_run(
        fixture.project,
        fixture.profile_path,
        run_id=pending_run_id,
        client=client,
        confirmed_at=submitted_at + timedelta(minutes=6),
    )
    assert read_project_private_state(fixture.project, ".run-state.json") == original_state

    recovered = query_run_status(
        fixture.project,
        fixture.profile_path,
        run_id=original.run_id,
        client=client,
    )
    assert recovered.status == "succeeded"
    fresh_preflight_at = datetime.now(UTC) - timedelta(milliseconds=500)
    run_preflight(
        fixture.project,
        fixture.profile_path,
        client=client,
        checked_at=fresh_preflight_at,
        resume_run_id=original.run_id,
    )
    retried = submit_approved_run(
        fixture.project,
        fixture.profile_path,
        actor="pytest-operator",
        approve_real_data=True,
        resume_run_id=original.run_id,
        client=client,
        approved_at=datetime.now(UTC),
    )
    assert retried.resume_from == original.run_id
    assert retried.run_id != pending_run_id
