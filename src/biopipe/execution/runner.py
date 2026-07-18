"""Approval-gated deployment, submission, resume, and status orchestration."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol
from uuid import UUID, uuid4, uuid5

from biopipe.audit import AuditWriter
from biopipe.cli.reports import (
    read_project_private_state,
    read_project_report_optional,
    write_project_private_state_atomic,
    write_project_report_atomic,
    write_project_report_create_only_atomic,
)
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution.client import ExecutionOperation, OpenSSHExecutionClient
from biopipe.execution.deploy import DeploymentBundle
from biopipe.execution.gate import ApprovalGate, LocalGateEvidence
from biopipe.execution.models import (
    ApprovalArtifactPaths,
    ApprovalRequest,
    RunAuthorization,
    RunPolicy,
)
from biopipe.execution.preflight import (
    ExecutionContext,
    compute_deployment_directory,
    load_execution_context,
)
from biopipe.execution.reports import ReconciliationReport, RunReport, StatusReport
from biopipe.execution.signing import sign_run_payload
from biopipe.models import AuditEvent, SourceProfile

_SAFE_ACTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_RUN_ID = re.compile(r"^run-[0-9a-f]{32}$")
_PREFLIGHT_ID = re.compile(r"^preflight-[0-9a-f]{32}$")
_DEPLOYMENT_ID = re.compile(r"^deployment-[0-9a-f]{32}$")
_TOKEN = re.compile(r"^[A-Za-z0-9._~-]{32,256}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PENDING_ABANDON_GRACE = timedelta(minutes=5)
_DURABLE_AUDIT_NAMESPACE = UUID("11daf67c-a3ea-5b5f-a0f8-3896cd0435f1")
_DEPLOYMENT_NAMESPACE = UUID("1cf3d5b5-fdf4-5b80-9d71-45de310ad727")
_RUN_STATE_KEYS = frozenset(
    {
        "state_version",
        "submission_state",
        "remote_status",
        "run_id",
        "profile_id",
        "profile_hash",
        "project_hash",
        "bundle_hash",
        "deployment_id",
        "deployment_dir",
        "authorization",
        "remote_work_dir",
        "result_dir",
        "submitted_at",
        "resume_run_id",
        "command_hash",
        "environment_hash",
        "return_code",
        "previous_state",
        "preflight_id",
        "acceptance_report",
    }
)


class ExecutionClient(Protocol):
    """Narrow fixed-operation transport seam."""

    def invoke(
        self,
        source: SourceProfile,
        *,
        agent_path: str,
        operation: ExecutionOperation,
        payload: dict[str, Any],
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Invoke one fixed operation."""


def validate_local_run_state(
    project_directory: str | Path,
    execution_profile_path: str | Path,
    evidence: LocalGateEvidence,
    *,
    bundle_hash: str,
    resume_run_id: str | None,
) -> None:
    """Validate private submit/resume state without building or mutating a deployment."""

    project = Path(project_directory).expanduser().absolute()
    if not _SHA256.fullmatch(bundle_hash):
        raise _preflight_state_error()
    preflight_state = read_project_private_state(project, ".preflight-state.json")
    context = ExecutionContext(
        project=project,
        profile_path=Path(execution_profile_path).expanduser().absolute(),
        profile=evidence.profile,
        bundle=DeploymentBundle(files=(), bundle_hash=bundle_hash),
        manifest=evidence.manifest,
        spec=evidence.spec,
        plan=evidence.plan,
        software_lock=evidence.software_lock,
        core_hashes=evidence.core_hashes,
        project_hash=evidence.preflight.project_hash,
        connection=SourceProfile(
            source_id=evidence.profile.profile_id,
            ssh_alias=evidence.profile.ssh_alias,
            username=evidence.profile.username,
            port=evidence.profile.port,
            allowed_roots=sorted(
                set(
                    evidence.profile.allowed_roots.deploy
                    + evidence.profile.allowed_roots.work
                    + evidence.profile.allowed_roots.output
                    + evidence.profile.allowed_roots.cache
                )
            ),
        ),
    )
    _require_no_pending_submission(context)
    previous_state: dict[str, Any] | None = None
    if resume_run_id is not None:
        previous_state = _load_run_state(context, resume_run_id)
        _require_terminal_resume_source(previous_state)
        previous_authorization = RunAuthorization.model_validate(previous_state["authorization"])
        evidence.validate_resume_compatibility(
            previous_authorization,
            bundle_hash=bundle_hash,
        )
    _validate_preflight_state(
        context,
        evidence,
        state=preflight_state,
        resume_run_id=resume_run_id,
        previous_state=previous_state,
    )


def submit_approved_run(
    project_directory: str | Path,
    execution_profile_path: str | Path,
    *,
    actor: str,
    approve_real_data: bool,
    resume_run_id: str | None = None,
    client: ExecutionClient | None = None,
    approved_at: datetime | None = None,
) -> RunReport:
    """Re-run the gate, durably audit approval, then deploy and submit."""

    if not _SAFE_ACTOR.fullmatch(actor):
        raise BioPipeError(
            ErrorCode.APPROVAL_REQUIRED,
            "The approval actor must be a stable safe identifier.",
            remediation=["Use a username containing letters, numbers, dot, underscore, or hyphen."],
        )
    if not approve_real_data:
        raise BioPipeError(
            ErrorCode.APPROVAL_REQUIRED,
            "Explicit --approve-real-data authorization is required.",
            remediation=["Review the exact artifacts and rerun with explicit approval."],
        )
    context = load_execution_context(
        project_directory,
        execution_profile_path,
        check_output_conflict=resume_run_id is None,
    )
    _require_no_pending_submission(context)
    selected_client = client or OpenSSHExecutionClient()
    timestamp = (approved_at or datetime.now(UTC)).astimezone(UTC)
    previous_state = _load_run_state(context, resume_run_id) if resume_run_id else None
    if previous_state is not None:
        _require_terminal_resume_source(previous_state)
    previous_authorization = (
        None
        if previous_state is None
        else RunAuthorization.model_validate(previous_state["authorization"])
    )
    authorization, evidence = ApprovalGate().authorize_with_evidence(
        _approval_paths(context),
        ApprovalRequest(
            policy=RunPolicy(
                run_real_data=True,
                require_approval=True,
                resume=resume_run_id is not None,
            ),
            approve_real_data=approve_real_data,
            actor=actor,
            approved_at=timestamp,
        ),
        bundle_hash=context.bundle.bundle_hash,
        previous_authorization=previous_authorization,
        now=timestamp,
    )
    _require_context_authorization(context, authorization)
    preflight_state = _load_preflight_state(
        context,
        evidence,
        resume_run_id=resume_run_id,
        previous_state=previous_state,
    )
    audit = AuditWriter(context.project / "audit" / "events.jsonl")
    _append_audit(
        audit,
        context,
        authorization,
        event_type="REAL_DATA_APPROVED",
        status="success",
        summary="Attributable hash-bound real-data execution approval recorded.",
    )

    deployment_id = (
        _deterministic_deployment_id(context, preflight_state)
        if previous_state is None
        else str(previous_state["deployment_id"])
    )
    run_id = f"run-{uuid4().hex}"
    operation: Literal["resume", "submit"] = "resume" if resume_run_id is not None else "submit"
    request = {
        "run_id": run_id,
        "preflight_id": preflight_state["preflight_id"],
        "preflight_token": preflight_state["preflight_token"],
        "deployment_id": deployment_id,
        "profile_id": context.profile.profile_id,
        "profile_hash": context.core_hashes.execution_profile,
        "project_hash": context.project_hash,
        "bundle_hash": context.bundle.bundle_hash,
        "approval": _remote_approval(authorization),
    }
    if resume_run_id is not None:
        request["resume_run_id"] = resume_run_id
    # Resolve and authenticate the complete request before the first remote
    # mutation. A missing or unsafe controller key must not leave an orphaned
    # deployment behind.
    request = sign_run_payload(context.profile, operation, request)

    if previous_state is None:
        try:
            deployment = selected_client.invoke(
                context.connection,
                agent_path=context.profile.bioexec_path,
                operation="deploy",
                payload={
                    "deployment_id": deployment_id,
                    "preflight_id": preflight_state["preflight_id"],
                    "profile_id": context.profile.profile_id,
                    "profile_hash": context.core_hashes.execution_profile,
                    "project_hash": context.project_hash,
                    "bundle_hash": context.bundle.bundle_hash,
                    "deployment_dir": preflight_state["deployment_dir"],
                    "files": context.bundle.protocol_files(),
                },
            )
            _validate_deployment_result(
                deployment,
                deployment_id=deployment_id,
                bundle_hash=context.bundle.bundle_hash,
                file_count=len(context.bundle.files),
            )
        except BioPipeError:
            _append_audit(
                audit,
                context,
                authorization,
                event_type="PIPELINE_DEPLOY_FAILED",
                status="failed",
                summary="The approved production bundle deployment failed safely.",
            )
            raise
        _append_audit(
            audit,
            context,
            authorization,
            event_type="PIPELINE_DEPLOYED",
            status="success",
            summary="The digest-verified production bundle was deployed create-only.",
            output_hashes={"bundle": context.bundle.bundle_hash},
        )
    with _run_state_lock(context.project):
        current_state = _read_optional_run_state(context)
        if current_state is not None and current_state["submission_state"] == "pending":
            raise _pending_submission_error(str(current_state["run_id"]))
        if resume_run_id is not None and (
            current_state is None or current_state.get("run_id") != resume_run_id
        ):
            raise BioPipeError(
                ErrorCode.RESUME_INCOMPATIBLE,
                "The recorded run changed before resume submission.",
                remediation=["Repeat status and preflight for the intended run."],
            )
        _persist_pending_run_state(
            context,
            authorization,
            run_id=run_id,
            deployment_id=deployment_id,
            deployment_dir=str(preflight_state["deployment_dir"]),
            preflight_id=str(preflight_state["preflight_id"]),
            submitted_at=timestamp,
            resume_run_id=resume_run_id,
            previous_state=previous_state,
        )
    try:
        _append_audit(
            audit,
            context,
            authorization,
            event_type="RUN_SUBMISSION_STARTED",
            status="started",
            summary=f"Remote submission pending for recoverable run ID {run_id}.",
            recoverable_run_id=run_id,
        )
    except BioPipeError as error:
        raise _recoverable_submission_error(error, run_id) from error
    try:
        remote = selected_client.invoke(
            context.connection,
            agent_path=context.profile.bioexec_path,
            operation=operation,
            payload=request,
        )
        report = _run_report(
            remote,
            context=context,
            authorization=authorization,
            run_id=run_id,
            deployment_id=deployment_id,
            submitted_at=timestamp,
            resume_run_id=resume_run_id,
        )
    except BioPipeError as error:
        try:
            _append_audit(
                audit,
                context,
                authorization,
                event_type="RUN_SUBMISSION_FAILED",
                status="failed",
                summary=f"Remote submission outcome is uncertain for run ID {run_id}.",
                recoverable_run_id=run_id,
            )
        except BioPipeError as audit_error:
            raise _recoverable_submission_error(audit_error, run_id) from error
        raise _recoverable_submission_error(error, run_id) from error

    try:
        _finalize_run_acceptance(context, report, authorization, audit)
    except BioPipeError as error:
        raise _recoverable_submission_error(error, run_id) from error

    return report


def query_run_status(
    project_directory: str | Path,
    execution_profile_path: str | Path,
    *,
    run_id: str,
    client: ExecutionClient | None = None,
    checked_at: datetime | None = None,
) -> StatusReport:
    """Query only the exact locally recorded run and persist a path-free report."""

    context = load_execution_context(
        project_directory,
        execution_profile_path,
        check_output_conflict=False,
    )
    state = _load_run_state(context, run_id)
    selected_client = client or OpenSSHExecutionClient()
    result = selected_client.invoke(
        context.connection,
        agent_path=context.profile.bioexec_path,
        operation="status",
        payload=_status_payload(context, run_id),
    )
    if (
        set(result)
        != {
            "run_id",
            "status",
            "return_code",
            "command_hash",
            "environment_hash",
        }
        or result.get("run_id") != run_id
    ):
        raise _protocol_error("status")
    try:
        report = StatusReport(
            run_id=run_id,
            status=result["status"],
            return_code=result["return_code"],
            command_hash=result["command_hash"],
            environment_hash=result["environment_hash"],
            checked_at=(checked_at or datetime.now(UTC)).astimezone(UTC),
        )
    except (TypeError, ValueError) as exc:
        raise _protocol_error("status") from exc
    authorization = RunAuthorization.model_validate(state["authorization"])
    audit = AuditWriter(context.project / "audit" / "events.jsonl")
    _persist_status_state(context, report, authorization, audit)
    write_project_report_atomic(context.project, "status.json", report.model_dump(mode="json"))
    return report


def abandon_pending_run(
    project_directory: str | Path,
    execution_profile_path: str | Path,
    *,
    run_id: str,
    client: ExecutionClient | None = None,
    confirmed_at: datetime | None = None,
) -> ReconciliationReport:
    """Resolve a pending run only through a delayed signed remote abandonment."""

    context = load_execution_context(
        project_directory,
        execution_profile_path,
        check_output_conflict=False,
    )
    state = _load_run_state(context, run_id)
    if state.get("submission_state") != "pending":
        raise BioPipeError(
            ErrorCode.RUN_STATUS_FAILED,
            "Only an unresolved pending submission can be abandoned.",
            context={"run_id": run_id},
        )
    timestamp = (confirmed_at or datetime.now(UTC)).astimezone(UTC)
    submitted_at = _state_timestamp(state)
    available_at = submitted_at + _PENDING_ABANDON_GRACE
    if timestamp < available_at:
        raise BioPipeError(
            ErrorCode.RUN_STATUS_FAILED,
            "The pending submission is still inside its reconciliation grace period.",
            context={
                "run_id": run_id,
                "abandon_available_at": available_at.isoformat().replace("+00:00", "Z"),
            },
            remediation=["Wait for the grace period, then repeat explicit abandonment."],
        )
    authorization = RunAuthorization.model_validate(state["authorization"])
    request = {
        "run_id": run_id,
        "profile_id": state["profile_id"],
        "profile_hash": state["profile_hash"],
        "project_hash": state["project_hash"],
        "bundle_hash": state["bundle_hash"],
        "deployment_id": state["deployment_id"],
        "resume_run_id": state["resume_run_id"],
        "submitted_at": state["submitted_at"],
        "approval": {},
    }
    signed = sign_run_payload(context.profile, "abandon", request)
    selected_client = client or OpenSSHExecutionClient()
    with _run_state_lock(context.project):
        current = _read_optional_run_state(context)
        if (
            current is None
            or current.get("run_id") != run_id
            or current.get("submission_state") != "pending"
            or current != state
        ):
            raise BioPipeError(
                ErrorCode.RUN_STATUS_FAILED,
                "The pending run changed during reconciliation.",
            )
        result = selected_client.invoke(
            context.connection,
            agent_path=context.profile.bioexec_path,
            operation="abandon",
            payload=signed,
        )
        if result != {"run_id": run_id, "status": "abandoned"}:
            raise _protocol_error("abandon")
        _append_audit(
            AuditWriter(context.project / "audit" / "events.jsonl"),
            context,
            authorization,
            event_type="RUN_SUBMISSION_ABANDONED",
            status="blocked",
            summary=f"The signed remote abandonment was confirmed for run ID {run_id}.",
            recoverable_run_id=run_id,
            event_id=_durable_audit_event_id(
                context,
                run_id=run_id,
                event_type="RUN_SUBMISSION_ABANDONED",
                event_status="blocked",
                evidence=current,
            ),
            append_once=True,
        )
        previous_state = current.get("previous_state")
        if previous_state is None:
            updated = dict(current)
            updated["submission_state"] = "abandoned"
            updated["remote_status"] = "not_found"
            updated["previous_state"] = None
            updated["acceptance_report"] = None
        else:
            updated = dict(previous_state)
        write_project_private_state_atomic(context.project, ".run-state.json", updated)
    return ReconciliationReport(run_id=run_id, confirmed_at=timestamp)


def _approval_paths(context: ExecutionContext) -> ApprovalArtifactPaths:
    return ApprovalArtifactPaths(
        dataset_manifest=context.project / "dataset.manifest.resolved.json",
        pipeline_spec=context.project / "pipeline.spec.yaml",
        execution_plan=context.project / "execution.plan.yaml",
        software_lock=context.project / "software.lock.yaml",
        validation_report=context.project / "reports" / "validation.json",
        test_report=context.project / "reports" / "test.json",
        execution_profile=context.profile_path,
        preflight_report=context.project / "reports" / "preflight.json",
    )


def _require_context_authorization(
    context: ExecutionContext,
    authorization: RunAuthorization,
) -> None:
    if (
        authorization.profile_id != context.profile.profile_id
        or authorization.project_id != context.spec.project.name
        or authorization.artifact_hashes.dataset_manifest != context.core_hashes.dataset_manifest
        or authorization.artifact_hashes.pipeline_spec != context.core_hashes.pipeline_spec
        or authorization.artifact_hashes.execution_plan != context.core_hashes.execution_plan
        or authorization.artifact_hashes.software_lock != context.core_hashes.software_lock
        or authorization.artifact_hashes.execution_profile != context.core_hashes.execution_profile
        or authorization.bundle_hash != context.bundle.bundle_hash
    ):
        raise BioPipeError(
            ErrorCode.APPROVAL_ARTIFACT_MISMATCH,
            "The authorization does not match the in-memory execution snapshot.",
        )


def _load_preflight_state(
    context: ExecutionContext,
    authorization: RunAuthorization | LocalGateEvidence,
    *,
    resume_run_id: str | None,
    previous_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    state = read_project_private_state(context.project, ".preflight-state.json")
    return _validate_preflight_state(
        context,
        authorization,
        state=state,
        resume_run_id=resume_run_id,
        previous_state=previous_state,
    )


def _validate_preflight_state(
    context: ExecutionContext,
    authorization: RunAuthorization | LocalGateEvidence,
    *,
    state: dict[str, Any],
    resume_run_id: str | None,
    previous_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    required = {
        "state_version",
        "preflight_id",
        "preflight_token",
        "profile_id",
        "profile_hash",
        "project_hash",
        "bundle_hash",
        "deployment_dir",
        "preflight_report_sha256",
        "checked_at",
        "resume_run_id",
        "deployment_id",
    }
    token = state.get("preflight_token")
    deployment_dir = state.get("deployment_dir")
    preflight_id = state.get("preflight_id")
    expected_preflight_id = (
        authorization.preflight.preflight_id
        if isinstance(authorization, LocalGateEvidence)
        else None
    )
    expected_checked_at = (
        authorization.preflight_checked_at.astimezone(UTC).isoformat().replace("+00:00", "Z")
    )
    expected_deployment_dir: str | None = None
    expected_deployment_id: str | None = None
    if isinstance(authorization, LocalGateEvidence):
        if resume_run_id is None and isinstance(preflight_id, str):
            expected_deployment_dir = compute_deployment_directory(
                context.profile,
                context.spec,
                context.project_hash,
                preflight_id,
            )
        elif previous_state is not None:
            expected_deployment_dir = str(previous_state["deployment_dir"])
            expected_deployment_id = str(previous_state["deployment_id"])
    if (
        set(state) != required
        or state.get("state_version") != "1.0"
        or state.get("profile_id") != context.profile.profile_id
        or state.get("profile_hash") != context.core_hashes.execution_profile
        or state.get("project_hash") != context.project_hash
        or state.get("bundle_hash") != context.bundle.bundle_hash
        or state.get("preflight_report_sha256") != authorization.artifact_hashes.preflight_report
        or state.get("resume_run_id") != resume_run_id
        or not isinstance(preflight_id, str)
        or not _PREFLIGHT_ID.fullmatch(preflight_id)
        or (expected_preflight_id is not None and preflight_id != expected_preflight_id)
        or state.get("checked_at") != expected_checked_at
        or not isinstance(token, str)
        or not _TOKEN.fullmatch(token)
        or not isinstance(deployment_dir, str)
        or not _below_any(deployment_dir, context.profile.allowed_roots.deploy)
        or (
            isinstance(authorization, LocalGateEvidence)
            and deployment_dir != expected_deployment_dir
        )
        or (
            isinstance(authorization, LocalGateEvidence)
            and state.get("deployment_id") != expected_deployment_id
        )
    ):
        raise _preflight_state_error()
    if resume_run_id is None and state.get("deployment_id") is not None:
        raise BioPipeError(ErrorCode.RESUME_INCOMPATIBLE, "Unexpected resume deployment state.")
    if resume_run_id is not None and not isinstance(state.get("deployment_id"), str):
        raise BioPipeError(ErrorCode.RESUME_INCOMPATIBLE, "Resume deployment state is missing.")
    return state


def _load_run_state(
    context: ExecutionContext,
    run_id: str | None,
) -> dict[str, Any]:
    if run_id is None or not _RUN_ID.fullmatch(run_id):
        raise BioPipeError(ErrorCode.RUN_STATUS_FAILED, "The run ID is invalid.")
    state = _read_optional_run_state(context)
    if state is None or state.get("run_id") != run_id:
        raise _run_state_error()
    return state


def _require_no_pending_submission(context: ExecutionContext) -> None:
    state = _read_optional_run_state(context)
    if state is not None and state.get("submission_state") == "pending":
        raise _pending_submission_error(str(state["run_id"]))


def _read_optional_run_state(context: ExecutionContext) -> dict[str, Any] | None:
    try:
        state = read_project_private_state(context.project, ".run-state.json")
    except BioPipeError as error:
        state_path = context.project / "reports" / ".run-state.json"
        try:
            state_path.lstat()
        except FileNotFoundError:
            return None
        raise error
    return _validate_run_state(context, state)


def _validate_run_state(
    context: ExecutionContext,
    state: dict[str, Any],
    *,
    allow_previous_state: bool = True,
) -> dict[str, Any]:
    submission_state = state.get("submission_state")
    remote_status = state.get("remote_status")
    resume_run_id = state.get("resume_run_id")
    preflight_id = state.get("preflight_id")
    submitted_at = state.get("submitted_at")
    command_hash = state.get("command_hash")
    environment_hash = state.get("environment_hash")
    return_code = state.get("return_code")
    previous_state = state.get("previous_state")
    acceptance_report = state.get("acceptance_report")
    if (
        set(state) != _RUN_STATE_KEYS
        or state.get("state_version") != "1.0"
        or not isinstance(state.get("run_id"), str)
        or not _RUN_ID.fullmatch(str(state["run_id"]))
        or state.get("profile_id") != context.profile.profile_id
        or state.get("profile_hash") != context.core_hashes.execution_profile
        or state.get("project_hash") != context.project_hash
        or state.get("bundle_hash") != context.bundle.bundle_hash
        or not isinstance(state.get("deployment_id"), str)
        or not _DEPLOYMENT_ID.fullmatch(str(state["deployment_id"]))
        or not isinstance(state.get("deployment_dir"), str)
        or not _below_any(str(state["deployment_dir"]), context.profile.allowed_roots.deploy)
        or not isinstance(preflight_id, str)
        or not _PREFLIGHT_ID.fullmatch(preflight_id)
        or not isinstance(state.get("authorization"), dict)
        or state.get("remote_work_dir") != context.spec.paths.work_dir
        or state.get("result_dir") != context.spec.paths.output_dir
        or not isinstance(submission_state, str)
        or not isinstance(remote_status, str)
        or submission_state not in {"pending", "accepted", "abandoned"}
        or (submission_state == "pending" and remote_status != "pending")
        or (
            submission_state == "accepted"
            and remote_status not in {"submitted", "running", "succeeded", "failed"}
        )
        or (submission_state == "abandoned" and remote_status != "not_found")
        or not _optional_sha256(command_hash)
        or not _optional_sha256(environment_hash)
        or (
            return_code is not None
            and (type(return_code) is not int or not 0 <= return_code <= 255)
        )
        or (
            submission_state == "pending"
            and (command_hash is not None or environment_hash is not None)
        )
        or (submission_state == "accepted" and (command_hash is None or environment_hash is None))
        or (
            remote_status in {"pending", "submitted", "running", "not_found"}
            and return_code is not None
        )
        or (remote_status == "succeeded" and return_code != 0)
        or (remote_status == "failed" and (return_code is None or return_code == 0))
        or (
            remote_status in {"succeeded", "failed"}
            and (command_hash is None or environment_hash is None)
        )
        or (
            resume_run_id is not None
            and (not isinstance(resume_run_id, str) or not _RUN_ID.fullmatch(resume_run_id))
        )
        or (submission_state != "pending" and previous_state is not None)
        or (submission_state != "pending" and acceptance_report is not None)
        or (not allow_previous_state and previous_state is not None)
        or not isinstance(submitted_at, str)
    ):
        raise _run_state_error()
    try:
        parsed_at = datetime.fromisoformat(submitted_at.replace("Z", "+00:00"))
        authorization = RunAuthorization.model_validate(state["authorization"])
        _require_context_authorization(context, authorization)
        if acceptance_report is not None:
            pending_report = RunReport.model_validate(acceptance_report)
            _require_report_matches_pending_state(
                context,
                state,
                pending_report,
                authorization,
            )
    except (TypeError, ValueError, BioPipeError) as error:
        raise _run_state_error() from error
    if parsed_at.tzinfo is None or parsed_at.utcoffset() is None:
        raise _run_state_error()
    if submission_state == "pending":
        if resume_run_id is None:
            if previous_state is not None:
                raise _run_state_error()
        else:
            if not isinstance(previous_state, dict):
                raise _run_state_error()
            restored = _validate_run_state(
                context,
                previous_state,
                allow_previous_state=False,
            )
            if (
                restored.get("run_id") != resume_run_id
                or restored.get("submission_state") != "accepted"
                or restored.get("remote_status") not in {"succeeded", "failed"}
            ):
                raise _run_state_error()
    return state


def _require_terminal_resume_source(state: dict[str, Any]) -> None:
    if state.get("submission_state") != "accepted" or state.get("remote_status") not in {
        "succeeded",
        "failed",
    }:
        raise BioPipeError(
            ErrorCode.RESUME_INCOMPATIBLE,
            "Only a recorded terminal run can be resumed.",
            remediation=["Query the run until it reaches a terminal status, then preflight again."],
        )


def _optional_sha256(value: Any) -> bool:
    return value is None or (isinstance(value, str) and _SHA256.fullmatch(value) is not None)


def _state_timestamp(state: dict[str, Any]) -> datetime:
    value = state.get("submitted_at")
    if not isinstance(value, str):
        raise _run_state_error()
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise _run_state_error() from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise _run_state_error()
    return parsed.astimezone(UTC)


def _status_payload(context: ExecutionContext, run_id: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "profile_id": context.profile.profile_id,
        "profile_hash": context.core_hashes.execution_profile,
        "project_hash": context.project_hash,
        "bundle_hash": context.bundle.bundle_hash,
    }


def _run_state_error() -> BioPipeError:
    return BioPipeError(
        ErrorCode.RUN_STATUS_FAILED,
        "The local run record is missing or incompatible.",
    )


def _preflight_state_error() -> BioPipeError:
    return BioPipeError(
        ErrorCode.APPROVAL_ARTIFACT_MISMATCH,
        "The private preflight capability does not match the approved evidence.",
        remediation=["Run a fresh matching preflight and approve again."],
    )


def _pending_submission_error(run_id: str) -> BioPipeError:
    return BioPipeError(
        ErrorCode.RUN_SUBMISSION_FAILED,
        "A prior remote submission has an unresolved outcome.",
        context={
            "run_id": run_id,
            "recovery_action": "query_status",
            "status_query_required": True,
        },
        remediation=["Query this run ID with --status before attempting another submission."],
    )


def _recoverable_submission_error(error: BioPipeError, run_id: str) -> BioPipeError:
    context = dict(error.context)
    context.update(
        {
            "run_id": run_id,
            "recovery_action": "query_status",
            "status_query_required": True,
        }
    )
    remediation = list(error.remediation)
    instruction = "Query this run ID with --status before attempting another submission."
    if instruction not in remediation:
        remediation.append(instruction)
    return BioPipeError(
        error.code,
        error.message,
        severity=error.severity,
        context=context,
        remediation=remediation,
    )


@contextmanager
def _run_state_lock(project: Path) -> Iterator[None]:
    reports = project / "reports"
    descriptor: int | None = None
    locked = False
    try:
        before = reports.lstat()
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise OSError("reports directory is unsafe")
        descriptor = os.open(
            reports,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError("reports directory changed while locking")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        yield
    except OSError as error:
        raise BioPipeError(
            ErrorCode.ARTIFACT_WRITE_FAILED,
            "The local run state could not be locked safely.",
        ) from error
    finally:
        if descriptor is not None:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)


def _remote_approval(authorization: RunAuthorization) -> dict[str, Any]:
    return {
        "approved": True,
        "authorization_id": authorization.authorization_id,
        "actor": authorization.actor,
        "approved_at": authorization.approved_at.isoformat().replace("+00:00", "Z"),
        "artifact_hashes": authorization.artifact_hashes.model_dump(mode="json"),
        "bundle_hash": authorization.bundle_hash,
        "compatibility_hash": authorization.compatibility_hash,
    }


def _validate_deployment_result(
    result: dict[str, Any],
    *,
    deployment_id: str,
    bundle_hash: str,
    file_count: int,
) -> None:
    if result != {
        "deployment_id": deployment_id,
        "bundle_hash": bundle_hash,
        "file_count": file_count,
        "status": "deployed",
    }:
        raise _protocol_error("deploy")


def _run_report(
    result: dict[str, Any],
    *,
    context: ExecutionContext,
    authorization: RunAuthorization,
    run_id: str,
    deployment_id: str,
    submitted_at: datetime,
    resume_run_id: str | None,
) -> RunReport:
    if set(result) != {
        "run_id",
        "status",
        "remote_work_dir",
        "result_dir",
        "command_hash",
        "environment_hash",
    }:
        raise _protocol_error("submit")
    if (
        result.get("run_id") != run_id
        or result.get("status") not in {"submitted", "running"}
        or result.get("remote_work_dir") != context.spec.paths.work_dir
        or result.get("result_dir") != context.spec.paths.output_dir
    ):
        raise _protocol_error("submit")
    try:
        return RunReport(
            status=result["status"],
            run_id=run_id,
            project_id=context.spec.project.name,
            profile_id=context.profile.profile_id,
            authorization_id=authorization.authorization_id,
            deployment_id=deployment_id,
            remote_work_dir=result["remote_work_dir"],
            result_dir=result["result_dir"],
            project_hash=context.project_hash,
            bundle_hash=context.bundle.bundle_hash,
            submitted_at=submitted_at,
            resume_from=resume_run_id,
            command_hash=result["command_hash"],
            environment_hash=result["environment_hash"],
        )
    except (TypeError, ValueError) as exc:
        raise _protocol_error("submit") from exc


def _persist_pending_run_state(
    context: ExecutionContext,
    authorization: RunAuthorization,
    *,
    run_id: str,
    deployment_id: str,
    deployment_dir: str,
    preflight_id: str,
    submitted_at: datetime,
    resume_run_id: str | None,
    previous_state: dict[str, Any] | None,
) -> None:
    write_project_private_state_atomic(
        context.project,
        ".run-state.json",
        _run_state_payload(
            context,
            authorization,
            submission_state="pending",
            remote_status="pending",
            run_id=run_id,
            deployment_id=deployment_id,
            deployment_dir=deployment_dir,
            preflight_id=preflight_id,
            submitted_at=submitted_at,
            resume_run_id=resume_run_id,
            command_hash=None,
            environment_hash=None,
            return_code=None,
            previous_state=previous_state,
            acceptance_report=None,
        ),
    )


def _finalize_run_acceptance(
    context: ExecutionContext,
    report: RunReport,
    authorization: RunAuthorization,
    audit: AuditWriter,
) -> None:
    with _run_state_lock(context.project):
        current = _read_optional_run_state(context)
        if (
            current is None
            or current.get("run_id") != report.run_id
            or current.get("submission_state") != "pending"
        ):
            raise BioPipeError(
                ErrorCode.ARTIFACT_WRITE_FAILED,
                "The pending run state changed before remote acceptance was recorded.",
            )
        current, canonical = _bind_pending_acceptance_report(
            context,
            current,
            report,
            authorization,
        )
        _commit_acceptance_locked(
            context,
            current,
            canonical,
            authorization,
            audit,
            final_status=report.status,
            return_code=None,
        )


def _persist_status_state(
    context: ExecutionContext,
    report: StatusReport,
    authorization: RunAuthorization,
    audit: AuditWriter,
) -> None:
    with _run_state_lock(context.project):
        current = _read_optional_run_state(context)
        if (
            current is None
            or current.get("run_id") != report.run_id
            or current.get("submission_state") not in {"pending", "accepted"}
        ):
            raise BioPipeError(
                ErrorCode.RUN_STATUS_FAILED,
                "The local run record changed while status was being queried.",
            )
        previous_status = str(current["remote_status"])
        if not _status_transition_allowed(previous_status, report.status):
            raise _protocol_error("status")
        command_hash = _bind_runtime_hash(
            current.get("command_hash"),
            report.command_hash,
        )
        environment_hash = _bind_runtime_hash(
            current.get("environment_hash"),
            report.environment_hash,
        )
        current_return_code = current.get("return_code")
        if previous_status in {"succeeded", "failed"} and (
            current_return_code != report.return_code
        ):
            raise _protocol_error("status")
        acceptance_report: RunReport | None = None
        if current["submission_state"] == "pending":
            candidate = _run_report_from_status(context, current, report, authorization)
            current, acceptance_report = _bind_pending_acceptance_report(
                context,
                current,
                candidate,
                authorization,
            )
        _append_audit(
            audit,
            context,
            authorization,
            event_type="RUN_STATUS_QUERIED",
            status="success",
            summary=f"A hash-bound status was recovered for run ID {report.run_id}.",
            recoverable_run_id=report.run_id,
        )
        if acceptance_report is not None:
            _commit_acceptance_locked(
                context,
                current,
                acceptance_report,
                authorization,
                audit,
                final_status=report.status,
                return_code=report.return_code,
            )
            return
        terminal_transition = previous_status not in {"succeeded", "failed"} and report.status in {
            "succeeded",
            "failed",
        }
        if terminal_transition:
            assert report.return_code is not None
            terminal_status: Literal["succeeded", "failed"] = (
                "succeeded" if report.status == "succeeded" else "failed"
            )
            _append_terminal_audit_once(
                context,
                report.run_id,
                terminal_status,
                report.return_code,
                report.command_hash,
                report.environment_hash,
                authorization,
                audit,
            )
        updated = dict(current)
        updated["submission_state"] = "accepted"
        updated["remote_status"] = report.status
        updated["command_hash"] = command_hash
        updated["environment_hash"] = environment_hash
        updated["return_code"] = report.return_code
        updated["previous_state"] = None
        write_project_private_state_atomic(
            context.project,
            ".run-state.json",
            updated,
        )


def _commit_acceptance_locked(
    context: ExecutionContext,
    state: dict[str, Any],
    report: RunReport,
    authorization: RunAuthorization,
    audit: AuditWriter,
    *,
    final_status: Literal["submitted", "running", "succeeded", "failed"],
    return_code: int | None,
) -> None:
    _require_report_matches_pending_state(context, state, report, authorization)
    _ensure_run_report(context, state, report)
    _consume_preflight_state(context, state, authorization)
    event_type = "RUN_RESUMED" if report.resume_from is not None else "RUN_SUBMITTED"
    acceptance_hashes = {
        "bundle": report.bundle_hash,
        "command": report.command_hash,
        "environment": report.environment_hash,
    }
    _append_audit(
        audit,
        context,
        authorization,
        event_type=event_type,
        status="success",
        summary=(
            f"A compatible fixed Nextflow resume was recorded as run ID {report.run_id}."
            if report.resume_from is not None
            else f"The fixed Nextflow submission was recorded as run ID {report.run_id}."
        ),
        output_hashes=acceptance_hashes,
        recoverable_run_id=report.run_id,
        event_id=_durable_audit_event_id(
            context,
            run_id=report.run_id,
            event_type=event_type,
            event_status="success",
            evidence=report.model_dump(mode="json"),
        ),
        append_once=True,
    )
    if final_status in {"succeeded", "failed"}:
        assert return_code is not None
        terminal_status: Literal["succeeded", "failed"] = (
            "succeeded" if final_status == "succeeded" else "failed"
        )
        _append_terminal_audit_once(
            context,
            report.run_id,
            terminal_status,
            return_code,
            report.command_hash,
            report.environment_hash,
            authorization,
            audit,
        )
    updated = dict(state)
    updated["submission_state"] = "accepted"
    updated["remote_status"] = final_status
    updated["command_hash"] = report.command_hash
    updated["environment_hash"] = report.environment_hash
    updated["return_code"] = return_code
    updated["previous_state"] = None
    updated["acceptance_report"] = None
    write_project_private_state_atomic(context.project, ".run-state.json", updated)


def _run_report_from_status(
    context: ExecutionContext,
    state: dict[str, Any],
    status: StatusReport,
    authorization: RunAuthorization,
) -> RunReport:
    try:
        return RunReport(
            status=status.status,
            run_id=status.run_id,
            project_id=context.spec.project.name,
            profile_id=context.profile.profile_id,
            authorization_id=authorization.authorization_id,
            deployment_id=state["deployment_id"],
            remote_work_dir=state["remote_work_dir"],
            result_dir=state["result_dir"],
            project_hash=context.project_hash,
            bundle_hash=context.bundle.bundle_hash,
            submitted_at=_state_timestamp(state),
            resume_from=state["resume_run_id"],
            command_hash=status.command_hash,
            environment_hash=status.environment_hash,
        )
    except (TypeError, ValueError) as error:
        raise _protocol_error("status") from error


def _bind_pending_acceptance_report(
    context: ExecutionContext,
    state: dict[str, Any],
    candidate: RunReport,
    authorization: RunAuthorization,
) -> tuple[dict[str, Any], RunReport]:
    _require_report_matches_pending_state(context, state, candidate, authorization)
    stored_value = state.get("acceptance_report")
    if stored_value is None:
        updated = dict(state)
        updated["acceptance_report"] = candidate.model_dump(mode="json")
        write_project_private_state_atomic(context.project, ".run-state.json", updated)
        return updated, candidate
    try:
        stored = RunReport.model_validate(stored_value)
    except (TypeError, ValueError) as error:
        raise _run_state_error() from error
    _require_report_matches_pending_state(context, state, stored, authorization)
    if stored.model_dump(mode="json", exclude={"status"}) != candidate.model_dump(
        mode="json",
        exclude={"status"},
    ) or not _status_transition_allowed(stored.status, candidate.status):
        raise _protocol_error("status")
    return state, stored


def _require_report_matches_pending_state(
    context: ExecutionContext,
    state: dict[str, Any],
    report: RunReport,
    authorization: RunAuthorization,
) -> None:
    if (
        state.get("submission_state") != "pending"
        or report.run_id != state.get("run_id")
        or report.project_id != context.spec.project.name
        or report.profile_id != state.get("profile_id")
        or report.authorization_id != authorization.authorization_id
        or state.get("authorization") != authorization.model_dump(mode="json")
        or report.deployment_id != state.get("deployment_id")
        or report.remote_work_dir != state.get("remote_work_dir")
        or report.result_dir != state.get("result_dir")
        or report.project_hash != state.get("project_hash")
        or report.bundle_hash != state.get("bundle_hash")
        or report.submitted_at != _state_timestamp(state)
        or report.resume_from != state.get("resume_run_id")
    ):
        raise BioPipeError(
            ErrorCode.ARTIFACT_WRITE_FAILED,
            "The recovered run acceptance does not match the pending local bindings.",
        )


def _ensure_run_report(
    context: ExecutionContext,
    state: dict[str, Any],
    expected: RunReport,
) -> None:
    payload = expected.model_dump(mode="json")
    if write_project_report_create_only_atomic(context.project, "run.json", payload):
        return
    existing_payload = read_project_report_optional(context.project, "run.json")
    if existing_payload is None:
        raise _run_report_conflict()
    try:
        existing = RunReport.model_validate(existing_payload)
    except (TypeError, ValueError) as error:
        raise _run_report_conflict() from error
    if existing == expected:
        return
    previous = state.get("previous_state")
    if not isinstance(previous, dict) or not _report_matches_previous_state(
        context,
        existing,
        previous,
    ):
        raise _run_report_conflict()
    write_project_report_atomic(context.project, "run.json", payload)
    confirmed = read_project_report_optional(context.project, "run.json")
    try:
        if confirmed is None or RunReport.model_validate(confirmed) != expected:
            raise _run_report_conflict()
    except (TypeError, ValueError) as error:
        raise _run_report_conflict() from error


def _report_matches_previous_state(
    context: ExecutionContext,
    report: RunReport,
    previous: dict[str, Any],
) -> bool:
    try:
        authorization = RunAuthorization.model_validate(previous["authorization"])
        submitted_at = _state_timestamp(previous)
    except (KeyError, TypeError, ValueError) as error:
        raise _run_state_error() from error
    return (
        report.run_id == previous.get("run_id")
        and report.project_id == context.spec.project.name
        and report.profile_id == previous.get("profile_id")
        and report.authorization_id == authorization.authorization_id
        and report.deployment_id == previous.get("deployment_id")
        and report.remote_work_dir == previous.get("remote_work_dir")
        and report.result_dir == previous.get("result_dir")
        and report.project_hash == previous.get("project_hash")
        and report.bundle_hash == previous.get("bundle_hash")
        and report.submitted_at == submitted_at
        and report.resume_from == previous.get("resume_run_id")
        and report.command_hash == previous.get("command_hash")
        and report.environment_hash == previous.get("environment_hash")
    )


def _consume_preflight_state(
    context: ExecutionContext,
    state: dict[str, Any],
    authorization: RunAuthorization,
) -> None:
    consumed = {
        "state_version": "1.0",
        "preflight_id": state["preflight_id"],
        "consumed": True,
    }
    current = read_project_private_state(context.project, ".preflight-state.json")
    if current == consumed:
        return
    validated = _load_preflight_state(
        context,
        authorization,
        resume_run_id=state["resume_run_id"],
    )
    if validated.get("preflight_id") != state.get("preflight_id") or validated.get(
        "deployment_dir"
    ) != state.get("deployment_dir"):
        raise BioPipeError(
            ErrorCode.APPROVAL_ARTIFACT_MISMATCH,
            "The preflight capability changed before acceptance was recorded.",
        )
    write_project_private_state_atomic(context.project, ".preflight-state.json", consumed)


def _append_terminal_audit_once(
    context: ExecutionContext,
    run_id: str,
    status: Literal["succeeded", "failed"],
    return_code: int,
    command_hash: str,
    environment_hash: str,
    authorization: RunAuthorization,
    audit: AuditWriter,
) -> None:
    event_type = "RUN_COMPLETED" if status == "succeeded" else "RUN_FAILED"
    terminal_hashes = {
        "command": command_hash,
        "environment": environment_hash,
        "return_code": _return_code_hash(return_code),
    }
    event_status: Literal["success", "failed"] = "success" if status == "succeeded" else "failed"
    _append_audit(
        audit,
        context,
        authorization,
        event_type=event_type,
        status=event_status,
        summary=f"The fixed Nextflow run reached terminal status {status}.",
        output_hashes=terminal_hashes,
        recoverable_run_id=run_id,
        event_id=_durable_audit_event_id(
            context,
            run_id=run_id,
            event_type=event_type,
            event_status=event_status,
            evidence=terminal_hashes,
        ),
        append_once=True,
    )


def _run_report_conflict() -> BioPipeError:
    return BioPipeError(
        ErrorCode.ARTIFACT_WRITE_FAILED,
        "The durable run report conflicts with the recovered remote acceptance.",
        remediation=["Preserve the project and audit trail for manual reconciliation."],
    )


def _run_state_payload(
    context: ExecutionContext,
    authorization: RunAuthorization,
    *,
    submission_state: Literal["pending", "accepted"],
    remote_status: Literal["pending", "submitted", "running", "succeeded", "failed"],
    run_id: str,
    deployment_id: str,
    deployment_dir: str,
    preflight_id: str,
    submitted_at: datetime,
    resume_run_id: str | None,
    command_hash: str | None,
    environment_hash: str | None,
    return_code: int | None,
    previous_state: dict[str, Any] | None,
    acceptance_report: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "state_version": "1.0",
        "submission_state": submission_state,
        "remote_status": remote_status,
        "run_id": run_id,
        "profile_id": context.profile.profile_id,
        "profile_hash": context.core_hashes.execution_profile,
        "project_hash": context.project_hash,
        "bundle_hash": context.bundle.bundle_hash,
        "deployment_id": deployment_id,
        "deployment_dir": deployment_dir,
        "preflight_id": preflight_id,
        "authorization": authorization.model_dump(mode="json"),
        "remote_work_dir": context.spec.paths.work_dir,
        "result_dir": context.spec.paths.output_dir,
        "submitted_at": submitted_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "resume_run_id": resume_run_id,
        "command_hash": command_hash,
        "environment_hash": environment_hash,
        "return_code": return_code,
        "previous_state": previous_state,
        "acceptance_report": acceptance_report,
    }


def _bind_runtime_hash(recorded: Any, received: str) -> str:
    if recorded is not None and received != recorded:
        raise _protocol_error("status")
    if recorded is not None and not isinstance(recorded, str):
        raise _run_state_error()
    if not _SHA256.fullmatch(received):
        raise _protocol_error("status")
    return received if recorded is None else recorded


def _status_transition_allowed(previous: str, received: str) -> bool:
    allowed = {
        "pending": {"submitted", "running", "succeeded", "failed"},
        "submitted": {"submitted", "running", "succeeded", "failed"},
        "running": {"running", "succeeded", "failed"},
        "succeeded": {"succeeded"},
        "failed": {"failed"},
    }
    return received in allowed.get(previous, set())


def _return_code_hash(return_code: int) -> str:
    return hashlib.sha256(str(return_code).encode("ascii")).hexdigest()


def _append_audit(
    writer: AuditWriter,
    context: ExecutionContext,
    authorization: RunAuthorization,
    *,
    event_type: str,
    status: Literal["started", "success", "failed", "blocked"],
    summary: str,
    output_hashes: dict[str, str] | None = None,
    recoverable_run_id: str | None = None,
    event_id: UUID | None = None,
    append_once: bool = False,
) -> None:
    selected_output_hashes = dict(output_hashes or {})
    if recoverable_run_id is not None:
        if not _RUN_ID.fullmatch(recoverable_run_id):
            raise ValueError("recoverable run ID is invalid")
        selected_output_hashes[recoverable_run_id] = hashlib.sha256(
            recoverable_run_id.encode("ascii")
        ).hexdigest()
    event = AuditEvent(
        event_id=event_id or uuid4(),
        timestamp=datetime.now(UTC),
        event_type=event_type,
        project_id=context.spec.project.name,
        actor=authorization.actor,
        input_hashes={
            **authorization.artifact_hashes.model_dump(mode="python"),
            "bundle": authorization.bundle_hash,
        },
        output_hashes=selected_output_hashes,
        status=status,
        summary=summary,
    )
    if append_once:
        if event_id is None:
            raise ValueError("idempotent audit append requires a deterministic event ID")
        writer.append_once(event)
    else:
        writer.append(event)


def _durable_audit_event_id(
    context: ExecutionContext,
    *,
    run_id: str,
    event_type: str,
    event_status: str,
    evidence: dict[str, Any],
) -> UUID:
    material = json.dumps(
        {
            "project_hash": context.project_hash,
            "run_id": run_id,
            "event_type": event_type,
            "event_status": event_status,
            "evidence": evidence,
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return uuid5(_DURABLE_AUDIT_NAMESPACE, material)


def _deterministic_deployment_id(
    context: ExecutionContext,
    preflight_state: dict[str, Any],
) -> str:
    material = json.dumps(
        {
            "profile_hash": context.core_hashes.execution_profile,
            "project_hash": context.project_hash,
            "bundle_hash": context.bundle.bundle_hash,
            "preflight_id": preflight_state["preflight_id"],
            "deployment_dir": preflight_state["deployment_dir"],
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"deployment-{uuid5(_DEPLOYMENT_NAMESPACE, material).hex}"


def _below_any(value: str, roots: tuple[str, ...]) -> bool:
    candidate = PurePosixPath(value)
    return any(PurePosixPath(root) in candidate.parents for root in roots)


def _protocol_error(operation: str) -> BioPipeError:
    return BioPipeError(
        ErrorCode.REMOTE_EXECUTION_PROTOCOL_ERROR,
        "The remote execution result violates its fixed contract.",
        context={"operation": operation},
    )


__all__ = [
    "ReconciliationReport",
    "RunReport",
    "StatusReport",
    "abandon_pending_run",
    "query_run_status",
    "submit_approved_run",
    "validate_local_run_state",
]
