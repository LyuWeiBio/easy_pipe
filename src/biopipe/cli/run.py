"""CLI entry point for approval-gated execution and safe status queries."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import typer
from pydantic import ValidationError

from biopipe.cli.common import ExitCode, dry_run_result, emit, fail, validation_error
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution.deploy import hash_frozen_deployment_snapshot
from biopipe.execution.gate import ApprovalGate
from biopipe.execution.models import ApprovalArtifactPaths
from biopipe.execution.runner import (
    abandon_pending_run,
    query_run_status,
    submit_approved_run,
    validate_local_run_state,
)
from biopipe.validation import validate_generated_project

_RUN_ID = re.compile(r"^run-[0-9a-f]{32}$")
_ACTOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def run_command(
    project_directory: Path = typer.Argument(
        ...,
        help="Validated, tested, and successfully preflighted generated project.",
    ),
    execution_profile: Path = typer.Option(
        ...,
        "--execution-profile",
        help="The same immutable execution profile used by preflight.",
    ),
    actor: str | None = typer.Option(
        None,
        "--actor",
        help="Attributable safe username approving this exact run.",
    ),
    approve_real_data: bool = typer.Option(
        False,
        "--approve-real-data",
        help="Explicitly approve use of the manifest's real-data paths.",
    ),
    resume_run_id: str | None = typer.Option(
        None,
        "--resume",
        help="Submit a compatible resume after `preflight --resume RUN_ID`.",
    ),
    status_run_id: str | None = typer.Option(
        None,
        "--status",
        help="Query only this locally recorded run ID; no approval is needed.",
    ),
    abandon_pending_run_id: str | None = typer.Option(
        None,
        "--abandon-pending",
        help="After the safety delay, reconcile and abandon a remotely absent pending run.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help=(
            "Validate submit/resume local gates and preview the mode without reading keys, "
            "signing, deploying, or contacting SSH."
        ),
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit compact machine-readable JSON."),
) -> None:
    """Submit only after the gate passes, or query one exact recorded run."""

    try:
        selected_run_ids = [resume_run_id, status_run_id, abandon_pending_run_id]
        if any(value is not None and not _RUN_ID.fullmatch(value) for value in selected_run_ids):
            raise BioPipeError(
                ErrorCode.VALIDATION_FAILED,
                "A run mode received an invalid run ID.",
                remediation=["Use the exact locally recorded run-NNN identifier."],
            )
        if actor is not None and not _ACTOR.fullmatch(actor):
            raise BioPipeError(
                ErrorCode.APPROVAL_REQUIRED,
                "The approval actor must be a stable safe identifier.",
            )
        if abandon_pending_run_id is not None and (
            status_run_id is not None
            or resume_run_id is not None
            or actor is not None
            or approve_real_data
        ):
            raise BioPipeError(
                ErrorCode.VALIDATION_FAILED,
                "Pending-run abandonment cannot be combined with other run modes.",
            )
        if status_run_id is not None and (
            resume_run_id is not None or actor is not None or approve_real_data
        ):
            raise BioPipeError(
                ErrorCode.VALIDATION_FAILED,
                "Status mode cannot be combined with approval or resume options.",
                remediation=["Use only --status RUN_ID with the project and profile."],
            )
        if dry_run:
            project = project_directory.expanduser().absolute()
            selected_run_id: str | None
            if abandon_pending_run_id is not None:
                mode = "abandon_pending"
                selected_run_id = abandon_pending_run_id
                remote_operations = ["executor.abandon"]
                status = "would_abandon_pending"
                report_names = [".run-state.json"]
            elif status_run_id is not None:
                mode = "status"
                selected_run_id = status_run_id
                remote_operations = ["executor.status"]
                status = "would_query_status"
                report_names = [".run-state.json", "run.json", "status.json"]
            else:
                mode = "resume" if resume_run_id is not None else "submit"
                selected_run_id = resume_run_id
                remote_operations = (
                    ["executor.resume"]
                    if resume_run_id is not None
                    else ["executor.deploy", "executor.submit"]
                )
                status = "would_resume" if resume_run_id is not None else "would_submit"
                report_names = [".preflight-state.json", ".run-state.json", "run.json"]
            if mode in {"submit", "resume"}:
                if actor is None:
                    raise BioPipeError(
                        ErrorCode.APPROVAL_REQUIRED,
                        "An attributable --actor is required to validate submission gates.",
                    )
                if not approve_real_data:
                    raise BioPipeError(
                        ErrorCode.APPROVAL_REQUIRED,
                        "Explicit --approve-real-data is required to validate submission gates.",
                    )
                _validate_local_submission_gate(
                    project,
                    execution_profile,
                    resume_run_id=resume_run_id,
                )
            dry_run_output = dry_run_result(
                "run",
                status,
                would_write=[
                    str(project / "audit" / "events.jsonl"),
                    *(str(project / "reports" / name) for name in report_names),
                ],
                remote_operations=remote_operations,
                details={
                    "actor_provided": actor is not None,
                    "approval_required_for_execution": mode in {"submit", "resume"},
                    "execution_profile": str(execution_profile.expanduser().absolute()),
                    "mode": mode,
                    "real_data_approval_provided": approve_real_data,
                    "run_id": selected_run_id,
                },
            )
            if mode in {"submit", "resume"}:
                dry_run_output["local_gate_validation"] = "passed"
            emit(dry_run_output, as_json=as_json)
            return
        if abandon_pending_run_id is not None:
            reconciliation = abandon_pending_run(
                project_directory,
                execution_profile,
                run_id=abandon_pending_run_id,
            )
            emit(reconciliation, as_json=as_json)
            return
        if status_run_id is not None:
            result = query_run_status(
                project_directory,
                execution_profile,
                run_id=status_run_id,
            )
            emit(result, as_json=as_json)
            if result.status == "failed":
                raise typer.Exit(code=ExitCode.COMMAND_FAILED)
            return
        else:
            if actor is None:
                raise BioPipeError(
                    ErrorCode.APPROVAL_REQUIRED,
                    "An attributable --actor is required for submission.",
                )
            run_result = submit_approved_run(
                project_directory,
                execution_profile,
                actor=actor,
                approve_real_data=approve_real_data,
                resume_run_id=resume_run_id,
            )
    except ValidationError as error:
        validation_error(error)
    except BioPipeError as error:
        fail(error)
    emit(run_result, as_json=as_json)
    if run_result.status == "failed":
        raise typer.Exit(code=ExitCode.COMMAND_FAILED)


def _validate_local_submission_gate(
    project: Path,
    execution_profile: Path,
    *,
    resume_run_id: str | None,
) -> None:
    validation = validate_generated_project(
        project,
        check_output_conflict=resume_run_id is None,
    )
    if validation.status != "valid":
        raise BioPipeError(
            ErrorCode.DEPLOYMENT_FAILED,
            "The generated project is not valid for deployment.",
            context={"finding_codes": [finding.code.value for finding in validation.findings]},
            remediation=["Regenerate, validate, test, and preflight the project before retrying."],
        )
    bundle_hash = hash_frozen_deployment_snapshot(project)
    approval_time = datetime.now(UTC)
    evidence = ApprovalGate().validate_local_evidence(
        ApprovalArtifactPaths(
            dataset_manifest=project / "dataset.manifest.resolved.json",
            pipeline_spec=project / "pipeline.spec.yaml",
            execution_plan=project / "execution.plan.yaml",
            software_lock=project / "software.lock.yaml",
            validation_report=project / "reports" / "validation.json",
            test_report=project / "reports" / "test.json",
            execution_profile=execution_profile.expanduser().absolute(),
            preflight_report=project / "reports" / "preflight.json",
        ),
        now=approval_time,
    )
    evidence.validate_approval_time(approval_time)
    validate_local_run_state(
        project,
        execution_profile,
        evidence,
        bundle_hash=bundle_hash,
        resume_run_id=resume_run_id,
    )


__all__ = ["run_command"]
