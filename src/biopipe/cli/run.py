"""CLI entry point for approval-gated execution and safe status queries."""

from __future__ import annotations

from pathlib import Path

import typer
from pydantic import ValidationError

from biopipe.cli.common import emit, fail, validation_error
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution.runner import abandon_pending_run, query_run_status, submit_approved_run


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
    as_json: bool = typer.Option(False, "--json", help="Emit compact machine-readable JSON."),
) -> None:
    """Submit only after the gate passes, or query one exact recorded run."""

    try:
        if abandon_pending_run_id is not None:
            if (
                status_run_id is not None
                or resume_run_id is not None
                or actor is not None
                or approve_real_data
            ):
                raise BioPipeError(
                    ErrorCode.VALIDATION_FAILED,
                    "Pending-run abandonment cannot be combined with other run modes.",
                )
            reconciliation = abandon_pending_run(
                project_directory,
                execution_profile,
                run_id=abandon_pending_run_id,
            )
            emit(reconciliation, as_json=as_json)
            return
        if status_run_id is not None:
            if resume_run_id is not None or actor is not None or approve_real_data:
                raise BioPipeError(
                    ErrorCode.VALIDATION_FAILED,
                    "Status mode cannot be combined with approval or resume options.",
                    remediation=["Use only --status RUN_ID with the project and profile."],
                )
            result = query_run_status(
                project_directory,
                execution_profile,
                run_id=status_run_id,
            )
            emit(result, as_json=as_json)
            if result.status == "failed":
                raise typer.Exit(code=2)
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
        raise typer.Exit(code=2)


__all__ = ["run_command"]
