"""CLI entry point for fixed remote execution preflight."""

from __future__ import annotations

from pathlib import Path

import typer
from pydantic import ValidationError

from biopipe.cli.common import ExitCode, dry_run_result, emit, fail, validation_error
from biopipe.errors import BioPipeError
from biopipe.execution.models import ExecutionProfile
from biopipe.execution.preflight import run_preflight
from biopipe.io import read_model
from biopipe.validation import validate_generated_project


def preflight_command(
    project_directory: Path = typer.Argument(
        ...,
        help="Validated generated Nextflow project directory.",
    ),
    execution_profile: Path = typer.Option(
        ...,
        "--execution-profile",
        help="Reviewed immutable M5 execution profile JSON.",
    ),
    resume_run_id: str | None = typer.Option(
        None,
        "--resume",
        help="Run ID whose compatible work/output state will be rechecked for resume.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Run local checks only; do not contact the executor or write evidence.",
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit compact machine-readable JSON."),
) -> None:
    """Check the execution host without deploying or running raw data."""

    try:
        if dry_run:
            profile = read_model(execution_profile, ExecutionProfile)
            static_report = validate_generated_project(
                project_directory,
                check_output_conflict=resume_run_id is None,
            )
            project = project_directory.expanduser().absolute()
            emit(
                dry_run_result(
                    "preflight",
                    "would_preflight" if static_report.status == "valid" else "blocked",
                    would_write=[
                        str(project / "reports" / ".preflight-state.json"),
                        str(project / "reports" / "preflight.json"),
                    ],
                    remote_operations=["executor.preflight"],
                    details={
                        "profile_id": profile.profile_id,
                        "resume_run_id": resume_run_id,
                        "static_status": static_report.status,
                    },
                ),
                as_json=as_json,
            )
            if static_report.status != "valid":
                raise typer.Exit(code=ExitCode.COMMAND_FAILED)
            return
        report = run_preflight(
            project_directory,
            execution_profile,
            resume_run_id=resume_run_id,
        )
    except ValidationError as error:
        validation_error(error)
    except BioPipeError as error:
        fail(error)
    emit(report, as_json=as_json)
    if report.status != "passed":
        raise typer.Exit(code=ExitCode.COMMAND_FAILED)


__all__ = ["preflight_command"]
