"""CLI entry point for fixed remote execution preflight."""

from __future__ import annotations

from pathlib import Path

import typer
from pydantic import ValidationError

from biopipe.cli.common import emit, fail, validation_error
from biopipe.errors import BioPipeError
from biopipe.execution.preflight import run_preflight


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
    as_json: bool = typer.Option(False, "--json", help="Emit compact machine-readable JSON."),
) -> None:
    """Check the execution host without deploying or running raw data."""

    try:
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
        raise typer.Exit(code=2)


__all__ = ["preflight_command"]
