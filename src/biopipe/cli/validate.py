"""Static and runtime validation for one generated Nextflow project."""

from __future__ import annotations

import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Literal

import typer

from biopipe.cli.common import ExitCode, dry_run_result, emit, fail
from biopipe.cli.reports import reportable_project_root, write_project_report_atomic
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.io import read_model
from biopipe.models import PipelineSpec
from biopipe.report_models import ReportCode, ValidationCommandReport
from biopipe.validation import ValidationReport, validate_generated_project
from biopipe.workflow_test import (
    WorkflowTestCode,
    WorkflowTestReport,
    WorkflowTestRunner,
    WorkflowTestStatus,
)

_FAILURE_EXIT_CODE = ExitCode.COMMAND_FAILED
_DEFAULT_TIMEOUT_SECONDS = 300.0
_DEFAULT_OUTPUT_LIMIT_BYTES = 256 * 1024


def validate_command(
    project_directory: Path = typer.Argument(
        ...,
        help="Generated Nextflow project directory.",
    ),
    fixture_root: Path | None = typer.Option(
        None,
        "--fixture-root",
        help=(
            "Synthetic fixture override; by default use the layout-matched fixture under "
            "PROJECT/tests/fixtures/."
        ),
    ),
    timeout_seconds: float = typer.Option(
        _DEFAULT_TIMEOUT_SECONDS,
        "--timeout-seconds",
        min=1.0,
        max=3_600.0,
        help="Per-command timeout for bounded Nextflow and nf-test checks.",
    ),
    output_limit_bytes: int = typer.Option(
        _DEFAULT_OUTPUT_LIMIT_BYTES,
        "--output-limit-bytes",
        min=1_024,
        max=16 * 1024 * 1024,
        help="Maximum captured output per external validation command.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Run static checks only; do not execute tools or write a report.",
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit compact machine-readable JSON."),
) -> None:
    """Validate immutable artifacts, Nextflow configuration, syntax, and nf-test."""

    static_report = validate_generated_project(project_directory)
    if dry_run:
        emit(
            dry_run_result(
                "validate",
                "would_validate" if static_report.status == "valid" else "blocked",
                would_write=[
                    str(project_directory.expanduser().absolute() / "reports" / "validation.json")
                ],
                details={
                    "external_commands": ["nextflow config", "nextflow lint", "nf-test"],
                    "static_status": static_report.status,
                },
            ),
            as_json=as_json,
        )
        if static_report.status != "valid":
            raise typer.Exit(code=_FAILURE_EXIT_CODE)
        return
    runtime_report: WorkflowTestReport | None = None
    if static_report.status == "valid":
        try:
            layout = _project_layout(project_directory)
            selected_fixture = fixture_root or _default_fixture_root(project_directory, layout)
            runtime_report = _run_runtime_validation(
                project_directory,
                fixture_root=selected_fixture,
                timeout_seconds=timeout_seconds,
                output_limit_bytes=output_limit_bytes,
            )
        except BioPipeError as error:
            fail(error)

    result = _persist_if_possible(
        project_directory,
        "validation.json",
        _validation_result(static_report, runtime_report),
    )
    emit(result, as_json=as_json)
    if result.status != WorkflowTestStatus.PASSED:
        raise typer.Exit(code=_FAILURE_EXIT_CODE)


def _run_runtime_validation(
    project_directory: Path,
    *,
    fixture_root: Path,
    timeout_seconds: float,
    output_limit_bytes: int,
) -> WorkflowTestReport:
    try:
        with tempfile.TemporaryDirectory(prefix="biopipe-m4-validate-") as temporary:
            return WorkflowTestRunner().validate(
                project_directory,
                fixture_root=fixture_root,
                runtime_directory=Path(temporary) / "runtime",
                timeout_seconds=timeout_seconds,
                output_limit_bytes=output_limit_bytes,
            )
    except OSError as exc:
        raise BioPipeError(
            ErrorCode.ARTIFACT_WRITE_FAILED,
            "An isolated validation runtime could not be created.",
            remediation=["Check local temporary-directory permissions and retry."],
        ) from exc


def _project_layout(project_directory: Path) -> Literal["single_end", "paired_end"]:
    spec = read_model(project_directory / "pipeline.spec.yaml", PipelineSpec)
    return spec.input.layout


def _default_fixture_root(
    project_directory: Path,
    layout: Literal["single_end", "paired_end"],
) -> Path:
    return project_directory / "tests" / "fixtures" / layout


def _validation_result(
    static_report: ValidationReport,
    runtime_report: WorkflowTestReport | None,
) -> ValidationCommandReport:
    code: ReportCode
    status: WorkflowTestStatus
    if static_report.status != "valid":
        findings = static_report.findings
        code = findings[0].code if findings else WorkflowTestCode.PROJECT_INVALID
        remediation = _unique(item for finding in findings for item in finding.remediation)
        status = WorkflowTestStatus.FAILED
    elif runtime_report is None:
        code = WorkflowTestCode.PROJECT_INVALID
        remediation = ["Retry validation with the complete generated project."]
        status = WorkflowTestStatus.FAILED
    else:
        code = runtime_report.code
        remediation = list(runtime_report.remediation)
        status = runtime_report.status
    return ValidationCommandReport(
        status=status,
        code=code,
        project_directory=static_report.project_directory,
        report_path="reports/validation.json",
        static_validation=static_report,
        runtime_validation=runtime_report,
        remediation=tuple(remediation),
    )


def _persist_if_possible(
    project_directory: Path,
    report_name: str,
    result: ValidationCommandReport,
) -> ValidationCommandReport:
    if not reportable_project_root(project_directory):
        return ValidationCommandReport.model_validate(
            {**result.model_dump(mode="json"), "report_path": None}
        )
    try:
        write_project_report_atomic(
            project_directory,
            report_name,
            result.model_dump(mode="json"),
        )
    except BioPipeError as error:
        fail(error)
    return result


def _unique(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))


__all__ = ["validate_command"]
