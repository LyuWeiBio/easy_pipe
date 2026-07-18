"""Static and runtime validation for one generated Nextflow project."""

from __future__ import annotations

import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal

import typer

from biopipe.cli.common import emit, fail
from biopipe.cli.reports import reportable_project_root, write_project_report_atomic
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.io import read_model
from biopipe.models import PipelineSpec
from biopipe.validation import ValidationReport, validate_generated_project
from biopipe.workflow_test import WorkflowTestReport, WorkflowTestRunner, WorkflowTestStatus

_FAILURE_EXIT_CODE = 2
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
    as_json: bool = typer.Option(False, "--json", help="Emit compact machine-readable JSON."),
) -> None:
    """Validate immutable artifacts, Nextflow configuration, syntax, and nf-test."""

    static_report = validate_generated_project(project_directory)
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

    result = _validation_result(static_report, runtime_report)
    _persist_if_possible(project_directory, "validation.json", result)
    emit(result, as_json=as_json)
    if result["status"] != WorkflowTestStatus.PASSED.value:
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
) -> dict[str, Any]:
    static_payload = static_report.to_dict()
    if static_report.status != "valid":
        findings = static_report.findings
        code = findings[0].code.value if findings else "PROJECT_INVALID"
        remediation = _unique(item for finding in findings for item in finding.remediation)
        status = WorkflowTestStatus.FAILED.value
    elif runtime_report is None:
        code = "PROJECT_INVALID"
        remediation = ["Retry validation with the complete generated project."]
        status = WorkflowTestStatus.FAILED.value
    else:
        code = runtime_report.code.value
        remediation = list(runtime_report.remediation)
        status = runtime_report.status.value
    return {
        "report_version": "1.0",
        "command": "validate",
        "status": status,
        "code": code,
        "project_directory": static_report.project_directory,
        "report_path": "reports/validation.json",
        "synthetic_data_only": True,
        "static_validation": static_payload,
        "runtime_validation": (
            None if runtime_report is None else runtime_report.model_dump(mode="json")
        ),
        "remediation": remediation,
    }


def _persist_if_possible(
    project_directory: Path,
    report_name: str,
    result: dict[str, Any],
) -> None:
    if not reportable_project_root(project_directory):
        result["report_path"] = None
        return
    try:
        write_project_report_atomic(project_directory, report_name, result)
    except BioPipeError as error:
        fail(error)


def _unique(items: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(items))


__all__ = ["validate_command"]
