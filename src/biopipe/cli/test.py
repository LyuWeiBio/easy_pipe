"""Synthetic-only stub and small-data end-to-end workflow testing."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import typer

from biopipe.cli.common import emit, fail
from biopipe.cli.reports import reportable_project_root, write_project_report_atomic
from biopipe.cli.validate import (
    _default_fixture_root,
    _project_layout,
    _unique,
)
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.validation import ValidationReport, validate_generated_project
from biopipe.workflow_test import WorkflowTestReport, WorkflowTestRunner, WorkflowTestStatus

_FAILURE_EXIT_CODE = 2
_DEFAULT_TIMEOUT_SECONDS = 300.0
_DEFAULT_OUTPUT_LIMIT_BYTES = 256 * 1024


def test_command(
    project_directory: Path = typer.Argument(
        ...,
        help="Generated Nextflow project directory.",
    ),
    profile: str = typer.Option(
        "test",
        "--profile",
        help="Only the synthetic-data test profile is supported.",
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
        help="Maximum captured output per external test command.",
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit compact machine-readable JSON."),
) -> None:
    """Run stub and pinned-tool E2E checks against synthetic FASTQ fixtures only."""

    if profile != "test":
        fail(
            BioPipeError(
                ErrorCode.VALIDATION_FAILED,
                "Only the synthetic-data test profile is supported.",
                context={"profile": profile},
                remediation=["Use --profile test."],
            )
        )

    static_report = validate_generated_project(project_directory)
    runs: list[WorkflowTestReport] = []
    if static_report.status == "valid":
        try:
            layout = _project_layout(project_directory)
            selected_fixture = fixture_root or _default_fixture_root(project_directory, layout)
            runs = _run_synthetic_tests(
                project_directory,
                fixture_root=selected_fixture,
                timeout_seconds=timeout_seconds,
                output_limit_bytes=output_limit_bytes,
            )
        except BioPipeError as error:
            fail(error)

    result = _test_result(static_report, runs)
    _persist_if_possible(project_directory, result)
    emit(result, as_json=as_json)
    if result["status"] != WorkflowTestStatus.PASSED.value:
        raise typer.Exit(code=_FAILURE_EXIT_CODE)


def _run_synthetic_tests(
    project_directory: Path,
    *,
    fixture_root: Path,
    timeout_seconds: float,
    output_limit_bytes: int,
) -> list[WorkflowTestReport]:
    try:
        with tempfile.TemporaryDirectory(prefix="biopipe-m4-test-") as temporary:
            runtime_parent = Path(temporary)
            runner = WorkflowTestRunner()
            stub = runner.stub_run(
                project_directory,
                fixture_root=fixture_root,
                runtime_directory=runtime_parent / "stub",
                timeout_seconds=timeout_seconds,
                output_limit_bytes=output_limit_bytes,
            )
            runs = [stub]
            if stub.status in {WorkflowTestStatus.PASSED, WorkflowTestStatus.DEGRADED}:
                runs.append(
                    runner.e2e_run(
                        project_directory,
                        fixture_root=fixture_root,
                        runtime_directory=runtime_parent / "e2e",
                        timeout_seconds=timeout_seconds,
                        output_limit_bytes=output_limit_bytes,
                    )
                )
            return runs
    except OSError as exc:
        raise BioPipeError(
            ErrorCode.ARTIFACT_WRITE_FAILED,
            "An isolated synthetic-test runtime could not be created.",
            remediation=["Check local temporary-directory permissions and retry."],
        ) from exc


def _test_result(
    static_report: ValidationReport,
    runs: list[WorkflowTestReport],
) -> dict[str, Any]:
    if static_report.status != "valid":
        findings = static_report.findings
        status = WorkflowTestStatus.FAILED
        code = findings[0].code.value if findings else "PROJECT_INVALID"
        remediation = _unique(item for finding in findings for item in finding.remediation)
    elif not runs:
        status = WorkflowTestStatus.FAILED
        code = "PROJECT_INVALID"
        remediation = ["Retry testing with the complete generated project."]
    else:
        status = _aggregate_status(runs)
        selected = next((report for report in runs if report.status == status), runs[0])
        code = selected.code.value
        remediation = _unique(item for report in runs for item in report.remediation)
    return {
        "report_version": "1.0",
        "command": "test",
        "profile": "test",
        "status": status.value,
        "code": code,
        "project_directory": static_report.project_directory,
        "report_path": "reports/test.json",
        "synthetic_data_only": True,
        "static_validation": static_report.to_dict(),
        "runs": {report.mode: report.model_dump(mode="json") for report in runs},
        "remediation": remediation,
    }


def _aggregate_status(runs: list[WorkflowTestReport]) -> WorkflowTestStatus:
    statuses = {report.status for report in runs}
    for candidate in (
        WorkflowTestStatus.FAILED,
        WorkflowTestStatus.BLOCKED,
        WorkflowTestStatus.DEGRADED,
        WorkflowTestStatus.PASSED,
    ):
        if candidate in statuses:
            return candidate
    return WorkflowTestStatus.FAILED


def _persist_if_possible(project_directory: Path, result: dict[str, Any]) -> None:
    if not reportable_project_root(project_directory):
        result["report_path"] = None
        return
    try:
        write_project_report_atomic(project_directory, "test.json", result)
    except BioPipeError as error:
        fail(error)


__all__ = ["test_command"]
