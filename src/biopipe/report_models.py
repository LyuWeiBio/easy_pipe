"""Public outer contracts persisted by ``validate`` and ``test`` commands."""

from __future__ import annotations

from typing import Literal

from pydantic import model_validator

from biopipe.models import StrictModel
from biopipe.validation import FindingCode, ValidationReport
from biopipe.workflow_test import (
    WorkflowTestCode,
    WorkflowTestReport,
    WorkflowTestStatus,
)

ReportCode = FindingCode | WorkflowTestCode


class ValidationCommandReport(StrictModel):
    """Complete public shape of persisted ``reports/validation.json``."""

    report_version: Literal["1.0"] = "1.0"
    command: Literal["validate"] = "validate"
    status: WorkflowTestStatus
    code: ReportCode
    project_directory: str
    report_path: Literal["reports/validation.json"] | None
    synthetic_data_only: Literal[True] = True
    static_validation: ValidationReport
    runtime_validation: WorkflowTestReport | None
    remediation: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_evidence_consistency(self) -> ValidationCommandReport:
        if self.project_directory != self.static_validation.project_directory:
            raise ValueError("validation project directory does not match static evidence")
        if self.static_validation.status != "valid":
            expected_code = (
                self.static_validation.findings[0].code.value
                if self.static_validation.findings
                else WorkflowTestCode.PROJECT_INVALID.value
            )
            if (
                self.runtime_validation is not None
                or self.status != WorkflowTestStatus.FAILED
                or self.code.value != expected_code
            ):
                raise ValueError("failed static validation is inconsistent with the outer report")
            return self
        if self.runtime_validation is None:
            if (
                self.status != WorkflowTestStatus.FAILED
                or self.code != WorkflowTestCode.PROJECT_INVALID
            ):
                raise ValueError("missing runtime validation requires PROJECT_INVALID")
            return self
        if (
            self.runtime_validation.mode != "validate"
            or self.status != self.runtime_validation.status
            or self.code.value != self.runtime_validation.code.value
        ):
            raise ValueError("runtime validation does not match the outer report")
        return self

    def require_gate_success(self) -> ValidationCommandReport:
        """Reject any report that is insufficient as real-data gate evidence."""

        if (
            self.report_path != "reports/validation.json"
            or self.status != WorkflowTestStatus.PASSED
            or self.code != WorkflowTestCode.OK
            or self.static_validation.status != "valid"
            or self.static_validation.findings
            or self.runtime_validation is None
            or self.runtime_validation.mode != "validate"
            or self.runtime_validation.status != WorkflowTestStatus.PASSED
        ):
            raise ValueError("validation evidence is not wholly successful")
        return self


class TestCommandReport(StrictModel):
    """Complete public shape of persisted ``reports/test.json``."""

    report_version: Literal["1.0"] = "1.0"
    command: Literal["test"] = "test"
    profile: Literal["test"] = "test"
    status: WorkflowTestStatus
    code: ReportCode
    project_directory: str
    report_path: Literal["reports/test.json"] | None
    synthetic_data_only: Literal[True] = True
    static_validation: ValidationReport
    runs: dict[str, WorkflowTestReport]
    remediation: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_evidence_consistency(self) -> TestCommandReport:
        if self.project_directory != self.static_validation.project_directory:
            raise ValueError("test project directory does not match static evidence")
        if any(
            key != report.mode or key not in {"stub", "e2e"} for key, report in self.runs.items()
        ):
            raise ValueError("test run keys must match supported report modes")
        if self.static_validation.status != "valid":
            expected_code = (
                self.static_validation.findings[0].code.value
                if self.static_validation.findings
                else WorkflowTestCode.PROJECT_INVALID.value
            )
            if (
                self.runs
                or self.status != WorkflowTestStatus.FAILED
                or self.code.value != expected_code
            ):
                raise ValueError("failed static validation is inconsistent with the test report")
            return self
        if not self.runs:
            if (
                self.status != WorkflowTestStatus.FAILED
                or self.code != WorkflowTestCode.PROJECT_INVALID
            ):
                raise ValueError("missing synthetic runs requires PROJECT_INVALID")
            return self
        expected_status = _aggregate_status(tuple(self.runs.values()))
        selected = next(report for report in self.runs.values() if report.status == expected_status)
        if self.status != expected_status or self.code.value != selected.code.value:
            raise ValueError("synthetic run evidence does not match the outer report")
        return self

    def require_gate_success(self) -> TestCommandReport:
        """Reject any report that is insufficient as real-data gate evidence."""

        if (
            self.report_path != "reports/test.json"
            or self.status != WorkflowTestStatus.PASSED
            or self.code != WorkflowTestCode.OK
            or self.static_validation.status != "valid"
            or self.static_validation.findings
            or set(self.runs) != {"e2e", "stub"}
            or any(report.status != WorkflowTestStatus.PASSED for report in self.runs.values())
        ):
            raise ValueError("test evidence is not wholly successful")
        return self


def _aggregate_status(reports: tuple[WorkflowTestReport, ...]) -> WorkflowTestStatus:
    statuses = {report.status for report in reports}
    for candidate in (
        WorkflowTestStatus.FAILED,
        WorkflowTestStatus.BLOCKED,
        WorkflowTestStatus.DEGRADED,
        WorkflowTestStatus.PASSED,
    ):
        if candidate in statuses:
            return candidate
    return WorkflowTestStatus.FAILED


__all__ = ["ReportCode", "TestCommandReport", "ValidationCommandReport"]
