"""Stable machine-readable reports for synthetic Nextflow verification."""

from __future__ import annotations

import json
from enum import Enum
from typing import Literal

from pydantic import Field, model_validator

from biopipe.models import StrictModel


class WorkflowTestStatus(str, Enum):  # noqa: UP042 - Python 3.10 test-env compatibility
    """Terminal status of a workflow test or one of its checks."""

    PASSED = "passed"
    FAILED = "failed"
    BLOCKED = "blocked"
    DEGRADED = "degraded"


class WorkflowTestCode(str, Enum):  # noqa: UP042 - Python 3.10 test-env compatibility
    """Stable additive codes for M4 validation and synthetic execution."""

    OK = "OK"
    PROJECT_INVALID = "PROJECT_INVALID"
    FIXTURE_INVALID = "FIXTURE_INVALID"
    FIXTURE_LAYOUT_MISMATCH = "FIXTURE_LAYOUT_MISMATCH"
    RUNTIME_DIRECTORY_CONFLICT = "RUNTIME_DIRECTORY_CONFLICT"
    NEXTFLOW_NOT_FOUND = "NEXTFLOW_NOT_FOUND"
    TOOL_NOT_FOUND = "TOOL_NOT_FOUND"
    TOOL_VERSION_CHECK_FAILED = "TOOL_VERSION_CHECK_FAILED"
    TOOL_VERSION_MISMATCH = "TOOL_VERSION_MISMATCH"
    NF_TEST_NOT_FOUND = "NF_TEST_NOT_FOUND"
    NF_TEST_SUITE_NOT_FOUND = "NF_TEST_SUITE_NOT_FOUND"
    COMMAND_TIMEOUT = "COMMAND_TIMEOUT"
    COMMAND_OUTPUT_LIMIT = "COMMAND_OUTPUT_LIMIT"
    CONFIG_CHECK_FAILED = "CONFIG_CHECK_FAILED"
    LINT_CHECK_FAILED = "LINT_CHECK_FAILED"
    SYNTAX_CHECK_FAILED = "SYNTAX_CHECK_FAILED"
    STUB_RUN_FAILED = "STUB_RUN_FAILED"
    E2E_RUN_FAILED = "E2E_RUN_FAILED"
    NF_TEST_FAILED = "NF_TEST_FAILED"
    OUTPUT_ASSERTION_FAILED = "OUTPUT_ASSERTION_FAILED"


class WorkflowCheck(StrictModel):
    """One bounded command or structural assertion without raw command output."""

    name: str
    status: WorkflowTestStatus
    code: WorkflowTestCode
    return_code: int | None = Field(default=None, ge=-255, le=255)
    message: str
    remediation: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_status_code(self) -> WorkflowCheck:
        if self.status == WorkflowTestStatus.PASSED and self.code != WorkflowTestCode.OK:
            raise ValueError("passed checks require code OK")
        if self.status != WorkflowTestStatus.PASSED and self.code == WorkflowTestCode.OK:
            raise ValueError("non-passed checks require a non-OK code")
        return self


class WorkflowTestReport(StrictModel):
    """Deterministic report for config, syntax, stub, or synthetic E2E checks."""

    report_version: Literal["1.0"] = "1.0"
    mode: Literal["validate", "stub", "e2e"]
    status: WorkflowTestStatus
    code: WorkflowTestCode
    layout: Literal["single_end", "paired_end"] | None = None
    trimming_enabled: bool | None = None
    synthetic_data_only: Literal[True] = True
    checks: tuple[WorkflowCheck, ...] = ()
    outputs: tuple[str, ...] = ()
    remediation: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_terminal_status(self) -> WorkflowTestReport:
        if self.status == WorkflowTestStatus.PASSED:
            if self.code != WorkflowTestCode.OK:
                raise ValueError("passed reports require code OK")
            if any(check.status != WorkflowTestStatus.PASSED for check in self.checks):
                raise ValueError("passed reports cannot contain a non-passed check")
        elif self.code == WorkflowTestCode.OK:
            raise ValueError("non-passed reports require a non-OK code")
        if tuple(sorted(set(self.outputs))) != self.outputs:
            raise ValueError("report outputs must be unique and sorted")
        return self

    def to_json(self) -> str:
        """Serialize with stable key ordering and no runtime-dependent fields."""

        return (
            json.dumps(
                self.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )


__all__ = [
    "WorkflowCheck",
    "WorkflowTestCode",
    "WorkflowTestReport",
    "WorkflowTestStatus",
]
