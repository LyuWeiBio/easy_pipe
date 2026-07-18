"""Machine-readable contracts for static generated-project validation."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from biopipe.models import StrictModel


class FindingCode(str, Enum):  # noqa: UP042 - bioinfo test environment is Python 3.10.
    """Stable, additive codes emitted by the static validator."""

    PROJECT_NOT_FOUND = "VALIDATION_PROJECT_NOT_FOUND"
    PROJECT_NOT_DIRECTORY = "VALIDATION_PROJECT_NOT_DIRECTORY"
    UNSAFE_PROJECT_ENTRY = "VALIDATION_UNSAFE_PROJECT_ENTRY"
    PROJECT_LIMIT_EXCEEDED = "VALIDATION_PROJECT_LIMIT_EXCEEDED"
    REQUIRED_ARTIFACT_MISSING = "VALIDATION_REQUIRED_ARTIFACT_MISSING"
    ARTIFACT_UNREADABLE = "VALIDATION_ARTIFACT_UNREADABLE"
    ARTIFACT_MODEL_INVALID = "VALIDATION_ARTIFACT_MODEL_INVALID"
    MANIFEST_INTEGRITY_INVALID = "MANIFEST_INTEGRITY_INVALID"
    MANIFEST_NOT_EXECUTABLE = "MANIFEST_NOT_EXECUTABLE"
    CROSS_ARTIFACT_MISMATCH = "VALIDATION_CROSS_ARTIFACT_MISMATCH"
    SOFTWARE_LOCK_MISMATCH = "REGISTRY_SOFTWARE_LOCK_MISMATCH"
    PATH_OVERLAP = "PATH_EXECUTION_OVERLAP"
    OUTPUT_CONFLICT = "PATH_OUTPUT_CONFLICT"
    DEFAULT_DENY_POLICY_INVALID = "APPROVAL_DEFAULT_DENY_INVALID"
    GENERATED_FILE_SET_MISMATCH = "TEMPLATE_FILE_SET_MISMATCH"
    GENERATED_CONTENT_MISMATCH = "TEMPLATE_CONTENT_MISMATCH"
    SAMPLESHEET_MISMATCH = "TEMPLATE_SAMPLESHEET_MISMATCH"
    GENERATED_HASH_MISMATCH = "TEMPLATE_ARTIFACT_HASH_MISMATCH"
    CONTAINER_REFERENCE_INVALID = "CONTAINER_REFERENCE_NOT_DIGEST_ONLY"
    FLOATING_VERSION = "CONTAINER_FLOATING_VERSION"
    AUDIT_RECORD_INVALID = "VALIDATION_AUDIT_RECORD_INVALID"
    REGISTRY_INVALID = "REGISTRY_DEFAULT_INVALID"


class FindingSeverity(str, Enum):  # noqa: UP042 - bioinfo test environment is Python 3.10.
    """Severity of a validation finding."""

    WARNING = "warning"
    BLOCKING = "blocking"


class ValidationFinding(StrictModel):
    """One stable, actionable result from a static validation check."""

    code: FindingCode
    severity: FindingSeverity = FindingSeverity.BLOCKING
    artifact: str | None = None
    message: str
    remediation: list[str] = Field(min_length=1)
    context: dict[str, str | int | bool | list[str]] = Field(default_factory=dict)

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str) -> str:
        if not value or any(ord(character) < 32 for character in value):
            raise ValueError("finding messages must be non-empty single-line text")
        return value

    @field_validator("artifact")
    @classmethod
    def validate_artifact(cls, value: str | None) -> str | None:
        if value is not None and (not value or any(ord(character) < 32 for character in value)):
            raise ValueError("finding artifact paths must be safe display text")
        return value


class ValidationReport(StrictModel):
    """Deterministic report returned by static generated-project validation."""

    report_version: Literal["1.0"] = "1.0"
    validator: Literal["static-generated-project"] = "static-generated-project"
    project_directory: str
    status: Literal["valid", "invalid"]
    checked_artifacts: list[str] = Field(default_factory=list)
    artifact_hashes: dict[str, str] = Field(default_factory=dict)
    output_target_checked: str | None = None
    findings: list[ValidationFinding] = Field(default_factory=list)

    @field_validator("artifact_hashes")
    @classmethod
    def validate_hashes(cls, values: dict[str, str]) -> dict[str, str]:
        if any(
            len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
            for value in values.values()
        ):
            raise ValueError("artifact hashes must be lowercase SHA-256 hex digests")
        return values

    @model_validator(mode="after")
    def validate_status(self) -> ValidationReport:
        has_blocking = any(
            finding.severity == FindingSeverity.BLOCKING for finding in self.findings
        )
        if (self.status == "invalid") != has_blocking:
            raise ValueError("report status must reflect blocking findings")
        return self

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation for CLI and report writers."""

        return self.model_dump(mode="json")


__all__ = [
    "FindingCode",
    "FindingSeverity",
    "ValidationFinding",
    "ValidationReport",
]
