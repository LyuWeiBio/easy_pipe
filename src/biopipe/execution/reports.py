"""Public, persisted execution-report contracts."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from biopipe.models import StrictModel

_RUN_ID = re.compile(r"^run-[0-9a-f]{32}$")
_DEPLOYMENT_ID = re.compile(r"^deployment-[0-9a-f]{32}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class RunReport(StrictModel):
    """Sanitized durable result of one submission or resume request."""

    report_version: Literal["1.0"] = "1.0"
    status: Literal["submitted", "running", "succeeded", "failed"]
    run_id: str
    project_id: str
    profile_id: str
    authorization_id: str
    deployment_id: str
    remote_work_dir: str
    result_dir: str
    project_hash: str
    bundle_hash: str
    submitted_at: datetime
    resume_from: str | None = None
    command_hash: str
    environment_hash: str

    @field_validator("run_id", "resume_from")
    @classmethod
    def validate_run_id(cls, value: str | None) -> str | None:
        if value is not None and not _RUN_ID.fullmatch(value):
            raise ValueError("run ID has an invalid format")
        return value

    @field_validator("deployment_id")
    @classmethod
    def validate_deployment_id(cls, value: str) -> str:
        if not _DEPLOYMENT_ID.fullmatch(value):
            raise ValueError("deployment ID has an invalid format")
        return value

    @field_validator("project_hash", "bundle_hash")
    @classmethod
    def validate_hashes(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("run hashes must be lowercase SHA-256")
        return value

    @field_validator("command_hash", "environment_hash")
    @classmethod
    def validate_runtime_hashes(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("runtime hashes must be lowercase SHA-256")
        return value

    @field_validator("remote_work_dir", "result_dir")
    @classmethod
    def validate_remote_paths(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            not path.is_absolute()
            or ".." in path.parts
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("run paths must be safe absolute POSIX paths")
        return str(path)


class StatusReport(StrictModel):
    """Path-free persisted response to a safe status query."""

    report_version: Literal["1.0"] = "1.0"
    run_id: str
    status: Literal["submitted", "running", "succeeded", "failed"]
    return_code: int | None = Field(default=None, ge=0, le=255)
    command_hash: str
    environment_hash: str
    checked_at: datetime

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        if not _RUN_ID.fullmatch(value):
            raise ValueError("run ID has an invalid format")
        return value

    @field_validator("command_hash", "environment_hash")
    @classmethod
    def validate_runtime_hashes(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("runtime hashes must be lowercase SHA-256")
        return value

    @model_validator(mode="after")
    def validate_status_evidence(self) -> StatusReport:
        if self.status in {"submitted", "running"}:
            if self.return_code is not None:
                raise ValueError("non-terminal status must not include a return code")
        elif self.status == "succeeded":
            if self.return_code != 0:
                raise ValueError("successful status must include return code zero")
        elif self.return_code in {None, 0}:
            raise ValueError("failed status must include a non-zero return code")
        return self


class ReconciliationReport(StrictModel):
    """Explicit local resolution of a remotely confirmed missing submission."""

    report_version: Literal["1.0"] = "1.0"
    status: Literal["abandoned"] = "abandoned"
    run_id: str
    confirmed_at: datetime

    @field_validator("run_id")
    @classmethod
    def validate_run_id(cls, value: str) -> str:
        if not _RUN_ID.fullmatch(value):
            raise ValueError("run ID has an invalid format")
        return value


__all__ = ["ReconciliationReport", "RunReport", "StatusReport"]
