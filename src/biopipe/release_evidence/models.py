"""Strict private models for release-candidate evidence.

These records are release-tooling internals.  They are deliberately not part of
the frozen public JSON Schema v1 catalog.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_RELEASE_ID_PATTERN = r"^[0-9]+\.[0-9]+\.[0-9]+-rc[1-9][0-9]*$"
_GIT_COMMIT_PATTERN = r"^[0-9a-f]{40}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ACTOR_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
_SEMVER_PATTERN = r"^[0-9]+\.[0-9]+\.[0-9]+$"
_CONTRACT_VERSION_PATTERN = r"^[0-9]+\.[0-9]+$"


class _StrictEvidenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ReleaseCandidate(_StrictEvidenceModel):
    """Identity and artifact digests for one source release candidate."""

    evidence_format_version: Literal["1.0"] = "1.0"
    release_id: str = Field(pattern=_RELEASE_ID_PATTERN)
    git_commit: str = Field(pattern=_GIT_COMMIT_PATTERN)
    controller_version: str = Field(pattern=_SEMVER_PATTERN)
    probe_version: str = Field(pattern=_SEMVER_PATTERN)
    remote_executor_version: str = Field(pattern=_SEMVER_PATTERN)
    compiler_version: str = Field(pattern=_SEMVER_PATTERN)
    registry_version: str = Field(pattern=_SEMVER_PATTERN)
    schema_version: str = Field(pattern=_CONTRACT_VERSION_PATTERN)
    cli_contract_version: str = Field(pattern=_CONTRACT_VERSION_PATTERN)
    schema_catalog_sha256: str = Field(pattern=_SHA256_PATTERN)
    schema_catalog_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_archive_sha256: str = Field(pattern=_SHA256_PATTERN)
    wheel_sha256: str = Field(pattern=_SHA256_PATTERN)
    sdist_sha256: str = Field(pattern=_SHA256_PATTERN)
    bioprobe_sha256: str = Field(pattern=_SHA256_PATTERN)
    bioexec_sha256: str = Field(pattern=_SHA256_PATTERN)
    created_at: str
    created_by: str = Field(pattern=_ACTOR_PATTERN)
    record_state: Literal["DRAFT_UNREVIEWED"] = "DRAFT_UNREVIEWED"
    release_signoff_status: Literal["pending"] = "pending"

    @field_validator("created_at")
    @classmethod
    def _created_at_is_canonical_utc(cls, value: str) -> str:
        try:
            parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise ValueError("created_at must be UTC with whole seconds and a Z suffix") from exc
        if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
            raise ValueError("created_at must use canonical UTC syntax")
        return value


class EvidenceVerification(_StrictEvidenceModel):
    """Safe result of an offline evidence-integrity verification."""

    evidence_format_version: Literal["1.0"] = "1.0"
    release_id: str = Field(pattern=_RELEASE_ID_PATTERN)
    git_commit: str = Field(pattern=_GIT_COMMIT_PATTERN)
    integrity_status: Literal["verified"] = "verified"
    release_signoff_status: Literal["pending"] = "pending"
    evidence_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    file_count: int = Field(ge=1, le=64)


__all__ = ["EvidenceVerification", "ReleaseCandidate"]
