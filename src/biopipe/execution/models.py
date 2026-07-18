"""Strict execution-domain contracts for M5 approval and local execution."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from biopipe.models import StrictModel

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TAGGED_IMAGE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
)
_SAFE_EXECUTABLE_PATH = re.compile(r"^(?:/|~/)[A-Za-z0-9_./~-]+$")


def _identifier(value: str, label: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} must be a safe identifier")
    return value


def _absolute_path(value: str, label: str) -> str:
    if (
        not value
        or len(value.encode("utf-8")) > 4096
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ValueError(f"{label} is not a bounded display-safe path")
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or path == PurePosixPath("/"):
        raise ValueError(f"{label} must be a non-root absolute POSIX path")
    return str(path)


def _aware_utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return value.astimezone(timezone.utc)  # noqa: UP017 - bioinfo supports Python 3.10.


def _paths_overlap(first: str, second: str) -> bool:
    first_path = PurePosixPath(first)
    second_path = PurePosixPath(second)
    return (
        first_path == second_path
        or first_path in second_path.parents
        or second_path in first_path.parents
    )


class ExecutionPathMapping(StrictModel):
    """One explicit source-to-execution prefix mapping."""

    source_prefix: str
    execution_prefix: str

    @field_validator("source_prefix", "execution_prefix")
    @classmethod
    def validate_paths(cls, value: str) -> str:
        return _absolute_path(value, "execution path mapping")


class AllowedExecutionRoots(StrictModel):
    """Role-separated remote write allowlists."""

    deploy: tuple[str, ...] = Field(min_length=1, max_length=64)
    work: tuple[str, ...] = Field(min_length=1, max_length=64)
    output: tuple[str, ...] = Field(min_length=1, max_length=64)
    cache: tuple[str, ...] = Field(min_length=1, max_length=64)

    @field_validator("deploy", "work", "output", "cache")
    @classmethod
    def validate_roots(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_absolute_path(value, "allowed execution root") for value in values)
        if len(set(normalized)) != len(normalized):
            raise ValueError("allowed execution roots must be unique")
        return tuple(sorted(normalized))


class LocalExecutionRuntime(StrictModel):
    """The only runtime admitted by the M5 MVP."""

    executor: Literal["local"] = "local"
    workflow_engine: Literal["nextflow"] = "nextflow"
    container_engine: Literal["apptainer", "docker"] = "apptainer"


class DiskThreshold(StrictModel):
    """Minimum free space required by preflight."""

    minimum_free_bytes: int = Field(default=10 * 1024**3, ge=1024**3, le=1024**5)


class ApprovalSigner(StrictModel):
    """Controller-side key reference for authenticated run authorizations.

    Only the key identifier and local file path are stored in the execution
    profile.  The HMAC key bytes never enter generated projects, reports, audit
    records, or the remote protocol.
    """

    key_id: str
    key_file: str

    @field_validator("key_id")
    @classmethod
    def validate_key_id(cls, value: str) -> str:
        return _identifier(value, "approval signing key identifier")

    @field_validator("key_file")
    @classmethod
    def validate_key_file(cls, value: str) -> str:
        return _absolute_path(value, "approval signing key file")


class ContainerArtifact(StrictModel):
    """Reviewed offline container identity and optional local SIF binding."""

    image: str
    digest: str
    local_path: str | None = None
    file_sha256: str | None = None

    @field_validator("image")
    @classmethod
    def validate_image(cls, value: str) -> str:
        if "@" in value or not _TAGGED_IMAGE.fullmatch(value):
            raise ValueError("container image must be a safe explicitly tagged OCI reference")
        if value.rsplit(":", maxsplit=1)[-1].casefold() == "latest":
            raise ValueError("container image must not use latest")
        return value

    @field_validator("digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if (
            not value.startswith("sha256:")
            or not _SHA256.fullmatch(value[7:])
            or value[7:] == "0" * 64
        ):
            raise ValueError("container digest must be one non-placeholder SHA-256 digest")
        return value

    @field_validator("local_path")
    @classmethod
    def validate_local_path(cls, value: str | None) -> str | None:
        return None if value is None else _absolute_path(value, "local container path")

    @field_validator("file_sha256")
    @classmethod
    def validate_file_hash(cls, value: str | None) -> str | None:
        if value is not None and (not _SHA256.fullmatch(value) or value == "0" * 64):
            raise ValueError("local container hash must be lowercase SHA-256")
        return value


class ExecutionProfile(StrictModel):
    """Hashed controller configuration for one bounded execution domain."""

    profile_version: Literal["1.0"] = "1.0"
    profile_id: str
    source_host: str
    execution_host: str
    ssh_alias: str
    username: str | None = None
    port: int = Field(default=22, ge=1, le=65_535, strict=True)
    bioexec_path: str = "~/.local/bin/bioexec.pyz"
    approval_signer: ApprovalSigner
    allowed_roots: AllowedExecutionRoots
    runtime: LocalExecutionRuntime = Field(default_factory=LocalExecutionRuntime)
    containers: dict[str, ContainerArtifact] = Field(min_length=1, max_length=64)
    disk_threshold: DiskThreshold = Field(default_factory=DiskThreshold)
    preflight_max_age_seconds: int = Field(default=900, ge=60, le=86_400)
    path_mapping: tuple[ExecutionPathMapping, ...] = Field(default=(), max_length=64)

    @field_validator("profile_id", "source_host", "execution_host")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return _identifier(value, "execution profile identifier")

    @field_validator("ssh_alias", "username")
    @classmethod
    def validate_ssh_argument(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if (
            not value
            or len(value.encode("utf-8")) > 255
            or value.startswith("-")
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise ValueError("SSH profile values must be one bounded safe argument")
        return value

    @field_validator("bioexec_path")
    @classmethod
    def validate_bioexec_path(cls, value: str) -> str:
        if (
            not value
            or len(value.encode("utf-8")) > 4096
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)
            or not (value.startswith("/") or value.startswith("~/"))
            or not _SAFE_EXECUTABLE_PATH.fullmatch(value)
        ):
            raise ValueError("bioexec_path must be one safe absolute or home-relative path")
        path = PurePosixPath(value.removeprefix("~"))
        if ".." in path.parts or path.name != "bioexec.pyz":
            raise ValueError("bioexec_path must identify a fixed bioexec.pyz without traversal")
        return value

    @field_validator("path_mapping")
    @classmethod
    def validate_mapping(
        cls, values: tuple[ExecutionPathMapping, ...]
    ) -> tuple[ExecutionPathMapping, ...]:
        sources = [value.source_prefix for value in values]
        if len(set(sources)) != len(sources):
            raise ValueError("execution mappings must have unique source prefixes")
        return tuple(
            sorted(values, key=lambda value: (value.source_prefix, value.execution_prefix))
        )

    @field_validator("containers")
    @classmethod
    def validate_container_names(
        cls, values: dict[str, ContainerArtifact]
    ) -> dict[str, ContainerArtifact]:
        for name in values:
            _identifier(name, "container component name")
        return dict(sorted(values.items()))

    @model_validator(mode="after")
    def validate_container_runtime(self) -> ExecutionProfile:
        root_groups = (
            self.allowed_roots.deploy,
            self.allowed_roots.work,
            self.allowed_roots.output,
            self.allowed_roots.cache,
        )
        if any(
            _paths_overlap(first, second)
            for index, group in enumerate(root_groups)
            for other in root_groups[index + 1 :]
            for first in group
            for second in other
        ):
            raise ValueError("execution root roles must not overlap")
        if self.runtime.container_engine == "apptainer":
            if any(
                artifact.local_path is None or artifact.file_sha256 is None
                for artifact in self.containers.values()
            ):
                raise ValueError("Apptainer profiles require a hashed local SIF for every image")
            if any(
                artifact.local_path is not None
                and not any(
                    PurePosixPath(root) in PurePosixPath(artifact.local_path).parents
                    for root in self.allowed_roots.cache
                )
                for artifact in self.containers.values()
            ):
                raise ValueError("Apptainer SIF paths must stay below a cache role root")
        elif any(
            artifact.local_path is not None or artifact.file_sha256 is not None
            for artifact in self.containers.values()
        ):
            raise ValueError("Docker profiles must not declare Apptainer SIF paths")
        return self

    def to_json(self) -> str:
        return _model_json(self)


class CoreArtifactHashes(StrictModel):
    """Core immutable inputs that preflight must attest."""

    dataset_manifest: str
    pipeline_spec: str
    execution_plan: str
    software_lock: str
    execution_profile: str

    @field_validator("*")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("artifact hashes must be lowercase SHA-256")
        return value


def compute_project_hash(hashes: CoreArtifactHashes) -> str:
    """Hash the four generated-project core digests, excluding the execution profile."""

    canonical = json.dumps(
        {
            "dataset_manifest": hashes.dataset_manifest,
            "execution_plan": hashes.execution_plan,
            "pipeline_spec": hashes.pipeline_spec,
            "software_lock": hashes.software_lock,
        },
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def compute_input_set_hash(paths: Sequence[str]) -> str:
    """Hash a sorted unique set of mapped execution paths without disclosing it."""

    normalized = sorted({_absolute_path(path, "preflight input path") for path in paths})
    canonical = json.dumps(
        normalized,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class AuthorizationArtifactHashes(CoreArtifactHashes):
    """Every artifact bound into a real-data authorization."""

    validation_report: str
    test_report: str
    preflight_report: str


class PreflightEvidence(StrictModel):
    """Minimal deterministic preflight evidence consumed by the approval gate."""

    report_version: Literal["1.0"] = "1.0"
    status: Literal["passed", "failed", "blocked", "degraded"]
    checked_at: datetime
    profile_id: str
    source_host: str
    execution_host: str
    artifact_hashes: CoreArtifactHashes

    @field_validator("profile_id", "source_host", "execution_host")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return _identifier(value, "preflight identifier")

    @field_validator("checked_at")
    @classmethod
    def validate_checked_at(cls, value: datetime) -> datetime:
        return _aware_utc(value, "preflight checked_at")

    def to_json(self) -> str:
        return _model_json(self)


class PreflightCheck(StrictModel):
    """One sanitized remote check; it deliberately carries no checked path."""

    name: str
    status: Literal["passed", "failed"]
    code: str | None = None
    message: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _identifier(value, "preflight check name")

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: str | None) -> str | None:
        return None if value is None else _identifier(value, "preflight check code")

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if (
            not value
            or len(value.encode("utf-8")) > 512
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or re.search(r"(?:^|[\s=:])(?:/|~/)", value)
            or "file://" in value.casefold()
        ):
            raise ValueError("preflight messages must be bounded and contain no raw path")
        return value


class PreflightReport(PreflightEvidence):
    """Complete machine-readable preflight report consumed by the approval gate."""

    preflight_id: str
    project_hash: str
    input_count: int = Field(ge=1, le=10_000_000, strict=True)
    input_set_hash: str
    checks: tuple[PreflightCheck, ...] = Field(min_length=1, max_length=256)

    @field_validator("preflight_id")
    @classmethod
    def validate_preflight_id(cls, value: str) -> str:
        return _identifier(value, "preflight identifier")

    @field_validator("project_hash", "input_set_hash")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("preflight digests must be lowercase SHA-256")
        return value

    @model_validator(mode="after")
    def validate_checks(self) -> PreflightReport:
        names = [check.name for check in self.checks]
        if len(names) != len(set(names)):
            raise ValueError("preflight check names must be unique")
        if tuple(names) != tuple(sorted(names)):
            raise ValueError("preflight checks must be sorted by name")
        all_passed = all(check.status == "passed" for check in self.checks)
        if (self.status == "passed") != all_passed:
            raise ValueError("preflight status must reflect its checks")
        return self


class ApprovalArtifactPaths(StrictModel):
    """Local files read and hashed by the approval gate."""

    dataset_manifest: Path
    pipeline_spec: Path
    execution_plan: Path
    software_lock: Path
    validation_report: Path
    test_report: Path
    execution_profile: Path
    preflight_report: Path


# A concise public synonym used by controllers that assemble the same eight inputs.
ApprovalInputs = ApprovalArtifactPaths


class RunPolicy(StrictModel):
    """Explicit real-data overlay; generated M3 artifacts remain unchanged."""

    run_real_data: Literal[True]
    require_approval: Literal[True]
    resume: bool = Field(default=False, strict=True)


class ApprovalRequest(StrictModel):
    """Attributable CLI approval request supplied separately from the project."""

    policy: RunPolicy
    approve_real_data: bool = Field(strict=True)
    actor: str
    approved_at: datetime

    @field_validator("actor")
    @classmethod
    def validate_actor(cls, value: str) -> str:
        if (
            not value
            or len(value) > 256
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise ValueError("approval actor must be bounded attributable text")
        return value

    @field_validator("approved_at")
    @classmethod
    def validate_approved_at(cls, value: datetime) -> datetime:
        return _aware_utc(value, "approval time")


class RunAuthorization(StrictModel):
    """Immutable authorization overlay bound to exact reviewed evidence."""

    authorization_version: Literal["1.0"] = "1.0"
    authorization_id: str
    project_id: str
    profile_id: str
    actor: str
    approved_at: datetime
    cli_approved: Literal[True]
    policy: RunPolicy
    artifact_hashes: AuthorizationArtifactHashes
    bundle_hash: str
    preflight_checked_at: datetime
    compatibility_hash: str

    @field_validator("authorization_id", "project_id", "profile_id")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return _identifier(value, "authorization identifier")

    @field_validator("actor")
    @classmethod
    def validate_actor(cls, value: str) -> str:
        if (
            not value
            or len(value) > 256
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
        ):
            raise ValueError("authorization actor must be bounded attributable text")
        return value

    @field_validator("bundle_hash", "compatibility_hash")
    @classmethod
    def validate_compatibility_hash(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("authorization hashes must be lowercase SHA-256")
        return value

    @field_validator("approved_at", "preflight_checked_at")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        return _aware_utc(value, "authorization timestamp")

    def to_json(self) -> str:
        return _model_json(self)


def _model_json(model: StrictModel) -> str:
    return (
        json.dumps(
            model.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


__all__ = [
    "AllowedExecutionRoots",
    "ApprovalArtifactPaths",
    "ApprovalInputs",
    "ApprovalRequest",
    "ApprovalSigner",
    "AuthorizationArtifactHashes",
    "ContainerArtifact",
    "CoreArtifactHashes",
    "DiskThreshold",
    "ExecutionPathMapping",
    "ExecutionProfile",
    "LocalExecutionRuntime",
    "PreflightCheck",
    "PreflightEvidence",
    "PreflightReport",
    "RunAuthorization",
    "RunPolicy",
    "compute_input_set_hash",
    "compute_project_hash",
]
