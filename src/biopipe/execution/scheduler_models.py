"""Dormant scheduler-aware controller contracts for M7 protocol version 2.

These models intentionally live beside, rather than extend or replace, the
frozen ``ExecutionProfile`` v1 contract.  No CLI, registry, preflight, approval,
or run entry point imports this module yet.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator

from biopipe.execution.models import (
    AllowedExecutionRoots,
    ApprovalSigner,
    ContainerArtifact,
    DiskThreshold,
    ExecutionPathMapping,
)
from biopipe.models import StrictModel

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SCHEDULER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", re.ASCII)
_SAFE_EXECUTABLE_PATH = re.compile(r"^(?:/|~/)[A-Za-z0-9_./~-]+$")
_TIME_LIMIT = re.compile(
    r"^(?:(?P<days>[1-9][0-9]?)-)?"
    r"(?P<hours>[0-2][0-9]):(?P<minutes>[0-5][0-9]):(?P<seconds>[0-5][0-9])$",
    re.ASCII,
)
_MAX_TIME_LIMIT_SECONDS = 30 * 24 * 60 * 60


def _identifier(value: str, label: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} must be a safe identifier")
    return value


def _scheduler_name(value: Any, label: str) -> str | None:
    if value is not None and (not isinstance(value, str) or not _SCHEDULER_NAME.fullmatch(value)):
        raise ValueError(f"{label} must be a bounded scheduler identifier")
    return value


def _paths_overlap(first: str, second: str) -> bool:
    first_path = PurePosixPath(first)
    second_path = PurePosixPath(second)
    return (
        first_path == second_path
        or first_path in second_path.parents
        or second_path in first_path.parents
    )


class SlurmRuntimeV2(StrictModel):
    """Unambiguous first-topology split between launch and workflow execution."""

    launch_backend: Literal["slurm"] = "slurm"
    workflow_engine: Literal["nextflow"] = "nextflow"
    workflow_executor: Literal["local"] = "local"
    container_engine: Literal["apptainer"] = "apptainer"
    topology: Literal["single_allocation_nextflow_local"] = "single_allocation_nextflow_local"

    @field_validator("*", mode="before")
    @classmethod
    def reject_runtime_normalization(cls, value: Any) -> str:
        if not isinstance(value, str) or value.strip() != value:
            raise ValueError("scheduler runtime literals must be exact strings")
        return value


class SlurmSchedulerPolicyV2(StrictModel):
    """Exact hash-bound Slurm policy with no free flags or site defaults."""

    partition: str
    account: str | None
    qos: str | None
    time_limit: str
    cpus_per_task: int = Field(ge=1, le=1_024, strict=True)
    memory_mib: int = Field(ge=1_024, le=16 * 1024 * 1024, strict=True)
    submit_timeout_seconds: int = Field(ge=1, le=300, strict=True)
    status_poll_seconds: int = Field(ge=5, le=3_600, strict=True)
    max_pending_seconds: int = Field(ge=60, le=2_592_000, strict=True)

    @field_validator("partition", "account", "qos", mode="before")
    @classmethod
    def validate_scheduler_name(cls, value: str | None, info: ValidationInfo) -> str | None:
        return _scheduler_name(value, info.field_name or "scheduler field")

    @field_validator("time_limit", mode="before")
    @classmethod
    def validate_time_limit(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("time_limit must be a canonical string")
        match = _TIME_LIMIT.fullmatch(value)
        if match is None:
            raise ValueError("time_limit must use canonical [[DD-]HH:]MM:SS form")
        days = int(match.group("days") or 0)
        hours = int(match.group("hours"))
        total = (
            days * 24 * 60 * 60
            + hours * 60 * 60
            + int(match.group("minutes")) * 60
            + int(match.group("seconds"))
        )
        if hours > 23 or total == 0 or total > _MAX_TIME_LIMIT_SECONDS:
            raise ValueError("time_limit is outside the supported range")
        return value

    @model_validator(mode="after")
    def validate_poll_window(self) -> SlurmSchedulerPolicyV2:
        if self.status_poll_seconds > self.max_pending_seconds:
            raise ValueError("status_poll_seconds must not exceed max_pending_seconds")
        return self

    def as_mapping(self) -> dict[str, str | int | None]:
        """Return the exact cross-distribution policy mapping."""

        return {
            "partition": self.partition,
            "account": self.account,
            "qos": self.qos,
            "time_limit": self.time_limit,
            "cpus_per_task": self.cpus_per_task,
            "memory_mib": self.memory_mib,
            "submit_timeout_seconds": self.submit_timeout_seconds,
            "status_poll_seconds": self.status_poll_seconds,
            "max_pending_seconds": self.max_pending_seconds,
        }


def canonical_scheduler_policy_bytes(policy: SlurmSchedulerPolicyV2) -> bytes:
    """Serialize the exact policy bytes shared with the dependency-free agent."""

    if not isinstance(policy, SlurmSchedulerPolicyV2):
        raise TypeError("policy must be a SlurmSchedulerPolicyV2")
    return json.dumps(
        policy.as_mapping(),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def scheduler_policy_hash(policy: SlurmSchedulerPolicyV2) -> str:
    """Return the hash bound by profile, agent configuration, and protocol v2."""

    return hashlib.sha256(canonical_scheduler_policy_bytes(policy)).hexdigest()


class SlurmExecutionProfileV2(StrictModel):
    """Hashed controller profile for one Slurm allocation and shared filesystem."""

    profile_version: Literal["2.0"] = "2.0"
    profile_id: str
    source_host: str
    execution_host: str
    ssh_alias: str
    username: str | None = None
    port: int = Field(default=22, ge=1, le=65_535, strict=True)
    bioexec_path: str = "~/.local/bin/bioexec.pyz"
    approval_signer: ApprovalSigner
    allowed_roots: AllowedExecutionRoots
    runtime: SlurmRuntimeV2 = Field(default_factory=SlurmRuntimeV2)
    scheduler: SlurmSchedulerPolicyV2
    containers: dict[str, ContainerArtifact] = Field(min_length=1, max_length=64)
    disk_threshold: DiskThreshold = Field(default_factory=DiskThreshold)
    preflight_max_age_seconds: int = Field(default=900, ge=60, le=86_400, strict=True)
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
    def validate_first_topology(self) -> SlurmExecutionProfileV2:
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
        if any(
            artifact.local_path is None or artifact.file_sha256 is None
            for artifact in self.containers.values()
        ):
            raise ValueError("Slurm v2 profiles require a hashed local SIF for every image")
        if any(
            artifact.local_path is not None
            and not any(
                PurePosixPath(root) in PurePosixPath(artifact.local_path).parents
                for root in self.allowed_roots.cache
            )
            for artifact in self.containers.values()
        ):
            raise ValueError("Slurm v2 SIF paths must stay below a shared cache role root")
        return self

    def to_json(self) -> str:
        """Return deterministic bytes-on-disk JSON for profile identity hashing."""

        return (
            json.dumps(
                self.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

    def profile_hash(self) -> str:
        """Return the identity that binds the full runtime and scheduler policy."""

        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()


__all__ = [
    "SlurmExecutionProfileV2",
    "SlurmRuntimeV2",
    "SlurmSchedulerPolicyV2",
    "canonical_scheduler_policy_bytes",
    "scheduler_policy_hash",
]
