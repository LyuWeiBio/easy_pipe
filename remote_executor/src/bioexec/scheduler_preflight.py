"""Dormant compute-node preflight contracts for the M7 Slurm path.

The module is deliberately unreachable from every version-1 entry point.  It
does not read files, run commands, sleep, inspect an environment, generate a
secret, or mutate durable state.  A future reviewed adapter may inject trusted
scheduler observations, clock values, and capability tokens into the pure
state transitions defined here.

The rendered batch script is only a fixed invocation contract for a separately
installed and hash-bound compute worker.  It does not pretend that the checks
ran.  A missing worker binding prevents both rendering and successful evidence
validation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from collections.abc import Mapping
from dataclasses import InitVar, dataclass, replace
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any, Literal, cast

from .slurm import (
    SlurmContractError,
    SlurmHeldJob,
    SlurmJobRef,
    SlurmMappedState,
    SlurmObservation,
    SlurmSchedulerPolicy,
    reconcile_slurm_observations,
    scheduler_policy_hash,
)

MANIFEST_VERSION = "1.1"
EVIDENCE_VERSION = "1.0"
WORKER_CONTRACT_VERSION = "1.0"

COMPUTE_CHECK_NAMES = (
    "allocation_policy",
    "apptainer_runtime",
    "cache_storage",
    "deployment_target",
    "free_space",
    "input_paths",
    "network_isolation",
    "nextflow_runtime",
    "output_storage",
    "path_mapping",
    "sif_artifacts",
    "work_storage",
)

PreflightPhase = Literal[
    "prepared",
    "submit_unknown",
    "held",
    "release_ready",
    "release_unknown",
    "polling",
    "awaiting_evidence",
    "candidate",
    "passed",
    "failed",
    "indeterminate",
    "timed_out",
]
CheckStatus = Literal["passed", "failed"]
EvidenceStatus = Literal["passed", "failed"]

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}", re.ASCII)
_TAGGED_IMAGE = re.compile(
    r"[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+:"
    r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}",
    re.ASCII,
)
_OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_SAFE_WORKER_PATH = re.compile(r"/[A-Za-z0-9_./-]{1,4094}", re.ASCII)

_MANIFEST_FIELDS = frozenset(
    {
        "manifest_version",
        "preflight_id",
        "profile_version",
        "profile_id",
        "profile_hash",
        "scheduler_policy_hash",
        "scheduler_policy",
        "compute_runtime",
        "project_hash",
        "artifact_hashes",
        "source_host",
        "execution_host",
        "host_relation",
        "source_paths",
        "execution_paths",
        "path_mapping",
        "input_set_hash",
        "deploy_dir",
        "work_dir",
        "output_dir",
        "cache_dir",
        "containers",
        "minimum_free_bytes",
        "network_disabled",
        "resume_run_id",
        "resume_directory_identities",
        "preflight_ttl_seconds",
        "worker",
    }
)
_ARTIFACT_FIELDS = frozenset(
    {
        "dataset_manifest",
        "pipeline_spec",
        "execution_plan",
        "software_lock",
        "execution_profile",
    }
)
_MAPPING_FIELDS = frozenset({"source_prefix", "execution_prefix"})
_CONTAINER_FIELDS = frozenset({"name", "image", "digest", "local_path", "file_sha256"})
_WORKER_FIELDS = frozenset(
    {
        "contract_version",
        "executable",
        "executable_sha256",
        "manifest_path",
        "evidence_path",
    }
)
_RUNTIME_FIELDS = frozenset(
    {
        "python_executable",
        "python_sha256",
        "java_executable",
        "java_sha256",
        "nextflow_executable",
        "nextflow_sha256",
        "nextflow_version",
        "nextflow_jar",
        "nextflow_jar_sha256",
        "apptainer_executable",
        "apptainer_sha256",
        "command_timeout_seconds",
        "max_command_output_bytes",
    }
)
_RESUME_DIRECTORY_ROLES = frozenset({"deploy", "work", "output"})
_DIRECTORY_IDENTITY_FIELDS = frozenset({"device", "inode", "owner", "group", "mode"})
_EVIDENCE_FIELDS = frozenset(
    {
        "evidence_version",
        "preflight_id",
        "profile_id",
        "profile_hash",
        "scheduler_policy_hash",
        "project_hash",
        "input_set_hash",
        "manifest_sha256",
        "worker_sha256",
        "job_id",
        "submission_marker",
        "status",
        "checks",
    }
)
_CHECK_FIELDS = frozenset({"name", "status", "code", "evidence_sha256"})

_MAX_PATH_BYTES = 4096
_MAX_ARRAY_ITEMS = 100_000
_MAX_CONTAINERS = 64
_MAX_EVIDENCE_BYTES = 256 * 1024
_MAX_JSON_NESTING = 128
_MAX_TEMPLATE_BYTES = 16 * 1024
_RETRYABLE_POLL_CODES = frozenset(
    {
        "SLURM_OBSERVATION_MISSING",
        "SLURM_TERMINAL_REQUIRES_SACCT",
        "SLURM_EXIT_CODE_UNAVAILABLE",
    }
)
_PREFLIGHT_PHASES = frozenset(
    {
        "prepared",
        "submit_unknown",
        "held",
        "release_ready",
        "release_unknown",
        "polling",
        "awaiting_evidence",
        "candidate",
        "passed",
        "failed",
        "indeterminate",
        "timed_out",
    }
)
_CAPABILITY_AUTHORITY = object()
_STATE_AUTHORITY = object()


class SchedulerPreflightError(ValueError):
    """A compute-preflight contract or transition is invalid."""


@dataclass(frozen=True)
class PathMappingBinding:
    """One exact source-to-compute path mapping."""

    source_prefix: str
    execution_prefix: str

    def __post_init__(self) -> None:
        _absolute_path(self.source_prefix, "source_prefix")
        _absolute_path(self.execution_prefix, "execution_prefix")

    def as_mapping(self) -> dict[str, str]:
        return {
            "source_prefix": self.source_prefix,
            "execution_prefix": self.execution_prefix,
        }


@dataclass(frozen=True)
class ContainerBinding:
    """One exact local SIF identity required on the compute node."""

    name: str
    image: str
    digest: str
    local_path: str
    file_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.name, "container.name")
        _tagged_image(self.image, "container.image")
        if (
            not isinstance(self.digest, str)
            or not _OCI_DIGEST.fullmatch(self.digest)
            or self.digest == f"sha256:{'0' * 64}"
        ):
            raise SchedulerPreflightError("container.digest must be a non-placeholder SHA-256")
        _sif_path(_absolute_path(self.local_path, "container.local_path"))
        _digest(self.file_sha256, "container.file_sha256")

    def as_mapping(self) -> dict[str, str]:
        return {
            "name": self.name,
            "image": self.image,
            "digest": self.digest,
            "local_path": self.local_path,
            "file_sha256": self.file_sha256,
        }


@dataclass(frozen=True)
class ComputeRuntimeBinding:
    """Exact compute-visible runtime identities and bounded command policy."""

    python_executable: str
    python_sha256: str
    java_executable: str
    java_sha256: str
    nextflow_executable: str
    nextflow_sha256: str
    nextflow_version: str
    nextflow_jar: str
    nextflow_jar_sha256: str
    apptainer_executable: str
    apptainer_sha256: str
    command_timeout_seconds: float
    max_command_output_bytes: int

    def __post_init__(self) -> None:
        _fixed_runtime_path(
            self.python_executable,
            "compute_runtime.python_executable",
            "python3",
        )
        _digest(self.python_sha256, "compute_runtime.python_sha256")
        _fixed_runtime_path(self.java_executable, "compute_runtime.java_executable", "java")
        _digest(self.java_sha256, "compute_runtime.java_sha256")
        _fixed_runtime_path(
            self.nextflow_executable,
            "compute_runtime.nextflow_executable",
            "nextflow",
        )
        _digest(self.nextflow_sha256, "compute_runtime.nextflow_sha256")
        _identifier(self.nextflow_version, "compute_runtime.nextflow_version")
        _absolute_path(self.nextflow_jar, "compute_runtime.nextflow_jar")
        _digest(self.nextflow_jar_sha256, "compute_runtime.nextflow_jar_sha256")
        _fixed_runtime_path(
            self.apptainer_executable,
            "compute_runtime.apptainer_executable",
            "apptainer",
        )
        _digest(self.apptainer_sha256, "compute_runtime.apptainer_sha256")
        _bounded_number(
            self.command_timeout_seconds,
            "compute_runtime.command_timeout_seconds",
            1.0,
            3600.0,
        )
        _strict_int(
            self.max_command_output_bytes,
            "compute_runtime.max_command_output_bytes",
            1024,
            16 * 1024 * 1024,
        )

    def as_mapping(self) -> dict[str, Any]:
        return {
            "python_executable": self.python_executable,
            "python_sha256": self.python_sha256,
            "java_executable": self.java_executable,
            "java_sha256": self.java_sha256,
            "nextflow_executable": self.nextflow_executable,
            "nextflow_sha256": self.nextflow_sha256,
            "nextflow_version": self.nextflow_version,
            "nextflow_jar": self.nextflow_jar,
            "nextflow_jar_sha256": self.nextflow_jar_sha256,
            "apptainer_executable": self.apptainer_executable,
            "apptainer_sha256": self.apptainer_sha256,
            "command_timeout_seconds": self.command_timeout_seconds,
            "max_command_output_bytes": self.max_command_output_bytes,
        }


@dataclass(frozen=True)
class ResumeDirectoryIdentity:
    """One exact private directory identity required for a resume attempt."""

    device: int
    inode: int
    owner: int
    group: int
    mode: int

    def __post_init__(self) -> None:
        for label, value in (
            ("device", self.device),
            ("inode", self.inode),
            ("owner", self.owner),
            ("group", self.group),
        ):
            _strict_int(value, f"resume_directory_identity.{label}", 0, 2**63 - 1)
        if self.mode != 0o700:
            raise SchedulerPreflightError("resume directory identity must require mode 0700")

    def as_mapping(self) -> dict[str, int]:
        return {
            "device": self.device,
            "inode": self.inode,
            "owner": self.owner,
            "group": self.group,
            "mode": self.mode,
        }


@dataclass(frozen=True)
class ComputeWorkerBinding:
    """Trusted future worker identity; without it no script can be rendered."""

    contract_version: str
    executable: str
    executable_sha256: str
    manifest_path: str
    evidence_path: str

    def __post_init__(self) -> None:
        if self.contract_version != WORKER_CONTRACT_VERSION:
            raise SchedulerPreflightError("worker contract_version must be exactly 1.0")
        _fixed_worker_path(self.executable, "worker.executable", "bioexec-compute-preflight")
        _digest(self.executable_sha256, "worker.executable_sha256")
        _fixed_worker_path(self.manifest_path, "worker.manifest_path", "manifest.json")
        _fixed_worker_path(self.evidence_path, "worker.evidence_path", "evidence.json")
        if self.manifest_path == self.evidence_path:
            raise SchedulerPreflightError("worker manifest and evidence paths must be distinct")

    def as_mapping(self) -> dict[str, str]:
        return {
            "contract_version": self.contract_version,
            "executable": self.executable,
            "executable_sha256": self.executable_sha256,
            "manifest_path": self.manifest_path,
            "evidence_path": self.evidence_path,
        }


@dataclass(frozen=True)
class ComputePreflightManifest:
    """Exact immutable input to the reviewed compute-preflight worker."""

    preflight_id: str
    profile_id: str
    profile_hash: str
    scheduler_policy_hash: str
    scheduler_policy: SlurmSchedulerPolicy
    compute_runtime: ComputeRuntimeBinding
    project_hash: str
    artifact_hashes: Mapping[str, str]
    source_host: str
    execution_host: str
    host_relation: str
    source_paths: tuple[str, ...]
    execution_paths: tuple[str, ...]
    path_mapping: tuple[PathMappingBinding, ...]
    input_set_hash: str
    deploy_dir: str
    work_dir: str
    output_dir: str
    cache_dir: str
    containers: tuple[ContainerBinding, ...]
    minimum_free_bytes: int
    resume_run_id: str | None
    resume_directory_identities: Mapping[str, ResumeDirectoryIdentity] | None
    preflight_ttl_seconds: int
    worker: ComputeWorkerBinding

    def __post_init__(self) -> None:
        _identifier(self.preflight_id, "preflight_id")
        _identifier(self.profile_id, "profile_id")
        _digest(self.profile_hash, "profile_hash")
        _digest(self.scheduler_policy_hash, "scheduler_policy_hash")
        _digest(self.project_hash, "project_hash")
        _digest(self.input_set_hash, "input_set_hash")
        if not isinstance(self.scheduler_policy, SlurmSchedulerPolicy):
            raise SchedulerPreflightError("scheduler_policy must be validated")
        if not isinstance(self.compute_runtime, ComputeRuntimeBinding):
            raise SchedulerPreflightError("compute_runtime must be validated")
        if not isinstance(self.worker, ComputeWorkerBinding):
            raise SchedulerPreflightError("a trusted compute worker binding is required")
        if self.resume_run_id is None:
            if self.resume_directory_identities is not None:
                raise SchedulerPreflightError("initial preflight cannot carry resume identities")
        elif (
            not isinstance(self.resume_directory_identities, Mapping)
            or set(self.resume_directory_identities) != _RESUME_DIRECTORY_ROLES
            or any(
                not isinstance(identity, ResumeDirectoryIdentity)
                for identity in self.resume_directory_identities.values()
            )
        ):
            raise SchedulerPreflightError(
                "resume preflight requires all exact directory identities"
            )

    def as_mapping(self) -> dict[str, Any]:
        return {
            "manifest_version": MANIFEST_VERSION,
            "preflight_id": self.preflight_id,
            "profile_version": "2.0",
            "profile_id": self.profile_id,
            "profile_hash": self.profile_hash,
            "scheduler_policy_hash": self.scheduler_policy_hash,
            "scheduler_policy": self.scheduler_policy.as_mapping(),
            "compute_runtime": self.compute_runtime.as_mapping(),
            "project_hash": self.project_hash,
            "artifact_hashes": dict(self.artifact_hashes),
            "source_host": self.source_host,
            "execution_host": self.execution_host,
            "host_relation": self.host_relation,
            "source_paths": list(self.source_paths),
            "execution_paths": list(self.execution_paths),
            "path_mapping": [item.as_mapping() for item in self.path_mapping],
            "input_set_hash": self.input_set_hash,
            "deploy_dir": self.deploy_dir,
            "work_dir": self.work_dir,
            "output_dir": self.output_dir,
            "cache_dir": self.cache_dir,
            "containers": [item.as_mapping() for item in self.containers],
            "minimum_free_bytes": self.minimum_free_bytes,
            "network_disabled": True,
            "resume_run_id": self.resume_run_id,
            "resume_directory_identities": (
                None
                if self.resume_directory_identities is None
                else {
                    role: self.resume_directory_identities[role].as_mapping()
                    for role in sorted(self.resume_directory_identities)
                }
            ),
            "preflight_ttl_seconds": self.preflight_ttl_seconds,
            "worker": self.worker.as_mapping(),
        }


@dataclass(frozen=True)
class ComputeCheckEvidence:
    """One hash-bound result from the reviewed compute worker."""

    name: str
    status: CheckStatus
    code: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or self.name not in COMPUTE_CHECK_NAMES:
            raise SchedulerPreflightError("compute check name is not in the fixed contract")
        if not isinstance(self.status, str) or self.status not in {"passed", "failed"}:
            raise SchedulerPreflightError("compute check status is not supported")
        if not isinstance(self.code, str) or not _CODE.fullmatch(self.code):
            raise SchedulerPreflightError("compute check code must be a stable uppercase code")
        if (self.status == "passed") != (self.code == "OK"):
            raise SchedulerPreflightError("only an OK check may be passed")
        _digest(self.evidence_sha256, "check.evidence_sha256")

    def as_mapping(self) -> dict[str, str]:
        return {
            "name": self.name,
            "status": self.status,
            "code": self.code,
            "evidence_sha256": self.evidence_sha256,
        }


@dataclass(frozen=True)
class ComputePreflightEvidence:
    """Raw evidence containing only values observable by the compute worker."""

    preflight_id: str
    profile_id: str
    profile_hash: str
    scheduler_policy_hash: str
    project_hash: str
    input_set_hash: str
    manifest_sha256: str
    worker_sha256: str
    job: SlurmJobRef
    status: EvidenceStatus
    checks: tuple[ComputeCheckEvidence, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.job, SlurmJobRef) or self.job.submitted_at is not None:
            raise SchedulerPreflightError(
                "raw compute evidence may bind only worker-observable job ID and marker"
            )
        for label, value in (
            ("profile_hash", self.profile_hash),
            ("scheduler_policy_hash", self.scheduler_policy_hash),
            ("project_hash", self.project_hash),
            ("input_set_hash", self.input_set_hash),
            ("manifest_sha256", self.manifest_sha256),
            ("worker_sha256", self.worker_sha256),
        ):
            _digest(value, label)
        derived = "passed" if all(check.status == "passed" for check in self.checks) else "failed"
        if not isinstance(self.status, str) or self.status != derived:
            raise SchedulerPreflightError("evidence status must be derived from all fixed checks")

    def as_mapping(self) -> dict[str, Any]:
        return {
            "evidence_version": EVIDENCE_VERSION,
            "preflight_id": self.preflight_id,
            "profile_id": self.profile_id,
            "profile_hash": self.profile_hash,
            "scheduler_policy_hash": self.scheduler_policy_hash,
            "project_hash": self.project_hash,
            "input_set_hash": self.input_set_hash,
            "manifest_sha256": self.manifest_sha256,
            "worker_sha256": self.worker_sha256,
            "job_id": self.job.job_id,
            "submission_marker": self.job.submission_marker,
            "status": self.status,
            "checks": [check.as_mapping() for check in self.checks],
        }


@dataclass(frozen=True)
class PreflightCapability:
    """Durable token-hash-only one-use grant bound to trusted elapsed time."""

    _authority: InitVar[object]
    preflight_id: str
    token_hash: str
    binding_hash: str
    issued_at: int
    expires_at: int
    consumed: bool = False
    consumed_by: str | None = None
    consumer_binding_hash: str | None = None
    consumed_at: int | None = None
    expired: bool = False
    expired_at: int | None = None

    def __post_init__(self, _authority: object) -> None:
        if _authority is not _CAPABILITY_AUTHORITY:
            raise SchedulerPreflightError("capability construction is internal to transitions")
        _identifier(self.preflight_id, "capability.preflight_id")
        _digest(self.token_hash, "capability.token_hash")
        _digest(self.binding_hash, "capability.binding_hash")
        _strict_int(self.issued_at, "capability.issued_at", 0, 2**63 - 1)
        _strict_int(self.expires_at, "capability.expires_at", self.issued_at + 1, 2**63 - 1)
        if not isinstance(self.expired, bool):
            raise SchedulerPreflightError("capability.expired must be a boolean")
        if self.consumed and self.expired:
            raise SchedulerPreflightError("capability cannot be both consumed and expired")
        if self.consumed:
            if (
                self.consumed_by is None
                or self.consumer_binding_hash is None
                or self.consumed_at is None
            ):
                raise SchedulerPreflightError(
                    "consumed capability requires actor, binding, and time"
                )
            _identifier(self.consumed_by, "capability.consumed_by")
            _digest(self.consumer_binding_hash, "capability.consumer_binding_hash")
            _strict_int(
                self.consumed_at,
                "capability.consumed_at",
                self.issued_at,
                self.expires_at - 1,
            )
        elif (
            self.consumed_by is not None
            or self.consumer_binding_hash is not None
            or self.consumed_at is not None
        ):
            raise SchedulerPreflightError("unconsumed capability cannot carry consumption data")
        if self.expired:
            if self.expired_at is None:
                raise SchedulerPreflightError("expired capability requires trusted elapsed time")
            _strict_int(
                self.expired_at,
                "capability.expired_at",
                self.expires_at,
                2**63 - 1,
            )
        elif self.expired_at is not None:
            raise SchedulerPreflightError("live capability cannot carry expiration data")

    def as_record(self) -> dict[str, Any]:
        """Return the owner-only durable shape without the raw capability token."""

        return {
            "preflight_id": self.preflight_id,
            "token_hash": self.token_hash,
            "binding_hash": self.binding_hash,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "consumed": self.consumed,
            "consumed_by": self.consumed_by,
            "consumer_binding_hash": self.consumer_binding_hash,
            "consumed_at": self.consumed_at,
            "expired": self.expired,
            "expired_at": self.expired_at,
        }


@dataclass(frozen=True)
class SchedulerPreflightState:
    """Immutable state advanced only by trusted adapter events."""

    _authority: InitVar[object]
    manifest: ComputePreflightManifest
    manifest_sha256: str
    template_bytes: bytes
    template_sha256: str
    submission_marker: str
    phase: PreflightPhase
    job: SlurmJobRef | None = None
    held_job: SlurmHeldJob | None = None
    terminal_observation: SlurmObservation | None = None
    elapsed_seconds: int = 0
    pending_since_seconds: int | None = None
    started: bool = False
    terminal_seen: bool = False
    reason_code: str = "PREFLIGHT_PREPARED"
    evidence: ComputePreflightEvidence | None = None
    evidence_sha256: str | None = None
    capability: PreflightCapability | None = None

    def __post_init__(self, _authority: object) -> None:
        if _authority is not _STATE_AUTHORITY:
            raise SchedulerPreflightError("state construction is internal to transitions")
        if not isinstance(self.manifest, ComputePreflightManifest):
            raise SchedulerPreflightError("state requires a validated compute manifest")
        _digest(self.manifest_sha256, "state.manifest_sha256")
        _digest(self.template_sha256, "state.template_sha256")
        _digest(self.submission_marker, "state.submission_marker")
        if not isinstance(self.template_bytes, bytes) or not self.template_bytes:
            raise SchedulerPreflightError("state requires generated template bytes")
        if self.phase not in _PREFLIGHT_PHASES:
            raise SchedulerPreflightError("state phase is not in the fixed transition contract")
        if self.job is not None:
            if not isinstance(self.job, SlurmJobRef) or self.job.submitted_at is None:
                raise SchedulerPreflightError("state job must bind an exact scheduler Submit time")
            if self.job.submission_marker != self.submission_marker:
                raise SchedulerPreflightError("state job marker does not bind this preflight")
        if self.held_job is not None and (
            not isinstance(self.held_job, SlurmHeldJob) or self.held_job.job != self.job
        ):
            raise SchedulerPreflightError("state user-hold evidence must bind the exact job")
        if self.terminal_observation is not None and (
            not isinstance(self.terminal_observation, SlurmObservation)
            or self.terminal_observation.job != self.job
        ):
            raise SchedulerPreflightError("terminal scheduler evidence must bind the exact job")
        if self.capability is not None and not isinstance(self.capability, PreflightCapability):
            raise SchedulerPreflightError("state capability must use the fixed capability contract")
        if self.capability is not None and self.phase not in {
            "passed",
            "indeterminate",
            "timed_out",
        }:
            raise SchedulerPreflightError(
                "capability may exist only in a passed or invalidated state"
            )
        if self.phase == "passed" and self.capability is None:
            raise SchedulerPreflightError("passed state requires one durable capability grant")
        _strict_int(self.elapsed_seconds, "state.elapsed_seconds", 0, 2**63 - 1)
        if self.pending_since_seconds is not None:
            _strict_int(
                self.pending_since_seconds,
                "state.pending_since_seconds",
                0,
                self.elapsed_seconds,
            )
        if not isinstance(self.started, bool):
            raise SchedulerPreflightError("state.started must be a boolean")
        if not isinstance(self.terminal_seen, bool):
            raise SchedulerPreflightError("state.terminal_seen must be a boolean")
        if not _CODE.fullmatch(self.reason_code):
            raise SchedulerPreflightError("state reason_code must be stable uppercase text")


def _replace_state(
    state: SchedulerPreflightState,
    **changes: Any,
) -> SchedulerPreflightState:
    return replace(state, _authority=_STATE_AUTHORITY, **changes)


def _replace_capability(
    capability: PreflightCapability,
    **changes: Any,
) -> PreflightCapability:
    return replace(capability, _authority=_CAPABILITY_AUTHORITY, **changes)


def parse_compute_manifest(value: Any) -> ComputePreflightManifest:
    """Parse one exact internal manifest without accepting scheduler mutation data."""

    manifest = _object(value, "compute manifest")
    _exact_fields(manifest, _MANIFEST_FIELDS, "compute manifest")
    if manifest["manifest_version"] != MANIFEST_VERSION:
        raise SchedulerPreflightError(f"manifest_version must be exactly {MANIFEST_VERSION}")
    if manifest["profile_version"] != "2.0":
        raise SchedulerPreflightError("profile_version must be exactly 2.0")

    preflight_id = _identifier(manifest["preflight_id"], "preflight_id")
    profile_id = _identifier(manifest["profile_id"], "profile_id")
    profile_hash = _digest(manifest["profile_hash"], "profile_hash")
    policy_hash = _digest(manifest["scheduler_policy_hash"], "scheduler_policy_hash")
    try:
        policy = SlurmSchedulerPolicy.from_mapping(manifest["scheduler_policy"])
    except SlurmContractError as exc:
        raise SchedulerPreflightError("scheduler_policy violates the fixed Slurm contract") from exc
    if scheduler_policy_hash(policy) != policy_hash:
        raise SchedulerPreflightError("scheduler_policy does not match scheduler_policy_hash")
    runtime_value = _object(manifest["compute_runtime"], "compute_runtime")
    _exact_fields(runtime_value, _RUNTIME_FIELDS, "compute_runtime")
    runtime = ComputeRuntimeBinding(
        python_executable=cast(str, runtime_value["python_executable"]),
        python_sha256=cast(str, runtime_value["python_sha256"]),
        java_executable=cast(str, runtime_value["java_executable"]),
        java_sha256=cast(str, runtime_value["java_sha256"]),
        nextflow_executable=cast(str, runtime_value["nextflow_executable"]),
        nextflow_sha256=cast(str, runtime_value["nextflow_sha256"]),
        nextflow_version=cast(str, runtime_value["nextflow_version"]),
        nextflow_jar=cast(str, runtime_value["nextflow_jar"]),
        nextflow_jar_sha256=cast(str, runtime_value["nextflow_jar_sha256"]),
        apptainer_executable=cast(str, runtime_value["apptainer_executable"]),
        apptainer_sha256=cast(str, runtime_value["apptainer_sha256"]),
        command_timeout_seconds=_bounded_number(
            runtime_value["command_timeout_seconds"],
            "compute_runtime.command_timeout_seconds",
            1.0,
            3600.0,
        ),
        max_command_output_bytes=_strict_int(
            runtime_value["max_command_output_bytes"],
            "compute_runtime.max_command_output_bytes",
            1024,
            16 * 1024 * 1024,
        ),
    )

    project_hash = _digest(manifest["project_hash"], "project_hash")
    hashes_value = _object(manifest["artifact_hashes"], "artifact_hashes")
    _exact_fields(hashes_value, _ARTIFACT_FIELDS, "artifact_hashes")
    artifact_hashes = {
        key: _digest(item, f"artifact_hashes.{key}") for key, item in hashes_value.items()
    }
    if artifact_hashes["execution_profile"] != profile_hash:
        raise SchedulerPreflightError("artifact_hashes do not bind profile_hash")
    if _project_hash(artifact_hashes) != project_hash:
        raise SchedulerPreflightError("artifact_hashes do not bind project_hash")

    source_host = _identifier(manifest["source_host"], "source_host")
    execution_host = _identifier(manifest["execution_host"], "execution_host")
    relation = manifest["host_relation"]
    if not isinstance(relation, str) or relation not in {"same", "shared"}:
        raise SchedulerPreflightError("host_relation must be same or shared")
    if (relation == "same") != (source_host == execution_host):
        raise SchedulerPreflightError("host_relation does not match the host identities")

    source_paths = _path_array(manifest["source_paths"], "source_paths")
    execution_paths = _path_array(manifest["execution_paths"], "execution_paths")
    mapping_values = _array(manifest["path_mapping"], "path_mapping", maximum=128)
    mappings: list[PathMappingBinding] = []
    source_prefixes: set[str] = set()
    for index, item in enumerate(mapping_values):
        mapping_value = _object(item, f"path_mapping[{index}]")
        _exact_fields(mapping_value, _MAPPING_FIELDS, f"path_mapping[{index}]")
        mapping = PathMappingBinding(
            source_prefix=_absolute_path(mapping_value["source_prefix"], "source_prefix"),
            execution_prefix=_absolute_path(mapping_value["execution_prefix"], "execution_prefix"),
        )
        if mapping.source_prefix in source_prefixes:
            raise SchedulerPreflightError("path_mapping source_prefix values must be unique")
        source_prefixes.add(mapping.source_prefix)
        mappings.append(mapping)
    _validate_path_mapping(relation, source_paths, execution_paths, tuple(mappings))

    requested_input_hash = _digest(manifest["input_set_hash"], "input_set_hash")
    if input_set_hash(execution_paths) != requested_input_hash:
        raise SchedulerPreflightError("execution_paths do not match input_set_hash")

    directories = {
        label: _absolute_path(manifest[label], label)
        for label in ("deploy_dir", "work_dir", "output_dir", "cache_dir")
    }
    container_values = _array(
        manifest["containers"],
        "containers",
        minimum=1,
        maximum=_MAX_CONTAINERS,
    )
    containers: list[ContainerBinding] = []
    names: set[str] = set()
    for index, item in enumerate(container_values):
        container_value = _object(item, f"containers[{index}]")
        _exact_fields(container_value, _CONTAINER_FIELDS, f"containers[{index}]")
        container = ContainerBinding(
            name=cast(str, container_value["name"]),
            image=cast(str, container_value["image"]),
            digest=cast(str, container_value["digest"]),
            local_path=cast(str, container_value["local_path"]),
            file_sha256=cast(str, container_value["file_sha256"]),
        )
        if container.name in names:
            raise SchedulerPreflightError("containers must have unique names")
        names.add(container.name)
        containers.append(container)

    minimum_free = _strict_int(
        manifest["minimum_free_bytes"],
        "minimum_free_bytes",
        1,
        2**63 - 1,
    )
    if manifest["network_disabled"] is not True:
        raise SchedulerPreflightError("network_disabled must be true")
    resume_value = manifest["resume_run_id"]
    resume_run_id = None if resume_value is None else _identifier(resume_value, "resume_run_id")
    resume_identities_value = manifest["resume_directory_identities"]
    resume_identities: Mapping[str, ResumeDirectoryIdentity] | None
    if resume_identities_value is None:
        resume_identities = None
    else:
        identities_mapping = _object(
            resume_identities_value,
            "resume_directory_identities",
        )
        _exact_fields(
            identities_mapping,
            _RESUME_DIRECTORY_ROLES,
            "resume_directory_identities",
        )
        parsed_identities: dict[str, ResumeDirectoryIdentity] = {}
        for role in sorted(_RESUME_DIRECTORY_ROLES):
            identity_value = _object(
                identities_mapping[role],
                f"resume_directory_identities.{role}",
            )
            _exact_fields(
                identity_value,
                _DIRECTORY_IDENTITY_FIELDS,
                f"resume_directory_identities.{role}",
            )
            parsed_identities[role] = ResumeDirectoryIdentity(
                device=_strict_int(
                    identity_value["device"],
                    f"resume_directory_identities.{role}.device",
                    0,
                    2**63 - 1,
                ),
                inode=_strict_int(
                    identity_value["inode"],
                    f"resume_directory_identities.{role}.inode",
                    0,
                    2**63 - 1,
                ),
                owner=_strict_int(
                    identity_value["owner"],
                    f"resume_directory_identities.{role}.owner",
                    0,
                    2**63 - 1,
                ),
                group=_strict_int(
                    identity_value["group"],
                    f"resume_directory_identities.{role}.group",
                    0,
                    2**63 - 1,
                ),
                mode=_strict_int(
                    identity_value["mode"],
                    f"resume_directory_identities.{role}.mode",
                    0,
                    0o7777,
                ),
            )
        resume_identities = MappingProxyType(parsed_identities)
    if (resume_run_id is None) != (resume_identities is None):
        raise SchedulerPreflightError(
            "resume_run_id and resume_directory_identities must appear together"
        )
    ttl = _strict_int(
        manifest["preflight_ttl_seconds"],
        "preflight_ttl_seconds",
        1,
        86_400,
    )
    worker_value = _object(manifest["worker"], "worker")
    _exact_fields(worker_value, _WORKER_FIELDS, "worker")
    worker = ComputeWorkerBinding(
        contract_version=cast(str, worker_value["contract_version"]),
        executable=cast(str, worker_value["executable"]),
        executable_sha256=cast(str, worker_value["executable_sha256"]),
        manifest_path=cast(str, worker_value["manifest_path"]),
        evidence_path=cast(str, worker_value["evidence_path"]),
    )
    return ComputePreflightManifest(
        preflight_id=preflight_id,
        profile_id=profile_id,
        profile_hash=profile_hash,
        scheduler_policy_hash=policy_hash,
        scheduler_policy=policy,
        compute_runtime=runtime,
        project_hash=project_hash,
        artifact_hashes=MappingProxyType(dict(sorted(artifact_hashes.items()))),
        source_host=source_host,
        execution_host=execution_host,
        host_relation=relation,
        source_paths=source_paths,
        execution_paths=execution_paths,
        path_mapping=tuple(mappings),
        input_set_hash=requested_input_hash,
        deploy_dir=directories["deploy_dir"],
        work_dir=directories["work_dir"],
        output_dir=directories["output_dir"],
        cache_dir=directories["cache_dir"],
        containers=tuple(containers),
        minimum_free_bytes=minimum_free,
        resume_run_id=resume_run_id,
        resume_directory_identities=resume_identities,
        preflight_ttl_seconds=ttl,
        worker=worker,
    )


def canonical_manifest_bytes(manifest: ComputePreflightManifest) -> bytes:
    """Return the exact ASCII JSON bytes hashed and consumed by future adapters."""

    validated = _validated_manifest(manifest)
    return _canonical_json_bytes(validated.as_mapping())


def manifest_hash(manifest: ComputePreflightManifest) -> str:
    """Hash the exact compute manifest bytes."""

    return hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


def render_compute_template(manifest: ComputePreflightManifest) -> bytes:
    """Render only the fixed future worker invocation, never arbitrary shell."""

    validated = _validated_manifest(manifest)
    worker = validated.worker
    runtime = validated.compute_runtime
    digest = manifest_hash(validated)
    script = (
        "#!/bin/sh\n"
        "set -eu\n"
        "umask 077\n"
        f"exec {runtime.python_executable} -I -S {worker.executable} \\\n"
        f"  --contract-version={WORKER_CONTRACT_VERSION} \\\n"
        f"  --manifest={worker.manifest_path} \\\n"
        f"  --manifest-sha256={digest} \\\n"
        f"  --worker-sha256={worker.executable_sha256} \\\n"
        f"  --evidence={worker.evidence_path}\n"
    ).encode("ascii")
    if len(script) > _MAX_TEMPLATE_BYTES:
        raise SchedulerPreflightError("compute template exceeds its fixed byte budget")
    return script


def template_hash(manifest: ComputePreflightManifest) -> str:
    """Hash the exact generated batch-template bytes."""

    return hashlib.sha256(render_compute_template(manifest)).hexdigest()


def decode_compute_evidence(data: Any) -> ComputePreflightEvidence:
    """Decode one bounded duplicate-free evidence JSON document."""

    if not isinstance(data, bytes) or not 0 < len(data) <= _MAX_EVIDENCE_BYTES:
        raise SchedulerPreflightError("compute evidence must be bounded non-empty bytes")
    try:
        text = data.decode("utf-8")
        _reject_excessive_nesting(text)
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise SchedulerPreflightError(
            "compute evidence must be strict duplicate-free JSON"
        ) from exc
    return parse_compute_evidence(value)


def parse_compute_evidence(value: Any) -> ComputePreflightEvidence:
    """Parse all twelve exact check records and derive pass/fail status."""

    evidence = _object(value, "compute evidence")
    _exact_fields(evidence, _EVIDENCE_FIELDS, "compute evidence")
    if evidence["evidence_version"] != EVIDENCE_VERSION:
        raise SchedulerPreflightError("evidence_version must be exactly 1.0")
    preflight_id = _identifier(evidence["preflight_id"], "preflight_id")
    profile_id = _identifier(evidence["profile_id"], "profile_id")
    digests = {
        label: _digest(evidence[label], label)
        for label in (
            "profile_hash",
            "scheduler_policy_hash",
            "project_hash",
            "input_set_hash",
            "manifest_sha256",
            "worker_sha256",
        )
    }
    try:
        job = SlurmJobRef(
            job_id=cast(str, evidence["job_id"]),
            submission_marker=cast(str, evidence["submission_marker"]),
            submitted_at=None,
        )
    except SlurmContractError as exc:
        raise SchedulerPreflightError("compute evidence has an invalid Slurm job binding") from exc
    check_values = _array(
        evidence["checks"],
        "checks",
        minimum=len(COMPUTE_CHECK_NAMES),
        maximum=len(COMPUTE_CHECK_NAMES),
    )
    checks: list[ComputeCheckEvidence] = []
    for index, item in enumerate(check_values):
        check_value = _object(item, f"checks[{index}]")
        _exact_fields(check_value, _CHECK_FIELDS, f"checks[{index}]")
        check = ComputeCheckEvidence(
            name=cast(str, check_value["name"]),
            status=cast(CheckStatus, check_value["status"]),
            code=cast(str, check_value["code"]),
            evidence_sha256=cast(str, check_value["evidence_sha256"]),
        )
        checks.append(check)
    if tuple(check.name for check in checks) != COMPUTE_CHECK_NAMES:
        raise SchedulerPreflightError("checks must contain the twelve fixed names in order")
    status_value = evidence["status"]
    if not isinstance(status_value, str) or status_value not in {"passed", "failed"}:
        raise SchedulerPreflightError("compute evidence status is not supported")
    return ComputePreflightEvidence(
        preflight_id=preflight_id,
        profile_id=profile_id,
        profile_hash=digests["profile_hash"],
        scheduler_policy_hash=digests["scheduler_policy_hash"],
        project_hash=digests["project_hash"],
        input_set_hash=digests["input_set_hash"],
        manifest_sha256=digests["manifest_sha256"],
        worker_sha256=digests["worker_sha256"],
        job=job,
        status=cast(EvidenceStatus, status_value),
        checks=tuple(checks),
    )


def canonical_evidence_bytes(evidence: ComputePreflightEvidence) -> bytes:
    """Return canonical bytes for one already validated evidence record."""

    if not isinstance(evidence, ComputePreflightEvidence):
        raise SchedulerPreflightError("evidence must be validated")
    validated = parse_compute_evidence(evidence.as_mapping())
    return _canonical_json_bytes(validated.as_mapping())


def evidence_hash(evidence: ComputePreflightEvidence) -> str:
    """Hash the complete scheduler- and worker-bound evidence record."""

    return hashlib.sha256(canonical_evidence_bytes(evidence)).hexdigest()


def prepare_preflight(manifest: ComputePreflightManifest) -> SchedulerPreflightState:
    """Generate the exact template and its domain-separated retry marker."""

    validated = _validated_manifest(manifest)
    template = render_compute_template(validated)
    manifest_sha256 = manifest_hash(validated)
    template_sha256 = hashlib.sha256(template).hexdigest()
    marker = _submission_marker(manifest_sha256, template_sha256)
    return SchedulerPreflightState(
        _authority=_STATE_AUTHORITY,
        manifest=validated,
        manifest_sha256=manifest_sha256,
        template_bytes=template,
        template_sha256=template_sha256,
        submission_marker=marker,
        phase="prepared",
    )


def record_submit_unknown(state: SchedulerPreflightState) -> SchedulerPreflightState:
    """Block an ambiguous submit result without authorizing a second submit."""

    _require_phase(state, {"prepared"})
    return _replace_state(
        state,
        phase="submit_unknown",
        reason_code="SLURM_PREFLIGHT_SUBMIT_UNKNOWN",
    )


def record_held_submission(
    state: SchedulerPreflightState,
    held_job: SlurmHeldJob,
) -> SchedulerPreflightState:
    """Bind exact scheduler evidence that the submitted job is still user-held."""

    _require_phase(state, {"prepared", "submit_unknown"})
    if not isinstance(held_job, SlurmHeldJob):
        raise SchedulerPreflightError("held submission requires validated user-hold evidence")
    if held_job.job.submission_marker != state.submission_marker:
        raise SchedulerPreflightError("held submission marker does not bind this preflight")
    return _replace_state(
        state,
        phase="held",
        job=held_job.job,
        held_job=held_job,
        reason_code="SLURM_HELD_JOB_BOUND",
    )


def record_release_intent(
    state: SchedulerPreflightState,
    *,
    elapsed_seconds: int,
) -> SchedulerPreflightState:
    """Durably authorize one exact release only while the attempt is fresh."""

    _require_phase(state, {"held"})
    if state.job is None or state.held_job is None:
        raise SchedulerPreflightError("release intent requires exact user-hold evidence")
    elapsed = _fresh_elapsed(state, elapsed_seconds, "release intent")
    if elapsed >= _overall_timeout_seconds(state.manifest.scheduler_policy):
        return _replace_state(
            state,
            phase="timed_out",
            elapsed_seconds=elapsed,
            reason_code="SLURM_PREFLIGHT_OVERALL_TIMEOUT",
        )
    return _replace_state(
        state,
        phase="release_ready",
        elapsed_seconds=elapsed,
        pending_since_seconds=elapsed,
        reason_code="SLURM_HELD_JOB_RELEASE_INTENT",
    )


def record_held_release(state: SchedulerPreflightState) -> SchedulerPreflightState:
    """Record success for the one exact durably authorized release."""

    _require_phase(state, {"release_ready"})
    if state.job is None or state.held_job is None:
        raise SchedulerPreflightError("held release requires exact user-hold evidence")
    return _replace_state(state, phase="polling", reason_code="SLURM_HELD_JOB_RELEASED")


def record_release_unknown(state: SchedulerPreflightState) -> SchedulerPreflightState:
    """Block an ambiguous release result for the exact held job."""

    _require_phase(state, {"release_ready"})
    if state.job is None or state.held_job is None:
        raise SchedulerPreflightError("ambiguous release requires exact user-hold evidence")
    return _replace_state(
        state,
        phase="release_unknown",
        reason_code="SLURM_PREFLIGHT_RELEASE_UNKNOWN",
    )


def record_clock_discontinuity(state: SchedulerPreflightState) -> SchedulerPreflightState:
    """Fail closed when durable elapsed time cannot cross a boot boundary safely."""

    _require_phase(
        state,
        {
            "submit_unknown",
            "held",
            "release_unknown",
            "polling",
            "awaiting_evidence",
            "candidate",
            "passed",
        },
    )
    return _replace_state(
        state,
        phase="indeterminate",
        reason_code="SCHEDULER_CLOCK_DISCONTINUITY",
    )


def record_revision_budget_exhausted(
    state: SchedulerPreflightState,
) -> SchedulerPreflightState:
    """Fail closed while one final journal slot is still available."""

    _require_phase(state, {"release_unknown", "polling", "awaiting_evidence", "candidate"})
    return _replace_state(
        state,
        phase="indeterminate",
        reason_code="SCHEDULER_REVISION_BUDGET_EXHAUSTED",
    )


def record_driver_timeout(
    state: SchedulerPreflightState,
    *,
    elapsed_seconds: int,
) -> SchedulerPreflightState:
    """Apply irreversible driver deadlines without inventing scheduler evidence."""

    _require_phase(
        state,
        {
            "submit_unknown",
            "held",
            "release_unknown",
            "polling",
            "awaiting_evidence",
            "candidate",
            "passed",
        },
    )
    elapsed = _fresh_elapsed(state, elapsed_seconds, "driver timeout")
    if state.phase == "passed" and (
        state.capability is None or state.capability.consumed or state.capability.expired
    ):
        raise SchedulerPreflightError(
            "driver timeout may invalidate only a live unconsumed capability"
        )
    if elapsed >= _overall_timeout_seconds(state.manifest.scheduler_policy):
        return _replace_state(
            state,
            phase="timed_out",
            elapsed_seconds=elapsed,
            reason_code="SLURM_PREFLIGHT_OVERALL_TIMEOUT",
        )
    if state.phase in {"release_unknown", "polling"} and not state.started:
        if state.pending_since_seconds is None:
            raise SchedulerPreflightError(
                "driver pending timeout requires the durable release-intent time"
            )
        if (
            elapsed - state.pending_since_seconds
            >= state.manifest.scheduler_policy.max_pending_seconds
        ):
            return _replace_state(
                state,
                phase="timed_out",
                elapsed_seconds=elapsed,
                reason_code="SLURM_PREFLIGHT_TIMEOUT",
            )
    return state


def preflight_overall_timeout_seconds(state: SchedulerPreflightState) -> int:
    """Return the fixed overall bound for one validated preflight state."""

    if not isinstance(state, SchedulerPreflightState):
        raise SchedulerPreflightError("state must be a SchedulerPreflightState")
    return _overall_timeout_seconds(state.manifest.scheduler_policy)


def record_scheduler_poll(
    state: SchedulerPreflightState,
    *,
    queue: SlurmObservation | None,
    accounting: SlurmObservation | None,
    elapsed_seconds: int,
) -> SchedulerPreflightState:
    """Advance one bounded poll without sleeping or querying a scheduler."""

    _require_phase(state, {"polling", "release_unknown"})
    elapsed = _strict_int(elapsed_seconds, "elapsed_seconds", 0, 2**63 - 1)
    if elapsed < state.elapsed_seconds:
        raise SchedulerPreflightError("poll elapsed_seconds must be monotonic")
    if state.job is None or state.held_job is None or state.pending_since_seconds is None:
        raise SchedulerPreflightError("scheduler poll requires a user-held bound job")
    for observation in (queue, accounting):
        if observation is not None and observation.job != state.job:
            raise SchedulerPreflightError("scheduler observation belongs to another job attempt")
    if elapsed >= _overall_timeout_seconds(state.manifest.scheduler_policy):
        return _replace_state(
            state,
            phase="timed_out",
            elapsed_seconds=elapsed,
            reason_code="SLURM_PREFLIGHT_OVERALL_TIMEOUT",
        )
    try:
        mapped = reconcile_slurm_observations(queue, accounting)
    except SlurmContractError as exc:
        raise SchedulerPreflightError("scheduler poll evidence is invalid") from exc
    terminal_like = mapped.state in {"succeeded", "failed"} or mapped.code in {
        "SLURM_TERMINAL_REQUIRES_SACCT",
        "SLURM_EXIT_CODE_UNAVAILABLE",
        "SLURM_SUCCESS_EXIT_CONFLICT",
        "SLURM_FAILURE_EXIT_CONFLICT",
    }
    current_terminal = (accounting or queue) if terminal_like else None
    if (
        state.terminal_observation is not None
        and current_terminal is not None
        and state.terminal_observation.state != current_terminal.state
    ):
        return _replace_state(
            state,
            phase="indeterminate",
            elapsed_seconds=elapsed,
            started=True,
            terminal_seen=True,
            reason_code="SLURM_OBSERVATION_CONFLICT",
        )

    if mapped.state == "succeeded":
        if (
            accounting is None
            or accounting.source != "sacct"
            or accounting.state != "COMPLETED"
            or accounting.exit_code != (0, 0)
        ):
            raise SchedulerPreflightError("only sacct COMPLETED 0:0 may succeed")
        return _replace_state(
            state,
            phase="awaiting_evidence",
            elapsed_seconds=elapsed,
            started=True,
            terminal_seen=True,
            reason_code="SLURM_COMPLETED",
            terminal_observation=accounting,
        )
    if mapped.state == "failed":
        return _replace_state(
            state,
            phase="failed",
            elapsed_seconds=elapsed,
            started=True,
            terminal_seen=True,
            terminal_observation=current_terminal,
            reason_code=mapped.code,
        )
    if mapped.state == "indeterminate" and mapped.code not in _RETRYABLE_POLL_CODES:
        return _terminal_state(
            state,
            "indeterminate",
            elapsed,
            mapped,
            started=state.started or queue is not None or accounting is not None,
            terminal_observation=current_terminal,
        )
    if state.terminal_seen and mapped.state in {"queued", "active"}:
        return _replace_state(
            state,
            phase="indeterminate",
            elapsed_seconds=elapsed,
            started=True,
            reason_code="SLURM_TERMINAL_STATE_REGRESSION",
        )
    release_still_unknown = state.phase == "release_unknown" and (
        mapped.state == "queued" or mapped.code == "SLURM_OBSERVATION_MISSING"
    )
    if mapped.state == "queued" and state.started:
        return _replace_state(
            state,
            phase="indeterminate",
            elapsed_seconds=elapsed,
            reason_code="SLURM_ACTIVE_STATE_REGRESSION",
        )
    observed_started = (
        state.started
        or mapped.state == "active"
        or mapped.code
        in {
            "SLURM_TERMINAL_REQUIRES_SACCT",
            "SLURM_EXIT_CODE_UNAVAILABLE",
        }
    )
    observed_terminal = state.terminal_seen or terminal_like
    pending_or_unseen = mapped.state == "queued" or (
        mapped.code == "SLURM_OBSERVATION_MISSING" and not observed_started
    )
    pending_elapsed = elapsed - state.pending_since_seconds
    if pending_or_unseen and pending_elapsed >= state.manifest.scheduler_policy.max_pending_seconds:
        return _replace_state(
            state,
            phase="timed_out",
            elapsed_seconds=elapsed,
            started=observed_started,
            reason_code="SLURM_PREFLIGHT_TIMEOUT",
        )
    return _replace_state(
        state,
        phase="release_unknown" if release_still_unknown else "polling",
        elapsed_seconds=elapsed,
        started=observed_started,
        terminal_seen=observed_terminal,
        terminal_observation=current_terminal or state.terminal_observation,
        reason_code=mapped.code,
    )


def record_compute_evidence(
    state: SchedulerPreflightState,
    value: ComputePreflightEvidence | Mapping[str, Any] | bytes,
    *,
    elapsed_seconds: int,
) -> SchedulerPreflightState:
    """Bind complete worker evidence after scheduler-confirmed success."""

    _require_phase(state, {"awaiting_evidence"})
    elapsed = _fresh_elapsed(state, elapsed_seconds, "compute evidence")
    if elapsed >= _overall_timeout_seconds(state.manifest.scheduler_policy):
        return _replace_state(
            state,
            phase="timed_out",
            elapsed_seconds=elapsed,
            reason_code="SLURM_PREFLIGHT_OVERALL_TIMEOUT",
        )
    evidence = validate_compute_evidence_binding(state, value)
    digest = evidence_hash(evidence)
    if evidence.status == "failed":
        failed = next(check for check in evidence.checks if check.status == "failed")
        return _replace_state(
            state,
            phase="failed",
            reason_code=failed.code,
            evidence=evidence,
            evidence_sha256=digest,
            elapsed_seconds=elapsed,
        )
    return _replace_state(
        state,
        phase="candidate",
        reason_code="COMPUTE_PREFLIGHT_CANDIDATE",
        evidence=evidence,
        evidence_sha256=digest,
        elapsed_seconds=elapsed,
    )


def validate_compute_evidence_binding(
    state: SchedulerPreflightState,
    value: ComputePreflightEvidence | Mapping[str, Any] | bytes,
) -> ComputePreflightEvidence:
    """Parse and bind worker evidence to one scheduler-confirmed attempt."""

    _require_phase(state, {"awaiting_evidence"})
    if isinstance(value, bytes):
        evidence = decode_compute_evidence(value)
    elif isinstance(value, ComputePreflightEvidence):
        evidence = parse_compute_evidence(value.as_mapping())
    else:
        evidence = parse_compute_evidence(dict(value))
    _bind_evidence(state, evidence)
    return evidence


def issue_capability(
    state: SchedulerPreflightState,
    *,
    token_hash: str,
    elapsed_seconds: int,
) -> SchedulerPreflightState:
    """Record one token hash only for a scheduler- and evidence-passed candidate."""

    _require_phase(state, {"candidate"})
    elapsed = _fresh_elapsed(state, elapsed_seconds, "capability issuance")
    if elapsed >= _overall_timeout_seconds(state.manifest.scheduler_policy):
        return _replace_state(
            state,
            phase="timed_out",
            elapsed_seconds=elapsed,
            reason_code="SLURM_PREFLIGHT_OVERALL_TIMEOUT",
        )
    digest = _digest(token_hash, "token_hash")
    issued = elapsed
    expires = issued + state.manifest.preflight_ttl_seconds
    if expires > 2**63 - 1:
        raise SchedulerPreflightError("capability expiry is outside the supported range")
    if state.job is None or state.evidence is None or state.evidence_sha256 is None:
        raise SchedulerPreflightError("capability candidate lacks complete evidence")
    _validate_capability_candidate(state)
    issued_state = _replace_state(state, elapsed_seconds=elapsed)
    success_binding = _capability_binding_hash(issued_state)
    binding = _capability_grant_hash(
        success_binding=success_binding,
        token_hash=digest,
        issued_at=issued,
        expires_at=expires,
        consumed=False,
        consumed_by=None,
        consumer_binding_hash=None,
        consumed_at=None,
        expired=False,
        expired_at=None,
    )
    capability = PreflightCapability(
        _authority=_CAPABILITY_AUTHORITY,
        preflight_id=state.manifest.preflight_id,
        token_hash=digest,
        binding_hash=binding,
        issued_at=issued,
        expires_at=expires,
    )
    return _replace_state(
        issued_state,
        phase="passed",
        reason_code="COMPUTE_PREFLIGHT_PASSED",
        capability=capability,
    )


def consume_capability(
    state: SchedulerPreflightState,
    *,
    token: str,
    consumed_by: str,
    consumer_binding_hash: str,
    elapsed_seconds: int,
) -> SchedulerPreflightState:
    """Verify a raw token transiently and apply the one-use transition."""

    _require_phase(state, {"passed"})
    _validate_passed_state(state)
    capability = state.capability
    if capability is None:
        raise SchedulerPreflightError("passed state has no capability")
    if capability.consumed:
        raise SchedulerPreflightError("preflight capability was already consumed")
    if capability.expired:
        raise SchedulerPreflightError("preflight capability has expired")
    supplied = _token(token)
    supplied_hash = hashlib.sha256(supplied.encode("ascii")).hexdigest()
    if not hmac.compare_digest(capability.token_hash, supplied_hash):
        raise SchedulerPreflightError("preflight capability token is invalid")
    at = _fresh_elapsed(state, elapsed_seconds, "capability consumption")
    if at >= capability.expires_at:
        raise SchedulerPreflightError("preflight capability has expired")
    return record_capability_consumed(
        state,
        token_hash=capability.token_hash,
        capability_binding_hash=capability.binding_hash,
        consumed_by=consumed_by,
        consumer_binding_hash=consumer_binding_hash,
        elapsed_seconds=at,
    )


def record_capability_consumed(
    state: SchedulerPreflightState,
    *,
    token_hash: str,
    capability_binding_hash: str,
    consumed_by: str,
    consumer_binding_hash: str,
    elapsed_seconds: int,
) -> SchedulerPreflightState:
    """Replay one trusted, hash-bound capability-consumption event."""

    _require_phase(state, {"passed"})
    _validate_passed_state(state)
    capability = state.capability
    if capability is None:
        raise SchedulerPreflightError("passed state has no capability")
    if capability.consumed:
        raise SchedulerPreflightError("preflight capability was already consumed")
    if capability.expired:
        raise SchedulerPreflightError("preflight capability has expired")
    if (
        _digest(token_hash, "token_hash") != capability.token_hash
        or _digest(capability_binding_hash, "capability_binding_hash") != capability.binding_hash
    ):
        raise SchedulerPreflightError("capability consumption does not bind the current grant")
    actor = _identifier(consumed_by, "consumed_by")
    consumer_binding = _digest(consumer_binding_hash, "consumer_binding_hash")
    at = _fresh_elapsed(state, elapsed_seconds, "capability consumption")
    if at >= capability.expires_at:
        raise SchedulerPreflightError("preflight capability has expired")
    consumed_binding = _capability_grant_hash(
        success_binding=_capability_binding_hash(state),
        token_hash=capability.token_hash,
        issued_at=capability.issued_at,
        expires_at=capability.expires_at,
        consumed=True,
        consumed_by=actor,
        consumer_binding_hash=consumer_binding,
        consumed_at=at,
        expired=False,
        expired_at=None,
    )
    consumed = _replace_capability(
        capability,
        binding_hash=consumed_binding,
        consumed=True,
        consumed_by=actor,
        consumer_binding_hash=consumer_binding,
        consumed_at=at,
    )
    return _replace_state(
        state,
        reason_code="COMPUTE_PREFLIGHT_CAPABILITY_CONSUMED",
        capability=consumed,
    )


def record_capability_expired(
    state: SchedulerPreflightState,
    *,
    token_hash: str,
    capability_binding_hash: str,
    elapsed_seconds: int,
) -> SchedulerPreflightState:
    """Replay one irreversible trusted capability-expiration event."""

    _require_phase(state, {"passed"})
    _validate_passed_state(state)
    capability = state.capability
    if capability is None:
        raise SchedulerPreflightError("passed state has no capability")
    if capability.consumed:
        raise SchedulerPreflightError("consumed capability cannot expire")
    if capability.expired:
        raise SchedulerPreflightError("preflight capability was already expired")
    if (
        _digest(token_hash, "token_hash") != capability.token_hash
        or _digest(capability_binding_hash, "capability_binding_hash") != capability.binding_hash
    ):
        raise SchedulerPreflightError("capability expiration does not bind the current grant")
    at = _fresh_elapsed(state, elapsed_seconds, "capability expiration")
    if at < capability.expires_at:
        raise SchedulerPreflightError("preflight capability has not expired")
    expired_binding = _capability_grant_hash(
        success_binding=_capability_binding_hash(state),
        token_hash=capability.token_hash,
        issued_at=capability.issued_at,
        expires_at=capability.expires_at,
        consumed=False,
        consumed_by=None,
        consumer_binding_hash=None,
        consumed_at=None,
        expired=True,
        expired_at=at,
    )
    expired = _replace_capability(
        capability,
        binding_hash=expired_binding,
        expired=True,
        expired_at=at,
    )
    return _replace_state(
        state,
        phase="timed_out",
        reason_code="COMPUTE_PREFLIGHT_CAPABILITY_EXPIRED",
        capability=expired,
    )


def preflight_result(state: SchedulerPreflightState) -> dict[str, Any]:
    """Return a sanitized durable result that never contains a raw capability token."""

    if not isinstance(state, SchedulerPreflightState):
        raise SchedulerPreflightError("state must be a SchedulerPreflightState")
    if state.phase == "passed":
        _validate_passed_state(state)
    return {
        "preflight_id": state.manifest.preflight_id,
        "status": state.phase,
        "code": state.reason_code,
        "preflight_token": None,
        "manifest_sha256": state.manifest_sha256,
        "template_sha256": state.template_sha256,
        "evidence_sha256": state.evidence_sha256,
    }


def input_set_hash(paths: tuple[str, ...]) -> str:
    """Return the canonical identity of exact compute-visible input paths."""

    if not isinstance(paths, tuple) or not paths:
        raise SchedulerPreflightError("input paths must be one validated non-empty tuple")
    validated = tuple(_absolute_path(path, "execution_path") for path in paths)
    if len(validated) != len(set(validated)):
        raise SchedulerPreflightError("input paths must not contain duplicates")
    return hashlib.sha256(_canonical_json_bytes(sorted(validated))).hexdigest()


def _validated_manifest(manifest: ComputePreflightManifest) -> ComputePreflightManifest:
    if not isinstance(manifest, ComputePreflightManifest):
        raise SchedulerPreflightError("manifest must be a ComputePreflightManifest")
    return parse_compute_manifest(manifest.as_mapping())


def _bind_evidence(
    state: SchedulerPreflightState,
    evidence: ComputePreflightEvidence,
) -> None:
    manifest = state.manifest
    expected = {
        "preflight_id": manifest.preflight_id,
        "profile_id": manifest.profile_id,
        "profile_hash": manifest.profile_hash,
        "scheduler_policy_hash": manifest.scheduler_policy_hash,
        "project_hash": manifest.project_hash,
        "input_set_hash": manifest.input_set_hash,
        "manifest_sha256": state.manifest_sha256,
        "worker_sha256": manifest.worker.executable_sha256,
    }
    observed = {
        "preflight_id": evidence.preflight_id,
        "profile_id": evidence.profile_id,
        "profile_hash": evidence.profile_hash,
        "scheduler_policy_hash": evidence.scheduler_policy_hash,
        "project_hash": evidence.project_hash,
        "input_set_hash": evidence.input_set_hash,
        "manifest_sha256": evidence.manifest_sha256,
        "worker_sha256": evidence.worker_sha256,
    }
    job_matches = (
        state.job is not None
        and evidence.job.job_id == state.job.job_id
        and evidence.job.submission_marker == state.job.submission_marker
    )
    if observed != expected or not job_matches:
        raise SchedulerPreflightError("compute evidence does not bind the exact preflight attempt")


def _capability_binding_hash(state: SchedulerPreflightState) -> str:
    assert state.job is not None and state.job.submitted_at is not None
    assert state.held_job is not None
    assert state.terminal_observation is not None
    assert state.evidence_sha256 is not None
    payload = {
        "preflight_id": state.manifest.preflight_id,
        "profile_hash": state.manifest.profile_hash,
        "scheduler_policy_hash": state.manifest.scheduler_policy_hash,
        "project_hash": state.manifest.project_hash,
        "input_set_hash": state.manifest.input_set_hash,
        "manifest_sha256": state.manifest_sha256,
        "template_sha256": state.template_sha256,
        "evidence_sha256": state.evidence_sha256,
        "job_id": state.job.job_id,
        "submission_marker": state.job.submission_marker,
        "submitted_at": state.job.submitted_at,
        "held_state": state.held_job.state,
        "held_reason": state.held_job.reason,
        "terminal_source": state.terminal_observation.source,
        "terminal_state": state.terminal_observation.state,
        "terminal_exit_code": list(state.terminal_observation.exit_code or ()),
        "elapsed_seconds": state.elapsed_seconds,
        "pending_since_seconds": state.pending_since_seconds,
    }
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def _validate_capability_candidate(state: SchedulerPreflightState) -> None:
    """Recheck every success invariant before a token can enter state."""

    if state.capability is not None:
        raise SchedulerPreflightError("capability candidate already contains a capability")
    _validate_success_bindings(state)


def _validate_passed_state(state: SchedulerPreflightState) -> None:
    """Reject a reconstructed or corrupted token-hash-only passed state."""

    _validate_success_bindings(state)
    capability = state.capability
    if capability is None:
        raise SchedulerPreflightError("passed state has no capability")
    expected_binding = _capability_grant_hash(
        success_binding=_capability_binding_hash(state),
        token_hash=capability.token_hash,
        issued_at=capability.issued_at,
        expires_at=capability.expires_at,
        consumed=capability.consumed,
        consumed_by=capability.consumed_by,
        consumer_binding_hash=capability.consumer_binding_hash,
        consumed_at=capability.consumed_at,
        expired=capability.expired,
        expired_at=capability.expired_at,
    )
    if (
        capability.preflight_id != state.manifest.preflight_id
        or capability.binding_hash != expected_binding
        or capability.expires_at != capability.issued_at + state.manifest.preflight_ttl_seconds
    ):
        raise SchedulerPreflightError("passed capability does not bind the exact preflight state")


def _validate_success_bindings(state: SchedulerPreflightState) -> None:
    """Validate held, terminal, compute, manifest, and template success evidence."""

    if not state.started or not state.terminal_seen:
        raise SchedulerPreflightError("success state lacks terminal scheduler provenance")
    if state.job is None or state.evidence is None or state.evidence_sha256 is None:
        raise SchedulerPreflightError("success state lacks complete evidence")
    if state.held_job is None or state.held_job.job != state.job:
        raise SchedulerPreflightError("capability candidate lacks exact user-hold evidence")
    terminal = state.terminal_observation
    if (
        terminal is None
        or terminal.source != "sacct"
        or terminal.job != state.job
        or terminal.state != "COMPLETED"
        or terminal.exit_code != (0, 0)
    ):
        raise SchedulerPreflightError("capability candidate lacks sacct COMPLETED 0:0 evidence")
    validated_evidence = parse_compute_evidence(state.evidence.as_mapping())
    _bind_evidence(state, validated_evidence)
    if validated_evidence.status != "passed":
        raise SchedulerPreflightError("capability candidate has failed compute evidence")
    if evidence_hash(validated_evidence) != state.evidence_sha256:
        raise SchedulerPreflightError("capability candidate evidence hash does not match")
    expected_manifest_hash = manifest_hash(state.manifest)
    expected_template = render_compute_template(state.manifest)
    expected_template_hash = hashlib.sha256(expected_template).hexdigest()
    if (
        state.manifest_sha256 != expected_manifest_hash
        or state.template_bytes != expected_template
        or state.template_sha256 != expected_template_hash
        or state.submission_marker
        != _submission_marker(expected_manifest_hash, expected_template_hash)
    ):
        raise SchedulerPreflightError("capability candidate manifest or template binding changed")


def _capability_grant_hash(
    *,
    success_binding: str,
    token_hash: str,
    issued_at: int,
    expires_at: int,
    consumed: bool,
    consumed_by: str | None,
    consumer_binding_hash: str | None,
    consumed_at: int | None,
    expired: bool,
    expired_at: int | None,
) -> str:
    """Bind one exact token hash and issuance window to passed evidence."""

    issued = _strict_int(issued_at, "issued_at", 0, 2**63 - 1)
    expires = _strict_int(expires_at, "expires_at", issued + 1, 2**63 - 1)
    if not isinstance(consumed, bool):
        raise SchedulerPreflightError("capability consumed flag must be a boolean")
    if not isinstance(expired, bool) or (consumed and expired):
        raise SchedulerPreflightError("capability terminal flags are invalid")
    if consumed:
        if consumed_by is None or consumer_binding_hash is None or consumed_at is None:
            raise SchedulerPreflightError(
                "consumed grant binding requires actor, binding, and time"
            )
        actor = _identifier(consumed_by, "consumed_by")
        consumer_binding = _digest(consumer_binding_hash, "consumer_binding_hash")
        at: int | None = _strict_int(consumed_at, "consumed_at", issued, expires - 1)
    else:
        if consumed_by is not None or consumer_binding_hash is not None or consumed_at is not None:
            raise SchedulerPreflightError("unconsumed grant binding cannot carry actor or time")
        actor = None
        consumer_binding = None
        at = None
    if expired:
        if expired_at is None:
            raise SchedulerPreflightError("expired grant binding requires trusted elapsed time")
        expiration: int | None = _strict_int(
            expired_at,
            "expired_at",
            expires,
            2**63 - 1,
        )
    else:
        if expired_at is not None:
            raise SchedulerPreflightError("live grant binding cannot carry expiration data")
        expiration = None
    payload = {
        "success_binding": _digest(success_binding, "success_binding"),
        "token_hash": _digest(token_hash, "token_hash"),
        "issued_at": issued,
        "expires_at": expires,
        "consumed": consumed,
        "consumed_by": actor,
        "consumer_binding_hash": consumer_binding,
        "consumed_at": at,
        "expired": expired,
        "expired_at": expiration,
    }
    return hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()


def _submission_marker(manifest_sha256: str, template_sha256: str) -> str:
    """Derive a stable positive-discovery marker without accepting caller input."""

    material = (
        b"easy-pipe:m7.0c:compute-preflight-marker:v1\x00"
        + bytes.fromhex(_digest(manifest_sha256, "manifest_sha256"))
        + bytes.fromhex(_digest(template_sha256, "template_sha256"))
    )
    return hashlib.sha256(material).hexdigest()


def _overall_timeout_seconds(policy: SlurmSchedulerPolicy) -> int:
    """Derive a bounded submit + pending + runtime + accounting deadline."""

    day_text, separator, clock = policy.time_limit.partition("-")
    if not separator:
        clock = day_text
        days = 0
    else:
        days = int(day_text)
    hours, minutes, seconds = (int(part) for part in clock.split(":"))
    runtime = (((days * 24) + hours) * 60 + minutes) * 60 + seconds
    accounting_grace = 2 * policy.status_poll_seconds
    return policy.submit_timeout_seconds + policy.max_pending_seconds + runtime + accounting_grace


def _fresh_elapsed(
    state: SchedulerPreflightState,
    value: int,
    label: str,
) -> int:
    elapsed = _strict_int(value, f"{label}.elapsed_seconds", 0, 2**63 - 1)
    if elapsed < state.elapsed_seconds:
        raise SchedulerPreflightError(f"{label} elapsed_seconds must be monotonic")
    return elapsed


def _terminal_state(
    state: SchedulerPreflightState,
    phase: Literal["failed", "indeterminate"],
    elapsed: int,
    mapped: SlurmMappedState,
    *,
    started: bool,
    terminal_observation: SlurmObservation | None = None,
) -> SchedulerPreflightState:
    return _replace_state(
        state,
        phase=phase,
        elapsed_seconds=elapsed,
        started=started,
        terminal_seen=state.terminal_seen or terminal_observation is not None,
        terminal_observation=terminal_observation or state.terminal_observation,
        reason_code=mapped.code,
    )


def _require_phase(state: SchedulerPreflightState, phases: set[str]) -> None:
    if not isinstance(state, SchedulerPreflightState):
        raise SchedulerPreflightError("state must be a SchedulerPreflightState")
    if state.phase not in phases:
        raise SchedulerPreflightError("preflight transition is invalid for the current phase")


def _validate_path_mapping(
    relation: str,
    source_paths: tuple[str, ...],
    execution_paths: tuple[str, ...],
    mappings: tuple[PathMappingBinding, ...],
) -> None:
    if len(source_paths) != len(execution_paths):
        raise SchedulerPreflightError("source and execution path counts differ")
    if relation == "same" and not mappings:
        if source_paths != execution_paths:
            raise SchedulerPreflightError("same-host paths must be identical without mappings")
        return
    if not mappings:
        raise SchedulerPreflightError("shared-host preflight requires path mappings")
    if tuple(_map_path(path, mappings) for path in source_paths) != execution_paths:
        raise SchedulerPreflightError("path_mapping does not produce execution_paths")


def _map_path(path: str, mappings: tuple[PathMappingBinding, ...]) -> str:
    source = PurePosixPath(path)
    candidates: list[tuple[int, str]] = []
    for mapping in mappings:
        prefix = PurePosixPath(mapping.source_prefix)
        try:
            relative = source.relative_to(prefix)
        except ValueError:
            continue
        target = PurePosixPath(mapping.execution_prefix) / relative
        candidates.append((len(prefix.parts), str(target)))
    if not candidates:
        raise SchedulerPreflightError("path_mapping is incomplete")
    longest = max(length for length, _target in candidates)
    targets = {target for length, target in candidates if length == longest}
    if len(targets) != 1:
        raise SchedulerPreflightError("path_mapping is ambiguous")
    return targets.pop()


def _project_hash(hashes: Mapping[str, str]) -> str:
    return hashlib.sha256(
        _canonical_json_bytes(
            {
                "dataset_manifest": hashes["dataset_manifest"],
                "execution_plan": hashes["execution_plan"],
                "pipeline_spec": hashes["pipeline_spec"],
                "software_lock": hashes["software_lock"],
            }
        )
    ).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise SchedulerPreflightError("value cannot be canonically serialized") from exc


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise SchedulerPreflightError(f"{label} must be an object with string keys")
    return cast(dict[str, Any], value)


def _exact_fields(value: dict[str, Any], fields: frozenset[str], label: str) -> None:
    if set(value) != fields:
        raise SchedulerPreflightError(f"{label} fields do not match the exact contract")


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise SchedulerPreflightError(f"{label} must be one safe identifier")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value) or value == "0" * 64:
        raise SchedulerPreflightError(f"{label} must be a non-placeholder lowercase SHA-256")
    return value


def _token(value: Any) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value) or value == "0" * 64:
        raise SchedulerPreflightError("trusted token must be one non-placeholder 32-byte hex value")
    return value


def _tagged_image(value: Any, label: str) -> str:
    image = _bounded_text(value, label, maximum=512)
    if (
        not _TAGGED_IMAGE.fullmatch(image)
        or image.rsplit(":", maxsplit=1)[-1].casefold() == "latest"
    ):
        raise SchedulerPreflightError(
            f"{label} must be one explicitly tagged safe OCI registry reference"
        )
    return image


def _sif_path(value: str) -> str:
    path = PurePosixPath(value)
    if not path.name.endswith(".sif") or path.name == ".sif":
        raise SchedulerPreflightError("container.local_path must identify one .sif file")
    return value


def _bounded_text(value: Any, label: str, *, maximum: int = _MAX_PATH_BYTES) -> str:
    if not isinstance(value, str):
        raise SchedulerPreflightError(f"{label} must be bounded safe text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SchedulerPreflightError(f"{label} must be bounded safe text") from exc
    if (
        not value
        or len(encoded) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SchedulerPreflightError(f"{label} must be bounded safe text")
    return value


def _absolute_path(value: Any, label: str) -> str:
    text = _bounded_text(value, label)
    path = PurePosixPath(text)
    if not path.is_absolute() or path == PurePosixPath("/") or ".." in path.parts:
        raise SchedulerPreflightError(f"{label} must be a non-root absolute POSIX path")
    if str(path) != text:
        raise SchedulerPreflightError(f"{label} must be a canonical POSIX path")
    return text


def _fixed_worker_path(value: Any, label: str, leaf: str) -> str:
    if not isinstance(value, str) or not _SAFE_WORKER_PATH.fullmatch(value):
        raise SchedulerPreflightError(f"{label} must be one shell-inert ASCII path")
    path = PurePosixPath(value)
    if path == PurePosixPath("/") or ".." in path.parts or str(path) != value or path.name != leaf:
        raise SchedulerPreflightError(f"{label} must end in the fixed {leaf!r} leaf")
    return value


def _fixed_runtime_path(value: Any, label: str, leaf: str) -> str:
    if not isinstance(value, str) or not _SAFE_WORKER_PATH.fullmatch(value):
        raise SchedulerPreflightError(f"{label} must be one shell-inert ASCII path")
    path = PurePosixPath(value)
    if path == PurePosixPath("/") or ".." in path.parts or str(path) != value or path.name != leaf:
        raise SchedulerPreflightError(f"{label} must end in the fixed {leaf!r} leaf")
    return value


def _array(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = _MAX_ARRAY_ITEMS,
) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise SchedulerPreflightError(f"{label} must be a bounded array")
    return value


def _path_array(value: Any, label: str) -> tuple[str, ...]:
    values = _array(value, label, minimum=1)
    result = tuple(_absolute_path(item, label) for item in values)
    if len(result) != len(set(result)):
        raise SchedulerPreflightError(f"{label} must not contain duplicates")
    return result


def _strict_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SchedulerPreflightError(f"{label} is outside its strict integer range")
    return value


def _bounded_number(value: Any, label: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SchedulerPreflightError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise SchedulerPreflightError(f"{label} is outside its supported range")
    return result


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _reject_excessive_nesting(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > _MAX_JSON_NESTING:
                raise ValueError("JSON nesting exceeds the supported limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ValueError("JSON delimiters are unbalanced")
    if depth != 0 or in_string:
        raise ValueError("JSON structure is incomplete")


__all__ = [
    "COMPUTE_CHECK_NAMES",
    "EVIDENCE_VERSION",
    "MANIFEST_VERSION",
    "WORKER_CONTRACT_VERSION",
    "ComputeCheckEvidence",
    "ComputePreflightEvidence",
    "ComputePreflightManifest",
    "ComputeRuntimeBinding",
    "ComputeWorkerBinding",
    "ContainerBinding",
    "PathMappingBinding",
    "PreflightCapability",
    "ResumeDirectoryIdentity",
    "SchedulerPreflightError",
    "SchedulerPreflightState",
    "canonical_evidence_bytes",
    "canonical_manifest_bytes",
    "consume_capability",
    "decode_compute_evidence",
    "evidence_hash",
    "input_set_hash",
    "issue_capability",
    "manifest_hash",
    "parse_compute_evidence",
    "parse_compute_manifest",
    "preflight_result",
    "prepare_preflight",
    "record_capability_consumed",
    "record_capability_expired",
    "record_clock_discontinuity",
    "record_compute_evidence",
    "record_driver_timeout",
    "record_held_release",
    "record_held_submission",
    "record_release_intent",
    "record_release_unknown",
    "record_scheduler_poll",
    "record_submit_unknown",
    "render_compute_template",
    "template_hash",
    "validate_compute_evidence_binding",
]
