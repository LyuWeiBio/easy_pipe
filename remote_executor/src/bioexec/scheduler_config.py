"""Pure, dormant Remote Executor configuration contract for M7 Slurm.

This module validates already-decoded configuration values only.  It does not
read a configuration file, inspect the filesystem, import the service entry
point, or make the scheduler reachable.  A later activation slice must repeat
the trusted-path and filesystem-identity checks at the mutation boundary.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import PurePosixPath
from typing import Any

from .slurm import SlurmContractError, SlurmSchedulerPolicy
from .slurm import scheduler_policy_hash as _scheduler_policy_hash

SCHEDULER_CONFIG_VERSION = "2.0"
SCHEDULER_PROFILE_VERSION = "2.0"

_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema_version",
        "profile_version",
        "profile_id",
        "profile_hash",
        "runtime",
        "scheduler",
        "read_roots",
        "deploy_roots",
        "work_roots",
        "output_roots",
        "cache_roots",
        "state_root",
        "executables",
        "nextflow_version",
        "nextflow_jar",
        "nextflow_jar_sha256",
        "approval_key_id",
        "approval_hmac_key",
        "limits",
    }
)
_RUNTIME_FIELDS = frozenset(
    {
        "launch_backend",
        "workflow_engine",
        "workflow_executor",
        "container_engine",
        "topology",
    }
)
_EXECUTABLE_FIELDS = frozenset(
    {
        "python",
        "java",
        "nextflow",
        "apptainer",
        "compute_worker",
        "compute_bootstrap",
        "sbatch",
        "squeue",
        "sacct",
        "scontrol",
    }
)
_EXECUTABLE_LEAVES = {
    "python": "python3",
    "java": "java",
    "nextflow": "nextflow",
    "apptainer": "apptainer",
    "compute_worker": "bioexec-compute-preflight",
    "compute_bootstrap": "bioexec-compute-bootstrap",
    "sbatch": "sbatch",
    "squeue": "squeue",
    "sacct": "sacct",
    "scontrol": "scontrol",
}
_LIMIT_FIELDS = frozenset(
    {
        "max_request_bytes",
        "max_response_bytes",
        "max_deployment_files",
        "max_file_bytes",
        "max_deployment_bytes",
        "max_raw_paths",
        "max_command_output_bytes",
        "command_timeout_seconds",
        "run_timeout_seconds",
        "preflight_ttl_seconds",
        "minimum_free_bytes",
    }
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_MAX_PATH_BYTES = 4096
_MAX_ROOTS_PER_ROLE = 128


class SchedulerConfigError(ValueError):
    """A decoded value violates the dormant scheduler configuration contract."""


@dataclass(frozen=True)
class SchedulerRuntime:
    """The only topology admitted by the first scheduler contract."""

    launch_backend: str
    workflow_engine: str
    workflow_executor: str
    container_engine: str
    topology: str

    def __post_init__(self) -> None:
        expected = {
            "launch_backend": "slurm",
            "workflow_engine": "nextflow",
            "workflow_executor": "local",
            "container_engine": "apptainer",
            "topology": "single_allocation_nextflow_local",
        }
        if self.as_mapping() != expected:
            raise SchedulerConfigError(
                "runtime must select Slurm, one allocation, Nextflow local, and Apptainer"
            )

    @classmethod
    def from_mapping(cls, value: Any) -> SchedulerRuntime:
        """Parse the exact fixed-topology runtime object."""

        mapping = _exact_mapping(value, _RUNTIME_FIELDS, "runtime")
        return cls(
            launch_backend=_string(mapping["launch_backend"], "runtime.launch_backend"),
            workflow_engine=_string(mapping["workflow_engine"], "runtime.workflow_engine"),
            workflow_executor=_string(mapping["workflow_executor"], "runtime.workflow_executor"),
            container_engine=_string(mapping["container_engine"], "runtime.container_engine"),
            topology=_string(mapping["topology"], "runtime.topology"),
        )

    def as_mapping(self) -> dict[str, str]:
        """Return the canonical runtime field order."""

        return {
            "launch_backend": self.launch_backend,
            "workflow_engine": self.workflow_engine,
            "workflow_executor": self.workflow_executor,
            "container_engine": self.container_engine,
            "topology": self.topology,
        }


@dataclass(frozen=True)
class SchedulerExecutables:
    """Absolute fixed-leaf executable paths required by the M7 topology."""

    python: str
    java: str
    nextflow: str
    apptainer: str
    compute_worker: str
    compute_bootstrap: str
    sbatch: str
    squeue: str
    sacct: str
    scontrol: str

    def __post_init__(self) -> None:
        for field, value in self.as_mapping().items():
            _fixed_executable(value, field)

    @classmethod
    def from_mapping(cls, value: Any) -> SchedulerExecutables:
        """Parse exactly the reviewed executable roles; Docker and scancel are absent."""

        mapping = _exact_mapping(value, _EXECUTABLE_FIELDS, "executables")
        return cls(
            python=_fixed_executable(mapping["python"], "python"),
            java=_fixed_executable(mapping["java"], "java"),
            nextflow=_fixed_executable(mapping["nextflow"], "nextflow"),
            apptainer=_fixed_executable(mapping["apptainer"], "apptainer"),
            compute_worker=_fixed_executable(mapping["compute_worker"], "compute_worker"),
            compute_bootstrap=_fixed_executable(
                mapping["compute_bootstrap"],
                "compute_bootstrap",
            ),
            sbatch=_fixed_executable(mapping["sbatch"], "sbatch"),
            squeue=_fixed_executable(mapping["squeue"], "squeue"),
            sacct=_fixed_executable(mapping["sacct"], "sacct"),
            scontrol=_fixed_executable(mapping["scontrol"], "scontrol"),
        )

    def as_mapping(self) -> dict[str, str]:
        """Return the canonical executable role order."""

        return {
            "python": self.python,
            "java": self.java,
            "nextflow": self.nextflow,
            "apptainer": self.apptainer,
            "compute_worker": self.compute_worker,
            "compute_bootstrap": self.compute_bootstrap,
            "sbatch": self.sbatch,
            "squeue": self.squeue,
            "sacct": self.sacct,
            "scontrol": self.scontrol,
        }


@dataclass(frozen=True)
class SchedulerLimits:
    """The v1 server ceilings carried unchanged into scheduler config v2."""

    max_request_bytes: int = 64 * 1024 * 1024
    max_response_bytes: int = 1024 * 1024
    max_deployment_files: int = 128
    max_file_bytes: int = 16 * 1024 * 1024
    max_deployment_bytes: int = 64 * 1024 * 1024
    max_raw_paths: int = 100_000
    max_command_output_bytes: int = 256 * 1024
    command_timeout_seconds: float = 30.0
    run_timeout_seconds: float = 7 * 24 * 60 * 60
    preflight_ttl_seconds: int = 900
    minimum_free_bytes: int = 1024 * 1024 * 1024

    def __post_init__(self) -> None:
        _strict_int(self.max_request_bytes, "limits.max_request_bytes", 1024, 128 * 1024**2)
        _strict_int(self.max_response_bytes, "limits.max_response_bytes", 512, 16 * 1024**2)
        _strict_int(self.max_deployment_files, "limits.max_deployment_files", 1, 1024)
        _strict_int(self.max_file_bytes, "limits.max_file_bytes", 1, 32 * 1024**2)
        _strict_int(
            self.max_deployment_bytes,
            "limits.max_deployment_bytes",
            1,
            128 * 1024**2,
        )
        _strict_int(self.max_raw_paths, "limits.max_raw_paths", 1, 1_000_000)
        _strict_int(
            self.max_command_output_bytes,
            "limits.max_command_output_bytes",
            1024,
            16 * 1024**2,
        )
        _bounded_number(
            self.command_timeout_seconds,
            "limits.command_timeout_seconds",
            1.0,
            3600.0,
        )
        _bounded_number(
            self.run_timeout_seconds,
            "limits.run_timeout_seconds",
            1.0,
            31 * 24 * 60 * 60.0,
        )
        _strict_int(self.preflight_ttl_seconds, "limits.preflight_ttl_seconds", 1, 86_400)
        _strict_int(
            self.minimum_free_bytes,
            "limits.minimum_free_bytes",
            1024 * 1024,
            2**63 - 1,
        )
        if self.max_file_bytes > self.max_deployment_bytes:
            raise SchedulerConfigError("limits.max_file_bytes must not exceed max_deployment_bytes")

    @classmethod
    def from_mapping(cls, value: Any) -> SchedulerLimits:
        """Parse the existing optional limit overrides and reject extensions."""

        if not isinstance(value, dict) or set(value) - _LIMIT_FIELDS:
            raise SchedulerConfigError("limits contains unsupported fields")
        defaults = cls()
        return cls(
            max_request_bytes=_mapping_int(
                value,
                "max_request_bytes",
                defaults.max_request_bytes,
                1024,
                128 * 1024**2,
            ),
            max_response_bytes=_mapping_int(
                value,
                "max_response_bytes",
                defaults.max_response_bytes,
                512,
                16 * 1024**2,
            ),
            max_deployment_files=_mapping_int(
                value,
                "max_deployment_files",
                defaults.max_deployment_files,
                1,
                1024,
            ),
            max_file_bytes=_mapping_int(
                value,
                "max_file_bytes",
                defaults.max_file_bytes,
                1,
                32 * 1024**2,
            ),
            max_deployment_bytes=_mapping_int(
                value,
                "max_deployment_bytes",
                defaults.max_deployment_bytes,
                1,
                128 * 1024**2,
            ),
            max_raw_paths=_mapping_int(
                value,
                "max_raw_paths",
                defaults.max_raw_paths,
                1,
                1_000_000,
            ),
            max_command_output_bytes=_mapping_int(
                value,
                "max_command_output_bytes",
                defaults.max_command_output_bytes,
                1024,
                16 * 1024**2,
            ),
            command_timeout_seconds=_mapping_number(
                value,
                "command_timeout_seconds",
                defaults.command_timeout_seconds,
                1.0,
                3600.0,
            ),
            run_timeout_seconds=_mapping_number(
                value,
                "run_timeout_seconds",
                defaults.run_timeout_seconds,
                1.0,
                31 * 24 * 60 * 60.0,
            ),
            preflight_ttl_seconds=_mapping_int(
                value,
                "preflight_ttl_seconds",
                defaults.preflight_ttl_seconds,
                1,
                86_400,
            ),
            minimum_free_bytes=_mapping_int(
                value,
                "minimum_free_bytes",
                defaults.minimum_free_bytes,
                1024 * 1024,
                2**63 - 1,
            ),
        )


@dataclass(frozen=True)
class SchedulerAgentConfig:
    """Complete syntax-level Remote Executor configuration for Slurm M7."""

    schema_version: str
    profile_version: str
    profile_id: str
    profile_hash: str
    runtime: SchedulerRuntime
    scheduler: SlurmSchedulerPolicy
    read_roots: tuple[str, ...]
    deploy_roots: tuple[str, ...]
    work_roots: tuple[str, ...]
    output_roots: tuple[str, ...]
    cache_roots: tuple[str, ...]
    state_root: str
    executables: SchedulerExecutables
    nextflow_version: str
    nextflow_jar: str
    nextflow_jar_sha256: str
    approval_key_id: str
    approval_hmac_key: bytes = dataclass_field(repr=False)
    limits: SchedulerLimits = dataclass_field(default_factory=SchedulerLimits)

    def __post_init__(self) -> None:
        if self.schema_version != SCHEDULER_CONFIG_VERSION:
            raise SchedulerConfigError("unsupported scheduler configuration schema_version")
        if self.profile_version != SCHEDULER_PROFILE_VERSION:
            raise SchedulerConfigError("unsupported scheduler execution profile version")
        _identifier(self.profile_id, "profile_id")
        _digest(self.profile_hash, "profile_hash", reject_zero=True)
        if not isinstance(self.runtime, SchedulerRuntime):
            raise SchedulerConfigError("runtime must be a validated SchedulerRuntime")
        if not isinstance(self.scheduler, SlurmSchedulerPolicy):
            raise SchedulerConfigError("scheduler must be a validated SlurmSchedulerPolicy")
        if not isinstance(self.executables, SchedulerExecutables):
            raise SchedulerConfigError("executables must be validated SchedulerExecutables")
        if not isinstance(self.limits, SchedulerLimits):
            raise SchedulerConfigError("limits must be validated SchedulerLimits")
        _identifier(self.nextflow_version, "nextflow_version")
        _absolute_path(self.nextflow_jar, "nextflow_jar")
        _digest(self.nextflow_jar_sha256, "nextflow_jar_sha256", reject_zero=True)
        _identifier(self.approval_key_id, "approval_key_id")
        if (
            not isinstance(self.approval_hmac_key, bytes)
            or len(self.approval_hmac_key) != 32
            or self.approval_hmac_key == bytes(32)
        ):
            raise SchedulerConfigError("approval_hmac_key must be one non-placeholder 32-byte key")
        roles = {
            "read_roots": self.read_roots,
            "deploy_roots": self.deploy_roots,
            "work_roots": self.work_roots,
            "output_roots": self.output_roots,
            "cache_roots": self.cache_roots,
        }
        for field, values in roles.items():
            _validated_roots(values, field, require_tuple=True)
        _absolute_path(self.state_root, "state_root")
        _validate_role_separation(roles, self.state_root)

    @classmethod
    def from_mapping(cls, value: Any) -> SchedulerAgentConfig:
        """Parse one exact decoded JSON object without touching external state."""

        mapping = _exact_mapping(value, _TOP_LEVEL_FIELDS, "configuration")
        scheduler_value = mapping["scheduler"]
        try:
            scheduler = SlurmSchedulerPolicy.from_mapping(scheduler_value)
        except SlurmContractError as exc:
            raise SchedulerConfigError(
                "scheduler policy violates the fixed Slurm contract"
            ) from exc
        roles = {
            field: _roots(mapping[field], field)
            for field in (
                "read_roots",
                "deploy_roots",
                "work_roots",
                "output_roots",
                "cache_roots",
            )
        }
        state_root = _absolute_path(mapping["state_root"], "state_root")
        _validate_role_separation(roles, state_root)
        return cls(
            schema_version=_string(mapping["schema_version"], "schema_version"),
            profile_version=_string(mapping["profile_version"], "profile_version"),
            profile_id=_identifier(mapping["profile_id"], "profile_id"),
            profile_hash=_digest(mapping["profile_hash"], "profile_hash", reject_zero=True),
            runtime=SchedulerRuntime.from_mapping(mapping["runtime"]),
            scheduler=scheduler,
            read_roots=roles["read_roots"],
            deploy_roots=roles["deploy_roots"],
            work_roots=roles["work_roots"],
            output_roots=roles["output_roots"],
            cache_roots=roles["cache_roots"],
            state_root=state_root,
            executables=SchedulerExecutables.from_mapping(mapping["executables"]),
            nextflow_version=_identifier(mapping["nextflow_version"], "nextflow_version"),
            nextflow_jar=_absolute_path(mapping["nextflow_jar"], "nextflow_jar"),
            nextflow_jar_sha256=_digest(
                mapping["nextflow_jar_sha256"],
                "nextflow_jar_sha256",
                reject_zero=True,
            ),
            approval_key_id=_identifier(mapping["approval_key_id"], "approval_key_id"),
            approval_hmac_key=_approval_key(mapping["approval_hmac_key"]),
            limits=SchedulerLimits.from_mapping(mapping["limits"]),
        )


def parse_scheduler_config(value: Any) -> SchedulerAgentConfig:
    """Parse a decoded scheduler configuration mapping without performing I/O."""

    return SchedulerAgentConfig.from_mapping(value)


def canonical_scheduler_policy_hash(policy: SlurmSchedulerPolicy) -> str:
    """Hash the exact canonical scheduler policy mapping used by profile identity."""

    if not isinstance(policy, SlurmSchedulerPolicy):
        raise SchedulerConfigError("policy must be a validated SlurmSchedulerPolicy")
    return _scheduler_policy_hash(policy)


def _exact_mapping(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise SchedulerConfigError(f"{label} fields do not match the fixed schema")
    return value


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise SchedulerConfigError(f"{field} must be a string")
    return value


def _identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise SchedulerConfigError(f"{field} must be a bounded safe identifier")
    return value


def _digest(value: Any, field: str, *, reject_zero: bool) -> str:
    if (
        not isinstance(value, str)
        or not _SHA256.fullmatch(value)
        or (reject_zero and value == "0" * 64)
    ):
        raise SchedulerConfigError(f"{field} must be one non-placeholder lowercase SHA-256")
    return value


def _approval_key(value: Any) -> bytes:
    digest = _digest(value, "approval_hmac_key", reject_zero=True)
    return bytes.fromhex(digest)


def _absolute_path(value: Any, field: str) -> str:
    try:
        encoded = value.encode("utf-8") if isinstance(value, str) else b""
    except UnicodeEncodeError as exc:
        raise SchedulerConfigError(f"{field} must be one bounded canonical absolute path") from exc
    if (
        not isinstance(value, str)
        or not value
        or len(encoded) > _MAX_PATH_BYTES
        or value.startswith("//")
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise SchedulerConfigError(f"{field} must be one bounded canonical absolute path")
    path = PurePosixPath(value)
    if (
        not path.is_absolute()
        or path == PurePosixPath("/")
        or ".." in path.parts
        or str(path) != value
    ):
        raise SchedulerConfigError(f"{field} must be one bounded canonical absolute path")
    return value


def _fixed_executable(value: Any, field: str) -> str:
    path = _absolute_path(value, f"executables.{field}")
    expected_leaf = _EXECUTABLE_LEAVES.get(field)
    if expected_leaf is None or PurePosixPath(path).name != expected_leaf:
        raise SchedulerConfigError(
            f"executables.{field} must use the fixed {expected_leaf or field!r} leaf"
        )
    return path


def _roots(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > _MAX_ROOTS_PER_ROLE:
        raise SchedulerConfigError(f"{field} must be one non-empty bounded array")
    roots = tuple(_absolute_path(item, field) for item in value)
    return _validated_roots(roots, field, require_tuple=True)


def _validated_roots(
    value: Any,
    field: str,
    *,
    require_tuple: bool,
) -> tuple[str, ...]:
    if require_tuple and not isinstance(value, tuple):
        raise SchedulerConfigError(f"{field} must be a validated tuple of roots")
    if not value or len(value) > _MAX_ROOTS_PER_ROLE:
        raise SchedulerConfigError(f"{field} must be one non-empty bounded array")
    roots = tuple(_absolute_path(item, field) for item in value)
    if len(set(roots)) != len(roots):
        raise SchedulerConfigError(f"{field} contains duplicate roots")
    for index, first in enumerate(roots):
        for second in roots[index + 1 :]:
            if _paths_overlap(first, second):
                raise SchedulerConfigError(f"{field} contains overlapping roots")
    return tuple(sorted(roots))


def _validate_role_separation(roles: dict[str, tuple[str, ...]], state_root: str) -> None:
    labeled = [(field, path) for field, roots in roles.items() for path in roots]
    labeled.append(("state_root", state_root))
    for index, (first_role, first) in enumerate(labeled):
        for second_role, second in labeled[index + 1 :]:
            if first_role != second_role and _paths_overlap(first, second):
                raise SchedulerConfigError("execution root roles must not overlap")


def _paths_overlap(first: str, second: str) -> bool:
    first_path = PurePosixPath(first)
    second_path = PurePosixPath(second)
    return (
        first_path == second_path
        or first_path in second_path.parents
        or second_path in first_path.parents
    )


def _strict_int(value: Any, field: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SchedulerConfigError(f"{field} is outside its supported integer range")
    return value


def _bounded_number(value: Any, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SchedulerConfigError(f"{field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise SchedulerConfigError(f"{field} is outside its supported range")
    return result


def _mapping_int(
    values: dict[str, Any],
    key: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    return _strict_int(values.get(key, default), f"limits.{key}", minimum, maximum)


def _mapping_number(
    values: dict[str, Any],
    key: str,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    return _bounded_number(values.get(key, default), f"limits.{key}", minimum, maximum)


__all__ = [
    "SCHEDULER_CONFIG_VERSION",
    "SCHEDULER_PROFILE_VERSION",
    "SchedulerAgentConfig",
    "SchedulerConfigError",
    "SchedulerExecutables",
    "SchedulerLimits",
    "SchedulerRuntime",
    "canonical_scheduler_policy_hash",
    "parse_scheduler_config",
]
