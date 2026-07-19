"""Trusted, dormant filesystem loader for the M7 scheduler configuration.

The syntax-only contract remains in :mod:`bioexec.scheduler_config`.  This
module adds the filesystem identities that a future scheduler adapter must
recheck at each mutation boundary.  No installed entry point imports this
module, and the loader never starts a process, writes state, consults the
environment, or accesses the network.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import InitVar, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, cast

from .scheduler_config import (
    SchedulerAgentConfig,
    SchedulerConfigError,
    canonical_scheduler_policy_hash,
    parse_scheduler_config,
)

MAX_SCHEDULER_CONFIG_BYTES = 1_048_576
MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
MAX_NEXTFLOW_JAR_BYTES = 128 * 1024 * 1024

_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_EXECUTABLE_ROLES = (
    "java",
    "nextflow",
    "apptainer",
    "sbatch",
    "squeue",
    "sacct",
    "scontrol",
)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_BINDING_AUTHORITY = object()
_CONFIG_AUTHORITY = object()

RootRole = Literal[
    "read",
    "deploy",
    "work",
    "output",
    "cache",
    "state",
]
ExecutableRole = Literal[
    "java",
    "nextflow",
    "apptainer",
    "sbatch",
    "squeue",
    "sacct",
    "scontrol",
]


class SchedulerConfigLoadError(ValueError):
    """A scheduler configuration or one of its trusted paths is invalid."""


@dataclass(frozen=True)
class TrustedDirectoryBinding:
    """One configured role root bound to its startup filesystem identity."""

    _authority: InitVar[object]
    role: RootRole
    path: Path
    device: int
    inode: int
    owner: int
    group: int
    mode: int

    def __post_init__(self, _authority: object) -> None:
        if _authority is not _BINDING_AUTHORITY:
            raise SchedulerConfigLoadError("scheduler root binding construction is internal")
        _validate_binding_path(self.path)
        if self.role not in {"read", "deploy", "work", "output", "cache", "state"}:
            raise SchedulerConfigLoadError("scheduler root binding has an invalid role")
        _validate_identity_numbers(
            self.device,
            self.inode,
            self.owner,
            self.group,
            self.mode,
        )


@dataclass(frozen=True)
class TrustedFileBinding:
    """One trusted regular file bound to its startup identity and optional hash."""

    _authority: InitVar[object]
    role: str
    path: Path
    device: int
    inode: int
    owner: int
    group: int
    mode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    sha256: str | None = None

    def __post_init__(self, _authority: object) -> None:
        if _authority is not _BINDING_AUTHORITY:
            raise SchedulerConfigLoadError("scheduler file binding construction is internal")
        _validate_binding_path(self.path)
        if self.role not in {"scheduler_config", "nextflow_jar", *_EXECUTABLE_ROLES}:
            raise SchedulerConfigLoadError("scheduler file binding has an invalid role")
        _validate_identity_numbers(
            self.device,
            self.inode,
            self.owner,
            self.group,
            self.mode,
        )
        for value in (self.size, self.mtime_ns, self.ctime_ns):
            if type(value) is not int or value < 0:
                raise SchedulerConfigLoadError("scheduler file binding has invalid identity data")
        if self.sha256 is not None and not _SHA256.fullmatch(self.sha256):
            raise SchedulerConfigLoadError("scheduler file binding has an invalid SHA-256")


@dataclass(frozen=True)
class TrustedSchedulerConfig:
    """A validated config-v2 contract plus trusted startup filesystem evidence."""

    _authority: InitVar[object]
    contract: SchedulerAgentConfig
    config_file: TrustedFileBinding
    config_sha256: str
    contract_sha256: str
    scheduler_policy_hash: str
    read_roots: tuple[TrustedDirectoryBinding, ...]
    deploy_roots: tuple[TrustedDirectoryBinding, ...]
    work_roots: tuple[TrustedDirectoryBinding, ...]
    output_roots: tuple[TrustedDirectoryBinding, ...]
    cache_roots: tuple[TrustedDirectoryBinding, ...]
    state_root: TrustedDirectoryBinding
    executables: Mapping[str, TrustedFileBinding]
    nextflow_jar: TrustedFileBinding

    def __post_init__(self, _authority: object) -> None:
        if _authority is not _CONFIG_AUTHORITY:
            raise SchedulerConfigLoadError("trusted scheduler config construction is internal")
        _validate_trusted_scheduler_config(self)


def load_trusted_scheduler_config(path: Path) -> TrustedSchedulerConfig:
    """Load one explicit config-v2 file and bind every trusted filesystem object."""

    selected = _absolute_loader_path(path)
    descriptor = -1
    try:
        descriptor, before = _open_trusted_regular(selected)
        _require_config_file(before)
        payload = _read_bounded(descriptor, MAX_SCHEDULER_CONFIG_BYTES + 1)
        after = os.fstat(descriptor)
        if _stable_file_identity(before) != _stable_file_identity(after):
            raise SchedulerConfigLoadError("scheduler configuration changed while it was read")
    except SchedulerConfigLoadError:
        raise
    except OSError as exc:
        raise SchedulerConfigLoadError("scheduler configuration cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if len(payload) > MAX_SCHEDULER_CONFIG_BYTES:
        raise SchedulerConfigLoadError("scheduler configuration exceeds its byte budget")
    mapping = _decode_config(payload)
    try:
        contract = parse_scheduler_config(mapping)
    except (SchedulerConfigError, UnicodeError) as exc:
        raise SchedulerConfigLoadError("scheduler configuration violates config-v2") from exc

    config_binding = _file_binding(
        "scheduler_config",
        selected,
        after,
        sha256=hashlib.sha256(payload).hexdigest(),
    )
    read_roots = _load_roots(contract.read_roots, "read")
    deploy_roots = _load_roots(contract.deploy_roots, "deploy")
    work_roots = _load_roots(contract.work_roots, "work")
    output_roots = _load_roots(contract.output_roots, "output")
    cache_roots = _load_roots(contract.cache_roots, "cache")
    state_root = _load_root(contract.state_root, "state")
    roots = (*read_roots, *deploy_roots, *work_roots, *output_roots, *cache_roots, state_root)
    _require_unique_identities(roots, "configured role roots alias one another")

    executable_paths = contract.executables.as_mapping()
    executables = {
        role: _load_executable(Path(executable_paths[role]), cast(ExecutableRole, role))
        for role in _EXECUTABLE_ROLES
    }
    _require_unique_identities(
        tuple(executables.values()),
        "configured executable roles alias one another",
    )
    nextflow_jar = _load_nextflow_jar(
        Path(contract.nextflow_jar),
        contract.nextflow_jar_sha256,
    )
    trusted_files = (config_binding, *executables.values(), nextflow_jar)
    _require_unique_identities(trusted_files, "trusted scheduler files alias one another")

    return TrustedSchedulerConfig(
        _authority=_CONFIG_AUTHORITY,
        contract=contract,
        config_file=config_binding,
        config_sha256=cast(str, config_binding.sha256),
        contract_sha256=_scheduler_contract_sha256(contract),
        scheduler_policy_hash=canonical_scheduler_policy_hash(contract.scheduler),
        read_roots=read_roots,
        deploy_roots=deploy_roots,
        work_roots=work_roots,
        output_roots=output_roots,
        cache_roots=cache_roots,
        state_root=state_root,
        executables=MappingProxyType(executables),
        nextflow_jar=nextflow_jar,
    )


def verify_scheduler_config_file(config: TrustedSchedulerConfig) -> None:
    """Re-open and re-hash the exact config-v2 file loaded at startup."""

    if not isinstance(config, TrustedSchedulerConfig):
        raise SchedulerConfigLoadError("trusted scheduler configuration is required")
    descriptor = -1
    try:
        descriptor, metadata = _open_trusted_regular(config.config_file.path)
        _require_config_file(metadata)
        _require_same_file(config.config_file, metadata)
        payload = _read_bounded(descriptor, MAX_SCHEDULER_CONFIG_BYTES + 1)
        after = os.fstat(descriptor)
        _require_same_file(config.config_file, after)
        if (
            len(payload) > MAX_SCHEDULER_CONFIG_BYTES
            or hashlib.sha256(payload).hexdigest() != config.config_sha256
        ):
            raise SchedulerConfigLoadError("scheduler configuration changed after startup")
    except SchedulerConfigLoadError:
        raise
    except OSError as exc:
        raise SchedulerConfigLoadError("scheduler configuration changed after startup") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def verify_scheduler_root(
    config: TrustedSchedulerConfig,
    role: RootRole,
    index: int = 0,
) -> None:
    """Re-open one role root and require its exact startup identity and policy."""

    if not isinstance(config, TrustedSchedulerConfig):
        raise SchedulerConfigLoadError("trusted scheduler configuration is required")
    binding = _selected_root(config, role, index)
    descriptor = -1
    try:
        descriptor, metadata = _open_trusted_directory(
            binding.path,
            trusted_owner=binding.role != "read",
            private=binding.role == "state",
        )
        if _directory_identity(metadata) != (
            binding.device,
            binding.inode,
            binding.owner,
            binding.group,
            binding.mode,
        ):
            raise SchedulerConfigLoadError("configured scheduler root changed after startup")
    except SchedulerConfigLoadError:
        raise
    except OSError as exc:
        raise SchedulerConfigLoadError("configured scheduler root changed after startup") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def verify_scheduler_executable(config: TrustedSchedulerConfig, role: ExecutableRole) -> None:
    """Re-open one fixed executable immediately before its reviewed argv is used."""

    if not isinstance(config, TrustedSchedulerConfig) or role not in _EXECUTABLE_ROLES:
        raise SchedulerConfigLoadError("trusted fixed executable role is required")
    binding = config.executables[role]
    descriptor = -1
    try:
        descriptor, metadata = _open_trusted_regular(binding.path)
        _require_executable(metadata)
        _require_same_file(binding, metadata)
        observed, after = _sha256_stable_descriptor(
            descriptor,
            metadata,
            MAX_EXECUTABLE_BYTES,
        )
        _require_same_file(binding, after)
        if binding.sha256 is None or observed != binding.sha256:
            raise SchedulerConfigLoadError("configured executable hash changed after startup")
    except SchedulerConfigLoadError:
        raise
    except OSError as exc:
        raise SchedulerConfigLoadError("configured executable changed after startup") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def verify_scheduler_nextflow_jar(config: TrustedSchedulerConfig) -> None:
    """Re-open and fully hash the bounded pinned Nextflow JAR."""

    if not isinstance(config, TrustedSchedulerConfig):
        raise SchedulerConfigLoadError("trusted scheduler configuration is required")
    binding = config.nextflow_jar
    descriptor = -1
    try:
        descriptor, metadata = _open_trusted_regular(binding.path)
        _require_artifact(metadata)
        _require_same_file(binding, metadata)
        observed, after = _sha256_stable_descriptor(
            descriptor,
            metadata,
            MAX_NEXTFLOW_JAR_BYTES,
        )
        _require_same_file(binding, after)
        if binding.sha256 is None or observed != binding.sha256:
            raise SchedulerConfigLoadError("pinned Nextflow JAR changed after startup")
    except SchedulerConfigLoadError:
        raise
    except OSError as exc:
        raise SchedulerConfigLoadError("pinned Nextflow JAR changed after startup") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _absolute_loader_path(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or len(path.parts) < 2:
        raise SchedulerConfigLoadError("scheduler config path must be explicit and absolute")
    try:
        encoded = str(path).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SchedulerConfigLoadError("scheduler config path contains unsafe text") from exc
    if (
        len(encoded) > 4096
        or path.anchor != "/"
        or str(path).startswith("//")
        or any(ord(character) < 32 or ord(character) == 127 for character in str(path))
        or ".." in path.parts
    ):
        raise SchedulerConfigLoadError("scheduler config path contains unsafe text")
    return path


def _validate_binding_path(path: Path) -> None:
    if not isinstance(path, Path):
        raise SchedulerConfigLoadError("scheduler binding path must be a pathlib Path")
    try:
        encoded = str(path).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SchedulerConfigLoadError("scheduler binding path contains unsafe text") from exc
    if (
        not path.is_absolute()
        or len(path.parts) < 2
        or path.anchor != "/"
        or str(path).startswith("//")
        or ".." in path.parts
        or len(encoded) > 4096
        or any(ord(character) < 32 or ord(character) == 127 for character in str(path))
    ):
        raise SchedulerConfigLoadError("scheduler binding path is not canonical and absolute")


def _validate_identity_numbers(
    device: int,
    inode: int,
    owner: int,
    group: int,
    mode: int,
) -> None:
    if any(type(value) is not int or value < 0 for value in (device, inode, owner, group)):
        raise SchedulerConfigLoadError("scheduler binding has invalid filesystem identity data")
    if type(mode) is not int or not 0 <= mode <= 0o7777:
        raise SchedulerConfigLoadError("scheduler binding has an invalid filesystem mode")


def _selected_root(
    config: TrustedSchedulerConfig,
    role: RootRole,
    index: int,
) -> TrustedDirectoryBinding:
    if type(index) is not int or index < 0:
        raise SchedulerConfigLoadError("scheduler root index is invalid")
    if not isinstance(role, str) or role not in {
        "read",
        "deploy",
        "work",
        "output",
        "cache",
        "state",
    }:
        raise SchedulerConfigLoadError("scheduler root role is invalid")
    if role == "state":
        if index != 0:
            raise SchedulerConfigLoadError("state root has only index zero")
        return config.state_root
    role_roots = {
        "read": config.read_roots,
        "deploy": config.deploy_roots,
        "work": config.work_roots,
        "output": config.output_roots,
        "cache": config.cache_roots,
    }
    if role not in role_roots:
        raise SchedulerConfigLoadError("scheduler root role is invalid")
    try:
        return role_roots[role][index]
    except IndexError as exc:
        raise SchedulerConfigLoadError("scheduler root index is invalid") from exc


def _validate_trusted_scheduler_config(config: TrustedSchedulerConfig) -> None:
    if not isinstance(config.contract, SchedulerAgentConfig):
        raise SchedulerConfigLoadError("trusted scheduler config requires config-v2")
    if not _SHA256.fullmatch(config.config_sha256):
        raise SchedulerConfigLoadError("trusted scheduler config has an invalid file hash")
    if (
        not isinstance(config.config_file, TrustedFileBinding)
        or config.config_file.role != "scheduler_config"
        or config.config_file.sha256 != config.config_sha256
    ):
        raise SchedulerConfigLoadError("trusted scheduler config file binding does not match")
    expected_contract_hash = _scheduler_contract_sha256(config.contract)
    if config.contract_sha256 != expected_contract_hash:
        raise SchedulerConfigLoadError("trusted scheduler contract hash does not match")
    expected_policy_hash = canonical_scheduler_policy_hash(config.contract.scheduler)
    if config.scheduler_policy_hash != expected_policy_hash:
        raise SchedulerConfigLoadError("trusted scheduler policy hash does not match")

    role_bindings = {
        "read": (config.contract.read_roots, config.read_roots),
        "deploy": (config.contract.deploy_roots, config.deploy_roots),
        "work": (config.contract.work_roots, config.work_roots),
        "output": (config.contract.output_roots, config.output_roots),
        "cache": (config.contract.cache_roots, config.cache_roots),
    }
    all_roots: list[TrustedDirectoryBinding] = []
    for role, (expected_paths, bindings) in role_bindings.items():
        if (
            not isinstance(bindings, tuple)
            or len(bindings) != len(expected_paths)
            or any(
                not isinstance(binding, TrustedDirectoryBinding)
                or binding.role != role
                or str(binding.path) != expected_paths[index]
                for index, binding in enumerate(bindings)
            )
        ):
            raise SchedulerConfigLoadError("trusted scheduler role roots do not match config-v2")
        all_roots.extend(bindings)
    if (
        not isinstance(config.state_root, TrustedDirectoryBinding)
        or config.state_root.role != "state"
        or str(config.state_root.path) != config.contract.state_root
    ):
        raise SchedulerConfigLoadError("trusted scheduler state root does not match config-v2")
    all_roots.append(config.state_root)
    _require_unique_identities(tuple(all_roots), "configured role roots alias one another")

    expected_executables = config.contract.executables.as_mapping()
    if not isinstance(config.executables, Mapping) or set(config.executables) != set(
        _EXECUTABLE_ROLES
    ):
        raise SchedulerConfigLoadError("trusted executable roles do not match config-v2")
    for role in _EXECUTABLE_ROLES:
        binding = config.executables[role]
        if (
            not isinstance(binding, TrustedFileBinding)
            or binding.role != role
            or str(binding.path) != expected_executables[role]
            or binding.sha256 is None
        ):
            raise SchedulerConfigLoadError("trusted executable binding does not match config-v2")
    if (
        not isinstance(config.nextflow_jar, TrustedFileBinding)
        or config.nextflow_jar.role != "nextflow_jar"
        or str(config.nextflow_jar.path) != config.contract.nextflow_jar
        or config.nextflow_jar.sha256 != config.contract.nextflow_jar_sha256
    ):
        raise SchedulerConfigLoadError("trusted Nextflow JAR binding does not match config-v2")
    trusted_files = (config.config_file, *config.executables.values(), config.nextflow_jar)
    _require_unique_identities(trusted_files, "trusted scheduler files alias one another")


def _scheduler_contract_sha256(config: SchedulerAgentConfig) -> str:
    limits = config.limits
    value = {
        "schema_version": config.schema_version,
        "profile_version": config.profile_version,
        "profile_id": config.profile_id,
        "profile_hash": config.profile_hash,
        "runtime": config.runtime.as_mapping(),
        "scheduler": config.scheduler.as_mapping(),
        "read_roots": list(config.read_roots),
        "deploy_roots": list(config.deploy_roots),
        "work_roots": list(config.work_roots),
        "output_roots": list(config.output_roots),
        "cache_roots": list(config.cache_roots),
        "state_root": config.state_root,
        "executables": config.executables.as_mapping(),
        "nextflow_version": config.nextflow_version,
        "nextflow_jar": config.nextflow_jar,
        "nextflow_jar_sha256": config.nextflow_jar_sha256,
        "approval_key_id": config.approval_key_id,
        "approval_hmac_key": config.approval_hmac_key.hex(),
        "limits": {
            "max_request_bytes": limits.max_request_bytes,
            "max_response_bytes": limits.max_response_bytes,
            "max_deployment_files": limits.max_deployment_files,
            "max_file_bytes": limits.max_file_bytes,
            "max_deployment_bytes": limits.max_deployment_bytes,
            "max_raw_paths": limits.max_raw_paths,
            "max_command_output_bytes": limits.max_command_output_bytes,
            "command_timeout_seconds": limits.command_timeout_seconds,
            "run_timeout_seconds": limits.run_timeout_seconds,
            "preflight_ttl_seconds": limits.preflight_ttl_seconds,
            "minimum_free_bytes": limits.minimum_free_bytes,
        },
    }
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _decode_config(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise SchedulerConfigLoadError("scheduler configuration must be strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise SchedulerConfigLoadError("scheduler configuration must be one JSON object")
    return value


def _load_roots(values: tuple[str, ...], role: RootRole) -> tuple[TrustedDirectoryBinding, ...]:
    return tuple(_load_root(value, role) for value in values)


def _load_root(value: str, role: RootRole) -> TrustedDirectoryBinding:
    path = Path(value)
    descriptor = -1
    try:
        descriptor, metadata = _open_trusted_directory(
            path,
            trusted_owner=role != "read",
            private=role == "state",
        )
        device, inode, owner, group, mode = _directory_identity(metadata)
        return TrustedDirectoryBinding(
            _authority=_BINDING_AUTHORITY,
            role=role,
            path=path,
            device=device,
            inode=inode,
            owner=owner,
            group=group,
            mode=mode,
        )
    except OSError as exc:
        raise SchedulerConfigLoadError("a configured scheduler root is unsafe") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_executable(path: Path, role: ExecutableRole) -> TrustedFileBinding:
    descriptor = -1
    try:
        descriptor, metadata = _open_trusted_regular(path)
        _require_executable(metadata)
        observed, after = _sha256_stable_descriptor(
            descriptor,
            metadata,
            MAX_EXECUTABLE_BYTES,
        )
        return _file_binding(role, path, after, sha256=observed)
    except SchedulerConfigLoadError:
        raise
    except OSError as exc:
        raise SchedulerConfigLoadError("a configured executable is unsafe") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _load_nextflow_jar(path: Path, expected_sha256: str) -> TrustedFileBinding:
    descriptor = -1
    try:
        descriptor, metadata = _open_trusted_regular(path)
        _require_artifact(metadata)
        observed, after = _sha256_stable_descriptor(
            descriptor,
            metadata,
            MAX_NEXTFLOW_JAR_BYTES,
        )
        if observed != expected_sha256:
            raise SchedulerConfigLoadError("pinned Nextflow JAR does not match its SHA-256")
        return _file_binding("nextflow_jar", path, after, sha256=observed)
    except SchedulerConfigLoadError:
        raise
    except OSError as exc:
        raise SchedulerConfigLoadError("pinned Nextflow JAR is unsafe") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_trusted_regular(path: Path) -> tuple[int, os.stat_result]:
    parent, leaf = _open_trusted_parent(path)
    descriptor = -1
    try:
        descriptor = os.open(leaf, _FILE_FLAGS, dir_fd=parent)
        metadata = os.fstat(descriptor)
        current = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise OSError("trusted regular file changed")
        _require_trusted_file(metadata)
        result = descriptor
        descriptor = -1
        return result, metadata
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _open_trusted_directory(
    path: Path,
    *,
    trusted_owner: bool,
    private: bool,
) -> tuple[int, os.stat_result]:
    if not path.is_absolute() or len(path.parts) < 2:
        raise OSError("trusted directory path must be absolute")
    descriptor = os.open(Path(path.anchor), _DIRECTORY_FLAGS)
    try:
        _require_trusted_parent(os.fstat(descriptor))
        for index, part in enumerate(path.parts[1:]):
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                metadata = os.fstat(next_descriptor)
                current = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if (
                    stat.S_ISLNK(current.st_mode)
                    or not stat.S_ISDIR(metadata.st_mode)
                    or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
                ):
                    raise OSError("trusted directory changed")
                is_leaf = index == len(path.parts[1:]) - 1
                if is_leaf:
                    _require_role_root(metadata, trusted_owner=trusted_owner, private=private)
                else:
                    _require_trusted_parent(metadata)
            except BaseException:
                os.close(next_descriptor)
                raise
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, os.fstat(descriptor)
    except BaseException:
        os.close(descriptor)
        raise


def _open_trusted_parent(path: Path) -> tuple[int, str]:
    if not path.is_absolute() or len(path.parts) < 2:
        raise OSError("trusted file path must be absolute")
    descriptor = os.open(Path(path.anchor), _DIRECTORY_FLAGS)
    try:
        _require_trusted_parent(os.fstat(descriptor))
        for part in path.parts[1:-1]:
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                metadata = os.fstat(next_descriptor)
                current = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if (
                    stat.S_ISLNK(current.st_mode)
                    or not stat.S_ISDIR(metadata.st_mode)
                    or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
                ):
                    raise OSError("trusted parent changed")
                _require_trusted_parent(metadata)
            except BaseException:
                os.close(next_descriptor)
                raise
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, path.parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _require_trusted_parent(metadata: os.stat_result) -> None:
    sticky_anchor = (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid in {0, os.geteuid()}
        and bool(metadata.st_mode & stat.S_ISVTX)
    )
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or (stat.S_IMODE(metadata.st_mode) & 0o022 and not sticky_anchor)
    ):
        raise OSError("trusted parent has unsafe ownership or permissions")


def _require_trusted_file(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise OSError("trusted file has unsafe ownership or permissions")


def _require_config_file(metadata: os.stat_result) -> None:
    if metadata.st_size > MAX_SCHEDULER_CONFIG_BYTES or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise SchedulerConfigLoadError("scheduler configuration is not a bounded private file")


def _require_role_root(
    metadata: os.stat_result,
    *,
    trusted_owner: bool,
    private: bool,
) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or mode & 0o022
        or (trusted_owner and metadata.st_uid not in {0, os.geteuid()})
        or (private and mode & 0o077)
    ):
        raise OSError("configured role root has unsafe ownership or permissions")


def _require_executable(metadata: os.stat_result) -> None:
    if (
        metadata.st_size <= 0
        or metadata.st_size > MAX_EXECUTABLE_BYTES
        or not _effective_execute_permission(metadata)
    ):
        raise SchedulerConfigLoadError("configured executable is not an executable regular file")


def _effective_execute_permission(metadata: os.stat_result) -> bool:
    mode = stat.S_IMODE(metadata.st_mode)
    effective_uid = os.geteuid()
    if effective_uid == 0:
        return bool(mode & 0o111)
    if metadata.st_uid == effective_uid:
        return bool(mode & 0o100)
    effective_groups = {os.getegid(), *os.getgroups()}
    if metadata.st_gid in effective_groups:
        return bool(mode & 0o010)
    return bool(mode & 0o001)


def _require_artifact(metadata: os.stat_result) -> None:
    if metadata.st_size <= 0 or metadata.st_size > MAX_NEXTFLOW_JAR_BYTES:
        raise SchedulerConfigLoadError("pinned Nextflow JAR is outside its byte budget")


def _sha256_descriptor(descriptor: int, maximum_bytes: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while chunk := os.read(descriptor, min(1024 * 1024, maximum_bytes + 1 - total)):
        total += len(chunk)
        if total > maximum_bytes:
            raise SchedulerConfigLoadError("trusted artifact exceeds its byte budget")
        digest.update(chunk)
        if total == maximum_bytes:
            extra = os.read(descriptor, 1)
            if extra:
                raise SchedulerConfigLoadError("trusted artifact exceeds its byte budget")
            break
    return digest.hexdigest()


def _sha256_stable_descriptor(
    descriptor: int,
    before: os.stat_result,
    maximum_bytes: int,
) -> tuple[str, os.stat_result]:
    observed = _sha256_descriptor(descriptor, maximum_bytes)
    after = os.fstat(descriptor)
    if _stable_file_identity(before) != _stable_file_identity(after):
        raise SchedulerConfigLoadError("trusted scheduler file changed while it was hashed")
    return observed, after


def _read_bounded(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _file_binding(
    role: str,
    path: Path,
    metadata: os.stat_result,
    *,
    sha256: str | None = None,
) -> TrustedFileBinding:
    return TrustedFileBinding(
        _authority=_BINDING_AUTHORITY,
        role=role,
        path=path,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner=metadata.st_uid,
        group=metadata.st_gid,
        mode=stat.S_IMODE(metadata.st_mode),
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
        sha256=sha256,
    )


def _require_same_file(binding: TrustedFileBinding, metadata: os.stat_result) -> None:
    if _file_identity(metadata) != (
        binding.device,
        binding.inode,
        binding.owner,
        binding.group,
        binding.mode,
        binding.size,
        binding.mtime_ns,
        binding.ctime_ns,
    ):
        raise SchedulerConfigLoadError("trusted scheduler file changed after startup")


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stable_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return _file_identity(metadata)


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
    )


def _require_unique_identities(values: tuple[Any, ...], message: str) -> None:
    identities = [(value.device, value.inode) for value in values]
    if len(set(identities)) != len(identities):
        raise SchedulerConfigLoadError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite number is forbidden: {value}")


__all__ = [
    "MAX_EXECUTABLE_BYTES",
    "MAX_NEXTFLOW_JAR_BYTES",
    "MAX_SCHEDULER_CONFIG_BYTES",
    "SchedulerConfigLoadError",
    "TrustedDirectoryBinding",
    "TrustedFileBinding",
    "TrustedSchedulerConfig",
    "load_trusted_scheduler_config",
    "verify_scheduler_config_file",
    "verify_scheduler_executable",
    "verify_scheduler_nextflow_jar",
    "verify_scheduler_root",
]
