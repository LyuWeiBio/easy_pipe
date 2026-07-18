"""Fail-closed configuration for the fixed execution agent."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path, PurePath
from typing import Any, cast

from .errors import AgentFailure, ReturnCode

CONFIG_ENV = "BIOEXEC_CONFIG"
MAX_CONFIG_BYTES = 1_048_576
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


@dataclass(frozen=True)
class Limits:
    """Server-enforced ceilings which requests cannot raise."""

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


@dataclass(frozen=True)
class ConfiguredRoot:
    """Canonical configured directory and its startup identity."""

    path: Path
    device: int
    inode: int


@dataclass(frozen=True)
class ExecutableIdentity:
    """Immutable identity of one reviewed executable leaf."""

    device: int
    inode: int
    owner: int
    mode: int


@dataclass(frozen=True)
class Executables:
    """Absolute reviewed executable paths used in fixed argv only."""

    java: Path
    nextflow: Path
    apptainer: Path | None = None
    docker: Path | None = None
    java_identity: ExecutableIdentity | None = None
    nextflow_identity: ExecutableIdentity | None = None
    apptainer_identity: ExecutableIdentity | None = None
    docker_identity: ExecutableIdentity | None = None


@dataclass(frozen=True)
class AgentConfig:
    """Complete immutable policy loaded before accepting requests."""

    profile_id: str
    profile_hash: str
    read_roots: tuple[ConfiguredRoot, ...]
    deploy_roots: tuple[ConfiguredRoot, ...]
    work_roots: tuple[ConfiguredRoot, ...]
    output_roots: tuple[ConfiguredRoot, ...]
    cache_roots: tuple[ConfiguredRoot, ...]
    state_root: ConfiguredRoot
    executables: Executables
    nextflow_version: str
    nextflow_jar: Path
    nextflow_jar_sha256: str
    nextflow_jar_identity: ExecutableIdentity
    approval_key_id: str
    approval_hmac_key: bytes = dataclass_field(repr=False)
    limits: Limits = Limits()


def discover_config_path() -> Path:
    value = os.environ.get(CONFIG_ENV)
    if value is not None:
        if _unsafe_text(value):
            raise _config_error("BIOEXEC_CONFIG must name an absolute configuration file")
        override = Path(value)
        if not override.is_absolute():
            raise _config_error("BIOEXEC_CONFIG must be absolute")
        return override
    candidates: list[Path] = []
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg is not None:
        if _unsafe_text(xdg) or not Path(xdg).is_absolute():
            raise _config_error("XDG_CONFIG_HOME must be a safe absolute path")
        candidates.append(Path(xdg) / "bioexec" / "config.json")
    try:
        candidates.append(Path.home() / ".config" / "bioexec" / "config.json")
    except RuntimeError as exc:
        raise _config_error("the agent account home directory is unavailable") from exc
    candidates.append(Path("/etc/bioexec/config.json"))
    for candidate in candidates:
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise _config_error("a default configuration candidate is unsafe") from exc
        return candidate
    raise _config_error("no bioexec configuration file was found")


def load_config(path: Path | None = None) -> AgentConfig:
    """Load a strict non-symlink JSON configuration."""

    selected = discover_config_path() if path is None else path
    if not selected.is_absolute():
        raise _config_error("config path must be absolute")
    try:
        descriptor, metadata = _open_trusted_regular(selected)
    except (OSError, AgentFailure) as exc:
        raise _config_error("configuration cannot be opened safely") from exc
    try:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > MAX_CONFIG_BYTES
            or metadata.st_mode & 0o077
            or metadata.st_uid not in {0, os.geteuid()}
        ):
            raise _config_error("configuration must be a bounded regular file")
        payload = _read_bounded(descriptor, MAX_CONFIG_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_CONFIG_BYTES:
        raise _config_error("configuration exceeds the size limit")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise _config_error("configuration must be strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise _config_error("configuration must be an object")
    return _parse_config(value)


def _parse_config(value: dict[str, Any]) -> AgentConfig:
    _exact_keys(
        value,
        {
            "schema_version",
            "profile_id",
            "profile_hash",
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
        },
        "configuration",
    )
    if value["schema_version"] != "1.0":
        raise _config_error("unsupported configuration schema_version")
    profile_id = _identifier(value["profile_id"], "profile_id")
    profile_hash = _digest(value["profile_hash"], "profile_hash")
    read_roots = _roots(value["read_roots"], "read_roots", trusted_owner=False)
    deploy_roots = _roots(value["deploy_roots"], "deploy_roots", trusted_owner=True)
    work_roots = _roots(value["work_roots"], "work_roots", trusted_owner=True)
    output_roots = _roots(value["output_roots"], "output_roots", trusted_owner=True)
    cache_roots = _roots(value["cache_roots"], "cache_roots", trusted_owner=True)
    state_root = _root(
        value["state_root"],
        "state_root",
        trusted_owner=True,
        private=True,
    )
    _validate_role_separation(
        read_roots,
        deploy_roots,
        work_roots,
        output_roots,
        cache_roots,
        state_root,
    )
    executables = _executables(value["executables"])
    nextflow_version = _identifier(value["nextflow_version"], "nextflow_version")
    nextflow_jar_sha256 = _digest(value["nextflow_jar_sha256"], "nextflow_jar_sha256")
    nextflow_jar, nextflow_jar_identity = _trusted_artifact(
        value["nextflow_jar"],
        "nextflow_jar",
        nextflow_jar_sha256,
    )
    approval_key_id = _identifier(value["approval_key_id"], "approval_key_id")
    approval_key_hex = _digest(value["approval_hmac_key"], "approval_hmac_key")
    if approval_key_hex == "0" * 64:
        raise _config_error("approval_hmac_key must not be an all-zero placeholder")
    limits = _limits(value["limits"])
    return AgentConfig(
        profile_id=profile_id,
        profile_hash=profile_hash,
        read_roots=read_roots,
        deploy_roots=deploy_roots,
        work_roots=work_roots,
        output_roots=output_roots,
        cache_roots=cache_roots,
        state_root=state_root,
        executables=executables,
        nextflow_version=nextflow_version,
        nextflow_jar=nextflow_jar,
        nextflow_jar_sha256=nextflow_jar_sha256,
        nextflow_jar_identity=nextflow_jar_identity,
        approval_key_id=approval_key_id,
        approval_hmac_key=bytes.fromhex(approval_key_hex),
        limits=limits,
    )


def _executables(value: Any) -> Executables:
    if not isinstance(value, dict):
        raise _config_error("executables must be an object")
    required = {"java", "nextflow", "apptainer", "docker"}
    _exact_keys(value, required, "executables")
    java, java_identity = _executable(value["java"], "java")
    nextflow, nextflow_identity = _executable(value["nextflow"], "nextflow")
    apptainer, apptainer_identity = _optional_executable(value["apptainer"], "apptainer")
    docker, docker_identity = _optional_executable(value["docker"], "docker")
    return Executables(
        java=java,
        nextflow=nextflow,
        apptainer=apptainer,
        docker=docker,
        java_identity=java_identity,
        nextflow_identity=nextflow_identity,
        apptainer_identity=apptainer_identity,
        docker_identity=docker_identity,
    )


def _executable(value: Any, field: str) -> tuple[Path, ExecutableIdentity]:
    if not isinstance(value, str):
        raise _config_error(f"{field} executable must be a string")
    path = _absolute_path(value, f"executables.{field}")
    if os.pathsep in str(path.parent):
        raise _config_error(f"{field} executable parent cannot be represented in PATH")
    if path.name != field:
        raise _config_error(f"{field} executable must use the fixed {field!r} leaf name")
    try:
        descriptor, metadata = _open_trusted_regular(path)
    except (OSError, AgentFailure) as exc:
        raise _config_error(f"{field} executable is unavailable") from exc
    try:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not os.access(path, os.X_OK)
            or metadata.st_mode & 0o022
            or metadata.st_uid not in {0, os.geteuid()}
        ):
            raise _config_error(f"{field} executable must be a trusted non-symlink file")
        identity = _executable_identity(metadata)
    finally:
        os.close(descriptor)
    return path, identity


def _optional_executable(
    value: Any,
    field: str,
) -> tuple[Path | None, ExecutableIdentity | None]:
    return (None, None) if value is None else _executable(value, field)


def _trusted_artifact(
    value: Any,
    field: str,
    expected_sha256: str,
) -> tuple[Path, ExecutableIdentity]:
    if not isinstance(value, str):
        raise _config_error(f"{field} must be a string")
    path = _absolute_path(value, field)
    try:
        descriptor, metadata = _open_trusted_regular(path)
    except OSError as exc:
        raise _config_error(f"{field} is unavailable") from exc
    try:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_mode & 0o022
            or metadata.st_uid not in {0, os.geteuid()}
            or _sha256_descriptor(descriptor) != expected_sha256
        ):
            raise _config_error(f"{field} must be the exact trusted pinned artifact")
        identity = _executable_identity(metadata)
    finally:
        os.close(descriptor)
    return path, identity


def verify_executable(path: Path, identity: ExecutableIdentity | None) -> None:
    """Re-open a reviewed executable and require its exact startup identity."""

    if identity is None:
        raise AgentFailure(
            ReturnCode.PREFLIGHT_FAILED,
            "EXECUTABLE_IDENTITY_MISSING",
            "reviewed executable identity evidence is unavailable",
        )
    try:
        descriptor, metadata = _open_trusted_regular(path)
    except OSError as exc:
        raise AgentFailure(
            ReturnCode.PREFLIGHT_FAILED,
            "EXECUTABLE_CHANGED",
            "a reviewed executable or its trusted parent chain changed",
        ) from exc
    try:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not os.access(path, os.X_OK)
            or metadata.st_mode & 0o022
            or metadata.st_uid not in {0, os.geteuid()}
            or _executable_identity(metadata) != identity
        ):
            raise AgentFailure(
                ReturnCode.PREFLIGHT_FAILED,
                "EXECUTABLE_CHANGED",
                "a reviewed executable or its trusted parent chain changed",
            )
    finally:
        os.close(descriptor)


def verify_nextflow_jar(config: AgentConfig) -> None:
    """Re-open and fully hash the pinned offline Nextflow launcher JAR."""

    try:
        descriptor, metadata = _open_trusted_regular(config.nextflow_jar)
    except OSError as exc:
        raise AgentFailure(
            ReturnCode.PREFLIGHT_FAILED,
            "NEXTFLOW_JAR_CHANGED",
            "the pinned offline Nextflow JAR or its trusted parent chain changed",
        ) from exc
    try:
        if (
            metadata.st_size <= 0
            or metadata.st_mode & 0o022
            or metadata.st_uid not in {0, os.geteuid()}
            or _executable_identity(metadata) != config.nextflow_jar_identity
            or _sha256_descriptor(descriptor) != config.nextflow_jar_sha256
        ):
            raise AgentFailure(
                ReturnCode.PREFLIGHT_FAILED,
                "NEXTFLOW_JAR_CHANGED",
                "the pinned offline Nextflow JAR or its trusted parent chain changed",
            )
    finally:
        os.close(descriptor)


def _sha256_descriptor(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _open_trusted_regular(path: Path) -> tuple[int, os.stat_result]:
    """Open an absolute leaf through a no-follow, trusted directory walk."""

    if not path.is_absolute() or len(path.parts) < 2:
        raise OSError("trusted leaf path must be absolute")
    directory = os.open(Path(path.anchor), _DIRECTORY_FLAGS)
    leaf_descriptor = -1
    try:
        _require_trusted_directory(os.fstat(directory))
        for part in path.parts[1:-1]:
            next_directory = os.open(part, _DIRECTORY_FLAGS, dir_fd=directory)
            try:
                opened = os.fstat(next_directory)
                current = os.stat(part, dir_fd=directory, follow_symlinks=False)
                if (
                    stat.S_ISLNK(current.st_mode)
                    or not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                ):
                    raise OSError("trusted path parent changed")
                _require_trusted_directory(opened)
            except BaseException:
                os.close(next_directory)
                raise
            os.close(directory)
            directory = next_directory
        leaf = path.parts[-1]
        leaf_descriptor = os.open(leaf, _FILE_FLAGS, dir_fd=directory)
        metadata = os.fstat(leaf_descriptor)
        current = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise OSError("trusted leaf changed")
        result = leaf_descriptor
        leaf_descriptor = -1
        return result, metadata
    finally:
        if leaf_descriptor >= 0:
            os.close(leaf_descriptor)
        os.close(directory)


def _require_trusted_directory(metadata: os.stat_result) -> None:
    sticky_root_anchor = (
        metadata.st_uid in {0, os.geteuid()}
        and bool(metadata.st_mode & stat.S_ISVTX)
        and stat.S_ISDIR(metadata.st_mode)
    )
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or (metadata.st_mode & 0o022 and not sticky_root_anchor)
    ):
        raise OSError("trusted path parent has unsafe ownership or permissions")


def _executable_identity(metadata: os.stat_result) -> ExecutableIdentity:
    return ExecutableIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        owner=metadata.st_uid,
        mode=stat.S_IMODE(metadata.st_mode),
    )


def _limits(value: Any) -> Limits:
    if not isinstance(value, dict):
        raise _config_error("limits must be an object")
    allowed = {
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
    if set(value) - allowed:
        raise _config_error("limits contains unsupported fields")
    defaults = Limits()
    return Limits(
        max_request_bytes=_bounded_int(
            value, "max_request_bytes", defaults.max_request_bytes, 1024, 128 * 1024 * 1024
        ),
        max_response_bytes=_bounded_int(
            value, "max_response_bytes", defaults.max_response_bytes, 512, 16 * 1024 * 1024
        ),
        max_deployment_files=_bounded_int(
            value, "max_deployment_files", defaults.max_deployment_files, 1, 1024
        ),
        max_file_bytes=_bounded_int(
            value, "max_file_bytes", defaults.max_file_bytes, 1, 32 * 1024 * 1024
        ),
        max_deployment_bytes=_bounded_int(
            value,
            "max_deployment_bytes",
            defaults.max_deployment_bytes,
            1,
            128 * 1024 * 1024,
        ),
        max_raw_paths=_bounded_int(value, "max_raw_paths", defaults.max_raw_paths, 1, 1_000_000),
        max_command_output_bytes=_bounded_int(
            value,
            "max_command_output_bytes",
            defaults.max_command_output_bytes,
            1024,
            16 * 1024 * 1024,
        ),
        command_timeout_seconds=_bounded_number(
            value,
            "command_timeout_seconds",
            defaults.command_timeout_seconds,
            1.0,
            3600.0,
        ),
        run_timeout_seconds=_bounded_number(
            value,
            "run_timeout_seconds",
            defaults.run_timeout_seconds,
            1.0,
            31 * 24 * 60 * 60.0,
        ),
        preflight_ttl_seconds=_bounded_int(
            value, "preflight_ttl_seconds", defaults.preflight_ttl_seconds, 1, 86_400
        ),
        minimum_free_bytes=_bounded_int(
            value,
            "minimum_free_bytes",
            defaults.minimum_free_bytes,
            1024 * 1024,
            2**63 - 1,
        ),
    )


def _roots(
    value: Any,
    field: str,
    *,
    trusted_owner: bool,
) -> tuple[ConfiguredRoot, ...]:
    if not isinstance(value, list) or not value or len(value) > 128:
        raise _config_error(f"{field} must be a non-empty bounded array")
    roots = tuple(_root(item, field, trusted_owner=trusted_owner, private=False) for item in value)
    if len({root.path for root in roots}) != len(roots):
        raise _config_error(f"{field} contains duplicate canonical roots")
    return roots


def _root(
    value: Any,
    field: str,
    *,
    trusted_owner: bool,
    private: bool,
) -> ConfiguredRoot:
    if not isinstance(value, str):
        raise _config_error(f"{field} paths must be strings")
    path = _absolute_path(value, field)
    try:
        before = path.lstat()
        canonical = path.resolve(strict=True)
        opened = canonical.stat()
        final = path.lstat()
    except OSError as exc:
        raise _config_error(f"{field} path is unavailable") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or stat.S_ISLNK(final.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or (before.st_dev, before.st_ino) != (final.st_dev, final.st_ino)
        or (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
        or opened.st_mode & 0o022
        or (trusted_owner and opened.st_uid not in {0, os.geteuid()})
        or (private and opened.st_mode & 0o077)
    ):
        raise _config_error(f"{field} must be a trusted stable non-symlink directory")
    return ConfiguredRoot(path=canonical, device=opened.st_dev, inode=opened.st_ino)


def _validate_role_separation(
    read: tuple[ConfiguredRoot, ...],
    deploy: tuple[ConfiguredRoot, ...],
    work: tuple[ConfiguredRoot, ...],
    output: tuple[ConfiguredRoot, ...],
    cache: tuple[ConfiguredRoot, ...],
    state: ConfiguredRoot,
) -> None:
    writable = (*deploy, *work, *output, *cache, state)
    if any(
        _overlap(first.path, second.path) or _same_root_identity(first, second)
        for first in read
        for second in writable
    ):
        raise _config_error("read roots must not overlap writable execution roots")
    groups = (deploy, work, output, cache, (state,))
    for index, group in enumerate(groups):
        for other in groups[index + 1 :]:
            if any(
                _overlap(first.path, second.path) or _same_root_identity(first, second)
                for first in group
                for second in other
            ):
                raise _config_error("writable execution root roles must not overlap")


def _absolute_path(value: str, field: str) -> Path:
    if _unsafe_text(value) or len(value.encode("utf-8")) > 4096:
        raise _config_error(f"{field} contains unsafe path text")
    pure = PurePath(value)
    if not pure.is_absolute() or ".." in pure.parts:
        raise _config_error(f"{field} must be an absolute path without traversal")
    return Path(os.path.normpath(value))


def _identifier(value: Any, field: str) -> str:
    import re

    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", value):
        raise _config_error(f"{field} must be a safe identifier")
    return value


def _digest(value: Any, field: str) -> str:
    import re

    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise _config_error(f"{field} must be a lowercase SHA-256 digest")
    return value


def _bounded_int(values: dict[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
    value = values.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise _config_error(f"limits.{key} is outside its supported range")
    return cast(int, value)


def _bounded_number(
    values: dict[str, Any], key: str, default: float, minimum: float, maximum: float
) -> float:
    value = values.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _config_error(f"limits.{key} must be numeric")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise _config_error(f"limits.{key} is outside its supported range")
    return result


def _exact_keys(value: dict[str, Any], expected: set[str], field: str) -> None:
    if set(value) != expected:
        raise _config_error(f"{field} fields do not match the fixed schema")


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


def _overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _same_root_identity(first: ConfiguredRoot, second: ConfiguredRoot) -> bool:
    return (first.device, first.inode) == (second.device, second.inode)


def _unsafe_text(value: str) -> bool:
    return not value or any(ord(character) < 32 or ord(character) == 127 for character in value)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite number is forbidden: {value}")


def _config_error(message: str) -> AgentFailure:
    return AgentFailure(
        ReturnCode.PROTOCOL_ERROR,
        "CONFIG_INVALID",
        message,
        remediation=["Install a reviewed bioexec configuration before retrying."],
    )


__all__ = [
    "CONFIG_ENV",
    "AgentConfig",
    "ConfiguredRoot",
    "ExecutableIdentity",
    "Executables",
    "Limits",
    "load_config",
    "verify_executable",
    "verify_nextflow_jar",
]
