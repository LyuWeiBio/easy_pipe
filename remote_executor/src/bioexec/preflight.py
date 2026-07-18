"""Fixed remote runtime, path, mapping, storage, and container checks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from .commands import BoundedCommandRunner, CommandRunner, minimal_environment
from .config import (
    AgentConfig,
    ExecutableIdentity,
    verify_executable,
    verify_nextflow_jar,
)
from .errors import AgentFailure, ReturnCode
from .paths import PathGuard
from .protocol import (
    require_bool,
    require_exact_fields,
    require_identifier,
    require_int,
    require_sha256,
    require_string,
)
from .state import StateStore

_DIGEST_REFERENCE = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
)
_CHECK_NAMES = frozenset(
    {
        "cache_writable",
        "container",
        "disk_space",
        "host_relationship",
        "output_dir_writable",
        "path_mapping",
        "rawdata_readable",
        "runtime",
        "workdir_writable",
    }
)
_CONTAINER_NAMES = frozenset({"fastqc", "fastp", "multiqc"})
_REQUIRED_CONTAINER_NAMES = frozenset({"fastqc", "multiqc"})


def run_preflight(
    payload: dict[str, Any],
    config: AgentConfig,
    *,
    command_runner: CommandRunner | None = None,
    state: StateStore | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Run all nine fixed M5 checks and mint a token only on complete success."""

    required = {
        "preflight_id",
        "profile_id",
        "profile_hash",
        "project_hash",
        "artifact_hashes",
        "source_host",
        "execution_host",
        "host_relation",
        "source_paths",
        "execution_paths",
        "path_mapping",
        "deploy_dir",
        "work_dir",
        "output_dir",
        "cache_dir",
        "container_engine",
        "containers",
        "minimum_free_bytes",
        "network_disabled",
    }
    require_exact_fields(payload, required=required, optional={"resume_run_id"})
    preflight_id = require_identifier(payload["preflight_id"], "preflight_id")
    profile_id, profile_hash, project_hash, artifact_hashes = _bindings(payload, config)
    source_host = require_identifier(payload["source_host"], "source_host")
    execution_host = require_identifier(payload["execution_host"], "execution_host")
    relation = payload["host_relation"]
    if relation not in {"same", "shared"}:
        raise _schema("host_relation must be same or shared")
    if require_bool(payload["network_disabled"], "network_disabled") is not True:
        raise _schema("network_disabled must be true")
    resume_run_id = payload.get("resume_run_id")
    if resume_run_id is not None:
        resume_run_id = require_identifier(resume_run_id, "resume_run_id")

    source_paths = _path_list(payload["source_paths"], "source_paths", config.limits.max_raw_paths)
    execution_paths = _path_list(
        payload["execution_paths"], "execution_paths", config.limits.max_raw_paths
    )
    mappings = _mapping_list(payload["path_mapping"])
    deploy_dir = _absolute_request_path(payload["deploy_dir"], "deploy_dir")
    _require_direct_child(deploy_dir, config.deploy_roots, "deploy_dir")
    work_dir = _absolute_request_path(payload["work_dir"], "work_dir")
    output_dir = _absolute_request_path(payload["output_dir"], "output_dir")
    cache_dir = _absolute_request_path(payload["cache_dir"], "cache_dir")
    minimum_free = require_int(
        payload["minimum_free_bytes"],
        "minimum_free_bytes",
        config.limits.minimum_free_bytes,
        2**63 - 1,
    )
    selected_engine = payload["container_engine"]
    if selected_engine not in {"apptainer", "docker"}:
        raise _schema("container_engine must be apptainer or docker")
    containers = _containers(payload["containers"])
    if state is None:
        raise AgentFailure(
            ReturnCode.INTERNAL_ERROR,
            "STATE_INVALID",
            "preflight requires the durable state store",
        )
    client_isolation = state.create_preflight_isolation(preflight_id)
    runner = command_runner or BoundedCommandRunner()
    guard = PathGuard()
    checks: dict[str, dict[str, Any]] = {}
    input_records: list[dict[str, Any]] = []
    free_space: dict[str, int] = {}
    directory_identities: dict[str, dict[str, int]] = {}

    _capture(
        checks,
        "host_relationship",
        lambda: _validate_host_relationship(source_host, execution_host, relation),
    )
    _capture(
        checks,
        "path_mapping",
        lambda: _validate_path_mapping(relation, source_paths, execution_paths, mappings),
    )
    _capture(
        checks,
        "rawdata_readable",
        lambda: _check_inputs(execution_paths, config, guard, input_records),
    )
    is_resume = resume_run_id is not None
    _capture(
        checks,
        "workdir_writable",
        lambda: _check_work_and_deploy(
            work_dir,
            deploy_dir,
            config,
            guard,
            is_resume,
            free_space,
            directory_identities,
        ),
    )
    _capture(
        checks,
        "output_dir_writable",
        lambda: _check_storage(
            "output",
            output_dir,
            config.output_roots,
            guard,
            not is_resume,
            free_space,
            directory_identities,
            target_private=is_resume,
        ),
    )
    _capture(
        checks,
        "cache_writable",
        lambda: _check_storage(
            "cache",
            cache_dir,
            config.cache_roots,
            guard,
            False,
            free_space,
            directory_identities,
        ),
    )
    _capture(
        checks,
        "disk_space",
        lambda: _check_free_space(free_space, minimum_free),
    )
    runtime_path = (
        config.executables.apptainer
        if selected_engine == "apptainer"
        else config.executables.docker
    )
    _capture(
        checks,
        "runtime",
        lambda: _check_runtime(
            selected_engine,
            runtime_path,
            config,
            runner,
            client_isolation,
        ),
    )
    _capture(
        checks,
        "container",
        lambda: _check_containers(
            containers,
            selected_engine,
            runtime_path,
            config,
            guard,
            runner,
            client_isolation,
        ),
    )
    if set(checks) != _CHECK_NAMES:
        raise AgentFailure(
            ReturnCode.INTERNAL_ERROR,
            "PREFLIGHT_REPORT_INCOMPLETE",
            "the fixed preflight report could not be assembled",
        )

    if resume_run_id is not None and checks["path_mapping"]["status"] == "passed":
        resume_candidate = {
            "resume_run_id": resume_run_id,
            "profile_id": profile_id,
            "profile_hash": profile_hash,
            "project_hash": project_hash,
            "deploy_dir": deploy_dir,
            "work_dir": work_dir,
            "output_dir": output_dir,
            "cache_dir": cache_dir,
            "directory_identities": directory_identities,
        }
        try:
            from .runner import validate_resume_preflight

            validate_resume_preflight(resume_candidate, state)
        except AgentFailure as failure:
            checks["path_mapping"] = {
                "name": "path_mapping",
                "status": "failed",
                "code": failure.code,
                "message": "The remote check failed; review the execution profile.",
            }

    input_set_hash = _input_set_hash(execution_paths)
    passed = all(check["status"] == "passed" for check in checks.values())
    issued_at = int(time.time())
    result: dict[str, Any] = {
        "status": "passed" if passed else "failed",
        "preflight_id": preflight_id,
        "preflight_token": None,
        "input_count": len(execution_paths),
        "input_set_hash": input_set_hash,
        "checks": [checks[name] for name in sorted(checks)],
    }
    if not passed:
        return result, None

    token = secrets_token()
    record = {
        "record_version": "1.0",
        "preflight_id": preflight_id,
        "profile_id": profile_id,
        "profile_hash": profile_hash,
        "project_hash": project_hash,
        "artifact_hashes": artifact_hashes,
        "source_host": source_host,
        "execution_host": execution_host,
        "host_relation": relation,
        "input_records": input_records,
        "input_set_hash": input_set_hash,
        "deploy_dir": deploy_dir,
        "work_dir": work_dir,
        "output_dir": output_dir,
        "cache_dir": cache_dir,
        "directory_identities": directory_identities if is_resume else None,
        "container_engine": selected_engine,
        "containers": containers,
        "minimum_free_bytes": minimum_free,
        "network_disabled": True,
        "resume_run_id": resume_run_id,
        "issued_at": issued_at,
        "expires_at": issued_at + config.limits.preflight_ttl_seconds,
        "token_hash": hashlib.sha256(token.encode("ascii")).hexdigest(),
        "consumed": False,
        "status": "passed",
    }
    result["preflight_token"] = token
    return result, record


def recheck_input_records(record: dict[str, Any], config: AgentConfig) -> None:
    """Detect input replacement between successful preflight and submission."""

    values = record.get("input_records")
    if not isinstance(values, list) or not values:
        raise _preflight_failure("INPUT_RECORD_INVALID")
    guard = PathGuard()
    for item in values:
        if not isinstance(item, dict) or set(item) != {
            "path",
            "device",
            "inode",
            "size",
            "mtime_ns",
            "ctime_ns",
        }:
            raise _preflight_failure("INPUT_RECORD_INVALID")
        path = item.get("path")
        if not isinstance(path, str):
            raise _preflight_failure("INPUT_RECORD_INVALID")
        with guard.open_regular(
            path,
            config.read_roots,
            require_no_group_world_write=True,
        ) as (_fd, _authorized, current):
            observed = (
                current.st_dev,
                current.st_ino,
                current.st_size,
                current.st_mtime_ns,
                current.st_ctime_ns,
            )
        expected = (
            item.get("device"),
            item.get("inode"),
            item.get("size"),
            item.get("mtime_ns"),
            item.get("ctime_ns"),
        )
        if observed != expected:
            raise _preflight_failure("INPUT_CHANGED_AFTER_PREFLIGHT")


def recheck_container_artifacts(record: dict[str, Any], config: AgentConfig) -> None:
    """Re-hash and re-identify every preflighted local SIF immediately before run."""

    if record.get("container_engine") != "apptainer":
        return
    containers = record.get("containers")
    if not isinstance(containers, list) or not containers:
        raise _preflight_failure("CONTAINER_RECORD_INVALID")
    guard = PathGuard()
    for container in containers:
        if not isinstance(container, dict):
            raise _preflight_failure("CONTAINER_RECORD_INVALID")
        expected = container.get("_local_fingerprint")
        if not isinstance(expected, dict):
            raise _preflight_failure("CONTAINER_RECORD_INVALID")
        observed = _local_image_fingerprint(container, config, guard)
        if observed != expected:
            raise _preflight_failure("IMAGE_CHANGED_AFTER_PREFLIGHT")


def _capture(
    checks: dict[str, dict[str, Any]],
    name: str,
    function: Callable[[], None],
) -> None:
    try:
        function()
    except AgentFailure as failure:
        if failure.return_code in {
            ReturnCode.PROTOCOL_ERROR,
            ReturnCode.BUDGET_EXCEEDED,
            ReturnCode.INTERNAL_ERROR,
        }:
            raise
        checks[name] = {
            "name": name,
            "status": "failed",
            "code": failure.code,
            "message": "The remote check failed; review the execution profile.",
        }
    except (OSError, ValueError):
        checks[name] = {
            "name": name,
            "status": "failed",
            "code": "CHECK_FAILED",
            "message": "The remote check failed; review the execution profile.",
        }
    else:
        checks[name] = {"name": name, "status": "passed"}


def _bindings(
    payload: Mapping[str, Any], config: AgentConfig
) -> tuple[str, str, str, dict[str, str]]:
    profile_id = require_identifier(payload["profile_id"], "profile_id")
    profile_hash = require_sha256(payload["profile_hash"], "profile_hash")
    project_hash = require_sha256(payload["project_hash"], "project_hash")
    hashes = payload["artifact_hashes"]
    if not isinstance(hashes, dict):
        raise _schema("artifact_hashes must be an object")
    require_exact_fields(
        hashes,
        required={
            "dataset_manifest",
            "pipeline_spec",
            "execution_plan",
            "software_lock",
            "execution_profile",
        },
    )
    artifact_hashes = {
        key: require_sha256(value, f"artifact_hashes.{key}") for key, value in hashes.items()
    }
    calculated_project = _project_hash(artifact_hashes)
    if (
        profile_id != config.profile_id
        or profile_hash != config.profile_hash
        or artifact_hashes["execution_profile"] != profile_hash
        or calculated_project != project_hash
    ):
        raise _preflight_failure("PROFILE_BINDING_MISMATCH")
    return profile_id, profile_hash, project_hash, artifact_hashes


def _path_list(value: Any, field: str, maximum: int) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise _schema(f"{field} must be a non-empty bounded array")
    paths = [_absolute_request_path(item, field) for item in value]
    if len(paths) != len(set(paths)):
        raise _schema(f"{field} must not contain duplicates")
    return paths


def _mapping_list(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or len(value) > 128:
        raise _schema("path_mapping must be a bounded array")
    mappings: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            raise _schema("path_mapping entries must be objects")
        require_exact_fields(item, required={"source_prefix", "execution_prefix"})
        mappings.append(
            {
                "source_prefix": _absolute_request_path(item["source_prefix"], "source_prefix"),
                "execution_prefix": _absolute_request_path(
                    item["execution_prefix"], "execution_prefix"
                ),
            }
        )
    if len({(item["source_prefix"], item["execution_prefix"]) for item in mappings}) != len(
        mappings
    ):
        raise _schema("path_mapping must not contain duplicates")
    return mappings


def _validate_host_relationship(source_host: str, execution_host: str, relation: str) -> None:
    if (relation == "same") != (source_host == execution_host):
        raise _preflight_failure("HOST_RELATION_INVALID")


def _validate_path_mapping(
    relation: str,
    source_paths: list[str],
    execution_paths: list[str],
    mappings: list[dict[str, str]],
) -> None:
    if len(source_paths) != len(execution_paths):
        raise _preflight_failure("PATH_MAPPING_INVALID")
    if relation == "same":
        if not mappings and source_paths != execution_paths:
            raise _preflight_failure("PATH_MAPPING_INVALID")
        if not mappings:
            return
    if not mappings:
        raise _preflight_failure("PATH_MAPPING_INCOMPLETE")
    if [_map_path(path, mappings) for path in source_paths] != execution_paths:
        raise _preflight_failure("PATH_MAPPING_INVALID")


def _map_path(value: str, mappings: list[dict[str, str]]) -> str:
    source = PurePosixPath(value)
    candidates: list[tuple[int, str]] = []
    for mapping in mappings:
        prefix = PurePosixPath(mapping["source_prefix"])
        try:
            relative = source.relative_to(prefix)
        except ValueError:
            continue
        target = PurePosixPath(mapping["execution_prefix"]) / relative
        candidates.append((len(prefix.parts), str(target)))
    if not candidates:
        raise _preflight_failure("PATH_MAPPING_INCOMPLETE")
    longest = max(length for length, _target in candidates)
    targets = {target for length, target in candidates if length == longest}
    if len(targets) != 1:
        raise _preflight_failure("PATH_MAPPING_AMBIGUOUS")
    return targets.pop()


def _check_inputs(
    paths: list[str],
    config: AgentConfig,
    guard: PathGuard,
    records: list[dict[str, Any]],
) -> None:
    for path in paths:
        with guard.open_regular(
            path,
            config.read_roots,
            require_no_group_world_write=True,
        ) as (_descriptor, _authorized, item):
            records.append(
                {
                    "path": path,
                    "device": item.st_dev,
                    "inode": item.st_ino,
                    "size": item.st_size,
                    "mtime_ns": item.st_mtime_ns,
                    "ctime_ns": item.st_ctime_ns,
                }
            )


def _check_work_and_deploy(
    work_dir: str,
    deploy_dir: str,
    config: AgentConfig,
    guard: PathGuard,
    is_resume: bool,
    free_space: dict[str, int],
    directory_identities: dict[str, dict[str, int]],
) -> None:
    _check_storage(
        "work",
        work_dir,
        config.work_roots,
        guard,
        not is_resume,
        free_space,
        directory_identities,
        target_private=is_resume,
    )
    if is_resume:
        with guard.open_directory(
            deploy_dir,
            config.deploy_roots,
            require_trusted_owner=True,
            require_no_group_world_write=True,
        ) as (directory, _authorized):
            filesystem = os.fstatvfs(directory)
            free_space["deploy"] = filesystem.f_bavail * filesystem.f_frsize
    else:
        _check_storage(
            "deploy",
            deploy_dir,
            config.deploy_roots,
            guard,
            True,
            free_space,
            directory_identities,
        )


def _check_storage(
    label: str,
    path: str,
    roots: Any,
    guard: PathGuard,
    must_be_absent: bool,
    free_space: dict[str, int],
    directory_identities: dict[str, dict[str, int]],
    *,
    target_private: bool = False,
) -> None:
    _authorized, available, identity = guard.test_writable_parent(
        path,
        roots,
        target_must_be_absent=must_be_absent,
        target_private=target_private,
    )
    free_space[label] = available
    if label in {"work", "output"} and identity is not None:
        directory_identities[label] = identity


def _check_free_space(free_space: dict[str, int], minimum: int) -> None:
    if set(free_space) != {"deploy", "work", "output", "cache"}:
        raise _preflight_failure("SPACE_UNVERIFIED")
    if any(available < minimum for available in free_space.values()):
        raise _preflight_failure("INSUFFICIENT_SPACE")


def _check_runtime(
    engine: str,
    runtime_path: Path | None,
    config: AgentConfig,
    runner: CommandRunner,
    client_isolation: dict[str, Path],
) -> None:
    if runtime_path is None:
        raise _preflight_failure("CONTAINER_RUNTIME_UNAVAILABLE")
    runtime_identity = _runtime_identity(engine, config)
    verify_nextflow_jar(config)
    checks: tuple[tuple[str, ...], ...] = (
        (str(config.executables.java), "-version"),
        (str(config.executables.nextflow), "-version"),
        (
            (str(runtime_path), "--version")
            if engine == "apptainer"
            else (str(runtime_path), "version", "--format", "{{json .Server.Version}}")
        ),
    )
    environment = minimal_environment(
        executable_paths=(runtime_path, config.executables.java, config.executables.nextflow),
        extra=_client_environment(config, client_isolation),
    )
    for argv in checks:
        executable = Path(argv[0])
        identity = {
            config.executables.java: config.executables.java_identity,
            config.executables.nextflow: config.executables.nextflow_identity,
            runtime_path: runtime_identity,
        }[executable]
        verify_executable(executable, identity)
        result = runner.run(
            argv,
            cwd=config.state_root.path,
            env=environment,
            timeout_seconds=config.limits.command_timeout_seconds,
            output_limit_bytes=config.limits.max_command_output_bytes,
        )
        if result.timed_out:
            raise _preflight_failure("RUNTIME_CHECK_TIMEOUT")
        if result.output_limit_exceeded or result.return_code != 0:
            raise _preflight_failure("RUNTIME_UNAVAILABLE")
        if executable == config.executables.nextflow and not _version_present(
            config.nextflow_version,
            result.stdout + "\n" + result.stderr,
        ):
            raise _preflight_failure("NEXTFLOW_VERSION_MISMATCH")


def _containers(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise _schema("containers must be a bounded non-empty array")
    result: list[dict[str, Any]] = []
    names: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            raise _schema("container entries must be objects")
        require_exact_fields(
            item,
            required={"name", "image", "digest", "local_path", "file_sha256"},
        )
        name = require_identifier(item["name"], "container.name")
        image = require_string(item["image"], "container.image", maximum_bytes=512)
        digest = require_string(item["digest"], "container.digest", maximum_bytes=128)
        if name in names or not _IMAGE.fullmatch(image) or not _DIGEST_REFERENCE.fullmatch(digest):
            raise _schema("container identity is invalid or duplicated")
        names.add(name)
        local_path = item["local_path"]
        file_sha256 = item["file_sha256"]
        if (local_path is None) != (file_sha256 is None):
            raise _schema("container local_path and file_sha256 must appear together")
        if local_path is not None:
            local_path = _absolute_request_path(local_path, "container.local_path")
            file_sha256 = require_sha256(file_sha256, "container.file_sha256")
        result.append(
            {
                "name": name,
                "image": image,
                "digest": digest,
                "local_path": local_path,
                "file_sha256": file_sha256,
            }
        )
    if not _REQUIRED_CONTAINER_NAMES.issubset(names) or not names.issubset(_CONTAINER_NAMES):
        raise _schema("containers do not match the fixed FASTQ-QC component set")
    return result


def _check_containers(
    containers: list[dict[str, Any]],
    engine: str,
    runtime_path: Path | None,
    config: AgentConfig,
    guard: PathGuard,
    runner: CommandRunner,
    client_isolation: dict[str, Path],
) -> None:
    if runtime_path is None:
        raise _preflight_failure("CONTAINER_RUNTIME_UNAVAILABLE")
    for container in containers:
        _check_container(
            container,
            engine,
            runtime_path,
            config,
            guard,
            runner,
            client_isolation,
        )


def _check_container(
    container: dict[str, Any],
    engine: str,
    runtime_path: Path,
    config: AgentConfig,
    guard: PathGuard,
    runner: CommandRunner,
    client_isolation: dict[str, Path],
) -> None:
    verify_executable(runtime_path, _runtime_identity(engine, config))
    environment = minimal_environment(
        executable_paths=(runtime_path, config.executables.java),
        extra=_client_environment(config, client_isolation),
    )
    argv: tuple[str, ...]
    if engine == "apptainer":
        local_path = container["local_path"]
        expected = container["file_sha256"]
        if not isinstance(local_path, str) or not isinstance(expected, str):
            raise _preflight_failure("IMAGE_LOCAL_ARTIFACT_REQUIRED")
        fingerprint = _local_image_fingerprint(container, config, guard)
        if fingerprint["sha256"] != expected:
            raise _preflight_failure("IMAGE_DIGEST_MISMATCH")
        container["_local_fingerprint"] = fingerprint
        argv = (str(runtime_path), "inspect", "--json", local_path)
    else:
        if container["local_path"] is not None:
            raise _schema("docker containers must not provide a local artifact path")
        reference = f"{container['image']}@{container['digest']}"
        argv = (
            str(runtime_path),
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}",
            reference,
        )
    result = runner.run(
        argv,
        cwd=config.state_root.path,
        env=environment,
        timeout_seconds=config.limits.command_timeout_seconds,
        output_limit_bytes=config.limits.max_command_output_bytes,
    )
    if result.timed_out or result.output_limit_exceeded or result.return_code != 0:
        raise _preflight_failure("IMAGE_UNAVAILABLE")
    if engine == "docker" and container["digest"] not in result.stdout:
        raise _preflight_failure("IMAGE_DIGEST_MISMATCH")


def _local_image_fingerprint(
    container: dict[str, Any],
    config: AgentConfig,
    guard: PathGuard,
) -> dict[str, Any]:
    local_path = container.get("local_path")
    if not isinstance(local_path, str):
        raise _preflight_failure("IMAGE_LOCAL_ARTIFACT_REQUIRED")
    with guard.open_regular(
        local_path,
        config.cache_roots,
        require_trusted_owner=True,
        require_no_group_world_write=True,
    ) as (descriptor, _authorized, before):
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after or size != before.st_size:
        raise _preflight_failure("IMAGE_CHANGED_DURING_CHECK")
    return {
        "device": before.st_dev,
        "inode": before.st_ino,
        "size": before.st_size,
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
        "sha256": digest.hexdigest(),
    }


def _runtime_identity(engine: str, config: AgentConfig) -> ExecutableIdentity | None:
    return (
        config.executables.apptainer_identity
        if engine == "apptainer"
        else config.executables.docker_identity
    )


def _client_environment(
    config: AgentConfig,
    isolation: dict[str, Path],
) -> dict[str, str]:
    if set(isolation) != {
        "client-home",
        "docker-config",
        "apptainer-config",
        "nxf-home",
        "tmp",
    }:
        raise AgentFailure(
            ReturnCode.INTERNAL_ERROR,
            "CLIENT_ISOLATION_INVALID",
            "private client isolation directories are unavailable",
        )
    return {
        "HOME": str(isolation["client-home"]),
        "JAVA_CMD": str(config.executables.java),
        "NXF_HOME": str(isolation["nxf-home"]),
        "NXF_BIN": str(config.nextflow_jar),
        "NXF_VER": config.nextflow_version,
        "NXF_TEMP": str(isolation["tmp"]),
        "TMPDIR": str(isolation["tmp"]),
        "DOCKER_CONFIG": str(isolation["docker-config"]),
        "DOCKER_HOST": "unix:///var/run/docker.sock",
        "APPTAINER_CONFIGDIR": str(isolation["apptainer-config"]),
        "SINGULARITY_CONFIGDIR": str(isolation["apptainer-config"]),
    }


def _version_present(expected: str, output: str) -> bool:
    return (
        re.search(
            rf"(?<![A-Za-z0-9_.-]){re.escape(expected)}(?![A-Za-z0-9_.-])",
            output,
        )
        is not None
    )


def _absolute_request_path(value: Any, field: str) -> str:
    text = require_string(value, field)
    path = PurePosixPath(text)
    if not path.is_absolute() or ".." in path.parts or str(path) != text or text == "/":
        raise _schema(f"{field} must be a normalized non-root absolute POSIX path")
    return text


def _input_set_hash(paths: list[str]) -> str:
    payload = json.dumps(
        sorted(set(paths)),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _project_hash(hashes: Mapping[str, str]) -> str:
    canonical = json.dumps(
        {
            "dataset_manifest": hashes["dataset_manifest"],
            "execution_plan": hashes["execution_plan"],
            "pipeline_spec": hashes["pipeline_spec"],
            "software_lock": hashes["software_lock"],
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def _require_direct_child(path: str, roots: Any, field: str) -> None:
    authorized = PathGuard().authorize(path, roots)
    if len(authorized.relative_parts) != 1:
        raise _schema(f"{field} must be a direct child of a configured role root")


def secrets_token() -> str:
    import secrets

    return secrets.token_hex(32)


def _schema(message: str) -> AgentFailure:
    return AgentFailure(ReturnCode.PROTOCOL_ERROR, "SCHEMA_ERROR", message)


def _preflight_failure(code: str) -> AgentFailure:
    return AgentFailure(
        ReturnCode.PREFLIGHT_FAILED,
        code,
        "a fixed remote preflight check failed",
        remediation=["Correct the execution profile or remote runtime before retrying."],
    )


__all__ = ["recheck_container_artifacts", "recheck_input_records", "run_preflight"]
