"""Fixed, dependency-free compute-node preflight worker for dormant M7.

The worker is a separate hash-bound artifact.  It accepts only the five
arguments rendered by :mod:`bioexec.scheduler_preflight`, reads one canonical
owner-only manifest without following links, performs the twelve fixed checks,
and publishes one create-only evidence file.  A complete failed check report is
still a successful worker execution; malformed trust inputs and uncertain
evidence commits exit nonzero without claiming scheduler success.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, Any, cast

from .scheduler_preflight import (
    COMPUTE_CHECK_NAMES,
    EVIDENCE_VERSION,
    WORKER_CONTRACT_VERSION,
    ComputePreflightEvidence,
    ComputePreflightManifest,
    ResumeDirectoryIdentity,
    canonical_evidence_bytes,
    canonical_manifest_bytes,
    input_set_hash,
    parse_compute_evidence,
    parse_compute_manifest,
)
from .slurm import SlurmContractError, SlurmJobRef

WORKER_FAILURE_EXIT = 70

_MAX_MANIFEST_BYTES = 128 * 1024 * 1024
_MAX_EVIDENCE_BYTES = 256 * 1024
_MAX_EXECUTABLE_BYTES = 128 * 1024 * 1024
_MAX_JAR_BYTES = 128 * 1024 * 1024
_MAX_ARTIFACT_BYTES = 2**63 - 1
_READ_CHUNK_BYTES = 1024 * 1024
_COMMAND_READ_BYTES = 64 * 1024
_PROCESS_EXIT_DRAIN_SECONDS = 0.50
_TERMINATE_GRACE_SECONDS = 0.25
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_JOB_ID = re.compile(r"[1-9][0-9]{0,127}", re.ASCII)
_VERSION_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", re.ASCII)
_TIME_LIMIT = re.compile(
    r"(?:(?P<days>[1-9][0-9]?)-)?"
    r"(?P<hours>[0-2][0-9]):(?P<minutes>[0-5][0-9]):(?P<seconds>[0-5][0-9])",
    re.ASCII,
)
_SAFE_ARGUMENT_PATH = re.compile(r"/[A-Za-z0-9_./-]{1,4094}", re.ASCII)
_ARGUMENTS = (
    "--contract-version=",
    "--manifest=",
    "--manifest-sha256=",
    "--worker-sha256=",
    "--evidence=",
)
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_CREATE_FLAGS = (
    os.O_CREAT
    | os.O_EXCL
    | os.O_WRONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


class ComputeWorkerError(RuntimeError):
    """The worker cannot produce trustworthy complete evidence."""


class ComputeWorkerCommitUnknown(ComputeWorkerError):
    """The create-only evidence file may be incomplete or not durable."""


class _CheckFailure(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__("a fixed compute check failed")


@dataclass(frozen=True)
class WorkerInvocation:
    contract_version: str
    manifest_path: str
    manifest_sha256: str
    worker_sha256: str
    evidence_path: str


@dataclass(frozen=True)
class _CommandResult:
    return_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_limit_exceeded: bool


CommandRunner = Callable[
    [tuple[str, ...], Path, Mapping[str, str], float, int],
    _CommandResult,
]


@dataclass(frozen=True)
class _WorkerContext:
    invocation: WorkerInvocation
    manifest: ComputePreflightManifest
    job: SlurmJobRef
    environment: Mapping[str, str]
    parent_path: Path
    isolation: Mapping[str, Path] | None
    command_runner: CommandRunner


def parse_worker_argv(argv: list[str]) -> WorkerInvocation:
    """Parse exactly the ordered fixed-template argument vector."""

    if not isinstance(argv, list) or len(argv) != len(_ARGUMENTS):
        raise ComputeWorkerError("worker arguments do not match the fixed contract")
    values: list[str] = []
    for index, prefix in enumerate(_ARGUMENTS):
        argument = argv[index]
        if not isinstance(argument, str) or not argument.startswith(prefix):
            raise ComputeWorkerError("worker arguments do not match the fixed contract")
        value = argument[len(prefix) :]
        if not value:
            raise ComputeWorkerError("worker arguments do not match the fixed contract")
        values.append(value)
    contract_version, manifest_path, manifest_sha256, worker_sha256, evidence_path = values
    if contract_version != WORKER_CONTRACT_VERSION:
        raise ComputeWorkerError("worker contract version is unsupported")
    _argument_path(manifest_path, "manifest.json")
    _argument_path(evidence_path, "evidence.json")
    if PurePosixPath(manifest_path).parent != PurePosixPath(evidence_path).parent:
        raise ComputeWorkerError("worker manifest and evidence must share one private parent")
    if not _valid_digest(manifest_sha256) or not _valid_digest(worker_sha256):
        raise ComputeWorkerError("worker digest argument is invalid")
    return WorkerInvocation(
        contract_version=contract_version,
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha256,
        worker_sha256=worker_sha256,
        evidence_path=evidence_path,
    )


def run_worker(
    invocation: WorkerInvocation,
    *,
    environment: Mapping[str, str],
    worker_path: str,
    python_path: str,
    command_runner: CommandRunner | None = None,
) -> ComputePreflightEvidence:
    """Run all fixed checks and durably publish one exact evidence record."""

    if not isinstance(invocation, WorkerInvocation):
        raise ComputeWorkerError("validated worker invocation is required")
    parent_path = Path(invocation.manifest_path).parent
    parent = _open_absolute_directory(parent_path)
    try:
        parent_identity = _require_private_directory(parent)
        _require_current_directory(parent_identity)
        raw_manifest = _read_private_file(
            parent,
            Path(invocation.manifest_path).name,
            _MAX_MANIFEST_BYTES,
        )
        if hashlib.sha256(raw_manifest).hexdigest() != invocation.manifest_sha256:
            raise ComputeWorkerError("compute manifest does not match its requested SHA-256")
        manifest = _decode_manifest(raw_manifest)
        if canonical_manifest_bytes(manifest) != raw_manifest:
            raise ComputeWorkerError("compute manifest bytes are not canonical")
        _bind_invocation(invocation, manifest, worker_path)
        _verify_trust_executable(
            worker_path,
            invocation.worker_sha256,
            _MAX_EXECUTABLE_BYTES,
        )
        if python_path != manifest.compute_runtime.python_executable:
            raise ComputeWorkerError("running Python does not match the trusted manifest")
        _verify_trust_executable(
            python_path,
            manifest.compute_runtime.python_sha256,
            _MAX_EXECUTABLE_BYTES,
        )
        evidence_leaf = Path(invocation.evidence_path).name
        _require_absent(parent, evidence_leaf)
        job = _job_from_environment(environment)
        try:
            isolation = _create_isolation(parent, parent_path)
        except ComputeWorkerError:
            isolation = None
        context = _WorkerContext(
            invocation=invocation,
            manifest=manifest,
            job=job,
            environment=dict(environment),
            parent_path=parent_path,
            isolation=isolation,
            command_runner=command_runner or _run_command,
        )
        checks = _run_checks(context)
        evidence_mapping = {
            "evidence_version": EVIDENCE_VERSION,
            "preflight_id": manifest.preflight_id,
            "profile_id": manifest.profile_id,
            "profile_hash": manifest.profile_hash,
            "scheduler_policy_hash": manifest.scheduler_policy_hash,
            "project_hash": manifest.project_hash,
            "input_set_hash": manifest.input_set_hash,
            "manifest_sha256": invocation.manifest_sha256,
            "worker_sha256": invocation.worker_sha256,
            "job_id": job.job_id,
            "submission_marker": job.submission_marker,
            "status": (
                "passed" if all(check["status"] == "passed" for check in checks) else "failed"
            ),
            "checks": checks,
        }
        evidence = parse_compute_evidence(evidence_mapping)
        payload = canonical_evidence_bytes(evidence)
        if not 0 < len(payload) <= _MAX_EVIDENCE_BYTES:
            raise ComputeWorkerError("compute evidence exceeds its fixed byte budget")
        _require_same_absolute_directory(parent_path, parent_identity)
        _publish_evidence(parent, evidence_leaf, payload)
        return evidence
    finally:
        os.close(parent)


def main(argv: list[str] | None = None) -> int:
    """Run silently; only a fully published evidence document returns zero."""

    selected = list(sys.argv[1:] if argv is None else argv)
    try:
        invocation = parse_worker_argv(selected)
        run_worker(
            invocation,
            environment=dict(os.environ),
            worker_path=sys.argv[0],
            python_path=sys.executable,
        )
    except BaseException:
        return WORKER_FAILURE_EXIT
    return 0


def _bind_invocation(
    invocation: WorkerInvocation,
    manifest: ComputePreflightManifest,
    worker_path: str,
) -> None:
    worker = manifest.worker
    if (
        worker.contract_version != invocation.contract_version
        or worker.executable != worker_path
        or worker.executable_sha256 != invocation.worker_sha256
        or worker.manifest_path != invocation.manifest_path
        or worker.evidence_path != invocation.evidence_path
    ):
        raise ComputeWorkerError("worker invocation does not bind the compute manifest")


def _decode_manifest(payload: bytes) -> ComputePreflightManifest:
    try:
        value = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        return parse_compute_manifest(value)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise ComputeWorkerError("compute manifest must be strict canonical JSON") from exc


def _job_from_environment(environment: Mapping[str, str]) -> SlurmJobRef:
    if not isinstance(environment, Mapping):
        raise ComputeWorkerError("Slurm environment is unavailable")
    job_id = environment.get("SLURM_JOB_ID")
    marker = environment.get("SLURM_JOB_NAME")
    if (
        not isinstance(job_id, str)
        or _JOB_ID.fullmatch(job_id) is None
        or not isinstance(marker, str)
        or not _valid_digest(marker)
    ):
        raise ComputeWorkerError("Slurm job identity is unavailable")
    try:
        return SlurmJobRef(job_id=job_id, submission_marker=marker, submitted_at=None)
    except SlurmContractError as exc:
        raise ComputeWorkerError("Slurm job identity is invalid") from exc


def _run_checks(context: _WorkerContext) -> list[dict[str, str]]:
    functions: dict[str, Callable[[_WorkerContext], Mapping[str, Any]]] = {
        "allocation_policy": _check_allocation_policy,
        "apptainer_runtime": _check_apptainer_runtime,
        "cache_storage": _check_cache_storage,
        "deployment_target": _check_deployment_target,
        "free_space": _check_free_space,
        "input_paths": _check_input_paths,
        "network_isolation": _check_network_isolation,
        "nextflow_runtime": _check_nextflow_runtime,
        "output_storage": _check_output_storage,
        "path_mapping": _check_path_mapping,
        "sif_artifacts": _check_sif_artifacts,
        "work_storage": _check_work_storage,
    }
    if tuple(functions) != COMPUTE_CHECK_NAMES:
        raise ComputeWorkerError("fixed compute check order is inconsistent")
    checks: list[dict[str, str]] = []
    for name in COMPUTE_CHECK_NAMES:
        code = "OK"
        status = "passed"
        observations: Mapping[str, Any]
        try:
            observations = functions[name](context)
        except _CheckFailure as exc:
            status = "failed"
            code = exc.code
            observations = {"failure_code": code}
        digest = _check_evidence_digest(context, name, status, code, observations)
        checks.append(
            {
                "name": name,
                "status": status,
                "code": code,
                "evidence_sha256": digest,
            }
        )
    return checks


def _check_evidence_digest(
    context: _WorkerContext,
    name: str,
    status: str,
    code: str,
    observations: Mapping[str, Any],
) -> str:
    value = {
        "check_name": name,
        "status": status,
        "code": code,
        "preflight_id": context.manifest.preflight_id,
        "manifest_sha256": context.invocation.manifest_sha256,
        "worker_sha256": context.invocation.worker_sha256,
        "job_id": context.job.job_id,
        "submission_marker": context.job.submission_marker,
        "observations": dict(observations),
    }
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(b"easy-pipe:m7.0d-d:compute-check:v1\x00" + payload).hexdigest()


def _check_allocation_policy(context: _WorkerContext) -> Mapping[str, Any]:
    environment = context.environment
    policy = context.manifest.scheduler_policy
    nodes = environment.get("SLURM_JOB_NUM_NODES", environment.get("SLURM_NNODES"))
    tasks = environment.get("SLURM_NTASKS", environment.get("SLURM_NPROCS"))
    expected: tuple[tuple[str | None, str], ...] = (
        (nodes, "1"),
        (tasks, "1"),
        (environment.get("SLURM_CPUS_PER_TASK"), str(policy.cpus_per_task)),
        (environment.get("SLURM_JOB_PARTITION"), policy.partition),
    )
    if any(observed != wanted for observed, wanted in expected):
        raise _CheckFailure("ALLOCATION_POLICY_MISMATCH")
    memory = _environment_int(environment.get("SLURM_MEM_PER_NODE"))
    if memory is None or memory < policy.memory_mib:
        raise _CheckFailure("ALLOCATION_POLICY_MISMATCH")
    started_at = _environment_int(environment.get("SLURM_JOB_START_TIME"))
    ends_at = _environment_int(environment.get("SLURM_JOB_END_TIME"))
    if (
        started_at is None
        or ends_at is None
        or ends_at - started_at != _effective_time_limit_seconds(policy.time_limit)
    ):
        raise _CheckFailure("ALLOCATION_POLICY_MISMATCH")
    if policy.account is not None and environment.get("SLURM_JOB_ACCOUNT") != policy.account:
        raise _CheckFailure("ALLOCATION_POLICY_MISMATCH")
    if policy.qos is not None and environment.get("SLURM_JOB_QOS") != policy.qos:
        raise _CheckFailure("ALLOCATION_POLICY_MISMATCH")
    return {
        "nodes": 1,
        "tasks": 1,
        "cpus_per_task": policy.cpus_per_task,
        "memory_mib": memory,
        "time_limit_seconds": ends_at - started_at,
        "partition_sha256": _text_hash(policy.partition),
        "account_sha256": None if policy.account is None else _text_hash(policy.account),
        "qos_sha256": None if policy.qos is None else _text_hash(policy.qos),
    }


def _check_apptainer_runtime(context: _WorkerContext) -> Mapping[str, Any]:
    runtime = context.manifest.compute_runtime
    try:
        observation = _observe_regular(
            runtime.apptainer_executable,
            maximum_bytes=_MAX_EXECUTABLE_BYTES,
            hash_contents=True,
            trusted_owner=True,
            require_executable=True,
            require_no_group_world_write=True,
        )
    except _CheckFailure as exc:
        raise _CheckFailure("APPTAINER_RUNTIME_UNAVAILABLE") from exc
    if observation.get("sha256") != runtime.apptainer_sha256:
        raise _CheckFailure("APPTAINER_IDENTITY_MISMATCH")
    result = context.command_runner(
        (runtime.apptainer_executable, "--version"),
        context.parent_path,
        _runtime_environment(context),
        runtime.command_timeout_seconds,
        runtime.max_command_output_bytes,
    )
    _require_command_success(result, "APPTAINER_RUNTIME")
    return {
        "executable_sha256": runtime.apptainer_sha256,
        "version_output_sha256": hashlib.sha256(
            result.stdout + b"\x00" + result.stderr
        ).hexdigest(),
    }


def _check_cache_storage(context: _WorkerContext) -> Mapping[str, Any]:
    try:
        return _storage_observation(
            context.manifest.cache_dir,
            role="cache",
            preflight_id=context.manifest.preflight_id,
            require_absent=False,
            resume_identity=None,
            probe_writable=True,
        )
    except _CheckFailure as exc:
        raise _CheckFailure("CACHE_STORAGE_UNAVAILABLE") from exc


def _check_deployment_target(context: _WorkerContext) -> Mapping[str, Any]:
    identity = _resume_identity(context.manifest, "deploy")
    try:
        return _storage_observation(
            context.manifest.deploy_dir,
            role="deploy",
            preflight_id=context.manifest.preflight_id,
            require_absent=context.manifest.resume_run_id is None,
            resume_identity=identity,
            probe_writable=True,
        )
    except _CheckFailure as exc:
        raise _CheckFailure("DEPLOYMENT_TARGET_UNSAFE") from exc


def _check_free_space(context: _WorkerContext) -> Mapping[str, Any]:
    values: dict[str, int] = {}
    for role, path in (
        ("deploy", context.manifest.deploy_dir),
        ("work", context.manifest.work_dir),
        ("output", context.manifest.output_dir),
        ("cache", context.manifest.cache_dir),
    ):
        try:
            observation = _storage_observation(
                path,
                role=role,
                preflight_id=context.manifest.preflight_id,
                require_absent=(role != "cache" and context.manifest.resume_run_id is None),
                resume_identity=_resume_identity(context.manifest, role),
                probe_writable=False,
            )
        except _CheckFailure as exc:
            raise _CheckFailure("SPACE_UNVERIFIED") from exc
        available = observation.get("available_bytes")
        if type(available) is not int:
            raise _CheckFailure("SPACE_UNVERIFIED")
        values[role] = available
    if any(value < context.manifest.minimum_free_bytes for value in values.values()):
        raise _CheckFailure("INSUFFICIENT_SPACE")
    return {"available_bytes": values, "minimum_free_bytes": context.manifest.minimum_free_bytes}


def _check_input_paths(context: _WorkerContext) -> Mapping[str, Any]:
    observations: list[dict[str, Any]] = []
    for path in context.manifest.execution_paths:
        try:
            observations.append(
                _observe_regular(
                    path,
                    maximum_bytes=_MAX_ARTIFACT_BYTES,
                    hash_contents=False,
                    trusted_owner=False,
                    require_executable=False,
                    require_no_group_world_write=True,
                )
            )
        except _CheckFailure as exc:
            raise _CheckFailure("INPUT_PATH_UNAVAILABLE") from exc
    return {
        "count": len(observations),
        "identity_sha256": _canonical_hash(observations),
    }


def _check_network_isolation(context: _WorkerContext) -> Mapping[str, Any]:
    runtime = context.manifest.compute_runtime
    container = min(context.manifest.containers, key=lambda item: item.name)
    try:
        apptainer = _observe_regular(
            runtime.apptainer_executable,
            maximum_bytes=_MAX_EXECUTABLE_BYTES,
            hash_contents=True,
            trusted_owner=True,
            require_executable=True,
            require_no_group_world_write=True,
        )
        image = _observe_regular(
            container.local_path,
            maximum_bytes=_MAX_ARTIFACT_BYTES,
            hash_contents=True,
            trusted_owner=True,
            require_executable=False,
            require_no_group_world_write=True,
        )
    except _CheckFailure as exc:
        raise _CheckFailure("NETWORK_ISOLATION_UNVERIFIED") from exc
    if (
        apptainer.get("sha256") != runtime.apptainer_sha256
        or image.get("sha256") != container.file_sha256
    ):
        raise _CheckFailure("NETWORK_ISOLATION_UNVERIFIED")
    result = context.command_runner(
        (
            runtime.apptainer_executable,
            "exec",
            "--containall",
            "--cleanenv",
            "--no-home",
            "--net",
            "--network",
            "none",
            container.local_path,
            "/bin/true",
        ),
        context.parent_path,
        _runtime_environment(context),
        runtime.command_timeout_seconds,
        runtime.max_command_output_bytes,
    )
    _require_command_success(result, "NETWORK_ISOLATION")
    return {
        "command_contract": "apptainer-network-none-v1",
        "image_sha256": container.file_sha256,
    }


def _check_nextflow_runtime(context: _WorkerContext) -> Mapping[str, Any]:
    runtime = context.manifest.compute_runtime
    bindings = (
        (
            runtime.java_executable,
            runtime.java_sha256,
            _MAX_EXECUTABLE_BYTES,
            True,
        ),
        (
            runtime.nextflow_executable,
            runtime.nextflow_sha256,
            _MAX_EXECUTABLE_BYTES,
            True,
        ),
        (
            runtime.nextflow_jar,
            runtime.nextflow_jar_sha256,
            _MAX_JAR_BYTES,
            False,
        ),
    )
    for path, expected, maximum, executable in bindings:
        try:
            observation = _observe_regular(
                path,
                maximum_bytes=maximum,
                hash_contents=True,
                trusted_owner=True,
                require_executable=executable,
                require_no_group_world_write=True,
            )
        except _CheckFailure as exc:
            raise _CheckFailure("NEXTFLOW_RUNTIME_UNAVAILABLE") from exc
        if observation.get("sha256") != expected:
            raise _CheckFailure("NEXTFLOW_IDENTITY_MISMATCH")
    command_environment = _runtime_environment(context)
    java_version = context.command_runner(
        (runtime.java_executable, "-version"),
        context.parent_path,
        command_environment,
        runtime.command_timeout_seconds,
        runtime.max_command_output_bytes,
    )
    _require_command_success(java_version, "JAVA_RUNTIME")
    nextflow_version = context.command_runner(
        (runtime.java_executable, "-jar", runtime.nextflow_jar, "-version"),
        context.parent_path,
        command_environment,
        runtime.command_timeout_seconds,
        runtime.max_command_output_bytes,
    )
    _require_command_success(nextflow_version, "NEXTFLOW_RUNTIME")
    version_output = nextflow_version.stdout + b"\n" + nextflow_version.stderr
    try:
        version_text = version_output.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _CheckFailure("NEXTFLOW_VERSION_MISMATCH") from exc
    if (
        re.search(
            rf"(?<![A-Za-z0-9_.-]){re.escape(runtime.nextflow_version)}"
            r"(?![A-Za-z0-9_.-])",
            version_text,
        )
        is None
    ):
        raise _CheckFailure("NEXTFLOW_VERSION_MISMATCH")
    return {
        "java_sha256": runtime.java_sha256,
        "nextflow_launcher_sha256": runtime.nextflow_sha256,
        "nextflow_jar_sha256": runtime.nextflow_jar_sha256,
        "nextflow_version": runtime.nextflow_version,
    }


def _check_output_storage(context: _WorkerContext) -> Mapping[str, Any]:
    try:
        return _storage_observation(
            context.manifest.output_dir,
            role="output",
            preflight_id=context.manifest.preflight_id,
            require_absent=context.manifest.resume_run_id is None,
            resume_identity=_resume_identity(context.manifest, "output"),
            probe_writable=True,
        )
    except _CheckFailure as exc:
        raise _CheckFailure("OUTPUT_STORAGE_UNAVAILABLE") from exc


def _check_path_mapping(context: _WorkerContext) -> Mapping[str, Any]:
    manifest = context.manifest
    try:
        mapped = tuple(_map_path(path, manifest.path_mapping) for path in manifest.source_paths)
    except ValueError as exc:
        raise _CheckFailure("PATH_MAPPING_INVALID") from exc
    if (
        mapped != manifest.execution_paths
        or input_set_hash(manifest.execution_paths) != manifest.input_set_hash
    ):
        raise _CheckFailure("PATH_MAPPING_INVALID")
    return {
        "mapping_sha256": _canonical_hash([item.as_mapping() for item in manifest.path_mapping]),
        "input_set_hash": manifest.input_set_hash,
        "path_count": len(manifest.execution_paths),
    }


def _check_sif_artifacts(context: _WorkerContext) -> Mapping[str, Any]:
    observations: list[dict[str, Any]] = []
    for container in context.manifest.containers:
        try:
            observed = _observe_regular(
                container.local_path,
                maximum_bytes=_MAX_ARTIFACT_BYTES,
                hash_contents=True,
                trusted_owner=True,
                require_executable=False,
                require_no_group_world_write=True,
            )
        except _CheckFailure as exc:
            raise _CheckFailure("SIF_ARTIFACT_UNAVAILABLE") from exc
        if observed.get("sha256") != container.file_sha256:
            raise _CheckFailure("SIF_ARTIFACT_MISMATCH")
        observations.append(
            {
                "name": container.name,
                "sha256": container.file_sha256,
                "size": observed["size"],
                "device": observed["device"],
                "inode": observed["inode"],
            }
        )
    return {
        "count": len(observations),
        "artifacts_sha256": _canonical_hash(observations),
    }


def _check_work_storage(context: _WorkerContext) -> Mapping[str, Any]:
    try:
        return _storage_observation(
            context.manifest.work_dir,
            role="work",
            preflight_id=context.manifest.preflight_id,
            require_absent=context.manifest.resume_run_id is None,
            resume_identity=_resume_identity(context.manifest, "work"),
            probe_writable=True,
        )
    except _CheckFailure as exc:
        raise _CheckFailure("WORK_STORAGE_UNAVAILABLE") from exc


def _storage_observation(
    path: str,
    *,
    role: str,
    preflight_id: str,
    require_absent: bool,
    resume_identity: ResumeDirectoryIdentity | None,
    probe_writable: bool,
) -> dict[str, Any]:
    selected = Path(path)
    parent = -1
    target = -1
    probe_directory = -1
    try:
        parent = _open_absolute_directory(selected.parent)
        try:
            existing = os.stat(selected.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if require_absent:
            if existing is not None:
                raise _CheckFailure("TARGET_ALREADY_EXISTS")
            probe_directory = parent
            metadata = os.fstat(parent)
        else:
            if (
                existing is None
                or stat.S_ISLNK(existing.st_mode)
                or not stat.S_ISDIR(existing.st_mode)
            ):
                raise _CheckFailure("DIRECTORY_TARGET_UNAVAILABLE")
            target = os.open(selected.name, _DIRECTORY_FLAGS, dir_fd=parent)
            metadata = os.fstat(target)
            current = os.stat(selected.name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
                or metadata.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise _CheckFailure("DIRECTORY_TARGET_UNSAFE")
            if resume_identity is not None and _directory_identity(metadata) != (
                resume_identity.device,
                resume_identity.inode,
                resume_identity.owner,
                resume_identity.group,
                resume_identity.mode,
            ):
                raise _CheckFailure("RESUME_DIRECTORY_CHANGED")
            if resume_identity is not None and stat.S_IMODE(metadata.st_mode) != 0o700:
                raise _CheckFailure("RESUME_DIRECTORY_CHANGED")
            probe_directory = target
        if probe_writable:
            _write_probe(probe_directory, preflight_id, role)
        filesystem = os.fstatvfs(probe_directory)
        available = filesystem.f_bavail * filesystem.f_frsize
        return {
            "path_sha256": _text_hash(path),
            "target_present": existing is not None,
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "owner": metadata.st_uid,
            "group": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "available_bytes": available,
        }
    except _CheckFailure:
        raise
    except (ComputeWorkerError, OSError) as exc:
        raise _CheckFailure("STORAGE_PATH_UNAVAILABLE") from exc
    finally:
        if target >= 0:
            os.close(target)
        if parent >= 0:
            os.close(parent)


def _write_probe(directory: int, preflight_id: str, role: str) -> None:
    leaf = f".bioexec-{preflight_id}-{role}-probe"
    descriptor = -1
    created = False
    try:
        descriptor = os.open(leaf, _CREATE_FLAGS, 0o600, dir_fd=directory)
        created = True
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, b"bioexec-compute-preflight\n")
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
        ):
            raise OSError("storage probe metadata changed")
        os.close(descriptor)
        descriptor = -1
        os.unlink(leaf, dir_fd=directory)
        created = False
        os.fsync(directory)
    except OSError as exc:
        raise _CheckFailure("STORAGE_NOT_WRITABLE") from exc
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if created:
            with contextlib.suppress(OSError):
                os.unlink(leaf, dir_fd=directory)


def _resume_identity(
    manifest: ComputePreflightManifest,
    role: str,
) -> ResumeDirectoryIdentity | None:
    identities = manifest.resume_directory_identities
    if identities is None:
        return None
    return identities.get(role)


def _map_path(path: str, mappings: tuple[Any, ...]) -> str:
    source = PurePosixPath(path)
    candidates: list[tuple[int, str]] = []
    for mapping in mappings:
        prefix = PurePosixPath(mapping.source_prefix)
        try:
            relative = source.relative_to(prefix)
        except ValueError:
            continue
        candidates.append(
            (len(prefix.parts), str(PurePosixPath(mapping.execution_prefix) / relative))
        )
    if not candidates:
        raise ValueError("path mapping is incomplete")
    longest = max(length for length, _target in candidates)
    targets = {target for length, target in candidates if length == longest}
    if len(targets) != 1:
        raise ValueError("path mapping is ambiguous")
    return targets.pop()


def _runtime_environment(context: _WorkerContext) -> Mapping[str, str]:
    isolation = context.isolation
    if isolation is None or set(isolation) != {
        "home",
        "nxf-home",
        "apptainer-config",
        "tmp",
    }:
        raise _CheckFailure("RUNTIME_ISOLATION_UNAVAILABLE")
    runtime = context.manifest.compute_runtime
    return {
        "HOME": str(isolation["home"]),
        "LANG": "C",
        "LC_ALL": "C",
        "JAVA_CMD": runtime.java_executable,
        "NXF_HOME": str(isolation["nxf-home"]),
        "NXF_BIN": runtime.nextflow_jar,
        "NXF_OFFLINE": "true",
        "NXF_DISABLE_CHECK_LATEST": "true",
        "NXF_TEMP": str(isolation["tmp"]),
        "TMPDIR": str(isolation["tmp"]),
        "APPTAINER_CONFIGDIR": str(isolation["apptainer-config"]),
        "APPTAINER_CACHEDIR": context.manifest.cache_dir,
        "SINGULARITY_CONFIGDIR": str(isolation["apptainer-config"]),
        "SINGULARITY_CACHEDIR": context.manifest.cache_dir,
    }


def _require_command_success(result: _CommandResult, prefix: str) -> None:
    if not isinstance(result, _CommandResult):
        raise ComputeWorkerError("fixed command runner returned an invalid result")
    if result.timed_out:
        raise _CheckFailure(f"{prefix}_TIMEOUT")
    if result.output_limit_exceeded:
        raise _CheckFailure(f"{prefix}_OUTPUT_LIMIT")
    if result.return_code != 0:
        raise _CheckFailure(f"{prefix}_UNAVAILABLE")


def _environment_int(value: str | None) -> int | None:
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdecimal():
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    if parsed < 0 or parsed > 2**63 - 1:
        return None
    return parsed


def _effective_time_limit_seconds(value: str) -> int:
    match = _TIME_LIMIT.fullmatch(value)
    if match is None:
        raise ComputeWorkerError("validated Slurm time limit is inconsistent")
    days = int(match.group("days") or "0")
    hours = int(match.group("hours"))
    minutes = int(match.group("minutes"))
    seconds = int(match.group("seconds"))
    requested = (((days * 24) + hours) * 60 + minutes) * 60 + seconds
    return ((requested + 59) // 60) * 60


def _canonical_hash(value: Any) -> str:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ComputeWorkerError("worker observation is not canonical") from exc
    return hashlib.sha256(payload).hexdigest()


def _text_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _run_command(
    argv: tuple[str, ...],
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    output_limit_bytes: int,
) -> _CommandResult:
    if (
        not isinstance(argv, tuple)
        or not argv
        or not PurePosixPath(argv[0]).is_absolute()
        or any(
            not isinstance(item, str) or not item or "\x00" in item or "\n" in item or "\r" in item
            for item in argv
        )
        or not isinstance(cwd, Path)
        or not cwd.is_absolute()
        or not isinstance(environment, Mapping)
        or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or not key
            or "=" in key
            or "\x00" in key
            or "\x00" in value
            for key, value in environment.items()
        )
        or isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
        or type(output_limit_bytes) is not int
        or output_limit_bytes < 1
    ):
        raise ComputeWorkerError("fixed runtime command contract is invalid")
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
        )
    except OSError:
        return _CommandResult(None, b"", b"", False, False)
    assert process.stdout is not None and process.stderr is not None
    streams = {process.stdout: "stdout", process.stderr: "stderr"}
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    total = 0
    timed_out = False
    overflow = False
    process_exited_at: float | None = None
    try:
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        deadline = time.monotonic() + float(timeout_seconds)
        while selector.get_map():
            now = time.monotonic()
            remaining = deadline - now
            if remaining <= 0:
                timed_out = True
                break
            if process.poll() is not None:
                if process_exited_at is None:
                    process_exited_at = now
                drain_remaining = _PROCESS_EXIT_DRAIN_SECONDS - (now - process_exited_at)
                if drain_remaining <= 0:
                    timed_out = True
                    break
                remaining = min(remaining, drain_remaining)
            events = selector.select(min(remaining, 0.25))
            if not events and process.poll() is not None:
                events = [(key, selectors.EVENT_READ) for key in selector.get_map().values()]
            for key, _mask in events:
                stream = cast(IO[bytes], key.fileobj)
                try:
                    chunk = os.read(stream.fileno(), _COMMAND_READ_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    with contextlib.suppress(Exception):
                        selector.unregister(stream)
                    stream.close()
                    continue
                available = max(0, output_limit_bytes - total)
                accepted = chunk[:available]
                target = stdout if streams[stream] == "stdout" else stderr
                target.extend(accepted)
                total += len(accepted)
                if len(accepted) != len(chunk):
                    overflow = True
                    break
            if overflow:
                break
        if timed_out or overflow:
            _terminate_process_group(process)
        else:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_process_group(process)
    finally:
        selector.close()
        for stream in streams:
            with contextlib.suppress(Exception):
                stream.close()
        if process.poll() is None:
            _terminate_process_group(process)
    return _CommandResult(
        return_code=process.returncode,
        stdout=bytes(stdout),
        stderr=bytes(stderr),
        timed_out=timed_out,
        output_limit_exceeded=overflow,
    )


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(OSError):
        os.killpg(process.pid, signal.SIGTERM)
    deadline = time.monotonic() + _TERMINATE_GRACE_SECONDS
    while _process_group_exists(process.pid) and time.monotonic() < deadline:
        process.poll()
        time.sleep(0.01)
    if _process_group_exists(process.pid):
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=_TERMINATE_GRACE_SECONDS)


def _process_group_exists(group_id: int) -> bool:
    try:
        os.killpg(group_id, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _argument_path(value: str, leaf: str) -> None:
    if not isinstance(value, str) or _SAFE_ARGUMENT_PATH.fullmatch(value) is None:
        raise ComputeWorkerError("worker path argument is unsafe")
    path = PurePosixPath(value)
    if path == PurePosixPath("/") or ".." in path.parts or str(path) != value or path.name != leaf:
        raise ComputeWorkerError("worker path argument is unsafe")


def _valid_digest(value: str) -> bool:
    return _SHA256.fullmatch(value) is not None and value != "0" * 64


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def _open_absolute_directory(path: Path, *, trusted_owner: bool = True) -> int:
    text = str(path)
    pure = PurePosixPath(text)
    if (
        not pure.is_absolute()
        or pure == PurePosixPath("/")
        or ".." in pure.parts
        or str(pure) != text
    ):
        raise ComputeWorkerError("worker directory path is not canonical and absolute")
    descriptor = -1
    try:
        descriptor = os.open("/", _DIRECTORY_FLAGS)
        _require_safe_parent(os.fstat(descriptor), trusted_owner=trusted_owner)
        for part in pure.parts[1:]:
            next_descriptor = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                opened = os.fstat(next_descriptor)
                current = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if (
                    stat.S_ISLNK(current.st_mode)
                    or not stat.S_ISDIR(opened.st_mode)
                    or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                ):
                    raise OSError("worker directory path changed")
                _require_safe_parent(opened, trusted_owner=trusted_owner)
            except BaseException:
                os.close(next_descriptor)
                raise
            os.close(descriptor)
            descriptor = next_descriptor
        result = descriptor
        descriptor = -1
        return result
    except ComputeWorkerError:
        raise
    except OSError as exc:
        raise ComputeWorkerError("worker directory cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _require_safe_parent(metadata: os.stat_result, *, trusted_owner: bool) -> None:
    mode = stat.S_IMODE(metadata.st_mode)
    sticky_anchor = (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid in {0, os.geteuid()}
        and bool(metadata.st_mode & stat.S_ISVTX)
    )
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (trusted_owner and metadata.st_uid not in {0, os.geteuid()})
        or (mode & 0o022 and not sticky_anchor)
    ):
        raise ComputeWorkerError("worker path has unsafe parent permissions")


def _require_private_directory(descriptor: int) -> tuple[int, int, int, int, int]:
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        raise ComputeWorkerError("worker private directory is unavailable") from exc
    identity = _directory_identity(metadata)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_nlink < 2
    ):
        raise ComputeWorkerError("worker directory must be exact owner-only mode 0700")
    return identity


def _require_current_directory(expected: tuple[int, int, int, int, int]) -> None:
    descriptor = -1
    try:
        descriptor = os.open(".", _DIRECTORY_FLAGS)
        if _directory_identity(os.fstat(descriptor)) != expected:
            raise ComputeWorkerError("worker current directory does not bind manifest files")
    except ComputeWorkerError:
        raise
    except OSError as exc:
        raise ComputeWorkerError("worker current directory is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_private_file(directory: int, leaf: str, maximum_bytes: int) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(leaf, _READ_FLAGS, dir_fd=directory)
        before = os.fstat(descriptor)
        current = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum_bytes
        ):
            raise ComputeWorkerError("worker private file metadata is invalid")
        payload = _read_bounded(descriptor, maximum_bytes + 1)
        after = os.fstat(descriptor)
        current_after = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
        if (
            len(payload) > maximum_bytes
            or _file_identity(before) != _file_identity(after)
            or (after.st_dev, after.st_ino) != (current_after.st_dev, current_after.st_ino)
        ):
            raise ComputeWorkerError("worker private file changed while it was read")
        return payload
    except ComputeWorkerError:
        raise
    except OSError as exc:
        raise ComputeWorkerError("worker private file cannot be opened safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _require_absent(directory: int, leaf: str) -> None:
    try:
        os.stat(leaf, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ComputeWorkerError("worker evidence destination is indeterminate") from exc
    raise ComputeWorkerError("worker evidence destination already exists")


def _verify_trust_executable(path: str, expected_sha256: str, maximum_bytes: int) -> None:
    try:
        observation = _observe_regular(
            path,
            maximum_bytes=maximum_bytes,
            hash_contents=True,
            trusted_owner=True,
            require_executable=True,
            require_no_group_world_write=True,
        )
    except _CheckFailure as exc:
        raise ComputeWorkerError("trusted executable cannot be verified") from exc
    if observation.get("sha256") != expected_sha256:
        raise ComputeWorkerError("trusted executable SHA-256 changed")


def _observe_regular(
    path: str,
    *,
    maximum_bytes: int,
    hash_contents: bool,
    trusted_owner: bool,
    require_executable: bool,
    require_no_group_world_write: bool,
) -> dict[str, Any]:
    selected = Path(path)
    parent = -1
    descriptor = -1
    try:
        parent = _open_absolute_directory(
            selected.parent,
            trusted_owner=trusted_owner,
        )
        descriptor = os.open(selected.name, _READ_FLAGS, dir_fd=parent)
        before = os.fstat(descriptor)
        current = os.stat(selected.name, dir_fd=parent, follow_symlinks=False)
        mode = stat.S_IMODE(before.st_mode)
        if (
            stat.S_ISLNK(current.st_mode)
            or not stat.S_ISREG(before.st_mode)
            or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum_bytes
            or (trusted_owner and before.st_uid not in {0, os.geteuid()})
            or (require_no_group_world_write and mode & 0o022)
            or (require_executable and not mode & 0o111)
        ):
            raise _CheckFailure("UNSAFE_REGULAR_FILE")
        digest = hashlib.sha256()
        total = 0
        if hash_contents:
            while True:
                chunk = os.read(descriptor, _READ_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum_bytes:
                    raise _CheckFailure("FILE_BUDGET_EXCEEDED")
                digest.update(chunk)
        else:
            chunk = os.read(descriptor, 1)
            total = len(chunk)
        after = os.fstat(descriptor)
        current_after = os.stat(selected.name, dir_fd=parent, follow_symlinks=False)
        if (
            _file_identity(before) != _file_identity(after)
            or (after.st_dev, after.st_ino) != (current_after.st_dev, current_after.st_ino)
            or (hash_contents and total != before.st_size)
        ):
            raise _CheckFailure("FILE_CHANGED_DURING_CHECK")
        result: dict[str, Any] = {
            "path_sha256": hashlib.sha256(path.encode("utf-8")).hexdigest(),
            "device": before.st_dev,
            "inode": before.st_ino,
            "size": before.st_size,
            "mtime_ns": before.st_mtime_ns,
            "ctime_ns": before.st_ctime_ns,
            "mode": mode,
        }
        if hash_contents:
            result["sha256"] = digest.hexdigest()
        return result
    except _CheckFailure:
        raise
    except (ComputeWorkerError, OSError, UnicodeError) as exc:
        raise _CheckFailure("PATH_UNAVAILABLE") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent >= 0:
            os.close(parent)


def _create_isolation(directory: int, parent_path: Path) -> Mapping[str, Path]:
    root_leaf = "compute-runtime-v1"
    root = -1
    try:
        os.mkdir(root_leaf, 0o700, dir_fd=directory)
        root = os.open(root_leaf, _DIRECTORY_FLAGS, dir_fd=directory)
        os.fchmod(root, 0o700)
        _require_private_directory(root)
        result: dict[str, Path] = {}
        for leaf in ("home", "nxf-home", "apptainer-config", "tmp"):
            os.mkdir(leaf, 0o700, dir_fd=root)
            child = os.open(leaf, _DIRECTORY_FLAGS, dir_fd=root)
            try:
                os.fchmod(child, 0o700)
                _require_private_directory(child)
                os.fsync(child)
            finally:
                os.close(child)
            result[leaf] = parent_path / root_leaf / leaf
        os.fsync(root)
        os.fsync(directory)
        return result
    except (ComputeWorkerError, OSError) as exc:
        raise ComputeWorkerError("private compute runtime isolation is unavailable") from exc
    finally:
        if root >= 0:
            os.close(root)


def _require_same_absolute_directory(
    path: Path,
    expected: tuple[int, int, int, int, int],
) -> None:
    current = _open_absolute_directory(path)
    try:
        if _require_private_directory(current) != expected:
            raise ComputeWorkerError("worker evidence parent changed before publication")
    finally:
        os.close(current)


def _publish_evidence(directory: int, leaf: str, payload: bytes) -> None:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= _MAX_EVIDENCE_BYTES:
        raise ComputeWorkerError("worker evidence payload is invalid")
    try:
        descriptor = os.open(leaf, _CREATE_FLAGS, 0o600, dir_fd=directory)
    except FileExistsError as exc:
        raise ComputeWorkerError("worker evidence destination already exists") from exc
    except OSError as exc:
        raise ComputeWorkerError("worker evidence destination cannot be created") from exc
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != len(payload)
        ):
            raise OSError("worker evidence metadata changed")
        os.fsync(descriptor)
    except BaseException as exc:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        raise ComputeWorkerCommitUnknown("worker evidence commit is uncertain") from exc
    try:
        os.close(descriptor)
    except BaseException as exc:
        raise ComputeWorkerCommitUnknown("worker evidence commit is uncertain") from exc
    try:
        os.fsync(directory)
    except OSError as exc:
        raise ComputeWorkerCommitUnknown("worker evidence directory commit is uncertain") from exc


def _read_bounded(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum
    while remaining:
        chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written < 1:
            raise OSError("worker evidence write made no progress")
        remaining = remaining[written:]


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
    )


def _file_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "WORKER_FAILURE_EXIT",
    "ComputeWorkerCommitUnknown",
    "ComputeWorkerError",
    "WorkerInvocation",
    "main",
    "parse_worker_argv",
    "run_worker",
]
