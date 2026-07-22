"""Dormant fixed compute-node bootstrap for one future scheduler run.

The installed protocol-v1 service never imports this module.  The separately
built entry point is intentionally silent and accepts only the fixed arguments
rendered by the dormant workload contract.  It replays owner-only run state,
reopens every execution artifact from the allocated node, and burns a
create-only start intent bound to the exact future Nextflow continuation.  It
still exits without executing that continuation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from .compute_worker import (
    ComputeWorkerError,
    _observe_regular,
    _open_absolute_directory,
)
from .deployment import _inventory
from .errors import AgentFailure
from .scheduler_config_loader import (
    TrustedSchedulerConfig,
    load_trusted_scheduler_config,
    verify_scheduler_config_file,
    verify_scheduler_executable,
    verify_scheduler_nextflow_jar,
)
from .scheduler_preflight import SchedulerPreflightState
from .scheduler_state import SchedulerStateSnapshot

if TYPE_CHECKING:
    from .scheduler_run import SchedulerDeploymentBinding

BOOTSTRAP_CONTRACT_VERSION = "1.0"
BOOTSTRAP_FAILURE_EXIT = 70

_ARGUMENTS = (
    "--contract-version=",
    "--config=",
    "--run-id=",
    "--identity-sha256=",
    "--bootstrap-sha256=",
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_MAX_ARTIFACT_BYTES = 2**63 - 1


class ComputeBootstrapError(RuntimeError):
    """The fixed compute bootstrap could not prove a safe start boundary."""


@dataclass(frozen=True)
class BootstrapInvocation:
    """Exactly the five ordered arguments admitted by the bootstrap artifact."""

    contract_version: str
    config_path: str
    run_id: str
    identity_sha256: str
    bootstrap_sha256: str


def parse_bootstrap_argv(argv: list[str]) -> BootstrapInvocation:
    """Parse one exact ordered bootstrap invocation without abbreviations."""

    if not isinstance(argv, list) or len(argv) != len(_ARGUMENTS):
        raise ComputeBootstrapError("bootstrap arguments do not match the fixed contract")
    values: list[str] = []
    for index, prefix in enumerate(_ARGUMENTS):
        argument = argv[index]
        if not isinstance(argument, str) or not argument.startswith(prefix):
            raise ComputeBootstrapError("bootstrap arguments do not match the fixed contract")
        value = argument[len(prefix) :]
        if not value:
            raise ComputeBootstrapError("bootstrap arguments do not match the fixed contract")
        values.append(value)
    contract_version, config_path, run_id, identity_sha256, bootstrap_sha256 = values
    if contract_version != BOOTSTRAP_CONTRACT_VERSION:
        raise ComputeBootstrapError("bootstrap contract version is unsupported")
    _absolute_path(config_path, "config")
    if _IDENTIFIER.fullmatch(run_id) is None:
        raise ComputeBootstrapError("bootstrap run identifier is invalid")
    if not _valid_digest(identity_sha256) or not _valid_digest(bootstrap_sha256):
        raise ComputeBootstrapError("bootstrap digest argument is invalid")
    return BootstrapInvocation(
        contract_version=contract_version,
        config_path=config_path,
        run_id=run_id,
        identity_sha256=identity_sha256,
        bootstrap_sha256=bootstrap_sha256,
    )


def verify_compute_artifacts(
    config: TrustedSchedulerConfig,
    deployment: SchedulerDeploymentBinding,
    preflight: SchedulerStateSnapshot,
    *,
    bootstrap_path: str,
    python_path: str,
) -> None:
    """Reopen and fully rehash the deployment, runtimes, JAR, and every SIF."""

    if not isinstance(config, TrustedSchedulerConfig):
        raise ComputeBootstrapError("trusted scheduler configuration is required")
    if not isinstance(preflight, SchedulerStateSnapshot):
        raise ComputeBootstrapError("a durable scheduler preflight snapshot is required")
    state = preflight.state
    if not isinstance(state, SchedulerPreflightState):
        raise ComputeBootstrapError("scheduler preflight state is invalid")
    capability = state.capability
    if (
        state.phase != "passed"
        or capability is None
        or not capability.consumed
        or capability.expired
    ):
        raise ComputeBootstrapError("compute bootstrap requires one consumed capability")

    bootstrap_binding = config.executables["compute_bootstrap"]
    python_binding = config.executables["python"]
    if (
        bootstrap_path != str(bootstrap_binding.path)
        or bootstrap_binding.sha256 is None
        or python_path != str(python_binding.path)
    ):
        raise ComputeBootstrapError("running bootstrap does not match trusted config-v2")
    try:
        verify_scheduler_config_file(config)
        for role in ("python", "java", "nextflow", "apptainer", "compute_bootstrap"):
            verify_scheduler_executable(config, role)
        verify_scheduler_nextflow_jar(config)
    except (OSError, ValueError) as exc:
        raise ComputeBootstrapError("trusted compute runtime changed before bootstrap") from exc
    _verify_deployment(config, deployment)
    _verify_sif_artifacts(state)


def main(argv: list[str] | None = None) -> int:
    """Run silently; any incomplete proof or uncertain start commit returns 70."""

    selected = list(sys.argv[1:] if argv is None else argv)
    try:
        invocation = parse_bootstrap_argv(selected)
        _run_fixed_bootstrap(
            invocation,
            bootstrap_path=sys.argv[0],
            python_path=sys.executable,
        )
    except BaseException:
        return BOOTSTRAP_FAILURE_EXIT
    return 0


def _run_fixed_bootstrap(
    invocation: BootstrapInvocation,
    *,
    bootstrap_path: str,
    python_path: str,
) -> None:
    """Load durable run state and claim its one non-replayable start permit."""

    # The scheduler-run store is imported here so protocol-v1 import graphs do
    # not gain a transitive scheduler-run dependency.
    from .scheduler_run import SchedulerRunStore, consume_start_permit
    from .scheduler_workload import prepare_scheduler_workload

    config = load_trusted_scheduler_config(Path(invocation.config_path))
    binding = config.executables["compute_bootstrap"]
    if binding.sha256 != invocation.bootstrap_sha256:
        raise ComputeBootstrapError("bootstrap invocation hash does not match config-v2")
    store = SchedulerRunStore(config)
    snapshot = store.load(invocation.run_id)
    if snapshot.identity_sha256 != invocation.identity_sha256:
        raise ComputeBootstrapError("bootstrap invocation does not bind the run reservation")
    preflight = store.load_consumed_preflight(snapshot)
    workload = prepare_scheduler_workload(config, snapshot, preflight)

    def verify() -> None:
        verify_compute_artifacts(
            config,
            snapshot.deployment,
            preflight,
            bootstrap_path=bootstrap_path,
            python_path=python_path,
        )

    with store.claim_start(
        snapshot,
        preflight,
        verify,
        workload=workload,
    ) as permit:
        consume_start_permit(permit, snapshot, workload)


def _verify_deployment(
    config: TrustedSchedulerConfig,
    deployment: SchedulerDeploymentBinding,
) -> None:
    expected = {item.path: (item.size, item.sha256) for item in deployment.files}
    directory = -1
    try:
        directory = _open_absolute_directory(Path(deployment.deployment_dir))
        before = os.fstat(directory)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            before.st_gid,
            stat.S_IMODE(before.st_mode),
        )
        if identity != deployment.directory_identity or before.st_nlink < 2:
            raise ComputeBootstrapError("deployment directory identity changed")
        try:
            observed = _inventory(
                directory,
                expected,
                maximum_entries=config.contract.limits.max_deployment_files * 4,
                maximum_file_bytes=config.contract.limits.max_file_bytes,
                maximum_total_bytes=config.contract.limits.max_deployment_bytes,
            )
        except (AgentFailure, OSError, ValueError) as exc:
            raise ComputeBootstrapError("deployment inventory could not be verified") from exc
        after = os.fstat(directory)
        current = os.stat(deployment.deployment_dir, follow_symlinks=False)
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            after.st_gid,
            stat.S_IMODE(after.st_mode),
        )
        if (
            stat.S_ISLNK(current.st_mode)
            or after_identity != identity
            or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino)
            or observed != expected
        ):
            raise ComputeBootstrapError("deployment contents changed during bootstrap")
        metadata = [
            {"path": path, "sha256": digest, "size": size}
            for path, (size, digest) in sorted(observed.items())
        ]
        if _canonical_hash(metadata) != deployment.bundle_hash:
            raise ComputeBootstrapError("deployment bundle hash changed")
    except ComputeBootstrapError:
        raise
    except (ComputeWorkerError, OSError, UnicodeError) as exc:
        raise ComputeBootstrapError("deployment cannot be opened safely") from exc
    finally:
        if directory >= 0:
            os.close(directory)


def _verify_sif_artifacts(state: SchedulerPreflightState) -> None:
    for container in state.manifest.containers:
        try:
            observed = _observe_regular(
                container.local_path,
                maximum_bytes=_MAX_ARTIFACT_BYTES,
                hash_contents=True,
                trusted_owner=True,
                require_executable=False,
                require_no_group_world_write=True,
            )
        except BaseException as exc:
            raise ComputeBootstrapError("a pinned SIF cannot be opened safely") from exc
        if observed.get("sha256") != container.file_sha256:
            raise ComputeBootstrapError("a pinned SIF hash changed before workflow start")


def _canonical_hash(value: Any) -> str:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ComputeBootstrapError("bootstrap binding is not canonical JSON") from exc
    return hashlib.sha256(payload).hexdigest()


def _absolute_path(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ComputeBootstrapError(f"bootstrap {label} path is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ComputeBootstrapError(f"bootstrap {label} path is invalid") from exc
    path = PurePosixPath(value)
    if (
        not 0 < len(encoded) <= 4096
        or not path.is_absolute()
        or path == PurePosixPath("/")
        or ".." in path.parts
        or str(path) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ComputeBootstrapError(f"bootstrap {label} path is invalid")
    return value


def _valid_digest(value: str) -> bool:
    return _SHA256.fullmatch(value) is not None and value != "0" * 64


__all__ = [
    "BOOTSTRAP_CONTRACT_VERSION",
    "BOOTSTRAP_FAILURE_EXIT",
    "BootstrapInvocation",
    "ComputeBootstrapError",
    "parse_bootstrap_argv",
    "verify_compute_artifacts",
]
