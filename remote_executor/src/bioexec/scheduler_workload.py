"""Pure fixed workload contract for the dormant M7 Slurm continuation.

The installed protocol-v1 service never imports this module.  It performs no
filesystem access, process execution, environment lookup, scheduler mutation,
or sleeping.  It reduces one trusted run reservation and consumed compute
preflight to the only admitted workload batch bytes, Nextflow argv,
environment, and Apptainer overlay.  A later activation adapter must submit
and materialize those exact bytes; it must not accept caller-provided argv,
environment entries, config fragments, or scheduler flags.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import InitVar, dataclass, field
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Any

from .scheduler_config_loader import TrustedSchedulerConfig
from .scheduler_preflight import SchedulerPreflightState
from .scheduler_run import (
    SCHEDULER_RUN_NAMESPACE,
    SchedulerRunSnapshot,
)
from .scheduler_state import SchedulerStateSnapshot
from .slurm import (
    SlurmContractError,
    SlurmSubmitSpec,
    build_sbatch_argv,
    build_scheduler_environment,
)

WORKLOAD_CONTRACT_VERSION = "1.0"

_PLAN_AUTHORITY = object()
_REQUIRED_DEPLOYMENT_FILES = frozenset(
    {
        "main.nf",
        "nextflow.config",
        "assets/samplesheet.csv",
        "conf/base.config",
        "conf/local.config",
    }
)
_REQUIRED_CONTAINER_NAMES = frozenset({"fastqc", "multiqc"})
_OPTIONAL_CONTAINER_NAMES = frozenset({"fastp"})
_MAX_BATCH_BYTES = 16 * 1024
_MAX_OVERLAY_BYTES = 64 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)


class SchedulerWorkloadError(ValueError):
    """Trusted state cannot produce the one fixed workload continuation."""


@dataclass(frozen=True)
class SchedulerWorkloadPlan:
    """Immutable hash-bound bytes and values for one dormant workload start."""

    _authority: InitVar[object]
    run_id: str
    run_identity_sha256: str
    preflight_request_sha256: str
    preflight_revision: int
    preflight_journal_sha256: str
    manifest_sha256: str
    resume: bool
    bootstrap_argv: tuple[str, ...]
    batch_bytes: bytes = field(repr=False)
    batch_sha256: str
    overlay_path: str
    overlay_bytes: bytes = field(repr=False)
    overlay_sha256: str
    nextflow_argv: tuple[str, ...]
    command_sha256: str
    environment: Mapping[str, str] = field(repr=False)
    environment_sha256: str
    private_directories: tuple[str, ...]
    working_directory: str
    submission_marker: str
    submit_argv: tuple[str, ...]
    submit_environment: Mapping[str, str] = field(repr=False)
    binding_sha256: str

    def __post_init__(self, _authority: object) -> None:
        if _authority is not _PLAN_AUTHORITY:
            raise SchedulerWorkloadError("workload plan construction is internal")
        if not self.batch_bytes or len(self.batch_bytes) > _MAX_BATCH_BYTES:
            raise SchedulerWorkloadError("workload batch bytes are outside the fixed budget")
        if not self.overlay_bytes or len(self.overlay_bytes) > _MAX_OVERLAY_BYTES:
            raise SchedulerWorkloadError("workload overlay bytes are outside the fixed budget")
        for payload, digest, label in (
            (self.batch_bytes, self.batch_sha256, "batch"),
            (self.overlay_bytes, self.overlay_sha256, "overlay"),
        ):
            if hashlib.sha256(payload).hexdigest() != digest:
                raise SchedulerWorkloadError(f"workload {label} digest changed")
        if _canonical_hash(list(self.nextflow_argv)) != self.command_sha256:
            raise SchedulerWorkloadError("workload command digest changed")
        if _canonical_hash(dict(self.environment)) != self.environment_sha256:
            raise SchedulerWorkloadError("workload environment digest changed")
        expected = _binding_hash(
            run_id=self.run_id,
            run_identity_sha256=self.run_identity_sha256,
            preflight_request_sha256=self.preflight_request_sha256,
            preflight_revision=self.preflight_revision,
            preflight_journal_sha256=self.preflight_journal_sha256,
            manifest_sha256=self.manifest_sha256,
            resume=self.resume,
            bootstrap_argv=self.bootstrap_argv,
            batch_sha256=self.batch_sha256,
            overlay_path=self.overlay_path,
            overlay_sha256=self.overlay_sha256,
            nextflow_argv=self.nextflow_argv,
            command_sha256=self.command_sha256,
            environment=self.environment,
            environment_sha256=self.environment_sha256,
            private_directories=self.private_directories,
            working_directory=self.working_directory,
            submission_marker=self.submission_marker,
            submit_argv=self.submit_argv,
            submit_environment=self.submit_environment,
        )
        if expected != self.binding_sha256:
            raise SchedulerWorkloadError("workload binding digest changed")


def prepare_scheduler_workload(
    config: TrustedSchedulerConfig,
    run: SchedulerRunSnapshot,
    preflight: SchedulerStateSnapshot,
) -> SchedulerWorkloadPlan:
    """Derive the sole batch, overlay, argv, and environment from trusted state."""

    _validate_inputs(config, run, preflight)
    state = preflight.state
    manifest = state.manifest
    runtime = manifest.compute_runtime
    bootstrap = config.executables["compute_bootstrap"]
    if bootstrap.sha256 is None:
        raise SchedulerWorkloadError("compute bootstrap lacks a trusted full hash")

    bootstrap_argv = (
        runtime.python_executable,
        "-I",
        "-S",
        str(bootstrap.path),
        "--contract-version=1.0",
        f"--config={config.config_file.path}",
        f"--run-id={run.run_id}",
        f"--identity-sha256={run.identity_sha256}",
        f"--bootstrap-sha256={bootstrap.sha256}",
    )
    batch_bytes = render_workload_batch(bootstrap_argv)
    batch_sha256 = hashlib.sha256(batch_bytes).hexdigest()

    run_directory = (
        PurePosixPath(str(config.state_root.path)) / SCHEDULER_RUN_NAMESPACE / run.run_id
    )
    runtime_directory = run_directory / "runtime-v1"
    overlay_path = str(runtime_directory / "workload.config")
    overlay_bytes = render_nextflow_overlay(state)
    overlay_sha256 = hashlib.sha256(overlay_bytes).hexdigest()
    resume = run.identity["operation"] == "resume"
    nextflow_argv = build_nextflow_argv(state, run.run_id, str(runtime_directory))
    command_sha256 = _canonical_hash(list(nextflow_argv))
    private_directories = (
        *(
            str(runtime_directory / leaf)
            for leaf in (
                "home",
                "nxf-home",
                "tmp",
                "apptainer-config",
            )
        ),
        str(PurePosixPath(manifest.work_dir) / ".easy-pipe-nextflow-cache-v1"),
    )
    environment = _nextflow_environment(state, private_directories)
    environment_sha256 = _canonical_hash(dict(environment))

    marker_seed = {
        "domain": "easy-pipe.scheduler-workload.submission-marker.v1",
        "run_identity_sha256": run.identity_sha256,
        "preflight_request_sha256": preflight.request_sha256,
        "preflight_revision": preflight.revision,
        "preflight_journal_sha256": preflight.journal_sha256,
        "manifest_sha256": state.manifest_sha256,
        "batch_sha256": batch_sha256,
        "overlay_sha256": overlay_sha256,
        "nextflow_argv": list(nextflow_argv),
        "command_sha256": command_sha256,
        "environment_sha256": environment_sha256,
    }
    submission_marker = _canonical_hash(marker_seed)
    try:
        submit_argv = build_sbatch_argv(
            str(config.executables["sbatch"].path),
            SlurmSubmitSpec(
                policy=manifest.scheduler_policy,
                submission_marker=submission_marker,
                working_directory=str(runtime_directory),
                log_directory=str(runtime_directory),
            ),
        )
        scheduler_home = str(run_directory)
        submit_environment = build_scheduler_environment(scheduler_home)
    except SlurmContractError as exc:
        raise SchedulerWorkloadError(
            "trusted paths or policy cannot form the fixed sbatch contract"
        ) from exc

    binding_sha256 = _binding_hash(
        run_id=run.run_id,
        run_identity_sha256=run.identity_sha256,
        preflight_request_sha256=preflight.request_sha256,
        preflight_revision=preflight.revision,
        preflight_journal_sha256=preflight.journal_sha256,
        manifest_sha256=state.manifest_sha256,
        resume=resume,
        bootstrap_argv=bootstrap_argv,
        batch_sha256=batch_sha256,
        overlay_path=overlay_path,
        overlay_sha256=overlay_sha256,
        nextflow_argv=nextflow_argv,
        command_sha256=command_sha256,
        environment=environment,
        environment_sha256=environment_sha256,
        private_directories=private_directories,
        working_directory=str(runtime_directory),
        submission_marker=submission_marker,
        submit_argv=submit_argv,
        submit_environment=submit_environment,
    )
    return SchedulerWorkloadPlan(
        _authority=_PLAN_AUTHORITY,
        run_id=run.run_id,
        run_identity_sha256=run.identity_sha256,
        preflight_request_sha256=preflight.request_sha256,
        preflight_revision=preflight.revision,
        preflight_journal_sha256=preflight.journal_sha256,
        manifest_sha256=state.manifest_sha256,
        resume=resume,
        bootstrap_argv=bootstrap_argv,
        batch_bytes=batch_bytes,
        batch_sha256=batch_sha256,
        overlay_path=overlay_path,
        overlay_bytes=overlay_bytes,
        overlay_sha256=overlay_sha256,
        nextflow_argv=nextflow_argv,
        command_sha256=command_sha256,
        environment=environment,
        environment_sha256=environment_sha256,
        private_directories=private_directories,
        working_directory=str(runtime_directory),
        submission_marker=submission_marker,
        submit_argv=submit_argv,
        submit_environment=submit_environment,
        binding_sha256=binding_sha256,
    )


def render_workload_batch(bootstrap_argv: tuple[str, ...]) -> bytes:
    """Render one shell-safe bootstrap exec with no workload command surface."""

    if (
        not isinstance(bootstrap_argv, tuple)
        or len(bootstrap_argv) != 9
        or not all(isinstance(argument, str) for argument in bootstrap_argv)
        or bootstrap_argv[1:3] != ("-I", "-S")
        or bootstrap_argv[4] != "--contract-version=1.0"
        or not bootstrap_argv[5].startswith("--config=")
        or not bootstrap_argv[6].startswith("--run-id=")
        or not bootstrap_argv[7].startswith("--identity-sha256=")
        or not bootstrap_argv[8].startswith("--bootstrap-sha256=")
    ):
        raise SchedulerWorkloadError("bootstrap argv does not match the fixed workload contract")
    config_path = bootstrap_argv[5].removeprefix("--config=")
    run_id = bootstrap_argv[6].removeprefix("--run-id=")
    identity_sha256 = bootstrap_argv[7].removeprefix("--identity-sha256=")
    bootstrap_sha256 = bootstrap_argv[8].removeprefix("--bootstrap-sha256=")
    if (
        not _canonical_absolute_path(bootstrap_argv[0], leaf="python3")
        or not _canonical_absolute_path(
            bootstrap_argv[3],
            leaf="bioexec-compute-bootstrap",
        )
        or not _canonical_absolute_path(config_path)
        or _IDENTIFIER.fullmatch(run_id) is None
        or _SHA256.fullmatch(identity_sha256) is None
        or identity_sha256 == "0" * 64
        or _SHA256.fullmatch(bootstrap_sha256) is None
        or bootstrap_sha256 == "0" * 64
    ):
        raise SchedulerWorkloadError("bootstrap argv does not match the fixed workload contract")
    rendered = " \\\n  ".join(_shell_quote(argument) for argument in bootstrap_argv)
    payload = ("#!/bin/sh\nset -eu\numask 077\nexec " + rendered + "\n").encode("ascii")
    if len(payload) > _MAX_BATCH_BYTES:
        raise SchedulerWorkloadError("workload batch bytes exceed the fixed budget")
    return payload


def build_nextflow_argv(
    state: SchedulerPreflightState,
    run_id: str,
    runtime_directory: str,
) -> tuple[str, ...]:
    """Build the exact named Nextflow argv and explicit prior-session resume."""

    if not isinstance(state, SchedulerPreflightState):
        raise SchedulerWorkloadError("validated scheduler preflight state is required")
    if not isinstance(run_id, str) or _IDENTIFIER.fullmatch(run_id) is None:
        raise SchedulerWorkloadError("workload run identifier is invalid")
    if not isinstance(runtime_directory, str):
        raise SchedulerWorkloadError("workload runtime directory is not canonical")
    selected = PurePosixPath(runtime_directory)
    if (
        not selected.is_absolute()
        or selected == PurePosixPath("/")
        or ".." in selected.parts
        or str(selected) != runtime_directory
        or selected.name != "runtime-v1"
        or selected.parent.name != run_id
        or selected.parent.parent.name != SCHEDULER_RUN_NAMESPACE
    ):
        raise SchedulerWorkloadError("workload runtime directory is not canonical")
    manifest = state.manifest
    deployment = PurePosixPath(manifest.deploy_dir)
    arguments = (
        manifest.compute_runtime.nextflow_executable,
        "-C",
        str(selected / "workload.config"),
        "-log",
        str(selected / "nextflow.log"),
        "run",
        str(deployment),
        "-profile",
        "local",
        "-work-dir",
        manifest.work_dir,
        "--output_dir",
        manifest.output_dir,
        "--samplesheet",
        str(deployment / "assets" / "samplesheet.csv"),
        "-name",
        _nextflow_session_name(run_id),
    )
    if manifest.resume_run_id is None:
        return arguments
    return (*arguments, "-resume", _nextflow_session_name(manifest.resume_run_id))


def render_nextflow_overlay(state: SchedulerPreflightState) -> bytes:
    """Render the fixed offline local-executor and local-SIF Nextflow config."""

    if not isinstance(state, SchedulerPreflightState):
        raise SchedulerWorkloadError("validated scheduler preflight state is required")
    manifest = state.manifest
    containers = {container.name: container.local_path for container in manifest.containers}
    names = frozenset(containers)
    if not names >= _REQUIRED_CONTAINER_NAMES or names - (
        _REQUIRED_CONTAINER_NAMES | _OPTIONAL_CONTAINER_NAMES
    ):
        raise SchedulerWorkloadError("workload containers do not match the fixed FASTQ-QC graph")
    selectors = {
        "fastqc_raw": containers["fastqc"],
        "fastqc_post_trim": containers["fastqc"],
        "multiqc": containers["multiqc"],
    }
    if "fastp" in containers:
        selectors["fastp"] = containers["fastp"]
    include = str(PurePosixPath(manifest.deploy_dir) / "nextflow.config")
    lines = [
        f"includeConfig {_groovy_quote(include)}",
        "process.executor = 'local'",
        f"executor.cpus = {manifest.scheduler_policy.cpus_per_task}",
        f"executor.memory = '{manifest.scheduler_policy.memory_mib} MB'",
        "executor.queueSize = 1",
        "wave.enabled = false",
        "tower.enabled = false",
        "fusion.enabled = false",
        "docker.enabled = false",
        "podman.enabled = false",
        "charliecloud.enabled = false",
        "conda.enabled = false",
        "spack.enabled = false",
        "apptainer.enabled = true",
        "apptainer.autoMounts = true",
        "singularity.enabled = false",
        f"apptainer.cacheDir = {_groovy_quote(manifest.cache_dir)}",
        "apptainer.runOptions = '--containall --no-home --cleanenv --net --network none'",
        "process {",
    ]
    for label in sorted(selectors):
        lines.extend(
            (
                f"    withLabel: {_groovy_quote(label)} {{",
                "        executor = 'local'",
                f"        container = {_groovy_quote(selectors[label])}",
                "    }",
            )
        )
    lines.append("}")
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    if len(payload) > _MAX_OVERLAY_BYTES:
        raise SchedulerWorkloadError("Nextflow overlay exceeds the fixed byte budget")
    return payload


def _validate_inputs(
    config: TrustedSchedulerConfig,
    run: SchedulerRunSnapshot,
    preflight: SchedulerStateSnapshot,
) -> None:
    if not isinstance(config, TrustedSchedulerConfig):
        raise SchedulerWorkloadError("trusted scheduler config-v2 is required")
    if not isinstance(run, SchedulerRunSnapshot):
        raise SchedulerWorkloadError("store-owned scheduler run snapshot is required")
    if not isinstance(preflight, SchedulerStateSnapshot):
        raise SchedulerWorkloadError("durable consumed preflight snapshot is required")
    state = preflight.state
    manifest = state.manifest
    capability = state.capability
    identity = run.identity
    if (
        state.phase != "passed"
        or capability is None
        or not capability.consumed
        or capability.expired
        or capability.token_hash != run.capability_token_hash
        or capability.consumed_by != run.actor
        or capability.consumer_binding_hash != run.consumer_binding_hash
        or preflight.request_sha256 != run.preflight_request_sha256
        or manifest.preflight_id != run.preflight_id
        or identity["config_sha256"] != config.config_sha256
        or identity["contract_sha256"] != config.contract_sha256
        or identity["profile_id"] != manifest.profile_id
        or identity["profile_hash"] != manifest.profile_hash
        or identity["scheduler_policy_hash"] != manifest.scheduler_policy_hash
        or identity["project_hash"] != manifest.project_hash
        or identity["resume_run_id"] != manifest.resume_run_id
        or (identity["operation"] == "resume") != (manifest.resume_run_id is not None)
        or run.deployment.deployment_dir != manifest.deploy_dir
        or run.deployment.bundle_hash != identity["deployment"]["bundle_hash"]
    ):
        raise SchedulerWorkloadError("run, config, deployment, and preflight bindings conflict")
    approval_hashes = identity["approval_artifact_hashes"]
    if any(approval_hashes[name] != digest for name, digest in manifest.artifact_hashes.items()):
        raise SchedulerWorkloadError("preflight artifacts do not match approved run artifacts")
    runtime = manifest.compute_runtime
    expected_runtime = {
        "python": (runtime.python_executable, runtime.python_sha256),
        "java": (runtime.java_executable, runtime.java_sha256),
        "nextflow": (runtime.nextflow_executable, runtime.nextflow_sha256),
        "apptainer": (runtime.apptainer_executable, runtime.apptainer_sha256),
    }
    for role, (path, digest) in expected_runtime.items():
        binding = config.executables[role]
        if str(binding.path) != path or binding.sha256 != digest:
            raise SchedulerWorkloadError("preflight runtime differs from trusted config-v2")
    if (
        str(config.nextflow_jar.path) != runtime.nextflow_jar
        or config.nextflow_jar.sha256 != runtime.nextflow_jar_sha256
        or config.contract.nextflow_version != runtime.nextflow_version
        or state.manifest_sha256 != _canonical_manifest_hash(manifest.as_mapping())
    ):
        raise SchedulerWorkloadError("preflight Nextflow binding differs from trusted config-v2")
    deployed = {item.path for item in run.deployment.files}
    if not deployed >= _REQUIRED_DEPLOYMENT_FILES:
        raise SchedulerWorkloadError("sealed deployment lacks a fixed workload entry file")


def _nextflow_environment(
    state: SchedulerPreflightState,
    private_directories: tuple[str, ...],
) -> Mapping[str, str]:
    manifest = state.manifest
    runtime = manifest.compute_runtime
    if len(private_directories) != 5:
        raise SchedulerWorkloadError("workload private directory contract changed")
    home, nxf_home, temporary, apptainer_config, nextflow_cache = private_directories
    path_directories: list[str] = []
    for executable in (
        runtime.apptainer_executable,
        runtime.java_executable,
        runtime.nextflow_executable,
    ):
        directory = str(PurePosixPath(executable).parent)
        if ":" in directory:
            raise SchedulerWorkloadError("runtime parent cannot contain the PATH separator")
        if directory not in path_directories:
            path_directories.append(directory)
    for directory in ("/bin", "/usr/bin"):
        if directory not in path_directories:
            path_directories.append(directory)
    return MappingProxyType(
        {
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": ":".join(path_directories),
            "HOME": home,
            "JAVA_CMD": runtime.java_executable,
            "NXF_ANSI_LOG": "false",
            "NXF_CACHE_DIR": nextflow_cache,
            "NXF_OFFLINE": "true",
            "NXF_DISABLE_CHECK_LATEST": "true",
            "NXF_HOME": nxf_home,
            "NXF_BIN": runtime.nextflow_jar,
            "NXF_VER": runtime.nextflow_version,
            "NXF_TEMP": temporary,
            "TMPDIR": temporary,
            "APPTAINER_CACHEDIR": manifest.cache_dir,
            "APPTAINER_CONFIGDIR": apptainer_config,
            "SINGULARITY_CACHEDIR": manifest.cache_dir,
            "SINGULARITY_CONFIGDIR": apptainer_config,
        }
    )


def _binding_hash(**values: Any) -> str:
    return _canonical_hash(
        {
            "domain": "easy-pipe.scheduler-workload.binding.v1",
            "workload_contract_version": WORKLOAD_CONTRACT_VERSION,
            **{
                key: (
                    list(value)
                    if isinstance(value, tuple)
                    else dict(value)
                    if isinstance(value, Mapping)
                    else value
                )
                for key, value in values.items()
            },
        }
    )


def canonical_workload_plan_bytes(plan: SchedulerWorkloadPlan) -> bytes:
    """Return the canonical secret-free bytes represented by the binding digest."""

    if not isinstance(plan, SchedulerWorkloadPlan):
        raise SchedulerWorkloadError("validated workload plan is required")
    value = {
        "domain": "easy-pipe.scheduler-workload.binding.v1",
        "workload_contract_version": WORKLOAD_CONTRACT_VERSION,
        "run_id": plan.run_id,
        "run_identity_sha256": plan.run_identity_sha256,
        "preflight_request_sha256": plan.preflight_request_sha256,
        "preflight_revision": plan.preflight_revision,
        "preflight_journal_sha256": plan.preflight_journal_sha256,
        "manifest_sha256": plan.manifest_sha256,
        "resume": plan.resume,
        "bootstrap_argv": list(plan.bootstrap_argv),
        "batch_sha256": plan.batch_sha256,
        "overlay_path": plan.overlay_path,
        "overlay_sha256": plan.overlay_sha256,
        "nextflow_argv": list(plan.nextflow_argv),
        "command_sha256": plan.command_sha256,
        "environment": dict(plan.environment),
        "environment_sha256": plan.environment_sha256,
        "private_directories": list(plan.private_directories),
        "working_directory": plan.working_directory,
        "submission_marker": plan.submission_marker,
        "submit_argv": list(plan.submit_argv),
        "submit_environment": dict(plan.submit_environment),
    }
    return _canonical_bytes(value)


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _canonical_manifest_hash(value: Mapping[str, Any]) -> str:
    return _canonical_hash(value)


def _shell_quote(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SchedulerWorkloadError("workload argv contains an unsafe value")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SchedulerWorkloadError("workload argv contains control text")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SchedulerWorkloadError("workload batch argv must be shell-inert ASCII") from exc
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _canonical_absolute_path(value: str, *, leaf: str | None = None) -> bool:
    if not isinstance(value, str) or not value:
        return False
    selected = PurePosixPath(value)
    return (
        selected.is_absolute()
        and selected != PurePosixPath("/")
        and ".." not in selected.parts
        and str(selected) == value
        and (leaf is None or selected.name == leaf)
    )


def _nextflow_session_name(run_id: str) -> str:
    if not isinstance(run_id, str) or _IDENTIFIER.fullmatch(run_id) is None:
        raise SchedulerWorkloadError("workload run identifier is invalid")
    return "ep-" + hashlib.sha256(run_id.encode("ascii")).hexdigest()


def _groovy_quote(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SchedulerWorkloadError("Nextflow config contains an unsafe value")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SchedulerWorkloadError("Nextflow config contains control text")
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


__all__ = [
    "WORKLOAD_CONTRACT_VERSION",
    "SchedulerWorkloadError",
    "SchedulerWorkloadPlan",
    "build_nextflow_argv",
    "canonical_workload_plan_bytes",
    "prepare_scheduler_workload",
    "render_nextflow_overlay",
    "render_workload_batch",
]
