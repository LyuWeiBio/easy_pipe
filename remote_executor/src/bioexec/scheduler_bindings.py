"""Trusted bindings shared by dormant scheduler state, transport, and worker files."""

from __future__ import annotations

import re
from pathlib import Path

from .scheduler_config_loader import (
    TrustedSchedulerConfig,
    verify_scheduler_executable,
    verify_scheduler_nextflow_jar,
)
from .scheduler_preflight import ComputePreflightManifest, ComputeRuntimeBinding

SCHEDULER_PREFLIGHT_NAMESPACE = "scheduler-preflights-v1"

_COMPUTE_EXECUTABLE_ROLES = (
    "python",
    "java",
    "nextflow",
    "apptainer",
    "compute_worker",
)
_PREFLIGHT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", re.ASCII)


class SchedulerBindingError(ValueError):
    """A compute manifest does not bind the trusted scheduler installation."""


def trusted_compute_runtime(config: TrustedSchedulerConfig) -> ComputeRuntimeBinding:
    """Build the only runtime binding admitted by one trusted config instance."""

    if not isinstance(config, TrustedSchedulerConfig):
        raise SchedulerBindingError("a trusted scheduler configuration is required")
    bindings = config.executables
    hashes = {role: bindings[role].sha256 for role in _COMPUTE_EXECUTABLE_ROLES}
    if any(value is None for value in hashes.values()) or config.nextflow_jar.sha256 is None:
        raise SchedulerBindingError("trusted compute files require complete SHA-256 bindings")
    limits = config.contract.limits
    return ComputeRuntimeBinding(
        python_executable=str(bindings["python"].path),
        python_sha256=_required_hash(hashes["python"]),
        java_executable=str(bindings["java"].path),
        java_sha256=_required_hash(hashes["java"]),
        nextflow_executable=str(bindings["nextflow"].path),
        nextflow_sha256=_required_hash(hashes["nextflow"]),
        nextflow_version=config.contract.nextflow_version,
        nextflow_jar=str(config.nextflow_jar.path),
        nextflow_jar_sha256=_required_hash(config.nextflow_jar.sha256),
        apptainer_executable=str(bindings["apptainer"].path),
        apptainer_sha256=_required_hash(hashes["apptainer"]),
        command_timeout_seconds=limits.command_timeout_seconds,
        max_command_output_bytes=limits.max_command_output_bytes,
    )


def expected_worker_paths(config: TrustedSchedulerConfig, preflight_id: str) -> tuple[str, str]:
    """Derive manifest and evidence paths; callers cannot select another directory."""

    if not isinstance(config, TrustedSchedulerConfig):
        raise SchedulerBindingError("a trusted scheduler configuration is required")
    if not isinstance(preflight_id, str) or _PREFLIGHT_ID.fullmatch(preflight_id) is None:
        raise SchedulerBindingError("a scheduler preflight identifier is required")
    directory = Path(config.state_root.path) / SCHEDULER_PREFLIGHT_NAMESPACE / preflight_id
    return str(directory / "manifest.json"), str(directory / "evidence.json")


def validate_compute_bindings(
    config: TrustedSchedulerConfig,
    manifest: ComputePreflightManifest,
) -> None:
    """Require exact trusted runtime, worker, and owner-only attempt-file bindings."""

    if not isinstance(manifest, ComputePreflightManifest):
        raise SchedulerBindingError("a validated compute manifest is required")
    expected_manifest, expected_evidence = expected_worker_paths(config, manifest.preflight_id)
    worker = config.executables["compute_worker"]
    limits = config.contract.limits
    if worker.sha256 is None:
        raise SchedulerBindingError("trusted compute worker has no SHA-256 binding")
    if (
        manifest.compute_runtime != trusted_compute_runtime(config)
        or manifest.worker.executable != str(worker.path)
        or manifest.worker.executable_sha256 != worker.sha256
        or manifest.worker.manifest_path != expected_manifest
        or manifest.worker.evidence_path != expected_evidence
        or manifest.preflight_ttl_seconds != limits.preflight_ttl_seconds
        or manifest.minimum_free_bytes != limits.minimum_free_bytes
    ):
        raise SchedulerBindingError("compute manifest does not bind the trusted installation")


def verify_compute_installation(
    config: TrustedSchedulerConfig,
    manifest: ComputePreflightManifest,
) -> None:
    """Re-open and hash every compute executable immediately before submission."""

    validate_compute_bindings(config, manifest)
    for role in _COMPUTE_EXECUTABLE_ROLES:
        verify_scheduler_executable(config, role)  # type: ignore[arg-type]
    verify_scheduler_nextflow_jar(config)


def _required_hash(value: str | None) -> str:
    if value is None:
        raise SchedulerBindingError("trusted compute file has no SHA-256 binding")
    return value


__all__ = [
    "SCHEDULER_PREFLIGHT_NAMESPACE",
    "SchedulerBindingError",
    "expected_worker_paths",
    "trusted_compute_runtime",
    "validate_compute_bindings",
    "verify_compute_installation",
]
