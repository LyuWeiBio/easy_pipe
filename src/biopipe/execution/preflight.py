"""Controller orchestration for remote execution preflight."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Final, Protocol
from uuid import uuid4

import yaml
from pydantic import ValidationError

from biopipe.cli.reports import (
    read_project_private_state,
    write_project_private_state_atomic,
    write_project_report_atomic,
)
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution.client import ExecutionOperation, OpenSSHExecutionClient
from biopipe.execution.deploy import DeploymentBundle, build_deployment_bundle
from biopipe.execution.models import (
    CoreArtifactHashes,
    ExecutionProfile,
    PreflightCheck,
    PreflightReport,
    compute_input_set_hash,
    compute_project_hash,
)
from biopipe.models import (
    DatasetManifest,
    ExecutionPlan,
    PipelineSpec,
    SoftwareLock,
    SourceProfile,
)

_MAX_PROFILE_BYTES: Final[int] = 1024 * 1024
_TOKEN_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9._~-]{32,256}$")
_REMOTE_CHECKS: Final[frozenset[str]] = frozenset(
    {
        "runtime",
        "rawdata_readable",
        "workdir_writable",
        "output_dir_writable",
        "cache_writable",
        "disk_space",
        "container",
        "path_mapping",
        "host_relationship",
        "network_policy",
    }
)
_REQUIRED_REMOTE_CHECKS: Final[frozenset[str]] = _REMOTE_CHECKS - {"network_policy"}


class ExecutionClient(Protocol):
    """Narrow client seam used by unit and integration tests."""

    def invoke(
        self,
        source: SourceProfile,
        *,
        agent_path: str,
        operation: ExecutionOperation,
        payload: dict[str, Any],
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Invoke one fixed remote operation."""


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """One in-memory, recompiled and profile-validated execution snapshot."""

    project: Path
    profile_path: Path
    profile: ExecutionProfile
    bundle: DeploymentBundle
    manifest: DatasetManifest
    spec: PipelineSpec
    plan: ExecutionPlan
    software_lock: SoftwareLock
    core_hashes: CoreArtifactHashes
    project_hash: str
    connection: SourceProfile


def load_execution_context(
    project_directory: str | Path,
    execution_profile_path: str | Path,
    *,
    check_output_conflict: bool = True,
) -> ExecutionContext:
    """Load one safe controller snapshot shared by preflight and submission."""

    project = Path(project_directory).expanduser().absolute()
    profile_path = Path(execution_profile_path).expanduser().absolute()
    profile, profile_bytes = _load_profile(profile_path)
    bundle = build_deployment_bundle(
        project,
        check_output_conflict=check_output_conflict,
    )
    manifest, spec, plan, software_lock = _bundle_models(bundle)
    _validate_profile(profile, spec, plan, software_lock)
    core_hashes = _core_hashes(bundle, profile_bytes)
    return ExecutionContext(
        project=project,
        profile_path=profile_path,
        profile=profile,
        bundle=bundle,
        manifest=manifest,
        spec=spec,
        plan=plan,
        software_lock=software_lock,
        core_hashes=core_hashes,
        project_hash=compute_project_hash(core_hashes),
        connection=_connection_profile(profile),
    )


def run_preflight(
    project_directory: str | Path,
    execution_profile_path: str | Path,
    *,
    client: ExecutionClient | None = None,
    checked_at: datetime | None = None,
    resume_run_id: str | None = None,
) -> PreflightReport:
    """Run all local and remote M5 checks and persist sanitized evidence."""

    context = load_execution_context(
        project_directory,
        execution_profile_path,
        check_output_conflict=resume_run_id is None,
    )
    project = context.project
    profile = context.profile
    core_hashes = context.core_hashes
    project_hash = context.project_hash
    source_paths, execution_paths = _mapped_inputs(context.manifest, context.plan)
    input_set_hash = compute_input_set_hash(execution_paths)
    timestamp = (checked_at or datetime.now(UTC)).astimezone(UTC)
    preflight_id = f"preflight-{uuid4().hex}"
    previous_state = None if resume_run_id is None else _resume_state(context, resume_run_id)
    deployment_dir = (
        compute_deployment_directory(profile, context.spec, project_hash, preflight_id)
        if previous_state is None
        else str(previous_state["deployment_dir"])
    )
    selected_client = client or OpenSSHExecutionClient()
    payload = _preflight_payload(
        profile=profile,
        manifest=context.manifest,
        spec=context.spec,
        plan=context.plan,
        software_lock=context.software_lock,
        core_hashes=core_hashes,
        project_hash=project_hash,
        preflight_id=preflight_id,
        deployment_dir=deployment_dir,
        source_paths=source_paths,
        execution_paths=execution_paths,
        resume_run_id=resume_run_id,
    )

    token: str | None = None
    try:
        result = selected_client.invoke(
            context.connection,
            agent_path=profile.bioexec_path,
            operation="preflight",
            payload=payload,
        )
        checks, token = _validate_remote_result(
            result,
            preflight_id=preflight_id,
            input_count=len(set(execution_paths)),
            input_set_hash=input_set_hash,
        )
    except BioPipeError as exc:
        checks = (
            PreflightCheck(
                name="ssh",
                status="failed",
                code=exc.code.value,
                message="The fixed SSH preflight transport did not complete.",
            ),
        )

    report = PreflightReport(
        status="passed" if all(check.status == "passed" for check in checks) else "failed",
        checked_at=timestamp,
        profile_id=profile.profile_id,
        source_host=profile.source_host,
        execution_host=profile.execution_host,
        artifact_hashes=core_hashes,
        preflight_id=preflight_id,
        project_hash=project_hash,
        input_count=len(set(execution_paths)),
        input_set_hash=input_set_hash,
        checks=tuple(sorted(checks, key=lambda check: check.name)),
    )
    report_path = write_project_report_atomic(
        project,
        "preflight.json",
        report.model_dump(mode="json"),
    )
    if report.status == "passed":
        assert token is not None
        write_project_private_state_atomic(
            project,
            ".preflight-state.json",
            {
                "state_version": "1.0",
                "preflight_id": preflight_id,
                "preflight_token": token,
                "profile_id": profile.profile_id,
                "profile_hash": core_hashes.execution_profile,
                "project_hash": project_hash,
                "bundle_hash": context.bundle.bundle_hash,
                "deployment_dir": deployment_dir,
                "preflight_report_sha256": _sha256_regular(report_path),
                "checked_at": timestamp.isoformat().replace("+00:00", "Z"),
                "resume_run_id": resume_run_id,
                "deployment_id": (
                    None if previous_state is None else previous_state["deployment_id"]
                ),
            },
        )
    return report


def _preflight_payload(
    *,
    profile: ExecutionProfile,
    manifest: DatasetManifest,
    spec: PipelineSpec,
    plan: ExecutionPlan,
    software_lock: SoftwareLock,
    core_hashes: CoreArtifactHashes,
    project_hash: str,
    preflight_id: str,
    deployment_dir: str,
    source_paths: tuple[str, ...],
    execution_paths: tuple[str, ...],
    resume_run_id: str | None,
) -> dict[str, Any]:
    del manifest
    containers = []
    for name, locked in sorted(software_lock.components.items()):
        configured = profile.containers[name]
        containers.append(
            {
                "name": name,
                "image": locked.image,
                "digest": locked.digest,
                "local_path": configured.local_path,
                "file_sha256": configured.file_sha256,
            }
        )
    payload: dict[str, Any] = {
        "preflight_id": preflight_id,
        "profile_id": profile.profile_id,
        "profile_hash": core_hashes.execution_profile,
        "project_hash": project_hash,
        "artifact_hashes": core_hashes.model_dump(mode="json"),
        "source_host": profile.source_host,
        "execution_host": profile.execution_host,
        "host_relation": ("same" if profile.source_host == profile.execution_host else "shared"),
        "source_paths": list(source_paths),
        "execution_paths": list(execution_paths),
        "path_mapping": [
            {
                "source_prefix": mapping.source_prefix,
                "execution_prefix": mapping.execution_prefix,
            }
            for mapping in (plan.path_mapping or [])
        ],
        "deploy_dir": deployment_dir,
        "work_dir": spec.paths.work_dir,
        "output_dir": spec.paths.output_dir,
        "cache_dir": spec.paths.container_cache,
        "container_engine": profile.runtime.container_engine,
        "containers": containers,
        "minimum_free_bytes": profile.disk_threshold.minimum_free_bytes,
        "network_disabled": True,
    }
    if resume_run_id is not None:
        payload["resume_run_id"] = resume_run_id
    return payload


def _validate_remote_result(
    result: dict[str, Any],
    *,
    preflight_id: str,
    input_count: int,
    input_set_hash: str,
) -> tuple[tuple[PreflightCheck, ...], str | None]:
    expected = {
        "preflight_id",
        "preflight_token",
        "status",
        "checks",
        "input_count",
        "input_set_hash",
    }
    if set(result) != expected:
        raise _preflight_protocol_error()
    if result["preflight_id"] != preflight_id:
        raise _preflight_protocol_error()
    if result["input_count"] != input_count or result["input_set_hash"] != input_set_hash:
        raise _preflight_protocol_error()
    if result["status"] not in {"passed", "failed"} or not isinstance(result["checks"], list):
        raise _preflight_protocol_error()
    token = result["preflight_token"]
    if result["status"] == "passed":
        if not isinstance(token, str) or not _TOKEN_PATTERN.fullmatch(token):
            raise _preflight_protocol_error()
    elif token is not None:
        raise _preflight_protocol_error()

    parsed: list[PreflightCheck] = []
    for value in result["checks"]:
        if not isinstance(value, dict) or set(value) - {"name", "status", "code", "message"}:
            raise _preflight_protocol_error()
        name = value.get("name")
        status = value.get("status")
        code = value.get("code")
        if name not in _REMOTE_CHECKS or status not in {"passed", "failed"}:
            raise _preflight_protocol_error()
        if code is not None and (
            not isinstance(code, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", code)
        ):
            raise _preflight_protocol_error()
        parsed.append(
            PreflightCheck(
                name=name,
                status=status,
                code=code,
                message="The fixed remote preflight check completed.",
            )
        )
    names = {check.name for check in parsed}
    if not names >= _REQUIRED_REMOTE_CHECKS or len(names) != len(parsed):
        raise _preflight_protocol_error()
    parsed.append(
        PreflightCheck(
            name="ssh",
            status="passed",
            message="Strict host-key-checked SSH transport completed.",
        )
    )
    all_passed = all(check.status == "passed" for check in parsed)
    if (result["status"] == "passed") != all_passed:
        raise _preflight_protocol_error()
    return tuple(parsed), token if isinstance(token, str) else None


def _bundle_models(
    bundle: DeploymentBundle,
) -> tuple[DatasetManifest, PipelineSpec, ExecutionPlan, SoftwareLock]:
    try:
        manifest = DatasetManifest.model_validate(
            json.loads(bundle.content("dataset.manifest.resolved.json").decode("utf-8"))
        )
        spec = PipelineSpec.model_validate(
            yaml.safe_load(bundle.content("pipeline.spec.yaml").decode("utf-8"))
        )
        plan = ExecutionPlan.model_validate(
            yaml.safe_load(bundle.content("execution.plan.yaml").decode("utf-8"))
        )
        software_lock = SoftwareLock.model_validate(
            yaml.safe_load(bundle.content("software.lock.yaml").decode("utf-8"))
        )
    except (KeyError, UnicodeError, TypeError, ValueError, ValidationError, yaml.YAMLError) as exc:
        raise BioPipeError(
            ErrorCode.PREFLIGHT_FAILED,
            "The deployment snapshot does not contain valid core artifacts.",
        ) from exc
    return manifest, spec, plan, software_lock


def _core_hashes(bundle: DeploymentBundle, profile_bytes: bytes) -> CoreArtifactHashes:
    file_hashes = {item.path: item.sha256 for item in bundle.files}
    return CoreArtifactHashes(
        dataset_manifest=file_hashes["dataset.manifest.resolved.json"],
        pipeline_spec=file_hashes["pipeline.spec.yaml"],
        execution_plan=file_hashes["execution.plan.yaml"],
        software_lock=file_hashes["software.lock.yaml"],
        execution_profile=hashlib.sha256(profile_bytes).hexdigest(),
    )


def _mapped_inputs(
    manifest: DatasetManifest,
    plan: ExecutionPlan,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    source_paths = tuple(
        value
        for sample in manifest.samples
        for lane in sample.lanes
        for value in (lane.read1, lane.read2)
        if value is not None
    )
    mappings = plan.path_mapping or []
    mapped: list[str] = []
    for value in source_paths:
        source = PurePosixPath(value)
        candidates = []
        for mapping in mappings:
            prefix = PurePosixPath(mapping.source_prefix)
            try:
                relative = source.relative_to(prefix)
            except ValueError:
                continue
            candidates.append((len(prefix.parts), mapping, relative))
        if mappings and not candidates:
            raise _profile_error("A manifest input has no reviewed execution path mapping.")
        if candidates:
            _length, selected, relative = max(candidates, key=lambda item: item[0])
            execution = PurePosixPath(selected.execution_prefix) / relative
        else:
            execution = source
        execution_root = PurePosixPath(plan.paths.execution_root)
        if execution == execution_root or execution_root not in execution.parents:
            raise _profile_error("A mapped input is outside the planned execution root.")
        mapped.append(str(execution))
    if not source_paths or len(set(source_paths)) != len(source_paths):
        raise _profile_error("The manifest input set is empty or contains duplicates.")
    return source_paths, tuple(mapped)


def _validate_profile(
    profile: ExecutionProfile,
    spec: PipelineSpec,
    plan: ExecutionPlan,
    software_lock: SoftwareLock,
) -> None:
    if (
        profile.source_host != plan.source_host
        or profile.execution_host != plan.execution_host
        or profile.runtime.executor != plan.executor
        or profile.runtime.executor != spec.execution.executor
        or profile.runtime.container_engine != spec.execution.container_engine
    ):
        raise _profile_error("The execution profile does not match the reviewed plan.")
    planned_mappings = {
        (mapping.source_prefix, mapping.execution_prefix) for mapping in (plan.path_mapping or [])
    }
    profile_mappings = {
        (mapping.source_prefix, mapping.execution_prefix) for mapping in profile.path_mapping
    }
    if planned_mappings != profile_mappings:
        raise _profile_error("The execution profile does not authorize the planned path mapping.")
    if set(profile.containers) != set(software_lock.components):
        raise _profile_error("The execution profile container set differs from the software lock.")
    for name, locked in software_lock.components.items():
        configured = profile.containers[name]
        if configured.image != locked.image or configured.digest != locked.digest:
            raise _profile_error("The execution profile container identity is not locked.")
        if configured.local_path is not None and not _below_any(
            configured.local_path,
            profile.allowed_roots.cache,
        ):
            raise _profile_error("An offline container is outside the approved cache roots.")
    for value, roots in (
        (spec.paths.work_dir, profile.allowed_roots.work),
        (spec.paths.output_dir, profile.allowed_roots.output),
        (spec.paths.container_cache, profile.allowed_roots.cache),
    ):
        if not _below_any(value, roots):
            raise _profile_error("A planned writable path is outside its role allowlist.")


def compute_deployment_directory(
    profile: ExecutionProfile,
    spec: PipelineSpec,
    project_hash: str,
    preflight_id: str,
) -> str:
    """Return the deterministic deployment directory bound by preflight."""

    leaf = f"{spec.project.name}-{project_hash[:12]}-{preflight_id.removeprefix('preflight-')[:12]}"
    return str(PurePosixPath(profile.allowed_roots.deploy[0]) / leaf)


def _resume_state(context: ExecutionContext, run_id: str) -> dict[str, Any]:
    if not re.fullmatch(r"run-[0-9a-f]{32}", run_id):
        raise BioPipeError(
            ErrorCode.RESUME_INCOMPATIBLE,
            "The requested resume run ID is invalid.",
        )
    state = read_project_private_state(context.project, ".run-state.json")
    required = {
        "state_version",
        "run_id",
        "profile_id",
        "profile_hash",
        "project_hash",
        "bundle_hash",
        "deployment_id",
        "deployment_dir",
        "authorization",
    }
    if (
        not required <= set(state)
        or state.get("state_version") != "1.0"
        or state.get("run_id") != run_id
        or state.get("profile_id") != context.profile.profile_id
        or state.get("profile_hash") != context.core_hashes.execution_profile
        or state.get("project_hash") != context.project_hash
        or state.get("bundle_hash") != context.bundle.bundle_hash
        or not isinstance(state.get("deployment_id"), str)
        or not isinstance(state.get("deployment_dir"), str)
    ):
        raise BioPipeError(
            ErrorCode.RESUME_INCOMPATIBLE,
            "The requested resume does not match the current execution artifacts.",
            remediation=["Repeat preflight and resume the matching recorded run."],
        )
    return state


def _connection_profile(profile: ExecutionProfile) -> SourceProfile:
    roots = sorted(
        set(
            profile.allowed_roots.deploy
            + profile.allowed_roots.work
            + profile.allowed_roots.output
            + profile.allowed_roots.cache
        )
    )
    return SourceProfile(
        source_id=profile.profile_id,
        ssh_alias=profile.ssh_alias,
        username=profile.username,
        port=profile.port,
        allowed_roots=roots,
    )


def _load_profile(path: Path) -> tuple[ExecutionProfile, bytes]:
    try:
        payload = _read_bounded_regular(path, _MAX_PROFILE_BYTES)
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        return ExecutionProfile.model_validate(value), payload
    except (OSError, UnicodeError, TypeError, ValueError, ValidationError, RecursionError) as exc:
        raise _profile_error("The execution profile file is missing, unsafe, or invalid.") from exc


def _read_bounded_regular(path: Path, maximum: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
            or not 0 < metadata.st_size <= maximum
        ):
            raise OSError("input is not a bounded stable regular file")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum:
            raise OSError("input exceeds its size limit")
        return payload
    finally:
        os.close(descriptor)


def _sha256_regular(path: Path) -> str:
    return hashlib.sha256(_read_bounded_regular(path, 16 * 1024 * 1024)).hexdigest()


def _below_any(value: str, roots: tuple[str, ...]) -> bool:
    path = PurePosixPath(value)
    return any(PurePosixPath(root) in path.parents for root in roots)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _profile_error(message: str) -> BioPipeError:
    return BioPipeError(
        ErrorCode.EXECUTION_PROFILE_INVALID,
        message,
        remediation=["Use a reviewed execution profile matching the generated plan."],
    )


def _preflight_protocol_error() -> BioPipeError:
    return BioPipeError(
        ErrorCode.REMOTE_EXECUTION_PROTOCOL_ERROR,
        "The remote preflight result violates its fixed contract.",
        remediation=["Install the reviewed bioexec.pyz version and retry."],
    )


__all__ = [
    "ExecutionContext",
    "compute_deployment_directory",
    "load_execution_context",
    "run_preflight",
]
