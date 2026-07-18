"""Fail-closed authorization gate for reviewed real-data execution."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel, ValidationError

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution.models import (
    ApprovalArtifactPaths,
    ApprovalRequest,
    AuthorizationArtifactHashes,
    CoreArtifactHashes,
    ExecutionProfile,
    PreflightReport,
    RunAuthorization,
    compute_input_set_hash,
    compute_project_hash,
)
from biopipe.manifests import require_valid_manifest
from biopipe.models import (
    DatasetManifest,
    ExecutionApproval,
    ExecutionPlan,
    PipelinePolicy,
    PipelineSpec,
    SoftwareLock,
)
from biopipe.planner import reconstruct_planned_pipeline
from biopipe.report_models import TestCommandReport, ValidationCommandReport

_MAX_CORE_BYTES = 16 * 1024 * 1024
_MAX_REPORT_BYTES = 16 * 1024 * 1024
_MAX_PROFILE_BYTES = 256 * 1024
_MAX_PREFLIGHT_BYTES = 1024 * 1024
_CLOCK_SKEW = timedelta(minutes=5)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CORE_NAMES = {
    "dataset_manifest": "dataset.manifest.resolved.json",
    "pipeline_spec": "pipeline.spec.yaml",
    "execution_plan": "execution.plan.yaml",
    "software_lock": "software.lock.yaml",
}
_REPORT_NAMES = {
    "validation_report": "validation.json",
    "test_report": "test.json",
    "preflight_report": "preflight.json",
}
_REQUIRED_PREFLIGHT_CHECKS = frozenset(
    {
        "cache_writable",
        "container",
        "disk_space",
        "host_relationship",
        "output_dir_writable",
        "path_mapping",
        "rawdata_readable",
        "runtime",
        "ssh",
        "workdir_writable",
    }
)

ModelT = TypeVar("ModelT", bound=BaseModel)


class _UniqueSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that also rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueSafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found a duplicate mapping key",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class _Artifact:
    __slots__ = ("digest", "payload")

    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.digest = hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class LocalGateEvidence:
    """Validated in-memory evidence for side-effect-free local run checks."""

    project_id: str
    profile_id: str
    manifest: DatasetManifest
    spec: PipelineSpec
    plan: ExecutionPlan
    software_lock: SoftwareLock
    profile: ExecutionProfile
    preflight: PreflightReport
    core_hashes: CoreArtifactHashes
    artifact_hashes: AuthorizationArtifactHashes
    preflight_checked_at: datetime

    def validate_approval_time(self, approved_at: datetime) -> None:
        """Apply the real authorization ordering check without creating authorization."""

        if _utc_now(approved_at) < self.preflight_checked_at:
            raise _gate_error(ErrorCode.APPROVAL_REQUIRED, "approval_precedes_preflight")

    def validate_resume_compatibility(
        self,
        previous: RunAuthorization,
        *,
        bundle_hash: str,
    ) -> None:
        """Apply the real resume compatibility check to validated local evidence."""

        if not _SHA256.fullmatch(bundle_hash):
            raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "bundle_hash_invalid")
        if (
            previous.project_id != self.project_id
            or previous.profile_id != self.profile_id
            or previous.compatibility_hash != _compatibility_hash(self.core_hashes, bundle_hash)
        ):
            raise _gate_error(ErrorCode.RESUME_INCOMPATIBLE, "authorization_inputs_changed")


class ApprovalGate:
    """Bind reviewed artifacts and fresh preflight evidence into one authorization."""

    def authorize(
        self,
        artifacts: ApprovalArtifactPaths,
        request: ApprovalRequest,
        *,
        bundle_hash: str,
        previous_authorization: RunAuthorization | None = None,
        now: datetime | None = None,
    ) -> RunAuthorization:
        """Authorize a run while preserving the stable public return contract."""

        authorization, _evidence = self.authorize_with_evidence(
            artifacts,
            request,
            bundle_hash=bundle_hash,
            previous_authorization=previous_authorization,
            now=now,
        )
        return authorization

    def authorize_with_evidence(
        self,
        artifacts: ApprovalArtifactPaths,
        request: ApprovalRequest,
        *,
        bundle_hash: str,
        previous_authorization: RunAuthorization | None = None,
        now: datetime | None = None,
    ) -> tuple[RunAuthorization, LocalGateEvidence]:
        """Authorize and retain the already validated evidence for local state binding."""

        try:
            artifacts = ApprovalArtifactPaths.model_validate(artifacts.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError, ValidationError) as exc:
            raise _gate_error(
                ErrorCode.APPROVAL_ARTIFACT_MISMATCH,
                "approval_inputs_invalid",
            ) from exc
        try:
            request = ApprovalRequest.model_validate(request.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError, ValidationError) as exc:
            raise _gate_error(ErrorCode.APPROVAL_REQUIRED, "approval_request_invalid") from exc
        if not request.approve_real_data:
            raise _gate_error(ErrorCode.APPROVAL_REQUIRED, "cli_approval_missing")
        if not _SHA256.fullmatch(bundle_hash):
            raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "bundle_hash_invalid")
        current_time = _utc_now(now)
        if request.approved_at > current_time + _CLOCK_SKEW:
            raise _gate_error(ErrorCode.APPROVAL_REQUIRED, "approval_time_in_future")

        evidence = self._validate_local_evidence(artifacts, current_time)
        evidence.validate_approval_time(request.approved_at)

        compatibility_hash = _compatibility_hash(evidence.core_hashes, bundle_hash)
        authorization_id = _authorization_id(
            project_id=evidence.project_id,
            actor=request.actor,
            approved_at=request.approved_at,
            policy=request.policy.model_dump(mode="json"),
            hashes=evidence.artifact_hashes,
            bundle_hash=bundle_hash,
        )
        authorization = RunAuthorization(
            authorization_id=authorization_id,
            project_id=evidence.project_id,
            profile_id=evidence.profile_id,
            actor=request.actor,
            approved_at=request.approved_at,
            cli_approved=True,
            policy=request.policy,
            artifact_hashes=evidence.artifact_hashes,
            bundle_hash=bundle_hash,
            preflight_checked_at=evidence.preflight_checked_at,
            compatibility_hash=compatibility_hash,
        )
        if request.policy.resume:
            if previous_authorization is None:
                raise _gate_error(ErrorCode.RESUME_INCOMPATIBLE, "previous_authorization_missing")
            assert_resume_compatible(previous_authorization, authorization)
        return authorization, evidence

    def validate_local_evidence(
        self,
        artifacts: ApprovalArtifactPaths,
        *,
        now: datetime | None = None,
    ) -> LocalGateEvidence:
        """Validate current local gate evidence without authorizing or mutating a run."""

        try:
            artifacts = ApprovalArtifactPaths.model_validate(artifacts.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError, ValidationError) as exc:
            raise _gate_error(
                ErrorCode.APPROVAL_ARTIFACT_MISMATCH,
                "approval_inputs_invalid",
            ) from exc
        return self._validate_local_evidence(artifacts, _utc_now(now))

    def _validate_local_evidence(
        self,
        artifacts: ApprovalArtifactPaths,
        current_time: datetime,
    ) -> LocalGateEvidence:
        self._validate_layout(artifacts)
        material = self._read_material(artifacts)
        manifest = _parse_json_model(material["dataset_manifest"].payload, DatasetManifest)
        spec = _parse_yaml_model(material["pipeline_spec"].payload, PipelineSpec)
        plan = _parse_yaml_model(material["execution_plan"].payload, ExecutionPlan)
        software_lock = _parse_yaml_model(material["software_lock"].payload, SoftwareLock)
        profile = _parse_profile(material["execution_profile"].payload)
        validation = _parse_json_model(
            material["validation_report"].payload,
            ValidationCommandReport,
        )
        test = _parse_json_model(material["test_report"].payload, TestCommandReport)
        try:
            validation.require_gate_success()
            test.require_gate_success()
        except ValueError as exc:
            raise _gate_error(
                ErrorCode.APPROVAL_ARTIFACT_MISMATCH,
                "report_not_successful",
            ) from exc
        preflight = _parse_json_model(
            material["preflight_report"].payload,
            PreflightReport,
        )

        core_hashes = CoreArtifactHashes(
            dataset_manifest=material["dataset_manifest"].digest,
            pipeline_spec=material["pipeline_spec"].digest,
            execution_plan=material["execution_plan"].digest,
            software_lock=material["software_lock"].digest,
            execution_profile=material["execution_profile"].digest,
        )
        self._validate_core(manifest, spec, plan, software_lock, profile)
        self._validate_reports(validation, test, core_hashes)
        self._validate_preflight(
            preflight,
            manifest,
            plan,
            profile,
            core_hashes,
            current_time,
        )

        all_hashes = AuthorizationArtifactHashes(
            **core_hashes.model_dump(),
            validation_report=material["validation_report"].digest,
            test_report=material["test_report"].digest,
            preflight_report=material["preflight_report"].digest,
        )
        return LocalGateEvidence(
            project_id=spec.project.name,
            profile_id=profile.profile_id,
            manifest=manifest,
            spec=spec,
            plan=plan,
            software_lock=software_lock,
            profile=profile,
            preflight=preflight,
            core_hashes=core_hashes,
            artifact_hashes=all_hashes,
            preflight_checked_at=preflight.checked_at,
        )

    @staticmethod
    def _validate_layout(artifacts: ApprovalArtifactPaths) -> None:
        core_paths = {
            field: Path(getattr(artifacts, field)).expanduser().absolute() for field in _CORE_NAMES
        }
        project_roots = {path.parent for path in core_paths.values()}
        if len(project_roots) != 1 or any(
            core_paths[field].name != expected for field, expected in _CORE_NAMES.items()
        ):
            raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "core_layout_invalid")
        project_root = next(iter(project_roots))
        for field, expected in _REPORT_NAMES.items():
            path = Path(getattr(artifacts, field)).expanduser().absolute()
            if path.name != expected or path.parent != project_root / "reports":
                raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "report_layout_invalid")

    @staticmethod
    def _read_material(artifacts: ApprovalArtifactPaths) -> dict[str, _Artifact]:
        limits = {
            "dataset_manifest": _MAX_CORE_BYTES,
            "pipeline_spec": _MAX_CORE_BYTES,
            "execution_plan": _MAX_CORE_BYTES,
            "software_lock": _MAX_CORE_BYTES,
            "validation_report": _MAX_REPORT_BYTES,
            "test_report": _MAX_REPORT_BYTES,
            "execution_profile": _MAX_PROFILE_BYTES,
            "preflight_report": _MAX_PREFLIGHT_BYTES,
        }
        return {
            field: _Artifact(_read_bounded(Path(getattr(artifacts, field)), limit, field))
            for field, limit in limits.items()
        }

    @staticmethod
    def _validate_core(
        manifest: DatasetManifest,
        spec: PipelineSpec,
        plan: ExecutionPlan,
        software_lock: SoftwareLock,
        profile: ExecutionProfile,
    ) -> None:
        try:
            require_valid_manifest(manifest)
            reconstruct_planned_pipeline(spec, plan, software_lock)
        except BioPipeError as exc:
            raise _gate_error(
                ErrorCode.APPROVAL_ARTIFACT_MISMATCH,
                "core_artifacts_invalid",
            ) from exc
        if (
            manifest.errors
            or not manifest.samples
            or manifest.privacy.artifact_scope != "full"
            or spec.policy != PipelinePolicy()
            or plan.approval != ExecutionApproval()
            or manifest.classification.layout != spec.input.layout
            or spec.input.manifest != "dataset.manifest.resolved.json"
            or plan.paths.source_root != manifest.source.root
            or plan.paths.work_dir != spec.paths.work_dir
            or plan.paths.output_dir != spec.paths.output_dir
            or plan.paths.container_cache != spec.paths.container_cache
            or plan.executor != spec.execution.executor
            or plan.executor != "local"
            or profile.runtime.executor != plan.executor
            or profile.runtime.workflow_engine != spec.execution.workflow_engine
            or profile.runtime.container_engine != spec.execution.container_engine
            or profile.source_host != plan.source_host
            or profile.execution_host != plan.execution_host
        ):
            raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "core_contract_mismatch")
        if set(profile.containers) != set(software_lock.components) or any(
            profile.containers[name].image != component.image
            or profile.containers[name].digest != component.digest
            for name, component in software_lock.components.items()
        ):
            raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "container_lock_mismatch")
        if profile.runtime.container_engine == "apptainer" and any(
            artifact.local_path is None
            or not _below_any(artifact.local_path, profile.allowed_roots.cache)
            for artifact in profile.containers.values()
        ):
            raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "container_path_not_allowed")
        plan_mapping = tuple(
            sorted(
                (
                    mapping.source_prefix,
                    mapping.execution_prefix,
                )
                for mapping in (plan.path_mapping or [])
            )
        )
        profile_mapping = tuple(
            (mapping.source_prefix, mapping.execution_prefix) for mapping in profile.path_mapping
        )
        if plan_mapping != profile_mapping:
            raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "path_mapping_mismatch")
        write_paths = (
            (plan.paths.work_dir, profile.allowed_roots.work),
            (plan.paths.output_dir, profile.allowed_roots.output),
            (plan.paths.container_cache, profile.allowed_roots.cache),
        )
        if any(not _below_any(path, roots) for path, roots in write_paths):
            raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "write_path_not_allowed")

    @staticmethod
    def _validate_reports(
        validation: ValidationCommandReport,
        test: TestCommandReport,
        core_hashes: CoreArtifactHashes,
    ) -> None:
        expected = {
            "dataset.manifest.resolved.json": core_hashes.dataset_manifest,
            "execution.plan.yaml": core_hashes.execution_plan,
            "pipeline.spec.yaml": core_hashes.pipeline_spec,
            "software.lock.yaml": core_hashes.software_lock,
        }
        if any(
            report.static_validation.artifact_hashes.get(name) != digest
            for report in (validation, test)
            for name, digest in expected.items()
        ):
            raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "report_hash_mismatch")
        if validation.static_validation != test.static_validation:
            raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "validation_report_mismatch")

    @staticmethod
    def _validate_preflight(
        preflight: PreflightReport,
        manifest: DatasetManifest,
        plan: ExecutionPlan,
        profile: ExecutionProfile,
        core_hashes: CoreArtifactHashes,
        current_time: datetime,
    ) -> None:
        if preflight.status != "passed":
            raise _gate_error(ErrorCode.PREFLIGHT_FAILED, "preflight_not_passed")
        if _REQUIRED_PREFLIGHT_CHECKS - {check.name for check in preflight.checks}:
            raise _gate_error(ErrorCode.PREFLIGHT_FAILED, "preflight_checks_incomplete")
        if (
            preflight.profile_id != profile.profile_id
            or preflight.source_host != profile.source_host
            or preflight.execution_host != profile.execution_host
            or preflight.artifact_hashes != core_hashes
            or preflight.project_hash != compute_project_hash(core_hashes)
        ):
            raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "preflight_binding_mismatch")
        mapped_inputs = _mapped_input_paths(manifest, plan)
        if preflight.input_count != len(
            mapped_inputs
        ) or preflight.input_set_hash != compute_input_set_hash(mapped_inputs):
            raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "preflight_input_mismatch")
        age = current_time - preflight.checked_at
        if age < -_CLOCK_SKEW or age > timedelta(seconds=profile.preflight_max_age_seconds):
            raise _gate_error(ErrorCode.PREFLIGHT_STALE, "preflight_outside_freshness_window")


def assert_resume_compatible(
    previous: RunAuthorization,
    current: RunAuthorization,
) -> None:
    """Reject resume when any execution-relevant immutable input changed."""

    if (
        previous.project_id != current.project_id
        or previous.profile_id != current.profile_id
        or previous.compatibility_hash != current.compatibility_hash
    ):
        raise _gate_error(ErrorCode.RESUME_INCOMPATIBLE, "authorization_inputs_changed")


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    descriptor: int | None = None
    try:
        descriptor = _open_without_symlinks(path)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= limit:
            raise OSError("artifact is not a bounded regular file")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if not 0 < len(payload) <= limit:
            raise OSError("artifact exceeds its read limit")
        return payload
    except OSError as exc:
        raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, f"{label}_unreadable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _open_without_symlinks(path: Path) -> int:
    absolute = path.expanduser().absolute()
    parts = absolute.parts
    if not absolute.is_absolute() or len(parts) < 2:
        raise OSError("artifact path is invalid")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_descriptor = os.open(parts[0], directory_flags)
    try:
        for component in parts[1:-1]:
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        return os.open(
            parts[-1],
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_descriptor,
        )
    finally:
        os.close(directory_descriptor)


def _parse_json_model(payload: bytes, model_type: type[ModelT]) -> ModelT:
    try:
        data = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        return model_type.model_validate(data)
    except (UnicodeError, ValueError, TypeError, ValidationError, RecursionError) as exc:
        raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "json_model_invalid") from exc


def _parse_yaml_model(payload: bytes, model_type: type[ModelT]) -> ModelT:
    try:
        data = yaml.load(payload.decode("utf-8"), Loader=_UniqueSafeLoader)
        return model_type.model_validate(data)
    except (
        UnicodeError,
        ValueError,
        TypeError,
        ValidationError,
        RecursionError,
        yaml.YAMLError,
    ) as exc:
        raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "yaml_model_invalid") from exc


def _parse_profile(payload: bytes) -> ExecutionProfile:
    try:
        return _parse_json_model(payload, ExecutionProfile)
    except BioPipeError as exc:
        raise BioPipeError(
            ErrorCode.EXECUTION_PROFILE_INVALID,
            "The execution profile is missing, unsafe, or invalid.",
            remediation=["Register a new validated execution profile and retry."],
        ) from exc


def _mapped_input_paths(manifest: DatasetManifest, plan: ExecutionPlan) -> tuple[str, ...]:
    mapped: list[str] = []
    for sample in manifest.samples:
        for lane in sample.lanes:
            mapped.append(_map_path(lane.read1, plan))
            if lane.read2 is not None:
                mapped.append(_map_path(lane.read2, plan))
    if len(mapped) != len(set(mapped)):
        raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "mapped_inputs_not_unique")
    return tuple(sorted(mapped))


def _map_path(value: str, plan: ExecutionPlan) -> str:
    source = PurePosixPath(value)
    candidates: list[tuple[int, str]] = []
    for mapping in plan.path_mapping or []:
        prefix = PurePosixPath(mapping.source_prefix)
        try:
            relative = source.relative_to(prefix)
        except ValueError:
            continue
        candidates.append(
            (len(prefix.parts), str(PurePosixPath(mapping.execution_prefix) / relative))
        )
    if candidates:
        longest = max(length for length, _value in candidates)
        mapped_values = {mapped for length, mapped in candidates if length == longest}
        if len(mapped_values) != 1:
            raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "path_mapping_ambiguous")
        mapped = PurePosixPath(mapped_values.pop())
    elif plan.path_mapping:
        raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "input_mapping_missing")
    else:
        source_root = PurePosixPath(plan.paths.source_root)
        execution_root = PurePosixPath(plan.paths.execution_root)
        if source_root != execution_root:
            raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "input_mapping_missing")
        try:
            mapped = execution_root / source.relative_to(source_root)
        except ValueError as exc:
            raise _gate_error(
                ErrorCode.APPROVAL_ARTIFACT_MISMATCH,
                "input_outside_source_root",
            ) from exc
    try:
        relative = mapped.relative_to(PurePosixPath(plan.paths.execution_root))
    except ValueError as exc:
        raise _gate_error(
            ErrorCode.APPROVAL_ARTIFACT_MISMATCH,
            "mapped_input_outside_root",
        ) from exc
    if relative == PurePosixPath("."):
        raise _gate_error(ErrorCode.APPROVAL_ARTIFACT_MISMATCH, "mapped_input_is_root")
    return str(mapped)


def _below_any(path: str, roots: tuple[str, ...]) -> bool:
    candidate = PurePosixPath(path)
    for root in roots:
        try:
            candidate.relative_to(PurePosixPath(root))
        except ValueError:
            continue
        return True
    return False


def _compatibility_hash(core_hashes: CoreArtifactHashes, bundle_hash: str) -> str:
    payload = {
        "bundle_hash": bundle_hash,
        "execution_profile": core_hashes.execution_profile,
        "project_hash": compute_project_hash(core_hashes),
    }
    return _canonical_hash(payload)


def _authorization_id(
    *,
    project_id: str,
    actor: str,
    approved_at: datetime,
    policy: Mapping[str, Any],
    hashes: AuthorizationArtifactHashes,
    bundle_hash: str,
) -> str:
    digest = _canonical_hash(
        {
            "actor": actor,
            "approved_at": approved_at.astimezone(timezone.utc).isoformat(),  # noqa: UP017
            "artifact_hashes": hashes.model_dump(mode="json"),
            "bundle_hash": bundle_hash,
            "policy": dict(policy),
            "project_id": project_id,
        }
    )
    return f"auth-{digest[:32]}"


def _canonical_hash(payload: Mapping[str, Any]) -> str:
    serialized = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _utc_now(value: datetime | None) -> datetime:
    selected = value or datetime.now(timezone.utc)  # noqa: UP017
    if selected.tzinfo is None or selected.utcoffset() is None:
        raise ValueError("approval gate time must include a timezone")
    return selected.astimezone(timezone.utc)  # noqa: UP017


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _gate_error(code: ErrorCode, reason: str) -> BioPipeError:
    messages = {
        ErrorCode.PREFLIGHT_FAILED: "The remote execution preflight did not pass.",
        ErrorCode.PREFLIGHT_STALE: "The remote execution preflight is stale.",
        ErrorCode.APPROVAL_REQUIRED: "Explicit attributable real-data approval is required.",
        ErrorCode.APPROVAL_ARTIFACT_MISMATCH: (
            "The approval evidence does not match the reviewed execution artifacts."
        ),
        ErrorCode.RESUME_INCOMPATIBLE: "The requested resume is incompatible with the prior run.",
    }
    return BioPipeError(
        code,
        messages[code],
        context={"reason": reason},
        remediation=["Regenerate the affected evidence and repeat the approval workflow."],
    )


__all__ = ["ApprovalGate", "LocalGateEvidence", "assert_resume_compatible"]
