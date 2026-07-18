"""Fail-closed, subprocess-free validation of generated Nextflow projects."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, TypeVar, cast

import yaml
from pydantic import BaseModel, ValidationError

from biopipe.compiler.compiler import NextflowCompiler, _generation_fingerprint
from biopipe.errors import BioPipeError
from biopipe.manifests.integrity import verify_manifest
from biopipe.models import (
    AuditEvent,
    DatasetManifest,
    ExecutionApproval,
    ExecutionPlan,
    PipelinePolicy,
    PipelineSpec,
    PreflightRequirements,
    SoftwareLock,
)
from biopipe.planner import component_ids_for_spec, reconstruct_planned_pipeline
from biopipe.registry import (
    ArtifactType,
    ComponentDefinition,
    ComponentRegistry,
    RegistryValidationError,
    load_default_registry,
)

from .models import FindingCode, FindingSeverity, ValidationFinding, ValidationReport

ModelT = TypeVar("ModelT", bound=BaseModel)

_CORE_ARTIFACTS: Mapping[str, type[BaseModel]] = {
    "dataset.manifest.resolved.json": DatasetManifest,
    "pipeline.spec.yaml": PipelineSpec,
    "execution.plan.yaml": ExecutionPlan,
    "software.lock.yaml": SoftwareLock,
}
_AUDIT_ARTIFACT = "audit/events.jsonl"
_ALLOWED_REPORT_ARTIFACTS = frozenset(
    {
        "reports/test.json",
        "reports/validation.json",
    }
)
_MAX_PROJECT_ENTRIES = 512
_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_MAX_PROJECT_BYTES = 64 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024
_LATEST_TOKEN = re.compile(r"(?i)(?:^|[^A-Za-z0-9_.-])latest(?:$|[^A-Za-z0-9_.-])")
_CONTAINER_ASSIGNMENT = re.compile(
    r"(?m)^\s*container\s*=\s*(['\"])(?P<reference>[^'\"\r\n]+)\1\s*$"
)
_IMMUTABLE_REFERENCE = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+@sha256:[0-9a-f]{64}$"
)

_FINDING_TEXT: Mapping[FindingCode, tuple[str, tuple[str, ...]]] = {
    FindingCode.PROJECT_NOT_FOUND: (
        "The generated project directory does not exist.",
        ("Generate the project into a new directory before validating it.",),
    ),
    FindingCode.PROJECT_NOT_DIRECTORY: (
        "The generated project path is not a safe directory.",
        ("Select the real, non-symlink generated project directory.",),
    ),
    FindingCode.UNSAFE_PROJECT_ENTRY: (
        "The generated project contains a symlink, special file, or unsafe path.",
        ("Remove the unsafe entry and regenerate the project from reviewed artifacts.",),
    ),
    FindingCode.PROJECT_LIMIT_EXCEEDED: (
        "The generated project exceeds the static validation size or entry limit.",
        ("Regenerate the fixed project and remove unrelated files before validation.",),
    ),
    FindingCode.REQUIRED_ARTIFACT_MISSING: (
        "A required generated-project artifact is missing.",
        ("Regenerate the complete project bundle; do not recreate artifacts by hand.",),
    ),
    FindingCode.ARTIFACT_UNREADABLE: (
        "A generated-project artifact could not be read safely.",
        ("Restore normal read permissions or regenerate the project bundle.",),
    ),
    FindingCode.ARTIFACT_MODEL_INVALID: (
        "A generated-project model artifact is invalid or ambiguous.",
        ("Regenerate the artifact from the strict easy-pipe model.",),
    ),
    FindingCode.MANIFEST_INTEGRITY_INVALID: (
        "The embedded manifest digest is missing or does not match its content.",
        ("Recreate the resolved manifest from the original scan artifact.",),
    ),
    FindingCode.MANIFEST_NOT_EXECUTABLE: (
        "The embedded manifest is not a full, resolved, executable dataset manifest.",
        ("Resolve blocking issues and generate from the integrity-verified full manifest.",),
    ),
    FindingCode.CROSS_ARTIFACT_MISMATCH: (
        "The manifest, specification, execution plan, and lock are inconsistent.",
        ("Re-run planning and generation from one reviewed resolved manifest.",),
    ),
    FindingCode.SOFTWARE_LOCK_MISMATCH: (
        "The software lock does not exactly match the reviewed component registry.",
        ("Recreate the lock from the packaged registry; do not edit it manually.",),
    ),
    FindingCode.PATH_OVERLAP: (
        "An execution write path overlaps another write path or an immutable input root.",
        ("Choose separate raw-data, work, output, and container-cache directories.",),
    ),
    FindingCode.OUTPUT_CONFLICT: (
        "The planned target output already exists and overwrite is disabled.",
        ("Choose a new output path or archive the existing output after manual review.",),
    ),
    FindingCode.DEFAULT_DENY_POLICY_INVALID: (
        "The project does not preserve the default-deny execution and approval policy.",
        ("Regenerate the plan with real-data approval denied and all preflight gates enabled.",),
    ),
    FindingCode.GENERATED_FILE_SET_MISMATCH: (
        "The generated project file set differs from the fixed compiler output.",
        ("Regenerate the complete project and keep validation reports only under reports/.",),
    ),
    FindingCode.GENERATED_CONTENT_MISMATCH: (
        "A generated template artifact differs from the reviewed compiler output.",
        ("Discard manual template edits and regenerate the project.",),
    ),
    FindingCode.SAMPLESHEET_MISMATCH: (
        "The runtime samplesheet differs from the manifest and execution path mapping.",
        ("Regenerate the samplesheet from the resolved manifest and execution plan.",),
    ),
    FindingCode.GENERATED_HASH_MISMATCH: (
        "Generated artifact hashes do not match the deterministic project or audit record.",
        ("Regenerate the project and review any post-generation modifications.",),
    ),
    FindingCode.CONTAINER_REFERENCE_INVALID: (
        "A workflow container reference is not the exact digest-only registry reference.",
        ("Regenerate configuration from the reviewed registry and immutable digest lock.",),
    ),
    FindingCode.FLOATING_VERSION: (
        "A generated code or configuration artifact contains a floating latest token.",
        ("Replace floating software selection by regenerating from the reviewed registry.",),
    ),
    FindingCode.AUDIT_RECORD_INVALID: (
        "The generation audit record is missing, malformed, or inconsistent.",
        ("Regenerate the complete project so its audit record is recreated atomically.",),
    ),
    FindingCode.REGISTRY_INVALID: (
        "The packaged default component registry could not be validated.",
        ("Restore the installed easy-pipe package and its reviewed registry resource.",),
    ),
}


class _UniqueSafeLoader(yaml.SafeLoader):
    """YAML loader that rejects duplicate mapping keys."""


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


class _FindingCollector:
    def __init__(self) -> None:
        self.findings: list[ValidationFinding] = []
        self._seen: set[tuple[str, str | None, str]] = set()

    def add(
        self,
        code: FindingCode,
        *,
        artifact: str | None = None,
        context: Mapping[str, str | int | bool | list[str]] | None = None,
    ) -> None:
        normalized_context = dict(context or {})
        key = (
            code.value,
            artifact,
            json.dumps(normalized_context, ensure_ascii=False, sort_keys=True),
        )
        if key in self._seen:
            return
        self._seen.add(key)
        message, remediation = _FINDING_TEXT[code]
        self.findings.append(
            ValidationFinding(
                code=code,
                artifact=artifact,
                message=message,
                remediation=list(remediation),
                context=normalized_context,
            )
        )


class StaticProjectValidator:
    """Validate generated artifacts without executing Nextflow or any subprocess."""

    def __init__(
        self,
        project_directory: str | Path,
        *,
        target_output: str | Path | None = None,
        check_output_conflict: bool = True,
    ) -> None:
        self.project_directory = Path(project_directory).expanduser().absolute()
        self.target_output = None if target_output is None else Path(target_output).expanduser()
        self.check_output_conflict = check_output_conflict
        self._collector = _FindingCollector()

    def validate(self) -> ValidationReport:
        """Run all possible static checks and return a deterministic report."""

        project_state = self._validate_project_root()
        if not project_state:
            return self._report({}, None)

        payloads, discovered_files, discovered_directories = self._collect_project()
        models = self._load_core_models(payloads)
        manifest = cast(DatasetManifest | None, models.get("dataset.manifest.resolved.json"))
        spec = cast(PipelineSpec | None, models.get("pipeline.spec.yaml"))
        execution_plan = cast(ExecutionPlan | None, models.get("execution.plan.yaml"))
        software_lock = cast(SoftwareLock | None, models.get("software.lock.yaml"))

        manifest_usable = self._validate_manifest(manifest)
        self._validate_default_deny(spec, execution_plan)
        self._validate_cross_artifact_consistency(manifest, spec, execution_plan)
        self._validate_path_separation(manifest, spec, execution_plan)
        output_target = self._validate_output_target(spec)

        registry = self._load_registry()
        selected: tuple[ComponentDefinition, ...] | None = None
        expected_lock: SoftwareLock | None = None
        if registry is not None and spec is not None:
            selected, expected_lock = self._registry_selection(registry, spec)
            if (
                expected_lock is not None
                and software_lock is not None
                and software_lock != expected_lock
            ):
                self._collector.add(
                    FindingCode.SOFTWARE_LOCK_MISMATCH,
                    artifact="software.lock.yaml",
                    context={"registry_version": registry.version},
                )

        self._validate_reconstructed_plan(
            manifest,
            spec,
            execution_plan,
            software_lock,
            registry,
            manifest_usable,
        )
        self._validate_floating_versions(payloads)
        if registry is not None and selected is not None:
            self._validate_container_references(payloads, selected)

        expected = self._render_expected_project(
            manifest,
            spec,
            execution_plan,
            expected_lock,
            registry,
            selected,
            manifest_usable,
        )
        self._validate_file_set(
            discovered_files,
            discovered_directories,
            expected,
        )
        self._validate_expected_content(payloads, expected)
        self._validate_audit(payloads, manifest, spec, registry, expected)
        return self._report(payloads, output_target)

    def _validate_project_root(self) -> bool:
        try:
            metadata = self.project_directory.lstat()
        except FileNotFoundError:
            self._collector.add(FindingCode.PROJECT_NOT_FOUND)
            return False
        except (OSError, ValueError):
            self._collector.add(FindingCode.PROJECT_NOT_DIRECTORY)
            return False
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            self._collector.add(FindingCode.PROJECT_NOT_DIRECTORY)
            return False
        return True

    def _collect_project(self) -> tuple[dict[str, bytes], set[str], set[str]]:
        payloads: dict[str, bytes] = {}
        discovered_files: set[str] = set()
        discovered_directories: set[str] = set()
        entry_count = 0
        total_bytes = 0
        limit_reported = False

        for directory, directory_names, file_names in os.walk(
            self.project_directory,
            topdown=True,
            followlinks=False,
        ):
            current = Path(directory)
            safe_directories: list[str] = []
            for name in sorted(directory_names):
                entry_count += 1
                candidate = current / name
                relative = self._display_relative(candidate)
                if entry_count > _MAX_PROJECT_ENTRIES:
                    if not limit_reported:
                        self._collector.add(FindingCode.PROJECT_LIMIT_EXCEEDED)
                        limit_reported = True
                    continue
                try:
                    metadata = candidate.lstat()
                except OSError:
                    self._collector.add(
                        FindingCode.ARTIFACT_UNREADABLE,
                        artifact=relative,
                    )
                    continue
                if relative == "<unsafe-entry>" or not stat.S_ISDIR(metadata.st_mode):
                    self._collector.add(
                        FindingCode.UNSAFE_PROJECT_ENTRY,
                        artifact=relative,
                    )
                    continue
                discovered_directories.add(relative)
                safe_directories.append(name)
            directory_names[:] = safe_directories

            for name in sorted(file_names):
                entry_count += 1
                candidate = current / name
                relative = self._display_relative(candidate)
                if entry_count > _MAX_PROJECT_ENTRIES:
                    if not limit_reported:
                        self._collector.add(FindingCode.PROJECT_LIMIT_EXCEEDED)
                        limit_reported = True
                    continue
                try:
                    metadata = candidate.lstat()
                except OSError:
                    self._collector.add(
                        FindingCode.ARTIFACT_UNREADABLE,
                        artifact=relative,
                    )
                    continue
                if relative == "<unsafe-entry>" or not stat.S_ISREG(metadata.st_mode):
                    self._collector.add(
                        FindingCode.UNSAFE_PROJECT_ENTRY,
                        artifact=relative,
                    )
                    continue
                discovered_files.add(relative)
                if metadata.st_size > _MAX_ARTIFACT_BYTES:
                    self._collector.add(
                        FindingCode.PROJECT_LIMIT_EXCEEDED,
                        artifact=relative,
                        context={"limit_bytes": _MAX_ARTIFACT_BYTES},
                    )
                    continue
                if total_bytes + metadata.st_size > _MAX_PROJECT_BYTES:
                    self._collector.add(
                        FindingCode.PROJECT_LIMIT_EXCEEDED,
                        context={"limit_bytes": _MAX_PROJECT_BYTES},
                    )
                    limit_reported = True
                    continue
                payload = self._read_regular_file(candidate, metadata, relative)
                if payload is None:
                    continue
                total_bytes += len(payload)
                payloads[relative] = payload

        return payloads, discovered_files, discovered_directories

    def _read_regular_file(
        self,
        path: Path,
        expected_metadata: os.stat_result,
        relative: str,
    ) -> bytes | None:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            actual_metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(actual_metadata.st_mode)
                or actual_metadata.st_dev != expected_metadata.st_dev
                or actual_metadata.st_ino != expected_metadata.st_ino
                or actual_metadata.st_size > _MAX_ARTIFACT_BYTES
            ):
                self._collector.add(
                    FindingCode.UNSAFE_PROJECT_ENTRY,
                    artifact=relative,
                )
                return None
            chunks: list[bytes] = []
            remaining = actual_metadata.st_size
            while remaining:
                chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, remaining))
                if not chunk:
                    raise OSError("artifact changed while being read")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise OSError("artifact grew while being read")
            return b"".join(chunks)
        except OSError:
            self._collector.add(
                FindingCode.ARTIFACT_UNREADABLE,
                artifact=relative,
            )
            return None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _load_core_models(self, payloads: Mapping[str, bytes]) -> dict[str, BaseModel]:
        loaded: dict[str, BaseModel] = {}
        for artifact, model_type in _CORE_ARTIFACTS.items():
            payload = payloads.get(artifact)
            if payload is None:
                self._collector.add(
                    FindingCode.REQUIRED_ARTIFACT_MISSING,
                    artifact=artifact,
                )
                continue
            model = self._parse_model(payload, artifact, model_type)
            if model is not None:
                loaded[artifact] = model
        if _AUDIT_ARTIFACT not in payloads:
            self._collector.add(
                FindingCode.REQUIRED_ARTIFACT_MISSING,
                artifact=_AUDIT_ARTIFACT,
            )
        return loaded

    def _parse_model(
        self,
        payload: bytes,
        artifact: str,
        model_type: type[ModelT],
    ) -> ModelT | None:
        try:
            text = payload.decode("utf-8")
            if artifact.endswith(".json"):
                data = json.loads(text, object_pairs_hook=_unique_json_object)
            else:
                data = yaml.load(text, Loader=_UniqueSafeLoader)
            return model_type.model_validate(data)
        except (
            UnicodeError,
            json.JSONDecodeError,
            yaml.YAMLError,
            ValidationError,
            ValueError,
            TypeError,
            RecursionError,
        ):
            self._collector.add(
                FindingCode.ARTIFACT_MODEL_INVALID,
                artifact=artifact,
                context={"model": model_type.__name__},
            )
            return None

    def _validate_manifest(self, manifest: DatasetManifest | None) -> bool:
        if manifest is None:
            return False
        digest_valid = verify_manifest(manifest)
        if not digest_valid:
            self._collector.add(
                FindingCode.MANIFEST_INTEGRITY_INVALID,
                artifact="dataset.manifest.resolved.json",
            )
        executable = (
            manifest.privacy.artifact_scope == "full"
            and not manifest.errors
            and bool(manifest.samples)
            and manifest.classification.layout in {"single_end", "paired_end"}
            and manifest.classification.dataset_type != "unknown"
        )
        if not executable:
            issue_codes = sorted({issue.code for issue in manifest.errors})
            context: dict[str, str | int | bool | list[str]] = {
                "artifact_scope": manifest.privacy.artifact_scope,
                "layout": manifest.classification.layout,
            }
            if issue_codes:
                context["issue_codes"] = issue_codes
            self._collector.add(
                FindingCode.MANIFEST_NOT_EXECUTABLE,
                artifact="dataset.manifest.resolved.json",
                context=context,
            )
        return digest_valid and executable

    def _validate_default_deny(
        self,
        spec: PipelineSpec | None,
        execution_plan: ExecutionPlan | None,
    ) -> None:
        invalid_parts: list[str] = []
        if spec is not None and spec.policy != PipelinePolicy():
            invalid_parts.append("pipeline_policy")
        if execution_plan is not None:
            if execution_plan.approval != ExecutionApproval():
                invalid_parts.append("execution_approval")
            if execution_plan.preflight != PreflightRequirements():
                invalid_parts.append("preflight_requirements")
        if invalid_parts:
            self._collector.add(
                FindingCode.DEFAULT_DENY_POLICY_INVALID,
                context={"invalid_contracts": invalid_parts},
            )

    def _validate_cross_artifact_consistency(
        self,
        manifest: DatasetManifest | None,
        spec: PipelineSpec | None,
        execution_plan: ExecutionPlan | None,
    ) -> None:
        if manifest is None or spec is None or execution_plan is None:
            return
        mismatches: list[str] = []
        if spec.input.manifest != "dataset.manifest.resolved.json":
            mismatches.append("spec.input.manifest")
        if manifest.classification.layout != spec.input.layout:
            mismatches.append("manifest.layout")
        if execution_plan.executor != spec.execution.executor:
            mismatches.append("executor")
        if execution_plan.paths.source_root != manifest.source.root:
            mismatches.append("source_root")
        if execution_plan.paths.work_dir != spec.paths.work_dir:
            mismatches.append("work_dir")
        if execution_plan.paths.output_dir != spec.paths.output_dir:
            mismatches.append("output_dir")
        if execution_plan.paths.container_cache != spec.paths.container_cache:
            mismatches.append("container_cache")
        if mismatches:
            self._collector.add(
                FindingCode.CROSS_ARTIFACT_MISMATCH,
                context={"fields": mismatches},
            )

    def _validate_path_separation(
        self,
        manifest: DatasetManifest | None,
        spec: PipelineSpec | None,
        execution_plan: ExecutionPlan | None,
    ) -> None:
        if spec is None or execution_plan is None:
            return
        writable_paths = (
            spec.paths.work_dir,
            spec.paths.output_dir,
            spec.paths.container_cache,
        )
        raw_roots = {execution_plan.paths.source_root, execution_plan.paths.execution_root}
        if manifest is not None:
            raw_roots.add(manifest.source.root)
        overlaps: list[str] = []
        for index, first in enumerate(writable_paths):
            for second in writable_paths[index + 1 :]:
                if _paths_overlap(first, second):
                    overlaps.append(f"{first} <-> {second}")
        for writable in writable_paths:
            for raw_root in sorted(raw_roots):
                if _paths_overlap(writable, raw_root):
                    overlaps.append(f"{writable} <-> {raw_root}")
        if overlaps:
            self._collector.add(
                FindingCode.PATH_OVERLAP,
                context={"overlaps": sorted(set(overlaps))},
            )

    def _validate_output_target(self, spec: PipelineSpec | None) -> str | None:
        if not self.check_output_conflict:
            return None
        selected = self.target_output
        if selected is None and spec is not None:
            selected = Path(spec.paths.output_dir)
        if selected is None:
            return None
        display = os.fspath(selected)
        try:
            conflicts = os.path.lexists(selected)
        except (OSError, ValueError):
            conflicts = True
            display = "<invalid-output-target>"
        if conflicts:
            self._collector.add(
                FindingCode.OUTPUT_CONFLICT,
                context={"target": display},
            )
        return display

    def _load_registry(self) -> ComponentRegistry | None:
        try:
            return load_default_registry()
        except (RegistryValidationError, BioPipeError, OSError, ValueError):
            self._collector.add(FindingCode.REGISTRY_INVALID)
            return None

    def _registry_selection(
        self,
        registry: ComponentRegistry,
        spec: PipelineSpec,
    ) -> tuple[tuple[ComponentDefinition, ...] | None, SoftwareLock | None]:
        try:
            component_ids = component_ids_for_spec(spec)
            input_type: ArtifactType = (
                "paired_fastq" if spec.input.layout == "paired_end" else "single_fastq"
            )
            return (
                registry.validate_graph(component_ids, input_type),
                registry.software_lock(component_ids),
            )
        except (RegistryValidationError, BioPipeError, ValueError):
            self._collector.add(FindingCode.REGISTRY_INVALID)
            return None, None

    def _validate_reconstructed_plan(
        self,
        manifest: DatasetManifest | None,
        spec: PipelineSpec | None,
        execution_plan: ExecutionPlan | None,
        software_lock: SoftwareLock | None,
        registry: ComponentRegistry | None,
        manifest_usable: bool,
    ) -> None:
        if (
            manifest is None
            or spec is None
            or execution_plan is None
            or software_lock is None
            or registry is None
            or not manifest_usable
        ):
            return
        try:
            planned = reconstruct_planned_pipeline(
                spec,
                execution_plan,
                software_lock,
                registry=registry,
            )
            NextflowCompiler()._validate_inputs(
                manifest,
                spec,
                execution_plan,
                software_lock,
                registry,
                planned.component_ids,
            )
        except (BioPipeError, RegistryValidationError, ValidationError, ValueError):
            self._collector.add(FindingCode.CROSS_ARTIFACT_MISMATCH)

    def _validate_floating_versions(self, payloads: Mapping[str, bytes]) -> None:
        relevant_suffixes = (".nf", ".config", ".yaml", ".yml")
        for artifact, payload in sorted(payloads.items()):
            if artifact in _ALLOWED_REPORT_ARTIFACTS or not artifact.endswith(relevant_suffixes):
                continue
            try:
                text = payload.decode("utf-8")
            except UnicodeError:
                continue
            if _LATEST_TOKEN.search(text):
                self._collector.add(
                    FindingCode.FLOATING_VERSION,
                    artifact=artifact,
                )

    def _validate_container_references(
        self,
        payloads: Mapping[str, bytes],
        selected: Sequence[ComponentDefinition],
    ) -> None:
        artifact = "conf/base.config"
        payload = payloads.get(artifact)
        if payload is None:
            return
        try:
            text = payload.decode("utf-8")
        except UnicodeError:
            self._collector.add(FindingCode.CONTAINER_REFERENCE_INVALID, artifact=artifact)
            return
        actual = [match.group("reference") for match in _CONTAINER_ASSIGNMENT.finditer(text)]
        expected = [component.container.immutable_reference for component in selected]
        valid_shape = all(
            _IMMUTABLE_REFERENCE.fullmatch(reference)
            and ":" not in reference.split("@", maxsplit=1)[0].rsplit("/", maxsplit=1)[-1]
            for reference in actual
        )
        if not valid_shape or Counter(actual) != Counter(expected):
            self._collector.add(
                FindingCode.CONTAINER_REFERENCE_INVALID,
                artifact=artifact,
                context={"expected_count": len(expected), "actual_count": len(actual)},
            )

    def _render_expected_project(
        self,
        manifest: DatasetManifest | None,
        spec: PipelineSpec | None,
        execution_plan: ExecutionPlan | None,
        expected_lock: SoftwareLock | None,
        registry: ComponentRegistry | None,
        selected: tuple[ComponentDefinition, ...] | None,
        manifest_usable: bool,
    ) -> dict[str, bytes] | None:
        if (
            manifest is None
            or spec is None
            or execution_plan is None
            or expected_lock is None
            or registry is None
            or selected is None
            or not manifest_usable
        ):
            return None
        try:
            compiler = NextflowCompiler()
            expected = compiler._render_artifacts(
                manifest,
                spec,
                execution_plan,
                expected_lock,
                registry,
                selected,
            )
            fingerprint = _generation_fingerprint(expected, registry)
            expected[_AUDIT_ARTIFACT] = compiler._audit_event(
                manifest,
                spec,
                expected,
                registry,
                fingerprint,
            )
            return expected
        except (BioPipeError, RegistryValidationError, ValidationError, ValueError):
            self._collector.add(FindingCode.CROSS_ARTIFACT_MISMATCH)
            return None

    def _validate_file_set(
        self,
        discovered_files: set[str],
        discovered_directories: set[str],
        expected: Mapping[str, bytes] | None,
    ) -> None:
        if expected is None:
            return
        expected_files = set(expected)
        material_files = discovered_files - _ALLOWED_REPORT_ARTIFACTS
        missing = sorted(expected_files - material_files)
        unexpected = sorted(material_files - expected_files)
        expected_directories = _parent_directories(expected_files)
        allowed_directories = set(expected_directories)
        if discovered_files.intersection(_ALLOWED_REPORT_ARTIFACTS):
            allowed_directories.add("reports")
        unexpected_directories = sorted(discovered_directories - allowed_directories)
        if missing or unexpected or unexpected_directories:
            context: dict[str, str | int | bool | list[str]] = {}
            if missing:
                context["missing"] = missing
            if unexpected:
                context["unexpected"] = unexpected
            if unexpected_directories:
                context["unexpected_directories"] = unexpected_directories
            self._collector.add(
                FindingCode.GENERATED_FILE_SET_MISMATCH,
                context=context,
            )

    def _validate_expected_content(
        self,
        payloads: Mapping[str, bytes],
        expected: Mapping[str, bytes] | None,
    ) -> None:
        if expected is None:
            return
        for artifact, expected_payload in sorted(expected.items()):
            actual = payloads.get(artifact)
            if actual is None or actual == expected_payload:
                continue
            if artifact == "assets/samplesheet.csv":
                code = FindingCode.SAMPLESHEET_MISMATCH
            elif artifact == _AUDIT_ARTIFACT:
                code = FindingCode.AUDIT_RECORD_INVALID
            elif artifact.endswith((".nf", ".config")) or artifact == "README.md":
                code = FindingCode.GENERATED_CONTENT_MISMATCH
            else:
                code = FindingCode.GENERATED_HASH_MISMATCH
            self._collector.add(code, artifact=artifact)

    def _validate_audit(
        self,
        payloads: Mapping[str, bytes],
        manifest: DatasetManifest | None,
        spec: PipelineSpec | None,
        registry: ComponentRegistry | None,
        expected: Mapping[str, bytes] | None,
    ) -> None:
        payload = payloads.get(_AUDIT_ARTIFACT)
        if payload is None:
            return
        try:
            text = payload.decode("utf-8")
            lines = text.splitlines()
            if len(lines) != 1 or not lines[0]:
                raise ValueError("generation audit must contain exactly one event")
            data = json.loads(lines[0], object_pairs_hook=_unique_json_object)
            event = AuditEvent.model_validate(data)
        except (
            UnicodeError,
            json.JSONDecodeError,
            ValidationError,
            ValueError,
            TypeError,
            RecursionError,
        ):
            self._collector.add(FindingCode.AUDIT_RECORD_INVALID, artifact=_AUDIT_ARTIFACT)
            return

        metadata_invalid = (
            event.event_type != "PIPELINE_GENERATED"
            or event.actor != "biopipe_compiler"
            or event.status != "success"
            or (spec is not None and event.project_id != spec.project.name)
            or (manifest is not None and event.timestamp != manifest.source.scanned_at)
        )
        if metadata_invalid:
            self._collector.add(FindingCode.AUDIT_RECORD_INVALID, artifact=_AUDIT_ARTIFACT)

        if expected is not None:
            core = set(_CORE_ARTIFACTS)
            expected_inputs = {
                name: _sha256(payloads[name]) for name in sorted(core) if name in payloads
            }
            if registry is not None:
                expected_inputs["component.registry.json"] = _sha256(
                    _json_model_bytes(registry.document)
                )
            expected_outputs = {
                name: _sha256(payloads[name])
                for name in sorted(set(expected) - core - {_AUDIT_ARTIFACT})
                if name in payloads
            }
            if event.input_hashes != expected_inputs or event.output_hashes != expected_outputs:
                self._collector.add(
                    FindingCode.GENERATED_HASH_MISMATCH,
                    artifact=_AUDIT_ARTIFACT,
                )

    def _report(
        self,
        payloads: Mapping[str, bytes],
        output_target: str | None,
    ) -> ValidationReport:
        material_payloads = {
            name: payload
            for name, payload in payloads.items()
            if name not in _ALLOWED_REPORT_ARTIFACTS
        }
        hashes = {name: _sha256(payload) for name, payload in sorted(material_payloads.items())}
        findings = sorted(
            self._collector.findings,
            key=lambda finding: (
                finding.code.value,
                finding.artifact or "",
                json.dumps(finding.context, ensure_ascii=False, sort_keys=True),
            ),
        )
        has_blocking = any(finding.severity == FindingSeverity.BLOCKING for finding in findings)
        return ValidationReport(
            project_directory=os.fspath(self.project_directory),
            status="invalid" if has_blocking else "valid",
            checked_artifacts=sorted(material_payloads),
            artifact_hashes=hashes,
            output_target_checked=output_target,
            findings=findings,
        )

    def _display_relative(self, path: Path) -> str:
        try:
            relative = path.relative_to(self.project_directory).as_posix()
        except ValueError:
            return "<unsafe-entry>"
        if not relative or any(
            ord(character) < 32 or ord(character) == 127 for character in relative
        ):
            return "<unsafe-entry>"
        return relative


def validate_generated_project(
    project_directory: str | Path,
    *,
    target_output: str | Path | None = None,
    check_output_conflict: bool = True,
) -> ValidationReport:
    """Validate one generated project without running external commands."""

    return StaticProjectValidator(
        project_directory,
        target_output=target_output,
        check_output_conflict=check_output_conflict,
    ).validate()


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _paths_overlap(first: str, second: str) -> bool:
    first_path = PurePosixPath(first)
    second_path = PurePosixPath(second)
    return (
        first_path == second_path
        or first_path in second_path.parents
        or second_path in first_path.parents
    )


def _parent_directories(files: set[str]) -> set[str]:
    directories: set[str] = set()
    for artifact in files:
        parent = PurePosixPath(artifact).parent
        while parent != PurePosixPath("."):
            directories.add(parent.as_posix())
            parent = parent.parent
    return directories


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_model_bytes(model: BaseModel) -> bytes:
    data: Any = model.model_dump(mode="json", exclude_none=False)
    return (
        json.dumps(
            data,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


__all__ = ["StaticProjectValidator", "validate_generated_project"]
