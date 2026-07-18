"""Strict, versioned domain contracts for the controller and probe protocol."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Version1 = Literal["1.0"]
Layout = Literal["single_end", "paired_end", "unknown"]
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_PINNED_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_TAGGED_IMAGE_PATTERN = re.compile(
    r"^[a-z0-9.-]+(?::[0-9]+)?(?:/[a-z0-9._-]+)+:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
)


class StrictModel(BaseModel):
    """Base contract that rejects unknown fields and validates mutation."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
    )


def _safe_identifier(value: str, field_name: str) -> str:
    if not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(
            f"{field_name} must start with an alphanumeric character and contain only "
            "letters, numbers, dot, underscore, or hyphen"
        )
    return value


def _safe_text(value: str, field_name: str) -> str:
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field_name} must not contain control characters")
    return value


def _absolute_posix_path(value: str, field_name: str) -> str:
    _safe_text(value, field_name)
    if len(value.encode("utf-8")) > 4096:
        raise ValueError(f"{field_name} exceeds the supported path length")
    path = PurePosixPath(value)
    if not path.is_absolute():
        raise ValueError(f"{field_name} must be an absolute POSIX path")
    if ".." in path.parts:
        raise ValueError(f"{field_name} must not contain parent traversal")
    return str(path)


class ProbeConfiguration(StrictModel):
    """Bounded, fail-closed defaults for the fixed Remote Probe."""

    remote_path: str = "~/.local/bin/bioprobe.pyz"
    max_runtime_seconds: int = Field(default=300, ge=1, le=3600)
    max_depth: int = Field(default=6, ge=0, le=64)
    max_entries: int = Field(default=100_000, ge=1, le=10_000_000)
    max_request_bytes: int = Field(default=1024 * 1024, ge=1024, le=16 * 1024 * 1024)
    max_paths: int = Field(default=10_000, ge=1, le=100_000)
    max_response_bytes: int = Field(default=10 * 1024 * 1024, ge=1024, le=100 * 1024 * 1024)
    stderr_limit_bytes: int = Field(default=4096, ge=256, le=1024 * 1024)
    follow_symlinks: bool = False

    @field_validator("remote_path")
    @classmethod
    def validate_remote_path(cls, value: str) -> str:
        _safe_text(value, "remote_path")
        if not (value.startswith("/") or value.startswith("~/")):
            raise ValueError("remote_path must be absolute or start with ~/")
        if ".." in PurePosixPath(value.removeprefix("~")).parts:
            raise ValueError("remote_path must not contain parent traversal")
        if re.search(r"[^A-Za-z0-9_./~-]", value):
            raise ValueError("remote_path contains unsupported characters")
        return value


class SourcePrivacy(StrictModel):
    """Privacy defaults for source metadata."""

    filenames_sensitive: bool = True
    allow_external_llm: bool = False


class SourceProfile(StrictModel):
    """A reference to existing SSH configuration; it never stores credentials."""

    schema_version: Version1 = "1.0"
    source_id: str
    ssh_alias: str
    username: str | None = None
    port: int | None = Field(default=None, ge=1, le=65_535)
    allowed_roots: list[str] = Field(min_length=1, max_length=1024)
    probe: ProbeConfiguration = Field(default_factory=ProbeConfiguration)
    privacy: SourcePrivacy = Field(default_factory=SourcePrivacy)

    @field_validator("source_id")
    @classmethod
    def validate_source_id(cls, value: str) -> str:
        return _safe_identifier(value, "source_id")

    @field_validator("ssh_alias")
    @classmethod
    def validate_ssh_alias(cls, value: str) -> str:
        _safe_text(value, "ssh_alias")
        if value.startswith("-") or any(character.isspace() for character in value):
            raise ValueError("ssh_alias must be one safe subprocess argument")
        return value

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str | None) -> str | None:
        if value is not None:
            _safe_text(value, "username")
            if value.startswith("-") or any(character.isspace() for character in value):
                raise ValueError("username must be one safe value")
        return value

    @field_validator("allowed_roots")
    @classmethod
    def validate_allowed_roots(cls, values: list[str]) -> list[str]:
        normalized = [_absolute_posix_path(value, "allowed_roots") for value in values]
        if len(set(normalized)) != len(normalized):
            raise ValueError("allowed_roots must not contain duplicates")
        return normalized


InspectionLevel = Literal["metadata_only", "format_summary", "integrity_check"]
ProbeOperation = Literal[
    "health",
    "list_tree",
    "stat_files",
    "detect_formats",
    "summarize_fastq",
    "parse_samplesheet",
    "parse_runinfo",
    "validate_pairs",
    "check_runtime",
    "check_paths",
    "scan_dataset",
]


class ProbePolicy(StrictModel):
    """Read and return budgets for a probe request."""

    inspection_level: InspectionLevel = "format_summary"
    max_depth: int = Field(default=6, ge=0, le=64)
    max_entries: int = Field(default=100_000, ge=1, le=10_000_000)
    max_runtime_seconds: int = Field(default=300, ge=1, le=3600)
    follow_symlinks: bool = False
    sample_fastq_records: int = Field(default=1_000, ge=0, le=100_000)
    return_sequences: bool = False
    return_qualities: bool = False
    return_read_names: bool = False

    @model_validator(mode="after")
    def forbid_raw_content_export(self) -> ProbePolicy:
        if self.return_sequences or self.return_qualities or self.return_read_names:
            raise ValueError("the MVP protocol forbids exporting raw FASTQ content")
        return self


class ProbeRequest(StrictModel):
    """A request for one allowlisted probe operation."""

    protocol_version: Version1 = "1.0"
    request_id: str
    operation: ProbeOperation
    root: str | None = None
    paths: list[str] = Field(default_factory=list, max_length=100_000)
    policy: ProbePolicy = Field(default_factory=ProbePolicy)

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        return _safe_identifier(value, "request_id")

    @field_validator("root")
    @classmethod
    def validate_root(cls, value: str | None) -> str | None:
        return None if value is None else _absolute_posix_path(value, "root")

    @field_validator("paths")
    @classmethod
    def validate_paths(cls, values: list[str]) -> list[str]:
        normalized = [_absolute_posix_path(value, "paths") for value in values]
        if len(set(normalized)) != len(normalized):
            raise ValueError("paths must not contain duplicates")
        return normalized

    @model_validator(mode="after")
    def require_root_for_path_operations(self) -> ProbeRequest:
        operations_without_root = {"health", "check_runtime"}
        if self.operation == "stat_files" and not self.paths:
            raise ValueError("operation 'stat_files' requires at least one path")
        if self.operation in {"detect_formats", "summarize_fastq"}:
            if not self.paths:
                raise ValueError(f"operation {self.operation!r} requires at least one path")
            if self.policy.inspection_level != "format_summary":
                raise ValueError(
                    f"operation {self.operation!r} requires inspection_level 'format_summary'"
                )
        if self.operation == "summarize_fastq" and self.policy.sample_fastq_records < 1:
            raise ValueError("operation 'summarize_fastq' requires sample_fastq_records >= 1")
        if self.operation not in operations_without_root | {"stat_files"} and self.root is None:
            raise ValueError(f"operation {self.operation!r} requires root")
        return self


class ProbeError(StrictModel):
    """A stable probe-side failure without raw data or exception details."""

    code: str
    message: str
    context: dict[str, Any] = Field(default_factory=dict)
    remediation: list[str] = Field(default_factory=list)

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: str) -> str:
        return _safe_identifier(value, "code")


class ProbeResponse(StrictModel):
    """Response envelope for the JSONL probe protocol."""

    protocol_version: Version1 = "1.0"
    request_id: str
    success: bool
    return_code: int = Field(ge=0, le=255)
    result: dict[str, Any] | None = None
    error: ProbeError | None = None

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        return _safe_identifier(value, "request_id")

    @model_validator(mode="after")
    def validate_envelope(self) -> ProbeResponse:
        if self.success:
            if self.return_code != 0 or self.error is not None:
                raise ValueError("successful responses require return_code 0 and no error")
        elif self.return_code == 0 or self.error is None:
            raise ValueError("failed responses require a nonzero return_code and an error")
        self._reject_sensitive_result(self.result)
        return self

    @staticmethod
    def _reject_sensitive_result(value: Any) -> None:
        sensitive_keys = {
            "password",
            "private_key",
            "quality",
            "quality_string",
            "read_name",
            "sequence",
            "token",
        }
        if isinstance(value, dict):
            for key, nested in value.items():
                if str(key).lower() in sensitive_keys:
                    raise ValueError("probe result contains a forbidden sensitive field")
                ProbeResponse._reject_sensitive_result(nested)
        elif isinstance(value, list):
            for nested in value:
                ProbeResponse._reject_sensitive_result(nested)


class ManifestSource(StrictModel):
    """Provenance of a dataset scan."""

    source_id: str
    root: str
    scanned_at: datetime
    scan_policy: InspectionLevel = "format_summary"

    @field_validator("source_id")
    @classmethod
    def validate_source_id(cls, value: str) -> str:
        return _safe_identifier(value, "source_id")

    @field_validator("root")
    @classmethod
    def validate_root(cls, value: str) -> str:
        return _absolute_posix_path(value, "root")

    @field_validator("scanned_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("scanned_at must include a timezone")
        return value


class DatasetClassification(StrictModel):
    """Detector conclusion with an explainable confidence score."""

    dataset_type: Literal["generic_fastq", "illumina_fastq", "unknown"]
    layout: Layout
    confidence: float = Field(ge=0.0, le=1.0)


class LaneFiles(StrictModel):
    """One lane/chunk of a logical sample."""

    lane: str = "unlaned"
    chunk: str | None = None
    read1: str
    read2: str | None = None

    @field_validator("lane")
    @classmethod
    def validate_lane(cls, value: str) -> str:
        return _safe_identifier(value, "lane")

    @field_validator("chunk")
    @classmethod
    def validate_chunk(cls, value: str | None) -> str | None:
        return None if value is None else _safe_identifier(value, "chunk")

    @field_validator("read1", "read2")
    @classmethod
    def validate_read_path(cls, value: str | None) -> str | None:
        return None if value is None else _absolute_posix_path(value, "read path")


class DatasetSample(StrictModel):
    """A sample with one or more independently retained lanes."""

    sample_id: str
    original_sample_name: str | None = None
    lanes: list[LaneFiles] = Field(min_length=1)

    @field_validator("sample_id")
    @classmethod
    def validate_sample_id(cls, value: str) -> str:
        return _safe_identifier(value, "sample_id")

    @field_validator("original_sample_name")
    @classmethod
    def validate_original_name(cls, value: str | None) -> str | None:
        return None if value is None else _safe_text(value, "original_sample_name")


class ReadLengthSummary(StrictModel):
    """Aggregate read lengths; it never contains sequence content."""

    minimum: int = Field(ge=0)
    median: float = Field(ge=0)
    maximum: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_order(self) -> ReadLengthSummary:
        if not self.minimum <= self.median <= self.maximum:
            raise ValueError("read length summary must be ordered minimum <= median <= maximum")
        return self


class DatasetObservations(StrictModel):
    """Low-risk aggregate observations from bounded remote inspection."""

    compression: Literal["gzip", "none", "mixed", "unknown"] = "unknown"
    read_length: ReadLengthSummary | None = None
    likely_quality_encoding: Literal["phred33", "phred64", "unknown"] = "unknown"
    header_family: str = "unknown"


class DetectionEvidence(StrictModel):
    """One explainable detector rule contribution."""

    rule: str
    score: float = Field(ge=0.0, le=1.0)
    detail: str | None = None

    @field_validator("rule")
    @classmethod
    def validate_rule(cls, value: str) -> str:
        return _safe_identifier(value, "rule")


class ManifestIssue(StrictModel):
    """A stable actionable warning or blocking manifest error."""

    code: str
    severity: Literal["warning", "blocking"]
    message: str
    context: dict[str, Any] = Field(default_factory=dict)
    remediation: list[str] = Field(default_factory=list)

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: str) -> str:
        return _safe_identifier(value, "manifest issue code")


class ManifestPrivacy(StrictModel):
    """Privacy claims attached to the scan artifact."""

    artifact_scope: Literal["full", "sanitized"] = "full"
    filenames_may_contain_identifiers: bool = True
    raw_content_exported: bool = False

    @field_validator("raw_content_exported")
    @classmethod
    def reject_raw_export(cls, value: bool) -> bool:
        if value:
            raise ValueError("raw_content_exported must remain false")
        return value

    @model_validator(mode="after")
    def validate_scope(self) -> ManifestPrivacy:
        if self.artifact_scope == "sanitized" and self.filenames_may_contain_identifiers:
            raise ValueError(
                "sanitized manifests must set filenames_may_contain_identifiers to false"
            )
        return self


class ManifestIntegrity(StrictModel):
    """Digest of a canonical manifest representation when finalized."""

    manifest_sha256: str | None = None

    @field_validator("manifest_sha256")
    @classmethod
    def validate_digest(cls, value: str | None) -> str | None:
        if value is not None and not _SHA256_PATTERN.fullmatch(value):
            raise ValueError("manifest_sha256 must be 64 lowercase hexadecimal characters")
        return value


class DatasetManifest(StrictModel):
    """Full or sanitized dataset structure derived from immutable scan facts."""

    manifest_version: Version1 = "1.0"
    source: ManifestSource
    classification: DatasetClassification
    samples: list[DatasetSample] = Field(default_factory=list)
    observations: DatasetObservations = Field(default_factory=DatasetObservations)
    evidence: list[DetectionEvidence] = Field(default_factory=list)
    warnings: list[ManifestIssue] = Field(default_factory=list)
    errors: list[ManifestIssue] = Field(default_factory=list)
    privacy: ManifestPrivacy = Field(default_factory=ManifestPrivacy)
    integrity: ManifestIntegrity = Field(default_factory=ManifestIntegrity)

    @model_validator(mode="after")
    def validate_layout(self) -> DatasetManifest:
        lanes = [lane for sample in self.samples for lane in sample.lanes]
        if not lanes and self.classification.layout != "unknown":
            raise ValueError("manifests without lanes require layout unknown")
        if self.classification.layout == "unknown" and not self.errors:
            raise ValueError("unknown-layout manifests require a blocking error")
        sample_ids = [sample.sample_id for sample in self.samples]
        if len(sample_ids) != len(set(sample_ids)):
            raise ValueError("manifest sample_id values must be unique")
        root = PurePosixPath(self.source.root)
        assigned_paths: set[str] = set()
        for sample in self.samples:
            slots = [(lane.lane, lane.chunk) for lane in sample.lanes]
            if len(slots) != len(set(slots)):
                raise ValueError("manifest lane/chunk slots must be unique within a sample")
            for lane in sample.lanes:
                for value in (lane.read1, lane.read2):
                    if value is None:
                        continue
                    try:
                        relative = PurePosixPath(value).relative_to(root)
                    except ValueError as exc:
                        raise ValueError("manifest read paths must stay below source.root") from exc
                    if relative == PurePosixPath("."):
                        raise ValueError("manifest read paths must stay below source.root")
                    if value in assigned_paths:
                        raise ValueError("manifest read paths must be assigned exactly once")
                    assigned_paths.add(value)
        if self.classification.layout == "paired_end" and any(lane.read2 is None for lane in lanes):
            raise ValueError("paired_end manifests require read2 for every lane")
        if self.classification.layout == "single_end" and any(
            lane.read2 is not None for lane in lanes
        ):
            raise ValueError("single_end manifests must not include read2")
        if any(issue.severity != "warning" for issue in self.warnings):
            raise ValueError("warnings may contain only warning-severity issues")
        if any(issue.severity != "blocking" for issue in self.errors):
            raise ValueError("errors may contain only blocking-severity issues")
        return self


class ManualPair(StrictModel):
    """An explicit, attributable pairing correction."""

    sample_id: str
    lane: str = "unlaned"
    read1: str
    read2: str | None = None

    @field_validator("sample_id", "lane")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return _safe_identifier(value, "manual pair identifier")

    @field_validator("read1", "read2")
    @classmethod
    def validate_paths(cls, value: str | None) -> str | None:
        return None if value is None else _absolute_posix_path(value, "manual pair path")


class ManifestOverrides(StrictModel):
    """User-reviewed changes kept separately from immutable scan facts."""

    override_version: Version1 = "1.0"
    rename_samples: dict[str, str] = Field(default_factory=dict)
    exclude_files: list[str] = Field(default_factory=list)
    manual_pairs: list[ManualPair] = Field(default_factory=list)
    reason: str
    approved_by: str

    @field_validator("exclude_files")
    @classmethod
    def validate_excluded_files(cls, values: list[str]) -> list[str]:
        return [_absolute_posix_path(value, "exclude_files") for value in values]

    @field_validator("reason", "approved_by")
    @classmethod
    def validate_attribution(cls, value: str) -> str:
        return _safe_text(value, "override attribution")


class PipelineProject(StrictModel):
    """Human-readable project identity."""

    name: str

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _safe_identifier(value, "project.name")


class PipelineInput(StrictModel):
    """Manifest input selected for planning."""

    manifest: str
    dataset_type: Literal["fastq"] = "fastq"
    layout: Literal["single_end", "paired_end"]

    @field_validator("manifest")
    @classmethod
    def validate_manifest(cls, value: str) -> str:
        return _safe_text(value, "input.manifest")


PipelineStage = Literal["raw_fastqc", "optional_trimming", "post_trim_fastqc", "multiqc"]


def _default_pipeline_stages() -> list[PipelineStage]:
    return ["raw_fastqc", "multiqc"]


class PipelineAnalysis(StrictModel):
    """The constrained M3 analysis graph."""

    goal: Literal["fastq_qc"] = "fastq_qc"
    stages: list[PipelineStage] = Field(default_factory=_default_pipeline_stages)


class TrimmingParameters(StrictModel):
    """Controlled fastp parameters; no arbitrary command fragment is accepted."""

    enabled: bool = Field(default=False, strict=True)
    tool: Literal["fastp"] = "fastp"
    minimum_length: int = Field(default=30, ge=1, le=1_000, strict=True)


class PipelineParameters(StrictModel):
    """Versioned parameters for the fixed QC graph."""

    trimming: TrimmingParameters = Field(default_factory=TrimmingParameters)


class PipelineExecution(StrictModel):
    """Bounded workflow execution resources."""

    workflow_engine: Literal["nextflow"] = "nextflow"
    executor: Literal["local", "slurm"] = "local"
    container_engine: Literal["apptainer", "docker"] = "apptainer"
    max_cpus: int = Field(default=1, ge=1, le=1_024)
    max_memory_gb: int = Field(default=4, ge=1, le=16_384)


class PipelinePaths(StrictModel):
    """Execution paths kept as data rather than shell fragments."""

    work_dir: str
    output_dir: str
    container_cache: str

    @field_validator("work_dir", "output_dir", "container_cache")
    @classmethod
    def validate_paths(cls, value: str) -> str:
        return _absolute_posix_path(value, "pipeline path")


class PipelinePolicy(StrictModel):
    """Fail-closed real-data and network policy defaults."""

    network_access_during_tasks: bool = False
    run_real_data: bool = False
    require_real_data_approval: bool = True
    overwrite_existing_outputs: bool = False

    @model_validator(mode="after")
    def preserve_approval_gate(self) -> PipelinePolicy:
        if self.run_real_data and not self.require_real_data_approval:
            raise ValueError("real-data execution cannot disable the approval requirement")
        return self


class PipelineSpec(StrictModel):
    """Deterministic specification for the fixed FASTQ QC goal."""

    spec_version: Version1 = "1.0"
    project: PipelineProject
    input: PipelineInput
    analysis: PipelineAnalysis = Field(default_factory=PipelineAnalysis)
    parameters: PipelineParameters = Field(default_factory=PipelineParameters)
    execution: PipelineExecution = Field(default_factory=PipelineExecution)
    paths: PipelinePaths
    policy: PipelinePolicy = Field(default_factory=PipelinePolicy)

    @model_validator(mode="after")
    def validate_fixed_fastq_qc_graph(self) -> PipelineSpec:
        expected: list[PipelineStage]
        if self.parameters.trimming.enabled:
            expected = [
                "raw_fastqc",
                "optional_trimming",
                "post_trim_fastqc",
                "multiqc",
            ]
        else:
            expected = ["raw_fastqc", "multiqc"]
        if self.analysis.stages != expected:
            raise ValueError(
                "analysis.stages must match the fixed fastq_qc graph selected by trimming.enabled"
            )
        return self


class LockedComponent(StrictModel):
    """Reviewed tool and immutable container identity."""

    version: str
    image: str
    digest: str
    license: str

    @field_validator("version", "image", "license")
    @classmethod
    def validate_text(cls, value: str) -> str:
        return _safe_text(value, "software lock value")

    @field_validator("version")
    @classmethod
    def reject_floating_version(cls, value: str) -> str:
        if value.casefold() == "latest" or not _PINNED_VERSION_PATTERN.fullmatch(value):
            raise ValueError("software lock versions must be pinned")
        return value

    @field_validator("image")
    @classmethod
    def reject_latest(cls, value: str) -> str:
        if "@" in value:
            raise ValueError("software lock image and digest must be stored separately")
        if not _TAGGED_IMAGE_PATTERN.fullmatch(value):
            raise ValueError("software lock images must be safe tagged OCI references")
        final_segment = value.rsplit("/", maxsplit=1)[-1]
        if ":" not in final_segment:
            raise ValueError("software lock images require an explicit versioned tag")
        tag = final_segment.rsplit(":", maxsplit=1)[-1]
        if not tag or tag.casefold() == "latest":
            raise ValueError("software lock images must not use the latest tag")
        return value

    @field_validator("digest")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        if not value.startswith("sha256:") or not _SHA256_PATTERN.fullmatch(value[7:]):
            raise ValueError("component digest must be sha256 followed by 64 lowercase hex digits")
        if value[7:] == "0" * 64:
            raise ValueError("component digest must not be an all-zero placeholder")
        return value


class SoftwareLock(StrictModel):
    """Pinned software inputs for a generated project."""

    lock_version: Version1 = "1.0"
    components: dict[str, LockedComponent] = Field(min_length=1)
    resolved_at: datetime
    resolver_version: str

    @field_validator("components")
    @classmethod
    def validate_component_names(
        cls, values: dict[str, LockedComponent]
    ) -> dict[str, LockedComponent]:
        for component_name in values:
            _safe_identifier(component_name, "software lock component name")
        return values

    @field_validator("resolved_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("resolved_at must include a timezone")
        return value

    @field_validator("resolver_version")
    @classmethod
    def validate_resolver_version(cls, value: str) -> str:
        return _safe_text(value, "resolver_version")


class ExecutionPaths(StrictModel):
    """Source and execution locations, including optional shared-path mapping."""

    source_root: str
    execution_root: str
    work_dir: str
    output_dir: str
    container_cache: str

    @field_validator("source_root", "execution_root", "work_dir", "output_dir", "container_cache")
    @classmethod
    def validate_paths(cls, value: str) -> str:
        return _absolute_posix_path(value, "execution path")


class PathMapping(StrictModel):
    """An explicit shared-filesystem prefix translation."""

    source_prefix: str
    execution_prefix: str

    @field_validator("source_prefix", "execution_prefix")
    @classmethod
    def validate_paths(cls, value: str) -> str:
        return _absolute_posix_path(value, "path mapping")


class PreflightRequirements(StrictModel):
    """Checks that must pass before an execution may be approved."""

    require_rawdata_readable: bool = True
    require_rawdata_not_writable: bool = False
    require_workdir_writable: bool = True
    require_output_dir_writable: bool = True
    require_container_runtime: bool = True


class ExecutionApproval(StrictModel):
    """Default-deny real-data approval state."""

    real_data_execution_required: bool = True
    approved: bool = False
    approved_by: str | None = None
    approved_at: datetime | None = None
    artifact_hashes: dict[str, str] = Field(default_factory=dict)

    @field_validator("artifact_hashes")
    @classmethod
    def validate_hashes(cls, values: dict[str, str]) -> dict[str, str]:
        if any(not _SHA256_PATTERN.fullmatch(value) for value in values.values()):
            raise ValueError("approval artifact hashes must be lowercase SHA-256 hex digests")
        return values

    @model_validator(mode="after")
    def require_approval_attribution(self) -> ExecutionApproval:
        if self.approved:
            if not self.real_data_execution_required:
                raise ValueError("real-data approval cannot bypass the execution requirement")
            if self.approved_by is None or self.approved_at is None or not self.artifact_hashes:
                raise ValueError(
                    "approved execution requires actor, timestamp, and artifact hashes"
                )
        return self


class ExecutionPlan(StrictModel):
    """Host, path, preflight, and approval contract for a future run."""

    plan_version: Version1 = "1.0"
    source_host: str
    execution_host: str
    executor: Literal["local", "slurm"] = "local"
    paths: ExecutionPaths
    path_mapping: list[PathMapping] | None = None
    preflight: PreflightRequirements = Field(default_factory=PreflightRequirements)
    approval: ExecutionApproval = Field(default_factory=ExecutionApproval)

    @field_validator("source_host", "execution_host")
    @classmethod
    def validate_hosts(cls, value: str) -> str:
        return _safe_identifier(value, "host identifier")


AuditStatus = Literal["started", "success", "failed", "blocked"]


class AuditEvent(StrictModel):
    """One append-only, non-sensitive audit record."""

    schema_version: Version1 = "1.0"
    event_id: UUID
    timestamp: datetime
    event_type: str
    project_id: str
    actor: str
    input_hashes: dict[str, str] = Field(default_factory=dict)
    output_hashes: dict[str, str] = Field(default_factory=dict)
    status: AuditStatus
    summary: str

    @field_validator("event_type", "project_id", "actor")
    @classmethod
    def validate_identifiers(cls, value: str) -> str:
        return _safe_identifier(value, "audit identifier")

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value

    @field_validator("input_hashes", "output_hashes")
    @classmethod
    def validate_hashes(cls, values: dict[str, str]) -> dict[str, str]:
        if any(not _SHA256_PATTERN.fullmatch(value) for value in values.values()):
            raise ValueError("audit artifact hashes must be lowercase SHA-256 hex digests")
        return values

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        return _safe_text(value, "summary")


PUBLIC_MODELS: tuple[type[BaseModel], ...] = (
    SourceProfile,
    ProbeRequest,
    ProbeResponse,
    DatasetManifest,
    ManifestOverrides,
    PipelineSpec,
    SoftwareLock,
    ExecutionPlan,
    AuditEvent,
)

__all__ = [
    "PUBLIC_MODELS",
    "AuditEvent",
    "DatasetManifest",
    "ExecutionPlan",
    "ManifestOverrides",
    "PipelineSpec",
    "ProbeRequest",
    "ProbeResponse",
    "SoftwareLock",
    "SourceProfile",
]
