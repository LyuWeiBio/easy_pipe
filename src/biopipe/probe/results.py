"""Strict M1 success-result contracts for the controller trust boundary."""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from biopipe.models import ProbeRequest, SourceProfile

_MODE_PATTERN = re.compile(r"^[0-7]{4}$")
_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$")
_MAX_RESULT_PATH_BYTES = 65_536
_M1_CAPABILITIES = {"health", "list_tree", "stat_files"}


class ProbeResultValidationError(ValueError):
    """A success payload is not one of the fixed metadata-only M1 shapes."""


class StrictResultModel(BaseModel):
    """Base model that prevents coercion and unreviewed response fields."""

    model_config = ConfigDict(extra="forbid", strict=True)


class ProbeBudgets(StrictResultModel):
    """Effective server budgets reported by a metadata operation."""

    max_depth: int = Field(ge=0, le=64)
    max_entries: int = Field(ge=1, le=10_000_000)
    max_runtime_seconds: float = Field(gt=0.0, le=3600.0)

    @field_validator("max_runtime_seconds")
    @classmethod
    def finite_runtime(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("max_runtime_seconds must be finite")
        return value


class FileMetadata(StrictResultModel):
    """The complete allowlist of fields that M1 may return for one path."""

    path: str
    relative_path: str
    name: str
    kind: Literal["file", "directory", "other"]
    size_bytes: int = Field(ge=0, le=2**63 - 1)
    mtime_ns: int = Field(ge=-(2**63), le=2**63 - 1)
    mode: str
    depth: int = Field(ge=0, le=64)

    @field_validator("path")
    @classmethod
    def absolute_safe_path(cls, value: str) -> str:
        _safe_path_text(value, "path")
        path = PurePosixPath(value)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("path must be an absolute normalized POSIX path")
        if str(path) != value:
            raise ValueError("path must be normalized")
        return value

    @field_validator("relative_path")
    @classmethod
    def safe_relative_path(cls, value: str) -> str:
        _safe_path_text(value, "relative_path")
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("relative_path must stay below its result root")
        if str(path) != value:
            raise ValueError("relative_path must be normalized")
        return value

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        if value == "":
            # The POSIX filesystem root is the sole path with an empty name;
            # the model-level path/name consistency check enforces that case.
            return value
        _safe_path_text(value, "name")
        if value in {".", ".."} or "/" in value:
            raise ValueError("name must contain one safe path component")
        return value

    @field_validator("mode")
    @classmethod
    def octal_mode(cls, value: str) -> str:
        if not _MODE_PATTERN.fullmatch(value):
            raise ValueError("mode must contain four octal digits")
        return value

    @model_validator(mode="after")
    def consistent_components(self) -> FileMetadata:
        path = PurePosixPath(self.path)
        relative = PurePosixPath(self.relative_path)
        if path.name != self.name:
            raise ValueError("name does not match path")
        expected_depth = 0 if self.relative_path == "." else len(relative.parts)
        if self.depth != expected_depth:
            raise ValueError("depth does not match relative_path")
        return self


class HealthLimits(ProbeBudgets):
    """Non-sensitive configured ceilings returned by ``health``."""

    max_request_bytes: int = Field(ge=1024, le=16_777_216)
    max_response_bytes: int = Field(ge=512, le=67_108_864)
    max_paths: int = Field(ge=1, le=1_000_000)
    max_path_bytes: int = Field(ge=256, le=65_536)


class HealthConfiguration(StrictResultModel):
    """Safe configuration summary returned by ``health``."""

    configured: bool
    config_source: Literal["none", "environment", "default", "explicit"]
    allowed_root_count: int = Field(ge=0, le=1024)
    follow_symlinks: Literal[False]
    allow_mount_crossing: bool
    limits: HealthLimits

    @model_validator(mode="after")
    def consistent_configuration_state(self) -> HealthConfiguration:
        if self.configured != (self.allowed_root_count > 0):
            raise ValueError("configured must match allowed_root_count")
        if self.configured == (self.config_source == "none"):
            raise ValueError("config_source does not match configured")
        return self


class HealthResult(StrictResultModel):
    """Validated result for the fixed ``health`` operation."""

    operation: Literal["health"]
    status: Literal["ok"]
    probe_version: str
    protocol_version: Literal["1.0"]
    capabilities: list[Literal["health", "list_tree", "stat_files"]] = Field(
        min_length=3,
        max_length=3,
    )
    configuration: HealthConfiguration

    @field_validator("probe_version")
    @classmethod
    def safe_probe_version(cls, value: str) -> str:
        if not _VERSION_PATTERN.fullmatch(value):
            raise ValueError("probe_version has an invalid format")
        return value

    @field_validator("capabilities")
    @classmethod
    def complete_capabilities(
        cls,
        values: list[Literal["health", "list_tree", "stat_files"]],
    ) -> list[Literal["health", "list_tree", "stat_files"]]:
        if set(values) != _M1_CAPABILITIES:
            raise ValueError("health must report every fixed M1 capability exactly once")
        return values


class ListTreeResult(StrictResultModel):
    """Validated result for a bounded metadata-only tree scan."""

    operation: Literal["list_tree"]
    root: str
    entries: list[FileMetadata]
    entry_count: int = Field(ge=0, le=10_000_000)
    max_depth_observed: int = Field(ge=0, le=64)
    budgets: ProbeBudgets

    @field_validator("root")
    @classmethod
    def safe_root(cls, value: str) -> str:
        return _absolute_result_path(value, "root")

    @model_validator(mode="after")
    def internally_consistent(self) -> ListTreeResult:
        if self.entry_count != len(self.entries):
            raise ValueError("entry_count does not match entries")
        if any(entry.relative_path == "." for entry in self.entries):
            raise ValueError("list_tree entries must be below the scanned root")
        if self.entry_count > self.budgets.max_entries:
            raise ValueError("entries exceed the reported budget")
        expected_depth = max((entry.depth for entry in self.entries), default=0)
        if self.max_depth_observed != expected_depth:
            raise ValueError("max_depth_observed does not match entries")
        if self.max_depth_observed > self.budgets.max_depth:
            raise ValueError("entry depth exceeds the reported budget")
        _validate_metadata_below_root(self.entries, self.root)
        _reject_duplicate_paths(self.entries)
        return self


class StatFilesResult(StrictResultModel):
    """Validated result for explicit metadata-only path statistics."""

    operation: Literal["stat_files"]
    root: str | None
    files: list[FileMetadata]
    file_count: int = Field(ge=0, le=100_000)
    budgets: ProbeBudgets

    @field_validator("root")
    @classmethod
    def safe_optional_root(cls, value: str | None) -> str | None:
        return None if value is None else _absolute_result_path(value, "root")

    @model_validator(mode="after")
    def internally_consistent(self) -> StatFilesResult:
        if self.file_count != len(self.files):
            raise ValueError("file_count does not match files")
        if self.file_count > self.budgets.max_entries:
            raise ValueError("files exceed the reported budget")
        if self.root is not None:
            _validate_metadata_below_root(self.files, self.root)
        _reject_duplicate_paths(self.files)
        return self


ProbeSuccessResult = HealthResult | ListTreeResult | StatFilesResult


def validate_success_result(
    source: SourceProfile,
    request: ProbeRequest,
    result: dict[str, Any] | None,
) -> ProbeSuccessResult:
    """Validate and cross-check one success result without retaining unknown data."""

    try:
        if request.operation == "health":
            health = HealthResult.model_validate(result)
            _validate_budget_caps(source, request, health.configuration.limits)
            return health
        if request.operation == "list_tree":
            tree = ListTreeResult.model_validate(result)
            _validate_budget_caps(source, request, tree.budgets)
            if request.root is None:
                raise ValueError("list_tree request is missing its root")
            _require_canonical_suffix(
                PurePosixPath(tree.root),
                _expected_canonical_suffix(source, PurePosixPath(request.root)),
            )
            return tree
        if request.operation == "stat_files":
            stats = StatFilesResult.model_validate(result)
            _validate_budget_caps(source, request, stats.budgets)
            _validate_stat_request(source, request, stats)
            return stats
        raise ValueError("operation has no M1 success-result contract")
    except (TypeError, ValueError) as exc:
        raise ProbeResultValidationError(
            "probe success result failed its fixed M1 metadata contract"
        ) from exc


def _validate_budget_caps(
    source: SourceProfile,
    request: ProbeRequest,
    budgets: ProbeBudgets,
) -> None:
    if budgets.max_depth > min(source.probe.max_depth, request.policy.max_depth):
        raise ValueError("reported max_depth exceeds the requested ceiling")
    if budgets.max_entries > min(source.probe.max_entries, request.policy.max_entries):
        raise ValueError("reported max_entries exceeds the requested ceiling")
    if budgets.max_runtime_seconds > min(
        source.probe.max_runtime_seconds,
        request.policy.max_runtime_seconds,
    ):
        raise ValueError("reported runtime exceeds the requested ceiling")


def _validate_stat_request(
    source: SourceProfile,
    request: ProbeRequest,
    result: StatFilesResult,
) -> None:
    if (request.root is None) != (result.root is None):
        raise ValueError("result root presence does not match the request")
    if result.file_count != len(request.paths):
        raise ValueError("stat_files result count does not match requested paths")

    if request.root is not None:
        request_root = PurePosixPath(request.root)
        assert result.root is not None
        _require_canonical_suffix(
            PurePosixPath(result.root),
            _expected_canonical_suffix(source, request_root),
        )
        expected_relative = Counter(
            str(PurePosixPath(path).relative_to(request_root)) for path in request.paths
        )
        returned_relative = Counter(item.relative_path for item in result.files)
        if returned_relative != expected_relative:
            raise ValueError("stat_files result paths do not match requested paths")
    else:
        expected_relative = Counter(
            str(_profile_relative_path(source, PurePosixPath(path))) for path in request.paths
        )
        returned_relative = Counter(item.relative_path for item in result.files)
        if returned_relative != expected_relative:
            raise ValueError("stat_files result paths do not match requested paths")

    unmatched_paths = [PurePosixPath(item.path) for item in result.files]
    for requested in request.paths:
        suffix = _expected_canonical_suffix(source, PurePosixPath(requested))
        match_index = next(
            (
                index
                for index, returned in enumerate(unmatched_paths)
                if _has_canonical_suffix(returned, suffix)
            ),
            None,
        )
        if match_index is None:
            raise ValueError("stat_files returned an unrelated canonical path")
        unmatched_paths.pop(match_index)


def _profile_root_and_relative(
    source: SourceProfile,
    path: PurePosixPath,
) -> tuple[PurePosixPath, PurePosixPath]:
    candidates: list[tuple[int, PurePosixPath, PurePosixPath]] = []
    for root_value in source.allowed_roots:
        root = PurePosixPath(root_value)
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        candidates.append((len(root.parts), root, relative))
    if not candidates:
        raise ValueError("path is outside the SourceProfile roots")
    _, root, relative = max(candidates, key=lambda item: item[0])
    return root, relative


def _profile_relative_path(source: SourceProfile, path: PurePosixPath) -> PurePosixPath:
    return _profile_root_and_relative(source, path)[1]


def _expected_canonical_suffix(
    source: SourceProfile,
    path: PurePosixPath,
) -> tuple[str, ...]:
    root, relative = _profile_root_and_relative(source, path)
    if root == PurePosixPath("/"):
        return path.parts
    return (root.name, *relative.parts)


def _has_canonical_suffix(path: PurePosixPath, suffix: tuple[str, ...]) -> bool:
    if not suffix:
        return path == PurePosixPath("/")
    if suffix[0] in {"/", "//"}:
        return path.parts == suffix
    return len(path.parts) >= len(suffix) and path.parts[-len(suffix) :] == suffix


def _require_canonical_suffix(path: PurePosixPath, suffix: tuple[str, ...]) -> None:
    if not _has_canonical_suffix(path, suffix):
        raise ValueError("returned canonical path is unrelated to the request")


def _validate_metadata_below_root(entries: list[FileMetadata], root: str) -> None:
    root_path = PurePosixPath(root)
    for entry in entries:
        entry_path = PurePosixPath(entry.path)
        try:
            relative = entry_path.relative_to(root_path)
        except ValueError as exc:
            raise ValueError("metadata path is outside the result root") from exc
        if str(relative) != entry.relative_path:
            raise ValueError("relative_path does not match path and root")


def _reject_duplicate_paths(entries: list[FileMetadata]) -> None:
    paths = [entry.path for entry in entries]
    if len(paths) != len(set(paths)):
        raise ValueError("metadata contains duplicate paths")


def _absolute_result_path(value: str, field_name: str) -> str:
    _safe_path_text(value, field_name)
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError(f"{field_name} must be an absolute normalized POSIX path")
    return value


def _safe_path_text(value: str, field_name: str) -> None:
    if not value:
        raise ValueError(f"{field_name} must not be empty")
    if any(
        ord(character) < 32 or ord(character) == 127 or 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    ):
        raise ValueError(f"{field_name} contains forbidden characters")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field_name} cannot be encoded as UTF-8") from exc
    if size > _MAX_RESULT_PATH_BYTES:
        raise ValueError(f"{field_name} is too long")


__all__ = [
    "FileMetadata",
    "HealthConfiguration",
    "HealthLimits",
    "HealthResult",
    "ListTreeResult",
    "ProbeBudgets",
    "ProbeResultValidationError",
    "ProbeSuccessResult",
    "StatFilesResult",
    "StrictResultModel",
    "validate_success_result",
]
