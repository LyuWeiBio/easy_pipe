"""Traceable application of explicit manifest overrides."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.manifests.integrity import finalize_manifest, require_valid_manifest
from biopipe.models import (
    DatasetClassification,
    DatasetManifest,
    DatasetSample,
    LaneFiles,
    Layout,
    ManifestIntegrity,
    ManifestIssue,
    ManifestOverrides,
    ManualPair,
)

_PAIRING_ISSUES = {
    "DUPLICATE_MATE",
    "INCOMPLETE_PAIRING",
    "MISSING_MATE",
    "NAMING_CONFLICT",
    "duplicate_mate",
    "incomplete_pairing",
    "missing_mate",
    "naming_conflict",
}


class OverrideDiff(BaseModel):
    """Auditable summary linking one override to original and resolved manifests."""

    model_config = ConfigDict(extra="forbid", strict=True)

    diff_version: Literal["1.0"] = "1.0"
    original_manifest_sha256: str
    override_sha256: str
    resolved_manifest_sha256: str
    reason: str
    approved_by: str
    renamed_samples: dict[str, str] = Field(default_factory=dict)
    excluded_files: list[str] = Field(default_factory=list)
    manual_pair_count: int = Field(ge=0)
    sample_count_before: int = Field(ge=0)
    sample_count_after: int = Field(ge=0)


class OverrideApplication(BaseModel):
    """The resolved manifest and its standalone trace record."""

    model_config = ConfigDict(extra="forbid", strict=True)

    resolved_manifest: DatasetManifest
    diff: OverrideDiff


def apply_overrides(
    original: DatasetManifest,
    overrides: ManifestOverrides,
) -> OverrideApplication:
    """Apply reviewed changes to a copy while preserving original scan facts."""

    require_valid_manifest(original)
    if len(overrides.exclude_files) != len(set(overrides.exclude_files)):
        raise _conflict("exclude_files contains duplicates")
    if not (overrides.rename_samples or overrides.exclude_files or overrides.manual_pairs):
        return _build_application(
            original,
            original.model_copy(deep=True),
            overrides,
            excluded=set(),
        )

    samples = [sample.model_copy(deep=True) for sample in original.samples]
    lookup: dict[str, int] = {}
    ambiguous: set[str] = set()
    for index, sample in enumerate(samples):
        for key in (sample.sample_id, sample.original_sample_name):
            if key is None:
                continue
            if key in lookup and lookup[key] != index:
                ambiguous.add(key)
            else:
                lookup[key] = index
    if ambiguous & set(overrides.rename_samples):
        raise _conflict("rename_samples contains an ambiguous original name")

    renamed_indexes: set[int] = set()
    for source_name, target_name in sorted(overrides.rename_samples.items()):
        sample_index = lookup.get(source_name)
        if sample_index is None:
            raise _conflict("rename_samples references an unknown sample")
        if sample_index in renamed_indexes:
            raise _conflict("rename_samples addresses one sample more than once")
        sample = samples[sample_index]
        try:
            samples[sample_index] = DatasetSample(
                sample_id=target_name,
                original_sample_name=sample.original_sample_name,
                lanes=[lane.model_copy(deep=True) for lane in sample.lanes],
            )
        except ValueError as exc:
            raise _conflict("rename_samples contains an invalid target identifier") from exc
        renamed_indexes.add(sample_index)
    final_ids = [sample.sample_id for sample in samples]
    if len(final_ids) != len(set(final_ids)):
        raise _conflict("rename_samples creates duplicate sample identifiers")

    excluded = set(overrides.exclude_files)
    root = PurePosixPath(original.source.root)
    for path in excluded:
        _require_below_root(path, root, "exclude_files")
    assigned_paths = {
        path
        for sample in samples
        for lane in sample.lanes
        for path in (lane.read1, lane.read2)
        if path is not None
    }
    known_paths = assigned_paths | _manifest_issue_paths(original)
    if not excluded <= known_paths:
        raise _conflict("exclude_files references a path absent from the original manifest")

    manual_paths: set[str] = set()
    manual_pair_path_sets: set[frozenset[str]] = set()
    for pair in overrides.manual_pairs:
        _validate_manual_pair(pair, original.source.root)
        pair_paths = {pair.read1} | ({pair.read2} if pair.read2 is not None else set())
        if pair_paths & manual_paths:
            raise _conflict("manual_pairs reuse a path")
        if not pair_paths <= known_paths:
            raise _conflict("manual_pairs references a path absent from the original scan facts")
        if pair_paths & excluded:
            raise _conflict("manual_pairs cannot reuse an excluded path")
        manual_paths.update(pair_paths)
        manual_pair_path_sets.add(frozenset(pair_paths))

    retained_samples: list[DatasetSample] = []
    for sample in samples:
        lanes: list[LaneFiles] = []
        for lane in sample.lanes:
            read1_excluded = lane.read1 in excluded
            read2_excluded = lane.read2 is not None and lane.read2 in excluded
            if lane.read2 is not None and read1_excluded != read2_excluded:
                raise _conflict("paired lane exclusions must remove both mates")
            if read1_excluded:
                continue
            lanes.append(lane.model_copy(deep=True))
        if lanes:
            retained_samples.append(
                DatasetSample(
                    sample_id=sample.sample_id,
                    original_sample_name=sample.original_sample_name,
                    lanes=lanes,
                )
            )
    samples = retained_samples

    reassigned_samples: list[DatasetSample] = []
    for sample in samples:
        reassigned_lanes: list[LaneFiles] = []
        for lane in sample.lanes:
            lane_paths = {lane.read1} | ({lane.read2} if lane.read2 is not None else set())
            overlap = lane_paths & manual_paths
            if overlap:
                if lane.read2 is not None and (
                    overlap != lane_paths or frozenset(lane_paths) not in manual_pair_path_sets
                ):
                    raise _conflict(
                        "manual_pairs must reassign both mates of an assigned paired lane together"
                    )
                continue
            reassigned_lanes.append(lane.model_copy(deep=True))
        if reassigned_lanes:
            reassigned_samples.append(
                DatasetSample(
                    sample_id=sample.sample_id,
                    original_sample_name=sample.original_sample_name,
                    lanes=reassigned_lanes,
                )
            )
    samples = reassigned_samples

    for pair in overrides.manual_pairs:
        _append_manual_pair(samples, pair)

    samples = [
        DatasetSample(
            sample_id=sample.sample_id,
            original_sample_name=sample.original_sample_name,
            lanes=sorted(sample.lanes, key=lambda lane: (lane.lane, lane.chunk or "")),
        )
        for sample in sorted(samples, key=lambda sample: sample.sample_id)
    ]
    layout, new_errors = _resolved_layout(samples)
    addressed = excluded | manual_paths
    retained_errors = [
        issue.model_copy(deep=True)
        for issue in original.errors
        if _retain_issue(issue, samples, excluded=excluded, addressed=addressed)
    ]
    retained_warnings = [
        issue.model_copy(deep=True)
        for issue in original.warnings
        if _retain_issue(issue, samples, excluded=excluded, addressed=addressed)
    ]
    if retained_errors:
        layout = "unknown"
    resolved = DatasetManifest(
        manifest_version=original.manifest_version,
        source=original.source.model_copy(deep=True),
        classification=DatasetClassification(
            dataset_type=(original.classification.dataset_type if samples else "unknown"),
            layout=layout,
            confidence=(original.classification.confidence if samples else 0.0),
        ),
        samples=samples,
        observations=original.observations.model_copy(deep=True),
        evidence=[item.model_copy(deep=True) for item in original.evidence],
        warnings=retained_warnings,
        errors=_merge_issues(retained_errors, new_errors),
        privacy=original.privacy.model_copy(deep=True),
        integrity=ManifestIntegrity(manifest_sha256=None),
    )
    resolved = finalize_manifest(resolved)
    return _build_application(original, resolved, overrides, excluded=excluded)


def _build_application(
    original: DatasetManifest,
    resolved: DatasetManifest,
    overrides: ManifestOverrides,
    *,
    excluded: set[str],
) -> OverrideApplication:
    """Build the audit record for a validated original/resolved manifest pair."""

    original_digest = original.integrity.manifest_sha256
    resolved_digest = resolved.integrity.manifest_sha256
    assert original_digest is not None
    assert resolved_digest is not None
    diff = OverrideDiff(
        original_manifest_sha256=original_digest,
        override_sha256=_override_sha256(overrides),
        resolved_manifest_sha256=resolved_digest,
        reason=overrides.reason,
        approved_by=overrides.approved_by,
        renamed_samples=dict(sorted(overrides.rename_samples.items())),
        excluded_files=sorted(excluded),
        manual_pair_count=len(overrides.manual_pairs),
        sample_count_before=len(original.samples),
        sample_count_after=len(resolved.samples),
    )
    return OverrideApplication(resolved_manifest=resolved, diff=diff)


def _append_manual_pair(samples: list[DatasetSample], pair: ManualPair) -> None:
    lane = LaneFiles(lane=pair.lane, read1=pair.read1, read2=pair.read2)
    matching = next((sample for sample in samples if sample.sample_id == pair.sample_id), None)
    if matching is None:
        samples.append(DatasetSample(sample_id=pair.sample_id, lanes=[lane]))
        return
    if any(
        (existing.lane, existing.chunk) == (lane.lane, lane.chunk) for existing in matching.lanes
    ):
        raise _conflict("manual_pairs duplicates a sample lane")
    matching.lanes.append(lane)


def _validate_manual_pair(pair: ManualPair, root: str) -> None:
    root_path = PurePosixPath(root)
    for value in (pair.read1, pair.read2):
        if value is None:
            continue
        _require_below_root(value, root_path, "manual_pairs")
    if pair.read2 == pair.read1:
        raise _conflict("manual_pairs cannot use one path for both mates")


def _require_below_root(value: str, root: PurePosixPath, field: str) -> None:
    try:
        relative = PurePosixPath(value).relative_to(root)
    except ValueError as exc:
        raise _conflict(f"{field} contains a path outside the scan root") from exc
    if relative == PurePosixPath("."):
        raise _conflict(f"{field} contains a path outside the scan root")


def _manifest_issue_paths(manifest: DatasetManifest) -> set[str]:
    root = PurePosixPath(manifest.source.root)
    paths: set[str] = set()
    for issue in (*manifest.warnings, *manifest.errors):
        candidates: list[object] = []
        if "path" in issue.context:
            candidates.append(issue.context["path"])
        for key in ("paths", "related_paths"):
            raw_paths = issue.context.get(key)
            if isinstance(raw_paths, list):
                candidates.extend(raw_paths)
        for value in candidates:
            if not isinstance(value, str):
                continue
            path = PurePosixPath(value)
            try:
                relative = path.relative_to(root)
            except ValueError:
                continue
            if path.is_absolute() and relative != PurePosixPath(".") and str(path) == value:
                paths.add(value)
    return paths


def _issue_paths(issue: ManifestIssue) -> set[str]:
    values: list[object] = []
    if "path" in issue.context:
        values.append(issue.context["path"])
    raw_paths = issue.context.get("paths")
    if isinstance(raw_paths, list):
        values.extend(raw_paths)
    return {value for value in values if isinstance(value, str)}


def _retain_issue(
    issue: ManifestIssue,
    samples: list[DatasetSample],
    *,
    excluded: set[str],
    addressed: set[str],
) -> bool:
    if issue.code.casefold() == "mixed_layout":
        paired_states = {lane.read2 is not None for sample in samples for lane in sample.lanes}
        return paired_states == {False, True}
    paths = _issue_paths(issue)
    if paths and paths <= excluded:
        return False
    if issue.code not in _PAIRING_ISSUES:
        return True
    if paths:
        return not paths <= addressed
    sample_key = issue.context.get("sample_key")
    if not isinstance(sample_key, str):
        return True
    return any(
        sample.sample_id == sample_key or sample.original_sample_name == sample_key
        for sample in samples
    )


def _merge_issues(
    retained: list[ManifestIssue],
    generated: list[ManifestIssue],
) -> list[ManifestIssue]:
    merged: list[ManifestIssue] = []
    seen: set[tuple[str, str]] = set()
    for issue in (*retained, *generated):
        key = _issue_identity(issue)
        if key in seen:
            continue
        seen.add(key)
        merged.append(issue)
    return merged


def _issue_identity(issue: ManifestIssue) -> tuple[str, str]:
    normalized_code = issue.code.casefold()
    if normalized_code in {"no_fastq_files"}:
        normalized_code = "no_fastq_files"
    elif normalized_code in {"incomplete_pairing", "mixed_layout"}:
        normalized_code = "incomplete_pairing"
    context = json.dumps(
        issue.context,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return normalized_code, context


def _resolved_layout(
    samples: list[DatasetSample],
) -> tuple[Layout, list[ManifestIssue]]:
    lanes = [lane for sample in samples for lane in sample.lanes]
    if not lanes:
        return "unknown", [
            ManifestIssue(
                code="no_fastq_files",
                severity="blocking",
                message="No FASTQ files remain after applying overrides.",
            )
        ]
    paired = [lane.read2 is not None for lane in lanes]
    if all(paired):
        return "paired_end", []
    if not any(paired):
        return "single_end", []
    return "unknown", [
        ManifestIssue(
            code="incomplete_pairing",
            severity="blocking",
            message="Resolved samples contain a mixture of paired and unpaired lanes.",
            remediation=["Provide complete manual pairs or exclude both mates."],
        )
    ]


def _override_sha256(overrides: ManifestOverrides) -> str:
    payload: Any = overrides.model_dump(mode="json", exclude_none=False)
    serialized = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _conflict(message: str) -> BioPipeError:
    return BioPipeError(
        ErrorCode.MANIFEST_OVERRIDE_CONFLICT,
        message,
        remediation=["Review the original manifest and submit a non-conflicting override."],
    )


__all__ = ["OverrideApplication", "OverrideDiff", "apply_overrides"]
