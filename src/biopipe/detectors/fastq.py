"""Deterministic controller-side FASTQ classification and pairing."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from pathlib import PurePosixPath
from statistics import median
from typing import Any, Literal, cast

from biopipe.detectors.models import (
    DetectorAssessment,
    FastqDetectionResult,
    FastqFileFacts,
    PairingSlotFacts,
    PairingStatus,
    ParsedFastqName,
    SamplePairingFacts,
)
from biopipe.detectors.naming import parse_fastq_filename
from biopipe.models import (
    DatasetClassification,
    DatasetObservations,
    DetectionEvidence,
    ManifestIssue,
    ReadLengthSummary,
)

_ILLUMINA_HEADERS = {"illumina_casava_1_8", "illumina_legacy"}
_BLOCKING_REMEDIATION = [
    "Correct the remote dataset or provide an explicit reviewed manifest override."
]


def assess_generic_fastq(files: Sequence[FastqFileFacts]) -> DetectorAssessment:
    """Score generic FASTQ evidence from aggregate facts only."""

    ordered = _ordered_unique_files(files)[0]
    parsed = tuple(parse_fastq_filename(item.path) for item in ordered)
    count = len(ordered)
    if count == 0:
        return DetectorAssessment(dataset_type="generic_fastq", confidence=0.0, evidence=())

    evidence = (
        _evidence(
            "valid_fastq_structure",
            0.55 * _fraction(ordered, lambda item: item.structure_valid),
            _ratio_detail(ordered, count, lambda item: item.structure_valid, "valid structures"),
        ),
        _evidence(
            "fastq_extension",
            0.15 * _fraction(parsed, lambda item: item.extension_recognized),
            _ratio_detail(
                parsed, count, lambda item: item.extension_recognized, "supported suffixes"
            ),
        ),
        _evidence(
            "parseable_naming",
            0.15 * _fraction(parsed, lambda item: item.sample_key is not None),
            _ratio_detail(parsed, count, lambda item: item.sample_key is not None, "sample keys"),
        ),
        _evidence(
            "read_length_aggregate",
            0.10 * _fraction(ordered, lambda item: item.read_length is not None),
            _ratio_detail(
                ordered, count, lambda item: item.read_length is not None, "read-length aggregates"
            ),
        ),
        _evidence(
            "quality_encoding_aggregate",
            0.05 * _fraction(ordered, lambda item: item.likely_quality_encoding != "unknown"),
            _ratio_detail(
                ordered,
                count,
                lambda item: item.likely_quality_encoding != "unknown",
                "likely quality encodings",
            ),
        ),
    )
    return DetectorAssessment(
        dataset_type="generic_fastq",
        confidence=_score(evidence),
        evidence=evidence,
    )


def assess_illumina_fastq(files: Sequence[FastqFileFacts]) -> DetectorAssessment:
    """Score Illumina-specific filename and header evidence."""

    ordered = _ordered_unique_files(files)[0]
    parsed = tuple(parse_fastq_filename(item.path) for item in ordered)
    count = len(ordered)
    if count == 0:
        return DetectorAssessment(dataset_type="illumina_fastq", confidence=0.0, evidence=())

    marker_consistent = sum(
        not _marker_conflicts(item, name.read_direction)
        for item, name in zip(ordered, parsed, strict=True)
    )
    evidence = (
        _evidence(
            "valid_fastq_structure",
            0.35 * _fraction(ordered, lambda item: item.structure_valid),
            _ratio_detail(ordered, count, lambda item: item.structure_valid, "valid structures"),
        ),
        _evidence(
            "fastq_extension",
            0.10 * _fraction(parsed, lambda item: item.extension_recognized),
            _ratio_detail(
                parsed, count, lambda item: item.extension_recognized, "supported suffixes"
            ),
        ),
        _evidence(
            "illumina_filename",
            0.30 * _fraction(parsed, lambda item: item.convention == "illumina"),
            _ratio_detail(
                parsed,
                count,
                lambda item: item.convention == "illumina",
                "Illumina lane/chunk names",
            ),
        ),
        _evidence(
            "illumina_header",
            0.20 * _fraction(ordered, lambda item: item.header_family in _ILLUMINA_HEADERS),
            _ratio_detail(
                ordered,
                count,
                lambda item: item.header_family in _ILLUMINA_HEADERS,
                "Illumina header families",
            ),
        ),
        _evidence(
            "header_mate_consistency",
            0.05 * marker_consistent / count,
            f"{marker_consistent}/{count} files have no filename/header mate conflict",
        ),
    )
    return DetectorAssessment(
        dataset_type="illumina_fastq",
        confidence=_score(evidence),
        evidence=evidence,
    )


def detect_fastq_dataset(files: Sequence[FastqFileFacts]) -> FastqDetectionResult:
    """Classify and pair aggregate FASTQ facts without filesystem I/O or guessing."""

    ordered, duplicate_paths, conflicting_paths = _ordered_unique_files(files)
    parsed = tuple(parse_fastq_filename(item.path) for item in ordered)
    errors: list[ManifestIssue] = []
    warnings: list[ManifestIssue] = []
    blocked_paths: set[str] = set()

    if not ordered:
        errors.append(
            _issue(
                "no_fastq_files",
                "blocking",
                "No FASTQ aggregate facts were provided.",
            )
        )

    for path in duplicate_paths:
        errors.append(
            _issue(
                "duplicate_path",
                "blocking",
                "The same path was supplied more than once.",
                {"path": path},
            )
        )
        blocked_paths.add(path)
    for path in conflicting_paths:
        errors.append(
            _issue(
                "conflicting_file_facts",
                "blocking",
                "The same path has conflicting aggregate facts.",
                {"path": path},
            )
        )
        blocked_paths.add(path)

    for item, name in zip(ordered, parsed, strict=True):
        if not item.structure_valid:
            errors.append(
                _issue(
                    "invalid_fastq_structure",
                    "blocking",
                    "A candidate file failed FASTQ structure validation.",
                    {"path": item.path},
                )
            )
            blocked_paths.add(item.path)
        if item.compression == "unknown":
            errors.append(
                _issue(
                    "unknown_compression",
                    "blocking",
                    "A candidate file has an unresolved compression format.",
                    {"path": item.path},
                )
            )
            blocked_paths.add(item.path)
        if name.sample_key is None:
            errors.append(
                _issue(
                    "unrecognized_fastq_name",
                    "blocking",
                    "A filename does not use a supported FASTQ suffix.",
                    {"path": item.path},
                )
            )
            blocked_paths.add(item.path)

        marker_state = _marker_state(item)
        if marker_state == "mixed":
            errors.append(
                _issue(
                    "mixed_header_mates",
                    "blocking",
                    "Sampled headers contain more than one mate category.",
                    {"path": item.path},
                )
            )
            blocked_paths.add(item.path)
        elif name.read_direction is not None and marker_state in {"read1", "read2"}:
            if marker_state != name.read_direction:
                errors.append(
                    _issue(
                        "header_mate_conflict",
                        "blocking",
                        "The sampled header mate marker conflicts with the filename direction.",
                        {
                            "path": item.path,
                            "filename_direction": name.read_direction,
                            "header_direction": marker_state,
                        },
                    )
                )
                blocked_paths.add(item.path)
        elif name.read_direction is None and marker_state in {"read1", "read2"}:
            warnings.append(
                _issue(
                    "unpaired_header_marker",
                    "warning",
                    "A single-end filename has a mate marker; no absent mate was inferred.",
                    {"path": item.path, "header_direction": marker_state},
                )
            )

    _add_observation_warnings(ordered, warnings)
    _add_detector_warnings(ordered, parsed, warnings)

    samples, pairing_errors = _pair_files(ordered, parsed, blocked_paths, errors)
    errors.extend(pairing_errors)
    layout = _layout(samples, errors)
    if layout == "mixed":
        errors.append(
            _issue(
                "mixed_layout",
                "blocking",
                "The dataset contains both complete single-end and paired-end slots.",
            )
        )
        resolved_layout: Literal["single_end", "paired_end", "unknown"] = "unknown"
    elif errors:
        resolved_layout = "unknown"
    else:
        resolved_layout = layout

    generic = assess_generic_fastq(ordered)
    illumina = assess_illumina_fastq(ordered)
    valid_count = _count(ordered, lambda item: item.structure_valid)
    if valid_count == 0:
        dataset_type: Literal["generic_fastq", "illumina_fastq", "unknown"] = "unknown"
        confidence = 0.0
        evidence = generic.evidence
    elif _has_coherent_illumina_signal(ordered, parsed):
        dataset_type = "illumina_fastq"
        confidence = illumina.confidence
        evidence = illumina.evidence
    else:
        dataset_type = "generic_fastq"
        confidence = generic.confidence
        evidence = generic.evidence

    return FastqDetectionResult(
        classification=DatasetClassification(
            dataset_type=dataset_type,
            layout=resolved_layout,
            confidence=confidence,
        ),
        observations=_observations(ordered),
        samples=samples,
        evidence=evidence,
        warnings=tuple(sorted(warnings, key=_issue_sort_key)),
        errors=tuple(sorted(errors, key=_issue_sort_key)),
    )


def _ordered_unique_files(
    files: Sequence[FastqFileFacts],
) -> tuple[tuple[FastqFileFacts, ...], tuple[str, ...], tuple[str, ...]]:
    by_path: dict[str, list[FastqFileFacts]] = defaultdict(list)
    for item in files:
        by_path[item.path].append(item)

    ordered: list[FastqFileFacts] = []
    duplicates: list[str] = []
    conflicts: list[str] = []
    for path in sorted(by_path):
        candidates = sorted(by_path[path], key=lambda item: item.model_dump_json())
        ordered.append(candidates[0])
        if len(candidates) > 1:
            duplicates.append(path)
            if len({item.model_dump_json() for item in candidates}) > 1:
                conflicts.append(path)
    return tuple(ordered), tuple(duplicates), tuple(conflicts)


def _pair_files(
    files: tuple[FastqFileFacts, ...],
    parsed: tuple[ParsedFastqName, ...],
    blocked_paths: set[str],
    file_errors: list[ManifestIssue],
) -> tuple[tuple[SamplePairingFacts, ...], list[ManifestIssue]]:
    entries_by_sample: dict[str, list[tuple[FastqFileFacts, ParsedFastqName]]] = defaultdict(list)
    for item, name in zip(files, parsed, strict=True):
        if name.sample_key is not None:
            entries_by_sample[name.sample_key].append((item, name))

    issues: list[ManifestIssue] = []
    samples: list[SamplePairingFacts] = []
    for sample_key in sorted(entries_by_sample):
        sample_entries = entries_by_sample[sample_key]
        sample_conventions = {name.convention for _, name in sample_entries}
        sample_numbers = {name.sample_number for _, name in sample_entries if name.sample_number}
        sample_conflict = len(sample_conventions) > 1 or len(sample_numbers) > 1
        if sample_conflict:
            direction_order = {"read1": 0, "read2": 1, None: 2}
            sample_paths = [
                item.path
                for item, name in sorted(
                    sample_entries,
                    key=lambda entry: (
                        direction_order[entry[1].read_direction],
                        entry[1].lane,
                        entry[1].chunk or "",
                        entry[0].path,
                    ),
                )
            ]
            issues.append(
                _issue(
                    "naming_conflict",
                    "blocking",
                    "A sample key has incompatible naming conventions or sample numbers.",
                    {
                        "sample_key": sample_key,
                        "conventions": sorted(sample_conventions),
                        "sample_numbers": sorted(sample_numbers),
                        "paths": sample_paths,
                    },
                )
            )

        by_slot: dict[tuple[str, str | None], list[tuple[FastqFileFacts, ParsedFastqName]]] = (
            defaultdict(list)
        )
        for entry in sample_entries:
            name = entry[1]
            by_slot[(name.lane, name.chunk)].append(entry)

        slots: list[PairingSlotFacts] = []
        for lane, chunk in sorted(by_slot, key=lambda key: (key[0], key[1] or "")):
            slot_entries = by_slot[(lane, chunk)]
            read1 = tuple(
                sorted(item.path for item, name in slot_entries if name.read_direction == "read1")
            )
            read2 = tuple(
                sorted(item.path for item, name in slot_entries if name.read_direction == "read2")
            )
            unpaired = tuple(
                sorted(item.path for item, name in slot_entries if name.read_direction is None)
            )
            conventions = tuple(sorted({name.convention for _, name in slot_entries}))
            numbers = tuple(
                sorted({name.sample_number for _, name in slot_entries if name.sample_number})
            )
            slot_paths = read1 + read2 + unpaired
            duplicate = len(read1) > 1 or len(read2) > 1 or len(unpaired) > 1
            missing = bool(read1) != bool(read2) and not unpaired
            facts_by_path = {item.path: item for item, _name in slot_entries}
            sampled_count_conflict = False
            if len(read1) == 1 and len(read2) == 1:
                read1_count = _sampled_record_count(facts_by_path[read1[0]])
                read2_count = _sampled_record_count(facts_by_path[read2[0]])
                sampled_count_conflict = (
                    read1_count is not None
                    and read2_count is not None
                    and read1_count != read2_count
                )
            invalid = sampled_count_conflict or any(path in blocked_paths for path in slot_paths)
            if invalid:
                _attach_related_paths(file_errors, slot_paths)
            directory_conflict = (
                len(read1) == 1
                and len(read2) == 1
                and not unpaired
                and PurePosixPath(read1[0]).parent != PurePosixPath(read2[0]).parent
            )
            local_conflict = (
                sample_conflict or directory_conflict or bool(unpaired and (read1 or read2))
            )

            if unpaired and (read1 or read2):
                issues.append(
                    _slot_issue(
                        "naming_conflict",
                        "A lane/chunk mixes paired and unpaired filename conventions.",
                        sample_key,
                        lane,
                        chunk,
                        slot_paths,
                    )
                )
            if duplicate:
                issues.append(
                    _slot_issue(
                        "duplicate_mate",
                        "A lane/chunk has multiple candidates for the same read direction.",
                        sample_key,
                        lane,
                        chunk,
                        slot_paths,
                    )
                )
            if directory_conflict:
                issues.append(
                    _slot_issue(
                        "naming_conflict",
                        "Opposite mates with the same basename key occur in different directories.",
                        sample_key,
                        lane,
                        chunk,
                        slot_paths,
                    )
                )
            if missing:
                issues.append(
                    _slot_issue(
                        "missing_mate",
                        "A directional FASTQ filename has no unique opposite mate.",
                        sample_key,
                        lane,
                        chunk,
                        slot_paths,
                        missing="read2" if read1 else "read1",
                    )
                )
            if sampled_count_conflict:
                issues.append(
                    _slot_issue(
                        "sampled_record_count_mismatch",
                        "Opposite mates yielded different bounded sampled-record counts.",
                        sample_key,
                        lane,
                        chunk,
                        slot_paths,
                        read1_records=_sampled_record_count(facts_by_path[read1[0]]),
                        read2_records=_sampled_record_count(facts_by_path[read2[0]]),
                    )
                )

            status = _pairing_status(
                invalid=invalid,
                naming_conflict=local_conflict,
                duplicate=duplicate,
                missing=missing,
                paired=bool(read1 and read2),
            )
            slots.append(
                PairingSlotFacts(
                    sample_key=sample_key,
                    lane=lane,
                    chunk=chunk,
                    sample_numbers=numbers,
                    naming_conventions=conventions,
                    read1_candidates=read1,
                    read2_candidates=read2,
                    unpaired_candidates=unpaired,
                    status=status,
                )
            )
        samples.append(SamplePairingFacts(sample_key=sample_key, slots=tuple(slots)))
    return tuple(samples), issues


def _pairing_status(
    *,
    invalid: bool,
    naming_conflict: bool,
    duplicate: bool,
    missing: bool,
    paired: bool,
) -> PairingStatus:
    if invalid:
        return "invalid"
    if naming_conflict:
        return "naming_conflict"
    if duplicate:
        return "duplicate_mate"
    if missing:
        return "missing_mate"
    return "paired" if paired else "single"


def _layout(
    samples: tuple[SamplePairingFacts, ...],
    errors: list[ManifestIssue],
) -> Literal["single_end", "paired_end", "unknown", "mixed"]:
    statuses = {slot.status for sample in samples for slot in sample.slots}
    if errors or statuses - {"single", "paired"}:
        return "unknown"
    if statuses == {"single", "paired"}:
        return "mixed"
    if statuses == {"paired"}:
        return "paired_end"
    if statuses == {"single"}:
        return "single_end"
    return "unknown"


def _observations(files: tuple[FastqFileFacts, ...]) -> DatasetObservations:
    compressions = {item.compression for item in files}
    compression: Literal["gzip", "none", "mixed", "unknown"]
    if not compressions or "unknown" in compressions:
        compression = "unknown"
    elif len(compressions) == 1:
        compression = cast(Literal["gzip", "none"], next(iter(compressions)))
    else:
        compression = "mixed"

    lengths = [item.read_length for item in files if item.read_length is not None]
    read_length = None
    if lengths:
        read_length = ReadLengthSummary(
            minimum=min(item.minimum for item in lengths),
            median=float(median(item.median for item in lengths)),
            maximum=max(item.maximum for item in lengths),
        )

    qualities = {item.likely_quality_encoding for item in files}
    quality = next(iter(qualities)) if len(qualities) == 1 else "unknown"
    headers = {item.header_family for item in files}
    header = next(iter(headers)) if len(headers) == 1 else ("mixed" if headers else "unknown")
    return DatasetObservations(
        compression=compression,
        read_length=read_length,
        likely_quality_encoding=quality,
        header_family=header,
    )


def _add_observation_warnings(
    files: tuple[FastqFileFacts, ...], warnings: list[ManifestIssue]
) -> None:
    compression = {item.compression for item in files if item.compression != "unknown"}
    if len(compression) > 1:
        warnings.append(
            _issue(
                "mixed_compression",
                "warning",
                "The dataset mixes gzip-compressed and uncompressed FASTQ files.",
            )
        )
    quality = {
        item.likely_quality_encoding for item in files if item.likely_quality_encoding != "unknown"
    }
    if len(quality) > 1:
        warnings.append(
            _issue(
                "mixed_quality_encoding",
                "warning",
                "Files have conflicting likely quality encodings.",
                {"encodings": sorted(quality)},
            )
        )
    headers = {item.header_family for item in files if item.header_family != "unknown"}
    if len(headers) > 1:
        warnings.append(
            _issue(
                "mixed_header_family",
                "warning",
                "Files have multiple recognized header families.",
                {"header_families": sorted(headers)},
            )
        )


def _add_detector_warnings(
    files: tuple[FastqFileFacts, ...],
    parsed: tuple[ParsedFastqName, ...],
    warnings: list[ManifestIssue],
) -> None:
    illumina_names = [name for name in parsed if name.convention == "illumina"]
    if illumina_names and len(illumina_names) != len(parsed):
        warnings.append(
            _issue(
                "mixed_naming_family",
                "warning",
                "The dataset mixes Illumina lane/chunk names with generic FASTQ names.",
                {
                    "illumina_named_files": len(illumina_names),
                    "total_files": len(parsed),
                },
            )
        )
    if illumina_names:
        conflicts = sorted(
            item.path
            for item, name in zip(files, parsed, strict=True)
            if name.convention == "illumina"
            and item.header_family not in _ILLUMINA_HEADERS | {"unknown"}
        )
        if conflicts:
            warnings.append(
                _issue(
                    "illumina_header_conflict",
                    "warning",
                    "Illumina-style filenames have a non-Illumina sampled header family.",
                    {"paths": conflicts},
                )
            )


def _has_coherent_illumina_signal(
    files: tuple[FastqFileFacts, ...], parsed: tuple[ParsedFastqName, ...]
) -> bool:
    if not files:
        return False
    illumina_names = _count(parsed, lambda item: item.convention == "illumina")
    illumina_headers = _count(files, lambda item: item.header_family in _ILLUMINA_HEADERS)
    conflicting_headers = _count(files, lambda item: item.header_family == "generic")
    return illumina_names == len(files) or (illumina_headers > 0 and conflicting_headers == 0)


def _marker_state(
    item: FastqFileFacts,
) -> Literal["read1", "read2", "unknown", "mixed"]:
    markers = item.mate_markers
    if markers is None or markers.mixed:
        return "mixed" if markers is not None and markers.mixed else "unknown"
    if markers.read_1 > 0:
        return "read1"
    if markers.read_2 > 0:
        return "read2"
    return "unknown"


def _sampled_record_count(item: FastqFileFacts) -> int | None:
    markers = item.mate_markers
    if markers is None:
        return None
    return markers.read_1 + markers.read_2 + markers.unknown


def _marker_conflicts(item: FastqFileFacts, direction: str | None) -> bool:
    state = _marker_state(item)
    return state == "mixed" or (
        direction is not None and state in {"read1", "read2"} and state != direction
    )


def _slot_issue(
    code: str,
    message: str,
    sample_key: str,
    lane: str,
    chunk: str | None,
    paths: tuple[str, ...],
    **extra: Any,
) -> ManifestIssue:
    context: dict[str, Any] = {
        "sample_key": sample_key,
        "lane": lane,
        "chunk": chunk,
        "paths": list(paths),
        **extra,
    }
    return _issue(code, "blocking", message, context)


def _attach_related_paths(
    issues: list[ManifestIssue],
    slot_paths: tuple[str, ...],
) -> None:
    related = list(slot_paths)
    for index, issue in enumerate(issues):
        if issue.context.get("path") not in slot_paths:
            continue
        context = dict(issue.context)
        context["related_paths"] = related
        issues[index] = ManifestIssue(
            code=issue.code,
            severity=issue.severity,
            message=issue.message,
            context=context,
            remediation=list(issue.remediation),
        )


def _issue(
    code: str,
    severity: Literal["warning", "blocking"],
    message: str,
    context: dict[str, Any] | None = None,
) -> ManifestIssue:
    return ManifestIssue(
        code=code,
        severity=severity,
        message=message,
        context=context or {},
        remediation=[] if severity == "warning" else _BLOCKING_REMEDIATION,
    )


def _issue_sort_key(issue: ManifestIssue) -> tuple[str, str, str]:
    return issue.code, issue.message, repr(sorted(issue.context.items()))


def _evidence(rule: str, score: float, detail: str) -> DetectionEvidence:
    return DetectionEvidence(rule=rule, score=round(score, 6), detail=detail)


def _score(evidence: tuple[DetectionEvidence, ...]) -> float:
    return round(min(1.0, sum(item.score for item in evidence)), 6)


def _ratio_detail(items: Sequence[Any], total: int, predicate: Any, label: str) -> str:
    return f"{_count(items, predicate)}/{total} {label}"


def _fraction(items: Sequence[Any], predicate: Any) -> float:
    return _count(items, predicate) / len(items) if items else 0.0


def _count(items: Sequence[Any], predicate: Any) -> int:
    return sum(bool(predicate(item)) for item in items)


__all__ = ["assess_generic_fastq", "assess_illumina_fastq", "detect_fastq_dataset"]
