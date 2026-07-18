"""Controller orchestration for bounded FASTQ discovery and manifest creation."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import PurePosixPath

from biopipe.detectors import (
    FastqFileFacts,
    detect_fastq_dataset,
)
from biopipe.detectors import (
    MateMarkerCounts as DetectorMateMarkerCounts,
)
from biopipe.errors import BioPipeError, ErrorCode
from biopipe.manifests import build_manifest
from biopipe.models import DatasetManifest, ManifestIssue, ReadLengthSummary, SourceProfile
from biopipe.probe import (
    DetectedFormat,
    DetectFormatsResult,
    OpenSSHProbeClient,
    ProbeClientError,
    RemoteProbeError,
    SummarizeFastqResult,
)
from biopipe.probe.results import FastqFileSummary, ListTreeResult


def inspect_fastq_dataset(
    source: SourceProfile,
    root: str,
    *,
    client: OpenSSHProbeClient | None = None,
    sample_fastq_records: int = 1_000,
    scanned_at: datetime | None = None,
) -> DatasetManifest:
    """Discover FASTQ files remotely and return one finalized local manifest."""

    if not 1 <= sample_fastq_records <= 100_000:
        raise BioPipeError(
            ErrorCode.VALIDATION_FAILED,
            "sample_fastq_records is outside the supported range.",
            context={"minimum": 1, "maximum": 100_000},
        )
    probe_client = client or OpenSSHProbeClient(
        max_stdout_bytes=source.probe.max_response_bytes,
        max_stderr_bytes=source.probe.stderr_limit_bytes,
    )
    tree_response = probe_client.list_tree(source, root)
    tree = ListTreeResult.model_validate(tree_response.result)
    request_paths = sorted(
        str(PurePosixPath(root) / entry.relative_path)
        for entry in tree.entries
        if entry.kind == "file"
    )

    detected = _detect_all(probe_client, source, root, request_paths)
    candidates = sorted(
        path
        for path, item in detected.items()
        if item.format == "fastq" or item.extension_candidate
    )
    summaries, summary_errors = _summarize_all(
        probe_client,
        source,
        root,
        candidates,
        sample_fastq_records,
    )
    facts = [_to_detector_facts(summaries[path], path) for path in sorted(summaries)]
    detection = detect_fastq_dataset(facts)
    ignored_count = sum(
        item.format == "unknown" and not item.extension_candidate for item in detected.values()
    )
    warnings: list[ManifestIssue] = []
    if ignored_count:
        warnings.append(
            ManifestIssue(
                code="unsupported_files_ignored",
                severity="warning",
                message="Non-FASTQ files were ignored after content-backed detection.",
                context={"file_count": ignored_count},
            )
        )
    timestamp = scanned_at or datetime.now(timezone.utc)  # noqa: UP017
    return build_manifest(
        source_id=source.source_id,
        root=root,
        scanned_at=timestamp,
        detection=detection,
        additional_warnings=warnings,
        additional_errors=summary_errors,
    )


def _detect_all(
    client: OpenSSHProbeClient,
    source: SourceProfile,
    root: str,
    paths: Sequence[str],
) -> dict[str, DetectedFormat]:
    detected: dict[str, DetectedFormat] = {}

    def detect(batch: Sequence[str]) -> None:
        if not batch:
            return
        try:
            response = client.detect_formats(source, root, batch)
        except RemoteProbeError as exc:
            code = str(exc.context.get("probe_code", ""))
            if (
                code
                in {
                    "REQUEST_BUDGET_EXCEEDED",
                    "RESPONSE_BUDGET_EXCEEDED",
                    "SCAN_BUDGET_EXCEEDED",
                }
                and len(batch) > 1
            ):
                midpoint = len(batch) // 2
                detect(batch[:midpoint])
                detect(batch[midpoint:])
                return
            raise
        except ProbeClientError as exc:
            if exc.code is ErrorCode.VALIDATION_FAILED and len(batch) > 1:
                midpoint = len(batch) // 2
                detect(batch[:midpoint])
                detect(batch[midpoint:])
                return
            raise
        result = DetectFormatsResult.model_validate(response.result)
        for item in result.files:
            requested = _requested_path(root, result.root, item.path, batch)
            detected[requested] = item

    batch_size = min(source.probe.max_paths, source.probe.max_entries)
    for batch in _batches(paths, batch_size):
        detect(batch)
    return detected


def _summarize_all(
    client: OpenSSHProbeClient,
    source: SourceProfile,
    root: str,
    paths: Sequence[str],
    sample_fastq_records: int,
) -> tuple[dict[str, FastqFileSummary], list[ManifestIssue]]:
    summaries: dict[str, FastqFileSummary] = {}
    errors: list[ManifestIssue] = []

    def summarize(batch: Sequence[str]) -> None:
        if not batch:
            return
        try:
            response = client.summarize_fastq(
                source,
                root,
                batch,
                sample_fastq_records=sample_fastq_records,
            )
        except RemoteProbeError as exc:
            code = str(exc.context.get("probe_code", ""))
            if (
                code
                in {
                    "REQUEST_BUDGET_EXCEEDED",
                    "RESPONSE_BUDGET_EXCEEDED",
                    "SCAN_BUDGET_EXCEEDED",
                }
                and len(batch) > 1
            ):
                midpoint = len(batch) // 2
                summarize(batch[:midpoint])
                summarize(batch[midpoint:])
                return
            if code not in {"INVALID_FASTQ", "UNSUPPORTED_FORMAT"}:
                raise
            if len(batch) > 1:
                midpoint = len(batch) // 2
                summarize(batch[:midpoint])
                summarize(batch[midpoint:])
                return
            errors.append(_summary_issue(code, batch[0]))
            return
        except ProbeClientError as exc:
            if exc.code is ErrorCode.VALIDATION_FAILED and len(batch) > 1:
                midpoint = len(batch) // 2
                summarize(batch[:midpoint])
                summarize(batch[midpoint:])
                return
            raise
        result = SummarizeFastqResult.model_validate(response.result)
        for item in result.files:
            requested = _requested_path(root, result.root, item.path, batch)
            summaries[requested] = item

    batch_size = min(source.probe.max_paths, source.probe.max_entries)
    for group in _batches(paths, batch_size):
        summarize(group)
    return summaries, sorted(errors, key=lambda issue: (issue.code, str(issue.context)))


def _to_detector_facts(summary: FastqFileSummary, requested_path: str) -> FastqFileFacts:
    return FastqFileFacts(
        path=requested_path,
        compression=summary.compression,
        structure_valid=summary.structure_valid,
        read_length=ReadLengthSummary(
            minimum=summary.read_length.minimum,
            median=summary.read_length.median,
            maximum=summary.read_length.maximum,
        ),
        likely_quality_encoding=summary.likely_quality_encoding,
        header_family=summary.header_family,
        mate_markers=DetectorMateMarkerCounts(
            read_1=summary.mate_markers.read_1,
            read_2=summary.mate_markers.read_2,
            unknown=summary.mate_markers.unknown,
            mixed=summary.mate_markers.mixed,
        ),
    )


def _requested_path(
    request_root: str,
    result_root: str,
    result_path: str,
    requested_paths: Sequence[str],
) -> str:
    try:
        relative = PurePosixPath(result_path).relative_to(PurePosixPath(result_root))
    except ValueError as exc:
        raise BioPipeError(
            ErrorCode.PROBE_PROTOCOL_ERROR,
            "The probe returned a file outside its result root.",
        ) from exc
    by_relative = {
        PurePosixPath(path).relative_to(PurePosixPath(request_root)): path
        for path in requested_paths
    }
    requested = by_relative.get(relative)
    if requested is None:
        raise BioPipeError(
            ErrorCode.PROBE_PROTOCOL_ERROR,
            "The probe returned a file unrelated to the request batch.",
        )
    return requested


def _summary_issue(code: str, path: str) -> ManifestIssue:
    if code == "INVALID_FASTQ":
        return ManifestIssue(
            code="invalid_fastq",
            severity="blocking",
            message="A FASTQ candidate has invalid or truncated record structure.",
            context={"path": path},
            remediation=["Correct the source file or exclude both affected mates explicitly."],
        )
    return ManifestIssue(
        code="unsupported_fastq_candidate",
        severity="blocking",
        message="A FASTQ-named candidate has unsupported content.",
        context={"path": path},
        remediation=["Verify the file format or exclude the candidate explicitly."],
    )


def _batches(values: Sequence[str], size: int) -> list[list[str]]:
    return [list(values[index : index + size]) for index in range(0, len(values), size)]


__all__ = ["inspect_fastq_dataset"]
