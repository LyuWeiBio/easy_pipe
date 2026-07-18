"""Controller inspection batching and isolation tests."""

from __future__ import annotations

from collections.abc import Sequence

from biopipe.errors import ErrorCode
from biopipe.inspection import _detect_all, _summarize_all
from biopipe.models import ProbeRequest, ProbeResponse, SourceProfile
from biopipe.probe import ProbeClientError

ROOT = "/srv/synthetic-raw"


class _RequestByteLimitedClient:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.detect_calls = 0
        self.summary_calls = 0

    def detect_formats(
        self,
        source: SourceProfile,
        root: str,
        paths: Sequence[str],
    ) -> ProbeResponse:
        self.detect_calls += 1
        request = ProbeRequest(
            request_id="detect-formats-" + "0" * 32,
            operation="detect_formats",
            root=root,
            paths=list(paths),
            policy={
                "inspection_level": "format_summary",
                "max_depth": source.probe.max_depth,
                "max_entries": source.probe.max_entries,
                "max_runtime_seconds": source.probe.max_runtime_seconds,
                "sample_fastq_records": 1,
            },
        )
        self._enforce(request)
        return ProbeResponse(
            request_id=request.request_id,
            success=True,
            return_code=0,
            result={
                "operation": "detect_formats",
                "root": root,
                "files": [
                    {
                        "path": path,
                        "format": "fastq",
                        "compression": "none",
                        "extension_candidate": True,
                    }
                    for path in paths
                ],
                "file_count": len(paths),
                "budgets": _budgets(source),
            },
        )

    def summarize_fastq(
        self,
        source: SourceProfile,
        root: str,
        paths: Sequence[str],
        *,
        sample_fastq_records: int,
    ) -> ProbeResponse:
        self.summary_calls += 1
        request = ProbeRequest(
            request_id="summarize-fastq-" + "0" * 32,
            operation="summarize_fastq",
            root=root,
            paths=list(paths),
            policy={
                "inspection_level": "format_summary",
                "max_depth": source.probe.max_depth,
                "max_entries": source.probe.max_entries,
                "max_runtime_seconds": source.probe.max_runtime_seconds,
                "sample_fastq_records": sample_fastq_records,
            },
        )
        self._enforce(request)
        return ProbeResponse(
            request_id=request.request_id,
            success=True,
            return_code=0,
            result={
                "operation": "summarize_fastq",
                "root": root,
                "files": [
                    {
                        "path": path,
                        "format": "fastq",
                        "compression": "none",
                        "records_sampled": 1,
                        "structure_valid": True,
                        "read_length": {"minimum": 4, "median": 4.0, "maximum": 4},
                        "likely_quality_encoding": "phred33",
                        "header_family": "generic",
                        "mate_markers": {
                            "read_1": 0,
                            "read_2": 0,
                            "unknown": 1,
                            "mixed": False,
                        },
                    }
                    for path in paths
                ],
                "file_count": len(paths),
                "budgets": _budgets(source),
            },
        )

    def _enforce(self, request: ProbeRequest) -> None:
        if len((request.model_dump_json() + "\n").encode("utf-8")) > self.limit:
            raise ProbeClientError(
                ErrorCode.VALIDATION_FAILED,
                "Synthetic request byte limit.",
            )


def _budgets(source: SourceProfile) -> dict[str, int | float]:
    return {
        "max_depth": source.probe.max_depth,
        "max_entries": source.probe.max_entries,
        "max_runtime_seconds": float(source.probe.max_runtime_seconds),
    }


def test_content_requests_adapt_to_serialized_request_byte_limit() -> None:
    source = SourceProfile(
        source_id="synthetic-source",
        ssh_alias="synthetic-host",
        allowed_roots=[ROOT],
        probe={"max_request_bytes": 1024, "max_paths": 100},
    )
    paths = [
        f"{ROOT}/{'nested-' + str(index) + '-' + 'x' * 180}/sample.fastq" for index in range(8)
    ]
    client = _RequestByteLimitedClient(source.probe.max_request_bytes)

    detected = _detect_all(client, source, ROOT, paths)  # type: ignore[arg-type]
    summaries, errors = _summarize_all(  # type: ignore[arg-type]
        client,
        source,
        ROOT,
        paths,
        10,
    )

    assert set(detected) == set(paths)
    assert set(summaries) == set(paths)
    assert not errors
    assert client.detect_calls > 1
    assert client.summary_calls > 1
