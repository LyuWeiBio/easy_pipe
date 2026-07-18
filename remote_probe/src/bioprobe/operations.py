"""Fixed, metadata-only probe operations."""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import PROTOCOL_VERSION, __version__
from .config import ProbeConfig
from .errors import ProbeFailure, ReturnCode
from .fastq import (
    FastqBudgetExceeded,
    FastqContentBudget,
    FastqFormatError,
    detect_compression,
    is_fastq_extension_candidate,
    sample_fastq,
)
from .paths import OpenedDirectory, PathGuard
from .protocol import (
    ProbeRequest,
    encode_json,
    encode_response_line,
    response_success,
)


@dataclass(frozen=True, slots=True)
class EffectiveBudgets:
    """Server ceilings intersected with optional request reductions."""

    max_depth: int
    max_entries: int
    max_runtime_seconds: float

    def to_dict(self) -> dict[str, int | float]:
        return {
            "max_depth": self.max_depth,
            "max_entries": self.max_entries,
            "max_runtime_seconds": self.max_runtime_seconds,
        }


class Deadline:
    """Monotonic elapsed-time budget checked throughout traversal."""

    def __init__(self, seconds: float, *, clock: Callable[[], float] | None = None) -> None:
        self._clock = time.monotonic if clock is None else clock
        self._expires_at = self._clock() + seconds

    def check(self) -> None:
        if self._clock() >= self._expires_at:
            raise ProbeFailure(
                ReturnCode.TIMEOUT,
                "SCAN_TIMEOUT",
                "operation exceeded max_runtime_seconds",
            )


def effective_budgets(request: ProbeRequest, config: ProbeConfig) -> EffectiveBudgets:
    """Compute limits a client can lower but never raise."""

    policy = request.policy
    return EffectiveBudgets(
        max_depth=min(
            config.limits.max_depth if policy.max_depth is None else policy.max_depth,
            config.limits.max_depth,
        ),
        max_entries=min(
            config.limits.max_entries if policy.max_entries is None else policy.max_entries,
            config.limits.max_entries,
        ),
        max_runtime_seconds=min(
            config.limits.max_runtime_seconds
            if policy.max_runtime_seconds is None
            else policy.max_runtime_seconds,
            config.limits.max_runtime_seconds,
        ),
    )


def health(request: ProbeRequest, config: ProbeConfig) -> dict[str, Any]:
    """Report non-sensitive capability and active limit information."""

    budgets = effective_budgets(request, config)
    return {
        "operation": "health",
        "status": "ok",
        "probe_version": __version__,
        "protocol_version": PROTOCOL_VERSION,
        "capabilities": [
            "detect_formats",
            "health",
            "list_tree",
            "stat_files",
            "summarize_fastq",
        ],
        "configuration": {
            "configured": bool(config.allowed_roots),
            "config_source": config.source,
            "allowed_root_count": len(config.allowed_roots),
            "follow_symlinks": False,
            "allow_mount_crossing": config.allow_mount_crossing,
            "limits": {
                **budgets.to_dict(),
                "max_request_bytes": config.limits.max_request_bytes,
                "max_response_bytes": config.limits.max_response_bytes,
                "max_paths": config.limits.max_paths,
                "max_path_bytes": config.limits.max_path_bytes,
                "max_sample_records_total": config.limits.max_sample_records_total,
                "max_content_bytes": config.limits.max_content_bytes,
                "max_input_bytes": config.limits.max_input_bytes,
                "max_fastq_line_bytes": config.limits.max_fastq_line_bytes,
            },
        },
    }


def list_tree(request: ProbeRequest, config: ProbeConfig) -> dict[str, Any]:
    """Traverse one allowlisted directory through bounded descriptor operations."""

    if request.policy.follow_symlinks:
        raise _symlink_policy_failure()
    budgets = effective_budgets(request, config)
    deadline = Deadline(budgets.max_runtime_seconds)
    deadline.check()
    guard = PathGuard(config)
    assert request.root is not None

    entries: list[dict[str, Any]] = []
    serialized_entry_bytes = 0
    max_depth_observed = 0
    with guard.open_directory(request.root) as root:
        deadline.check()
        initial = _tree_result(
            root.path,
            [],
            entry_count=0,
            max_depth_observed=0,
            budgets=budgets,
        )
        _ensure_collection_response_budget(
            request.request_id,
            initial,
            serialized_items_bytes=0,
            item_count=0,
            config=config,
        )

        def scan_directory(current: OpenedDirectory, current_depth: int) -> None:
            nonlocal serialized_entry_bytes, max_depth_observed
            deadline.check()
            try:
                with os.scandir(current.fd) as iterator:
                    for entry in iterator:
                        deadline.check()
                        depth = current_depth + 1
                        if depth > budgets.max_depth:
                            raise _budget_failure("max_depth", budgets.max_depth)
                        if len(entries) >= budgets.max_entries:
                            raise _budget_failure("max_entries", budgets.max_entries)

                        child_stat = guard.stat_child(current, entry.name)
                        child_directory: OpenedDirectory | None = None
                        if stat.S_ISDIR(child_stat.stat_result.st_mode):
                            child_directory = guard.open_child_directory(current, entry.name)
                            item_stat = child_directory.stat_result
                            item_path = child_directory.path
                        else:
                            item_stat = child_stat.stat_result
                            item_path = child_stat.path

                        try:
                            metadata = _metadata(
                                item_path,
                                item_stat,
                                root=root.path,
                                depth=depth,
                            )
                            item_size = len(encode_json(metadata))
                            projected_count = len(entries) + 1
                            projected_depth = max(max_depth_observed, depth)
                            projected = _tree_result(
                                root.path,
                                [],
                                entry_count=projected_count,
                                max_depth_observed=projected_depth,
                                budgets=budgets,
                            )
                            _ensure_collection_response_budget(
                                request.request_id,
                                projected,
                                serialized_items_bytes=(serialized_entry_bytes + item_size),
                                item_count=projected_count,
                                config=config,
                            )
                            entries.append(metadata)
                            serialized_entry_bytes += item_size
                            max_depth_observed = projected_depth

                            if child_directory is not None:
                                scan_directory(child_directory, depth)
                        finally:
                            if child_directory is not None:
                                child_directory.close()
            except ProbeFailure:
                raise
            except OSError as exc:
                raise _unavailable_failure() from exc

        scan_directory(root, 0)
        deadline.check()

    return _tree_result(
        root.path,
        entries,
        entry_count=len(entries),
        max_depth_observed=max_depth_observed,
        budgets=budgets,
    )


def stat_files(request: ProbeRequest, config: ProbeConfig) -> dict[str, Any]:
    """Return metadata for an explicit bounded list using fstat/fstatat."""

    if request.policy.follow_symlinks:
        raise _symlink_policy_failure()
    budgets = effective_budgets(request, config)
    deadline = Deadline(budgets.max_runtime_seconds)
    deadline.check()
    if len(request.paths) > config.limits.max_paths:
        raise _budget_failure("max_paths", config.limits.max_paths)
    if len(request.paths) > budgets.max_entries:
        raise _budget_failure("max_entries", budgets.max_entries)

    guard = PathGuard(config)
    results: list[dict[str, Any]] = []
    serialized_item_bytes = 0
    with ExitStack() as stack:
        root: OpenedDirectory | None = None
        if request.root is not None:
            root = stack.enter_context(guard.open_directory(request.root))
        root_value = None if root is None else str(root.path)
        initial = _stat_result(
            root_value,
            [],
            file_count=0,
            budgets=budgets,
        )
        _ensure_collection_response_budget(
            request.request_id,
            initial,
            serialized_items_bytes=0,
            item_count=0,
            config=config,
        )

        for value in request.paths:
            deadline.check()
            authorized = guard.stat_path(value, base=root)
            relative_root = (
                root.path if root is not None else authorized.authorized.allowed_root.canonical
            )
            depth = len(authorized.path.relative_to(relative_root).parts)
            metadata = _metadata(
                authorized.path,
                authorized.stat_result,
                root=relative_root,
                depth=depth,
            )
            item_size = len(encode_json(metadata))
            projected_count = len(results) + 1
            projected = _stat_result(
                root_value,
                [],
                file_count=projected_count,
                budgets=budgets,
            )
            _ensure_collection_response_budget(
                request.request_id,
                projected,
                serialized_items_bytes=serialized_item_bytes + item_size,
                item_count=projected_count,
                config=config,
            )
            results.append(metadata)
            serialized_item_bytes += item_size
        deadline.check()

    return _stat_result(
        root_value,
        results,
        file_count=len(results),
        budgets=budgets,
    )


def detect_formats(request: ProbeRequest, config: ProbeConfig) -> dict[str, Any]:
    """Classify explicit files from gzip magic and one bounded FASTQ record."""

    budgets, deadline, content_budget = _content_budgets(request, config)
    guard = PathGuard(config)
    assert request.root is not None
    files: list[dict[str, Any]] = []
    serialized_item_bytes = 0

    with guard.open_directory(request.root) as root:
        initial = _content_result(
            "detect_formats",
            root.path,
            [],
            file_count=0,
            budgets=budgets,
        )
        _ensure_collection_response_budget(
            request.request_id,
            initial,
            serialized_items_bytes=0,
            item_count=0,
            config=config,
        )
        for value in request.paths:
            deadline.check()
            try:
                with guard.open_file(value, base=root) as opened:
                    try:
                        compression = detect_compression(
                            opened.fd,
                            deadline,
                            content_budget,
                        )
                        sample_fastq(
                            opened.fd,
                            compression,
                            1,
                            deadline,
                            content_budget,
                            config.limits.max_fastq_line_bytes,
                        )
                    except FastqBudgetExceeded as exc:
                        raise _budget_failure(exc.budget, exc.limit) from exc
                    except FastqFormatError:
                        detected_format = "unknown"
                    else:
                        detected_format = "fastq"
                    item = {
                        "path": str(opened.path),
                        "format": detected_format,
                        "compression": compression,
                        "extension_candidate": is_fastq_extension_candidate(opened.path),
                    }
            except OSError as exc:
                raise _unavailable_failure() from exc
            serialized_item_bytes = _append_bounded_content_item(
                request,
                config,
                budgets,
                root.path,
                "detect_formats",
                files,
                item,
                serialized_item_bytes,
            )
        deadline.check()

    return _content_result(
        "detect_formats",
        root.path,
        files,
        file_count=len(files),
        budgets=budgets,
    )


def summarize_fastq(request: ProbeRequest, config: ProbeConfig) -> dict[str, Any]:
    """Return aggregate facts from a bounded sample of explicit FASTQ files."""

    budgets, deadline, content_budget = _content_budgets(request, config)
    guard = PathGuard(config)
    assert request.root is not None
    files: list[dict[str, Any]] = []
    serialized_item_bytes = 0

    with guard.open_directory(request.root) as root:
        initial = _content_result(
            "summarize_fastq",
            root.path,
            [],
            file_count=0,
            budgets=budgets,
        )
        _ensure_collection_response_budget(
            request.request_id,
            initial,
            serialized_items_bytes=0,
            item_count=0,
            config=config,
        )
        for path_index, value in enumerate(request.paths):
            deadline.check()
            try:
                with guard.open_file(value, base=root) as opened:
                    try:
                        compression = detect_compression(
                            opened.fd,
                            deadline,
                            content_budget,
                        )
                        aggregate = sample_fastq(
                            opened.fd,
                            compression,
                            request.policy.sample_fastq_records,
                            deadline,
                            content_budget,
                            config.limits.max_fastq_line_bytes,
                        )
                    except FastqBudgetExceeded as exc:
                        raise _budget_failure(exc.budget, exc.limit) from exc
                    except FastqFormatError as exc:
                        if exc.recognized_fastq or is_fastq_extension_candidate(opened.path):
                            raise _invalid_fastq_failure(path_index) from exc
                        raise _unsupported_format_failure(path_index) from exc
                    item = aggregate.to_result(opened.path, compression)
            except ProbeFailure:
                raise
            except OSError as exc:
                raise _unavailable_failure() from exc
            serialized_item_bytes = _append_bounded_content_item(
                request,
                config,
                budgets,
                root.path,
                "summarize_fastq",
                files,
                item,
                serialized_item_bytes,
            )
        deadline.check()

    return _content_result(
        "summarize_fastq",
        root.path,
        files,
        file_count=len(files),
        budgets=budgets,
    )


def _content_budgets(
    request: ProbeRequest,
    config: ProbeConfig,
) -> tuple[EffectiveBudgets, Deadline, FastqContentBudget]:
    if request.policy.follow_symlinks:
        raise _symlink_policy_failure()
    budgets = effective_budgets(request, config)
    if len(request.paths) > config.limits.max_paths:
        raise _budget_failure("max_paths", config.limits.max_paths)
    if len(request.paths) > budgets.max_entries:
        raise _budget_failure("max_entries", budgets.max_entries)
    deadline = Deadline(budgets.max_runtime_seconds)
    deadline.check()
    content_budget = FastqContentBudget(
        max_sample_records_total=config.limits.max_sample_records_total,
        max_content_bytes=config.limits.max_content_bytes,
        max_input_bytes=config.limits.max_input_bytes,
    )
    return budgets, deadline, content_budget


def _append_bounded_content_item(
    request: ProbeRequest,
    config: ProbeConfig,
    budgets: EffectiveBudgets,
    root: Path,
    operation: str,
    files: list[dict[str, Any]],
    item: dict[str, Any],
    serialized_item_bytes: int,
) -> int:
    item_size = len(encode_json(item))
    projected_count = len(files) + 1
    projected = _content_result(
        operation,
        root,
        [],
        file_count=projected_count,
        budgets=budgets,
    )
    projected_bytes = serialized_item_bytes + item_size
    _ensure_collection_response_budget(
        request.request_id,
        projected,
        serialized_items_bytes=projected_bytes,
        item_count=projected_count,
        config=config,
    )
    files.append(item)
    return projected_bytes


def _content_result(
    operation: str,
    root: Path,
    files: list[dict[str, Any]],
    *,
    file_count: int,
    budgets: EffectiveBudgets,
) -> dict[str, Any]:
    return {
        "operation": operation,
        "root": str(root),
        "files": files,
        "file_count": file_count,
        "budgets": budgets.to_dict(),
    }


def _tree_result(
    root: Path,
    entries: list[dict[str, Any]],
    *,
    entry_count: int,
    max_depth_observed: int,
    budgets: EffectiveBudgets,
) -> dict[str, Any]:
    return {
        "operation": "list_tree",
        "root": str(root),
        "entries": entries,
        "entry_count": entry_count,
        "max_depth_observed": max_depth_observed,
        "budgets": budgets.to_dict(),
    }


def _stat_result(
    root: str | None,
    files: list[dict[str, Any]],
    *,
    file_count: int,
    budgets: EffectiveBudgets,
) -> dict[str, Any]:
    return {
        "operation": "stat_files",
        "root": root,
        "files": files,
        "file_count": file_count,
        "budgets": budgets.to_dict(),
    }


def _ensure_collection_response_budget(
    request_id: str,
    result_with_empty_collection: dict[str, Any],
    *,
    serialized_items_bytes: int,
    item_count: int,
    config: ProbeConfig,
) -> None:
    empty_size = len(
        encode_response_line(response_success(request_id, result_with_empty_collection))
    )
    comma_bytes = max(0, item_count - 1)
    projected_size = empty_size + serialized_items_bytes + comma_bytes
    if projected_size > config.limits.max_response_bytes:
        raise ProbeFailure(
            ReturnCode.BUDGET_EXCEEDED,
            "RESPONSE_BUDGET_EXCEEDED",
            "response exceeds max_response_bytes",
            context={"max_response_bytes": config.limits.max_response_bytes},
        )


def _metadata(path: Path, item_stat: os.stat_result, *, root: Path, depth: int) -> dict[str, Any]:
    if stat.S_ISREG(item_stat.st_mode):
        kind = "file"
    elif stat.S_ISDIR(item_stat.st_mode):
        kind = "directory"
    else:
        kind = "other"
    relative = path.relative_to(root)
    return {
        "path": str(path),
        "relative_path": str(relative),
        "name": path.name,
        "kind": kind,
        "size_bytes": item_stat.st_size,
        "mtime_ns": item_stat.st_mtime_ns,
        "mode": f"{stat.S_IMODE(item_stat.st_mode):04o}",
        "depth": depth,
    }


def _budget_failure(name: str, limit: int) -> ProbeFailure:
    return ProbeFailure(
        ReturnCode.BUDGET_EXCEEDED,
        "SCAN_BUDGET_EXCEEDED",
        "operation exceeded a configured scan budget",
        context={"budget": name, "limit": limit},
    )


def _symlink_policy_failure() -> ProbeFailure:
    return ProbeFailure(
        ReturnCode.SYMLINK_OR_ESCAPE,
        "SYMLINK_FORBIDDEN",
        "M2 does not permit following symlinks",
    )


def _unavailable_failure(
    message: str = "path does not exist or cannot be read",
) -> ProbeFailure:
    return ProbeFailure(ReturnCode.PATH_UNAVAILABLE, "PATH_UNAVAILABLE", message)


def _unsupported_format_failure(path_index: int) -> ProbeFailure:
    return ProbeFailure(
        ReturnCode.UNSUPPORTED_FORMAT,
        "UNSUPPORTED_FORMAT",
        "requested file is not a supported FASTQ stream",
        context={"path_index": path_index},
    )


def _invalid_fastq_failure(path_index: int) -> ProbeFailure:
    return ProbeFailure(
        ReturnCode.INVALID_FASTQ,
        "INVALID_FASTQ",
        "sampled FASTQ content has invalid or truncated four-line structure",
        context={"path_index": path_index},
    )


__all__ = [
    "Deadline",
    "EffectiveBudgets",
    "detect_formats",
    "effective_budgets",
    "health",
    "list_tree",
    "stat_files",
    "summarize_fastq",
]
