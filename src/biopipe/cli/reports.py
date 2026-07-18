"""Controlled atomic report persistence for generated projects."""

from __future__ import annotations

import json
import os
import secrets
import stat
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any

from biopipe.errors import BioPipeError, ErrorCode

_REPORT_NAMES = frozenset({"validation.json", "test.json"})
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_TEMPORARY_ATTEMPTS = 16


def reportable_project_root(project_directory: str | Path) -> bool:
    """Return whether a report can safely be placed below the project root."""

    root = Path(project_directory).expanduser().absolute()
    descriptor: int | None = None
    try:
        descriptor, _metadata = _open_bound_directory(root)
    except (OSError, ValueError):
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return True


def write_project_report_atomic(
    project_directory: str | Path,
    report_name: str,
    payload: Mapping[str, Any],
) -> Path:
    """Atomically replace one allowlisted report and no other project artifact."""

    if report_name not in _REPORT_NAMES:
        raise ValueError("report name is not allowlisted")
    root = Path(project_directory).expanduser().absolute()
    root_descriptor: int | None = None
    reports_descriptor: int | None = None
    temporary_name: str | None = None
    try:
        serialized = (
            json.dumps(
                dict(payload),
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        root_descriptor, root_metadata = _open_bound_directory(root)
        reports_descriptor, reports_metadata = _open_reports_directory(
            root_descriptor,
            root,
            root_metadata,
        )
        _validate_destination(reports_descriptor, report_name)
        temporary_descriptor, temporary_name = _create_temporary_report(
            reports_descriptor,
            report_name,
        )
        with os.fdopen(temporary_descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())

        _assert_directory_binding(root, root_descriptor, root_metadata)
        _assert_child_binding(
            root_descriptor,
            "reports",
            reports_descriptor,
            reports_metadata,
        )
        _validate_destination(reports_descriptor, report_name)
        os.replace(
            temporary_name,
            report_name,
            src_dir_fd=reports_descriptor,
            dst_dir_fd=reports_descriptor,
        )
        temporary_name = None
        os.fsync(reports_descriptor)
        _assert_directory_binding(root, root_descriptor, root_metadata)
        _assert_child_binding(
            root_descriptor,
            "reports",
            reports_descriptor,
            reports_metadata,
        )
        return root / "reports" / report_name
    except BioPipeError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise _report_write_error() from exc
    finally:
        if temporary_name is not None and reports_descriptor is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=reports_descriptor)
        if reports_descriptor is not None:
            os.close(reports_descriptor)
        if root_descriptor is not None:
            os.close(root_descriptor)


def _open_bound_directory(path: Path) -> tuple[int, os.stat_result]:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise OSError("directory path is unsafe")
    descriptor = os.open(path, _DIRECTORY_FLAGS)
    try:
        opened = os.fstat(descriptor)
        if not _same_inode(before, opened) or not stat.S_ISDIR(opened.st_mode):
            raise OSError("directory path changed while opening")
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _open_reports_directory(
    root_descriptor: int,
    root: Path,
    root_metadata: os.stat_result,
) -> tuple[int, os.stat_result]:
    _assert_directory_binding(root, root_descriptor, root_metadata)
    try:
        before = os.stat("reports", dir_fd=root_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        os.mkdir("reports", mode=0o700, dir_fd=root_descriptor)
        os.fsync(root_descriptor)
        before = os.stat("reports", dir_fd=root_descriptor, follow_symlinks=False)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise OSError("reports path is unsafe")
    descriptor = os.open("reports", _DIRECTORY_FLAGS, dir_fd=root_descriptor)
    try:
        opened = os.fstat(descriptor)
        if not _same_inode(before, opened) or not stat.S_ISDIR(opened.st_mode):
            raise OSError("reports path changed while opening")
        _assert_directory_binding(root, root_descriptor, root_metadata)
        _assert_child_binding(root_descriptor, "reports", descriptor, opened)
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _create_temporary_report(directory_descriptor: int, report_name: str) -> tuple[int, str]:
    flags = (
        os.O_CREAT
        | os.O_EXCL
        | os.O_WRONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for _attempt in range(_TEMPORARY_ATTEMPTS):
        name = f".{report_name}.{secrets.token_hex(12)}.tmp"
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory_descriptor)
        except FileExistsError:
            continue
        try:
            os.fchmod(descriptor, 0o600)
        except BaseException:
            os.close(descriptor)
            with suppress(FileNotFoundError):
                os.unlink(name, dir_fd=directory_descriptor)
            raise
        return descriptor, name
    raise OSError("could not allocate a unique report temporary file")


def _validate_destination(directory_descriptor: int, report_name: str) -> None:
    try:
        metadata = os.stat(report_name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise OSError("report destination is unsafe")


def _assert_directory_binding(
    path: Path,
    descriptor: int,
    expected: os.stat_result,
) -> None:
    current = path.lstat()
    opened = os.fstat(descriptor)
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or not _same_inode(expected, opened)
        or not _same_inode(expected, current)
    ):
        raise OSError("directory path binding changed")


def _assert_child_binding(
    parent_descriptor: int,
    child_name: str,
    child_descriptor: int,
    expected: os.stat_result,
) -> None:
    current = os.stat(child_name, dir_fd=parent_descriptor, follow_symlinks=False)
    opened = os.fstat(child_descriptor)
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or not _same_inode(expected, opened)
        or not _same_inode(expected, current)
    ):
        raise OSError("child directory path binding changed")


def _same_inode(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _report_write_error() -> BioPipeError:
    return BioPipeError(
        ErrorCode.ARTIFACT_WRITE_FAILED,
        "The controlled project report could not be written safely.",
        remediation=[
            "Ensure the generated project and its reports directory are real writable directories."
        ],
    )


__all__ = ["reportable_project_root", "write_project_report_atomic"]
