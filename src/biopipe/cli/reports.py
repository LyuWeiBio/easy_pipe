"""Controlled atomic report persistence for generated projects."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any

from biopipe.errors import BioPipeError, ErrorCode

_REPORT_NAMES = frozenset({"validation.json", "test.json"})


def reportable_project_root(project_directory: str | Path) -> bool:
    """Return whether a report can safely be placed below the project root."""

    root = Path(project_directory).expanduser().absolute()
    try:
        metadata = root.lstat()
    except OSError:
        return False
    return not stat.S_ISLNK(metadata.st_mode) and stat.S_ISDIR(metadata.st_mode)


def write_project_report_atomic(
    project_directory: str | Path,
    report_name: str,
    payload: Mapping[str, Any],
) -> Path:
    """Atomically replace one allowlisted report and no other project artifact."""

    if report_name not in _REPORT_NAMES:
        raise ValueError("report name is not allowlisted")
    root = Path(project_directory).expanduser().absolute()
    if not reportable_project_root(root):
        raise _report_write_error()

    reports_directory = root / "reports"
    try:
        if os.path.lexists(reports_directory):
            metadata = reports_directory.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise _report_write_error()
        else:
            reports_directory.mkdir(mode=0o700)

        destination = reports_directory / report_name
        if os.path.lexists(destination):
            metadata = destination.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise _report_write_error()

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
        temporary_path: Path | None = None
        try:
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=f".{report_name}.",
                suffix=".tmp",
                dir=reports_directory,
                text=True,
            )
            temporary_path = Path(temporary_name)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, destination)
            temporary_path = None
            _sync_directory(reports_directory)
        finally:
            if temporary_path is not None:
                with suppress(FileNotFoundError):
                    temporary_path.unlink()
        return destination
    except BioPipeError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise _report_write_error() from exc


def _sync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _report_write_error() -> BioPipeError:
    return BioPipeError(
        ErrorCode.ARTIFACT_WRITE_FAILED,
        "The controlled project report could not be written safely.",
        remediation=[
            "Ensure the generated project and its reports directory are real writable directories."
        ],
    )


__all__ = ["reportable_project_root", "write_project_report_atomic"]
