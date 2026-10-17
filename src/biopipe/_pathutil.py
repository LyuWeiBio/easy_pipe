"""Shared path-relationship helpers for the controller package.

There must be exactly one implementation of each predicate — do not fork
copies into ``compiler.py``, ``validator.py``, ``models.py``,
``scheduler_models.py`` or ``fastq_qc.py`` again.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath

__all__ = ["ensure_private_directory", "paths_overlap"]


def paths_overlap(first: str, second: str) -> bool:
    """Return True when two POSIX paths are equal or one contains the other."""
    first_path = PurePosixPath(first)
    second_path = PurePosixPath(second)
    return (
        first_path == second_path
        or first_path in second_path.parents
        or second_path in first_path.parents
    )


def ensure_private_directory(path: Path, *, mode: int = 0o700) -> None:
    """Create ``path`` (and missing parents) with ``mode`` guaranteed on the leaf.

    ``Path.mkdir(mode=..., parents=True)`` applies ``mode`` only to the final
    component — and even that is masked by the process umask. This helper
    creates the full chain but only ever tightens the leaf it was asked for:
    pre-existing parents keep their permissions (they belong to the
    operator), while the leaf is explicitly chmod'ed so the umask cannot
    leave it more permissive than requested.
    """

    path.mkdir(mode=mode, parents=True, exist_ok=True)
    if stat.S_IMODE(path.lstat().st_mode) != mode:
        os.chmod(path, mode)
