"""Shared path-relationship helpers for the controller package.

There must be exactly one implementation of each predicate — do not fork
copies into ``compiler.py``, ``validator.py``, ``models.py``,
``scheduler_models.py`` or ``fastq_qc.py`` again.
"""

from __future__ import annotations

from pathlib import PurePosixPath

__all__ = ["paths_overlap"]


def paths_overlap(first: str, second: str) -> bool:
    """Return True when two POSIX paths are equal or one contains the other."""
    first_path = PurePosixPath(first)
    second_path = PurePosixPath(second)
    return (
        first_path == second_path
        or first_path in second_path.parents
        or second_path in first_path.parents
    )
