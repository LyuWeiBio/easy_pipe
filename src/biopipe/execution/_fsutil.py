"""Shared low-level filesystem traversal primitives for the execution subsystem.

These helpers are security-sensitive: they implement symlink-safe path
traversal (``O_NOFOLLOW`` component-by-component open) and bounded reads.
There must be exactly one implementation of each — do not fork copies into
``gate.py``, ``signing.py``, ``profiles.py``, ``preflight.py`` or
``runner.py`` again.

All functions raise :class:`OSError` on any unsafe condition; callers
translate that into their domain error type.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath

__all__ = [
    "below_any",
    "open_without_symlinks",
    "read_bounded",
]


def open_without_symlinks(path: Path) -> int:
    """Open a file by walking each path component with ``O_NOFOLLOW``.

    Rejects non-absolute paths and ``..`` components (a ``..`` can never be
    part of a legitimate pinned path), requires ``O_NOFOLLOW`` support, and
    opens every component — including intermediate directories — without
    following symlinks.  Returns an open read-only file descriptor for the
    final component; the caller owns it.

    Raises :class:`OSError` if the path is invalid, the platform cannot open
    files without following symlinks, or any component is a symlink.
    """
    absolute = path.expanduser().absolute()
    parts = absolute.parts
    if not absolute.is_absolute() or ".." in parts or len(parts) < 2:
        raise OSError("path is invalid")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if not getattr(os, "O_NOFOLLOW", 0):
        raise OSError("platform cannot safely open files without following symlinks")
    directory = os.open(parts[0], directory_flags)
    try:
        for component in parts[1:-1]:
            next_directory = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        return os.open(
            parts[-1],
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW,
            dir_fd=directory,
        )
    finally:
        os.close(directory)


def read_bounded(descriptor: int, limit: int) -> bytes:
    """Read at most ``limit`` bytes from an open descriptor.

    Reads one byte past the limit to detect over-long input without trusting
    the pre-read size.  Raises :class:`OSError` when the payload exceeds
    ``limit``.  An empty payload is allowed — callers that need a non-empty
    payload check that themselves.
    """
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    payload = b"".join(chunks)
    if len(payload) > limit:
        raise OSError("payload exceeds its read limit")
    return payload


def read_bounded_regular_file(path: Path, limit: int, *, allow_empty: bool = False) -> bytes:
    """Open ``path`` without following symlinks and read at most ``limit`` bytes.

    The file must be a bounded regular file.  Raises :class:`OSError` when it
    is not, when the payload exceeds ``limit``, or — unless ``allow_empty``
    is set — when the payload is empty.
    """
    descriptor: int | None = None
    try:
        descriptor = open_without_symlinks(path)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= limit:
            raise OSError("path is not a bounded regular file")
        payload = read_bounded(descriptor, limit)
        if not allow_empty and not payload:
            raise OSError("path is empty")
        return payload
    finally:
        if descriptor is not None:
            os.close(descriptor)


def below_any(value: str, roots: tuple[str, ...]) -> bool:
    """Return True when ``value`` is strictly below one of ``roots``.

    "Strictly below" is deliberate: a path equal to a root itself is not
    below it, and every call site (artifact placement, deployment
    directories, configured paths) needs a genuine descendant, never the
    root directory itself.
    """
    candidate = PurePosixPath(value)
    return any(PurePosixPath(root) in candidate.parents for root in roots)
