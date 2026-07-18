"""Hash helpers for immutable and auditable project artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path

from biopipe.errors import BioPipeError, ErrorCode

_CHUNK_SIZE = 1024 * 1024


def sha256_file(path: str | Path) -> str:
    """Return the hexadecimal SHA-256 digest of *path* using bounded memory."""

    source = Path(path)
    digest = hashlib.sha256()
    try:
        with source.open("rb") as stream:
            for chunk in iter(lambda: stream.read(_CHUNK_SIZE), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError as exc:
        raise BioPipeError(
            ErrorCode.ARTIFACT_READ_FAILED,
            "Could not hash the artifact.",
            context={"path": str(source)},
        ) from exc


__all__ = ["sha256_file"]
