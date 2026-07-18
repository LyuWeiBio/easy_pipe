"""Bounded no-follow hashing and canonical checksum manifests."""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Final

from biopipe.errors import BioPipeError, ErrorCode

_CHUNK_BYTES: Final[int] = 1024 * 1024
_MAX_ARTIFACT_BYTES: Final[int] = 512 * 1024 * 1024
_CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,127})$")

ARTIFACT_LOGICAL_NAMES: Final[dict[str, str]] = {
    "bioexec": "bioexec.pyz",
    "bioprobe": "bioprobe.pyz",
    "sdist": "easy-pipe-sdist.tar.gz",
    "source_archive": "easy-pipe-source.tar.gz",
    "wheel": "easy-pipe-wheel.whl",
}


def hash_release_artifact(path: str | Path, role: str) -> str:
    """Hash one fixed release-artifact role without following any symlink."""

    if role not in ARTIFACT_LOGICAL_NAMES:
        raise ValueError("unknown release artifact role")
    descriptor: int | None = None
    try:
        descriptor = _open_file_no_symlink(path)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > _MAX_ARTIFACT_BYTES
        ):
            raise OSError("unsafe release artifact")
        digest = hashlib.sha256()
        consumed = 0
        prefix = bytearray()
        while chunk := os.read(descriptor, _CHUNK_BYTES):
            consumed += len(chunk)
            if consumed > _MAX_ARTIFACT_BYTES:
                raise OSError("release artifact changed size")
            if len(prefix) < 64:
                prefix.extend(chunk[: 64 - len(prefix)])
            digest.update(chunk)
        after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if consumed != before.st_size or any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise OSError("release artifact changed while hashing")
        _validate_artifact_magic(role, bytes(prefix))
        return digest.hexdigest()
    except (OSError, ValueError) as exc:
        raise BioPipeError(
            ErrorCode.ARTIFACT_READ_FAILED,
            "A required release artifact is missing, unsafe, or unstable.",
            context={"artifact_role": role},
            remediation=["Provide a bounded regular artifact through a non-symlink path."],
        ) from exc
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)


def render_checksum_manifest(entries: Mapping[str, str]) -> bytes:
    """Render sorted sha256sum-compatible bytes for safe logical names."""

    normalized: list[tuple[str, str]] = []
    for name, digest in entries.items():
        if _CHECKSUM_LINE.fullmatch(f"{digest}  {name}") is None:
            raise ValueError("checksum entry is not canonical")
        normalized.append((name, digest))
    if len({name for name, _digest in normalized}) != len(normalized):
        raise ValueError("checksum entries contain duplicate names")
    return "".join(f"{digest}  {name}\n" for name, digest in sorted(normalized)).encode("ascii")


def parse_checksum_manifest(
    payload: bytes,
    *,
    expected_names: frozenset[str],
) -> dict[str, str]:
    """Parse a canonical manifest and require exactly *expected_names*."""

    try:
        text = payload.decode("ascii")
    except UnicodeError as exc:
        raise ValueError("checksum manifest is not ASCII") from exc
    if not text or "\r" in text or not text.endswith("\n"):
        raise ValueError("checksum manifest has non-canonical newlines")
    parsed: dict[str, str] = {}
    lines = text.splitlines()
    for line in lines:
        match = _CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise ValueError("checksum manifest contains an invalid line")
        digest, name = match.groups()
        if name in parsed:
            raise ValueError("checksum manifest contains a duplicate name")
        parsed[name] = digest
    if lines != [f"{parsed[name]}  {name}" for name in sorted(parsed)]:
        raise ValueError("checksum manifest is not sorted")
    if frozenset(parsed) != expected_names:
        raise ValueError("checksum manifest file set does not match")
    return parsed


def checksum_payloads(payloads: Mapping[str, bytes]) -> bytes:
    """Collect canonical checksums for already bounded in-memory evidence."""

    return render_checksum_manifest(
        {name: hashlib.sha256(payload).hexdigest() for name, payload in payloads.items()}
    )


def read_bounded_regular(path: str | Path, *, role: str, limit_bytes: int) -> bytes:
    """Read one small trusted-role input through the same no-symlink traversal."""

    if not role or not 0 < limit_bytes <= 16 * 1024 * 1024:
        raise ValueError("bounded resource parameters are invalid")
    descriptor: int | None = None
    try:
        descriptor = _open_file_no_symlink(path)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit_bytes:
            raise OSError("unsafe bounded resource")
        payload = bytearray()
        while chunk := os.read(descriptor, min(_CHUNK_BYTES, limit_bytes + 1 - len(payload))):
            payload.extend(chunk)
            if len(payload) > limit_bytes:
                raise OSError("bounded resource exceeds limit")
        after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(payload) != before.st_size or any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise OSError("bounded resource changed while reading")
        return bytes(payload)
    except (OSError, ValueError) as exc:
        raise BioPipeError(
            ErrorCode.ARTIFACT_READ_FAILED,
            "A required release-evidence resource is missing, unsafe, or unstable.",
            context={"resource_role": role},
            remediation=["Restore the reviewed regular resource and retry."],
        ) from exc
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)


def _validate_artifact_magic(role: str, prefix: bytes) -> None:
    if role in {"source_archive", "sdist"}:
        valid = prefix.startswith(b"\x1f\x8b")
    elif role == "wheel":
        valid = prefix.startswith(b"PK\x03\x04")
    else:
        valid = prefix.startswith(b"#!/usr/bin/env python3\n") and b"PK\x03\x04" in prefix
    if not valid:
        raise ValueError("release artifact does not match its fixed role")


def _open_file_no_symlink(path: str | Path) -> int:
    raw = os.fspath(path)
    if not raw or "\x00" in raw:
        raise ValueError("invalid artifact path")
    original = Path(raw)
    if any(part == ".." for part in original.parts):
        raise ValueError("parent traversal is not allowed")
    absolute = Path(os.path.abspath(raw))
    parts = absolute.parts
    if not parts or not absolute.is_absolute() or absolute.name in {"", ".", ".."}:
        raise ValueError("artifact path must select a file")

    directory_descriptor = os.open(
        parts[0],
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        for component in parts[1:-1]:
            next_descriptor = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_descriptor,
            )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        return os.open(
            parts[-1],
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_descriptor,
        )
    finally:
        os.close(directory_descriptor)


__all__ = [
    "ARTIFACT_LOGICAL_NAMES",
    "checksum_payloads",
    "hash_release_artifact",
    "parse_checksum_manifest",
    "read_bounded_regular",
    "render_checksum_manifest",
]
