"""Authenticated controller attestations for fixed run mutations."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path, PurePath
from typing import Any, Literal

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution.models import ExecutionProfile

_HEX_KEY = re.compile(rb"[0-9a-f]{64}\n?")
_MAX_KEY_BYTES = 65


def sign_run_payload(
    profile: ExecutionProfile,
    operation: Literal["submit", "resume", "abandon"],
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Return a copied request payload carrying one exact HMAC attestation.

    The remote agent verifies the same canonical envelope before reading or
    mutating any preflight, deployment, or run state.  This makes the trusted
    controller key—not client-supplied success fields—the remote approval
    boundary.
    """

    approval_value = payload.get("approval")
    if not isinstance(approval_value, dict) or "signature" in approval_value:
        raise _signing_error(profile.approval_signer.key_id)
    approval = dict(approval_value)
    approval["key_id"] = profile.approval_signer.key_id
    unsigned = {**payload, "approval": approval}
    key = _read_key(Path(profile.approval_signer.key_file), profile.approval_signer.key_id)
    signature = hmac.new(
        key,
        canonical_attestation_bytes(operation, unsigned),
        hashlib.sha256,
    ).hexdigest()
    return {**unsigned, "approval": {**approval, "signature": signature}}


def canonical_attestation_bytes(
    operation: Literal["submit", "resume", "abandon"], payload: dict[str, Any]
) -> bytes:
    """Serialize the versioned envelope shared with the dependency-free agent."""

    try:
        return json.dumps(
            {
                "protocol_version": "1.0",
                "operation": operation,
                "payload": payload,
            },
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise BioPipeError(
            ErrorCode.APPROVAL_REQUIRED,
            "The authenticated run authorization could not be serialized.",
        ) from exc


def validate_approval_key(profile: ExecutionProfile) -> None:
    """Fail closed while registering a profile whose local signer is unsafe."""

    _read_key(Path(profile.approval_signer.key_file), profile.approval_signer.key_id)


def _read_key(path: Path, key_id: str) -> bytes:
    descriptor: int | None = None
    try:
        descriptor = _open_without_symlinks(path)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid not in {0, os.geteuid()}
            or metadata.st_mode & 0o077
            or not 0 < metadata.st_size <= _MAX_KEY_BYTES
        ):
            raise OSError("approval key is not a private bounded regular file")
        chunks: list[bytes] = []
        remaining = _MAX_KEY_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if not _HEX_KEY.fullmatch(raw):
            raise OSError("approval key does not contain one lowercase 32-byte key")
        return bytes.fromhex(raw.rstrip(b"\n").decode("ascii"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise _signing_error(key_id) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _open_without_symlinks(path: Path) -> int:
    absolute = path.expanduser().absolute()
    pure = PurePath(absolute)
    if not pure.is_absolute() or ".." in pure.parts or len(pure.parts) < 2:
        raise OSError("approval key path is invalid")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if not getattr(os, "O_NOFOLLOW", 0):
        raise OSError("platform cannot safely open approval keys")
    directory = os.open(os.path.sep, directory_flags)
    try:
        for component in pure.parts[1:-1]:
            next_directory = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        return os.open(
            pure.parts[-1],
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory,
        )
    finally:
        os.close(directory)


def _signing_error(key_id: str) -> BioPipeError:
    return BioPipeError(
        ErrorCode.APPROVAL_REQUIRED,
        "The controller approval signing key is missing, unsafe, or invalid.",
        context={"key_id": key_id},
        remediation=["Install the reviewed private approval key with owner-only permissions."],
    )


__all__ = ["canonical_attestation_bytes", "sign_run_payload", "validate_approval_key"]
