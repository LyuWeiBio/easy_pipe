"""Create-only, symlink-safe execution profile registry."""

from __future__ import annotations

import json
import os
import re
import stat
from contextlib import suppress
from pathlib import Path

from pydantic import ValidationError

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.execution.models import ExecutionProfile

_PROFILE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MAX_PROFILE_BYTES = 256 * 1024


class ExecutionProfileRegistry:
    """Store one immutable JSON profile per safe identifier."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory).expanduser().absolute()

    def register(self, profile: ExecutionProfile) -> Path:
        payload = profile.to_json().encode("utf-8")
        descriptor: int | None = None
        directory_descriptor: int | None = None
        name = self._name(profile.profile_id)
        try:
            if not 0 < len(payload) <= _MAX_PROFILE_BYTES:
                raise ValueError("execution profile exceeds its storage limit")
            directory_descriptor = self._open_directory(create=True)
            descriptor = os.open(
                name,
                os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=directory_descriptor,
            )
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            os.fsync(directory_descriptor)
            os.close(descriptor)
            descriptor = None
            return self.directory / name
        except (OSError, ValueError) as exc:
            if directory_descriptor is not None and descriptor is not None:
                with suppress(OSError):
                    os.unlink(name, dir_fd=directory_descriptor)
            raise _profile_error("register", profile.profile_id) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory_descriptor is not None:
                os.close(directory_descriptor)

    def load(self, profile_id: str) -> ExecutionProfile:
        name = self._name(profile_id)
        directory_descriptor: int | None = None
        descriptor: int | None = None
        try:
            directory_descriptor = self._open_directory()
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_descriptor,
            )
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or not 0 < metadata.st_size <= _MAX_PROFILE_BYTES:
                raise OSError("execution profile is not a bounded regular file")
            payload = _read_bounded(descriptor, _MAX_PROFILE_BYTES)
            data = json.loads(
                payload.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
            profile = ExecutionProfile.model_validate(data)
            if profile.profile_id != profile_id:
                raise ValueError("execution profile does not match its filename")
            return profile
        except (
            OSError,
            UnicodeError,
            ValidationError,
            ValueError,
            TypeError,
            RecursionError,
        ) as exc:
            raise _profile_error("load", profile_id) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory_descriptor is not None:
                os.close(directory_descriptor)

    def list(self) -> tuple[ExecutionProfile, ...]:
        try:
            descriptor = self._open_directory(missing_ok=True)
        except FileNotFoundError:
            return ()
        try:
            identifiers = sorted(
                name.removesuffix(".json")
                for name in os.listdir(descriptor)
                if name.endswith(".json") and _PROFILE_ID.fullmatch(name.removesuffix(".json"))
            )
        finally:
            os.close(descriptor)
        return tuple(self.load(identifier) for identifier in identifiers)

    def _name(self, profile_id: str) -> str:
        if not _PROFILE_ID.fullmatch(profile_id):
            raise _profile_error("identify", "<invalid>")
        return f"{profile_id}.json"

    def _open_directory(self, *, create: bool = False, missing_ok: bool = False) -> int:
        descriptor: int | None = None
        try:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            parts = self.directory.parts
            if not self.directory.is_absolute() or len(parts) < 2:
                raise OSError("execution profile directory is invalid")
            descriptor = os.open(parts[0], flags)
            for component in parts[1:]:
                try:
                    next_descriptor = os.open(component, flags, dir_fd=descriptor)
                except FileNotFoundError:
                    if not create:
                        raise
                    with suppress(FileExistsError):
                        os.mkdir(component, mode=0o700, dir_fd=descriptor)
                    next_descriptor = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            result = descriptor
            descriptor = None
            return result
        except FileNotFoundError as exc:
            if missing_ok:
                raise
            raise _profile_error("open", None) from exc
        except OSError as exc:
            raise _profile_error("open", None) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written < 1:
            raise OSError("execution profile write made no progress")
        remaining = remaining[written:]


def _read_bounded(descriptor: int, limit: int) -> bytes:
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
        raise OSError("execution profile exceeds its size limit")
    return payload


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _profile_error(operation: str, profile_id: str | None) -> BioPipeError:
    context = {"operation": operation}
    if profile_id is not None:
        context["profile_id"] = profile_id
    return BioPipeError(
        ErrorCode.EXECUTION_PROFILE_INVALID,
        "The execution profile is missing, unsafe, or invalid.",
        context=context,
        remediation=["Register a new validated execution profile and retry."],
    )


__all__ = ["ExecutionProfileRegistry"]
