"""Append-only audit logging for controller events."""

from __future__ import annotations

import fcntl
import json
import os
import stat
from contextlib import suppress
from datetime import datetime
from pathlib import Path, PurePath
from typing import Any

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.models import AuditEvent

_MAX_EVENT_BYTES = 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024


class AuditWriter:
    """Append one complete JSON event per line without truncating prior history."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, event: AuditEvent) -> None:
        """Append and fsync *event*; existing bytes are never rewritten."""
        self._append(event, once=False)

    def append_once(self, event: AuditEvent) -> bool:
        """Atomically append *event* unless its deterministic ID already exists."""

        return self._append(event, once=True)

    def _append(self, event: AuditEvent, *, once: bool) -> bool:
        directory_descriptor: int | None = None
        descriptor: int | None = None
        appended = False
        try:
            path = self.path.expanduser().absolute()
            if not path.name or path.name in {".", ".."}:
                raise OSError("audit filename is unsafe")
            directory_descriptor = _open_directory_chain(path.parent)
            descriptor = _open_audit_file(directory_descriptor, path.name)
            try:
                opened = os.fstat(descriptor)
                current = os.stat(
                    path.name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or stat.S_ISLNK(current.st_mode)
                    or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                ):
                    raise OSError("audit destination is unsafe")
                os.fchmod(descriptor, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                size = os.fstat(descriptor).st_size
                if not once or not _contains_event(descriptor, size, event):
                    previous_timestamp = _last_timestamp(descriptor, size)
                    selected = (
                        event
                        if previous_timestamp is None or event.timestamp >= previous_timestamp
                        else event.model_copy(update={"timestamp": previous_timestamp})
                    )
                    payload = _serialize_event(selected)
                    remaining = memoryview(payload)
                    while remaining:
                        written = os.write(descriptor, remaining)
                        if written == 0:
                            raise OSError("audit append made no progress")
                        remaining = remaining[written:]
                    os.fsync(descriptor)
                    appended = True
            finally:
                with suppress(OSError):
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            current = os.stat(
                path.name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise OSError("audit destination changed while appending")
            os.fsync(directory_descriptor)
        except (OSError, TypeError, ValueError) as exc:
            raise BioPipeError(
                ErrorCode.AUDIT_WRITE_FAILED,
                "Could not append the audit event.",
                context={"path": str(self.path)},
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory_descriptor is not None:
                os.close(directory_descriptor)
        return appended


def _serialize_event(event: AuditEvent) -> bytes:
    payload = (
        json.dumps(
            event.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")
    if len(payload) > _MAX_EVENT_BYTES:
        raise OSError("audit event exceeds its fixed size limit")
    return payload


def _open_audit_file(directory_descriptor: int, name: str) -> int:
    """Open an audit file, using exclusive creation to serialize first writers."""

    flags = os.O_APPEND | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(name, flags, dir_fd=directory_descriptor)
    except FileNotFoundError:
        try:
            return os.open(
                name,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_descriptor,
            )
        except FileExistsError:
            return os.open(name, flags, dir_fd=directory_descriptor)


def _last_timestamp(descriptor: int, size: int) -> datetime | None:
    """Read only the final bounded event while holding the append lock."""

    if size == 0:
        return None
    window = min(size, _MAX_EVENT_BYTES + 1)
    offset = size - window
    try:
        tail = os.pread(descriptor, window, offset)
        if len(tail) != window or not tail.endswith(b"\n"):
            raise ValueError("audit history has an incomplete final event")
        body = tail[:-1]
        if offset and b"\n" not in body:
            raise ValueError("final audit event exceeds its fixed size limit")
        last_line = body.rsplit(b"\n", maxsplit=1)[-1]
        if not last_line:
            raise ValueError("audit history contains an empty final event")
        value = json.loads(
            last_line.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
        return AuditEvent.model_validate(value).timestamp
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise OSError("audit history cannot be extended safely") from exc


def _contains_event(descriptor: int, size: int, expected: AuditEvent) -> bool:
    """Strictly scan history and reject deterministic-ID semantic collisions."""

    offset = 0
    pending = bytearray()
    match_count = 0
    try:
        while offset < size:
            chunk = os.pread(descriptor, min(_READ_CHUNK_BYTES, size - offset), offset)
            if not chunk:
                raise ValueError("audit history ended before its recorded size")
            offset += len(chunk)
            pending.extend(chunk)
            while True:
                newline = pending.find(b"\n")
                if newline < 0:
                    if len(pending) > _MAX_EVENT_BYTES:
                        raise ValueError("audit event exceeds its fixed size limit")
                    break
                line = bytes(pending[:newline])
                del pending[: newline + 1]
                if not line or len(line) + 1 > _MAX_EVENT_BYTES:
                    raise ValueError("audit history contains an invalid event boundary")
                value = json.loads(
                    line.decode("utf-8"),
                    object_pairs_hook=_unique_json_object,
                    parse_constant=_reject_json_constant,
                )
                existing = AuditEvent.model_validate(value)
                if existing.event_id == expected.event_id:
                    if not _same_event_semantics(existing, expected):
                        raise ValueError("audit event ID collides with different semantics")
                    match_count += 1
        if pending:
            raise ValueError("audit history has an incomplete final event")
        if match_count > 1:
            raise ValueError("audit history contains duplicate deterministic event IDs")
        return match_count == 1
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise OSError("audit history cannot be deduplicated safely") from exc


def _same_event_semantics(first: AuditEvent, second: AuditEvent) -> bool:
    return first.model_dump(mode="json", exclude={"timestamp"}) == second.model_dump(
        mode="json",
        exclude={"timestamp"},
    )


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate audit key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite audit number is forbidden: {value}")


def _open_directory_chain(path: Path) -> int:
    """Open/create an absolute directory one no-follow component at a time."""

    pure = PurePath(path)
    if not pure.is_absolute() or ".." in pure.parts:
        raise OSError("audit parent must be an absolute path")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(os.path.sep, flags)
    try:
        for part in pure.parts[1:]:
            if not part or part in {".", ".."}:
                raise OSError("audit parent contains an unsafe component")
            try:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                with suppress(FileExistsError):
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


__all__ = ["AuditWriter"]
