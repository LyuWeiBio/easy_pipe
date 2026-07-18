"""Descriptor-bound durable agent state records."""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .config import ConfiguredRoot
from .errors import AgentFailure, ReturnCode

_KINDS = frozenset({"preflights", "deployments", "runs"})
_MAX_RECORD_BYTES = 4 * 1024 * 1024
_ISOLATION_DIRECTORIES = (
    "client-home",
    "docker-config",
    "apptainer-config",
    "nxf-home",
    "tmp",
)
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


class StateStore:
    """Create, read, and replace only agent-owned bounded JSON records."""

    def __init__(self, root: ConfiguredRoot) -> None:
        self._root = root

    def create(self, kind: str, identifier: str, payload: dict[str, Any]) -> None:
        data = _serialize(payload)
        with self._open_kind(kind) as directory:
            name = f"{identifier}.json"
            flags = (
                os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                descriptor = os.open(name, flags, 0o600, dir_fd=directory)
            except FileExistsError as exc:
                raise AgentFailure(
                    ReturnCode.STATE_CONFLICT,
                    "STATE_ALREADY_EXISTS",
                    "an agent state identifier already exists",
                ) from exc
            try:
                _write_all(descriptor, data)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(directory)

    def read(self, kind: str, identifier: str) -> dict[str, Any]:
        with self._open_kind(kind) as directory:
            name = f"{identifier}.json"
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(name, flags, dir_fd=directory)
            except FileNotFoundError as exc:
                raise AgentFailure(
                    ReturnCode.PATH_UNAVAILABLE,
                    "STATE_NOT_FOUND",
                    "the requested agent state record does not exist",
                ) from exc
            try:
                metadata = os.fstat(descriptor)
                current = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_ISLNK(current.st_mode)
                    or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
                    or not 0 < metadata.st_size <= _MAX_RECORD_BYTES
                ):
                    raise _state_invalid()
                raw = _read_bounded(descriptor, _MAX_RECORD_BYTES + 1)
            finally:
                os.close(descriptor)
        if len(raw) > _MAX_RECORD_BYTES:
            raise _state_invalid()
        try:
            value = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            raise _state_invalid() from exc
        if not isinstance(value, dict):
            raise _state_invalid()
        return value

    def replace(self, kind: str, identifier: str, payload: dict[str, Any]) -> None:
        data = _serialize(payload)
        with self._open_kind(kind) as directory:
            destination = f"{identifier}.json"
            try:
                current = os.stat(destination, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise AgentFailure(
                    ReturnCode.PATH_UNAVAILABLE,
                    "STATE_NOT_FOUND",
                    "the requested agent state record does not exist",
                ) from exc
            if stat.S_ISLNK(current.st_mode) or not stat.S_ISREG(current.st_mode):
                raise _state_invalid()
            temporary = f".{identifier}.{secrets.token_hex(12)}.tmp"
            flags = (
                os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
            try:
                _write_all(descriptor, data)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                os.replace(temporary, destination, src_dir_fd=directory, dst_dir_fd=directory)
                os.fsync(directory)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=directory)

    def claim(self, kind: str, identifier: str, claim: str) -> None:
        """Create an irreversible exclusive marker for a one-shot transition."""

        if not claim or any(character not in "abcdefghijklmnopqrstuvwxyz-" for character in claim):
            raise ValueError("invalid state claim")
        with self._open_kind(kind) as directory:
            name = f"{identifier}.{claim}"
            flags = (
                os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                descriptor = os.open(name, flags, 0o600, dir_fd=directory)
            except FileExistsError as exc:
                raise AgentFailure(
                    ReturnCode.STATE_CONFLICT,
                    "STATE_ALREADY_CLAIMED",
                    "the one-shot state transition was already consumed",
                ) from exc
            try:
                _write_all(descriptor, b"claimed\n")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(directory)

    def create_run_directory(self, identifier: str) -> Path:
        """Create one private direct child used only for immutable overlay and logs."""

        root = self._open_root()
        run_files = -1
        try:
            try:
                os.mkdir("run-files", 0o700, dir_fd=root)
                os.fsync(root)
            except FileExistsError:
                pass
            run_files = os.open("run-files", _DIRECTORY_FLAGS, dir_fd=root)
            current = os.stat("run-files", dir_fd=root, follow_symlinks=False)
            opened = os.fstat(run_files)
            if (
                stat.S_ISLNK(current.st_mode)
                or not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid not in {0, os.geteuid()}
                or stat.S_IMODE(opened.st_mode) != 0o700
                or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
            ):
                raise _state_invalid()
            try:
                os.mkdir(identifier, 0o700, dir_fd=run_files)
            except FileExistsError as exc:
                raise AgentFailure(
                    ReturnCode.STATE_CONFLICT,
                    "RUN_FILES_ALREADY_EXIST",
                    "run state files already exist",
                ) from exc
            os.fsync(run_files)
            return self._root.path / "run-files" / identifier
        finally:
            if run_files >= 0:
                os.close(run_files)
            os.close(root)

    def create_preflight_isolation(self, identifier: str) -> dict[str, Path]:
        """Create one private empty client environment for a preflight request."""

        root = self._open_root()
        category = -1
        request = -1
        try:
            category = self._open_or_create_private_directory(root, "preflight-files")
            try:
                os.mkdir(identifier, 0o700, dir_fd=category)
            except FileExistsError as exc:
                raise AgentFailure(
                    ReturnCode.STATE_CONFLICT,
                    "PREFLIGHT_FILES_ALREADY_EXIST",
                    "preflight client isolation files already exist",
                ) from exc
            request = self._open_private_directory(category, identifier)
            self._create_isolation_children(request)
            os.fsync(category)
            base = self._root.path / "preflight-files" / identifier
            return {name: base / name for name in _ISOLATION_DIRECTORIES}
        finally:
            if request >= 0:
                os.close(request)
            if category >= 0:
                os.close(category)
            os.close(root)

    def create_run_isolation(self, identifier: str) -> dict[str, Path]:
        """Create one private empty client environment inside a run directory."""

        with self._open_run_directory(identifier) as directory:
            self._create_isolation_children(directory)
        base = self._root.path / "run-files" / identifier
        return {name: base / name for name in _ISOLATION_DIRECTORIES}

    def _create_isolation_children(self, parent: int) -> None:
        for name in _ISOLATION_DIRECTORIES:
            try:
                os.mkdir(name, 0o700, dir_fd=parent)
            except FileExistsError as exc:
                raise AgentFailure(
                    ReturnCode.STATE_CONFLICT,
                    "CLIENT_ISOLATION_ALREADY_EXISTS",
                    "private client isolation directories already exist",
                ) from exc
            child = self._open_private_directory(parent, name)
            try:
                with os.scandir(child) as entries:
                    if next(entries, None) is not None:
                        raise _state_invalid()
                os.fsync(child)
            finally:
                os.close(child)
        os.fsync(parent)

    def _open_or_create_private_directory(self, parent: int, name: str) -> int:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
        return self._open_private_directory(parent, name)

    def _open_private_directory(self, parent: int, name: str) -> int:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent)
        metadata = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(current.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid not in {0, os.geteuid()}
            or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
        ):
            os.close(descriptor)
            raise _state_invalid()
        return descriptor

    def create_supervisor_lease(self, identifier: str) -> None:
        """Create the no-follow 0600 lease inode before launching a supervisor."""

        with self._open_run_directory(identifier) as directory:
            flags = (
                os.O_CREAT
                | os.O_EXCL
                | os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                descriptor = os.open("supervisor.lock", flags, 0o600, dir_fd=directory)
            except FileExistsError as exc:
                raise AgentFailure(
                    ReturnCode.STATE_CONFLICT,
                    "SUPERVISOR_LEASE_ALREADY_EXISTS",
                    "the run supervisor lease already exists",
                ) from exc
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                    raise _state_invalid()
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(directory)

    def acquire_supervisor_lease(self, identifier: str) -> int:
        """Lock and return the inheritable job-lifetime lease descriptor.

        Callers must only close their own descriptor copy.  They must never
        explicitly unlock it because forked supervisor and job processes share
        the same open-file-description.
        """

        import fcntl

        descriptor = self._open_supervisor_lease_fd(identifier)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    @contextlib.contextmanager
    def hold_supervisor_lease(self, identifier: str) -> Iterator[int]:
        """Hold a lease locally, releasing it only by closing the descriptor."""

        descriptor = self.acquire_supervisor_lease(identifier)
        try:
            yield descriptor
        finally:
            os.close(descriptor)

    @contextlib.contextmanager
    def try_supervisor_recovery_lease(self, identifier: str) -> Iterator[bool]:
        """Try to exclude a live supervisor while status recovers stale state."""

        import fcntl

        try:
            descriptor = self._open_supervisor_lease_fd(identifier)
        except AgentFailure as failure:
            if failure.code != "SUPERVISOR_LEASE_NOT_FOUND":
                raise
            yield True
            return
        acquired = False
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except BlockingIOError:
                pass
            yield acquired
        finally:
            os.close(descriptor)

    def _open_supervisor_lease_fd(self, identifier: str) -> int:
        with self._open_run_directory(identifier) as directory:
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open("supervisor.lock", flags, dir_fd=directory)
            except FileNotFoundError as exc:
                raise _lease_not_found() from exc
            metadata = os.fstat(descriptor)
            current = os.stat(
                "supervisor.lock",
                dir_fd=directory,
                follow_symlinks=False,
            )
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid not in {0, os.geteuid()}
                or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
            ):
                os.close(descriptor)
                raise _state_invalid()
            return descriptor

    @contextlib.contextmanager
    def _open_run_directory(self, identifier: str) -> Iterator[int]:
        root = self._open_root()
        run_files = -1
        directory = -1
        try:
            try:
                run_files = os.open("run-files", _DIRECTORY_FLAGS, dir_fd=root)
                run_files_metadata = os.fstat(run_files)
                run_files_current = os.stat("run-files", dir_fd=root, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(run_files_metadata.st_mode)
                    or stat.S_ISLNK(run_files_current.st_mode)
                    or stat.S_IMODE(run_files_metadata.st_mode) != 0o700
                    or run_files_metadata.st_uid not in {0, os.geteuid()}
                    or (run_files_metadata.st_dev, run_files_metadata.st_ino)
                    != (run_files_current.st_dev, run_files_current.st_ino)
                ):
                    raise _state_invalid()
                directory = os.open(identifier, _DIRECTORY_FLAGS, dir_fd=run_files)
            except FileNotFoundError as exc:
                raise _lease_not_found() from exc
            metadata = os.fstat(directory)
            current = os.stat(identifier, dir_fd=run_files, follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_uid not in {0, os.geteuid()}
                or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
            ):
                raise _state_invalid()
            yield directory
        finally:
            if directory >= 0:
                os.close(directory)
            if run_files >= 0:
                os.close(run_files)
            os.close(root)

    @contextlib.contextmanager
    def _open_kind(self, kind: str) -> Iterator[int]:
        if kind not in _KINDS:
            raise ValueError("unknown state record kind")
        root = self._open_root()
        directory = -1
        try:
            try:
                os.mkdir(kind, mode=0o700, dir_fd=root)
                os.fsync(root)
            except FileExistsError:
                pass
            directory = os.open(kind, _DIRECTORY_FLAGS, dir_fd=root)
            metadata = os.fstat(directory)
            current = os.stat(kind, dir_fd=root, follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_uid not in {0, os.geteuid()}
                or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
            ):
                raise _state_invalid()
            yield directory
        finally:
            if directory >= 0:
                os.close(directory)
            os.close(root)

    def _open_root(self) -> int:
        try:
            descriptor = os.open(self._root.path, _DIRECTORY_FLAGS)
            metadata = os.fstat(descriptor)
        except OSError as exc:
            raise _state_invalid() from exc
        if (metadata.st_dev, metadata.st_ino) != (self._root.device, self._root.inode):
            os.close(descriptor)
            raise _state_invalid()
        if metadata.st_uid not in {0, os.geteuid()} or stat.S_IMODE(metadata.st_mode) & 0o077:
            os.close(descriptor)
            raise _state_invalid()
        return descriptor


def _serialize(value: dict[str, Any]) -> bytes:
    try:
        data = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise _state_invalid() from exc
    if not 0 < len(data) <= _MAX_RECORD_BYTES:
        raise _state_invalid()
    return data


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written < 1:
            raise OSError("state write made no progress")
        remaining = remaining[written:]


def _read_bounded(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate state key")
        result[key] = value
    return result


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite state number is forbidden: {value}")


def _state_invalid() -> AgentFailure:
    return AgentFailure(
        ReturnCode.INTERNAL_ERROR,
        "STATE_INVALID",
        "agent state is missing, unsafe, or internally inconsistent",
    )


def _lease_not_found() -> AgentFailure:
    return AgentFailure(
        ReturnCode.PATH_UNAVAILABLE,
        "SUPERVISOR_LEASE_NOT_FOUND",
        "the run supervisor lease does not exist",
    )


__all__ = ["StateStore"]
