"""Descriptor-anchored create-only publication for evidence records."""

from __future__ import annotations

import ctypes
import errno
import os
import secrets
import stat
import sys
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Final

from biopipe.errors import BioPipeError, ErrorCode

_MAX_FILE_BYTES: Final[int] = 4 * 1024 * 1024
_MAX_BUNDLE_BYTES: Final[int] = 16 * 1024 * 1024
_MAX_FILES: Final[int] = 64
_RENAME_NOREPLACE: Final[int] = 1
_RENAME_EXCL: Final[int] = 4


class EvidenceBundleStore:
    """Publish one complete private evidence directory without replacement."""

    def __init__(self, output_directory: str | Path) -> None:
        self.output_directory = Path(output_directory).absolute()

    def create(self, artifacts: Mapping[str, bytes]) -> tuple[str, ...]:
        rendered = self._validate_artifacts(artifacts)
        parent = self.output_directory.parent
        final_name = self.output_directory.name
        parent_descriptor: int | None = None
        stage_descriptor: int | None = None
        stage_name: str | None = None
        created_names: list[str] = []
        try:
            parent_descriptor = self._open_private_directory(parent)
            self._reject_existing(parent_descriptor, final_name)
            for _attempt in range(16):
                candidate = f".{final_name}.biopipe-{secrets.token_hex(8)}"
                try:
                    os.mkdir(candidate, mode=0o700, dir_fd=parent_descriptor)
                except FileExistsError:
                    continue
                stage_name = candidate
                break
            if stage_name is None:
                raise OSError(errno.EEXIST, "could not allocate staging directory")
            stage_descriptor = os.open(
                stage_name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            for name, payload in rendered:
                descriptor = os.open(
                    name,
                    os.O_CREAT
                    | os.O_EXCL
                    | os.O_WRONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=stage_descriptor,
                )
                created_names.append(name)
                try:
                    remaining = memoryview(payload)
                    while remaining:
                        written = os.write(descriptor, remaining)
                        if written == 0:
                            raise OSError(errno.EIO, "evidence write made no progress")
                        remaining = remaining[written:]
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            os.fsync(stage_descriptor)
            self._reject_existing(parent_descriptor, final_name)
            self._rename_exclusive(parent_descriptor, stage_name, final_name)
            stage_name = None
            os.fsync(parent_descriptor)
            return tuple(name for name, _payload in rendered)
        except BioPipeError:
            raise
        except OSError as exc:
            raise self._write_error(exc.errno) from exc
        finally:
            if stage_descriptor is not None:
                if stage_name is not None:
                    for name in reversed(created_names):
                        with suppress(OSError):
                            os.unlink(name, dir_fd=stage_descriptor)
                os.close(stage_descriptor)
            if stage_name is not None and parent_descriptor is not None:
                with suppress(OSError):
                    os.rmdir(stage_name, dir_fd=parent_descriptor)
            if parent_descriptor is not None:
                os.close(parent_descriptor)

    @staticmethod
    def create_file(output_file: str | Path, payload: bytes) -> Path:
        """Atomically create one private file through a bound parent directory."""

        destination = Path(output_file).absolute()
        if not EvidenceBundleStore._safe_name(destination.name):
            raise EvidenceBundleStore._write_error(errno.EINVAL)
        if not payload or len(payload) > _MAX_FILE_BYTES:
            raise EvidenceBundleStore._write_error(errno.EFBIG)
        parent_descriptor: int | None = None
        temporary_name: str | None = None
        try:
            parent_descriptor = EvidenceBundleStore._open_private_directory(destination.parent)
            EvidenceBundleStore._reject_existing(parent_descriptor, destination.name)
            temporary_name = f".{destination.name}.biopipe-{secrets.token_hex(8)}"
            descriptor = os.open(
                temporary_name,
                os.O_CREAT
                | os.O_EXCL
                | os.O_WRONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=parent_descriptor,
            )
            try:
                remaining = memoryview(payload)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written == 0:
                        raise OSError(errno.EIO, "evidence write made no progress")
                    remaining = remaining[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.link(
                temporary_name,
                destination.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            os.unlink(temporary_name, dir_fd=parent_descriptor)
            temporary_name = None
            os.fsync(parent_descriptor)
            return destination
        except BioPipeError:
            raise
        except OSError as exc:
            raise EvidenceBundleStore._write_error(exc.errno) from exc
        finally:
            if temporary_name is not None and parent_descriptor is not None:
                with suppress(OSError):
                    os.unlink(temporary_name, dir_fd=parent_descriptor)
            if parent_descriptor is not None:
                os.close(parent_descriptor)

    @staticmethod
    def _validate_artifacts(artifacts: Mapping[str, bytes]) -> list[tuple[str, bytes]]:
        if not artifacts or len(artifacts) > _MAX_FILES:
            raise EvidenceBundleStore._write_error(errno.EINVAL)
        rendered: list[tuple[str, bytes]] = []
        total = 0
        for name, payload in sorted(artifacts.items()):
            if not EvidenceBundleStore._safe_name(name) or not isinstance(payload, bytes):
                raise EvidenceBundleStore._write_error(errno.EINVAL)
            if not payload or len(payload) > _MAX_FILE_BYTES:
                raise EvidenceBundleStore._write_error(errno.EFBIG)
            total += len(payload)
            rendered.append((name, payload))
        if total > _MAX_BUNDLE_BYTES:
            raise EvidenceBundleStore._write_error(errno.EFBIG)
        return rendered

    @staticmethod
    def _safe_name(name: str) -> bool:
        return (
            0 < len(name) <= 128
            and name not in {".", ".."}
            and not name.startswith((".", "-"))
            and "/" not in name
            and "\\" not in name
            and all(32 <= ord(character) < 127 for character in name)
        )

    @staticmethod
    def _open_private_directory(directory: Path) -> int:
        """Open every directory component without following symlinks."""

        absolute = Path(os.path.abspath(os.fspath(directory)))
        parts = absolute.parts
        if not parts or not absolute.is_absolute():
            raise OSError(errno.EINVAL, "output parent must be absolute")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(parts[0], flags)
        try:
            for component in parts[1:]:
                next_descriptor = os.open(
                    component,
                    flags,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
                raise OSError(errno.EACCES, "output parent must be a private directory")
            result = descriptor
            descriptor = -1
            return result
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _reject_existing(parent_descriptor: int, name: str) -> None:
        if not EvidenceBundleStore._safe_name(name):
            raise EvidenceBundleStore._write_error(errno.EINVAL)
        try:
            os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise EvidenceBundleStore._write_error(errno.EEXIST)

    @staticmethod
    def _rename_exclusive(parent_descriptor: int, source: str, destination: str) -> None:
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform.startswith("linux"):
            function = getattr(library, "renameat2", None)
            arguments: tuple[object, ...] = (
                parent_descriptor,
                os.fsencode(source),
                parent_descriptor,
                os.fsencode(destination),
                _RENAME_NOREPLACE,
            )
        elif sys.platform == "darwin":
            function = getattr(library, "renameatx_np", None)
            arguments = (
                parent_descriptor,
                os.fsencode(source),
                parent_descriptor,
                os.fsencode(destination),
                _RENAME_EXCL,
            )
        else:
            function = None
            arguments = ()
        if function is None:
            raise OSError(errno.ENOTSUP, "exclusive rename is unavailable")
        function.restype = ctypes.c_int
        if function(*arguments) != 0:
            error_number = ctypes.get_errno() or errno.EIO
            raise OSError(error_number, os.strerror(error_number))

    @staticmethod
    def _write_error(error_number: int | None) -> BioPipeError:
        context: dict[str, int] = {}
        if error_number is not None:
            context["errno"] = error_number
        return BioPipeError(
            ErrorCode.ARTIFACT_WRITE_FAILED,
            "Release evidence could not be published create-only and atomically.",
            context=context,
            remediation=[
                "Use a new destination beneath an existing non-symlink directory that is not "
                "group- or world-writable."
            ],
        )


__all__ = ["EvidenceBundleStore"]
