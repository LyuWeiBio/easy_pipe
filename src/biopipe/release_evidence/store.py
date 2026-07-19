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
from biopipe.release_evidence.filesystem import (
    FileIdentity,
    require_directory_outside_identities,
    require_no_extended_acl,
)

_MAX_FILE_BYTES: Final[int] = 4 * 1024 * 1024
_MAX_BUNDLE_BYTES: Final[int] = 16 * 1024 * 1024
_MAX_FILES: Final[int] = 64
_RENAME_NOREPLACE: Final[int] = 1
_RENAME_EXCL: Final[int] = 4


class EvidenceBundleStore:
    """Publish one complete private evidence directory without replacement."""

    def __init__(
        self,
        output_directory: str | Path,
        *,
        forbidden_directory_identities: frozenset[FileIdentity] = frozenset(),
    ) -> None:
        self.output_directory = Path(output_directory).absolute()
        self._forbidden_directory_identities = forbidden_directory_identities

    def create(self, artifacts: Mapping[str, bytes]) -> tuple[str, ...]:
        rendered = self._validate_artifacts(artifacts)
        parent = self.output_directory.parent
        final_name = self.output_directory.name
        parent_descriptor: int | None = None
        stage_descriptor: int | None = None
        stage_name: str | None = None
        stage_identity: FileIdentity | None = None
        published = False
        completed = False
        created_files: dict[str, FileIdentity] = {}
        try:
            parent_descriptor = self._open_private_directory(
                parent,
                forbidden_directory_identities=self._forbidden_directory_identities,
            )
            self._reject_existing(parent_descriptor, final_name)
            for _attempt in range(16):
                candidate = f".{final_name}.biopipe-{secrets.token_hex(8)}"
                try:
                    os.mkdir(candidate, mode=0o700, dir_fd=parent_descriptor)
                except FileExistsError:
                    continue
                stage_name = candidate
                metadata = os.stat(candidate, dir_fd=parent_descriptor, follow_symlinks=False)
                stage_identity = metadata.st_dev, metadata.st_ino
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
            os.fchmod(stage_descriptor, 0o700)
            self._require_private_directory(stage_descriptor, owner_only=True)
            require_directory_outside_identities(
                stage_descriptor,
                self._forbidden_directory_identities,
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
                created_files[name] = self._descriptor_identity(descriptor)
                try:
                    os.fchmod(descriptor, 0o600)
                    remaining = memoryview(payload)
                    while remaining:
                        written = os.write(descriptor, remaining)
                        if written == 0:
                            raise OSError(errno.EIO, "evidence write made no progress")
                        remaining = remaining[written:]
                    os.fsync(descriptor)
                    self._require_private_regular(descriptor)
                finally:
                    os.close(descriptor)
            os.fsync(stage_descriptor)
            self._require_created_files(stage_descriptor, created_files)
            self._require_private_directory(parent_descriptor, owner_only=False)
            require_directory_outside_identities(
                parent_descriptor,
                self._forbidden_directory_identities,
            )
            self._reject_existing(parent_descriptor, final_name)
            self._rename_exclusive(parent_descriptor, stage_name, final_name)
            stage_name = None
            published = True
            os.fsync(parent_descriptor)
            self._require_private_directory(stage_descriptor, owner_only=True)
            self._require_created_files(stage_descriptor, created_files)
            require_directory_outside_identities(
                stage_descriptor,
                self._forbidden_directory_identities,
            )
            self._require_private_directory(parent_descriptor, owner_only=False)
            require_directory_outside_identities(
                parent_descriptor,
                self._forbidden_directory_identities,
            )
            completed = True
            return tuple(name for name, _payload in rendered)
        except BioPipeError:
            raise
        except OSError as exc:
            raise self._write_error(exc.errno) from None
        finally:
            if stage_descriptor is not None:
                if not completed:
                    for name, identity in reversed(created_files.items()):
                        self._unlink_if_identity(stage_descriptor, name, identity)
                if stage_name is not None and parent_descriptor is not None:
                    self._rmdir_if_descriptor(parent_descriptor, stage_name, stage_descriptor)
                if published and not completed and parent_descriptor is not None:
                    self._rmdir_if_descriptor(parent_descriptor, final_name, stage_descriptor)
                os.close(stage_descriptor)
            elif (
                stage_name is not None
                and stage_identity is not None
                and parent_descriptor is not None
            ):
                self._rmdir_if_identity(parent_descriptor, stage_name, stage_identity)
            if parent_descriptor is not None:
                os.close(parent_descriptor)

    @staticmethod
    def create_file(
        output_file: str | Path,
        payload: bytes,
        *,
        forbidden_directory_identities: frozenset[FileIdentity] = frozenset(),
    ) -> Path:
        """Atomically create one private file through a bound parent directory."""

        destination = Path(output_file).absolute()
        if not EvidenceBundleStore._safe_name(destination.name):
            raise EvidenceBundleStore._write_error(errno.EINVAL)
        if not payload or len(payload) > _MAX_FILE_BYTES:
            raise EvidenceBundleStore._write_error(errno.EFBIG)
        parent_descriptor: int | None = None
        descriptor: int | None = None
        temporary_name: str | None = None
        published = False
        completed = False
        try:
            parent_descriptor = EvidenceBundleStore._open_private_directory(
                destination.parent,
                forbidden_directory_identities=forbidden_directory_identities,
            )
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
            os.fchmod(descriptor, 0o600)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written == 0:
                    raise OSError(errno.EIO, "evidence write made no progress")
                remaining = remaining[written:]
            os.fsync(descriptor)
            EvidenceBundleStore._require_private_regular(descriptor)
            EvidenceBundleStore._require_private_directory(parent_descriptor, owner_only=False)
            require_directory_outside_identities(
                parent_descriptor,
                forbidden_directory_identities,
            )
            os.link(
                temporary_name,
                destination.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            published = True
            os.unlink(temporary_name, dir_fd=parent_descriptor)
            temporary_name = None
            EvidenceBundleStore._require_private_regular(descriptor)
            os.fsync(parent_descriptor)
            EvidenceBundleStore._require_private_directory(parent_descriptor, owner_only=False)
            require_directory_outside_identities(
                parent_descriptor,
                forbidden_directory_identities,
            )
            completed = True
            return destination
        except BioPipeError:
            raise
        except OSError as exc:
            raise EvidenceBundleStore._write_error(exc.errno) from None
        finally:
            if (
                temporary_name is not None
                and parent_descriptor is not None
                and descriptor is not None
            ):
                EvidenceBundleStore._unlink_if_descriptor(
                    parent_descriptor,
                    temporary_name,
                    descriptor,
                )
            if (
                published
                and not completed
                and parent_descriptor is not None
                and descriptor is not None
            ):
                EvidenceBundleStore._unlink_if_descriptor(
                    parent_descriptor,
                    destination.name,
                    descriptor,
                )
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
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
    def _open_private_directory(
        directory: Path,
        *,
        forbidden_directory_identities: frozenset[FileIdentity] = frozenset(),
    ) -> int:
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
            EvidenceBundleStore._require_private_directory(descriptor, owner_only=False)
            require_directory_outside_identities(descriptor, forbidden_directory_identities)
            result = descriptor
            descriptor = -1
            return result
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _require_private_directory(descriptor: int, *, owner_only: bool) -> None:
        metadata = os.fstat(descriptor)
        disallowed_mode = 0o077 if owner_only else 0o022
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & disallowed_mode:
            raise OSError(errno.EACCES, "output parent must be a private directory")
        require_no_extended_acl(descriptor)

    @staticmethod
    def _require_private_regular(descriptor: int) -> None:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_nlink != 1:
            raise OSError(errno.EACCES, "output file must remain private and single-link")
        require_no_extended_acl(descriptor)

    @staticmethod
    def _require_created_files(
        directory_descriptor: int,
        created_files: Mapping[str, FileIdentity],
    ) -> None:
        if frozenset(os.listdir(directory_descriptor)) != frozenset(created_files):
            raise OSError(errno.EIO, "published evidence file set changed")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        for name, expected_identity in created_files.items():
            descriptor = os.open(name, flags, dir_fd=directory_descriptor)
            try:
                if EvidenceBundleStore._descriptor_identity(descriptor) != expected_identity:
                    raise OSError(errno.EIO, "published evidence file identity changed")
                EvidenceBundleStore._require_private_regular(descriptor)
            finally:
                os.close(descriptor)

    @staticmethod
    def _descriptor_identity(descriptor: int) -> FileIdentity:
        metadata = os.fstat(descriptor)
        return metadata.st_dev, metadata.st_ino

    @staticmethod
    def _unlink_if_identity(
        parent_descriptor: int,
        name: str,
        expected_identity: FileIdentity,
    ) -> None:
        try:
            metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (metadata.st_dev, metadata.st_ino) == expected_identity:
                os.unlink(name, dir_fd=parent_descriptor)
        except OSError:
            pass

    @staticmethod
    def _unlink_if_descriptor(parent_descriptor: int, name: str, descriptor: int) -> None:
        try:
            identity = EvidenceBundleStore._descriptor_identity(descriptor)
        except OSError:
            return
        EvidenceBundleStore._unlink_if_identity(parent_descriptor, name, identity)

    @staticmethod
    def _rmdir_if_descriptor(parent_descriptor: int, name: str, descriptor: int) -> None:
        try:
            expected = EvidenceBundleStore._descriptor_identity(descriptor)
        except OSError:
            return
        EvidenceBundleStore._rmdir_if_identity(parent_descriptor, name, expected)

    @staticmethod
    def _rmdir_if_identity(
        parent_descriptor: int,
        name: str,
        expected_identity: FileIdentity,
    ) -> None:
        try:
            metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if (
                stat.S_ISDIR(metadata.st_mode)
                and (
                    metadata.st_dev,
                    metadata.st_ino,
                )
                == expected_identity
            ):
                os.rmdir(name, dir_fd=parent_descriptor)
        except OSError:
            pass

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
