"""Create-only publication for a complete generated project bundle."""

from __future__ import annotations

import ctypes
import errno
import os
import sys
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Final

from biopipe.errors import BioPipeError, ErrorCode

_MAX_FILE_BYTES: Final[int] = 16 * 1024 * 1024
_MAX_BUNDLE_BYTES: Final[int] = 64 * 1024 * 1024
_AT_FDCWD: Final[int] = -100
_RENAME_NOREPLACE: Final[int] = 1
_RENAME_EXCL: Final[int] = 4


class ProjectBundleStore:
    """Publish a generated project as one atomic, create-only directory.

    Every file is rendered and fsynced in a private sibling directory first.  A
    platform no-replace rename then exposes the entire tree in one operation.  If
    the controller platform cannot provide that primitive, publication fails
    closed instead of exposing a partial tree or risking replacement.
    """

    def __init__(self, output_directory: str | Path) -> None:
        self.output_directory = Path(output_directory).expanduser()

    def create(self, artifacts: Mapping[str, bytes]) -> tuple[str, ...]:
        """Atomically create all *artifacts* without replacing any destination."""

        rendered = self._validate_artifacts(artifacts)
        self._validate_output_directory()
        parent = self.output_directory.parent
        staged_root: Path | None = None
        active_path = "<bundle>"
        try:
            parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._reject_existing_destination()
            staged_root = Path(
                tempfile.mkdtemp(
                    dir=parent,
                    prefix=f".{self.output_directory.name}.biopipe-",
                )
            )
            os.chmod(staged_root, 0o700)
            self._stage(staged_root, rendered)
            self._rename_exclusive(staged_root, self.output_directory)
            staged_root = None
            self._fsync_directory_safely(parent)
            return tuple(relative for relative, _payload in rendered)
        except BioPipeError:
            raise
        except OSError as exc:
            raise self._error(active_path, exc.errno) from exc
        finally:
            if staged_root is not None:
                self._remove_staging_tree(staged_root)

    def _validate_output_directory(self) -> None:
        value = os.fspath(self.output_directory)
        if not self.output_directory.name or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise self._error("<bundle>", errno.EINVAL)

    def _reject_existing_destination(self) -> None:
        try:
            self.output_directory.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise self._error("<bundle>", exc.errno) from exc
        raise self._error("<bundle>", errno.EEXIST)

    @staticmethod
    def _validate_artifacts(artifacts: Mapping[str, bytes]) -> list[tuple[str, bytes]]:
        if not artifacts:
            raise BioPipeError(
                ErrorCode.ARTIFACT_WRITE_FAILED,
                "A generated project bundle must contain at least one artifact.",
            )
        rendered: list[tuple[str, bytes]] = []
        total_bytes = 0
        for relative, payload in sorted(artifacts.items()):
            path = PurePosixPath(relative)
            if (
                not relative
                or path.is_absolute()
                or relative != path.as_posix()
                or any(part in {"", ".", ".."} for part in path.parts)
                or any(ord(character) < 32 or ord(character) == 127 for character in relative)
            ):
                raise BioPipeError(
                    ErrorCode.ARTIFACT_WRITE_FAILED,
                    "A generated artifact has an unsafe relative path.",
                    context={"artifact": "<invalid>"},
                )
            if not isinstance(payload, bytes):
                raise BioPipeError(
                    ErrorCode.ARTIFACT_WRITE_FAILED,
                    "Generated project artifacts must be encoded bytes.",
                    context={"artifact": relative},
                )
            if len(payload) > _MAX_FILE_BYTES:
                raise BioPipeError(
                    ErrorCode.ARTIFACT_WRITE_FAILED,
                    "A generated project artifact exceeds the size limit.",
                    context={"artifact": relative},
                )
            total_bytes += len(payload)
            rendered.append((relative, payload))
        if total_bytes > _MAX_BUNDLE_BYTES:
            raise BioPipeError(
                ErrorCode.ARTIFACT_WRITE_FAILED,
                "The generated project bundle exceeds the size limit.",
            )
        return rendered

    @staticmethod
    def _stage(root: Path, artifacts: list[tuple[str, bytes]]) -> None:
        for relative, payload in artifacts:
            destination = root / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                destination,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                remaining = memoryview(payload)
                while remaining:
                    written = os.write(descriptor, remaining)
                    if written == 0:
                        raise OSError(errno.EIO, "artifact write made no progress")
                    remaining = remaining[written:]
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        ProjectBundleStore._fsync_tree(root)

    @staticmethod
    def _rename_exclusive(source: Path, destination: Path) -> None:
        """Atomically rename *source* while refusing any existing destination."""

        source_bytes = os.fsencode(source)
        destination_bytes = os.fsencode(destination)
        library = ctypes.CDLL(None, use_errno=True)
        function: object | None
        arguments: tuple[object, ...]
        if sys.platform.startswith("linux"):
            function = getattr(library, "renameat2", None)
            arguments = (
                _AT_FDCWD,
                source_bytes,
                _AT_FDCWD,
                destination_bytes,
                _RENAME_NOREPLACE,
            )
        elif sys.platform == "darwin":
            function = getattr(library, "renamex_np", None)
            arguments = (source_bytes, destination_bytes, _RENAME_EXCL)
        elif os.name == "nt":
            os.rename(source, destination)
            return
        else:
            function = None
            arguments = ()
        if function is None:
            raise OSError(errno.ENOTSUP, "exclusive directory rename is unavailable")

        function.restype = ctypes.c_int
        result = function(*arguments)
        if result != 0:
            error_number = ctypes.get_errno() or errno.EIO
            raise OSError(
                error_number,
                os.strerror(error_number),
                os.fspath(destination),
            )

    @staticmethod
    def _fsync_tree(root: Path) -> None:
        directories = [root]
        directories.extend(path for path in root.rglob("*") if path.is_dir())
        for directory in reversed(directories):
            descriptor = os.open(
                directory,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    @staticmethod
    def _fsync_directory_safely(directory: Path) -> None:
        with suppress(OSError):
            descriptor = os.open(
                directory,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    @staticmethod
    def _remove_staging_tree(root: Path) -> None:
        if not root.exists():
            return
        for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            with suppress(OSError):
                if path.is_dir():
                    path.rmdir()
                else:
                    path.unlink()
        with suppress(OSError):
            root.rmdir()

    @staticmethod
    def _error(artifact: str, error_number: int | None) -> BioPipeError:
        context: dict[str, str | int] = {"artifact": artifact}
        if error_number is not None:
            context["errno"] = error_number
        return BioPipeError(
            ErrorCode.ARTIFACT_WRITE_FAILED,
            "The generated project bundle could not be created without overwriting files.",
            context=context,
            remediation=["Choose a new output directory and retry generation."],
        )


__all__ = ["ProjectBundleStore"]
