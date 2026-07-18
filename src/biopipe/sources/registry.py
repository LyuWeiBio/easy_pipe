"""Atomic, file-backed storage for remote source profiles."""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Final

from pydantic import ValidationError

from biopipe.errors import BioPipeError, ErrorCode
from biopipe.models import SourceProfile

SourceRegistryErrorCode = ErrorCode

_SOURCE_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_PROFILE_SUFFIX: Final[str] = ".json"
_MAX_PROFILE_BYTES: Final[int] = 1024 * 1024


class SourceRegistryError(BioPipeError):
    """A stable source-registry failure suitable for CLI serialization."""


class SourceRegistry:
    """Store one validated :class:`SourceProfile` per atomically-created file.

    The registry intentionally has no update/upsert operation. Callers must remove
    an existing profile before adding a replacement, which prevents an accidental
    configuration overwrite from silently changing the remote security boundary.
    """

    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory).expanduser()

    @property
    def directory(self) -> Path:
        """Return the configured registry directory."""

        return self._directory

    def add(self, profile: SourceProfile) -> SourceProfile:
        """Atomically add *profile*, failing when its identifier already exists."""

        destination = self._profile_path(profile.source_id)
        serialized = (
            json.dumps(
                profile.model_dump(mode="json", exclude_none=False),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

        temporary_path: Path | None = None
        try:
            self._ensure_directory()
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self._directory,
                prefix=f".{profile.source_id}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                temporary.write(serialized)
                temporary.flush()
                os.fsync(temporary.fileno())

            # A hard link gives create-if-absent semantics while making the fully
            # fsynced temporary file visible in one filesystem operation.
            os.link(temporary_path, destination)
            self._fsync_directory()
            return profile
        except FileExistsError as exc:
            raise SourceRegistryError(
                ErrorCode.SOURCE_ALREADY_EXISTS,
                "A source profile with this identifier already exists.",
                context={"source_id": profile.source_id},
                remediation=["Remove the existing profile before adding a replacement."],
            ) from exc
        except SourceRegistryError:
            raise
        except OSError as exc:
            raise self._storage_error("write", profile.source_id, exc) from exc
        finally:
            if temporary_path is not None:
                with suppress(OSError):
                    temporary_path.unlink(missing_ok=True)

    def list(self) -> list[SourceProfile]:
        """Return all profiles sorted by their stable source identifier."""

        try:
            directory_stat = self._directory.lstat()
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise self._storage_error("list", None, exc) from exc
        try:
            self._require_regular_directory(directory_stat)
            paths = sorted(
                (path for path in self._directory.iterdir() if path.name.endswith(_PROFILE_SUFFIX)),
                key=lambda path: path.name,
            )
            return [self._read_profile(path, expected_id=path.stem) for path in paths]
        except SourceRegistryError:
            raise
        except OSError as exc:
            raise self._storage_error("list", None, exc) from exc

    def get(self, source_id: str) -> SourceProfile:
        """Load one profile or raise ``SOURCE_NOT_FOUND``."""

        destination = self._profile_path(source_id)
        try:
            return self._read_profile(destination, expected_id=source_id)
        except FileNotFoundError as exc:
            raise self._not_found(source_id) from exc
        except SourceRegistryError:
            raise
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                raise self._not_found(source_id) from exc
            raise self._storage_error("read", source_id, exc) from exc

    def remove(self, source_id: str) -> SourceProfile:
        """Atomically unlink one profile and return the profile that was removed."""

        destination = self._profile_path(source_id)
        profile = self.get(source_id)
        try:
            destination.unlink()
            self._fsync_directory()
            return profile
        except FileNotFoundError as exc:
            # Another process may have removed the source after ``get``.
            raise self._not_found(source_id) from exc
        except OSError as exc:
            raise self._storage_error("remove", source_id, exc) from exc

    def _ensure_directory(self) -> None:
        try:
            self._directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._require_regular_directory(self._directory.lstat())
        except OSError as exc:
            raise self._storage_error("initialize", None, exc) from exc

    def _profile_path(self, source_id: str) -> Path:
        if not _SOURCE_ID_PATTERN.fullmatch(source_id):
            # Do not reflect an attacker-controlled identifier into the structured
            # context: it can contain terminal controls or path material.
            raise SourceRegistryError(
                ErrorCode.SOURCE_NOT_FOUND,
                "The requested source profile does not exist.",
                context={"source_id": "<invalid>"},
            )
        return self._directory / f"{source_id}{_PROFILE_SUFFIX}"

    def _read_profile(self, path: Path, *, expected_id: str) -> SourceProfile:
        descriptor: int | None = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise OSError(errno.EINVAL, "Profile is not a regular file", path)
            if file_stat.st_size > _MAX_PROFILE_BYTES:
                raise OSError(errno.EFBIG, "Profile exceeds the size limit", path)
            with os.fdopen(descriptor, mode="rb") as stream:
                descriptor = None
                raw = stream.read(_MAX_PROFILE_BYTES + 1)
            if len(raw) > _MAX_PROFILE_BYTES:
                raise OSError(errno.EFBIG, "Profile exceeds the size limit", path)
            data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
            profile = SourceProfile.model_validate(data)
        except (
            UnicodeError,
            ValidationError,
            TypeError,
            ValueError,
            RecursionError,
        ) as exc:
            raise SourceRegistryError(
                ErrorCode.SOURCE_STORAGE_FAILED,
                "A stored source profile is invalid.",
                context={"source_id": expected_id, "operation": "read"},
                remediation=["Remove the invalid profile and add it again."],
            ) from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if profile.source_id != expected_id:
            raise SourceRegistryError(
                ErrorCode.SOURCE_STORAGE_FAILED,
                "A stored source profile does not match its filename.",
                context={"source_id": expected_id, "operation": "read"},
                remediation=["Remove the invalid profile and add it again."],
            )
        return profile

    def _fsync_directory(self) -> None:
        descriptor: int | None = None
        try:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self._directory, flags)
            os.fsync(descriptor)
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _require_regular_directory(directory_stat: os.stat_result) -> None:
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise NotADirectoryError(
                errno.ENOTDIR,
                "Registry path must be a non-symlink directory",
            )

    @staticmethod
    def _not_found(source_id: str) -> SourceRegistryError:
        return SourceRegistryError(
            ErrorCode.SOURCE_NOT_FOUND,
            "The requested source profile does not exist.",
            context={"source_id": source_id},
            remediation=["List configured sources or add this source profile first."],
        )

    @staticmethod
    def _storage_error(
        operation: str,
        source_id: str | None,
        error: OSError,
    ) -> SourceRegistryError:
        context: dict[str, str | int] = {"operation": operation}
        if source_id is not None:
            context["source_id"] = source_id
        if error.errno is not None:
            context["errno"] = error.errno
        return SourceRegistryError(
            ErrorCode.SOURCE_STORAGE_FAILED,
            "The source registry could not complete a storage operation.",
            context=context,
            remediation=["Check that the registry directory is readable and writable."],
        )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


__all__ = ["SourceRegistry", "SourceRegistryError", "SourceRegistryErrorCode"]
