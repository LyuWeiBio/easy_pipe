"""Race-resistant allowlist traversal using POSIX directory descriptors."""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePath
from types import TracebackType

from .config import AllowedRoot, ProbeConfig
from .errors import ProbeFailure, ReturnCode


@dataclass(frozen=True, slots=True)
class AuthorizedPath:
    """A lexical request path anchored beneath one canonical allowed root."""

    path: Path
    allowed_root: AllowedRoot
    relative_parts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthorizedStat:
    """Metadata obtained with fstat/fstatat without following a symlink."""

    authorized: AuthorizedPath
    stat_result: os.stat_result

    @property
    def path(self) -> Path:
        return self.authorized.path


@dataclass(slots=True)
class OpenedDirectory:
    """An owned directory descriptor and its stable display path."""

    authorized: AuthorizedPath
    fd: int
    stat_result: os.stat_result

    @property
    def path(self) -> Path:
        return self.authorized.path

    @property
    def allowed_root(self) -> AllowedRoot:
        return self.authorized.allowed_root

    @property
    def relative_parts(self) -> tuple[str, ...]:
        return self.authorized.relative_parts

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> OpenedDirectory:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


@dataclass(slots=True)
class OpenedFile:
    """An owned regular-file descriptor opened below an allowed directory."""

    authorized: AuthorizedPath
    fd: int
    stat_result: os.stat_result

    @property
    def path(self) -> Path:
        return self.authorized.path

    @property
    def allowed_root(self) -> AllowedRoot:
        return self.authorized.allowed_root

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> OpenedFile:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class PathGuard:
    """Resolve and access paths only through no-follow directory descriptors."""

    def __init__(self, config: ProbeConfig) -> None:
        self._config = config
        _require_supported_platform()

    def authorize(self, value: str) -> AuthorizedPath:
        """Map a safe absolute path beneath the most-specific configured root."""

        self._validate_text(value)
        requested = Path(os.path.normpath(value))
        match = self._match_lexical_root(requested)
        if match is None:
            raise _outside_failure()
        root, relative_parts = match
        canonical_display = root.canonical.joinpath(*relative_parts)
        self._validate_output_path(canonical_display)
        return AuthorizedPath(
            path=canonical_display,
            allowed_root=root,
            relative_parts=relative_parts,
        )

    def open_directory(self, value: str) -> OpenedDirectory:
        """Securely open a requested directory, checking every component once."""

        authorized = self.authorize(value)
        root_fd = self._open_allowed_root(authorized.allowed_root)
        return self._walk_directory_owned(root_fd, authorized)

    def stat_path(self, value: str, *, base: OpenedDirectory | None = None) -> AuthorizedStat:
        """Stat a path relative to an opened root without reopening checked names."""

        authorized = self.authorize(value)
        if base is None:
            start_fd = self._open_allowed_root(authorized.allowed_root)
            suffix = authorized.relative_parts
            baseline_device = authorized.allowed_root.device
        else:
            if base.fd < 0:
                raise _unavailable_failure("request root directory is already closed")
            if not _is_relative_to(authorized.path, base.path):
                raise ProbeFailure(
                    ReturnCode.PATH_OUTSIDE_ALLOWLIST,
                    "PATH_OUTSIDE_REQUEST_ROOT",
                    "stat_files path is outside the request root",
                )
            suffix = authorized.path.relative_to(base.path).parts
            try:
                start_fd = os.dup(base.fd)
            except OSError as exc:
                raise _unavailable_failure() from exc
            baseline_device = base.allowed_root.device
        item_stat = self._stat_relative_owned(
            start_fd,
            suffix,
            baseline_device=baseline_device,
        )
        return AuthorizedStat(authorized=authorized, stat_result=item_stat)

    def stat_child(self, parent: OpenedDirectory, name: str) -> AuthorizedStat:
        """Stat one scandir child with fstatat and no symlink following."""

        authorized = self._child_authorized(parent, name)
        try:
            item_stat = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        except OSError as exc:
            raise _mapped_access_failure(parent.fd, name, exc) from exc
        _reject_symlink_stat(item_stat)
        self._enforce_mount(item_stat, parent.allowed_root.device)
        return AuthorizedStat(authorized=authorized, stat_result=item_stat)

    def open_file(self, value: str, *, base: OpenedDirectory | None = None) -> OpenedFile:
        """Open one regular file through anchored ``openat`` calls without symlinks."""

        authorized = self.authorize(value)
        if base is None:
            start_fd = self._open_allowed_root(authorized.allowed_root)
            suffix = authorized.relative_parts
            baseline_device = authorized.allowed_root.device
        else:
            if base.fd < 0:
                raise _unavailable_failure("request root directory is already closed")
            if not _is_relative_to(authorized.path, base.path):
                raise ProbeFailure(
                    ReturnCode.PATH_OUTSIDE_ALLOWLIST,
                    "PATH_OUTSIDE_REQUEST_ROOT",
                    "file path is outside the request root",
                )
            suffix = authorized.path.relative_to(base.path).parts
            try:
                start_fd = os.dup(base.fd)
            except OSError as exc:
                raise _unavailable_failure() from exc
            baseline_device = base.allowed_root.device
        return self._open_file_relative_owned(
            start_fd,
            authorized,
            suffix,
            baseline_device=baseline_device,
        )

    def open_child_directory(self, parent: OpenedDirectory, name: str) -> OpenedDirectory:
        """Open one child with openat O_NOFOLLOW and retain its descriptor."""

        authorized = self._child_authorized(parent, name)
        child_fd, child_stat = _open_directory_component(parent.fd, name)
        try:
            self._enforce_mount(child_stat, parent.allowed_root.device)
        except Exception:
            os.close(child_fd)
            raise
        return OpenedDirectory(
            authorized=authorized,
            fd=child_fd,
            stat_result=child_stat,
        )

    def _open_allowed_root(self, root: AllowedRoot) -> int:
        flags = _directory_flags()
        try:
            current_fd = os.open("/", flags)
        except OSError as exc:
            raise _unavailable_failure("cannot open the filesystem root") from exc
        try:
            for component in root.canonical.parts[1:]:
                next_fd, _ = _open_directory_component(current_fd, component)
                os.close(current_fd)
                current_fd = next_fd
            root_stat = os.fstat(current_fd)
            if (root_stat.st_dev, root_stat.st_ino) != (root.device, root.inode):
                raise _unavailable_failure("configured allowed root changed after probe startup")
            return current_fd
        except Exception:
            os.close(current_fd)
            raise

    def _walk_directory_owned(self, start_fd: int, authorized: AuthorizedPath) -> OpenedDirectory:
        current_fd = start_fd
        try:
            current_stat = os.fstat(current_fd)
            for component in authorized.relative_parts:
                next_fd, next_stat = _open_directory_component(current_fd, component)
                os.close(current_fd)
                current_fd = next_fd
                current_stat = next_stat
                self._enforce_mount(current_stat, authorized.allowed_root.device)
            return OpenedDirectory(
                authorized=authorized,
                fd=current_fd,
                stat_result=current_stat,
            )
        except Exception:
            os.close(current_fd)
            raise

    def _stat_relative_owned(
        self,
        start_fd: int,
        relative_parts: tuple[str, ...],
        *,
        baseline_device: int,
    ) -> os.stat_result:
        current_fd = start_fd
        try:
            if not relative_parts:
                item_stat = os.fstat(current_fd)
                self._enforce_mount(item_stat, baseline_device)
                return item_stat
            for component in relative_parts[:-1]:
                next_fd, next_stat = _open_directory_component(current_fd, component)
                os.close(current_fd)
                current_fd = next_fd
                self._enforce_mount(next_stat, baseline_device)
            final_name = relative_parts[-1]
            try:
                item_stat = os.stat(
                    final_name,
                    dir_fd=current_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise _mapped_access_failure(current_fd, final_name, exc) from exc
            _reject_symlink_stat(item_stat)
            self._enforce_mount(item_stat, baseline_device)
            return item_stat
        finally:
            os.close(current_fd)

    def _open_file_relative_owned(
        self,
        start_fd: int,
        authorized: AuthorizedPath,
        relative_parts: tuple[str, ...],
        *,
        baseline_device: int,
    ) -> OpenedFile:
        current_fd = start_fd
        file_fd = -1
        try:
            if not relative_parts:
                raise _unavailable_failure("requested path is not a regular file")
            for component in relative_parts[:-1]:
                next_fd, next_stat = _open_directory_component(current_fd, component)
                os.close(current_fd)
                current_fd = next_fd
                self._enforce_mount(next_stat, baseline_device)
            final_name = relative_parts[-1]
            try:
                file_fd = os.open(final_name, _file_flags(), dir_fd=current_fd)
            except OSError as exc:
                raise _mapped_access_failure(current_fd, final_name, exc) from exc
            file_stat = os.fstat(file_fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise _unavailable_failure("requested path is not a regular file")
            self._enforce_mount(file_stat, baseline_device)
            opened = OpenedFile(
                authorized=authorized,
                fd=file_fd,
                stat_result=file_stat,
            )
            file_fd = -1
            return opened
        finally:
            if file_fd >= 0:
                os.close(file_fd)
            os.close(current_fd)

    def _child_authorized(self, parent: OpenedDirectory, name: str) -> AuthorizedPath:
        if parent.fd < 0:
            raise _unavailable_failure("directory descriptor is already closed")
        if (
            not name
            or name in {".", ".."}
            or "/" in name
            or _has_control_characters(name)
            or _has_surrogate(name)
        ):
            raise ProbeFailure(
                ReturnCode.PROTOCOL_ERROR,
                "UNSAFE_PATH",
                "a discovered path contains forbidden characters",
            )
        path = parent.path / name
        self._validate_output_path(path)
        return AuthorizedPath(
            path=path,
            allowed_root=parent.allowed_root,
            relative_parts=(*parent.relative_parts, name),
        )

    def _validate_text(self, value: str) -> None:
        if not value or _has_control_characters(value) or _has_surrogate(value):
            raise ProbeFailure(
                ReturnCode.PROTOCOL_ERROR,
                "UNSAFE_PATH",
                "path contains forbidden characters",
            )
        try:
            byte_length = len(value.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ProbeFailure(
                ReturnCode.PROTOCOL_ERROR,
                "UNSAFE_PATH",
                "path cannot be represented safely",
            ) from exc
        if byte_length > self._config.limits.max_path_bytes:
            raise ProbeFailure(
                ReturnCode.PROTOCOL_ERROR,
                "PATH_TOO_LONG",
                "path exceeds max_path_bytes",
            )
        pure = PurePath(value)
        if not pure.is_absolute() or ".." in pure.parts:
            raise _outside_failure()

    def _validate_output_path(self, value: Path) -> None:
        text = str(value)
        if _has_control_characters(text) or _has_surrogate(text):
            raise ProbeFailure(
                ReturnCode.PROTOCOL_ERROR,
                "UNSAFE_PATH",
                "a discovered path contains forbidden characters",
            )
        try:
            encoded_length = len(text.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ProbeFailure(
                ReturnCode.PROTOCOL_ERROR,
                "UNSAFE_PATH",
                "a discovered path cannot be represented safely",
            ) from exc
        if encoded_length > self._config.limits.max_path_bytes:
            raise ProbeFailure(
                ReturnCode.PROTOCOL_ERROR,
                "PATH_TOO_LONG",
                "a discovered path exceeds max_path_bytes",
            )

    def _match_lexical_root(self, requested: Path) -> tuple[AllowedRoot, tuple[str, ...]] | None:
        candidates: list[tuple[AllowedRoot, tuple[str, ...]]] = []
        for root in self._config.allowed_roots:
            for base in (root.configured, root.canonical):
                try:
                    relative = requested.relative_to(base)
                except ValueError:
                    continue
                candidates.append((root, relative.parts))
        if not candidates:
            return None
        return max(candidates, key=lambda item: len(item[0].canonical.parts))

    def _enforce_mount(self, item_stat: os.stat_result, baseline_device: int) -> None:
        if not self._config.allow_mount_crossing and item_stat.st_dev != baseline_device:
            raise ProbeFailure(
                ReturnCode.SYMLINK_OR_ESCAPE,
                "MOUNT_BOUNDARY_FORBIDDEN",
                "path crosses an unapproved filesystem boundary",
            )


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _file_flags() -> int:
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)


def _open_directory_component(parent_fd: int, name: str) -> tuple[int, os.stat_result]:
    try:
        child_fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except OSError as exc:
        raise _mapped_access_failure(parent_fd, name, exc) from exc
    try:
        child_stat = os.fstat(child_fd)
        if not stat.S_ISDIR(child_stat.st_mode):
            raise _unavailable_failure("path component is not a directory")
        return child_fd, child_stat
    except Exception:
        os.close(child_fd)
        raise


def _mapped_access_failure(parent_fd: int, name: str, error: OSError) -> ProbeFailure:
    if error.errno == errno.ELOOP:
        return _symlink_failure()
    try:
        item_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return _unavailable_failure()
    if stat.S_ISLNK(item_stat.st_mode):
        return _symlink_failure()
    return _unavailable_failure()


def _reject_symlink_stat(item_stat: os.stat_result) -> None:
    if stat.S_ISLNK(item_stat.st_mode):
        raise _symlink_failure()


def _require_supported_platform() -> None:
    supported = (
        os.name == "posix"
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and os.open in os.supports_dir_fd
        and os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
        and os.scandir in os.supports_fd
    )
    if not supported:
        raise ProbeFailure(
            ReturnCode.INTERNAL_ERROR,
            "PLATFORM_UNSUPPORTED",
            "secure descriptor-based traversal is unavailable on this host",
        )


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _outside_failure() -> ProbeFailure:
    return ProbeFailure(
        ReturnCode.PATH_OUTSIDE_ALLOWLIST,
        "PATH_OUTSIDE_ALLOWLIST",
        "path is not within a configured allowed root",
    )


def _symlink_failure() -> ProbeFailure:
    return ProbeFailure(
        ReturnCode.SYMLINK_OR_ESCAPE,
        "SYMLINK_FORBIDDEN",
        "symlink paths are not permitted",
    )


def _unavailable_failure(
    message: str = "path does not exist or cannot be read",
) -> ProbeFailure:
    return ProbeFailure(ReturnCode.PATH_UNAVAILABLE, "PATH_UNAVAILABLE", message)


def _has_control_characters(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)


def _has_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


__all__ = [
    "AuthorizedPath",
    "AuthorizedStat",
    "OpenedDirectory",
    "OpenedFile",
    "PathGuard",
]
